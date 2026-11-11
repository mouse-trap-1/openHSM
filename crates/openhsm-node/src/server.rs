//! Network listener: TLS 1.3 with mandatory client certificates, bounded
//! frames, deadlines on every read, and a cap on concurrent connections.

use crate::node::Node;
use crate::proto::{read_frame, write_frame, MAX_FRAME};
use crate::util::sha256;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use std::collections::HashMap;
use std::io::{self, Read};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const MAX_CONNECTIONS: usize = 256;
/// Connections one source address may hold, so that a single host cannot
/// occupy every slot before authenticating.
pub const MAX_CONNECTIONS_PER_SOURCE: usize = 32;
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(5);
const FRAME_DEADLINE: Duration = Duration::from_secs(60);

use rustls::pki_types::pem::PemObject;

pub fn parse_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, String> {
    let certs = CertificateDer::pem_slice_iter(pem).collect::<Result<Vec<_>, _>>().map_err(|e| format!("certificate: {e}"))?;
    if certs.is_empty() {
        return Err("no certificate found in PEM".into());
    }
    Ok(certs)
}

pub fn parse_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, String> {
    PrivateKeyDer::from_pem_slice(pem).map_err(|e| format!("private key: {e}"))
}

pub fn root_store(ca_pem: &[u8]) -> Result<RootCertStore, String> {
    let mut roots = RootCertStore::empty();
    for c in parse_certs(ca_pem)? {
        roots.add(c).map_err(|e| format!("CA certificate: {e}"))?;
    }
    Ok(roots)
}

/// TLS configuration for the node: TLS 1.3 only, client certificate
/// required and verified against the cluster CA recorded in the state.
pub fn tls_config(node: &Node) -> Result<Arc<ServerConfig>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let roots = root_store(node.state.ca_cert_pem.as_bytes())?;
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone()).build().map_err(|e| e.to_string())?;
    let certs = parse_certs(&node.tls_cert_pem()?)?;
    let key_pem = node.tls_key_pem()?;
    let key = parse_key(&key_pem)?;
    let cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|e| format!("TLS certificate does not match the node key: {e}"))?;
    Ok(Arc::new(cfg))
}

/// A reader that gives the peer a fixed time to deliver a whole frame.
struct Deadline<'a> {
    inner: &'a mut StreamOwned<ServerConnection, TcpStream>,
    until: Instant,
}

impl Read for Deadline<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.until.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()).ok_or(io::ErrorKind::TimedOut)?;
        self.inner.sock.set_read_timeout(Some(left))?;
        self.inner.read(buf)
    }
}

fn handle_conn(node: &Mutex<Node>, cfg: Arc<ServerConfig>, mut tcp: TcpStream) -> io::Result<()> {
    tcp.set_nodelay(true)?;
    tcp.set_write_timeout(Some(HANDSHAKE_DEADLINE))?;
    let mut conn = ServerConnection::new(cfg).map_err(io::Error::other)?;
    let start = Instant::now();
    while conn.is_handshaking() {
        let left = HANDSHAKE_DEADLINE.checked_sub(start.elapsed()).filter(|d| !d.is_zero()).ok_or(io::ErrorKind::TimedOut)?;
        tcp.set_read_timeout(Some(left))?;
        conn.complete_io(&mut tcp)?;
    }
    let peer_fp = match conn.peer_certificates().and_then(|c| c.first()) {
        Some(cert) => sha256(&[cert.as_ref()]),
        None => return Err(io::Error::new(io::ErrorKind::PermissionDenied, "no client certificate")),
    };
    let mut tls = StreamOwned::new(conn, tcp);
    loop {
        let frame = {
            let mut r = Deadline { inner: &mut tls, until: Instant::now() + FRAME_DEADLINE };
            match read_frame(&mut r, MAX_FRAME) {
                Ok(f) => f,
                Err(_) => return Ok(()), // closed, timed out or oversized: drop the connection
            }
        };
        let resp = node.lock().unwrap_or_else(|e| e.into_inner()).handle_frame(&frame, &peer_fp);
        write_frame(&mut tls, &resp)?;
    }
}

/// Accept loop. One thread per connection, at most `MAX_CONNECTIONS` in
/// total and `MAX_CONNECTIONS_PER_SOURCE` per source address.
pub fn serve(node: Arc<Mutex<Node>>, listener: TcpListener, cfg: Arc<ServerConfig>) {
    let active = Arc::new(AtomicUsize::new(0));
    let per_source: Arc<Mutex<HashMap<IpAddr, usize>>> = Arc::new(Mutex::new(HashMap::new()));
    for tcp in listener.incoming() {
        let Ok(tcp) = tcp else { continue };
        let Ok(peer) = tcp.peer_addr().map(|a| a.ip()) else { continue };
        {
            let mut map = per_source.lock().unwrap_or_else(|e| e.into_inner());
            let n = map.entry(peer).or_insert(0);
            if *n >= MAX_CONNECTIONS_PER_SOURCE || active.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
                continue; // dropping the socket closes it
            }
            *n += 1;
            active.fetch_add(1, Ordering::SeqCst);
        }
        let (node, cfg, active, per_source) = (node.clone(), cfg.clone(), active.clone(), per_source.clone());
        std::thread::spawn(move || {
            let _ = handle_conn(&node, cfg, tcp);
            active.fetch_sub(1, Ordering::SeqCst);
            let mut map = per_source.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(n) = map.get_mut(&peer) {
                *n -= 1;
                if *n == 0 {
                    map.remove(&peer);
                }
            }
        });
    }
}
