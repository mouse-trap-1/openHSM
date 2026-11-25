//! Hybrid post-quantum key exchange on the API and cluster links.
//!
//! Handshakes run in memory between the node's real server and client
//! configurations, with certificates made the way `hsmctl` makes them.

use openhsm_node::client::client_config;
use openhsm_node::server::{parse_certs, parse_key, root_store, server_config};
use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};
use rustls::crypto::{aws_lc_rs, CryptoProvider};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, NamedGroup, ServerConnection};
use std::sync::Arc;

struct Pki {
    ca: String,
    server_cert: String,
    server_key: String,
    client_cert: String,
    client_key: String,
}

fn pki() -> Pki {
    let ca_key = KeyPair::generate().unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(DnType::CommonName, "test cluster CA");
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = p.self_signed(&ca_key).unwrap();

    let skey = KeyPair::generate().unwrap();
    let mut p = CertificateParams::new(vec!["node1.openhsm".to_string()]).unwrap();
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let scert = p.signed_by(&skey, &ca, &ca_key).unwrap();

    let ckey = KeyPair::generate().unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(DnType::CommonName, "alice");
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let ccert = p.signed_by(&ckey, &ca, &ca_key).unwrap();

    Pki { ca: ca.pem(), server_cert: scert.pem(), server_key: skey.serialize_pem(), client_cert: ccert.pem(), client_key: ckey.serialize_pem() }
}

/// Runs a handshake in memory. Returns the group the server chose, or the
/// first error either side raised.
fn handshake(client: Arc<ClientConfig>, server: Arc<rustls::ServerConfig>) -> Result<NamedGroup, String> {
    let mut c = ClientConnection::new(client, ServerName::try_from("node1.openhsm").unwrap()).map_err(|e| e.to_string())?;
    let mut s = ServerConnection::new(server).map_err(|e| e.to_string())?;
    for _ in 0..10 {
        let mut buf = Vec::new();
        while c.wants_write() {
            c.write_tls(&mut buf).map_err(|e| e.to_string())?;
        }
        s.read_tls(&mut &buf[..]).map_err(|e| e.to_string())?;
        s.process_new_packets().map_err(|e| format!("server: {e}"))?;
        let mut buf = Vec::new();
        while s.wants_write() {
            s.write_tls(&mut buf).map_err(|e| e.to_string())?;
        }
        c.read_tls(&mut &buf[..]).map_err(|e| e.to_string())?;
        c.process_new_packets().map_err(|e| format!("client: {e}"))?;
        if !c.is_handshaking() && !s.is_handshaking() {
            let g = s.negotiated_key_exchange_group().ok_or("no group")?.name();
            assert_eq!(Some(g), c.negotiated_key_exchange_group().map(|k| k.name()));
            return Ok(g);
        }
    }
    Err("handshake did not finish".into())
}

fn classical_client(p: &Pki) -> Arc<ClientConfig> {
    let provider = Arc::new(CryptoProvider { kx_groups: vec![aws_lc_rs::kx_group::X25519], ..aws_lc_rs::default_provider() });
    Arc::new(
        ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(root_store(p.ca.as_bytes()).unwrap())
            .with_client_auth_cert(parse_certs(p.client_cert.as_bytes()).unwrap(), parse_key(p.client_key.as_bytes()).unwrap())
            .unwrap(),
    )
}

#[test]
fn openhsm_client_and_node_agree_on_hybrid_mlkem() {
    let p = pki();
    let server = server_config(p.ca.as_bytes(), p.server_cert.as_bytes(), p.server_key.as_bytes()).unwrap();
    let client = client_config(p.ca.as_bytes(), p.client_cert.as_bytes(), p.client_key.as_bytes()).unwrap();
    assert_eq!(handshake(client, server).unwrap(), NamedGroup::X25519MLKEM768);
}

#[test]
fn node_still_accepts_a_classical_client() {
    // Third-party clients whose TLS library has no ML-KEM yet still connect, with X25519.
    let p = pki();
    let server = server_config(p.ca.as_bytes(), p.server_cert.as_bytes(), p.server_key.as_bytes()).unwrap();
    assert_eq!(handshake(classical_client(&p), server).unwrap(), NamedGroup::X25519);
}

#[test]
fn openhsm_client_refuses_a_classical_only_server() {
    let p = pki();
    let provider = Arc::new(CryptoProvider { kx_groups: vec![aws_lc_rs::kx_group::X25519], ..aws_lc_rs::default_provider() });
    let roots = root_store(p.ca.as_bytes()).unwrap();
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone()).build().unwrap();
    let server = Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(parse_certs(p.server_cert.as_bytes()).unwrap(), parse_key(p.server_key.as_bytes()).unwrap())
            .unwrap(),
    );
    let client = client_config(p.ca.as_bytes(), p.client_cert.as_bytes(), p.client_key.as_bytes()).unwrap();
    assert!(handshake(client, server).is_err(), "client must not fall back to a classical key exchange");
}
