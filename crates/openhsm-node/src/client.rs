//! Client library: builds, signs and sends requests. Used by `hsmctl` and by
//! the integration tests.

use crate::proto::{read_frame, sign_payload, write_frame, Frame, Payload, SigEntry, MAX_FRAME};
use crate::server::{parse_certs, parse_key, root_store};
use crate::util::{now_ms, random};
use ed25519_dalek::SigningKey;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// Everything a principal needs to talk to a node.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub addr: String,
    pub server_name: String,
    pub cluster: String,
    pub id: String,
    pub ca: PathBuf,
    pub cert: PathBuf,
    pub key: PathBuf,
    pub sign_key: PathBuf,
}

/// Load an Ed25519 request-signing key (32-byte seed, hex).
pub fn load_sign_key(path: &Path) -> Result<SigningKey, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(text.trim(), &mut seed[..]).map_err(|_| format!("{}: not a 32-byte hex seed", path.display()))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Build the payload text for a request. `validity_ms` is set for quorum
/// operations, which stay valid long enough to collect signatures.
pub fn build_payload(cluster: &str, node: Option<&str>, method: &str, params: Value, validity_ms: Option<u64>) -> Result<String, String> {
    let ts = now_ms();
    let p = Payload {
        v: 1,
        cluster: cluster.to_string(),
        node: node.map(str::to_string),
        ts,
        exp: validity_ms.map(|v| ts + v),
        nonce: hex::encode(random::<16>()?),
        method: method.to_string(),
        params,
    };
    serde_json::to_string(&p).map_err(|e| e.to_string())
}

pub struct Client {
    pub profile: Profile,
    tls: Arc<ClientConfig>,
    sign_key: SigningKey,
}

impl Client {
    pub fn new(profile: Profile) -> Result<Client, String> {
        let read = |p: &Path| std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| e.to_string())?
            .with_root_certificates(root_store(&read(&profile.ca)?)?)
            .with_client_auth_cert(parse_certs(&read(&profile.cert)?)?, parse_key(&read(&profile.key)?)?)
            .map_err(|e| e.to_string())?;
        let sign_key = load_sign_key(&profile.sign_key)?;
        Ok(Client { profile, tls: Arc::new(tls), sign_key })
    }

    /// Sign `payload` as this client.
    pub fn sign(&self, payload: &str) -> SigEntry {
        SigEntry { id: self.profile.id.clone(), sig: sign_payload(&self.sign_key, payload) }
    }

    /// Send a prepared frame and return the raw response document.
    pub fn send(&self, frame: &Frame) -> Result<Value, String> {
        let tcp = TcpStream::connect(&self.profile.addr).map_err(|e| format!("connect {}: {e}", self.profile.addr))?;
        tcp.set_read_timeout(Some(Duration::from_secs(120))).map_err(|e| e.to_string())?;
        tcp.set_nodelay(true).map_err(|e| e.to_string())?;
        let name = ServerName::try_from(self.profile.server_name.clone()).map_err(|e| e.to_string())?;
        let conn = ClientConnection::new(self.tls.clone(), name).map_err(|e| e.to_string())?;
        let mut tls = StreamOwned::new(conn, tcp);
        write_frame(&mut tls, &serde_json::to_vec(frame).map_err(|e| e.to_string())?).map_err(|e| format!("send: {e}"))?;
        let resp = read_frame(&mut tls, MAX_FRAME).map_err(|e| format!("receive: {e}"))?;
        serde_json::from_slice(&resp).map_err(|e| e.to_string())
    }

    /// Call a method signed by this client alone. Returns the result or the
    /// node's error as `code: message`.
    pub fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let payload = build_payload(&self.profile.cluster, None, method, params, None)?;
        let frame = Frame { sigs: vec![self.sign(&payload)], payload };
        unwrap_response(self.send(&frame)?)
    }
}

pub fn unwrap_response(v: Value) -> Result<Value, String> {
    if v.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(v.get("result").cloned().unwrap_or(Value::Null))
    } else {
        let e = v.get("error");
        let code = e.and_then(|e| e.get("code")).and_then(Value::as_str).unwrap_or("error");
        let msg = e.and_then(|e| e.get("message")).and_then(Value::as_str).unwrap_or("");
        Err(format!("{code}: {msg}"))
    }
}
