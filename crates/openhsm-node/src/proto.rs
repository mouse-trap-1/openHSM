//! Wire protocol shared by the node and its clients.
//!
//! Transport: TLS 1.3 with mutual authentication. Framing: a 4-byte
//! big-endian length followed by one JSON document.
//!
//! ```text
//! request  = { "payload": "<JSON text>", "sigs": [ { "id": "...", "sig": "<hex>" }, ... ] }
//! payload  = { "v": 1, "cluster": "...", "node": "..."?, "ts": <ms>, "exp": <ms>?, "nonce": "<32 hex>",
//!              "method": "...", "params": { ... } }
//! sig      = Ed25519( principal key, "OPENHSM-REQ-v1\0" || payload bytes )
//! response = { "ok": true, "result": ... } | { "ok": false, "error": { "code": "...", "message": "..." } }
//! ```
//!
//! The payload travels as a string so that the signature covers the exact
//! bytes that were signed; nothing is re-serialised before verification.

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{self, Read, Write};

pub const REQ_DOMAIN: &[u8] = b"OPENHSM-REQ-v1\0";
/// Largest accepted frame. Snapshots of 10,000 wallets fit comfortably.
pub const MAX_FRAME: usize = 16 * 1024 * 1024;
/// Clock skew tolerated between a client and the node.
pub const SKEW_MS: u64 = 30_000;
/// Longest validity of a quorum-signed operation.
pub const MAX_ADMIN_VALIDITY_MS: u64 = 24 * 3600 * 1000;
pub const MAX_SIGS: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigEntry {
    pub id: String,
    pub sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Frame {
    pub payload: String,
    pub sigs: Vec<SigEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Payload {
    pub v: u32,
    pub cluster: String,
    /// The node this request is for. Required for quorum operations, so an
    /// approved operation cannot be replayed against another node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    pub ts: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    pub nonce: String,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Clone)]
pub struct ApiError {
    pub code: &'static str,
    pub message: String,
}

impl ApiError {
    pub fn new(code: &'static str, message: impl Into<String>) -> ApiError {
        ApiError { code, message: message.into() }
    }
}

pub fn sign_payload(key: &SigningKey, payload: &str) -> String {
    let mut msg = REQ_DOMAIN.to_vec();
    msg.extend_from_slice(payload.as_bytes());
    hex::encode(key.sign(&msg).to_bytes())
}

pub fn verify_payload(pubkey_hex: &str, payload: &str, sig_hex: &str) -> bool {
    let mut pk = [0u8; 32];
    let mut sig = [0u8; 64];
    if hex::decode_to_slice(pubkey_hex, &mut pk).is_err() || hex::decode_to_slice(sig_hex, &mut sig).is_err() {
        return false;
    }
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else { return false };
    let mut msg = REQ_DOMAIN.to_vec();
    msg.extend_from_slice(payload.as_bytes());
    vk.verify_strict(&msg, &Signature::from_bytes(&sig)).is_ok()
}

pub fn read_frame(r: &mut impl Read, max: usize) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let n = u32::from_be_bytes(len) as usize;
    if n == 0 || n > max {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame length out of range"));
    }
    // Grow the buffer as bytes arrive instead of trusting the declared length.
    let mut buf = Vec::with_capacity(n.min(64 * 1024));
    r.take(n as u64).read_to_end(&mut buf)?;
    if buf.len() != n {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated frame"));
    }
    Ok(buf)
}

pub fn write_frame(w: &mut impl Write, data: &[u8]) -> io::Result<()> {
    w.write_all(&(data.len() as u32).to_be_bytes())?;
    w.write_all(data)?;
    w.flush()
}
