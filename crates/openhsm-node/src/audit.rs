//! Tamper-evident audit log.
//!
//! Each line is `{"b":<body>,"h":"<hash>","s":"<signature>"}` where
//!
//! ```text
//! hash      = SHA-256("OPENHSM-AUDIT-v1" || prev_hash || body_bytes)
//! signature = Ed25519(node identity key, hash)
//! ```
//!
//! Entries are numbered from 1 without gaps and each names its predecessor,
//! so removing, reordering or editing any entry breaks the chain. The newest
//! sequence number is mirrored in the tamper supervisor's monotonic counter,
//! which detects truncation of the tail (rollback). Verification needs only
//! the node's public identity key, so an auditor can check an exported log
//! offline.

use crate::util::sha256;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

const DOMAIN: &[u8] = b"OPENHSM-AUDIT-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Body {
    pub seq: u64,
    pub ts: u64,
    pub node: String,
    pub actor: String,
    pub event: String,
    pub ok: bool,
    pub detail: Value,
    /// Hash of the state file after this event, when the event changed it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub state: Option<String>,
    pub prev: String,
}

pub fn entry_hash(prev: &[u8; 32], body: &[u8]) -> [u8; 32] {
    sha256(&[DOMAIN, prev, body])
}

/// Split one log line into (raw body, hash, signature) without re-serialising.
fn split_line(line: &str) -> Option<(&str, [u8; 32], [u8; 64])> {
    let rest = line.strip_prefix("{\"b\":")?;
    let idx = rest.rfind(",\"h\":\"")?;
    let (body, tail) = rest.split_at(idx);
    let tail = tail.strip_prefix(",\"h\":\"")?;
    let (h, tail) = tail.split_at_checked(64)?;
    let tail = tail.strip_prefix("\",\"s\":\"")?;
    let (s, tail) = tail.split_at_checked(128)?;
    if tail != "\"}" {
        return None;
    }
    let mut hash = [0u8; 32];
    let mut sig = [0u8; 64];
    hex::decode_to_slice(h, &mut hash).ok()?;
    hex::decode_to_slice(s, &mut sig).ok()?;
    Some((body, hash, sig))
}

/// Verify a whole log file. Returns the entries in order.
///
/// A genuine log is never empty: it starts with the `node_init` entry written
/// when the node was created. An empty or headless file is rejected, so that
/// "replace the log with nothing" does not pass offline verification.
/// Truncation of the tail cannot be seen from the file alone; compare the
/// last entry with the node's `audit_head` (the node itself detects it at
/// boot through the tamper supervisor's monotonic counter).
pub fn verify_file(path: &Path, vk: &VerifyingKey) -> Result<Vec<Body>, String> {
    let (entries, _) = verify_chain(path, vk)?;
    match entries.first() {
        Some(first) if first.event == "node_init" => Ok(entries),
        Some(_) => Err("audit log does not start with the node_init entry".into()),
        None => Err("audit log is empty".into()),
    }
}

fn verify_chain(path: &Path, vk: &VerifyingKey) -> Result<(Vec<Body>, [u8; 32]), String> {
    let f = File::open(path).map_err(|e| format!("open audit log: {e}"))?;
    let mut prev = [0u8; 32];
    let mut out = Vec::new();
    for (i, line) in BufReader::new(f).lines().enumerate() {
        let n = i as u64 + 1;
        let line = line.map_err(|e| format!("audit line {n}: {e}"))?;
        let (raw, hash, sig) = split_line(&line).ok_or(format!("audit line {n}: malformed"))?;
        if entry_hash(&prev, raw.as_bytes()) != hash {
            return Err(format!("audit line {n}: hash chain broken"));
        }
        vk.verify_strict(&hash, &Signature::from_bytes(&sig)).map_err(|_| format!("audit line {n}: bad signature"))?;
        let body: Body = serde_json::from_str(raw).map_err(|e| format!("audit line {n}: {e}"))?;
        if body.seq != n || body.prev != hex::encode(prev) {
            return Err(format!("audit line {n}: sequence or predecessor mismatch"));
        }
        prev = hash;
        out.push(body);
    }
    Ok((out, prev))
}

pub struct AuditLog {
    path: PathBuf,
    file: File,
    pub seq: u64,
    pub head: [u8; 32],
    pub last_ts: u64,
    fsync: bool,
}

impl AuditLog {
    pub fn create(path: &Path) -> Result<AuditLog, String> {
        let file = OpenOptions::new().create_new(true).append(true).open(path).map_err(|e| format!("create audit log: {e}"))?;
        Ok(AuditLog { path: path.to_path_buf(), file, seq: 0, head: [0; 32], last_ts: 0, fsync: true })
    }

    /// Open an existing log, verifying every entry.
    pub fn open(path: &Path, vk: &VerifyingKey) -> Result<(AuditLog, Vec<Body>), String> {
        let (entries, head) = verify_chain(path, vk)?;
        let file = OpenOptions::new().append(true).open(path).map_err(|e| format!("open audit log: {e}"))?;
        let log = AuditLog { path: path.to_path_buf(), file, seq: entries.len() as u64, head, last_ts: entries.last().map(|e| e.ts).unwrap_or(0), fsync: true };
        Ok((log, entries))
    }

    pub fn set_fsync(&mut self, on: bool) {
        self.fsync = on;
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one entry and make it durable. Returns its sequence number.
    #[allow(clippy::too_many_arguments)]
    pub fn append(
        &mut self,
        sk: &SigningKey,
        ts: u64,
        node: &str,
        actor: &str,
        event: &str,
        ok: bool,
        detail: Value,
        state: Option<String>,
    ) -> Result<u64, String> {
        let body = Body {
            seq: self.seq + 1,
            ts,
            node: node.to_string(),
            actor: actor.to_string(),
            event: event.to_string(),
            ok,
            detail,
            state,
            prev: hex::encode(self.head),
        };
        let raw = serde_json::to_string(&body).map_err(|e| e.to_string())?;
        let hash = entry_hash(&self.head, raw.as_bytes());
        let sig = sk.sign(&hash);
        let line = format!("{{\"b\":{raw},\"h\":\"{}\",\"s\":\"{}\"}}\n", hex::encode(hash), hex::encode(sig.to_bytes()));
        self.file.write_all(line.as_bytes()).map_err(|e| format!("audit write failed: {e}"))?;
        if self.fsync {
            self.file.sync_data().map_err(|e| format!("audit sync failed: {e}"))?;
        }
        self.seq += 1;
        self.head = hash;
        self.last_ts = ts;
        Ok(self.seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("openhsm-audit-{name}-{}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn chain_verifies_and_detects_edits() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let path = tmp("chain");
        let mut log = AuditLog::create(&path).unwrap();
        for i in 0..5 {
            let event = if i == 0 { "node_init" } else { "evt" };
            log.append(&sk, 1000 + i, "n", "actor", event, true, json!({"i": i, "note": "a,\"h\":\"x"}), None).unwrap();
        }
        let (reopened, entries) = AuditLog::open(&path, &sk.verifying_key()).unwrap();
        assert_eq!((entries.len(), reopened.seq), (5, 5));
        assert_eq!(reopened.head, log.head);

        let text = std::fs::read_to_string(&path).unwrap();
        // Edit one field.
        std::fs::write(&path, text.replacen("\"i\":2", "\"i\":9", 1)).unwrap();
        assert!(verify_file(&path, &sk.verifying_key()).is_err());
        // Drop a middle line.
        let lines: Vec<&str> = text.lines().collect();
        std::fs::write(&path, format!("{}\n{}\n{}\n", lines[0], lines[1], lines[3])).unwrap();
        assert!(verify_file(&path, &sk.verifying_key()).is_err());
        // Wrong key.
        std::fs::write(&path, &text).unwrap();
        assert!(verify_file(&path, &SigningKey::from_bytes(&[8u8; 32]).verifying_key()).is_err());
        // Truncating the tail still verifies as a chain; the monotonic counter catches it.
        std::fs::write(&path, format!("{}\n", lines[0])).unwrap();
        assert_eq!(verify_file(&path, &sk.verifying_key()).unwrap().len(), 1);
        // An empty log, or one whose first entry was cut off, is rejected.
        std::fs::write(&path, "").unwrap();
        assert!(verify_file(&path, &sk.verifying_key()).is_err());
        std::fs::write(&path, format!("{}\n", lines[1])).unwrap();
        assert!(verify_file(&path, &sk.verifying_key()).is_err());
        let _ = std::fs::remove_file(&path);
    }
}
