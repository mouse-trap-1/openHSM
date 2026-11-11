//! Persistent node state: principals, wallets (wrapped key blobs and
//! policies), the sealed KEK and break-glass share records.
//!
//! Nothing in this file is secret: wallet keys are AES-256-GCM blobs under
//! the cluster KEK and the KEK is sealed to this node's tamper secret. The
//! file's integrity is anchored in the signed audit chain (see `audit.rs`):
//! every change records the SHA-256 of the new file, and at boot the file
//! must match the last anchored hash.

use crate::chains::btc::Network;
use crate::policy::{Chain, Policy};
use crate::util::sha256;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Operators. Sensitive operations need a quorum of admins.
    Admin,
    /// Application servers. May request signatures, nothing else.
    Signer,
    /// Read-only access to status and the audit log.
    Auditor,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    pub role: Role,
    /// Ed25519 request-signing public key (hex).
    pub pubkey: String,
    /// SHA-256 of the principal's TLS client certificate (hex).
    pub cert_fp: String,
}

/// An AES-256-GCM record produced by the signing module.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Blob {
    pub iv: String,
    pub tag: String,
    pub ct: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wallet {
    pub id: String,
    pub label: String,
    pub chain: Chain,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub network: Option<Network>,
    /// Compressed SEC1 public key (hex).
    pub pubkey: String,
    pub address: String,
    pub blob: Blob,
    /// Blob under the incoming KEK during a rotation.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub new_blob: Option<Blob>,
    pub frozen: bool,
    pub created_ms: u64,
    pub policy: Policy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareRecord {
    pub x: u8,
    pub card: String,
    pub challenge: String,
    pub header: String,
    pub blob: Blob,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareSet {
    pub m: u8,
    pub n: u8,
    pub fp: String,
    pub records: Vec<ShareRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    pub cluster: String,
    pub node_id: String,
    /// Number of distinct admins that must sign a sensitive operation.
    pub quorum: usize,
    /// Number of signing nodes sharing each daily limit.
    pub lease_divisor: u64,
    pub principals: BTreeMap<String, Principal>,
    pub wallets: BTreeMap<String, Wallet>,
    pub sealed_kek: Option<Blob>,
    pub share_set: Option<ShareSet>,
    /// Nonces of accepted quorum operations, kept until they expire.
    pub used_admin_nonces: BTreeMap<String, u64>,
    /// Encryptions performed under the current KEK (SP 800-38D bound).
    pub kek_wrap_count: u64,
    pub ca_cert_pem: String,
}

/// Genesis document: the trust anchors a node is initialised with.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Genesis {
    pub cluster: String,
    pub quorum: usize,
    #[serde(default = "one")]
    pub lease_divisor: u64,
    pub ca_cert_pem: String,
    pub principals: BTreeMap<String, Principal>,
}

fn one() -> u64 {
    1
}

pub fn valid_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
}

impl Principal {
    pub fn validate(&self) -> Result<(), String> {
        crate::util::unhex_n::<32>(&self.pubkey).map_err(|_| "pubkey must be 32 bytes of hex".to_string())?;
        crate::util::unhex_n::<32>(&self.cert_fp).map_err(|_| "cert_fp must be 32 bytes of hex".to_string())?;
        Ok(())
    }
}

impl Genesis {
    pub fn validate(&self) -> Result<(), String> {
        if !valid_id(&self.cluster) {
            return Err("invalid cluster name".into());
        }
        for (id, p) in &self.principals {
            if !valid_id(id) {
                return Err(format!("invalid principal id {id:?}"));
            }
            p.validate()?;
        }
        let admins = self.principals.values().filter(|p| p.role == Role::Admin).count();
        if self.quorum < 1 || self.quorum > admins {
            return Err(format!("quorum {} is not satisfiable by {admins} admins", self.quorum));
        }
        if self.lease_divisor == 0 {
            return Err("lease_divisor must be at least 1".into());
        }
        Ok(())
    }
}

impl State {
    pub fn from_genesis(g: &Genesis, node_id: &str) -> State {
        State {
            cluster: g.cluster.clone(),
            node_id: node_id.to_string(),
            quorum: g.quorum,
            lease_divisor: g.lease_divisor,
            principals: g.principals.clone(),
            wallets: BTreeMap::new(),
            sealed_kek: None,
            share_set: None,
            used_admin_nonces: BTreeMap::new(),
            kek_wrap_count: 0,
            ca_cert_pem: g.ca_cert_pem.clone(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec_pretty(self).expect("state serialises")
    }

    pub fn hash_of(bytes: &[u8]) -> String {
        hex::encode(sha256(&[b"OPENHSM-STATE-v1", bytes]))
    }

    pub fn admins(&self) -> usize {
        self.principals.values().filter(|p| p.role == Role::Admin).count()
    }
}

/// Write a file durably: temporary file, fsync, rename.
pub fn write_atomic(path: &Path, data: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    let run = || -> std::io::Result<()> {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    };
    run().map_err(|e| format!("write {}: {e}", path.display()))
}

/// Create a file readable by the owner only.
pub fn write_private(path: &Path, data: &[u8]) -> Result<(), String> {
    write_atomic(path, data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    }
    Ok(())
}
