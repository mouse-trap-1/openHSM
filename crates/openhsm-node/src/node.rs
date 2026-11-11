//! The node: boot sequence, integrity anchoring and tamper response.

use crate::audit::{AuditLog, Body};
use crate::policy::{Ledger, Spend};
use crate::proto::ApiError;
use crate::secure::SecureWorld;
use crate::state::{write_atomic, write_private, Genesis, State};
use crate::util::{now_ms, random};
use ed25519_dalek::SigningKey;
use openhsm_hw::Hardware;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

const ID_AAD: &[u8] = b"OPENHSM-ID-v1";
const TLS_AAD: &[u8] = b"OPENHSM-TLS-v1";

#[derive(Debug, Clone)]
pub struct NodeOptions {
    /// fsync the audit log on every entry. Turn off only for benchmarks.
    pub audit_fsync: bool,
    /// Per-principal request rate (token bucket).
    pub rate_per_sec: f64,
    pub burst: f64,
}

impl Default for NodeOptions {
    fn default() -> Self {
        NodeOptions { audit_fsync: true, rate_per_sec: 200.0, burst: 400.0 }
    }
}

pub(crate) struct ReplayEntry {
    pub ts: u64,
    pub payload_hash: [u8; 32],
    pub response: Option<Vec<u8>>,
}

pub(crate) struct Bucket {
    pub tokens: f64,
    pub last_ms: u64,
}

pub struct Node {
    pub dir: PathBuf,
    pub sw: SecureWorld,
    pub state: State,
    pub audit: AuditLog,
    pub ledger: Ledger,
    pub opts: NodeOptions,
    pub tampered: bool,
    pub boot_ms: u64,
    pub identity_pub: [u8; 32],
    pub(crate) last_ts: u64,
    pub(crate) replay: HashMap<(String, String), ReplayEntry>,
    pub(crate) buckets: HashMap<String, Bucket>,
    pub(crate) auth_fail_last_ms: u64,
    pub(crate) auth_fail_suppressed: u64,
}

impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material.
        f.debug_struct("Node").field("node", &self.state.node_id).field("audit_seq", &self.audit.seq).finish_non_exhaustive()
    }
}

/// What `init` hands back to the operator.
#[derive(Debug)]
pub struct InitSummary {
    pub identity_pubkey: String,
    pub csr_path: PathBuf,
}

fn state_path(dir: &Path) -> PathBuf {
    dir.join("state.json")
}
fn state_new_path(dir: &Path) -> PathBuf {
    dir.join("state.json.new")
}
fn audit_path(dir: &Path) -> PathBuf {
    dir.join("audit.log")
}

impl Node {
    /// First-time initialisation of a node from a genesis document.
    ///
    /// Brings up the session with the enclosure, generates the node identity key and the TLS key inside the secure
    /// world (both sealed to the tamper secret), writes a certificate signing
    /// request for the operators' CA, and starts the audit chain.
    pub fn init(dir: &Path, genesis: &Genesis, node_id: &str, sans: &[String], hw: Box<dyn Hardware>) -> Result<InitSummary, String> {
        genesis.validate()?;
        if !crate::state::valid_id(node_id) {
            return Err("invalid node id".into());
        }
        if state_path(dir).exists() {
            return Err("this data directory is already initialised".into());
        }
        fs::create_dir_all(dir.join("tls")).map_err(|e| e.to_string())?;
        fs::create_dir_all(dir.join("cardslot")).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
        }
        let mut sw = SecureWorld::start(hw)?;

        // Node identity (Ed25519), sealed at rest.
        let seed = zeroize::Zeroizing::new(random::<32>()?);
        let identity = SigningKey::from_bytes(&seed);
        write_private(&dir.join("identity.sealed"), &sw.seal(ID_AAD, &seed[..])?)?;
        let identity_pubkey = hex::encode(identity.verifying_key().to_bytes());
        write_atomic(&dir.join("identity.pub"), identity_pubkey.as_bytes())?;

        // TLS key pair and CSR. The private key never touches disk in the clear.
        let key = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
        let mut params = rcgen::CertificateParams::new(sans.to_vec()).map_err(|e| e.to_string())?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CommonName, node_id);
        params.distinguished_name.push(rcgen::DnType::OrganizationName, genesis.cluster.as_str());
        let csr = params.serialize_request(&key).map_err(|e| e.to_string())?;
        let csr_path = dir.join("tls").join("node.csr");
        write_atomic(&csr_path, csr.pem().map_err(|e| e.to_string())?.as_bytes())?;
        let key_pem = zeroize::Zeroizing::new(key.serialize_pem());
        write_private(&dir.join("tls").join("node.key.sealed"), &sw.seal(TLS_AAD, key_pem.as_bytes())?)?;
        write_atomic(&dir.join("tls").join("ca.crt"), genesis.ca_cert_pem.as_bytes())?;

        // State and the first audit entry, which anchors the state hash.
        let state = State::from_genesis(genesis, node_id);
        let bytes = state.to_bytes();
        write_atomic(&state_path(dir), &bytes)?;
        let mut audit = AuditLog::create(&audit_path(dir))?;
        audit.append(
            &identity,
            now_ms(),
            node_id,
            "system",
            "node_init",
            true,
            json!({"cluster": genesis.cluster, "quorum": genesis.quorum, "identity": identity_pubkey, "version": env!("CARGO_PKG_VERSION")}),
            Some(State::hash_of(&bytes)),
        )?;
        // The first entry must start a fresh counter: a re-used enclosure
        // would otherwise disagree with the new log.
        if sw.hw.counter_increment().map_err(|e| e.0)? != 1 {
            return Err("the tamper supervisor's counter is not fresh; provision a new enclosure for a new node".into());
        }
        Ok(InitSummary { identity_pubkey, csr_path })
    }

    /// Boot an initialised node. Every integrity check must pass or the node
    /// refuses to start.
    pub fn boot(dir: &Path, opts: NodeOptions, mut hw: Box<dyn Hardware>) -> Result<Node, String> {
        if let Some(t) = hw.tamper_status().map_err(|e| e.0)? {
            return Err(format!(
                "TAMPERED: sensor '{}' tripped at {}. The tamper secret is destroyed; re-provision this node and re-enrol it.",
                t.sensor, t.ts
            ));
        }
        let mut sw = SecureWorld::start(hw)?;

        let sealed_id = fs::read(dir.join("identity.sealed")).map_err(|e| format!("identity key: {e}"))?;
        let seed = sw.unseal(ID_AAD, &sealed_id)?;
        let seed: [u8; 32] = seed[..].try_into().map_err(|_| "identity key has the wrong length".to_string())?;
        let identity = SigningKey::from_bytes(&seed);
        let identity_pub = identity.verifying_key().to_bytes();

        // Audit chain: every signature, every link, and the rollback anchor.
        let (mut audit, entries) = AuditLog::open(&audit_path(dir), &identity.verifying_key())?;
        audit.set_fsync(opts.audit_fsync);
        let counter = sw.hw.counter().map_err(|e| e.0)?;
        if audit.seq == counter + 1 {
            sw.hw.counter_increment().map_err(|e| e.0)?; // crash between the append and the counter step
        } else if audit.seq != counter {
            return Err(format!(
                "INTEGRITY: audit log ends at entry {} but the tamper supervisor's monotonic counter is {counter}. The log has been truncated or replaced.",
                audit.seq
            ));
        }

        // State file must match the last hash anchored in the audit chain.
        let anchored = entries.iter().rev().find_map(|e| e.state.clone()).ok_or("INTEGRITY: no state hash is anchored in the audit log")?;
        let mut bytes = fs::read(state_path(dir)).map_err(|e| format!("state file: {e}"))?;
        if State::hash_of(&bytes) != anchored {
            // A commit may have been interrupted after the audit entry was written.
            match fs::read(state_new_path(dir)) {
                Ok(newer) if State::hash_of(&newer) == anchored => {
                    fs::rename(state_new_path(dir), state_path(dir)).map_err(|e| e.to_string())?;
                    bytes = newer;
                }
                _ => return Err("INTEGRITY: state file does not match the hash anchored in the audit log (modified or rolled back)".into()),
            }
        }
        let _ = fs::remove_file(state_new_path(dir));
        let state: State = serde_json::from_slice(&bytes).map_err(|e| format!("state file: {e}"))?;

        sw.identity = Some(identity);
        let mut node = Node {
            dir: dir.to_path_buf(),
            sw,
            state,
            audit,
            ledger: Ledger::default(),
            opts,
            tampered: false,
            boot_ms: 0,
            identity_pub,
            last_ts: entries.last().map(|e| e.ts).unwrap_or(0),
            replay: HashMap::new(),
            buckets: HashMap::new(),
            auth_fail_last_ms: 0,
            auth_fail_suppressed: 0,
        };
        node.rebuild_ledger(&entries);
        drop(entries);

        // Restore the KEK from the sealed copy, if this node has one.
        let mut kek = "absent";
        if let Some(sealed) = node.state.sealed_kek.clone() {
            kek = match node.sw.kek_unseal(&sealed) {
                Ok(()) => "unsealed",
                Err(_) => "unseal_failed",
            };
        }
        // A rotation does not survive a restart: the incoming KEK was volatile.
        if node.state.wallets.values().any(|w| w.new_blob.is_some()) {
            let mut st = node.state.clone();
            st.wallets.values_mut().for_each(|w| w.new_blob = None);
            node.commit_state(st, "system", "rotation_aborted", json!({"reason": "restart during rotation"})).map_err(|e| e.message)?;
        }
        node.boot_ms = node.now();
        node.log("system", "node_boot", true, json!({"kek": kek, "version": env!("CARGO_PKG_VERSION")})).map_err(|e| e.message)?;
        Ok(node)
    }

    /// Daily totals and signing rates are derived from the audit chain, so a
    /// restart cannot reset them.
    fn rebuild_ledger(&mut self, entries: &[Body]) {
        for e in entries.iter().filter(|e| e.ok) {
            let (Some(wallet), Some(spends)) = (e.detail.get("wallet").and_then(Value::as_str), e.detail.get("spends")) else { continue };
            let Ok(spends) = serde_json::from_value::<Vec<Spend>>(spends.clone()) else { continue };
            let sigs = e.detail.get("signatures").and_then(Value::as_u64).unwrap_or(1) as usize;
            self.ledger.commit(e.ts, wallet, &spends, sigs);
        }
    }

    /// Node time: wall clock that never runs backwards across entries.
    pub fn now(&mut self) -> u64 {
        self.last_ts = now_ms().max(self.last_ts);
        self.last_ts
    }

    fn internal(m: String) -> ApiError {
        ApiError::new("internal", m)
    }

    fn append(&mut self, actor: &str, event: &str, ok: bool, detail: Value, state: Option<String>) -> Result<u64, ApiError> {
        let ts = self.now();
        let node_id = self.state.node_id.clone();
        let id = self.sw.identity.as_ref().ok_or_else(|| ApiError::new("tamper", "node identity key is gone"))?;
        let seq = self.audit.append(id, ts, &node_id, actor, event, ok, detail, state).map_err(Self::internal)?;
        self.sw.hw.counter_increment().map_err(|e| Self::internal(e.0))?;
        Ok(seq)
    }

    /// Write an audit entry. Nothing is released to a caller before the
    /// entry describing it is durable.
    pub fn log(&mut self, actor: &str, event: &str, ok: bool, detail: Value) -> Result<u64, ApiError> {
        self.append(actor, event, ok, detail, None)
    }

    /// Replace the state: write the new file, anchor its hash in the audit
    /// chain, then swap it in.
    pub fn commit_state(&mut self, new: State, actor: &str, event: &str, detail: Value) -> Result<(), ApiError> {
        self.commit_state_with(new, actor, event, true, detail)
    }

    pub(crate) fn commit_state_with(&mut self, new: State, actor: &str, event: &str, ok: bool, detail: Value) -> Result<(), ApiError> {
        let bytes = new.to_bytes();
        write_atomic(&state_new_path(&self.dir), &bytes).map_err(Self::internal)?;
        self.append(actor, event, ok, detail, Some(State::hash_of(&bytes)))?;
        fs::rename(state_new_path(&self.dir), state_path(&self.dir)).map_err(|e| Self::internal(e.to_string()))?;
        self.state = new;
        Ok(())
    }

    /// Check the supervisor's kill line. The hardware has already acted (S is
    /// erased, the signing module is wiped); the SoC records the event with
    /// its identity key and then drops every key it holds.
    pub fn poll_tamper(&mut self) {
        if self.tampered {
            return;
        }
        if let Ok(Some(trip)) = self.sw.hw.tamper_status() {
            let _ = self.log("system", "tamper", true, json!({"sensor": trip.sensor, "tripped_ms": trip.ts}));
            self.sw.drop_keys();
            self.tampered = true;
            self.replay.clear();
        }
    }

    /// The TLS private key (PEM), unsealed for the listener.
    pub fn tls_key_pem(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
        let sealed = fs::read(self.dir.join("tls").join("node.key.sealed")).map_err(|e| format!("TLS key: {e}"))?;
        self.sw.unseal(TLS_AAD, &sealed)
    }

    pub fn tls_cert_pem(&self) -> Result<Vec<u8>, String> {
        fs::read(self.dir.join("tls").join("node.crt"))
            .map_err(|_| "tls/node.crt is missing: have the operators' CA sign tls/node.csr (hsmctl pki sign-csr)".to_string())
    }
}
