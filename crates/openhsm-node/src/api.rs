//! Request authentication, authorisation and the API methods.
//!
//! Order of checks for every request:
//!
//! 1. every signature on the frame verifies against a registered principal;
//! 2. the first signer's registered TLS certificate is the one presented on
//!    this connection (binds the request key to the channel);
//! 3. cluster name, protocol version, freshness and replay;
//! 4. role, and for sensitive operations a quorum of distinct admins;
//! 5. rate limit;
//! 6. the method itself, which writes an audit entry before returning.

use crate::cards;
use crate::chains::btc::{self, BtcTx, BtcTxRequest, Network};
use crate::chains::eth::{self, EthTx, EthTxRequest};
use crate::node::{Bucket, Node, ReplayEntry};
use crate::policy::{Chain, Policy, Spend};
use crate::proto::{verify_payload, ApiError, Frame, Payload, MAX_ADMIN_VALIDITY_MS, MAX_SIGS, SKEW_MS};
use crate::secure::{KekTransfer, SignerError};
use crate::state::{valid_id, Blob, Principal, Role, ShareRecord, ShareSet, State, Wallet};
use crate::util::{hash160, keccak256, random, sha256, unhex, unhex_n};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use openhsm_signer::crypto::ct_eq;
use openhsm_signer::err;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

/// AES-GCM with random 96-bit IVs: stay far below the SP 800-38D bound of
/// 2^32 invocations per key. Rotation is required beyond this.
const MAX_KEK_WRAPS: u64 = 1 << 31;
const MAX_REPLAY_ENTRIES: usize = 200_000;

type R<T> = Result<T, ApiError>;

fn bad(m: impl Into<String>) -> ApiError {
    ApiError::new("bad_request", m)
}
fn unauth() -> ApiError {
    // One message for every authentication failure: no oracle for which
    // check failed or whether a principal exists.
    ApiError::new("unauthenticated", "request could not be authenticated")
}
fn param<T: DeserializeOwned>(v: &Value) -> R<T> {
    serde_json::from_value(v.clone()).map_err(|e| bad(format!("invalid parameters: {e}")))
}
fn ceremony_off() -> ApiError {
    ApiError::new("ceremony_required", "the ceremony key-switch on this node is off; an operator must turn it at the node")
}
fn signer_err(e: SignerError) -> ApiError {
    match e {
        SignerError::Code(err::TAMPER) => ApiError::new("tamper", "signing module reports tamper"),
        SignerError::Code(err::NO_KEK) => ApiError::new("no_kek", "no KEK is loaded on this node"),
        other => ApiError::new("signer_error", other.message()),
    }
}

struct Spec {
    roles: &'static [Role],
    quorum: bool,
}

const ANY: &[Role] = &[Role::Admin, Role::Signer, Role::Auditor];
const SIGNER: &[Role] = &[Role::Signer];
const READ: &[Role] = &[Role::Admin, Role::Auditor];
const ADMIN: &[Role] = &[Role::Admin];

fn spec(method: &str) -> Option<Spec> {
    let (roles, quorum) = match method {
        "status" | "wallet_list" | "wallet_get" => (ANY, false),
        "eth_sign_transaction" | "btc_sign_transaction" | "eth_sign_message" | "sign_digest" => (SIGNER, false),
        "audit_head" | "audit_tail" => (READ, false),
        "kek_fingerprint" | "enrol_begin" | "kek_import" | "rotate_import" | "rotate_rewrap" | "snapshot_export" | "wallet_freeze" => (ADMIN, false),
        "kek_generate" | "kek_export" | "kek_erase" | "rotate_begin" | "rotate_export" | "rotate_promote" | "wallet_create" | "policy_set"
        | "wallet_unfreeze" | "principal_add" | "principal_remove" | "ceremony_split" | "ceremony_restore" | "snapshot_import" => (ADMIN, true),
        _ => return None,
    };
    Some(Spec { roles, quorum })
}

/// Portable copy of the replicated data: wrapped wallet blobs, policies and
/// share records. Contains no secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub cluster: String,
    pub exported_ms: u64,
    pub kek_fp: Option<String>,
    pub wallets: BTreeMap<String, Wallet>,
    pub share_set: Option<ShareSet>,
}

impl Node {
    /// Handle one request frame from a peer whose TLS client certificate has
    /// SHA-256 fingerprint `peer_fp`. Always returns a response document.
    pub fn handle_frame(&mut self, raw: &[u8], peer_fp: &[u8; 32]) -> Vec<u8> {
        match self.process(raw, peer_fp) {
            Ok(bytes) => bytes,
            Err(e) => error_response(&e),
        }
    }

    fn note_auth_failure(&mut self, claimed: &str, peer_fp: &[u8; 32]) {
        // At most one audit entry per second, so failed attempts cannot be
        // used to flood the log.
        let now = self.now();
        if now.saturating_sub(self.auth_fail_last_ms) < 1000 {
            self.auth_fail_suppressed += 1;
            return;
        }
        self.auth_fail_last_ms = now;
        let suppressed = std::mem::take(&mut self.auth_fail_suppressed);
        let claimed: String = claimed.chars().filter(|c| c.is_ascii_graphic()).take(64).collect();
        let _ = self.log("unauthenticated", "auth_failure", false, json!({"claimed": claimed, "cert_fp": hex::encode(peer_fp), "suppressed": suppressed}));
    }

    fn process(&mut self, raw: &[u8], peer_fp: &[u8; 32]) -> R<Vec<u8>> {
        self.poll_tamper();
        if self.tampered {
            return Err(ApiError::new("tamper", "tamper response has zeroised this node"));
        }
        let frame: Frame = serde_json::from_slice(raw).map_err(|_| bad("malformed frame"))?;
        if frame.sigs.is_empty() || frame.sigs.len() > MAX_SIGS {
            return Err(unauth());
        }

        // 1. Every signature must verify; ids must be distinct.
        let mut seen = BTreeSet::new();
        let mut admin_sigs = 0usize;
        let mut all_ok = true;
        for s in &frame.sigs {
            match self.state.principals.get(&s.id) {
                Some(p) if seen.insert(s.id.as_str()) && verify_payload(&p.pubkey, &frame.payload, &s.sig) => {
                    if p.role == Role::Admin {
                        admin_sigs += 1;
                    }
                }
                _ => all_ok = false,
            }
        }
        let sender_id = frame.sigs[0].id.clone();
        // 2. Channel binding of the first signer.
        let sender = self.state.principals.get(&sender_id).cloned();
        let bound = sender.as_ref().and_then(|p| unhex_n::<32>(&p.cert_fp).ok()).is_some_and(|fp| ct_eq(&fp, peer_fp));
        let (Some(sender), true, true) = (sender, bound, all_ok) else {
            self.note_auth_failure(&sender_id, peer_fp);
            return Err(unauth());
        };

        // 3. Envelope.
        let payload: Payload = serde_json::from_str(&frame.payload).map_err(|e| bad(format!("malformed payload: {e}")))?;
        if payload.v != 1 {
            return Err(bad("unsupported protocol version"));
        }
        if payload.cluster != self.state.cluster {
            return Err(bad("request is addressed to a different cluster"));
        }
        if payload.node.as_ref().is_some_and(|n| *n != self.state.node_id) {
            return Err(bad("request is addressed to a different node"));
        }
        if payload.nonce.len() != 32 || !payload.nonce.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(bad("nonce must be 16 bytes of hex"));
        }
        let Some(spec) = spec(&payload.method) else {
            return Err(ApiError::new("not_found", "unknown method"));
        };
        let now = self.now();

        // 4. Authorisation.
        if !spec.roles.contains(&sender.role) {
            let _ = self.log(&sender_id, "forbidden", false, json!({"method": payload.method}));
            return Err(ApiError::new("forbidden", "this principal's role may not call this method"));
        }
        if spec.quorum {
            let exp = payload.exp.ok_or_else(|| bad("a quorum operation needs an expiry (exp)"))?;
            if payload.node.is_none() {
                return Err(bad("a quorum operation must name the node it is for"));
            }
            if payload.ts > now + SKEW_MS || exp < payload.ts || exp - payload.ts > MAX_ADMIN_VALIDITY_MS {
                return Err(ApiError::new("stale", "validity window of the operation is not acceptable"));
            }
            if now > exp {
                return Err(ApiError::new("stale", "operation has expired"));
            }
            if admin_sigs < self.state.quorum {
                let _ = self.log(&sender_id, "quorum_missing", false, json!({"method": payload.method, "have": admin_sigs, "need": self.state.quorum}));
                return Err(ApiError::new("quorum_required", format!("{} admin signatures required, {admin_sigs} present", self.state.quorum)));
            }
            if self.state.used_admin_nonces.contains_key(&payload.nonce) {
                return Err(ApiError::new("replay", "this operation has already been submitted"));
            }
        } else {
            if payload.ts + SKEW_MS < now || payload.ts > now + SKEW_MS {
                return Err(ApiError::new("stale", "request timestamp is outside the accepted window"));
            }
            if payload.ts < self.boot_ms {
                // The replay cache is volatile; anything signed before boot
                // could be a replay from before the restart.
                return Err(ApiError::new("stale", "request predates this node's boot; sign it again"));
            }
            let key = (sender_id.clone(), payload.nonce.clone());
            let h = sha256(&[frame.payload.as_bytes()]);
            if let Some(prev) = self.replay.get(&key) {
                return match &prev.response {
                    // Idempotent retry: same request, same answer, nothing signed twice.
                    Some(resp) if prev.payload_hash == h => Ok(mark_replayed(resp)),
                    _ => Err(ApiError::new("replay", "nonce already used")),
                };
            }
        }

        // 5. Rate limit per principal.
        let (rate, burst) = (self.opts.rate_per_sec, self.opts.burst);
        let b = self.buckets.entry(sender_id.clone()).or_insert(Bucket { tokens: burst, last_ms: now });
        b.tokens = (b.tokens + (now.saturating_sub(b.last_ms)) as f64 * rate / 1000.0).min(burst);
        b.last_ms = now;
        if b.tokens < 1.0 {
            return Err(ApiError::new("rate_limited", "too many requests"));
        }
        b.tokens -= 1.0;

        // 6. Execute.
        let approvers: Vec<String> = frame.sigs.iter().map(|s| s.id.clone()).collect();
        let result = if spec.quorum { self.run_quorum(&sender_id, &approvers, &payload, now) } else { self.run_plain(&sender_id, &payload, now) };
        let bytes = match &result {
            Ok(v) => serde_json::to_vec(&json!({"ok": true, "result": v})).unwrap_or_default(),
            Err(e) => error_response(e),
        };
        if !spec.quorum {
            if self.replay.len() >= MAX_REPLAY_ENTRIES {
                self.replay.retain(|_, e| e.ts + 2 * SKEW_MS >= now);
            }
            if self.replay.len() < MAX_REPLAY_ENTRIES {
                let key = (sender_id, payload.nonce.clone());
                self.replay.insert(key, ReplayEntry { ts: payload.ts, payload_hash: sha256(&[frame.payload.as_bytes()]), response: Some(bytes.clone()) });
            } else {
                // Cache full: fail closed rather than lose replay protection.
                return Err(ApiError::new("rate_limited", "replay cache is full"));
            }
        }
        Ok(bytes)
    }

    // ------------------------------------------------------------ plain ----

    fn run_plain(&mut self, actor: &str, p: &Payload, now: u64) -> R<Value> {
        match p.method.as_str() {
            "status" => Ok(self.status_doc()),
            "wallet_list" => Ok(Value::Array(self.state.wallets.values().map(wallet_public).collect())),
            "wallet_get" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct P {
                    wallet: String,
                }
                let q: P = param(&p.params)?;
                let w = self.state.wallets.get(&q.wallet).ok_or_else(|| ApiError::new("not_found", "no such wallet"))?;
                let mut v = wallet_public(w);
                v["policy"] = serde_json::to_value(&w.policy).unwrap_or(Value::Null);
                Ok(v)
            }
            "eth_sign_transaction" => self.eth_sign_transaction(actor, &p.params, now),
            "btc_sign_transaction" => self.btc_sign_transaction(actor, &p.params, now),
            "eth_sign_message" => self.eth_sign_message(actor, &p.params, now),
            "sign_digest" => self.sign_digest(actor, &p.params, now),
            "audit_head" => Ok(json!({"seq": self.audit.seq, "hash": hex::encode(self.audit.head), "identity": hex::encode(self.identity_pub)})),
            "audit_tail" => self.audit_tail(&p.params),
            "kek_fingerprint" => {
                let fp = self.sw.kek_fingerprint().map_err(signer_err)?;
                Ok(json!({"fingerprint": hex::encode(fp)}))
            }
            "enrol_begin" => {
                let (x, y) = self.sw.enrol_pubkey().map_err(signer_err)?;
                let fp = hex::encode(sha256(&[&x, &y]));
                self.log(actor, "enrol_begin", true, json!({"enrol_fp": fp}))?;
                Ok(json!({"enrol_x": hex::encode(x), "enrol_y": hex::encode(y), "enrol_fp": fp, "node": self.state.node_id}))
            }
            "kek_import" | "rotate_import" => {
                let t: KekTransfer = param(&p.params)?;
                if !self.sw.ceremony_enabled() {
                    return Err(ceremony_off());
                }
                if p.method == "kek_import" {
                    self.sw.kek_import(&t).map_err(signer_err)?;
                    let mut st = self.state.clone();
                    st.sealed_kek = Some(self.sw.kek_seal().map_err(signer_err)?);
                    st.kek_wrap_count = st.wallets.len() as u64;
                    let fp = hex::encode(self.sw.kek_fingerprint().map_err(signer_err)?);
                    self.commit_state(st, actor, "kek_import", json!({"kek_fp": fp}))?;
                    Ok(json!({"kek_fp": fp}))
                } else {
                    self.sw.kek_new_import(&t).map_err(signer_err)?;
                    self.log(actor, "rotate_import", true, json!({}))?;
                    Ok(json!({"rotation_pending": true}))
                }
            }
            "rotate_rewrap" => {
                if !self.sw.rotation_pending() {
                    return Err(bad("no rotation in progress"));
                }
                let mut st = self.state.clone();
                let mut n = 0u64;
                for w in st.wallets.values_mut().filter(|w| w.new_blob.is_none()) {
                    let wid: [u8; 16] = unhex_n(&w.id).map_err(bad)?;
                    w.new_blob = Some(self.sw.rewrap(&wid, &w.blob).map_err(signer_err)?);
                    n += 1;
                }
                self.commit_state(st, actor, "rotate_rewrap", json!({"rewrapped": n}))?;
                Ok(json!({"rewrapped": n}))
            }
            "snapshot_export" => {
                let kek_fp = self.sw.kek_fingerprint().ok().map(hex::encode);
                let snap = Snapshot {
                    cluster: self.state.cluster.clone(),
                    exported_ms: now,
                    kek_fp,
                    wallets: self.state.wallets.clone(),
                    share_set: self.state.share_set.clone(),
                };
                self.log(actor, "snapshot_export", true, json!({"wallets": snap.wallets.len()}))?;
                serde_json::to_value(snap).map_err(|e| ApiError::new("internal", e.to_string()))
            }
            "wallet_freeze" => {
                // Any single admin can stop a wallet; un-freezing needs a quorum.
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct P {
                    wallet: String,
                }
                let q: P = param(&p.params)?;
                let mut st = self.state.clone();
                st.wallets.get_mut(&q.wallet).ok_or_else(|| ApiError::new("not_found", "no such wallet"))?.frozen = true;
                self.commit_state(st, actor, "wallet_freeze", json!({"wallet": q.wallet}))?;
                Ok(json!({"wallet": q.wallet, "frozen": true}))
            }
            _ => Err(ApiError::new("not_found", "unknown method")),
        }
    }

    fn status_doc(&mut self) -> Value {
        json!({
            "node": self.state.node_id,
            "cluster": self.state.cluster,
            "version": env!("CARGO_PKG_VERSION"),
            "signer_protocol": format!("{:#04x}", openhsm_signer::VERSION),
            "signer_status": self.sw.status(),
            "kek_loaded": self.sw.kek_loaded(),
            "rotation_pending": self.sw.rotation_pending(),
            "ceremony_switch": self.sw.ceremony_enabled(),
            "shares_recorded": self.state.share_set.as_ref().map(|s| format!("{}-of-{}", s.m, s.n)),
            "wallets": self.state.wallets.len(),
            "principals": self.state.principals.len(),
            "quorum": self.state.quorum,
            "audit_seq": self.audit.seq,
            "audit_head": hex::encode(self.audit.head),
            "identity": hex::encode(self.identity_pub),
            "tamper": self.tampered,
            "boot_ms": self.boot_ms,
        })
    }

    fn audit_tail(&mut self, params: &Value) -> R<Value> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct P {
            #[serde(default)]
            from_seq: u64,
            #[serde(default)]
            limit: Option<usize>,
        }
        let q: P = param(params)?;
        let limit = q.limit.unwrap_or(100).min(1000);
        let text = std::fs::read_to_string(self.audit.path()).map_err(|e| ApiError::new("internal", e.to_string()))?;
        let lines: Vec<&str> = text.lines().collect();
        let start = if q.from_seq == 0 { lines.len().saturating_sub(limit) } else { (q.from_seq as usize - 1).min(lines.len()) };
        let slice: Vec<&str> = lines[start..].iter().take(limit).copied().collect();
        Ok(json!({"lines": slice, "identity": hex::encode(self.identity_pub)}))
    }

    // ---------------------------------------------------------- signing ----

    fn wallet_for(&self, id: &str, chain: Chain) -> R<Wallet> {
        let w = self.state.wallets.get(id).ok_or_else(|| ApiError::new("not_found", "no such wallet"))?;
        if w.chain != chain {
            return Err(bad("wallet belongs to a different chain"));
        }
        if w.frozen {
            return Err(ApiError::new("frozen", "wallet is frozen"));
        }
        Ok(w.clone())
    }

    fn deny<T>(&mut self, actor: &str, method: &str, wallet: &str, reason: String) -> R<T> {
        self.log(actor, "policy_denied", false, json!({"method": method, "wallet": wallet, "reason": reason}))?;
        Err(ApiError::new("policy_denied", reason))
    }

    /// Ask the module for a signature, then check it against the wallet's
    /// recorded public key and derive the recovery id.
    fn sign_checked(&mut self, w: &Wallet, digest: &[u8; 32]) -> R<([u8; 32], [u8; 32], u8)> {
        let wid: [u8; 16] = unhex_n(&w.id).map_err(bad)?;
        let (r, s) = self.sw.sign(&wid, &w.blob, digest).map_err(signer_err)?;
        let mismatch = || ApiError::new("signer_error", "signature does not verify against the wallet's public key");
        let pk = unhex(&w.pubkey).map_err(|_| mismatch())?;
        let vk = VerifyingKey::from_sec1_bytes(&pk).map_err(|_| mismatch())?;
        let sig = Signature::from_scalars(r, s).map_err(|_| mismatch())?;
        for recid in 0..2u8 {
            let id = RecoveryId::from_byte(recid).ok_or_else(mismatch)?;
            if VerifyingKey::recover_from_prehash(digest, &sig, id).is_ok_and(|rec| rec == vk) {
                return Ok((r, s, recid));
            }
        }
        Err(mismatch())
    }

    fn sign_failed<T>(&mut self, actor: &str, method: &str, wallet: &str, e: ApiError) -> R<T> {
        let _ = self.log(actor, "sign_failed", false, json!({"method": method, "wallet": wallet, "error": e.message}));
        Err(e)
    }

    fn eth_sign_transaction(&mut self, actor: &str, params: &Value, now: u64) -> R<Value> {
        const M: &str = "eth_sign_transaction";
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct P {
            wallet: String,
            tx: EthTxRequest,
        }
        let q: P = param(params)?;
        let w = self.wallet_for(&q.wallet, Chain::Ethereum)?;
        let tx = EthTx::parse(&q.tx).map_err(bad)?;
        let spends = match w.policy.check_eth(&tx) {
            Ok(s) => s,
            Err(reason) => return self.deny(actor, M, &w.id, reason),
        };
        if let Err(reason) = self.ledger.check(now, &w.id, &spends, w.policy.max_signatures_per_minute, 1, self.state.lease_divisor) {
            return self.deny(actor, M, &w.id, reason);
        }
        let digest = tx.sighash();
        let (r, s, recid) = match self.sign_checked(&w, &digest) {
            Ok(v) => v,
            Err(e) => return self.sign_failed(actor, M, &w.id, e),
        };
        let raw = tx.encode_signed(recid, &r, &s);
        let tx_hash = format!("0x{}", hex::encode(keccak256(&raw)));
        self.log(
            actor,
            M,
            true,
            json!({
                "wallet": w.id, "chain_id": tx.chain_id, "nonce": tx.nonce,
                "to": tx.to.map(|a| eth::to_checksum(&a)), "value": tx.value, "data_len": tx.data.len(),
                "tx_hash": tx_hash, "spends": spends, "signatures": 1,
            }),
        )?;
        self.ledger.commit(now, &w.id, &spends, 1);
        Ok(json!({
            "raw_tx": format!("0x{}", hex::encode(&raw)), "tx_hash": tx_hash, "from": w.address,
            "y_parity": recid, "r": format!("0x{}", hex::encode(r)), "s": format!("0x{}", hex::encode(s)),
        }))
    }

    fn eth_sign_message(&mut self, actor: &str, params: &Value, now: u64) -> R<Value> {
        const M: &str = "eth_sign_message";
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct P {
            wallet: String,
            message: String,
        }
        let q: P = param(params)?;
        let w = self.wallet_for(&q.wallet, Chain::Ethereum)?;
        let msg = unhex(&q.message).map_err(bad)?;
        if msg.len() > 64 * 1024 {
            return Err(bad("message too large"));
        }
        if !w.policy.allow_message_signing {
            return self.deny(actor, M, &w.id, "message signing is not permitted for this wallet".into());
        }
        if let Err(reason) = self.ledger.check(now, &w.id, &[], w.policy.max_signatures_per_minute, 1, 1) {
            return self.deny(actor, M, &w.id, reason);
        }
        let digest = eth::personal_message_hash(&msg);
        let (r, s, recid) = match self.sign_checked(&w, &digest) {
            Ok(v) => v,
            Err(e) => return self.sign_failed(actor, M, &w.id, e),
        };
        self.log(actor, M, true, json!({"wallet": w.id, "digest": hex::encode(digest), "spends": [], "signatures": 1}))?;
        self.ledger.commit(now, &w.id, &[], 1);
        let mut sig = r.to_vec();
        sig.extend(s);
        sig.push(27 + recid);
        Ok(json!({"signature": format!("0x{}", hex::encode(sig)), "address": w.address}))
    }

    fn sign_digest(&mut self, actor: &str, params: &Value, now: u64) -> R<Value> {
        const M: &str = "sign_digest";
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct P {
            wallet: String,
            digest: String,
        }
        let q: P = param(params)?;
        let w = self.state.wallets.get(&q.wallet).cloned().ok_or_else(|| ApiError::new("not_found", "no such wallet"))?;
        if w.frozen {
            return Err(ApiError::new("frozen", "wallet is frozen"));
        }
        let digest: [u8; 32] = unhex_n(&q.digest).map_err(bad)?;
        if !w.policy.allow_raw_digest {
            return self.deny(actor, M, &w.id, "raw digest signing (blind signing) is not permitted for this wallet".into());
        }
        if let Err(reason) = self.ledger.check(now, &w.id, &[], w.policy.max_signatures_per_minute, 1, 1) {
            return self.deny(actor, M, &w.id, reason);
        }
        let (r, s, recid) = match self.sign_checked(&w, &digest) {
            Ok(v) => v,
            Err(e) => return self.sign_failed(actor, M, &w.id, e),
        };
        self.log(actor, M, true, json!({"wallet": w.id, "digest": hex::encode(digest), "spends": [], "signatures": 1}))?;
        self.ledger.commit(now, &w.id, &[], 1);
        Ok(json!({"r": hex::encode(r), "s": hex::encode(s), "recovery_id": recid}))
    }

    fn btc_sign_transaction(&mut self, actor: &str, params: &Value, now: u64) -> R<Value> {
        const M: &str = "btc_sign_transaction";
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct P {
            wallet: String,
            tx: BtcTxRequest,
        }
        let q: P = param(params)?;
        let w = self.wallet_for(&q.wallet, Chain::Bitcoin)?;
        let net = w.network.ok_or_else(|| ApiError::new("internal", "wallet has no network"))?;
        let tx = BtcTx::parse(net, &q.tx).map_err(bad)?;
        let pk: [u8; 33] = unhex_n(&w.pubkey).map_err(bad)?;
        let pkh = hash160(&pk);
        let own_script = btc::p2wpkh_script(&pkh);
        let n = tx.ins.len();
        let spends: Vec<Spend> = match w.policy.check_btc(net, &tx, &own_script) {
            Ok(s) => s,
            Err(reason) => return self.deny(actor, M, &w.id, reason),
        };
        if let Err(reason) = self.ledger.check(now, &w.id, &spends, w.policy.max_signatures_per_minute, n, self.state.lease_divisor) {
            return self.deny(actor, M, &w.id, reason);
        }
        let mut witness = Vec::with_capacity(n);
        for idx in 0..n {
            let digest = tx.sighash_p2wpkh(idx, &pkh);
            match self.sign_checked(&w, &digest) {
                Ok((r, s, _)) => witness.push((btc::der_encode(&r, &s), pk)),
                Err(e) => return self.sign_failed(actor, M, &w.id, e),
            }
        }
        let raw = tx.serialize(Some(&witness));
        let txid = tx.txid();
        let fee = tx.fee().map_err(bad)?;
        let vsize = (tx.serialize(None).len() * 3 + raw.len()).div_ceil(4);
        self.log(
            actor,
            M,
            true,
            json!({"wallet": w.id, "network": net, "txid": txid, "inputs": n, "outputs": tx.outs.len(), "fee": fee, "spends": spends, "signatures": n}),
        )?;
        self.ledger.commit(now, &w.id, &spends, n);
        Ok(json!({"raw_tx": hex::encode(&raw), "txid": txid, "fee": fee, "vsize": vsize, "from": w.address}))
    }

    // ----------------------------------------------------------- quorum ----

    fn run_quorum(&mut self, actor: &str, approvers: &[String], p: &Payload, now: u64) -> R<Value> {
        let exp = p.exp.unwrap_or(now);
        let mut st = self.state.clone();
        st.used_admin_nonces.retain(|_, e| *e >= now);
        st.used_admin_nonces.insert(p.nonce.clone(), exp);
        let base = st.clone();
        match self.quorum_op(&p.method, &p.params, &mut st, now) {
            Ok((result, mut detail)) => {
                detail["approvers"] = json!(approvers);
                self.commit_state(st, actor, &p.method, detail)?;
                Ok(result)
            }
            Err(e) => {
                // The operation failed, but its nonce is spent all the same.
                self.commit_state_with(base, actor, &p.method, false, json!({"approvers": approvers, "error": e.message}))?;
                Err(e)
            }
        }
    }

    /// Sensitive operations. Each mutates `st` (a copy of the state that is
    /// committed by the caller) and returns the result and the audit detail.
    fn quorum_op(&mut self, method: &str, params: &Value, st: &mut State, now: u64) -> R<(Value, Value)> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WalletRef {
            wallet: String,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct EnrolRef {
            enrol_x: String,
            enrol_y: String,
            node: String,
        }
        match method {
            "kek_generate" => {
                self.sw.kek_generate().map_err(signer_err)?;
                st.sealed_kek = Some(self.sw.kek_seal().map_err(signer_err)?);
                st.kek_wrap_count = 0;
                st.share_set = None;
                let fp = hex::encode(self.sw.kek_fingerprint().map_err(signer_err)?);
                Ok((json!({"kek_fp": fp}), json!({"kek_fp": fp})))
            }
            "kek_erase" => {
                self.sw.kek_erase().map_err(signer_err)?;
                st.sealed_kek = None;
                Ok((json!({"kek_loaded": false}), json!({})))
            }
            "kek_export" | "rotate_export" => {
                // The quorum's signatures over the enrolment key are the
                // out-of-band check the module cannot make for itself.
                let q: EnrolRef = param(params)?;
                if !self.sw.ceremony_enabled() {
                    return Err(ceremony_off());
                }
                let (x, y): ([u8; 32], [u8; 32]) = (unhex_n(&q.enrol_x).map_err(bad)?, unhex_n(&q.enrol_y).map_err(bad)?);
                let t = if method == "kek_export" { self.sw.kek_export(&x, &y) } else { self.sw.kek_new_export(&x, &y) }.map_err(signer_err)?;
                let detail = json!({"to_node": q.node, "enrol_fp": hex::encode(sha256(&[&x, &y]))});
                Ok((serde_json::to_value(t).map_err(|e| ApiError::new("internal", e.to_string()))?, detail))
            }
            "rotate_begin" => {
                if st.wallets.values().any(|w| w.new_blob.is_some()) {
                    return Err(bad("a rotation is already in progress"));
                }
                self.sw.kek_new_generate().map_err(signer_err)?;
                Ok((json!({"rotation_pending": true}), json!({})))
            }
            "rotate_promote" => {
                if !self.sw.rotation_pending() {
                    return Err(bad("no rotation in progress"));
                }
                if st.wallets.values().any(|w| w.new_blob.is_none()) {
                    return Err(bad("not every wallet has been rewrapped; run rotate_rewrap first"));
                }
                self.sw.kek_promote().map_err(signer_err)?;
                for w in st.wallets.values_mut() {
                    if let Some(nb) = w.new_blob.take() {
                        w.blob = nb;
                    }
                }
                st.sealed_kek = Some(self.sw.kek_seal().map_err(signer_err)?);
                st.share_set = None; // old shares belong to the old KEK
                st.kek_wrap_count = st.wallets.len() as u64;
                let fp = hex::encode(self.sw.kek_fingerprint().map_err(signer_err)?);
                Ok((json!({"kek_fp": fp, "shares_recorded": false}), json!({"kek_fp": fp})))
            }
            "wallet_create" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct P {
                    label: String,
                    chain: Chain,
                    #[serde(default)]
                    network: Option<Network>,
                    #[serde(default)]
                    policy: Policy,
                }
                let q: P = param(params)?;
                if q.label.len() > 128 || q.label.chars().any(char::is_control) {
                    return Err(bad("invalid label"));
                }
                if q.chain == Chain::Ethereum && q.network.is_some() {
                    return Err(bad("an Ethereum wallet takes chain ids in its policy, not a network"));
                }
                let policy = q.policy.normalize(q.chain, q.network).map_err(bad)?;
                if st.kek_wrap_count >= MAX_KEK_WRAPS {
                    return Err(ApiError::new("signer_error", "KEK usage limit reached; rotate the KEK"));
                }
                let wid = random::<16>().map_err(|e| ApiError::new("internal", e))?;
                let (blob, x, y) = self.sw.new_wallet(&wid).map_err(signer_err)?;
                // The blob must unwrap to the key the module reported.
                if self.sw.pubkey(&wid, &blob).map_err(signer_err)? != (x, y) {
                    return Err(ApiError::new("signer_error", "wallet blob does not match its public key"));
                }
                st.kek_wrap_count += 1;
                let mut compressed = [0u8; 33];
                compressed[0] = 0x02 | (y[31] & 1);
                compressed[1..].copy_from_slice(&x);
                let address = match q.chain {
                    Chain::Ethereum => {
                        let mut xy = [0u8; 64];
                        xy[..32].copy_from_slice(&x);
                        xy[32..].copy_from_slice(&y);
                        eth::to_checksum(&eth::address_from_pubkey(&xy))
                    }
                    Chain::Bitcoin => btc::p2wpkh_address(q.network.ok_or_else(|| bad("a Bitcoin wallet needs a network"))?, &compressed),
                };
                let w = Wallet {
                    id: hex::encode(wid),
                    label: q.label,
                    chain: q.chain,
                    network: q.network,
                    pubkey: hex::encode(compressed),
                    address,
                    blob,
                    new_blob: None,
                    frozen: false,
                    created_ms: now,
                    policy,
                };
                let public = wallet_public(&w);
                st.wallets.insert(w.id.clone(), w);
                Ok((public.clone(), public))
            }
            "policy_set" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct P {
                    wallet: String,
                    policy: Policy,
                }
                let q: P = param(params)?;
                let w = st.wallets.get_mut(&q.wallet).ok_or_else(|| ApiError::new("not_found", "no such wallet"))?;
                w.policy = q.policy.normalize(w.chain, w.network).map_err(bad)?;
                let detail = json!({"wallet": q.wallet, "policy_hash": hex::encode(sha256(&[&serde_json::to_vec(&w.policy).unwrap_or_default()]))});
                Ok((json!({"wallet": q.wallet, "policy": w.policy}), detail))
            }
            "wallet_unfreeze" => {
                let q: WalletRef = param(params)?;
                st.wallets.get_mut(&q.wallet).ok_or_else(|| ApiError::new("not_found", "no such wallet"))?.frozen = false;
                Ok((json!({"wallet": q.wallet, "frozen": false}), json!({"wallet": q.wallet})))
            }
            "principal_add" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct P {
                    id: String,
                    role: Role,
                    pubkey: String,
                    cert_fp: String,
                }
                let q: P = param(params)?;
                if !valid_id(&q.id) || st.principals.contains_key(&q.id) || st.principals.len() >= 1024 {
                    return Err(bad("invalid or duplicate principal id"));
                }
                let principal = Principal { role: q.role, pubkey: q.pubkey.to_ascii_lowercase(), cert_fp: q.cert_fp.to_ascii_lowercase() };
                principal.validate().map_err(bad)?;
                if st.principals.values().any(|p| p.pubkey == principal.pubkey) {
                    return Err(bad("this request key is already registered"));
                }
                let detail = json!({"id": q.id, "role": principal.role});
                st.principals.insert(q.id, principal);
                Ok((detail.clone(), detail))
            }
            "principal_remove" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct P {
                    id: String,
                }
                let q: P = param(params)?;
                st.principals.remove(&q.id).ok_or_else(|| ApiError::new("not_found", "no such principal"))?;
                if st.admins() < st.quorum {
                    return Err(bad("removal would leave fewer admins than the quorum"));
                }
                Ok((json!({"removed": q.id}), json!({"id": q.id})))
            }
            "ceremony_split" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct P {
                    m: u8,
                    cards: Vec<String>,
                }
                let q: P = param(params)?;
                let set = self.ceremony_split(q.m, &q.cards)?;
                let detail = json!({"m": set.m, "n": set.n, "kek_fp13": set.fp, "cards": q.cards});
                let result = serde_json::to_value(&set).map_err(|e| ApiError::new("internal", e.to_string()))?;
                st.share_set = Some(set);
                Ok((result, detail))
            }
            "ceremony_restore" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct P {
                    cards: Vec<String>,
                }
                let q: P = param(params)?;
                let set = st.share_set.clone().ok_or_else(|| bad("no share records on this node; import a snapshot first"))?;
                self.ceremony_restore(&set, &q.cards)?;
                st.sealed_kek = Some(self.sw.kek_seal().map_err(signer_err)?);
                st.kek_wrap_count = st.wallets.len() as u64;
                let fp = hex::encode(self.sw.kek_fingerprint().map_err(signer_err)?);
                Ok((json!({"kek_fp": fp}), json!({"kek_fp": fp, "cards": q.cards})))
            }
            "snapshot_import" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct P {
                    snapshot: Snapshot,
                }
                let q: P = param(params)?;
                let snap = q.snapshot;
                if snap.cluster != st.cluster {
                    return Err(bad("snapshot belongs to a different cluster"));
                }
                let have_kek = self.sw.kek_loaded();
                if have_kek {
                    let fp = hex::encode(self.sw.kek_fingerprint().map_err(signer_err)?);
                    if snap.kek_fp.as_deref().is_some_and(|f| f != fp) {
                        return Err(bad("snapshot was made under a different KEK"));
                    }
                }
                let mut wallets = BTreeMap::new();
                for (id, mut w) in snap.wallets {
                    let wid: [u8; 16] = unhex_n(&id).map_err(|_| bad("invalid wallet id in snapshot"))?;
                    if w.id != id {
                        return Err(bad("wallet id mismatch in snapshot"));
                    }
                    w.new_blob = None;
                    w.policy = w.policy.normalize(w.chain, w.network).map_err(bad)?;
                    if have_kek {
                        // Each blob must open under the cluster KEK and hold
                        // the key the record claims.
                        let (x, y) = self.sw.pubkey(&wid, &w.blob).map_err(|_| bad(format!("wallet {id}: blob does not open under this node's KEK")))?;
                        let mut c = [0u8; 33];
                        c[0] = 0x02 | (y[31] & 1);
                        c[1..].copy_from_slice(&x);
                        if hex::encode(c) != w.pubkey {
                            return Err(bad(format!("wallet {id}: public key does not match its blob")));
                        }
                    }
                    wallets.insert(id, w);
                }
                let n = wallets.len();
                st.wallets = wallets;
                st.share_set = snap.share_set;
                st.kek_wrap_count = st.kek_wrap_count.max(n as u64);
                Ok((json!({"wallets": n, "verified": have_kek}), json!({"wallets": n, "verified": have_kek})))
            }
            _ => Err(ApiError::new("not_found", "unknown method")),
        }
    }

    // -------------------------------------------------------- ceremonies ----

    fn ceremony_split(&mut self, m: u8, cards_present: &[String]) -> R<ShareSet> {
        if !self.sw.ceremony_enabled() {
            return Err(ceremony_off());
        }
        let n = cards_present.len();
        if !(2..=8).contains(&n) || (m as usize) > n || m < 2 {
            return Err(bad("need 2 <= m <= n <= 8 cards"));
        }
        if cards_present.iter().collect::<BTreeSet<_>>().len() != n {
            return Err(bad("each card may hold only one share"));
        }
        let slot = self.dir.join("cardslot");
        let template = self.sw.split_begin(m, n as u8).map_err(signer_err)?;
        let mut records = Vec::new();
        let mut run = || -> R<()> {
            for (i, card) in cards_present.iter().enumerate() {
                let x = i as u8 + 1;
                let challenge = random::<32>().map_err(|e| ApiError::new("internal", e))?;
                let response = cards::respond(&slot, card, &challenge).map_err(bad)?;
                let r = cards::card_secret(&response, &challenge);
                let mut header = template;
                header[0] = x;
                let blob = self.sw.share_get(&header, &r).map_err(signer_err)?;
                records.push(ShareRecord { x, card: card.clone(), challenge: hex::encode(challenge), header: hex::encode(header), blob });
            }
            Ok(())
        };
        let outcome = run();
        // Always discard the sharing polynomial, even after a failure.
        let ended = self.sw.split_end().map_err(signer_err);
        outcome?;
        ended?;
        Ok(ShareSet { m, n: n as u8, fp: hex::encode(&template[3..]), records })
    }

    fn ceremony_restore(&mut self, set: &ShareSet, cards_present: &[String]) -> R<()> {
        if !self.sw.ceremony_enabled() {
            return Err(ceremony_off());
        }
        if self.sw.kek_loaded() {
            return Err(ApiError::new("signer_error", "a KEK is already loaded"));
        }
        let slot = self.dir.join("cardslot");
        let mut used = 0u8;
        let mut run = || -> R<()> {
            for rec in set.records.iter().filter(|r| cards_present.contains(&r.card)) {
                let challenge: [u8; 32] = unhex_n(&rec.challenge).map_err(bad)?;
                let header: [u8; 16] = unhex_n(&rec.header).map_err(bad)?;
                let response = cards::respond(&slot, &rec.card, &challenge).map_err(bad)?;
                let r = cards::card_secret(&response, &challenge);
                self.sw.share_put(&header, &rec.blob, &r).map_err(signer_err)?;
                used += 1;
                if used == set.m {
                    break;
                }
            }
            if used < set.m {
                return Err(bad(format!("only {used} of the required {} cards are present", set.m)));
            }
            self.sw.restore().map_err(signer_err)
        };
        let outcome = run();
        if outcome.is_err() {
            let _ = self.sw.restore_abort();
        }
        outcome
    }
}

fn wallet_public(w: &Wallet) -> Value {
    json!({
        "id": w.id, "label": w.label, "chain": w.chain, "network": w.network,
        "address": w.address, "pubkey": w.pubkey, "frozen": w.frozen, "created_ms": w.created_ms,
    })
}

fn error_response(e: &ApiError) -> Vec<u8> {
    serde_json::to_vec(&json!({"ok": false, "error": {"code": e.code, "message": e.message}})).unwrap_or_default()
}

fn mark_replayed(resp: &[u8]) -> Vec<u8> {
    match serde_json::from_slice::<Value>(resp) {
        Ok(mut v) => {
            v["replayed"] = json!(true);
            serde_json::to_vec(&v).unwrap_or_else(|_| resp.to_vec())
        }
        Err(_) => resp.to_vec(),
    }
}

/// Used by `Blob` consumers outside this module.
pub fn blob_is_well_formed(b: &Blob) -> bool {
    unhex_n::<12>(&b.iv).is_ok() && unhex_n::<16>(&b.tag).is_ok() && unhex_n::<32>(&b.ct).is_ok()
}
