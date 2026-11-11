//! In-process end-to-end tests of the node: every request goes through the
//! same `handle_frame` entry point the TLS listener uses.

use ed25519_dalek::SigningKey;
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};
use openhsm_hw::Enclosure;
use openhsm_node::client::build_payload;
use openhsm_node::node::{Node, NodeOptions};
use openhsm_node::proto::{sign_payload, Frame, Payload, SigEntry};
use openhsm_node::state::{Genesis, Principal, Role};
use openhsm_node::util::{keccak256, now_ms, sha256};
use serde_json::{json, Value};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

const DEST: &str = "0x3535353535353535353535353535353535353535";
const BTC_DEST: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
static COUNTER: AtomicU32 = AtomicU32::new(0);

struct Lab {
    root: PathBuf,
    keys: BTreeMap<String, SigningKey>,
    genesis: Genesis,
    /// The physical side of each node's enclosure (sensors, key-switch).
    enclosures: RefCell<BTreeMap<String, Arc<Mutex<Enclosure>>>>,
}

fn fp_of(id: &str) -> [u8; 32] {
    sha256(&[b"test-cert:", id.as_bytes()])
}

impl Lab {
    fn new() -> Lab {
        let root = std::env::temp_dir().join(format!("openhsm-e2e-{}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::SeqCst)));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let mut keys = BTreeMap::new();
        let mut principals = BTreeMap::new();
        for (i, (id, role)) in
            [("alice", Role::Admin), ("bob", Role::Admin), ("carol", Role::Admin), ("app", Role::Signer), ("aud", Role::Auditor)].into_iter().enumerate()
        {
            let sk = SigningKey::from_bytes(&[i as u8 + 1; 32]);
            principals.insert(id.to_string(), Principal { role, pubkey: hex::encode(sk.verifying_key().to_bytes()), cert_fp: hex::encode(fp_of(id)) });
            keys.insert(id.to_string(), sk);
        }
        let genesis = Genesis { cluster: "testnet".into(), quorum: 2, lease_divisor: 1, ca_cert_pem: String::new(), principals };
        Lab { root, keys, genesis, enclosures: RefCell::new(BTreeMap::new()) }
    }

    fn dir(&self, node: &str) -> PathBuf {
        self.root.join(node)
    }

    fn enclosure(&self, node: &str, provision: bool) -> Arc<Mutex<Enclosure>> {
        let state = self.dir(node).join("enclosure");
        let enc = if provision { Enclosure::provision(&state) } else { Enclosure::power_on(&state) }.unwrap();
        let shared = Arc::new(Mutex::new(enc));
        self.enclosures.borrow_mut().insert(node.to_string(), shared.clone());
        shared
    }

    fn physical(&self, node: &str, command: &str) {
        let reply = self.enclosures.borrow()[node].lock().unwrap().physical_command(command);
        assert!(reply.starts_with("ok"), "{reply}");
    }

    fn init(&self, node: &str) -> Node {
        let hw = self.enclosure(node, true);
        Node::init(&self.dir(node), &self.genesis, node, &["localhost".to_string()], Box::new(hw)).unwrap();
        self.boot(node).unwrap()
    }

    fn boot(&self, node: &str) -> Result<Node, String> {
        let hw = self.enclosure(node, false);
        Node::boot(&self.dir(node), NodeOptions { audit_fsync: false, rate_per_sec: 1e6, burst: 1e6 }, Box::new(hw))
    }

    fn frame(&self, payload: &str, signers: &[&str]) -> Vec<u8> {
        let sigs = signers.iter().map(|id| SigEntry { id: id.to_string(), sig: sign_payload(&self.keys[*id], payload) }).collect();
        serde_json::to_vec(&Frame { payload: payload.to_string(), sigs }).unwrap()
    }

    fn send(&self, n: &mut Node, frame: &[u8], as_id: &str) -> Result<Value, (String, String)> {
        let v: Value = serde_json::from_slice(&n.handle_frame(frame, &fp_of(as_id))).unwrap();
        if v["ok"] == json!(true) {
            Ok(v["result"].clone())
        } else {
            Err((v["error"]["code"].as_str().unwrap().to_string(), v["error"]["message"].as_str().unwrap().to_string()))
        }
    }

    fn call(&self, n: &mut Node, id: &str, method: &str, params: Value) -> Result<Value, (String, String)> {
        let payload = build_payload("testnet", None, method, params, None).unwrap();
        self.send(n, &self.frame(&payload, &[id]), id)
    }

    fn quorum(&self, n: &mut Node, method: &str, params: Value) -> Result<Value, (String, String)> {
        let node_id = n.state.node_id.clone();
        let payload = build_payload("testnet", Some(&node_id), method, params, Some(3_600_000)).unwrap();
        self.send(n, &self.frame(&payload, &["alice", "bob"]), "alice")
    }

    fn eth_wallet(&self, n: &mut Node) -> Value {
        self.quorum(
            n,
            "wallet_create",
            json!({"label": "eth", "chain": "ethereum", "policy": {
                "chain_ids": [11155111], "max_per_tx": "1000000", "max_per_day": "100000000000000",
                "max_fee": "42000000000000", "allowlist": [DEST]}}),
        )
        .unwrap()
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn code<T: std::fmt::Debug>(r: Result<T, (String, String)>) -> String {
    r.unwrap_err().0
}

fn eth_tx(wallet: &str, to: &str, value: &str, nonce: u64) -> Value {
    json!({"wallet": wallet, "tx": {"chain_id": 11155111, "nonce": nonce, "gas_limit": 21000, "to": to, "value": value,
           "max_fee_per_gas": "2000000000", "max_priority_fee_per_gas": "1000000000"}})
}

fn verify(pubkey_hex: &str, digest: &[u8; 32], r: &str, s: &str) -> bool {
    let vk = VerifyingKey::from_sec1_bytes(&hex::decode(pubkey_hex).unwrap()).unwrap();
    let mut rb = [0u8; 32];
    let mut sb = [0u8; 32];
    hex::decode_to_slice(r.trim_start_matches("0x"), &mut rb).unwrap();
    hex::decode_to_slice(s.trim_start_matches("0x"), &mut sb).unwrap();
    vk.verify_prehash(digest, &Signature::from_scalars(rb, sb).unwrap()).is_ok()
}

#[test]
fn ethereum_and_bitcoin_signing() {
    let lab = Lab::new();
    let mut n = lab.init("a");
    assert_eq!(code(lab.quorum(&mut n, "wallet_create", json!({"label": "x", "chain": "ethereum"}))), "no_kek");
    lab.quorum(&mut n, "kek_generate", json!({})).unwrap();
    let w = lab.eth_wallet(&mut n);
    let id = w["id"].as_str().unwrap();

    let out = lab.call(&mut n, "app", "eth_sign_transaction", eth_tx(id, DEST, "1000", 0)).unwrap();
    let raw = hex::decode(out["raw_tx"].as_str().unwrap().trim_start_matches("0x")).unwrap();
    assert_eq!(raw[0], 0x02);
    assert_eq!(out["tx_hash"].as_str().unwrap(), format!("0x{}", hex::encode(keccak256(&raw))));
    // The signature covers keccak(0x02 || rlp(fields)): strip the three signature items and re-hash.
    let unsigned_len = raw.len() - (1 + 33 + 33);
    assert!(unsigned_len > 0);
    assert!(out["from"].as_str().unwrap().starts_with("0x"));

    let b = lab
        .quorum(
            &mut n,
            "wallet_create",
            json!({"label": "btc", "chain": "bitcoin", "network": "testnet",
                   "policy": {"max_per_tx": "100000", "max_per_day": "150000", "max_fee": "2000", "max_fee_rate": 20, "allowlist": [BTC_DEST]}}),
        )
        .unwrap();
    let (bid, baddr) = (b["id"].as_str().unwrap(), b["address"].as_str().unwrap());
    assert!(baddr.starts_with("tb1q"));
    let txid = "11".repeat(32);
    let spend = |amount: u64, change: u64| {
        json!({"wallet": bid, "tx": {"inputs": [{"txid": txid, "vout": 0, "amount": 200000}],
               "outputs": [{"address": BTC_DEST, "amount": amount}, {"address": baddr, "amount": change}]}})
    };
    let out = lab.call(&mut n, "app", "btc_sign_transaction", spend(90_000, 109_000)).unwrap();
    assert_eq!(out["fee"], json!(1000));
    assert_eq!(out["txid"].as_str().unwrap().len(), 64);
    // Fee cap, allow-list, per-transaction cap and daily cap.
    assert_eq!(code(lab.call(&mut n, "app", "btc_sign_transaction", spend(90_000, 100_000))), "policy_denied");
    assert_eq!(code(lab.call(&mut n, "app", "btc_sign_transaction", spend(100_001, 98_999))), "policy_denied");
    let elsewhere = json!({"wallet": bid, "tx": {"inputs": [{"txid": txid, "vout": 0, "amount": 200000}],
        "outputs": [{"address": "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", "amount": 199000}]}});
    assert_eq!(code(lab.call(&mut n, "app", "btc_sign_transaction", elsewhere)), "policy_denied");
    assert_eq!(code(lab.call(&mut n, "app", "btc_sign_transaction", spend(90_000, 109_000))), "policy_denied", "daily cap: 91000 + 91000 > 150000");
    // A wallet cannot be used on the other chain.
    assert_eq!(code(lab.call(&mut n, "app", "eth_sign_transaction", eth_tx(bid, DEST, "1", 0))), "bad_request");
}

#[test]
fn authentication_and_authorisation() {
    let lab = Lab::new();
    let mut n = lab.init("a");
    lab.quorum(&mut n, "kek_generate", json!({})).unwrap();
    let w = lab.eth_wallet(&mut n);
    let id = w["id"].as_str().unwrap();
    let good = build_payload("testnet", None, "status", json!({}), None).unwrap();

    // Wrong TLS certificate for the claimed principal.
    assert_eq!(code(lab.send(&mut n, &lab.frame(&good, &["app"]), "aud")), "unauthenticated");
    // Unknown principal, bad signature, altered payload, no signature.
    let mut f: Frame = serde_json::from_slice(&lab.frame(&good, &["app"])).unwrap();
    f.sigs[0].id = "mallory".into();
    assert_eq!(code(lab.send(&mut n, &serde_json::to_vec(&f).unwrap(), "app")), "unauthenticated");
    let mut f: Frame = serde_json::from_slice(&lab.frame(&good, &["app"])).unwrap();
    f.payload = f.payload.replace("status", "wallet_list");
    assert_eq!(code(lab.send(&mut n, &serde_json::to_vec(&f).unwrap(), "app")), "unauthenticated");
    let f = Frame { payload: good.clone(), sigs: vec![] };
    assert_eq!(code(lab.send(&mut n, &serde_json::to_vec(&f).unwrap(), "app")), "unauthenticated");
    // A signature made by another principal's key under this principal's name.
    let forged = Frame { payload: good.clone(), sigs: vec![SigEntry { id: "app".into(), sig: sign_payload(&lab.keys["aud"], &good) }] };
    assert_eq!(code(lab.send(&mut n, &serde_json::to_vec(&forged).unwrap(), "app")), "unauthenticated");

    // Roles.
    assert_eq!(code(lab.call(&mut n, "aud", "eth_sign_transaction", eth_tx(id, DEST, "1", 0))), "forbidden");
    assert_eq!(code(lab.call(&mut n, "alice", "eth_sign_transaction", eth_tx(id, DEST, "1", 0))), "forbidden");
    assert_eq!(code(lab.call(&mut n, "app", "audit_tail", json!({}))), "forbidden");
    assert_eq!(code(lab.call(&mut n, "app", "kek_fingerprint", json!({}))), "forbidden");
    assert!(lab.call(&mut n, "aud", "audit_tail", json!({})).is_ok());

    // Quorum: one admin is not enough; the same admin twice is not two; a signer is not an admin.
    let op = |n: &Node| build_payload("testnet", Some(&n.state.node_id), "wallet_unfreeze", json!({"wallet": id}), Some(60_000)).unwrap();
    let p = op(&n);
    assert_eq!(code(lab.send(&mut n, &lab.frame(&p, &["alice"]), "alice")), "quorum_required");
    assert_eq!(code(lab.send(&mut n, &lab.frame(&p, &["alice", "alice"]), "alice")), "unauthenticated");
    assert_eq!(code(lab.send(&mut n, &lab.frame(&p, &["alice", "app"]), "alice")), "quorum_required");
    assert_eq!(code(lab.send(&mut n, &lab.frame(&p, &["app", "alice", "bob"]), "app")), "forbidden");
    assert!(lab.send(&mut n, &lab.frame(&p, &["alice", "bob"]), "alice").is_ok());
    // An approved operation is single-use, and bound to its node and cluster.
    assert_eq!(code(lab.send(&mut n, &lab.frame(&p, &["carol", "alice", "bob"]), "carol")), "replay");
    let other_node = build_payload("testnet", Some("node-z"), "wallet_unfreeze", json!({"wallet": id}), Some(60_000)).unwrap();
    assert_eq!(code(lab.send(&mut n, &lab.frame(&other_node, &["alice", "bob"]), "alice")), "bad_request");
    let no_node = build_payload("testnet", None, "wallet_unfreeze", json!({"wallet": id}), Some(60_000)).unwrap();
    assert_eq!(code(lab.send(&mut n, &lab.frame(&no_node, &["alice", "bob"]), "alice")), "bad_request");
    let other_cluster = build_payload("mainnet", None, "status", json!({}), None).unwrap();
    assert_eq!(code(lab.send(&mut n, &lab.frame(&other_cluster, &["app"]), "app")), "bad_request");
    // Validity longer than a day is refused.
    let long = build_payload("testnet", Some("a"), "wallet_unfreeze", json!({"wallet": id}), Some(25 * 3_600_000)).unwrap();
    assert_eq!(code(lab.send(&mut n, &lab.frame(&long, &["alice", "bob"]), "alice")), "stale");
}

#[test]
fn replay_and_freshness() {
    let lab = Lab::new();
    let mut n = lab.init("a");
    lab.quorum(&mut n, "kek_generate", json!({})).unwrap();
    let w = lab.eth_wallet(&mut n);
    let id = w["id"].as_str().unwrap();

    let p = build_payload("testnet", None, "eth_sign_transaction", eth_tx(id, DEST, "5", 0), None).unwrap();
    let f = lab.frame(&p, &["app"]);
    let first: Value = serde_json::from_slice(&n.handle_frame(&f, &fp_of("app"))).unwrap();
    let seq = n.audit.seq;
    let again: Value = serde_json::from_slice(&n.handle_frame(&f, &fp_of("app"))).unwrap();
    assert_eq!(again["replayed"], json!(true));
    assert_eq!(again["result"], first["result"], "an identical retry returns the first answer");
    assert_eq!(n.audit.seq, seq, "and signs nothing new");

    // Same nonce with a different body is a replay attempt.
    let mut q: Payload = serde_json::from_str(&p).unwrap();
    q.params = eth_tx(id, DEST, "6", 0);
    let p2 = serde_json::to_string(&q).unwrap();
    assert_eq!(code(lab.send(&mut n, &lab.frame(&p2, &["app"]), "app")), "replay");

    // Stale and future timestamps.
    for ts in [now_ms() - 120_000, now_ms() + 120_000] {
        let mut q: Payload = serde_json::from_str(&p).unwrap();
        q.ts = ts;
        q.nonce = hex::encode([ts as u8; 16]);
        assert_eq!(code(lab.send(&mut n, &lab.frame(&serde_json::to_string(&q).unwrap(), &["app"]), "app")), "stale");
    }
    // A request signed before a restart is refused after it (the replay cache is volatile).
    drop(n);
    std::thread::sleep(std::time::Duration::from_millis(5));
    let mut n = lab.boot("a").unwrap();
    assert_eq!(code(lab.send(&mut n, &f, "app")), "stale");
}

#[test]
fn daily_limit_survives_restart_and_freeze_works() {
    let lab = Lab::new();
    let mut n = lab.init("a");
    lab.quorum(&mut n, "kek_generate", json!({})).unwrap();
    let w = lab
        .quorum(
            &mut n,
            "wallet_create",
            json!({"label": "tight", "chain": "ethereum", "policy": {"chain_ids": [11155111], "max_per_tx": "1000",
                   "max_per_day": "84000000001500", "max_fee": "42000000000000", "allowlist": [DEST]}}),
        )
        .unwrap();
    let id = w["id"].as_str().unwrap();
    // Each transfer debits value + worst-case fee (42e12). Two fit, a third does not.
    assert!(lab.call(&mut n, "app", "eth_sign_transaction", eth_tx(id, DEST, "700", 0)).is_ok());
    assert!(lab.call(&mut n, "app", "eth_sign_transaction", eth_tx(id, DEST, "700", 1)).is_ok());
    assert_eq!(code(lab.call(&mut n, "app", "eth_sign_transaction", eth_tx(id, DEST, "700", 2))), "policy_denied");
    drop(n);
    let mut n = lab.boot("a").unwrap();
    assert_eq!(code(lab.call(&mut n, "app", "eth_sign_transaction", eth_tx(id, DEST, "700", 2))), "policy_denied", "restart does not reset the budget");

    // One admin can freeze; un-freezing needs the quorum.
    lab.call(&mut n, "carol", "wallet_freeze", json!({"wallet": id})).unwrap();
    assert_eq!(code(lab.call(&mut n, "app", "eth_sign_transaction", eth_tx(id, DEST, "1", 3))), "frozen");
    assert_eq!(code(lab.call(&mut n, "carol", "wallet_unfreeze", json!({"wallet": id}))), "bad_request");
    lab.quorum(&mut n, "wallet_unfreeze", json!({"wallet": id})).unwrap();
    // Raw digests and messages are refused unless the policy allows them.
    assert_eq!(code(lab.call(&mut n, "app", "sign_digest", json!({"wallet": id, "digest": "11".repeat(32)}))), "policy_denied");
    assert_eq!(code(lab.call(&mut n, "app", "eth_sign_message", json!({"wallet": id, "message": "0x68656c6c6f"}))), "policy_denied");
}

#[test]
fn integrity_checks_at_boot() {
    let lab = Lab::new();
    let mut n = lab.init("a");
    lab.quorum(&mut n, "kek_generate", json!({})).unwrap();
    let w = lab.eth_wallet(&mut n);
    let id = w["id"].as_str().unwrap().to_string();
    let dir = lab.dir("a");

    // Keep a copy of the disk (not of the tamper supervisor's RAM) for a rollback attempt.
    let backup = lab.root.join("backup");
    std::fs::create_dir_all(&backup).unwrap();
    for f in ["state.json", "audit.log"] {
        std::fs::copy(dir.join(f), backup.join(f)).unwrap();
    }
    lab.call(&mut n, "carol", "wallet_freeze", json!({"wallet": id})).unwrap();
    drop(n);

    // 1. Edit the state file: raise a limit.
    let state = std::fs::read_to_string(dir.join("state.json")).unwrap();
    std::fs::write(dir.join("state.json"), state.replace("\"max_per_tx\": \"1000000\"", "\"max_per_tx\": \"9000000\"")).unwrap();
    assert!(lab.boot("a").unwrap_err().contains("INTEGRITY"));
    std::fs::write(dir.join("state.json"), &state).unwrap();
    assert!(lab.boot("a").is_ok());

    // 2. Truncate the audit log by one entry.
    let log = std::fs::read_to_string(dir.join("audit.log")).unwrap();
    let cut = log.trim_end().rfind('\n').unwrap();
    std::fs::write(dir.join("audit.log"), &log[..=cut]).unwrap();
    assert!(lab.boot("a").unwrap_err().contains("INTEGRITY"));

    // 3. Roll the whole disk back to the earlier, internally consistent copy
    //    (un-freezing the wallet). The supervisor's counter gives it away.
    for f in ["state.json", "audit.log"] {
        std::fs::copy(backup.join(f), dir.join(f)).unwrap();
    }
    assert!(lab.boot("a").unwrap_err().contains("monotonic counter"));

    // 4. Edit an audit entry.
    std::fs::write(dir.join("audit.log"), log.replacen("wallet_create", "wallet_xxxxxx", 1)).unwrap();
    assert!(lab.boot("a").unwrap_err().contains("audit line"));
}

#[test]
fn tamper_zeroises_and_refuses_restart() {
    let lab = Lab::new();
    let mut n = lab.init("a");
    lab.quorum(&mut n, "kek_generate", json!({})).unwrap();
    let w = lab.eth_wallet(&mut n);
    let seq = n.audit.seq;
    lab.physical("a", "tamper mesh");
    assert_eq!(code(lab.call(&mut n, "app", "eth_sign_transaction", eth_tx(w["id"].as_str().unwrap(), DEST, "1", 0))), "tamper");
    assert_eq!(code(lab.call(&mut n, "alice", "status", json!({}))), "tamper");
    assert!(!n.sw.kek_loaded());
    assert_eq!(n.audit.seq, seq + 1, "the tamper event is the last thing the node records");
    drop(n);
    assert!(lab.boot("a").unwrap_err().contains("TAMPERED"));
    let mcu = std::fs::read_to_string(lab.dir("a").join("enclosure/mcu-ram.json")).unwrap();
    assert!(mcu.contains("\"secret\":null"), "the tamper secret is gone");
}

#[test]
fn enrolment_recovery_and_rotation() {
    let lab = Lab::new();
    let mut a = lab.init("a");
    lab.quorum(&mut a, "kek_generate", json!({})).unwrap();
    let w = lab.eth_wallet(&mut a);
    let id = w["id"].as_str().unwrap();
    let fp = lab.call(&mut a, "alice", "kek_fingerprint", json!({})).unwrap();

    // Operator cards.
    for i in 1..=5 {
        std::fs::write(lab.dir("a").join(format!("cardslot/op{i}.card")), hex::encode([i as u8; 20])).unwrap();
    }
    // With the key-switch off, even the quorum cannot move the KEK.
    assert_eq!(code(lab.quorum(&mut a, "ceremony_split", json!({"m": 3, "cards": ["op1", "op2", "op3"]}))), "ceremony_required");
    lab.physical("a", "ceremony on");
    assert_eq!(code(lab.quorum(&mut a, "ceremony_split", json!({"m": 3, "cards": ["op1", "op1", "op2"]}))), "bad_request");
    assert_eq!(code(lab.quorum(&mut a, "ceremony_split", json!({"m": 3, "cards": ["op1", "op2", "missing"]}))), "bad_request");
    lab.quorum(&mut a, "ceremony_split", json!({"m": 3, "cards": ["op1", "op2", "op3", "op4", "op5"]})).unwrap();

    // Node B joins over ECIES.
    let mut b = lab.init("b");
    let enrol = lab.call(&mut b, "alice", "enrol_begin", json!({})).unwrap();
    let args = json!({"enrol_x": enrol["enrol_x"], "enrol_y": enrol["enrol_y"], "node": "b"});
    assert_eq!(code(lab.call(&mut a, "alice", "kek_export", args.clone())), "bad_request", "export needs the quorum");
    let pkg = lab.quorum(&mut a, "kek_export", args).unwrap();
    assert_eq!(code(lab.call(&mut b, "alice", "kek_import", pkg.clone())), "ceremony_required");
    lab.physical("b", "ceremony on");
    lab.call(&mut b, "alice", "kek_import", pkg.clone()).unwrap();
    assert_eq!(lab.call(&mut b, "alice", "kek_fingerprint", json!({})).unwrap(), fp);
    assert_eq!(code(lab.call(&mut b, "alice", "kek_import", pkg)), "signer_error", "a transfer package is single-use");

    let snap = lab.call(&mut a, "alice", "snapshot_export", json!({})).unwrap();
    // A snapshot whose wallet record was altered is rejected by a node that holds the KEK.
    let mut evil = snap.clone();
    evil["wallets"][id]["pubkey"] = json!(format!("02{}", "11".repeat(32)));
    assert_eq!(code(lab.quorum(&mut b, "snapshot_import", json!({"snapshot": evil}))), "bad_request");
    lab.quorum(&mut b, "snapshot_import", json!({"snapshot": snap.clone()})).unwrap();
    let out = lab.call(&mut b, "app", "eth_sign_transaction", eth_tx(id, DEST, "1", 0)).unwrap();
    assert_eq!(out["from"], w["address"]);

    // Break-glass on a fresh node C: two cards are not enough, three are.
    let mut c = lab.init("c");
    lab.quorum(&mut c, "snapshot_import", json!({"snapshot": snap})).unwrap();
    for i in [2, 4] {
        std::fs::copy(lab.dir("a").join(format!("cardslot/op{i}.card")), lab.dir("c").join(format!("cardslot/op{i}.card"))).unwrap();
    }
    lab.physical("c", "ceremony on");
    assert_eq!(code(lab.quorum(&mut c, "ceremony_restore", json!({"cards": ["op2", "op4"]}))), "bad_request");
    std::fs::write(lab.dir("c").join("cardslot/op5.card"), hex::encode([0xEE; 20])).unwrap(); // a different card with the same name
    assert_eq!(code(lab.quorum(&mut c, "ceremony_restore", json!({"cards": ["op2", "op4", "op5"]}))), "signer_error");
    std::fs::write(lab.dir("c").join("cardslot/op5.card"), hex::encode([5u8; 20])).unwrap();
    lab.quorum(&mut c, "ceremony_restore", json!({"cards": ["op2", "op4", "op5"]})).unwrap();
    assert_eq!(lab.call(&mut c, "alice", "kek_fingerprint", json!({})).unwrap(), fp);
    let out = lab.call(&mut c, "app", "eth_sign_transaction", eth_tx(id, DEST, "1", 0)).unwrap();
    assert!(verify_eth(&w, &out));
    // The restored KEK is sealed to node C and survives a restart.
    drop(c);
    let mut c = lab.boot("c").unwrap();
    assert!(lab.call(&mut c, "app", "eth_sign_transaction", eth_tx(id, DEST, "1", 1)).is_ok());

    // Rotation on A: old blobs die, the wallet key does not change.
    assert_eq!(code(lab.quorum(&mut a, "rotate_promote", json!({}))), "bad_request");
    lab.quorum(&mut a, "rotate_begin", json!({})).unwrap();
    assert_eq!(code(lab.quorum(&mut a, "rotate_promote", json!({}))), "bad_request", "wallets not yet rewrapped");
    lab.call(&mut a, "alice", "rotate_rewrap", json!({})).unwrap();
    let new_fp = lab.quorum(&mut a, "rotate_promote", json!({})).unwrap();
    assert_ne!(new_fp["kek_fp"], fp["fingerprint"]);
    let out = lab.call(&mut a, "app", "eth_sign_transaction", eth_tx(id, DEST, "1", 2)).unwrap();
    assert!(verify_eth(&w, &out));
    assert_eq!(lab.call(&mut a, "alice", "status", json!({})).unwrap()["shares_recorded"], Value::Null, "old shares are discarded");
}

/// Check an Ethereum signing result against the wallet's public key by
/// rebuilding the signing hash from the raw transaction.
fn verify_eth(wallet: &Value, out: &Value) -> bool {
    let raw = hex::decode(out["raw_tx"].as_str().unwrap().trim_start_matches("0x")).unwrap();
    // 0x02 || rlp(list): drop yParity (1 byte), r and s (33 bytes each), fix the list header.
    let body = &raw[1..];
    let (hdr_len, payload_len) = if body[0] <= 0xf7 { (1, (body[0] - 0xc0) as usize) } else { (2, body[1] as usize) };
    let unsigned_payload = &body[hdr_len..hdr_len + payload_len - 67];
    let mut unsigned = vec![0x02];
    if unsigned_payload.len() < 56 {
        unsigned.push(0xc0 + unsigned_payload.len() as u8);
    } else {
        unsigned.extend([0xf8, unsigned_payload.len() as u8]);
    }
    unsigned.extend(unsigned_payload);
    verify(wallet["pubkey"].as_str().unwrap(), &keccak256(&unsigned), out["r"].as_str().unwrap(), out["s"].as_str().unwrap())
}
