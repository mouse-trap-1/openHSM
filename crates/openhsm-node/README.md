# openhsm-node

The **node daemon** (`openhsmd`) and its library. This is the software that runs on
a signing node's SoC: it exposes an authenticated API to application servers and
operators, applies policy to every signing request, drives the signing module, and
keeps a signed, tamper-evident audit chain.

| | |
|---|---|
| Kind | Library (`openhsm_node`) and daemon binary (`openhsmd`) |
| Depends on | [`openhsm-signer`](../openhsm-signer) (protocol constants, crypto helpers), [`openhsm-hw`](../openhsm-hw) (`Hardware` trait, `Enclosure`, `RemoteHardware`) |
| Used by | [`openhsm-cli`](../openhsm-cli) (client, protocol, state types) |
| `unsafe` | Forbidden |

**Private keys never exist in this process.** Wallet keys are generated, unwrapped
and used inside the signing module and leave it only as AES-256-GCM blobs under the
cluster KEK. The node sees transactions, public keys, signatures and ciphertext.

## Trust domains inside the crate

| Domain | Modules |
|---|---|
| Tamper enclosure | Not in this crate: reached through `openhsm_hw::Hardware` |
| Secure world (holds session keys) | `secure`, `node`, `policy`, `audit`, `cards` |
| Normal world (network-facing) | `server`, `proto`, `api` |
| Pure functions | `chains::*`, `util` |

On the target board the secure-world modules run in OP-TEE; in this prototype the
separation is by module and by the `Hardware` boundary.

## Module guide

| Module | Responsibility |
|---|---|
| `main.rs` | `openhsmd init` and `openhsmd run`; picks the hardware link |
| `node.rs` | `Node`: first-time `init`, `boot` with integrity checks, `commit_state`, `log`, `poll_tamper`. Owns state, audit log, policy ledger, replay cache and rate buckets |
| `secure.rs` | `SecureWorld`: the only code that talks to the signing module; Rust equivalent of the reference host driver `sn_host.py`. Builds MAC'd commands, **verifies the response MAC (X1)**, holds the channel and SoC-seal keys. Wraps `new_wallet`, `sign`, `pubkey`, KEK, rotation, ECIES transfer and Shamir calls. `seal`/`unseal` protect the node's own secrets at rest |
| `api.rs` | `Node::handle_frame`: authentication, authorisation, quorum, replay, rate limit, then the method. Also snapshot export/import |
| `policy.rs` | Per-wallet `Policy` (fail-closed: all limits zero, allow-list required by default), `check_eth`, `check_btc`, and the daily/rate `Ledger` |
| `chains/eth.rs`, `rlp.rs` | Builds EIP-1559 and legacy EIP-155 transactions (including ERC-20 `transfer`) from structured fields. RLP is encode-only so no parser faces the network |
| `chains/btc.rs`, `addr.rs` | Builds native SegWit (P2WPKH) transactions, BIP-143 sighash, SIGHASH_ALL only; Bech32/Bech32m and Base58Check codecs |
| `audit.rs` | Hash-chained, Ed25519-signed JSON-lines log. `verify_file` checks a log offline with only the node's public identity key |
| `state.rs` | Persistent state (principals, wallets, policies, sealed KEK, share records) and `Genesis`. Contains no secrets |
| `cards.rs` | Operator cards for break-glass recovery: YubiKey HMAC-SHA1 challenge-response (via `ykman`, untested on hardware) or a software test card |
| `proto.rs` | Wire protocol: framing, `Frame`, `Payload`, Ed25519 payload signatures |
| `server.rs` | TLS 1.3 listener with mandatory client certificates, handshake/frame deadlines, connection caps |
| `client.rs` | `Profile` and `Client` library used by `hsmctl` and the tests |
| `util.rs` | Hashes (SHA-256, double SHA-256, Keccak-256, HASH160), hex, time, a `U256` type |

## How a request flows

```text
 client ──TLS 1.3, mutual──► server.rs ──frame──► Node::handle_frame (api.rs)
                                                       │
   1 every signature verifies against a registered principal
   2 first signer's registered TLS cert fingerprint == this connection's cert
   3 cluster, protocol version, node, nonce, freshness, replay
   4 role check; quorum of distinct admins for sensitive methods
   5 per-principal rate limit
   6 method: parse tx → policy → ledger → sign via SecureWorld → audit entry
                                                       │
                                  SecureWorld ──Hardware trait──► openhsm-hw ──► openhsm-signer
```

Authentication failures return a single message so there is no oracle for which
check failed. Non-quorum requests that repeat a nonce with an identical payload get
the cached response (idempotent retry, nothing signed twice).

### Wire protocol

TLS 1.3, 4-byte big-endian length, then one JSON document:

```text
request  = { "payload": "<JSON text>", "sigs": [ { "id": "...", "sig": "<hex>" }, ... ] }
sig      = Ed25519( principal key, "OPENHSM-REQ-v1\0" || payload bytes )
response = { "ok": true, "result": ... } | { "ok": false, "error": { "code", "message" } }
```

The payload travels as a string so the signature covers exactly the bytes signed.

### Roles and methods

| Role | Methods |
|---|---|
| `signer` (application servers) | `eth_sign_transaction`, `btc_sign_transaction`, `eth_sign_message`, `sign_digest`, plus `status`, `wallet_list`, `wallet_get` |
| `auditor` | `status`, `wallet_list`, `wallet_get`, `audit_head`, `audit_tail` |
| `admin`, single signature | the read methods above, `kek_fingerprint`, `enrol_begin`, `kek_import`, `rotate_import`, `rotate_rewrap`, `snapshot_export`, `wallet_freeze` |
| `admin`, **quorum** of distinct admins | `kek_generate`, `kek_export`, `kek_erase`, `rotate_begin`, `rotate_export`, `rotate_promote`, `wallet_create`, `policy_set`, `wallet_unfreeze`, `principal_add`, `principal_remove`, `ceremony_split`, `ceremony_restore`, `snapshot_import` |

Quorum operations must name the node, carry an expiry (at most 24 h) and a
single-use nonce.

## Integrity and persistence

- **Audit chain.** Each entry hashes its predecessor and is signed by the node
  identity key. Nothing is released to a caller before the entry describing it is
  durable.
- **Rollback anchor.** The newest sequence number is mirrored in the supervisor's
  monotonic counter. Boot fails if the log has been truncated or replaced.
- **State anchoring.** Every state change records the SHA-256 of the new state file
  in the audit chain. Boot refuses to start if `state.json` does not match the last
  anchored hash.
- **Derived limits.** Daily totals and signing rates are rebuilt from the audit
  chain, so a restart cannot reset them.
- **Secrets at rest.** The node identity key and TLS key are sealed under a key
  derived from the tamper secret (`identity.sealed`, `tls/node.key.sealed`).
- **Tamper response.** Every request first polls `tamper_status()`; on a trip the node
  logs the event, drops its keys and refuses all further requests.

## Running

```text
openhsmd init --data DIR --genesis FILE --node-id ID [--san NAME]... [--hardware inproc|unix:PATH]
openhsmd run  --data DIR --listen ADDR [--hardware inproc|unix:PATH] [--sim-physical] [--no-audit-fsync]
```

1. `init` brings up the enclosure session, generates the identity and TLS keys
   (sealed), writes a certificate signing request at `DIR/tls/node.csr`, writes the
   initial state and the first audit entry, and prints the identity public key.
2. Sign the CSR with the cluster CA (`hsmctl pki sign-csr`) and place the result at
   `DIR/tls/node.crt`.
3. `run` boots, verifies integrity, restores the KEK from its sealed copy if present,
   and serves.

`--hardware inproc` (default) runs the enclosure model inside the daemon, so the
daemon then holds the signing module's keys, which a real node never does. Use
`unix:PATH` with `openhsm-hwsim` for realistic isolation. `--sim-physical` exposes
the simulated physical world at `DIR/sim.sock` (inproc only). `--no-audit-fsync`
is for benchmarks only.

## How it plugs into the larger system

- **Downwards:** all hardware access goes through `Box<dyn Hardware>` from
  `openhsm-hw`, and all signing-module commands use the register map, command codes
  and labels from `openhsm-signer`.
- **Upwards:** application servers and operators connect over mutual TLS.
  [`hsmctl`](../openhsm-cli) reuses this crate's `client`, `proto` and `state` modules
  so client and server cannot drift apart.
- **Sideways (clustering):** nodes of a cluster share a CA and a KEK. A KEK moves
  between nodes by ECIES transfer (`enrol_begin` → `kek_export` → `kek_import`) behind
  the ceremony switch; wallets replicate by signed **snapshot** export and import.
  The prototype has **no Raft, leader election or automatic failover**, so the
  README's availability targets are not met (see `docs/SYSTEM_DESIGN.md`).

## Tests

```bash
cargo test -p openhsm-node --release
```

`tests/e2e.rs` drives a lab of nodes in-process through the same `handle_frame`
entry point the TLS listener uses, with an `Enclosure` per node. The Python
penetration suite in [`pentest/`](../../pentest) attacks the real binaries.

## Further reading

- [`docs/SYSTEM_SPECIFICATION.md`](../../docs/SYSTEM_SPECIFICATION.md): required behaviour, protocol, policy rules
- [`docs/INTERFACE_CONTROL_DOCUMENT.md`](../../docs/INTERFACE_CONTROL_DOCUMENT.md): API and file formats
- [`docs/THREAT_MODEL.md`](../../docs/THREAT_MODEL.md)
