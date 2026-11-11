# OpenHSM System Specification

Version 0.5.0 (prototype). This document specifies the node as built: interfaces, formats, cryptographic constructions and required behaviour. The reasons are in the [System Design](SYSTEM_DESIGN.md). Every interface is listed in one place in the [Interface Control Document](INTERFACE_CONTROL_DOCUMENT.md). The signing module's own specification is [`FPGA/README.md`](../FPGA/README.md); section 3 here lists only what the prototype adds to it.

Requirement identifiers (`REQ-…`) are referenced by the tests and the compliance mapping.

## 1. Scope

| In scope | Out of scope in 0.5.0 |
| --- | --- |
| secp256k1 ECDSA signing for Ethereum (legacy EIP-155, EIP-1559, ERC-20 `transfer`, optional EIP-191) and Bitcoin (native SegWit P2WPKH) | Taproot/BIP-340, Ed25519 chains, PSBT, EIP-712, multisig scripts |
| Wallet creation, policy, freeze | BIP-32 derivation: every wallet key is independently generated on the module |
| KEK lifecycle: generate, seal, enrol a node by ECIES, split to operator cards, restore, rotate | Raft replication and automatic failover: replication is by signed snapshot |
| Authenticated API, quorum administration, signed audit chain | Real hardware: FPGA bitstream, supervisor firmware, OP-TEE trusted application |

## 2. Components and processes

| Binary | Role | Deployment |
| --- | --- | --- |
| `openhsmd` | Node daemon on the SoC | Production component |
| `hsmctl` | Operator and client tool | Production component |
| `openhsm-hwsim` | Tamper enclosure (signing module + supervisor) as a process, reached over two Unix sockets | Prototype fixture, replaced by hardware |
| `openhsm-signer-sim` | Signing module pins on a loopback TCP socket, for host-driver and attack tooling | Test fixture, never deployed |

Build: Rust 1.87 or later, `cargo build --release`. No C dependencies beyond those of `ring`.

## 3. Signing module protocol 0xB2

The module implements the register map and commands of protocol 0xB1 (`FPGA/README.md` sections 5 to 7) unchanged, so the existing driver `FPGA/V0.4/sn_host.py` works against it (test A-01). `VERSION` (0xFF) reads 0xB2. The additions are:

| Ext. | Requirement | Definition |
| --- | --- | --- |
| X1 | REQ-MOD-01 Responses are authenticated | Register `RMAC` (0xC4, 32 bytes, read-only) = HMAC-SHA256(chan_key, "SN-RESP-v1" ‖ nonce(16) ‖ ctr(4) ‖ cmd(1) ‖ error(1) ‖ WID ‖ IV ‖ TAG ‖ A ‖ B ‖ C) over the buffers as left by the command. The driver rejects any response whose RMAC does not verify. |
| X2 | REQ-MOD-02 Guessing is bounded | 8 consecutive failed command authentications lock the command channel until reset. A success resets the count. |
| X3 | REQ-MOD-03 No faulty signature is released | After signing, the module recomputes the public key from the unwrapped key and verifies (r, s). On mismatch it returns error 6 and clears the buffers. |
| X4 | REQ-MOD-04 No residue | Any error clears IV, TAG, A, B, C. The command MAC register is cleared after every command. |
| X5 | REQ-MOD-05 Card secrets are confidential on the bus | Commands 0x56 `SHARE_GET_C` and 0x57 `SHARE_PUT_C` behave as 0x51 and 0x53 with BUF_B XORed with HMAC-SHA256(chan_key, "SN-CONF-v1" ‖ nonce ‖ ctr). The node uses only these. |
| X6 | REQ-MOD-06 KEK movement needs physical presence | Input pin `ceremony`. When low, commands 0x41, 0x42, 0x45, 0x46, 0x50, 0x51, 0x53, 0x54, 0x56, 0x57 return error 8 (bad command), as if they did not exist. |

Unchanged from 0xB1 and relied on by the node: MAC and strictly increasing counter on every command (REQ-MOD-07); wallet blob bound to its wallet id by AAD (REQ-MOD-08); on-curve check before ECDH (REQ-MOD-09); hedged RFC 6979 nonce, low-s (REQ-MOD-10); asynchronous tamper wipe that latches (REQ-MOD-11); no key generation while the entropy health tests have failed (REQ-MOD-12).

The model is functional rather than cycle-accurate: a command completes within the bus write that starts it. Scalar arithmetic uses the `k256` crate.

## 4. Tamper supervisor interface

The node reaches the enclosure only through the `Hardware` trait (`crates/openhsm-hw/src/lib.rs`):

| Call | Meaning |
| --- | --- |
| `bus_write(ptr, data)`, `bus_read(ptr, n)` | I2C register access to the signing module |
| `restart_signer()` | Reset the module and have the supervisor resend S |
| `soc_keys()` | `chan` = HMAC-SHA256(S, "SN-CHAN"), `seal` = HMAC-SHA256(S, "SOC-SEAL-v1") |
| `counter()`, `counter_increment()` | Battery-backed 64-bit monotonic counter |
| `tamper_status()` | Empty, or the sensor that tripped and when |
| `ceremony_enabled()` | State of the ceremony key-switch |

- REQ-SUP-01 The supervisor never discloses S; the SoC receives only the two derived keys.
- REQ-SUP-02 Any sensor trip (mesh, lid, light, accelerometer, voltage, temperature) erases S, latches, and asserts the module's tamper input. The latch survives power cycles.
- REQ-SUP-03 The counter only increases and survives power loss.
- REQ-SUP-04 The ceremony switch is a physical input; no SoC call can change it.

## 5. Node API

### 5.1 Transport and framing

- REQ-API-01 TLS 1.3 only, with a client certificate that chains to the cluster CA recorded in the node state.
- Frame: 4-byte big-endian length, then one JSON document. Maximum frame 16 MiB. At most 256 connections, 32 per source address; 5 s handshake deadline, 60 s frame deadline.

```
request  = { "payload": "<JSON text>", "sigs": [ { "id": "<principal>", "sig": "<hex Ed25519>" }, … ] }
payload  = { "v": 1, "cluster": "…", "node": "…"?, "ts": <ms>, "exp": <ms>?, "nonce": "<32 hex>", "method": "…", "params": { … } }
sig      = Ed25519(principal key, "OPENHSM-REQ-v1\0" ‖ payload bytes)
response = { "ok": true, "result": … } | { "ok": false, "error": { "code": "…", "message": "…" } }
```

### 5.2 Request checks, in order

| # | Check | Requirement |
| --- | --- | --- |
| 1 | Every signature verifies against a registered principal; ids distinct; at most 16 | REQ-API-02 |
| 2 | The first signer's registered certificate fingerprint equals the certificate on this connection | REQ-API-03 |
| 3 | Protocol version, cluster name, node name if present, nonce format | REQ-API-04 |
| 4 | The caller's role may call the method | REQ-API-05 |
| 5 | Plain methods: `ts` within ±30 s and not before this boot; (principal, nonce) unseen, or an identical retry, which returns the stored response | REQ-API-06 |
| 6 | Quorum methods: `node` and `exp` present, validity at most 24 h, not expired, at least `quorum` distinct admin signatures, nonce never used (persisted) | REQ-API-07 |
| 7 | Per-principal token bucket: 200 requests/s, burst 400 | REQ-API-08 |

Failures of checks 1 and 2 return the same `unauthenticated` error and are audited at most once per second.

### 5.3 Roles and methods

| Role | Methods |
| --- | --- |
| any | `status`, `wallet_list`, `wallet_get` |
| signer | `eth_sign_transaction`, `btc_sign_transaction`, `eth_sign_message`, `sign_digest` |
| admin, auditor | `audit_head`, `audit_tail` |
| admin (single) | `kek_fingerprint`, `enrol_begin`, `kek_import`, `rotate_import`, `rotate_rewrap`, `snapshot_export`, `wallet_freeze` |
| admin quorum | `kek_generate`, `kek_export`, `kek_erase`, `rotate_begin`, `rotate_export`, `rotate_promote`, `wallet_create`, `policy_set`, `wallet_unfreeze`, `principal_add`, `principal_remove`, `ceremony_split`, `ceremony_restore`, `snapshot_import` |

Methods that move a KEK (`kek_export`, `kek_import`, `rotate_export`, `rotate_import`, `ceremony_split`, `ceremony_restore`) additionally return `ceremony_required` unless the key-switch is on (REQ-API-09).

Error codes: `unauthenticated`, `forbidden`, `quorum_required`, `bad_request`, `not_found`, `stale`, `replay`, `rate_limited`, `policy_denied`, `frozen`, `ceremony_required`, `signer_error`, `tamper`, `internal`.

### 5.4 Signing methods

`eth_sign_transaction { wallet, tx }` where `tx` has `type` ("eip1559" default, or "legacy"), `chain_id`, `nonce`, `gas_limit`, `to`, `value`, `data`, and either `max_fee_per_gas` + `max_priority_fee_per_gas` or `gas_price`, optional `access_list`. Amounts are decimal strings. Returns `raw_tx`, `tx_hash`, `from`, `y_parity`, `r`, `s`.

`btc_sign_transaction { wallet, tx }` where `tx` has `inputs` (`txid`, `vout`, `amount` in satoshi, optional `sequence`), `outputs` (`address`, `amount`), optional `version` (1 or 2) and `locktime`. Every input must belong to the wallet. Returns `raw_tx` (SegWit serialisation with witnesses), `txid`, `fee`, `vsize`, `from`.

`eth_sign_message { wallet, message }` signs the EIP-191 personal-message hash; `sign_digest { wallet, digest }` signs a caller-supplied digest. Both are refused unless the wallet policy enables them.

- REQ-SIG-01 The node computes every transaction digest itself from the decoded fields.
- REQ-SIG-02 Ethereum signatures are low-s; legacy transactions always carry EIP-155 replay protection; chain id 0 is refused.
- REQ-SIG-03 Bitcoin signatures are BIP-143, `SIGHASH_ALL`, strict DER, low-s.
- REQ-SIG-04 The node verifies each signature against the wallet's recorded public key before releasing it.
- REQ-SIG-05 The audit entry for a signature is durable before the response is sent.

## 6. Policy

| Field | Default | Applies to | Meaning |
| --- | --- | --- | --- |
| `max_per_tx` | 0 | both | Largest native amount leaving in one transaction (Bitcoin: sum of non-change outputs) |
| `max_per_day` | 0 | both | Native amount plus worst-case fees per UTC day |
| `max_fee` | 0 | both | Largest total fee (Ethereum: `gas_limit × max_fee_per_gas`) |
| `max_fee_rate` | 0 | Bitcoin | Largest fee rate in sat/vB; required |
| `require_allowlist` | true | both | Every recipient must be in `allowlist` |
| `allowlist` | empty | both | Ethereum addresses or Bitcoin addresses of the wallet's network |
| `chain_ids` | empty | Ethereum | Chain ids the wallet may sign for |
| `erc20` | empty | Ethereum | Token contract → `max_per_tx`, `max_per_day`; only `transfer(address,uint256)` with exact 68-byte calldata and a recipient on the allow-list |
| `allow_contract_calls`, `contract_allowlist` | false, empty | Ethereum | Arbitrary calldata to listed contracts |
| `allow_contract_creation` | false | Ethereum | Transactions without `to` |
| `allow_message_signing` | false | Ethereum | EIP-191 |
| `allow_raw_digest` | false | both | Blind signing |
| `max_signatures_per_minute` | 600 | both | Per-wallet rate |

- REQ-POL-01 Deny by default: an empty policy permits nothing.
- REQ-POL-02 Numeric fields are exact unsigned integers; overflow, negative values, non-decimal encodings and unknown fields are rejected.
- REQ-POL-03 The daily total is rebuilt from the audit chain at boot and is checked and committed atomically with signing.
- REQ-POL-04 Each node enforces `max_per_day / lease_divisor`.
- REQ-POL-05 A frozen wallet signs nothing; any admin can freeze, only a quorum can unfreeze.

## 7. Persistent data

| File (under the data directory, mode 0700) | Content | Protection |
| --- | --- | --- |
| `state.json` | Cluster name, node id, quorum, lease divisor, CA certificate, principals (role, Ed25519 key, certificate fingerprint), wallets (id, label, chain, network, public key, address, blob, policy, frozen), sealed KEK, share records, used admin nonces, KEK wrap count | No secrets; SHA-256 anchored in the audit chain |
| `audit.log` | One JSON line per event | Hash chain, Ed25519 signatures, supervisor counter |
| `identity.sealed`, `tls/node.key.sealed` | Node identity seed, TLS private key | AES-256-GCM under `soc_seal`, mode 0600 |
| `identity.pub`, `tls/node.crt`, `tls/node.csr`, `tls/ca.crt` | Public material | The CA actually trusted is the copy in `state.json` |
| `cardslot/` | Software operator cards (prototype only) | Stand-in for the front-panel reader |

Audit line: `{"b": <body>, "h": "<hash>", "s": "<signature>"}` with `hash = SHA-256("OPENHSM-AUDIT-v1" ‖ prev_hash ‖ body_bytes)`, `signature = Ed25519(identity key, hash)`, and body fields `seq`, `ts`, `node`, `actor`, `event`, `ok`, `detail`, optional `state` (hash of the state file after the event), `prev`.

- REQ-INT-01 Boot fails unless every audit entry verifies, sequence numbers run from 1 without gaps, the last sequence number equals the supervisor counter (or is one ahead, which is completed), and `state.json` matches the last anchored hash.
- REQ-INT-02 Boot fails if the supervisor reports a tamper trip.
- REQ-INT-03 `hsmctl audit-verify` verifies a copy of the log with only the node's public identity key and rejects an empty log or one that does not begin with `node_init`.

Events recorded: `node_init`, `node_boot`, every successful signature with its spends, `policy_denied`, `sign_failed`, `forbidden`, `quorum_missing`, `auth_failure` (rate-limited), every administrative operation with its approvers, `tamper`, `rotation_aborted`.

## 8. Cryptographic algorithms

| Purpose | Algorithm | Notes |
| --- | --- | --- |
| Transaction signatures | ECDSA secp256k1, SHA-256/Keccak-256 digests, hedged RFC 6979 | On the module |
| Wallet, KEK, share wrapping | AES-256-GCM, 96-bit random IV, 128-bit tag | 32-byte records only; at most 2^31 wraps per KEK |
| Channel and response MAC, KDFs, fingerprints | HMAC-SHA256 | Labels in `FPGA/README.md` section 7 and section 3 above |
| KEK transfer | ECIES: ephemeral ECDH on secp256k1, HMAC-SHA256 KDF bound to both public keys, AES-256-GCM | Points validated before use |
| Break-glass | Shamir over GF(2^8), 2 ≤ m ≤ n ≤ 8, fingerprint check on restore | Card secret from HMAC-SHA1 challenge-response |
| Requests, audit chain, node identity | Ed25519 (strict verification) | |
| Transport | TLS 1.3 (rustls with ring), ECDSA P-256 certificates | |
| Hashes | SHA-256, Keccak-256, RIPEMD-160 (addresses) | |
| Random numbers | Module: TRNG with repetition-count and adaptive-proportion tests. Node: operating system CSPRNG | The model's source is the OS CSPRNG behind the same health tests |

## 9. Procedures

| Procedure | Steps |
| --- | --- |
| Create a cluster | `hsmctl pki init`; `hsmctl identity` per principal; `hsmctl genesis`; on the first node `openhsm-hwsim provision` (prototype), `openhsmd init`, sign its CSR, `openhsmd run`; quorum `kek_generate`; ceremony switch on; quorum `ceremony_split`; switch off |
| Create a wallet | Quorum `wallet_create` with label, chain, network and policy |
| Add a node | Initialise it from the same genesis; `enrol_begin` on the new node; switch on at the source; quorum `kek_export` naming the enrolment key; switch off; switch on at the new node; `kek_import`; switch off; `snapshot_export` at the source; quorum `snapshot_import` at the new node; compare `kek_fingerprint` |
| Recover from operator cards | New node from genesis; quorum `snapshot_import`; insert m cards; switch on; quorum `ceremony_restore`; switch off |
| Rotate the KEK | Quorum `rotate_begin`; for each other node `enrol_begin`, quorum `rotate_export`, `rotate_import`; `rotate_rewrap`; quorum `rotate_promote` on every node; repeat the split ceremony |
| Respond to tamper | The node zeroises itself and refuses to boot. Provision a new enclosure, initialise a new node, enrol or restore |
| Audit | `audit_tail` or a copy of `audit.log`; `hsmctl audit-verify`; compare the last entry with `audit_head` |

## 10. Verification

| Layer | What | Command | Result at 0.5.0 |
| --- | --- | --- | --- |
| Unit and integration tests | 49 tests: BIP-143, EIP-155, BIP-173/350 vectors, RFC 6979, policy, audit chain, module protocol, end-to-end node | `cargo test --release` | 49 pass |
| Lint | Clippy with warnings denied | `cargo clippy --workspace --all-targets -- -D warnings` | Clean |
| Dependencies | RustSec advisories | `cargo audit` | No advisories |
| Simulated penetration tests | 68 tests in 7 suites | `python3 pentest/run.py` | 65 pass, 2 findings against protocol 0xB1 (both closed in 0xB2), 1 residual-risk note |
| Demonstration | Full lifecycle on three nodes | `scripts/demo.sh` | Completes |

## 11. Document history

| Version | Change |
| --- | --- |
| 0.5.0 | First system specification. Adds protocol 0xB2, the supervisor interface, the node API, policy, persistent formats. Offline audit verification now rejects empty logs (penetration test E-05). |
