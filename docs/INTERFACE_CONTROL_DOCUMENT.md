# OpenHSM Interface Control Document

Version 0.5.0 (prototype). Companion documents: [System Design](SYSTEM_DESIGN.md), [System Specification](SYSTEM_SPECIFICATION.md), [Threat Model](THREAT_MODEL.md), [Penetration Test Report](PENETRATION_TEST_REPORT.md), [Compliance Mapping](COMPLIANCE.md), and the signing module's own specification in [`FPGA/README.md`](../FPGA/README.md).

This document lists every interface in the system in one place: who talks to whom, over what, in what format, and how the interface is protected. The specification says what each component must do; this document says what crosses each boundary. Where the two overlap, the byte-level definitions here were taken from the code at 0.5.0, and the code is authoritative.

## 1. Interface register

Status words: **Implemented** means working code in this repository. **Modelled** means a software model stands in for hardware. **RTL** means defined by the Verilog in `FPGA/`. **Hardware design** means described in the repository README only, with nothing in the prototype. **Open** means not yet defined.

| ID | Interface | Between | Medium in the product | In the prototype | Status |
| --- | --- | --- | --- | --- | --- |
| IF-01 | Node API | Application servers, operators ↔ SoC | TLS 1.3 over Ethernet (client port) | TLS 1.3 over TCP | Implemented |
| IF-02 | Signing module bus | SoC ↔ FPGA signing module | I2C, slave address 0x48 | Register reads and writes carried by IF-05 | RTL (0xB1); Modelled (0xB2) |
| IF-03 | Tamper secret delivery | Supervisor → signing module | Receive-only SPI | Function call inside the enclosure model | RTL; supervisor side Modelled |
| IF-04 | Module discrete signals | Supervisor, board → signing module | Tamper line, ceremony pin, clock, reset, LEDs | Model inputs | RTL except the ceremony pin (Modelled) |
| IF-05 | Supervisor services | SoC ↔ tamper supervisor | Open (board-level link not chosen) | Unix socket, binary RPC | Modelled; physical link Open |
| IF-06 | Sensors and key-switch | Physical world → supervisor | Mesh, lid switches, photodiode, accelerometer, voltage, temperature, key-switch | Physical-simulation socket | Modelled |
| IF-07 | Operator card | Operator's YubiKey ↔ SoC | USB CCID reader on the front panel | `ykman` call, or a file in `cardslot/` | Implemented with software cards; YubiKey path untested |
| IF-08 | Persistent storage | SoC ↔ NVMe drive | NVMe | Files in the data directory | Implemented |
| IF-09 | Node-to-node transfer | Node ↔ node, carried by an operator | Documents moved through IF-01 | Same | Implemented (no automatic replication) |
| IF-10 | Operator files | `hsmctl` ↔ operator workstation | Files | Same | Implemented |
| IF-11 | Command lines | Operator ↔ binaries | Shell | Same | Implemented |
| IF-12 | Cluster port | Node ↔ node | Ethernet (second port) | None | Hardware design; protocol Open |
| IF-13 | Power | PDUs → node; battery → tamper domain | Dual 12 V with ORing; CR123A cell | None | Hardware design |
| IF-T1 | Module pin simulator | Test tools ↔ signing-module model | None (never deployed) | Loopback TCP | Test fixture |

```
 application servers        operators (hsmctl)
        │  IF-01  TLS 1.3, signed requests  │        IF-10 files, IF-11 command lines
 ┌──────▼───────────────────────────────────▼──────┐
 │ SoC (openhsmd)                                  │── IF-08 ── NVMe
 │                                                 │── IF-07 ── operator card reader
 │                                                 │── IF-12 ── cluster port (open)
 └──────┬───────────────────────────┬──────────────┘
        │ IF-02  I2C                │ IF-05  supervisor services
 ┌──────▼──────────────┐   ┌────────▼─────────────┐
 │ Signing module      │◄──│ Tamper supervisor    │◄── IF-06 sensors, key-switch
 │ (FPGA)              │   │ (STM32U5)            │◄── IF-13 battery
 └─────────────────────┘   └──────────────────────┘
        IF-03 SPI (S), IF-04 tamper line, ceremony pin
 └────────────────── tamper enclosure ─────────────┘
```

## 2. IF-01 Node API

The only network interface of the node. Source: `crates/openhsm-node/src/proto.rs`, `server.rs`, `api.rs`.

### 2.1 Transport

| Property | Value |
| --- | --- |
| Protocol | TLS 1.3 only. The client must present a certificate that chains to the cluster CA held in the node state |
| Certificates | ECDSA P-256 |
| Listener | Address given to `openhsmd run --listen` |
| Connection limits | 256 in total, 32 per source address |
| Deadlines | 5 s to finish the handshake, 60 s per frame |
| Framing | 4-byte big-endian length, then one JSON document. Length 0 or above 16 MiB is rejected |

### 2.2 Messages

```
request  = { "payload": "<JSON text>", "sigs": [ { "id": "<principal>", "sig": "<hex>" }, … ] }
payload  = { "v": 1, "cluster": "…", "node": "…"?, "ts": <ms>, "exp": <ms>?,
             "nonce": "<32 hex>", "method": "…", "params": { … } }
sig      = Ed25519(principal key, "OPENHSM-REQ-v1\0" ‖ payload bytes)
response = { "ok": true, "result": … }
         | { "ok": false, "error": { "code": "…", "message": "…" } }
```

The payload travels as a string so that the signature covers the exact bytes that were signed. Unknown fields are rejected at every level. At most 16 signatures per request. `node` and `exp` are required for quorum methods; `exp` may be at most 24 hours after `ts`. For other methods `ts` must be within 30 s of the node's clock.

The first entry in `sigs` is the sender. Its registered certificate fingerprint must equal the certificate on the connection. The order of checks is in the specification, section 5.2.

### 2.3 Methods

Access: **any** is every registered principal; **quorum** is at least the configured number of distinct admin signatures on the same payload. Methods marked ⚿ also need the ceremony key-switch on (IF-06).

| Method | Access | Parameters | Result |
| --- | --- | --- | --- |
| `status` | any | none | `node`, `cluster`, `version`, `signer_protocol`, `signer_status`, `kek_loaded`, `rotation_pending`, `ceremony_switch`, `shares_recorded`, `wallets`, `principals`, `quorum`, `audit_seq`, `audit_head`, `identity`, `tamper`, `boot_ms` |
| `wallet_list` | any | none | Array of wallet records (below) |
| `wallet_get` | any | `wallet` | Wallet record plus `policy` |
| `eth_sign_transaction` | signer | `wallet`, `tx` (2.4) | `raw_tx`, `tx_hash`, `from`, `y_parity`, `r`, `s` |
| `btc_sign_transaction` | signer | `wallet`, `tx` (2.4) | `raw_tx`, `txid`, `fee`, `vsize`, `from` |
| `eth_sign_message` | signer | `wallet`, `message` (hex, at most 64 KiB) | `signature`, `address` |
| `sign_digest` | signer | `wallet`, `digest` (32 bytes, hex) | `r`, `s`, `recovery_id` |
| `audit_head` | admin, auditor | none | `seq`, `hash`, `identity` |
| `audit_tail` | admin, auditor | `from_seq` (default 0: the newest), `limit` (default 100, at most 1000) | `lines` (audit lines as text), `identity` |
| `kek_fingerprint` | admin | none | `fingerprint` |
| `enrol_begin` | admin | none | `enrol_x`, `enrol_y`, `enrol_fp`, `node` |
| `kek_import` ⚿ | admin | KEK transfer document (section 9.2) | `kek_fp` |
| `rotate_import` ⚿ | admin | KEK transfer document | `rotation_pending` |
| `rotate_rewrap` | admin | none | `rewrapped` (count) |
| `snapshot_export` | admin | none | Snapshot document (section 9.1) |
| `wallet_freeze` | admin | `wallet` | `wallet`, `frozen: true` |
| `kek_generate` | quorum | none | `kek_fp` |
| `kek_erase` | quorum | none | `kek_loaded: false` |
| `kek_export` ⚿ | quorum | `enrol_x`, `enrol_y`, `node` (the receiving node) | KEK transfer document |
| `rotate_begin` | quorum | none | `rotation_pending` |
| `rotate_export` ⚿ | quorum | `enrol_x`, `enrol_y`, `node` | KEK transfer document |
| `rotate_promote` | quorum | none | `kek_fp`, `shares_recorded: false` |
| `wallet_create` | quorum | `label` (at most 128 characters), `chain` (`ethereum` or `bitcoin`), `network` (Bitcoin only: `mainnet`, `testnet`, `signet`, `regtest`), `policy` | Wallet record |
| `policy_set` | quorum | `wallet`, `policy` | `wallet`, `policy` |
| `wallet_unfreeze` | quorum | `wallet` | `wallet`, `frozen: false` |
| `principal_add` | quorum | `id`, `role` (`admin`, `signer`, `auditor`), `pubkey`, `cert_fp` | `id`, `role` |
| `principal_remove` | quorum | `id` | `removed` |
| `ceremony_split` ⚿ | quorum | `m`, `cards` (card names, section 7) | Share set (section 9.1) |
| `ceremony_restore` ⚿ | quorum | `cards` | `kek_fp` |
| `snapshot_import` | quorum | `snapshot` | `wallets` (count), `verified` |

Wallet record: `id` (16 bytes, hex), `label`, `chain`, `network`, `address`, `pubkey` (33-byte compressed, hex), `frozen`, `created_ms`. The wrapped key blob is never returned by `wallet_list` or `wallet_get`; it appears only inside a snapshot.

The policy object is defined in the specification, section 6.

### 2.4 Transaction requests

Ethereum `tx`:

| Field | Type | Notes |
| --- | --- | --- |
| `type` | string | `eip1559` (default) or `legacy` |
| `chain_id` | integer | Required; 0 is refused |
| `nonce`, `gas_limit` | integer | |
| `to` | string | EIP-55 checksummed address; omit for contract creation |
| `value` | decimal string | Wei; default 0 |
| `data` | hex string | Default empty |
| `max_fee_per_gas`, `max_priority_fee_per_gas` | decimal string | EIP-1559 only |
| `gas_price` | decimal string | Legacy only |
| `access_list` | array | Optional |

Bitcoin `tx`:

| Field | Type | Notes |
| --- | --- | --- |
| `inputs` | array of `{ txid, vout, amount, sequence? }` | `amount` in satoshi. Every input must belong to the wallet |
| `outputs` | array of `{ address, amount }` | Addresses of the wallet's network. No raw scripts |
| `version` | integer | 1 or 2 |
| `locktime` | integer | Default 0 |

The caller never supplies a hash or a signature-hash type. The node encodes the transaction and computes the digest itself.

### 2.5 Error codes

| Code | Meaning |
| --- | --- |
| `unauthenticated` | A signature, principal or certificate binding failed. One message for all causes |
| `forbidden` | The caller's role may not call the method |
| `quorum_required` | Too few distinct admin signatures |
| `bad_request` | Malformed or inconsistent request |
| `not_found` | Unknown method, wallet or principal |
| `stale` | Timestamp outside the window, expired, or validity too long |
| `replay` | Nonce already used |
| `rate_limited` | Per-principal limit (200 requests/s, burst 400) |
| `policy_denied` | The wallet policy does not allow the request |
| `frozen` | The wallet is frozen |
| `ceremony_required` | The key-switch is off |
| `signer_error` | The signing module refused or failed |
| `tamper` | The node has tripped and serves nothing |
| `internal` | Fault inside the node |

A plain request repeated with the same principal, nonce and body returns the stored response without signing again.

## 3. IF-02 Signing module bus

The only data path into the signing module. Source: `FPGA/V0.4/sign_node_top.v` (protocol 0xB1), `crates/openhsm-signer/src/lib.rs` (protocol 0xB2).

### 3.1 Electrical and framing

I2C slave, 7-bit address 0x48 by default. Single-byte register pointer that auto-increments; multi-byte values are big-endian. No clock stretching: the system clock must be at least 8 times SCL. Buffers can be written only while the module is idle.

### 3.2 Register map

| Address | Name | Dir | Size | Content |
| --- | --- | --- | --- | --- |
| 0x00 | STATUS | R | 1 | b0 busy, b1 done, b2 error, b3 KEK loaded, b4 tamper, b5 TRNG fail, b6 session up, b7 enrolment key |
| 0x01 | CMD | W | 1 | Writing starts the command |
| 0x02 | ERROR | R | 1 | Error code of the last command |
| 0x03 | STATUS2 | R | 1 | b6 slot-2 KEK, b5 sharing active, b3:0 shares held |
| 0x04 | CTR | W | 4 | Strictly increasing counter |
| 0x08 | NONCE | R | 16 | Random per session |
| 0x18 | WID | R/W | 16 | Wallet id (AAD) or share header |
| 0x28 | IV | R/W | 12 | GCM IV |
| 0x34 | TAG | R/W | 16 | GCM tag |
| 0x44 | BUF_A | R/W | 32 | Wrapped key, ciphertext, r, or public x |
| 0x64 | BUF_B | R/W | 32 | Digest, s, public y, point x, or card secret |
| 0x84 | BUF_C | R/W | 32 | Point y |
| 0xA4 | MAC | W | 32 | Command MAC |
| 0xC4 | RMAC | R | 32 | Response MAC (0xB2 only) |
| 0xFF | VERSION | R | 1 | 0xB1 on the RTL, 0xB2 on the model |

### 3.3 Authentication

```
command MAC  = HMAC-SHA256(chan_key, nonce(16) ‖ ctr(4) ‖ cmd(1) ‖ WID ‖ IV ‖ TAG ‖ A ‖ B ‖ C)      161 bytes
response MAC = HMAC-SHA256(chan_key, "SN-RESP-v1" ‖ nonce(16) ‖ ctr(4) ‖ cmd(1) ‖ error(1)
                                     ‖ WID ‖ IV ‖ TAG ‖ A ‖ B ‖ C)                               0xB2 only
```

Every command needs a valid MAC and a counter greater than the last accepted one. In 0xB2, eight consecutive failures lock the channel until reset, any error clears IV, TAG, A, B and C, and the MAC register is cleared after every command.

### 3.4 Commands

| Code | Command | Inputs | Outputs |
| --- | --- | --- | --- |
| 0x10 | KEK_GEN | none (only if no KEK) | KEK loaded |
| 0x11 | KEK_SEAL | none | IV, TAG, A = KEK sealed under the seal key |
| 0x12 | KEK_UNSEAL | IV, TAG, A | KEK loaded (only if none) |
| 0x13 | KEK_ERASE | none | KEK, slot 2, enrolment key and sharing state cleared |
| 0x14 | KEK_NEW_GEN | none | New KEK in slot 2 |
| 0x15 | REWRAP | WID, IV, TAG, A | IV, TAG, A = blob under the slot-2 KEK |
| 0x16 | KEK_PROMOTE | none | Slot 2 becomes the KEK |
| 0x17 | KEK_FP | none | B = KEK fingerprint |
| 0x20 | GEN_WALLET | WID | IV, TAG, A = wrapped key; B, C = public key |
| 0x21 | SIGN | WID, IV, TAG, A, B = digest | A = r, B = s |
| 0x22 | PUBKEY | WID, IV, TAG, A | A = x, B = y |
| 0x40 | ENROL_GEN | none | B, C = enrolment public key |
| 0x41 ⚿ / 0x45 ⚿ | KEK_EXPORT / KEK_NEW_EXPORT | B, C = recipient enrolment key | IV, TAG, A = ciphertext; B, C = ephemeral public key |
| 0x42 ⚿ / 0x46 ⚿ | KEK_IMPORT / KEK_NEW_IMPORT | IV, TAG, A; B, C = ephemeral public key | KEK (or slot 2) loaded |
| 0x50 ⚿ | SPLIT_BEGIN | B top byte = m, next byte = n | WID = header template |
| 0x51 ⚿ | SHARE_GET | WID = header, B = card secret | IV, TAG, A = wrapped share |
| 0x52 | SPLIT_END | none | Sharing polynomial discarded |
| 0x53 ⚿ | SHARE_PUT | WID = header, IV, TAG, A, B = card secret | Share stored |
| 0x54 ⚿ | RESTORE | none | KEK rebuilt and loaded |
| 0x55 | RESTORE_ABORT | none | Stored shares discarded |
| 0x56 ⚿ | SHARE_GET_C (0xB2) | As 0x51, with B masked | As 0x51 |
| 0x57 ⚿ | SHARE_PUT_C (0xB2) | As 0x53, with B masked | As 0x53 |

⚿ In 0xB2 these return error 8 unless the ceremony pin (IF-04) is high. The mask for 0x56 and 0x57 is `HMAC-SHA256(chan_key, "SN-CONF-v1" ‖ nonce ‖ ctr)` XORed onto BUF_B. The node uses 0x56 and 0x57 and never 0x51 or 0x53.

### 3.5 Error codes

| Code | Meaning | Code | Meaning |
| --- | --- | --- | --- |
| 0 | OK | 8 | Bad command |
| 1 | No session | 9 | Bad parameter |
| 2 | No KEK | 10 | Unwrap or blob authentication failed |
| 3 | KEK already loaded | 11 | Invalid curve point |
| 4 | TRNG failure | 12 | No enrolment key |
| 5 | MAC or counter rejected | 13 | Share rejected |
| 6 | Signing failed | 14 | Not enough shares, or no active split |
| 7 | Tamper | 15 | No slot-2 KEK |

## 4. IF-03 and IF-04 Supervisor to signing module

| Signal | Direction | Definition |
| --- | --- | --- |
| SPI (SCLK, MOSI, CS) | Supervisor → module | Mode 0, MSB first, no MISO. One 33-byte frame: 0xA5, then the 32-byte tamper secret S. A wrong header or length is discarded. Accepted once per reset. System clock at least 4 times SCLK |
| `tamper` | Supervisor → module | Active high, asynchronous. Zeroes the secret store, sharing state and engine registers at once and latches until reset. Hold high while the fault lasts |
| `ceremony` | Supervisor → module | Level input driven from the physical key-switch. Low disables the commands marked ⚿ in section 3.4. Defined in 0xB2 only; not yet in the RTL |
| Clock, reset | Board → module | Reset clears the session; S must be sent again |
| `led_busy`, `led_kek`, `led_tamper` | Module → front panel | Status indicators |

From S the module derives `chan_key = HMAC-SHA256(S, "SN-CHAN")` and `seal_key = HMAC-SHA256(S, "SN-SEAL")`. S never appears on IF-02 or IF-05.

## 5. IF-05 Supervisor services

What the SoC can ask of the tamper supervisor. In the code this is the `Hardware` trait (`crates/openhsm-hw/src/lib.rs`), which also carries the IF-02 register accesses so that one link reaches everything inside the enclosure.

| Op | Call | Request payload | Reply payload |
| --- | --- | --- | --- |
| 1 | `bus_write` | pointer(1) ‖ data | empty |
| 2 | `bus_read` | pointer(1) ‖ count(2) | data, at most 256 bytes |
| 3 | `restart_signer` | empty | empty. Resets the module and resends S over IF-03 |
| 4 | `soc_keys` | empty | chan(32) ‖ seal(32). `chan` = HMAC-SHA256(S, "SN-CHAN"), `seal` = HMAC-SHA256(S, "SOC-SEAL-v1"). Fails after a tamper event |
| 5 | `counter` | empty | 64-bit big-endian monotonic counter |
| 6 | `counter_increment` | empty | New counter value |
| 7 | `tamper_status` | empty | Empty, or JSON `{ "sensor": "…", "ts": <ms> }` |
| 8 | `ceremony_enabled` | empty | One byte, 0 or 1 |

Prototype encoding, over a Unix socket with mode 0600:

```
request : op(1) len(2, big-endian) payload(len)
response: status(1; 0 = ok) len(2) payload(len)      payload = error text if status ≠ 0
```

The supervisor never returns S, and no call can set the ceremony switch or clear a tamper latch.

**Open item.** The physical link between the SoC and the STM32U5 on the carrier board (bus, framing, and how `soc_keys` is protected in transit) is not defined. The supervisor firmware does not exist yet. The eight calls above are the functional contract that link must carry.

## 6. IF-06 Sensors and key-switch

Inputs to the supervisor from the physical world. Software on the SoC cannot drive them.

| Input | Effect |
| --- | --- |
| `mesh`, `lid`, `light`, `accelerometer`, `voltage`, `temperature` | Any trip erases S, latches across power cycles, and asserts the module's tamper line |
| Ceremony key-switch | Sets the ceremony pin (IF-04) and the value read by `ceremony_enabled` |
| Power | Loss of main power clears the module's volatile KEK; the supervisor's battery domain keeps S and the counter |

Prototype: one text command per connection on the physical-simulation socket, one line of reply.

| Command | Meaning |
| --- | --- |
| `tamper <sensor>` | Trip the named sensor |
| `ceremony on` / `ceremony off` | Turn the key-switch |
| `power-cycle` | Remove and restore main power |
| `trng-fail on` / `trng-fail off` | Force the module's entropy source to fail (simulation only) |
| `glitch` | Corrupt the next signature computation (simulation only) |
| `status` | `tripped`, `ceremony`, `counter`, `signer_status` |

Sensor thresholds, debounce times and the electrical interface of each sensor are not specified yet.

## 7. IF-07 Operator card

A card maps a 32-byte challenge to a secret response. It is used only in `ceremony_split` and `ceremony_restore`.

| Card name in a request | Mechanism |
| --- | --- |
| `yubikey:<serial>` or `yubikey:<serial>:<slot>` | YubiKey OTP slot (1 or 2, default 2) in HMAC-SHA1 challenge-response mode with touch required. The node runs `ykman --device <serial> otp calculate <slot> <challenge hex>`. Not yet tested on hardware |
| `<name>` | Software card: file `cardslot/<name>.card` in the node data directory holding a 20-byte HMAC-SHA1 key in hex. Test double only |

```
response    = HMAC-SHA1(card key, challenge)
card secret = HMAC-SHA256(key = response, "SN-CARD-v1" ‖ challenge)
```

The card never sees a share and the module never sees the card's key. The card secret exists on the SoC for one command and crosses IF-02 masked (commands 0x56 and 0x57).

## 8. IF-08 Persistent storage

Files under the node data directory (mode 0700). Formats are in the specification, section 7.

| File | Written by | Content | Protection |
| --- | --- | --- | --- |
| `state.json` | Node, atomically on every state change | Cluster, node id, quorum, CA certificate, principals, wallets with wrapped blobs and policies, sealed KEK, share records, used admin nonces | No secrets in the clear. SHA-256 anchored in the audit chain |
| `audit.log` | Node, append-only | One JSON line per event: `{ "b": body, "h": hash, "s": signature }` | Hash chain, Ed25519 signature per line, last sequence number mirrored in the supervisor counter |
| `identity.sealed`, `tls/node.key.sealed` | Node at `init` | Node identity seed, TLS private key | AES-256-GCM under the `seal` key from IF-05, mode 0600 |
| `identity.pub`, `tls/node.csr`, `tls/node.crt`, `tls/ca.crt` | Node and operator | Public material | The trusted CA is the copy inside `state.json` |
| `cardslot/` | Operator (prototype only) | Software operator cards | None; stand-in for the card reader |
| `sim.sock` | Node with `--sim-physical` (prototype only) | Physical-simulation socket for an in-process enclosure | Mode 0600 |

## 9. IF-09 and IF-10 Documents

All are JSON. Unknown fields are rejected on input.

### 9.1 Passed between nodes through the API

| Document | Produced by | Consumed by | Fields |
| --- | --- | --- | --- |
| Enrolment key | `enrol_begin` on the new node | `kek_export` or `rotate_export` on the source | `enrol_x`, `enrol_y` (32 bytes each, hex), `enrol_fp`, `node` |
| KEK transfer | `kek_export`, `rotate_export` | `kek_import`, `rotate_import` | `iv`, `tag`, `ct`, `tx`, `ty` (hex). ECIES ciphertext of the KEK and the ephemeral public key |
| Snapshot | `snapshot_export` | `snapshot_import` | `cluster`, `exported_ms`, `kek_fp`, `wallets` (id → full wallet record with `blob`), `share_set` |
| Share set | `ceremony_split` | Stored in `state.json`, travels in snapshots | `m`, `n`, `fp`, `records`: each `x`, `card`, `challenge`, `header`, `blob` |

A blob is `{ "iv", "tag", "ct" }` in hex: AES-256-GCM output for a 32-byte record. A KEK transfer opens only inside the module that generated the enrolment key. A snapshot contains wrapped keys only and is useless without the KEK; on import, when the node holds the KEK, every blob must open and match its recorded public key.

### 9.2 Operator files

| File | Written by | Content |
| --- | --- | --- |
| `ca.crt`, `ca.key` | `hsmctl pki init` | Cluster CA. Keep `ca.key` offline |
| `<name>.crt`, `<name>.key` | `hsmctl identity` | TLS client certificate and key of a principal |
| `<name>.sign` | `hsmctl identity` | Ed25519 request-signing key (32-byte seed, hex) |
| `<name>.principal.json` | `hsmctl identity` | Registration record: role, Ed25519 public key, certificate fingerprint |
| Genesis | `hsmctl genesis` | `cluster`, `quorum`, `lease_divisor`, `ca_cert_pem`, `principals` |
| Profile | `hsmctl profile` | `addr`, `server_name`, `cluster`, `id`, and paths `ca`, `cert`, `key`, `sign_key` |
| Operation | `hsmctl propose`, then `approve` | A request frame as in 2.2 with the signatures collected so far. Validity 1 to 24 hours (default 12) |

## 10. IF-11 Command lines

```
openhsmd init --data DIR --genesis FILE --node-id ID [--san NAME]... [--hardware inproc|unix:PATH]
openhsmd run  --data DIR --listen ADDR [--hardware inproc|unix:PATH] [--sim-physical] [--no-audit-fsync]

openhsm-hwsim provision --state DIR
openhsm-hwsim run --state DIR --soc-socket PATH --physical-socket PATH

hsmctl pki init | pki sign-csr
hsmctl identity | genesis | profile
hsmctl call --profile FILE METHOD [PARAMS | @FILE]
hsmctl propose | approve | submit
hsmctl audit-verify
hsmctl card-new
hsmctl sim --socket PATH COMMAND...          (prototype only; commands of section 6)
```

`--hardware unix:PATH` selects the enclosure process over IF-05; `inproc` runs the enclosure model inside the daemon and is for tests. Run any command with `--help` for its options.

## 11. Interfaces that exist only in the hardware design

The repository README and bill of materials describe these. The prototype does not implement them and this document does not yet define them.

| ID | Interface | What is known | What is open |
| --- | --- | --- | --- |
| IF-12 | Cluster port | Second Ethernet port for node-to-node traffic | Protocol, authentication, replication format. The prototype replicates by snapshot through IF-01 |
| IF-13 | Power | Two 12 V feeds with ORing, 5 V and 3.3 V rails; CR123A cell for the tamper domain | Brown-out thresholds, battery-low signalling to the SoC |
| IF-05 | SoC to supervisor link | Functional contract in section 5 | Bus and transit protection |
| IF-07 | Card reader | USB CCID reader on the front panel | Whether YubiKey HMAC challenge-response is reached through `ykman`, as now, or directly |

## 12. Test-only interface IF-T1

`openhsm-signer-sim` exposes the pins of the signing-module model on a loopback TCP socket so that `FPGA/V0.4/sn_host.py`, `sn_ceremony.py` and the penetration tests can drive it. It gives its peer the physical pins of the module and must never be deployed.

```
request : op(1) arg(1) len(2, big-endian) data(len)
response: len(2, big-endian) data(len)
```

| Op | Meaning |
| --- | --- |
| 0x01 | I2C write: arg = register pointer, data = bytes |
| 0x02 | I2C read: arg = register pointer, len = bytes to read |
| 0x10 | SPI frame from the supervisor (0xA5 ‖ S) |
| 0x11 | Tamper pin: arg = level |
| 0x12 | Reset |
| 0x13 | TRNG fault: arg = 1 forces failure |
| 0x14 | Glitch: corrupt the next signature |
| 0x15 | Ceremony pin: arg = level |

## 13. Secrets by interface

What sensitive material is allowed to cross each interface. The penetration tests named check these by exact-byte search.

| Interface | May cross | Must never cross | Checked by |
| --- | --- | --- | --- |
| IF-01 | Public keys, addresses, signatures, wrapped blobs (in snapshots), ECIES ciphertext | Wallet keys, KEK, S, `chan`, `seal` | B-09 |
| IF-02 | Wrapped blobs, digests, signatures, public keys, masked card secret | Wallet keys, KEK, S, seal key, card secret in the clear | A-07, A-13 |
| IF-03 | S | Anything in the other direction | By construction: the link has no MISO line |
| IF-05 | `chan`, `seal`, counter, tamper status | S, the module's seal key | A-14, F-08 |
| IF-07 | Challenge, HMAC-SHA1 response | Shares, KEK | F-06 |
| IF-08 | Wrapped blobs, sealed KEK, sealed node keys, share records | Any key in the clear | E-01 |
| IF-09 | Wrapped blobs, ECIES ciphertext, wrapped shares | Any key in the clear | F-06, F-07 |

## 14. Document history

| Version | Change |
| --- | --- |
| 0.5.0 | First interface control document, written from the 0.5.0 code and `FPGA/README.md`. |
