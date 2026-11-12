# OpenHSM Interface Control Document

Version 0.5.0 (prototype). Companion documents: [System Design](SYSTEM_DESIGN.md), [System Specification](SYSTEM_SPECIFICATION.md), [Threat Model](THREAT_MODEL.md), [Penetration Test Report](PENETRATION_TEST_REPORT.md), [Compliance Mapping](COMPLIANCE.md), and the signing module's own specification in [`FPGA/README.md`](../FPGA/README.md).

This document lists every interface in the system in one place: who talks to whom, over what, in what format, and how the interface is protected. The specification says what each component must do; this document says what crosses each boundary. Where the two overlap, the byte-level definitions here were taken from the code at 0.5.0, and the code is authoritative.

## 1. Interface register

Status words: **Implemented** means working code in this repository. **Modelled** means a software model stands in for hardware. **RTL** means defined by the Verilog in `FPGA/`. **Hardware design** means described in the repository README only, with nothing in the prototype. **Open** means not yet defined.

| ID | Interface | Between | Medium in the product | In the prototype | Status |
| --- | --- | --- | --- | --- | --- |
| IF-01 | Node API | Application servers, operators ↔ SoC | TLS 1.3 over Ethernet (client port) | TLS 1.3 over TCP | Implemented |
| IF-02 | Signing module bus | SoC ↔ FPGA signing module | I2C, slave address 0x48 | Register reads and writes carried by IF-05 | RTL (0xB2, `FPGA/V0.5`) and model |
| IF-03 | Tamper secret delivery | Supervisor → signing module | Receive-only SPI | Function call inside the enclosure model | RTL; supervisor side Modelled |
| IF-04 | Module discrete signals | Supervisor, board → signing module | Tamper line, ceremony pin, clock, reset, LEDs | Model inputs | RTL |
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

The only data path into the signing module. Source: `FPGA/V0.5/sign_node_top.v` and `crates/openhsm-signer/src/lib.rs` (both protocol 0xB2). `FPGA/V0.4` is the earlier protocol 0xB1, which lacks RMAC, the lockout, commands 0x56 and 0x57 and the ceremony pin.

### 3.1 Electrical and framing

I2C slave, 7-bit address 0x48 by default. Single-byte register pointer that auto-increments; multi-byte values are big-endian. No clock stretching: the system clock must be at least 8 times SCL. Buffers can be written only while the module is idle.

### 3.2 Register map

| Address | Name | Dir | Size | Content |
| --- | --- | --- | --- | --- |
| 0x00 | STATUS | R | 1 | b0 busy, b1 done, b2 error, b3 KEK loaded, b4 tamper, b5 TRNG fail, b6 session up, b7 enrolment key |
| 0x01 | CMD | W | 1 | Writing starts the command |
| 0x02 | ERROR | R | 1 | Error code of the last command |
| 0x03 | STATUS2 | R | 1 | b7 command channel locked, b6 slot-2 KEK, b5 sharing active, b4 ceremony pin, b3:0 shares held |
| 0x04 | CTR | W | 4 | Strictly increasing counter |
| 0x08 | NONCE | R | 16 | Random per session |
| 0x18 | WID | R/W | 16 | Wallet id (AAD) or share header |
| 0x28 | IV | R/W | 12 | GCM IV |
| 0x34 | TAG | R/W | 16 | GCM tag |
| 0x44 | BUF_A | R/W | 32 | Wrapped key, ciphertext, r, or public x |
| 0x64 | BUF_B | R/W | 32 | Digest, s, public y, point x, or card secret |
| 0x84 | BUF_C | R/W | 32 | Point y |
| 0xA4 | MAC | W | 32 | Command MAC |
| 0xC4 | RMAC | R | 32 | Response MAC |
| 0xFF | VERSION | R | 1 | 0xB2 |

### 3.3 Authentication

```
command MAC  = HMAC-SHA256(chan_key, nonce(16) ‖ ctr(4) ‖ cmd(1) ‖ WID ‖ IV ‖ TAG ‖ A ‖ B ‖ C)      161 bytes
response MAC = HMAC-SHA256(chan_key, "SN-RESP-v1" ‖ nonce(16) ‖ ctr(4) ‖ cmd(1) ‖ error(1)
                                     ‖ WID ‖ IV ‖ TAG ‖ A ‖ B ‖ C)                               172 bytes
```

Every command needs a valid MAC and a counter greater than the last accepted one. Eight consecutive failures lock the channel until reset, any error clears IV, TAG, A, B and C, and the MAC register is cleared after every command. A command that fails authentication produces no response MAC; RMAC then reads as zero.

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
| 0x56 ⚿ | SHARE_GET_C | As 0x51, with B masked | As 0x51 |
| 0x57 ⚿ | SHARE_PUT_C | As 0x53, with B masked | As 0x53 |

⚿ These return error 8 unless the ceremony pin (IF-04) is high. The mask for 0x56 and 0x57 is `HMAC-SHA256(chan_key, "SN-CONF-v1" ‖ nonce ‖ ctr)` XORed onto BUF_B. The node uses 0x56 and 0x57 and never 0x51 or 0x53.

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
| `ceremony` | Supervisor → module | Level input driven from the physical key-switch. Low disables the commands marked ⚿ in section 3.4. Must not be routed to the SoC |
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

## 14. Message construction

How each message is laid out: the order of the bytes, what each field means, and what each bit of a status byte reports. The examples are real output of the prototype, produced by `scripts/message_examples/` and checked with code that shares nothing with the node (section 14.8). Nonces, wallet keys and timestamps are random or time-dependent, so a new run gives different hex with the same layout; the values below are from one run.

### 14.1 Conventions

| Item | Rule |
| --- | --- |
| Byte order | Big-endian for every multi-byte value on IF-02, IF-05 and in the API, except where an external format says otherwise (Bitcoin amounts and version are little-endian, as the Bitcoin format requires) |
| Bit numbering | b0 is the least significant bit, b7 the most significant. `0x4A` is `0100 1010` |
| Integers on the module bus | r, s, x, y, digests and keys are 32-byte unsigned big-endian values, left-padded with zeros |
| Unused buffers | Written as zero bytes. The MAC covers all of them, so a command with unused buffers still sends them as zeros |
| `‖` | Concatenation |

### 14.2 Signing module: one command

#### 14.2.1 The I2C transactions

With the default slave address 0x48, the first byte of every transaction is 0x90 for a write and 0x91 for a read.

```
write  :  S  0x90  ptr  d0 d1 … dn  P                 ptr is the register address; it advances after each byte
read   :  S  0x90  ptr  Sr  0x91  b0 b1 … bn  P       the host acknowledges every byte but the last
```

To run one command the host performs these writes in this order, then polls. The order of the first eight is free; writing CMD last is what starts the command.

| Step | Register | Bytes | Example transaction (counter 3) |
| --- | --- | --- | --- |
| 1 | WID 0x18 | 16 | `90 18` ‖ wallet id |
| 2 | IV 0x28 | 12 | `90 28` ‖ IV |
| 3 | TAG 0x34 | 16 | `90 34` ‖ tag |
| 4 | BUF_A 0x44 | 32 | `90 44` ‖ A |
| 5 | BUF_B 0x64 | 32 | `90 64` ‖ B |
| 6 | BUF_C 0x84 | 32 | `90 84` ‖ C |
| 7 | CTR 0x04 | 4 | `90 04 00 00 00 03` |
| 8 | MAC 0xA4 | 32 | `90 A4` ‖ command MAC |
| 9 | CMD 0x01 | 1 | `90 01 21` (0x21 = SIGN) |
| 10 | Poll STATUS 0x00 until b1 (done) is 1 | 1 | `90 00` `91` → one byte |
| 11 | Read ERROR 0x02, the buffers, RMAC 0xC4 | | Accept the result only if RMAC verifies |

The pointer auto-increments, so WID, IV and TAG, which are adjacent, could be written in one transaction starting at 0x18 (16 + 12 + 16 = 44 bytes, ending at 0x43). Registers may be written only while the module is idle.

#### 14.2.2 The command MAC: what it covers and where

```
offset  len  field                        notes
     0   16  NONCE      register 0x08    read from the module after S arrives; random per session
    16    4  CTR        register 0x04    strictly increasing; the first command of a session uses 1
    20    1  CMD                         the byte written to register 0x01
    21   16  WID        register 0x18
    37   12  IV         register 0x28
    49   16  TAG        register 0x34
    65   32  BUF_A      register 0x44
    97   32  BUF_B      register 0x64
   129   32  BUF_C      register 0x84
   161                                   total 161 bytes
MAC = HMAC-SHA256(chan_key, those 161 bytes)        written to register 0xA4
```

The response MAC is computed by the module over the buffers as the command left them and read back from register 0xC4:

```
offset  len  field
     0   10  ASCII "SN-RESP-v1"
    10   16  NONCE
    26    4  CTR           the counter of the command being answered
    30    1  CMD           the byte the host wrote
    31    1  ERROR         0 on success
    32   16  WID           as left by the command
    48   12  IV
    60   16  TAG
    76   32  BUF_A
   108   32  BUF_B
   140   32  BUF_C
   172                    total 172 bytes
RMAC = HMAC-SHA256(chan_key, those 172 bytes)
```

#### 14.2.3 What each command puts in each buffer

Anything not listed is zero on input. "Out" means the module overwrites it.

| Command | WID | IV / TAG | BUF_A | BUF_B | BUF_C |
| --- | --- | --- | --- | --- | --- |
| `GEN_WALLET` 0x20 | In: the new wallet id (16 bytes chosen by the host) | Out: GCM IV and tag of the wrapped key | Out: wrapped private key (ciphertext, 32 bytes) | Out: public key x | Out: public key y |
| `SIGN` 0x21 | In: wallet id | In: from `GEN_WALLET` | In: wrapped key | In: digest (32 bytes). Out: s | zero in, zero out |
| `PUBKEY` 0x22 | In: wallet id | In | In: wrapped key. Out: x | Out: y | zero |
| `ENROL_GEN` 0x40 | zero | zero | zero | Out: enrolment public key x | Out: y |
| `KEK_EXPORT` 0x41 | zero | Out: IV and tag of the transfer | Out: KEK ciphertext (32 bytes) | In: recipient enrolment x. Out: ephemeral T.x | In: recipient y. Out: T.y |
| `KEK_IMPORT` 0x42 | zero | In | In: ciphertext | In: T.x | In: T.y |
| `SPLIT_BEGIN` 0x50 | Out: share header template | zero | zero | In: byte 0 = m, byte 1 = n (the rest zero). That is B[255:248] and B[247:240] | zero |
| `SHARE_GET_C` 0x56 | In: share header | Out: share IV and tag | Out: wrapped share | In: card secret XOR mask (14.2.4) | zero |
| `SHARE_PUT_C` 0x57 | In: share header | In | In: wrapped share | In: card secret XOR mask | zero |
| `KEK_FP` 0x17 | zero | zero | zero | Out: HMAC-SHA256(KEK, "KEK-FP-v1") | zero |

`SIGN` returns r in BUF_A and s in BUF_B. The digest the host put in BUF_B is overwritten by s. The module does not return a recovery id; the node tries both values against the wallet's recorded public key and keeps the one that recovers it.

The share header (WID in the sharing commands) is 16 bytes: `x (1) ‖ m (1) ‖ n (1) ‖ fingerprint (13)`, where the fingerprint is the first 13 bytes of HMAC-SHA256(KEK, "KEK-FP-v1").

#### 14.2.4 The masked card secret

For commands 0x56 and 0x57 the host sends `BUF_B = r XOR mask`, where `mask = HMAC-SHA256(chan_key, "SN-CONF-v1" ‖ nonce(16) ‖ ctr(4))` and `ctr` is the counter of that same command. The MAC covers the masked value. A different counter gives a different mask, so a copy recorded from the bus is no use for another command.

#### 14.2.5 Reading STATUS and STATUS2

STATUS (0x00):

| Bit | 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Meaning | enrolment key present | session up | TRNG failed | tamper | KEK loaded | error | done | busy |

STATUS2 (0x03):

| Bit | 7 | 6 | 5 | 4 | 3..0 |
| --- | --- | --- | --- | --- | --- |
| Meaning | command channel locked | slot-2 KEK present | sharing active | ceremony pin high | number of shares held |

Values read in the worked example:

| Value | Binary | Reads as |
| --- | --- | --- |
| STATUS `0x42` | `0100 0010` | session up, done; no KEK yet |
| STATUS `0x4A` | `0100 1010` | session up, KEK loaded, done |
| STATUS `0x4E` | `0100 1110` | session up, KEK loaded, **error**, done (after the rejected command below) |
| STATUS2 `0x00` | `0000 0000` | not locked, no slot-2 KEK, no sharing, ceremony pin low, no shares |

#### 14.2.6 SPI frame from the supervisor

```
byte 0        byte 1 … 32
0xA5          S (32 bytes)
```

Exactly 33 bytes with CS low. A different first byte or length is discarded. It is accepted once per reset. S is never read back.

### 14.3 Signing module: worked example

Fixed for the example: S = `000102…1f` (bytes 0 to 31). Everything else came from the module.

```
S          000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
chan_key   546c061a0f995ccabbc16bac98baa7e5b55198e2a530d52d0b68cacccd48ba0f    = HMAC-SHA256(S, "SN-CHAN")
VERSION    b2
NONCE      9a8df0e999921a9bf1fbc4f8fa7ce68d
```

`KEK_GEN` is command 1 (counter 1). Then **`GEN_WALLET`**, counter 2:

```
CMD   20
CTR   00000002
WID   a1a2a3a4a5a6a7a8a9aaabacadaeafb0
IV, TAG, A, B, C   all zero
MAC   097dbe3d8e2fd74954343ab8e3674e28ffd419917ac000887432efeb04e047af
```

Response, ERROR = 0:

```
IV    575fce1b1583a546e301f83f
TAG   b825f322dc0511596708c9641114cd47
A     125676fe54383065094c6ce227a1c64489873faff8ea2009a8f70c4f7f760795      wrapped private key
B     e912c1752b608a0546a48d26d79cd803df7b89e22fef756761ad4680947eb93f      public key x
C     1bd89038f753d2dfd23dc997df24b5ee9df4f721c7456e18512016e9d825ac12      public key y
RMAC  7d39b661510fcb3bdb44d1587da719198ba1847e6ffcb1a30440f704a5d2cc6c
```

The host stores WID, IV, TAG and A as the wallet's blob. Then **`SIGN`**, counter 3, over the digest SHA-256("openhsm worked example"):

```
CMD   21
CTR   00000003
WID   a1a2a3a4a5a6a7a8a9aaabacadaeafb0
IV    575fce1b1583a546e301f83f
TAG   b825f322dc0511596708c9641114cd47
A     125676fe54383065094c6ce227a1c64489873faff8ea2009a8f70c4f7f760795
B     c55c312c3ce89d5ef5e6b0ee257dc395d3440beb10a84fac19395aead3f07f14      the digest
C     00…00
MAC   3269c6dc0f9896e25b0cbaf69ae1b9b8c0bb38466b3a0dab269d68071d542d52
```

The MAC input is the 161 bytes `9a8df0e9…e68d ‖ 00000003 ‖ 21 ‖ a1a2…afb0 ‖ 575f…f83f ‖ b825…cd47 ‖ 1256…0795 ‖ c55c…7f14 ‖ 00…00`.

Response, ERROR = 0:

```
A     71ad725edb17dc3ce103df82b9d6772e6c59a2141ab4df089b978074306912aa      r
B     2461414b0aa0f35dee18feb306bedb07c1c77e7fb5b22bd7f573d139b235bff3      s   (low half of the range)
RMAC  a23a80659d6a4add01a0afe697a3bdf33ae81cc4ec0bd5d3451f25fb6102fda2
```

A command with a bad MAC (here, 32 zero bytes at counter 4) is refused:

```
ERROR   05                      MAC or counter rejected
STATUS  4e                      error and done set
BUF_A, BUF_B, BUF_C, IV, TAG    unchanged: this error path does not touch them
RMAC    00…00                   no response MAC on an authentication failure
```

Because no RMAC accompanies error 5, a host cannot tell this refusal from one forged by a device on the bus, and must not treat it as proof of anything. After eight in a row STATUS2 b7 is set and only a reset clears it.

### 14.4 Node API: one request

#### 14.4.1 On the wire

```
offset  len        field
     0   4         length N of the JSON that follows, big-endian (1 to 16,777,216)
     4   N         JSON document: { "payload": "<string>", "sigs": [ … ] }
```

`payload` is a JSON document carried as a string. It is the exact byte sequence that is signed. Each entry of `sigs` is `{ "id": "<principal>", "sig": "<128 hex>" }`, where the signature is Ed25519 over:

```
"OPENHSM-REQ-v1" ‖ 0x00 ‖ payload bytes          (15-byte prefix: 4f50454e48534d2d5245512d763100)
```

#### 14.4.2 Payload fields

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `v` | integer | yes | Protocol version, 1 |
| `cluster` | string | yes | Cluster name; must match the node |
| `node` | string | quorum methods | Node the request is for |
| `ts` | integer | yes | Milliseconds since 1970. Must be within 30 s of the node's clock for non-quorum methods |
| `exp` | integer | quorum methods | Expiry in milliseconds, at most 24 hours after `ts` |
| `nonce` | string | yes | 32 hexadecimal characters; single use |
| `method` | string | yes | Method name (section 2.3) |
| `params` | object | yes | Parameters; `{}` if none. Unknown fields anywhere are rejected |

#### 14.4.3 Worked example (layout)

This request was built and signed with the `app1` signer key. The timestamp is fixed so that the bytes are stable, so a node would refuse it as stale; the signature is valid and was verified.

```
payload (391 bytes, one line, exactly as signed):
{"v": 1, "cluster": "lab", "ts": 1800000000000, "nonce": "00112233445566778899aabbccddeeff", "method": "eth_sign_transaction", "params": {"wallet": "e4b1c75469274a76c7512f16b4cc73c3", "tx": {"chain_id": 11155111, "nonce": 0, "gas_limit": 21000, "to": "0x3535353535353535353535353535353535353535", "value": "1000", "max_fee_per_gas": "30000000000", "max_priority_fee_per_gas": "1000000000"}}}

signature (Ed25519, 64 bytes):
19dda1a3f8ba760f2a12c10a3b20ac070961bbb831ad14bc96ad11989fbcb4aecd306bbbdb35180ad5b02cf9baa94845566f737848fd3046d989ed76c97ae004

frame: 4-byte length 00000269 (617), then the JSON { "payload": "<the string above, escaped>", "sigs": [ { "id": "app1", "sig": "19dd…e004" } ] }
```

A quorum request has the same shape with `node` and `exp` in the payload and two or more entries in `sigs`, all signing the same payload bytes. The first entry is the sender, whose certificate must be the one on the TLS connection.

Response to the same request sent with a fresh timestamp:

```
{ "ok": true, "result": {
    "from":    "0x9aD55D59F8113F85a694BE9Cb85AFD52ADEfD736",
    "y_parity": 1,
    "r":       "0x5e1f8d210bd6a84ad199965ea24f22b82b8182cf1b3dd6412261c8d375aac49e",
    "s":       "0x478574d5e75ce84a203eafb432c9674bf386852d9a7afba0e87bfa342766fcdd",
    "tx_hash": "0x55703480c17ce52babf6cc1cddcb2c7f22fc11dbbe9c7789794de7ff48182f37",
    "raw_tx":  "0x02f87083aa36a7…" } }
```

### 14.5 Ethereum transaction

The caller sends fields (section 2.4). The node builds the bytes below, hashes them, and sends only the 32-byte hash to the module.

**RLP rules used:** a byte string of one byte below 0x80 is itself; a string of 0 to 55 bytes is `0x80 + length` then the bytes; a list of payload 0 to 55 bytes is `0xC0 + length` then the items, and above 55 bytes `0xF7 + (bytes in the length)` then the length then the items. Integers are minimal big-endian with no leading zero, and zero is the empty string `0x80`.

**EIP-1559 digest.** `digest = Keccak-256( 0x02 ‖ RLP([ chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value, data, access_list ]) )`. For the request above:

```
02                          type byte
ed                          list, payload 0x2d = 45 bytes
83 aa36a7                   chain_id 11155111
80                          nonce 0
84 3b9aca00                max_priority_fee_per_gas 1,000,000,000
85 06fc23ac00              max_fee_per_gas 30,000,000,000
82 5208                    gas_limit 21000
94 3535353535353535353535353535353535353535     to (20 bytes)
82 03e8                    value 1000
80                          data (empty)
c0                          access_list (empty list)

digest   6625f155a05aefaa011f674524a3d0bc5873e66943034c23a391489aa2f0efd2
```

**Signed transaction.** `0x02 ‖ RLP([ …the same nine fields…, y_parity, r, s ])`. The node adds three items; `y_parity` is 0 or 1, and `r`, `s` are 32-byte strings:

```
02
f8 70                       list, payload 0x70 = 112 bytes
   83 aa36a7 80 84 3b9aca00 85 06fc23ac00 82 5208
   94 3535…3535 82 03e8 80 c0
   01                       y_parity
   a0 5e1f8d21…aac49e       r  (0xa0 = 32-byte string)
   a0 478574d5…66fcdd       s
```

`tx_hash` is Keccak-256 of the whole signed byte string (0x02 included). The sender address is the last 20 bytes of Keccak-256 of the 64-byte public key (x ‖ y), shown with EIP-55 capitalisation.

**Legacy transactions** carry EIP-155 protection: the digest is Keccak-256 of `RLP([nonce, gas_price, gas_limit, to, value, data, chain_id, 0, 0])`, and the signed transaction replaces the last three items by `v, r, s` with `v = 35 + 2 × chain_id + y_parity`. This is the standard encoding; no worked hex for it is shown here.

### 14.6 Bitcoin transaction

For `btc_sign_transaction` the node builds a native SegWit (P2WPKH) transaction and signs each input with the BIP-143 digest and `SIGHASH_ALL`. Amounts and version are little-endian as the Bitcoin format requires. The request used one input of 200,000 satoshi, a payment of 50,000 to a fixed address and 149,000 of change, so the fee is 1,000.

```
02000000                       version 2
00 01                          SegWit marker and flag
01                             1 input
  abab…abab (32 bytes)         previous txid (as given in the request)
  00000000                     vout 0
  00                           scriptSig length 0 (empty for SegWit)
  fdffffff                     sequence 0xfffffffd
02                             2 outputs
  50c3000000000000             50,000 satoshi
  16 0014 751e76e8199196d454941c45d1b3a323f1433bd6      scriptPubKey: OP_0, push 20 bytes of the hash
  0846020000000000             149,000 satoshi
  16 0014 f6e3e48ee11360b32b12bc07d89129ba425edf37      change, back to the wallet
witness for input 0
  02                           2 items
  47 3044 0220 <r, 32 bytes> 0220 <s, 32 bytes> 01      DER signature + SIGHASH_ALL byte (0x01), 71 bytes
  21 028686b8…951132           compressed public key, 33 bytes
00000000                       locktime 0
```

**The digest the module signs** (BIP-143) is the double SHA-256 of:

```
version (4, LE)  ‖  hashPrevouts (32)  ‖  hashSequence (32)  ‖  outpoint (36)  ‖  scriptCode (25)
‖  amount (8, LE)  ‖  sequence (4)  ‖  hashOutputs (32)  ‖  locktime (4)  ‖  sighash type (4, LE) = 01000000
```

where `scriptCode = 76 a9 14 <20-byte public key hash> 88 ac`, `hashPrevouts` is the double SHA-256 of all outpoints, `hashSequence` of all sequences, and `hashOutputs` of all outputs as `amount ‖ length ‖ script`. The module signs each input's digest in turn; the node converts `(r, s)` to strict DER and appends the sighash byte.

`txid` is the double SHA-256 of the serialisation without the marker, flag and witness, shown in reverse byte order: here `1d58235dd43368c907ebb91d8e536e79a8a5762ff1cfeca8aae22cd84b12a8fb`. `vsize` is 141.

### 14.7 Documents passed between nodes

All are JSON with hexadecimal byte strings. Layouts of the encrypted parts:

| Document | Field | Layout |
| --- | --- | --- |
| Wallet blob | `iv` (12), `tag` (16), `ct` (32) | AES-256-GCM(key = KEK, IV, AAD = the 16-byte wallet id, plaintext = the 32-byte private key) |
| Sealed KEK | `iv`, `tag`, `ct` | AES-256-GCM(key = seal_key, AAD = `"KEK-SEAL-v1"` followed by 5 zero bytes) |
| KEK transfer | `iv`, `tag`, `ct` (32), `tx`, `ty` (32 each) | `T = (tx, ty)` is the sender's ephemeral public key. `shared = x(t·E)`; `K = HMAC-SHA256(shared, "ECIES-KEK-v1" ‖ Tx ‖ Ty ‖ Ex ‖ Ey)`; `ct` = AES-256-GCM(K, IV, AAD = `"KEK-ECIES-v1"` plus 4 zero bytes, KEK). E is the recipient's enrolment key |
| Share record | `x`, `card`, `challenge` (32), `header` (16), `blob` | `header = x ‖ m ‖ n ‖ fp(13)`; `blob` = AES-256-GCM(K, IV, AAD = header, share) with `K = HMAC-SHA256(r, "SHARE-WRAP-v1" ‖ header)` and `r` the card secret |
| Card secret | derived on the SoC | `r = HMAC-SHA256(key = HMAC-SHA1(card key, challenge), "SN-CARD-v1" ‖ challenge)` |
| KEK fingerprint | 32 bytes | `HMAC-SHA256(KEK, "KEK-FP-v1")` |

### 14.8 How the examples were checked

`scripts/message_examples/` regenerates every example from the running prototype. Run `python3 gen_module.py > module.json`, `python3 gen_node.py > node.json`, then `python3 check.py`, from that directory after `cargo build --release`. Each value is checked with code that does not use the node's own implementation:

| Example | Independent check | Result |
| --- | --- | --- |
| Command MAC of `SIGN` | HMAC-SHA256 over the 161 bytes assembled by hand (`gen_module.py`) | Equal to the MAC sent |
| Response MAC | Recomputed over the 172 bytes by the test host | Verified for `GEN_WALLET` and `SIGN` |
| Module signature | ECDSA verification with the public key returned by `GEN_WALLET` (`cryptography` package) | Valid; s in the low half |
| API request signature | Ed25519 verification of the 15-byte prefix and payload (`check.py`) | Valid |
| Ethereum digest and signature | Keccak-256 and RLP from `pentest/suites/d_verify.py`, then ECDSA verification (`gen_node.py`) | Digest as shown, signature valid, `tx_hash` equals Keccak-256 of the raw bytes |
| Bitcoin signature | BIP-143 digest and strict DER parse from the same file (`check.py`) | Valid |

## 15. Document history

| Version | Change |
| --- | --- |
| 0.5.0 | First interface control document, written from the 0.5.0 code and `FPGA/README.md`. |
| 0.5.1 | Protocol 0xB2 is in the RTL from `FPGA/V0.5`: IF-02 and IF-04 status, register map and notes updated. |
| 0.5.2 | Section 14 added: byte-level message construction with worked examples generated from the prototype. Document history is now section 15. |
