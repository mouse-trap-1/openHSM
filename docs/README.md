# OpenHSM: Architecture and Interfaces

Version 0.5.1 (prototype). This is the one-page map of the system: what the parts are, how they are connected, and what crosses every interface. It summarises the other documents and does not replace them. Where a number or format here differs from the code, the code wins.

| Document | Read it for |
| --- | --- |
| [SYSTEM_DESIGN.md](SYSTEM_DESIGN.md) | Why the system is built this way |
| [SYSTEM_SPECIFICATION.md](SYSTEM_SPECIFICATION.md) | Required behaviour, with requirement identifiers |
| [INTERFACE_CONTROL_DOCUMENT.md](INTERFACE_CONTROL_DOCUMENT.md) | Byte-level definition of every interface |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Attackers and assets |
| [PENETRATION_TEST_REPORT.md](PENETRATION_TEST_REPORT.md) | Simulated attacks, methods, results |
| [COMPLIANCE.md](COMPLIANCE.md) | Mapping to standards and regulations |
| [`FPGA/README.md`](../FPGA/README.md) | The signing module's own specification (protocol 0xB2) |

## 1. What it is

A signing node for Ethereum and Bitcoin wallets. An application server asks for a signature on a transaction; the node checks the wallet's policy, builds the transaction itself, has the signing module sign it, and returns the result. Wallet private keys are generated inside the signing module, stored outside it only as AES-256-GCM blobs wrapped under a cluster key (the KEK), and used only inside it. The only curve is secp256k1 and the only signature scheme is ECDSA.

Design target: about 55 signatures per second per node, about 10,000 wallets per node, a cluster of six nodes at two sites. Any node can sign for any wallet because the module keeps no wallet state.

## 2. Parts

```
            application servers                operators (hsmctl)
                    │  IF-01  TLS 1.3, signed requests  │      IF-10 files, IF-11 command lines
   ┌────────────────▼───────────────────────────────────▼────────────┐
   │ SoC  i.MX 8M Plus           openhsmd                            │── IF-08 ── NVMe
   │  normal world   listener, framing, authentication               │── IF-07 ── operator card reader
   │  secure world   policy, chain encoders, audit, module driver    │── IF-12 ── cluster port (open)
   └────────┬──────────────────────────────┬─────────────────────────┘
            │ IF-02  I2C 0x48              │ IF-05  supervisor services
   ┌────────▼───────────────┐    ┌─────────▼────────────┐
   │ Signing module (FPGA)  │◄───│ Tamper supervisor    │◄── IF-06 sensors, key-switch
   │ KEK in volatile regs   │SPI │ STM32U5, battery     │◄── IF-13 battery
   │ unwrap · sign · wipe   │IF-03│ holds S, counter     │
   └────────────────────────┘ IF-04 tamper line, ceremony pin
   └──────────────────────── tamper enclosure ───────────────────────┘
```

| Part | Real hardware | In the prototype | Status |
| --- | --- | --- | --- |
| Signing module | FPGA, drop-in for the NXP SE050 on I2C | `FPGA/V0.5` (RTL, protocol 0xB2) and `crates/openhsm-signer` (register-level model) | RTL simulated, not synthesised; model working |
| Tamper supervisor | STM32U5 with battery, mesh, lid, light, accelerometer, voltage and temperature sensors, key-switch | `crates/openhsm-hw`, run as the `openhsm-hwsim` process | Model; firmware not written |
| Node | i.MX 8M Plus, NVMe | `crates/openhsm-node` (`openhsmd`) | Working, runs on Linux |
| Operator tool | Workstation | `crates/openhsm-cli` (`hsmctl`) | Working |
| Operator cards | YubiKeys, HMAC-SHA1 challenge-response | Software cards; YubiKey path through `ykman` | Not tested on real cards |

All first-party Rust is `#![forbid(unsafe_code)]`.

## 3. Responsibilities

| Component | Does | Never does |
| --- | --- | --- |
| Signing module | Generates wallet keys, unwraps and signs, holds the KEK in volatile registers, moves the KEK by ECIES or Shamir shares, wipes on tamper | TLS, policy, transaction parsing, holding the node identity key |
| Tamper supervisor | Holds the secret S, sends it to the module once per boot, derives keys for the SoC, counts audit entries, trips on sensors, reads the key-switch | Return S to anyone |
| SoC secure world | Decodes the request, enforces the policy, encodes the transaction and computes the digest, drives the module, writes the audit chain | See a wallet private key, the KEK, or S |
| SoC normal world | Terminates TLS, frames and authenticates requests | Reach the module or the supervisor directly |
| Operators | Approve sensitive operations by quorum, turn the key-switch, present cards | Sign transactions (admins cannot sign) |

## 4. Core architecture of the signing module

One command sequencer drives a small set of shared engines. Each command is a fixed list of steps, only one engine runs at a time, and every working register is scrubbed when a command ends. No vendor primitives and no soft CPU.

```
 I2C ──► i2c_slave ──► register file ──► command sequencer (sign_node_top) ──► response MAC ──► RMAC
 SPI ──► spi_secret_rx ─► S ─► hmac ─► secret_store (chan_key, seal_key, KEK, KEK slot 2, enrolment key)
 tamper ─────────────────────────────► asynchronous clear of the store, sharing state and engine registers
 ceremony ───────────────────────────► gates the commands that move the KEK

 sequencer drives:  hmac_sha256 / sha256_core    MACs, KDFs, fingerprints
                    aes_gcm32 (aes256, gf128)    wallet blobs, one record shape
                    rfc6979_nonce + trng_ro      hedged nonce, key generation
                    ecdsa_secp256k1_sign         Montgomery ladder, microcoded
                    modmul_serial (second copy)  start-point randomisation, scalar check
                    point_check                  on-curve test before any ECDH
                    shamir_core                  (m, n) sharing over GF(2^8)
```

| Block | File | Role |
| --- | --- | --- |
| Sequencer | `sign_node_top.v` | Register file, MAC and lockout, command steps, signature check, scrub, response MAC |
| Signer core | `ecdsa_secp256k1_sign.v`, `modmul_serial.v`, `ecdsa_ucode_rom.v` | Constant-time ladder with complete add and double formulas, Fermat inversion, low-s. Modes: sign, public key, multiply an arbitrary point |
| Nonce | `rfc6979_nonce.v` | RFC 6979 HMAC-DRBG hedged with fresh TRNG bytes |
| Hash | `sha256_core.v`, `hmac_sha256.v` | One shared HMAC-SHA256 |
| AEAD | `aes256_core.v`, `gf128_mul.v`, `aes_gcm32.v` | AES-256-GCM for 96-bit IV, 16-byte AAD, 32-byte payload; plaintext withheld on tag failure |
| Point check | `point_check.v` | Range and on-curve check |
| Sharing | `shamir_core.v` | Split by Horner, combine by Lagrange |
| Secret store | `secret_store.v` | The only long-lived secrets, cleared asynchronously by tamper |
| TRNG | `trng_ro.v` | Ring oscillators, von Neumann debias, repetition and adaptive-proportion tests |
| Bus and SPI | `i2c_slave.v`, `spi_secret_rx.v` | Soft controller, no clock stretching; receive-only 33-byte frame |

Control flow of a signature: the host writes the buffers, MAC and counter, then the command. The sequencer checks the MAC and counter, unwraps the key under the KEK, draws entropy, derives the nonce, and runs the signer from a randomised start point. It holds r and s back, checks them (scalar identity and a second multiplication), copies them out only if both checks pass, scrubs, computes the response MAC, and raises done. A signature takes 3,469,730 cycles in simulation, about 27 per second at 100 MHz; `VERIFY_SIGN = 0` restores about 48 per second and drops the fault check.

## 5. Key hierarchy

```
S   tamper supervisor, battery-backed, erased on tamper
├── HMAC(S,"SN-CHAN")      chan_key   module and SoC   authenticates the I2C channel in both directions
├── HMAC(S,"SN-SEAL")      seal_key   module only      seals the KEK for local restart
└── HMAC(S,"SOC-SEAL-v1")  soc_seal   SoC only         seals the node identity key and TLS key

KEK  cluster key-encryption key, module volatile registers
├── wallet key d      AES-256-GCM(KEK, AAD = wallet id)   kept by the SoC, replicated as ciphertext
├── sealed KEK        AES-256-GCM(seal_key)               one per node on its NVMe
├── ECIES transfer    to a joining node's enrolment key   in transit only
└── Shamir shares     m of n, each wrapped to one operator card
```

The SoC gets `chan_key` and `soc_seal` but never S, so it cannot derive `seal_key` and cannot open the sealed KEK on its own disk. Three routes reach the KEK and each needs something a remote attacker lacks: S (held only in the enclosure) to unseal it, the ceremony key-switch plus an admin quorum to export it, or m operator cards plus the key-switch to rebuild it.

## 6. Interface register

| ID | Interface | Between | Medium in the product | Prototype | Status |
| --- | --- | --- | --- | --- | --- |
| IF-01 | Node API | Applications, operators ↔ SoC | TLS 1.3 over Ethernet | TLS 1.3 over TCP | Implemented |
| IF-02 | Signing module bus | SoC ↔ FPGA | I2C, address 0x48 | Register access carried by IF-05 | RTL and model |
| IF-03 | Tamper secret delivery | Supervisor → module | Receive-only SPI | Function call | RTL; supervisor modelled |
| IF-04 | Module discrete signals | Supervisor, board → module | Tamper line, ceremony pin, clock, reset, LEDs | Model inputs | RTL |
| IF-05 | Supervisor services | SoC ↔ supervisor | Link not chosen | Unix socket, binary RPC | Modelled; physical link open |
| IF-06 | Sensors and key-switch | Physical world → supervisor | Mesh, lid, light, accelerometer, voltage, temperature, key-switch | Simulation socket | Modelled |
| IF-07 | Operator card | YubiKey ↔ SoC | USB CCID reader | `ykman` or file in `cardslot/` | Implemented with software cards |
| IF-08 | Persistent storage | SoC ↔ NVMe | NVMe | Files in the data directory | Implemented |
| IF-09 | Node-to-node transfer | Node ↔ node, by an operator | Documents through IF-01 | Same | Implemented; no automatic replication |
| IF-10 | Operator files | `hsmctl` ↔ workstation | Files | Same | Implemented |
| IF-11 | Command lines | Operator ↔ binaries | Shell | Same | Implemented |
| IF-12 | Cluster port | Node ↔ node | Second Ethernet port | None | Hardware design; protocol open |
| IF-13 | Power | PDUs, battery → node | Dual 12 V, CR123A cell | None | Hardware design |
| IF-T1 | Module pin simulator | Test tools ↔ module model | Loopback TCP | Same | Test fixture, never deployed |

### IF-01 Node API

TLS 1.3 with a client certificate from the cluster CA. Frames are a 4-byte big-endian length (at most 16 MiB) and one JSON document. At most 256 connections, 32 per source.

```
request  = { "payload": "<JSON text>", "sigs": [ { "id": "<principal>", "sig": "<hex>" }, … ] }
payload  = { "v": 1, "cluster", "node"?, "ts", "exp"?, "nonce": "<32 hex>", "method", "params" }
sig      = Ed25519(principal key, "OPENHSM-REQ-v1\0" ‖ payload bytes)
response = { "ok": true, "result": … } | { "ok": false, "error": { "code", "message" } }
```

| Role | Methods |
| --- | --- |
| any registered principal | `status`, `wallet_list`, `wallet_get` |
| signer | `eth_sign_transaction`, `btc_sign_transaction`, `eth_sign_message`, `sign_digest` |
| admin, auditor | `audit_head`, `audit_tail` |
| admin, single signature | `kek_fingerprint`, `enrol_begin`, `kek_import`, `rotate_import`, `rotate_rewrap`, `snapshot_export`, `wallet_freeze` |
| admin quorum (two of three in the examples) | `kek_generate`, `kek_export`, `kek_erase`, `rotate_begin`, `rotate_export`, `rotate_promote`, `wallet_create`, `policy_set`, `wallet_unfreeze`, `principal_add`, `principal_remove`, `ceremony_split`, `ceremony_restore`, `snapshot_import` |

The six methods that move the KEK also need the ceremony key-switch on (`ceremony_required` otherwise). The caller sends transaction fields, never a hash: the node encodes the transaction and computes the digest itself. Error codes: `unauthenticated`, `forbidden`, `quorum_required`, `bad_request`, `not_found`, `stale`, `replay`, `rate_limited`, `policy_denied`, `frozen`, `ceremony_required`, `signer_error`, `tamper`, `internal`.

### IF-02 Signing module bus

I2C slave, address 0x48, single-byte register pointer that auto-increments, big-endian values, no clock stretching (system clock at least 8 times SCL). Buffers can be written only while the module is idle.

| Address | Name | Dir | Bytes | Content |
| --- | --- | --- | --- | --- |
| 0x00 | STATUS | R | 1 | b0 busy, b1 done, b2 error, b3 KEK loaded, b4 tamper, b5 TRNG fail, b6 session up, b7 enrolment key |
| 0x01 | CMD | W | 1 | Writing starts the command |
| 0x02 | ERROR | R | 1 | Error code of the last command |
| 0x03 | STATUS2 | R | 1 | b7 channel locked, b6 slot-2 KEK, b5 sharing active, b4 ceremony pin, b3:0 shares held |
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

```
command MAC  = HMAC-SHA256(chan_key, nonce ‖ ctr ‖ cmd ‖ WID ‖ IV ‖ TAG ‖ A ‖ B ‖ C)                    161 bytes
response MAC = HMAC-SHA256(chan_key, "SN-RESP-v1" ‖ nonce ‖ ctr ‖ cmd ‖ error ‖ WID ‖ IV ‖ TAG ‖ A ‖ B ‖ C)   172 bytes
```

Procedure: write WID, IV, TAG, A, B, C, CTR and MAC, then CMD; poll STATUS for done; read ERROR, the buffers and RMAC; accept the result only if RMAC verifies. Eight consecutive authentication failures lock the channel until reset. Any error clears IV, TAG, A, B and C.

| Group | Commands |
| --- | --- |
| Key encryption key | 0x10 `KEK_GEN`, 0x11 `KEK_SEAL`, 0x12 `KEK_UNSEAL`, 0x13 `KEK_ERASE`, 0x14 `KEK_NEW_GEN`, 0x15 `REWRAP`, 0x16 `KEK_PROMOTE`, 0x17 `KEK_FP` |
| Wallets | 0x20 `GEN_WALLET`, 0x21 `SIGN`, 0x22 `PUBKEY` |
| Transfer (ceremony pin needed) | 0x40 `ENROL_GEN`, 0x41/0x45 `KEK_EXPORT`/`KEK_NEW_EXPORT`, 0x42/0x46 `KEK_IMPORT`/`KEK_NEW_IMPORT` |
| Sharing (ceremony pin needed except 0x52, 0x55) | 0x50 `SPLIT_BEGIN`, 0x51/0x56 `SHARE_GET`/`SHARE_GET_C`, 0x52 `SPLIT_END`, 0x53/0x57 `SHARE_PUT`/`SHARE_PUT_C`, 0x54 `RESTORE`, 0x55 `RESTORE_ABORT` |

The node uses 0x56 and 0x57 only, where BUF_B is XORed with HMAC-SHA256(chan_key, "SN-CONF-v1" ‖ nonce ‖ ctr). Module error codes: 0 OK, 1 no session, 2 no KEK, 3 KEK already loaded, 4 TRNG failure, 5 MAC or counter rejected, 6 signing failed, 7 tamper, 8 bad command, 9 bad parameter, 10 blob authentication failed, 11 invalid point, 12 no enrolment key, 13 share rejected, 14 not enough shares, 15 no slot-2 KEK.

### IF-03 and IF-04 Supervisor to module

| Signal | Definition |
| --- | --- |
| SPI | Mode 0, MSB first, no MISO. One 33-byte frame, `0xA5 ‖ S`, accepted once per reset. System clock at least 4 times SCLK |
| `tamper` | Active high, asynchronous. Zeroes the secret store, sharing state and engine registers at once and latches until reset |
| `ceremony` | Level from the physical key-switch. Low makes the ceremony commands answer error 8. Not routed to the SoC |
| Clock, reset | Reset ends the session; S must be sent again |
| `led_busy`, `led_kek`, `led_tamper` | Front-panel indicators |

### IF-05 Supervisor services

The functional contract between the SoC and the supervisor (`Hardware` trait in `crates/openhsm-hw`). In the prototype it is one Unix socket (mode 0600) that also carries the IF-02 register accesses: request `op(1) ‖ len(2) ‖ payload`, response `status(1) ‖ len(2) ‖ payload`.

| Op | Call | Returns |
| --- | --- | --- |
| 1, 2 | `bus_write`, `bus_read` | Register access to the module (at most 256 bytes per read) |
| 3 | `restart_signer` | Resets the module and resends S |
| 4 | `soc_keys` | `chan` (32) ‖ `soc_seal` (32); fails after a tamper event |
| 5, 6 | `counter`, `counter_increment` | 64-bit monotonic counter |
| 7 | `tamper_status` | Empty, or the sensor and time |
| 8 | `ceremony_enabled` | 0 or 1 |

The physical link (bus, framing, protection of `soc_keys` in transit) is not defined yet.

### IF-06 Sensors and key-switch

Mesh, lid, light, accelerometer, voltage and temperature: any trip erases S, latches across power cycles and asserts the tamper line. The key-switch sets the ceremony pin. Loss of main power clears the module's KEK; the battery domain keeps S and the counter. Sensor thresholds and debounce times are not specified yet. The prototype's physical-simulation socket accepts `tamper <sensor>`, `ceremony on|off`, `power-cycle`, `trng-fail on|off`, `glitch` and `status`.

### IF-07 Operator card

`response = HMAC-SHA1(card key, challenge)`; `card secret = HMAC-SHA256(key = response, "SN-CARD-v1" ‖ challenge)`. Used only in `ceremony_split` and `ceremony_restore`. Cards are named `yubikey:<serial>[:<slot>]` (touch required) or `<name>` for a software card in `cardslot/`. The card never sees a share and the module never sees the card key.

### IF-08 Storage

Under the node data directory (mode 0700): `state.json` (no secrets in the clear, SHA-256 anchored in the audit chain), `audit.log` (one JSON line per event, hash-chained and signed), `identity.sealed` and `tls/node.key.sealed` (AES-256-GCM under `soc_seal`), public certificates, and for the prototype `cardslot/` and `sim.sock`.

### IF-09 and IF-10 Documents

All JSON; unknown fields are rejected. Enrolment key (`enrol_x`, `enrol_y`, `enrol_fp`, `node`), KEK transfer (`iv`, `tag`, `ct`, `tx`, `ty`), snapshot (`cluster`, `exported_ms`, `kek_fp`, `wallets`, `share_set`), share set (`m`, `n`, `fp`, `records`). A wallet blob is `{iv, tag, ct}`. Operator files: `ca.crt`/`ca.key`, `<name>.crt`/`.key`/`.sign`/`.principal.json`, genesis, profile, and operation files collected by `propose` and `approve`.

### IF-11 Command lines

```
openhsmd init --data DIR --genesis FILE --node-id ID [--san NAME]... [--hardware inproc|unix:PATH]
openhsmd run  --data DIR --listen ADDR [--hardware inproc|unix:PATH] [--sim-physical] [--no-audit-fsync]
openhsm-hwsim provision --state DIR  |  run --state DIR --soc-socket PATH --physical-socket PATH
hsmctl pki init | pki sign-csr | identity | genesis | profile | call | propose | approve | submit | audit-verify | card-new | sim
```

### Message layouts

How to arrange each message, what every field and status bit means, and worked hex examples (module command and response MACs, the API request, Ethereum and Bitcoin transactions) are in section 14 of the [Interface Control Document](INTERFACE_CONTROL_DOCUMENT.md#14-message-construction). The examples are regenerated and checked by `scripts/message_examples/`.

### Interfaces in the hardware design only

IF-12 (cluster port) and IF-13 (power) are described in the repository README and have no protocol or thresholds yet. The IF-05 physical link is likewise open.

## 7. Trust boundaries and what may cross them

| Boundary | May cross | Must never cross | Protection |
| --- | --- | --- | --- |
| Network ↔ SoC (IF-01) | Requests, public keys, addresses, signatures, blobs in snapshots | Wallet keys, KEK, S, `chan`, `soc_seal` | TLS 1.3, client certificate, Ed25519 signature bound to the certificate, replay and freshness checks |
| SoC ↔ module (IF-02) | Blobs, digests, signatures, public keys, masked card secret | Wallet keys, KEK, S, `seal_key`, card secret in the clear | HMAC on every command and response, counter, lockout |
| Supervisor → module (IF-03/04) | S, tamper line, ceremony pin | Anything back | No MISO; hardware lines |
| Supervisor ↔ SoC (IF-05) | `chan`, `soc_seal`, counter, tamper status | S, `seal_key` | Contract above; link protection open |
| SoC ↔ disk (IF-08) | Wrapped blobs, sealed keys, share records | Any key in the clear | Hash chain, signatures, supervisor counter |
| Operators ↔ node (IF-07, IF-09) | Challenge and response, wrapped shares, ECIES ciphertext | Shares or KEK in the clear | Quorum, key-switch, cards |

## 8. Path of one signature

1. The application server sends `eth_sign_transaction` or `btc_sign_transaction` with fields, not a hash (IF-01).
2. The node checks signatures, certificate binding, freshness, replay, role and rate.
3. The node encodes the transaction (RLP for Ethereum, BIP-143 for Bitcoin), evaluates the wallet policy on what it decoded, and computes the digest.
4. It sends the wallet blob and digest to the module (IF-02, authenticated).
5. The module unwraps the key, signs with a hedged nonce, checks its own signature twice, wipes, and returns r and s with a response MAC.
6. The node verifies the signature against the wallet's public key, writes the signed audit entry, steps the supervisor counter (IF-05), and only then returns the signed transaction.

## 9. Status and limits

| Area | State |
| --- | --- |
| Simulation | 68 simulated penetration tests; RTL system benches pass (71, 53 and 48 checks) with independent Python verification |
| Not done | RTL not co-simulated against the Rust model; no synthesis or timing closure; no scalar blinding or AES/HMAC masking; supervisor firmware and carrier board unwritten; no real YubiKeys; no independent review or certification |
| Throughput | About 27 signatures per second per node with the signature check on, against a target of 55 |
| Residual risk R-1 | A fully compromised SoC can request signatures on arbitrary digests, because policy runs on the SoC and not in the module |
| Scope | secp256k1 ECDSA only: Ethereum (legacy, EIP-1559, ERC-20 `transfer`, optional EIP-191) and Bitcoin P2WPKH. No Taproot, Ed25519 chains, PSBT or EIP-712 |

The prototype has not run on target hardware and is not a certified device.
