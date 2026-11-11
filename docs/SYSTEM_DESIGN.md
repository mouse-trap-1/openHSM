# OpenHSM System Design

Version 0.5.0 (prototype). Companion documents: [System Specification](SYSTEM_SPECIFICATION.md), [Threat Model](THREAT_MODEL.md), [Penetration Test Report](PENETRATION_TEST_REPORT.md), [Compliance Mapping](COMPLIANCE.md). The FPGA signing module has its own specification in [`FPGA/README.md`](../FPGA/README.md).

This document explains how the prototype is put together and why. The specification says exactly what each interface does.

## 1. What the prototype is

OpenHSM is a signing node for Ethereum and Bitcoin wallets. An application server asks the node to sign a transaction; the node decides whether the wallet's policy allows it, and if so returns the signed transaction. Private keys are generated, stored (wrapped) and used inside a signing module that does nothing else.

The prototype is the complete node in software, split into the same parts as the hardware design:

| Part of the real node | In this prototype | Status |
| --- | --- | --- |
| FPGA signing module (replaces the NXP SE050 on I2C) | `openhsm-signer`: a register-level model of `FPGA/V0.4/sign_node_top.v` | Functional model; the RTL is the reference |
| STM32U5 tamper supervisor, sensors, key-switch | `openhsm-hw`: supervisor model, run as its own process (`openhsm-hwsim`) | Model; firmware not written |
| i.MX 8M Plus SoC (API, policy, storage, cluster logic) | `openhsm-node` (`openhsmd`) | Working code, runs on Linux |
| Operator workstation | `hsmctl` | Working code |
| YubiKey operator cards | HMAC-SHA1 challenge-response cards; software cards in tests | YubiKey path untested on hardware |

It runs end to end on one machine: `scripts/demo.sh` builds a cluster, creates wallets, signs Ethereum and Bitcoin transactions under policy, enrols a second node, trips a tamper sensor, recovers on a third node from operator cards and rotates the cluster key.

It is not a certified device and has not run on the target hardware. Section 9 lists what separates it from one.

## 2. Design decisions carried into the prototype

These were fixed before the prototype was written and the code follows them.

| # | Decision | Where it shows |
| --- | --- | --- |
| D1 | The signing module does one job: sign secp256k1 ECDSA. No NFC, no TLS, no policy. | `openhsm-signer` has no network code and no transaction parser |
| D2 | It is a drop-in for the SE050 slot: an I2C slave with a soft controller. | Register map and command set of `sign_node_top.v`, address 0x48 |
| D3 | Wallet keys are generated on the module, kept only as blobs wrapped under the cluster KEK, and used on the module. | `GEN_WALLET`, `SIGN`; the node never sees a private key |
| D4 | Keys must be exportable between nodes for cluster use, never in the clear. | ECIES transfer of the KEK; wallet blobs replicate as ciphertext |
| D5 | Tamper detectors zero the keys. The STM32U5 supervisor connects directly to the module. | Supervisor sends S over receive-only SPI and drives the tamper line |
| D6 | The SoC has the network, runs the API and cluster configuration, and owns the NVMe drive. | `openhsm-node` |
| D7 | The node's identity key and mutual TLS stay in the SoC secure world, not the module. | Identity and TLS keys are sealed by the SoC, see 5.3 |
| D8 | Operator cards are YubiKeys and are used for cluster key recovery. | Shamir shares wrapped to card secrets, `ceremony_split` / `ceremony_restore` |
| D9 | About 55 signatures per second per node is acceptable. | Stateless module, so throughput scales by adding nodes |
| D10 | Policy is enforced on the HSM so that a compromised application server cannot drain funds (repository README). | `policy.rs`, deny by default |

## 3. Architecture

```
            application servers                operators (hsmctl)
                    |  TLS 1.3, client certificates, signed requests  |
   +----------------v-------------------------------------------------v---------+
   | SoC (i.MX 8M Plus)                                      openhsmd            |
   |                                                                            |
   |  normal world     server.rs  proto.rs  api.rs      listener, framing, auth  |
   |  ---------------------------------------------------------------------     |
   |  secure world     policy.rs  chains/   audit.rs    decode, decide, record   |
   |                   secure.rs (driver, holds chan key and SoC seal key)       |
   |                   node.rs   (boot checks, state anchoring, tamper poll)     |
   +----------|--------------------------------|-------------------|-------------+
              | I2C, MAC on commands           | derived keys,     | NVMe
              | and responses                  | counter, status   | state.json, audit.log
   +----------v----------------+     +---------v-----------+       (no secrets in clear)
   | Signing module (FPGA)     |<----| Tamper supervisor   |
   | KEK in volatile registers | SPI | (STM32U5, battery)  |<-- mesh, lid, light, accelerometer,
   | unwrap, sign, wipe        | S   | holds S, counter    |    voltage, temperature, key-switch
   +---------------------------+ tamper line, ceremony pin +
   \____________________ tamper enclosure ________________/
```

In the prototype the enclosure is the `openhsm-hwsim` process and the SoC is the `openhsmd` process. They talk over a Unix socket that carries exactly the signals on the board: I2C register reads and writes, and the supervisor's services. The signing module's keys and the tamper secret never enter the `openhsmd` address space. Penetration test F-08 dumps that process's memory to confirm it.

### 3.1 Workspace layout

| Path | Contents |
| --- | --- |
| `crates/openhsm-signer` | Signing module model, its cryptography, Shamir, entropy health tests, bus simulator binary |
| `crates/openhsm-hw` | `Hardware` trait, supervisor model, in-process and separate-process enclosure |
| `crates/openhsm-node` | Daemon: API, policy, Ethereum and Bitcoin encoders, audit chain, state, driver |
| `crates/openhsm-cli` | `hsmctl` |
| `pentest/` | Attack harness and seven suites, written in Python and independent of the Rust code |
| `scripts/demo.sh` | End-to-end demonstration |
| `FPGA/` | The RTL and its host tools (existing) |
| `docs/` | This documentation |

All first-party Rust is `#![forbid(unsafe_code)]`.

## 4. Trust boundaries

| Boundary | What crosses it | Protection |
| --- | --- | --- |
| Network to SoC | Requests and responses | TLS 1.3 with client certificates from the cluster CA; every request also signed with the principal's Ed25519 key and bound to the certificate on the connection |
| SoC to signing module | Commands with wrapped blobs and digests; results | HMAC-SHA256 on every command (session nonce, strictly increasing counter), HMAC on every response, lockout after 8 failures |
| Supervisor to signing module | Tamper secret S, tamper line, ceremony pin | Receive-only SPI, accepted once per reset; lines are hardware signals |
| Supervisor to SoC | Two keys derived from S, monotonic counter, tamper status | The SoC never receives S itself |
| SoC to disk | State file, audit log, sealed keys | Nothing secret in the clear; integrity anchored in a signed hash chain and the supervisor's counter |
| Operators to node | Quorum operations, cards | Two of three admin signatures; physical key-switch for anything that moves the KEK |

The most important consequence: the three ways to reach the KEK each need something a remote attacker does not have. Opening the sealed copy needs S, which only the enclosure holds. Exporting it needs the ceremony switch turned at the node and an admin quorum. Rebuilding it needs m operator cards and the same switch.

## 5. Key hierarchy

```
S (tamper supervisor, battery-backed, erased on tamper)
├── HMAC(S,"SN-CHAN")     chan_key   module + SoC   authenticates the I2C channel
├── HMAC(S,"SN-SEAL")     seal_key   module only    seals the KEK for local restart
└── HMAC(S,"SOC-SEAL-v1") soc_seal   SoC only       seals the node identity key and TLS key

KEK (cluster key-encryption key, module volatile registers)
├── wallet key d_i        AES-256-GCM(KEK, AAD = wallet id)      stored by the SoC, replicated
├── sealed KEK            AES-256-GCM(seal_key)                  one per node, on its NVMe
├── ECIES transfer        to a new node's enrolment key          in transit only
└── Shamir shares (m of n) each wrapped to one operator card     break-glass
```

### 5.1 Why the SoC gets derived keys instead of S

The FPGA host driver in `FPGA/V0.4/sn_host.py` is given S. With S the SoC can derive `seal_key`, open the sealed KEK on its own disk, and decrypt every wallet key without the module. That defeats decision D3 for anyone who compromises the SoC. Penetration test A-14 demonstrates it against protocol 0xB1.

The prototype moves the derivation into the supervisor. The SoC receives `chan_key` (it must, to send commands) and a separate `soc_seal` for its own secrets. It cannot compute `seal_key`. This needs a small change in the supervisor firmware and none in the RTL.

### 5.2 One KEK for all wallets

A single KEK keeps the module stateless, which is what allows about 10,000 wallets per node and lets any node sign for any wallet. The cost is that a KEK compromise exposes every wallet. The design answers with three things: the KEK never leaves a module except by ECIES or as card-wrapped shares; rotation exists (`rotate_begin`, `rotate_rewrap`, `rotate_promote`); and the node counts wraps under a KEK and refuses beyond 2^31 so the random 96-bit GCM IVs stay far from the collision bound.

### 5.3 Node identity and TLS keys

Per D7 these live in the SoC. The prototype generates both at `openhsmd init`, seals them under `soc_seal`, and unseals them at boot. On the real board the same code belongs in an OP-TEE trusted application. A tamper event destroys S, so both keys become unrecoverable together with the KEK.

## 6. How a signature is made

1. The application server sends `eth_sign_transaction` or `btc_sign_transaction` with structured fields (recipient, value, fees). It does not send a hash.
2. The node authenticates the request: signature, certificate binding, freshness, replay cache, role, rate limit.
3. The node encodes the transaction itself (RLP for Ethereum, BIP-143 for Bitcoin) and evaluates the wallet policy on the decoded meaning: chain id, recipient allow-list, per-transaction cap, fee cap, token rules, daily budget including worst-case fees.
4. If allowed, the node computes the digest and sends the wallet blob and digest to the module.
5. The module unwraps the key under the KEK, derives a hedged RFC 6979 nonce, signs, verifies its own signature against the recomputed public key, and wipes.
6. The node checks the signature against the wallet's recorded public key, writes a signed audit entry, steps the supervisor's counter, and only then returns the signed transaction.

Two properties follow. The module never signs a digest the node cannot explain, unless a wallet's policy explicitly enables raw digests. And nothing leaves the node before its audit record is durable.

### 6.1 Encode, never parse

The node builds transactions from fields and has no RLP or Bitcoin transaction parser on the request path. A parser that disagrees with the network about what bytes mean is the classic way to get an HSM to approve one thing and sign another. Suite D of the penetration tests decodes every output with independent code to confirm the bytes match the request.

### 6.2 Policy model

Policies are per wallet and deny by default: a wallet created with an empty policy signs nothing. Ethereum wallets permit plain transfers to allow-listed recipients and `transfer` on listed ERC-20 tokens; arbitrary contract calls, contract creation, EIP-191 messages and raw digests are separate opt-ins. Bitcoin wallets are native SegWit (P2WPKH), sign `SIGHASH_ALL` only, and treat outputs to the wallet's own address as change.

Daily totals are rebuilt from the audit chain at boot, so restarting the node does not reset them. In a cluster each node may spend `max_per_day / lease_divisor` without consulting the others; with the divisor equal to the number of signing nodes, the cluster-wide cap holds even when nodes cannot reach each other.

## 7. Administration

There are three roles. Signers can only request signatures. Auditors can only read status and the audit log. Admins can only administer, and cannot sign.

Sensitive operations need signatures from a quorum of distinct admins (two of three in the examples) over the same payload, which names the node and carries an expiry and a single-use nonce. One admin drafts with `hsmctl propose`, others add signatures with `hsmctl approve`, any of them submits. A single admin can freeze a wallet at once; un-freezing needs the quorum.

Anything that moves the KEK into or out of a module also needs the ceremony key-switch on that node to be on. The switch is a pin on the module driven by the supervisor from a physical lock, so no software on the SoC can assert it. This is extension X6 and is the answer to "what if the admin quorum is phished": they would still have to send someone to the rack.

## 8. Integrity of stored state

The state file (principals, quorum, CA, wallets with blobs and policies, sealed KEK, share records) contains no secrets but decides who may do what. Its SHA-256 is recorded in the audit chain on every change. Each audit entry is hash-chained to its predecessor and signed with the node identity key. The newest sequence number is mirrored in the supervisor's monotonic counter.

At boot the node verifies every signature and link, compares the last sequence number with the counter, and compares the state file with the last anchored hash. Any mismatch stops the boot. This catches edits, deletions, forged entries and, through the counter, restoring an old but self-consistent disk image.

## 9. Gaps between this prototype and a deployable HSM

| Area | Gap | Consequence |
| --- | --- | --- |
| Hardware | The FPGA is simulated RTL, not synthesised; the supervisor firmware and carrier board do not exist | No claim about physical security, side channels, faults or real entropy can be tested yet |
| Module protocol | Extensions X1 to X6 exist in the model only | They must be back-ported to the RTL before the model and the FPGA agree |
| Secure world | `openhsmd` is one Linux process | The secure/normal world split is a module boundary, not OP-TEE isolation |
| Policy location | Policy is enforced by the SoC, not the module | A full SoC compromise can request signatures on arbitrary digests (residual risk R-1) |
| Clustering | Wallets replicate by signed snapshot export and import; there is no Raft, leader election or automatic failover | The README's availability targets are not met by this prototype |
| Chains | secp256k1 ECDSA only: Ethereum (legacy, EIP-1559, ERC-20 transfer) and Bitcoin P2WPKH | No Taproot/Schnorr, no Ed25519 chains, no PSBT, no EIP-712 |
| Cards | YubiKey responder is exercised with software cards only | Needs a drill with real cards |
| Performance | Not measured on target hardware | The 55 signatures per second target is unverified |
| Assurance | No independent review, no formal verification, no certification | See [COMPLIANCE.md](COMPLIANCE.md) |

## 10. Change log of this document

| Version | Change |
| --- | --- |
| 0.5.0 | First system-level design: node software, enclosure model, protocol extensions X1 to X6, policy engine, audit chain. Dependencies moved to k256 0.14 after RUSTSEC-2026-0387; `rustls-pemfile` removed (unmaintained). |
