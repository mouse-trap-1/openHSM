# OpenHSM and Ethereum's move to post-quantum signatures

Version 0.6.0, 25 November 2026. This document records what the Ethereum Foundation announced, what it means for each part of OpenHSM, what changed in 0.6, and what is left to do and in which order. Companion documents: [System Design](SYSTEM_DESIGN.md) (decision D11), [Threat Model](THREAT_MODEL.md) (T11, R-11, R-12), [Compliance Mapping](COMPLIANCE.md) (section 2.3), [Interface Control Document](INTERFACE_CONTROL_DOCUMENT.md) (IF-01, IF-02).

## 1. What was announced

On 23 November 2026 the Ethereum Foundation published [PQAI #0: Preparing Ethereum for a post-quantum, post-AI world](https://blog.ethereum.org/2026/11/23/pqai-0). In short:

- Ethereum will move from elliptic-curve to **hash-based** cryptography in three places: validator signatures (consensus), user-account signatures (wallets get a path to hash-based keys), and blob commitments.
- Hash-based cryptography was chosen after more than a year of evaluating candidates, because Ethereum already depends on hash security, so no new assumption is added.
- Timeline: December 2028 proposed as a target, 2029 as the Foundation's internal deadline, with a timeline review in January 2027. Early specifications and the first post-quantum consensus devnet have started.
- Wallets, multisigs and staking pools all need changes. Signatures will be much larger.

What the post does **not** say, and what OpenHSM therefore must not assume yet: which signature scheme (stateful XMSS-style or stateless SPHINCS+/SLH-DSA-style), which hash function and parameters, how user accounts migrate (account abstraction, a new transaction type, or both), when secp256k1 transactions stop being accepted, or anything about hardware signers and HSMs.

## 2. What it means for OpenHSM

The signing node does four things with public-key cryptography. Each is affected differently by a future quantum computer (attacker T11).

| Use in OpenHSM | Today | Exposed to | Urgency | Status |
| --- | --- | --- | --- | --- |
| Wallet signatures (Ethereum, Bitcoin) | secp256k1 ECDSA in the FPGA | Key recovery from a public key once a large quantum computer exists | Set by Ethereum's and Bitcoin's timelines; nothing the HSM can do alone | Waiting for Ethereum's scheme; hardware prepared (section 3) |
| API and cluster TLS (IF-01) | TLS 1.3, X25519 | "Harvest now, decrypt later": sessions recorded today and decrypted later | Immediate | **Done in 0.6**: hybrid X25519MLKEM768 |
| KEK transfer between nodes | ECIES: ECDH on secp256k1 + AES-GCM | Harvest now, decrypt later: a recorded transfer package yields the KEK, which opens every wallet blob | High | Designed (section 4); interim procedure in force |
| Card-protected KEK shares | Shamir shares wrapped under secrets from YubiKey HMAC-SHA1 challenge-response | Only a quantum key search, about 2^80 work for a 160-bit key | Low | Unaffected by Shor's algorithm; upgrade path in section 6 |
| Request signing, certificates, audit chain | Ed25519, ECDSA P-256 | Forgery once a quantum computer exists, not before | Medium | Planned (section 7) |
| Symmetric cryptography (AES-256-GCM, HMAC-SHA256, SHA-256, Keccak-256) | Everywhere | Grover's algorithm only; 256-bit keys keep about 128 bits of security | None | No change |

The most important consequence for the hardware is size. secp256k1 signatures are 64 bytes. Hash-based signatures are kilobytes:

| Scheme family | Signature size | At 55 signatures per second |
| --- | --- | --- |
| secp256k1 ECDSA | 64 bytes | 3.5 KB/s |
| Stateful, XMSS-style (for example XMSS-SHA2_10_256) | about 2.5 KB | about 140 KB/s |
| Stateless SLH-DSA-128s / 128f (FIPS 205) | 7,856 / 17,088 bytes | 430 / 940 KB/s |
| Stateless SLH-DSA-256f (FIPS 205) | 49,856 bytes | 2.7 MB/s |

A 1 MHz I2C bus moves about 0.1 MB/s, so it could not carry even the smallest of these at the node's target rate. That is why the host link changed first.

Stateful schemes add a harder problem than size: every one-time key must be used once only, so the signer has to keep a counter that can never go backwards, across reboots, backups, restores and cluster nodes. Section 5 covers it.

## 3. Changes made in 0.6

| Change | Where | Why |
| --- | --- | --- |
| **SPI host link** replaces I2C between the SoC and the FPGA. SPI mode 0, up to 12.5 MHz, same register map, commands and MACs. Protocol 0xB3 | `FPGA/V0.6/spi_host_slave.v`, `sign_node_top.v`; carrier schematic draft 0.2 (ECSPI, 33 Ω termination); ICD section 3 | About 12× the raw bandwidth of 1 MHz I2C, and no address or ACK bits. Also cuts per-request bus time for today's ECDSA from about 2.9 ms to about 0.2 ms |
| **Keccak-256 core**, one round per clock, 24 cycles per 136-byte block, tested against Ethereum vectors | `FPGA/V0.6/keccak256_core.v`, `tb_keccak.v`, `gen_keccak_vectors.py` | Any Ethereum hash-based signer needs a fast Keccak-f[1600]. The same permutation serves SHA3-256 and SHAKE256 (rate 1088) by changing the padding byte, and ML-KEM (section 4) is built on SHA-3 and SHAKE. It also lets the module hash a transaction itself in future, instead of trusting the SoC's digest (R-1). Not yet wired into the sequencer |
| **FPGA headroom measured** by generic synthesis | Section 8 | The XC7A50T must hold the existing design, Keccak, and later a hash-based signer and ML-KEM. The estimate shows the existing design is already about 2.7 times too large for it (section 8) |
| **Hybrid post-quantum TLS**: X25519MLKEM768 on the API and cluster links | `crates/openhsm-node/src/server.rs`, `client.rs`, test `tests/pq_tls.rs` | Closes harvest-now-decrypt-later on everything that crosses the network, including KEK transfer packages carried over the API |
| Threat model, compliance, design and interface documents | `docs/` | T11, R-11, R-12, decision D11, FIPS 203/204/205 and SP 800-208 |

The TLS change in detail: the node's listener prefers X25519MLKEM768 and still accepts plain X25519, so third-party clients whose TLS library has no ML-KEM keep working. OpenHSM's own clients (`hsmctl`, node to node) offer X25519MLKEM768 only and fail the handshake rather than fall back. A test checks all three cases. The TLS provider moved from `ring` to `aws-lc-rs`, which has ML-KEM. Certificates and request signatures are still ECDSA P-256 and Ed25519; authentication only has to resist an attacker at the time of the handshake, so it can move later (section 7).

## 4. KEK transfer: hybrid ECDH + ML-KEM (designed, not built)

### 4.1 The problem

`KEK_EXPORT` encrypts the cluster KEK to a joining node's secp256k1 enrolment key. Anyone who records the package (`iv`, `tag`, `ct`, `tx`, `ty`) and later breaks one ECDH with a quantum computer recovers the KEK and, with the replicated blobs, every wallet key on every node. The package is protected in transit by TLS, which is now hybrid, but it is also written to files by the operator tooling and may end up in backups.

### 4.2 Interim procedure (in force from 0.6)

1. Move KEK transfer packages only over the node API. That traffic is now hybrid post-quantum.
2. Do not store packages. Delete the file as soon as `kek_import` succeeds, and keep packages out of backups and tickets.
3. Where a package may already have been stored or copied, rotate the KEK (`rotate_begin`, `rotate_rewrap`, `rotate_promote`).
4. For new nodes, consider restoring from operator cards (`ceremony_restore`) instead of ECIES. That path is symmetric (section 6) and has no ECDH to break, at the cost of gathering m operators.

### 4.3 Design for V0.7: KEK_EXPORT_PQ / KEK_IMPORT_PQ

Both nodes run both key agreements and the KEK is wrapped under a key derived from both shared secrets, so the transfer stays safe if either ECDH or ML-KEM holds.

```
Joining node (ENROL_GEN_PQ):
    e  <- TRNG               E  = e·G                  (secp256k1, as today)
    (ek, dk) <- ML-KEM-768.KeyGen                       (FIPS 203; ek 1,184 bytes)
    output E, ek

Sending node (KEK_EXPORT_PQ, ceremony pin high):
    check E is on the curve, check ek (FIPS 203 input check)
    t  <- TRNG               T  = t·G
    ss1 = x(t·E)
    (ct, ss2) = ML-KEM-768.Encaps(ek)                   (ct 1,088 bytes)
    K   = HMAC-SHA256(ss1 ‖ ss2, "KEK-HYB-v1" ‖ Tx ‖ Ty ‖ Ex ‖ Ey ‖ SHA3-256(ek) ‖ SHA3-256(ct))
    out = IV, TAG, AES-256-GCM(K, IV, AAD = "KEK-HYB-v1"‖0^6, KEK), T, ct

Joining node (KEK_IMPORT_PQ):
    ss1 = x(e·T); ss2 = ML-KEM-768.Decaps(dk, ct); same K; open; load KEK
```

The combiner binds both public keys and the ML-KEM ciphertext into the key, so neither half can be swapped independently. Both nodes erase `e`, `dk`, `t`, `ss1`, `ss2` and `K` when the command ends, as today.

Interface consequences:

- `ek` and `ct` do not fit the 32-byte buffers. V0.7 adds a **bulk window**: a 4 KiB buffer reached with two new SPI opcodes, `0x0A` (write) and `0x0B` (read), each followed by a 16-bit offset. The command MAC and response MAC gain `SHA-256(bulk[0:len])` and `len`. The existing register map is unchanged, so 0xB3 drivers keep working. This is also where kilobyte hash-based signatures will be read out.
- The Keccak core needs a rate parameter (1088 for SHA3-256 and SHAKE256, 1344 for SHAKE128, 576 for SHA3-512) and a domain byte (0x01 Keccak, 0x06 SHA-3, 0x1F SHAKE). The permutation is unchanged.
- ML-KEM needs a number-theoretic transform over q = 3329 and SHAKE sampling. Its area on the XC7A50T must be measured before committing (section 8).

Alternative if ML-KEM does not fit: drop ECIES enrolment altogether and move the KEK only through card shares (section 6), which needs no public-key cryptography. Operationally heavier, cryptographically simpler.

## 5. Stateful hash-based keys: state, export and the cluster

If Ethereum chooses a stateful scheme (XMSS-style, as current validator research suggests) the module will hold long-lived signing keys whose one-time keys must never be reused. That conflicts with three things OpenHSM does today: wallet keys are stateless blobs any node can use (D3), keys are exportable between nodes (D4), and nodes restore from snapshots.

### 5.1 Rules the design will follow

1. **Reserve before use.** The module may use a one-time index only after the tamper supervisor's monotonic counter has moved past it. The supervisor advances the counter in blocks (for example 1,024 indices) and the module signs inside the reserved block. A crash or tamper event burns the rest of the block; it never causes reuse. The supervisor already exposes a battery-backed monotonic counter (`Hardware::counter`, `counter_increment`); it needs one counter per stateful key, or per key range.
2. **Never export state, export ranges.** A stateful key is never copied whole to another node. Each node gets a disjoint range of indices (or its own subtree of a multi-tree), assigned by an admin quorum and recorded in the replicated state, like the leased daily limits. The wrapped key blob carries its range in the AAD, so the module refuses an index outside it. This is the "distributed multi-tree" and "sectorization" approaches of [RFC 10033](https://www.rfc-editor.org/rfc/rfc10033).
3. **Restores never move a counter backwards.** Snapshots carry blobs and range assignments, never a "next index". A node restored from backup, or a replacement node, gets a fresh range; the old range is retired.
4. **Tamper retires the range.** Zeroisation destroys the node's position in its range, so the whole range is marked burned in the cluster state and never reassigned.
5. **Monitor exhaustion.** Ranges are finite. The node reports remaining signatures per key, and the API refuses to sign below a reserve kept for a key-rotation transaction.

### 5.2 Compliance consequence

NIST SP 800-208, which approves XMSS and LMS, requires key and signature generation inside hardware modules that do not allow the private key to be exported, and NIST says it is revising this to allow export with mitigations ([NIST CSRC](https://csrc.nist.gov/Projects/Stateful-Hash-Based-Signatures)). Rule 2 keeps the one-time keys of each range inside one module, but the seed of a multi-tree still crosses between nodes wrapped under the KEK. Until the revision is published, a FIPS claim for stateful keys would need one key per node with no export at all. See COMPLIANCE.md section 2.3.

### 5.3 If the scheme is stateless

SLH-DSA-style schemes have no state, so the current model (stateless blobs, any node signs) carries over unchanged. The cost moves to time and bandwidth: thousands of hash calls per signature and up to 50 KB per signature. Section 8 sizes that.

## 6. Operator cards

The cards are YubiKey OTP slots in HMAC-SHA1 challenge-response mode (`crates/openhsm-node/src/cards.rs`). The card secret r = HMAC-SHA256(response, "SN-CARD-v1" ‖ challenge) wraps each Shamir share with AES-256-GCM. That chain is entirely symmetric, so Shor's algorithm does not apply. The remaining margin issue is that the response carries at most 160 bits, which a quantum key search would reduce to about 2^80 work (R-12).

- Keep shares on the symmetric path. Do **not** move them to PIV (RSA or ECC) wrapping, which would make them harvestable.
- To widen the margin: use FIDO2 `hmac-secret` (HMAC-SHA256 with a 32-byte credential secret), or derive r from two OTP slots. Either is a change to `cards.rs` and the ceremony tool, not to the RTL, because the module only ever sees r.

## 7. Authentication and long-lived signatures on the SoC

These do not need to change before a quantum computer exists, because forging them requires the attacker to have one at the time. They should change before then:

| Item | Today | Plan |
| --- | --- | --- |
| Cluster CA and node certificates | ECDSA P-256 | ML-DSA or hybrid certificates once `rustls` and `rcgen` support them |
| Principal request signatures | Ed25519 | ML-DSA, or hybrid Ed25519 + ML-DSA |
| Audit chain signatures | Ed25519, hash-chained, anchored by the supervisor counter | The hash chain and counter already hold without the signature; add a hash-based signature over periodic checkpoints (LMS fits: low volume, one signer) |
| SoC secure boot (HAB) | RSA/ECDSA in i.MX fuses | Fixed by the silicon; track NXP's post-quantum boot support |
| FPGA bitstream | AES-256 + HMAC (symmetric) | No change |

## 8. FPGA capacity

Generic Xilinx 7-series synthesis with Yosys 0.33 (`synth_xilinx -family xc7`, flattened, no timing, no Vivado optimisation). Treat these as upper-bound estimates; Vivado usually does better on LUT count.

| Block | LUTs | Flip-flops | Notes |
| --- | --- | --- | --- |
| **Whole node, V0.6 `sign_node_top`, flattened** | **88,767** | **38,755** | 272% of the XC7A50T's LUTs, 59% of its flip-flops. No block RAM or DSP was inferred |
| Hierarchical run of the same design (no cross-module optimisation) | 113,831 | 39,840 | Used for the breakdown below |
| — sequencer and register file (`sign_node_top` itself) | 70,059 | 8,831 | Wide multiplexers onto the 256-bit buffers and the 1,536-bit HMAC message register |
| — ECDSA signer core | 11,450 | 8,237 | Plus one `modmul_serial` (1,804 LUTs) per instance, three instances |
| — Shamir core | 8,627 | 5,255 | |
| — AES-256 | 5,013 | 2,319 | |
| — HMAC-SHA256 and SHA-256 | 5,976 | 3,805 | |
| `keccak256_core` alone (not in the totals above) | 5,719 | 1,607 | Round-per-clock |
| `spi_host_slave` (V0.6) / `i2c_slave` (V0.5) | 22 / 70 | 47 / 44 | |

**The existing design does not fit the XC7A50T, before anything post-quantum is added.** Yosys's generic flow is pessimistic and Vivado will do better, but not by a factor of 2.7. The cost is concentrated: over 60% of the LUTs are the sequencer's parallel multiplexing, which block RAM and narrower datapaths would remove. In order:

1. Run Vivado synthesis to get the real figure (already the first open item in `FPGA/README.md` section 12).
2. Restructure the sequencer: keep the buffers and the HMAC message in block RAM and stream them 32 bits at a time instead of assembling 1,536-bit words in registers. This is the largest saving available and does not change the protocol.
3. If that is not enough, the XC7A100T (63,400 LUTs) comes in the same FTG256 package (check pin compatibility in Xilinx UG475 before changing the BOM). The XC7A200T needs a larger package and a carrier change.

Do not add a post-quantum block to the RTL until steps 1 and 2 have been done.

The XC7A50T has 32,600 LUTs, 65,200 flip-flops, 75 36-kb block RAMs and 120 DSP slices.

What has to fit later, and what to measure before choosing:

| Block | Needed for | Notes |
| --- | --- | --- |
| Hash-based signer datapath | Ethereum hash-based signatures | Mostly Keccak calls plus tree traversal and a few KB of buffer. Exact cost depends on the scheme Ethereum picks |
| ML-KEM-768 | Hybrid KEK transfer (section 4) | NTT over q = 3329, polynomial storage in block RAM, SHAKE from the Keccak core |
| Bulk window | Kilobyte inputs and outputs | 4 KiB in one or two block RAMs |
| Second signer core | Today's ECDSA throughput target (FPGA spec section 9) | Roughly doubles the signer area |

All of this comes after the area reduction above.

## 9. Order of work

| Step | What | Depends on |
| --- | --- | --- |
| Done (0.6) | SPI host link, Keccak-256 core, headroom estimate, hybrid TLS, interim KEK-transfer procedure, documents | — |
| 0 | Vivado synthesis, then reduce the sequencer's area (buffers and HMAC message in block RAM); change device only if still needed | Nothing; blocks steps 2, 3 and 5 |
| 1 | Supervisor firmware: per-key monotonic counters with block reservation | Nothing; needed by any stateful scheme |
| 2 | Bulk window and parameterised Keccak (rates, domain bytes) in the RTL | Step 0 |
| 3 | ML-KEM-768 in the RTL and `KEK_EXPORT_PQ` / `KEK_IMPORT_PQ`; Rust model and host driver to match | Steps 0 and 2 |
| 4 | FIDO2 `hmac-secret` cards | Nothing |
| 5 | Hash-based signer in the RTL, range-bound blobs, range assignment in the node state | Step 0; Ethereum's specification of the user-account scheme |
| 6 | Post-quantum certificates and request signatures on the SoC | Library support |

Signals to watch: the Foundation's January 2027 timeline review, the first published user-account signature specification, the post-quantum devnets, and the revision of SP 800-208.

## 10. Sources

- [Ethereum Foundation, PQAI #0, 23 November 2026](https://blog.ethereum.org/2026/11/23/pqai-0)
- [NIST, Stateful Hash-Based Signatures project page (SP 800-208 and its planned revision)](https://csrc.nist.gov/Projects/Stateful-Hash-Based-Signatures)
- [RFC 10033, Hash-Based Signatures: State and Backup Management, September 2026](https://www.rfc-editor.org/rfc/rfc10033)
- FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), FIPS 202 (SHA-3), NIST, August 2024 and August 2015
