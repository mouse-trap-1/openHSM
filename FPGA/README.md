# Secp256k1 Signing Node: System Specification

An FPGA module that signs secp256k1 ECDSA transactions with wallet keys it never stores. Verilog, simulated under Icarus Verilog (`-g2005`); not yet synthesised or run on hardware.

This document describes **V0.5, protocol 0xB2**. `V0.5/` holds the complete source tree; `V0.2` to `V0.4` hold the history, each with only the files that changed. What V0.5 adds to V0.4 is listed in [`V0.5/README.md`](V0.5/README.md).

Contents: [1 Purpose](#1-purpose-and-scope) · [2 Context](#2-system-context-and-threat-model) · [3 Architecture](#3-architecture) · [4 Keys](#4-key-hierarchy-and-security-architecture) · [5 Interfaces](#5-external-interfaces) · [6 Commands](#6-command-set-and-error-codes) · [7 Crypto](#7-cryptographic-specification) · [8 Procedures](#8-lifecycle-procedures) · [9 Performance](#9-performance) · [10 Verification](#10-verification-status) · [11 Limitations](#11-known-limitations-and-residual-risks) · [12 Integration](#12-hardware-integration-requirements-and-open-items) · [Appendix: files and simulation](#appendix-files-and-simulation)

## 1. Purpose and scope

The signing node is an FPGA module that signs secp256k1 ECDSA transactions with wallet keys it never stores, and does nothing else. It takes the place of the NXP SE050 on the signing node's I2C bus.

It does:

- Generate wallet keys on the module, return them only as AES-256-GCM blobs wrapped under a cluster key-encryption key (KEK), and sign with a blob presented per request.
- Hold the KEK in volatile registers only, and destroy it on tamper or power loss.
- Seal the KEK for local restart, move it to new nodes with ECIES, split it across operator YubiKeys for break-glass recovery, and rotate it.
- Authenticate every command and every response with an HMAC keyed from a secret delivered by the STM32U5 tamper MCU, and lock the command channel after eight failed attempts.
- Check every signature before releasing it, and refuse to move the KEK unless the ceremony key-switch is on.

It does not:

- Terminate TLS or hold the mTLS identity key. That stays in the SoC secure world.
- Speak the SE050 T=1/APDU protocol. A thin new driver replaces the SE050 one.
- Decide what to sign. It signs the 32-byte digest it is given, so policy and transaction decoding live on the SoC.
- Verify client signatures on commands (not implemented; commands are authenticated by the shared-secret MAC).

The design target is about 55 signatures per second per node across roughly 10,000 wallets per node, in a 6-node, 2-site cluster.

## 2. System context and threat model

The node sits between three parties: the i.MX 8M Plus SoC (network, API, cluster logic, NVMe), the STM32U5 tamper MCU, and the operators. The FPGA trusts none of them blindly.

| Party | Connection | Trusted for | Not trusted for |
| --- | --- | --- | --- |
| SoC secure world | I2C master | Sending authenticated commands, storing wrapped blobs and the sealed KEK | Nothing beyond what the MAC and counter allow |
| SoC normal world / network | none directly | Nothing | Everything: it never reaches the FPGA |
| STM32U5 tamper MCU | SPI (receive only), tamper line, ceremony pin | Delivering secret S after each boot, raising tamper, reporting the key-switch | Reading anything back: there is no MISO |
| NVMe / Raft peers | via SoC | Holding wrapped wallet blobs and sealed KEK blobs | Confidentiality: blobs are useless without the KEK |
| Operators with YubiKeys | via SoC during ceremonies | Releasing shares for break-glass recovery | Acting alone: m cards are required |

Assumptions the design depends on:

- The I2C link between the SoC secure world and the FPGA is not trusted. Commands and responses are both authenticated, so a device on the bus can block traffic or lock the channel but cannot forge either direction.
- The SoC is given only chan_key by the tamper MCU, never S. With S it could derive seal_key and open the sealed KEK on its own disk.
- The tamper MCU holds S only while the enclosure is intact, so a tamper event destroys the means to unseal the local KEK blob.
- During a share ceremony the SoC secure world briefly sees each card-derived secret r. A compromised secure world at that moment, plus the stored blobs, could rebuild the KEK. The ceremony must run on a trusted node. On the bus r is masked, and no ceremony command runs unless the key-switch is on.

Attackers considered: a remote attacker with full control of the SoC normal world; a thief with the NVMe drive and database backups; a replay, injection or substitution attacker on the I2C bus in either direction; a single injected fault during signing; physical probing that trips tamper. Side-channel attacks and multiple or targeted faults are listed as open items in section 11.

## 3. Architecture

One command sequencer in `sign_node_top` drives a small set of shared engines. Every command is a fixed sequence of steps: build a job, call an engine, wait, continue. Only one engine runs at a time, and all working registers are scrubbed when a command ends.

| Block | File | Role |
| --- | --- | --- |
| Command sequencer | `sign_node_top.v` | I2C register file, MAC check and lockout, command steps, signature check, scrub on completion, response MAC |
| Signer core | `ecdsa_secp256k1_sign.v`, `modmul_serial.v`, `ecdsa_ucode_rom.v` | Constant-time Montgomery ladder, complete add/double formulas, Fermat inversion, low-s. Modes: sign, public key, and multiply an arbitrary point (ECDH). The start point is taken in projective form, so the caller can randomise it |
| Shared multiplier | `modmul_serial.v` (second instance in `sign_node_top.v`) | Mod p: randomises the start point of every scalar multiplication. Mod n: the scalar half of the signature check |
| Nonce | `rfc6979_nonce.v` | RFC 6979 HMAC-DRBG, hedged with fresh TRNG bytes |
| Hash engines | `sha256_core.v`, `hmac_sha256.v` | One shared HMAC-SHA256 for MACs, KDFs, nonce, key extraction, fingerprints |
| AEAD | `aes256_core.v`, `gf128_mul.v`, `aes_gcm32.v` | AES-256-GCM for one record shape: 96-bit IV, 16-byte AAD, 32-byte payload. Plaintext withheld on tag failure |
| Point check | `point_check.v` | On-curve and range check before any ECDH |
| Secret sharing | `shamir_core.v` | (m, n) Shamir over GF(2^8), split by Horner, combine by Lagrange |
| Secret store | `secret_store.v` | The only long-lived secrets: chan_key, seal_key, KEK, slot-2 KEK, enrolment key. Asynchronous tamper clear |
| TRNG | `trng_ro.v` | Ring-oscillator source, von Neumann debias, repetition and adaptive-proportion health tests |
| I2C slave | `i2c_slave.v` | Soft controller, pointer protocol, open-drain via `sda_oe`, no clock stretching |
| SPI receiver | `spi_secret_rx.v` | Receive-only, one 33-byte frame, rejects bad length or header |

Control flow of a signature: the host writes the buffers, MAC and counter, then the command byte. The sequencer HMACs the buffers with chan_key and checks the MAC and counter. It then unwraps the key with AES-GCM under the KEK, draws fresh entropy, derives the nonce and runs the signer core from a randomised start point. It holds r and s back while it checks them (section 7), copies them to the buffers only if the check passes, scrubs, computes the response MAC over the buffers, and raises done.

The design uses no vendor primitives and no soft CPU.

## 4. Key hierarchy and security architecture

The FPGA holds one durable-looking secret, the cluster KEK, and it is volatile. Everything else is either derived from S at boot, wrapped under the KEK, or short-lived.

| Key | Origin | Where it lives | Lifetime | Protects |
| --- | --- | --- | --- | --- |
| S (256 bit) | Tamper MCU | STM32U5, sent over SPI once per boot | Until reset or tamper | Roots the two keys below |
| chan_key | HMAC(S, "SN-CHAN") | secret_store, volatile | Session | MAC on every command |
| seal_key | HMAC(S, "SN-SEAL") | secret_store, volatile | Session | Local sealed copy of the KEK |
| KEK (256 bit) | TRNG on first node; ECIES or Shamir restore elsewhere | secret_store, volatile | Until tamper, reset or erase | Every wallet key blob |
| KEK slot 2 | TRNG; ECIES to other nodes | secret_store, volatile | During rotation only | Re-wrapped blobs |
| Wallet key d | TRNG on module, range-checked in [1, n-1] | Outside, as AES-GCM blob (AAD = wallet id) | Blob persists; plaintext exists only during one command | Signatures |
| Enrolment key | TRNG on a joining node | secret_store, volatile | Until the KEK arrives | ECIES delivery of the KEK |
| Shamir shares | Split from the KEK inside the FPGA | Outside, wrapped to one operator card each | Persistent, m of n needed | Break-glass recovery |

Security properties the design aims for:

- **No key export in the clear.** No register or command returns the KEK or a wallet key. Wallet keys leave only as blobs bound to their wallet id.
- **Fail closed.** A node with no session, no KEK, a bad MAC or a stale counter does nothing. A failed unwrap returns no plaintext and leaves no key material in working registers.
- **Tamper wins.** The tamper input clears the secret store, the Shamir state and every engine register asynchronously, even with the clock stopped. The node stays locked until reset.
- **Replay protection.** Each MAC covers a per-session random nonce and a strictly increasing counter.
- **Authenticated responses.** The host can tell a genuine reply from one altered or invented on the bus.
- **Bounded guessing.** Eight consecutive authentication failures lock the command channel until reset. The KEK is kept.
- **No faulty signature leaves.** A signature that fails the module's own check is withheld and the buffers are cleared.
- **Physical presence to move the KEK.** Export, import, split and restore exist only while the ceremony pin is high.
- **Separation.** The mTLS identity key never enters the FPGA. The FPGA never accepts a new S without a reset.

## 5. External interfaces

The node has six external connections: I2C to the SoC secure world, SPI from the tamper MCU, an asynchronous tamper input, the ceremony pin, clock and reset, and three status LEDs.

**I2C.** 7-bit slave address, default 0x48 (the SE050's), configurable by parameter. Single-byte register pointer, big-endian multi-byte values, pointer auto-increments. No clock stretching, so keep the system clock at least 8 times SCL. Buffers can be written only while the node is idle.

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
| 0xA4 | MAC | W | 32 | HMAC-SHA256 over the command frame. Reads as zero; cleared after every command |
| 0xC4 | RMAC | R | 32 | HMAC-SHA256 over the response frame. Zero while a command runs, after an authentication failure, and with no session |
| 0xFF | VERSION | R | 1 | 0xB2 |

The MAC input is 161 bytes: nonce, counter, command, WID, IV, TAG, BUF_A, BUF_B, BUF_C. The response MAC input is 172 bytes: the label "SN-RESP-v1", nonce, counter, command, error code, then WID, IV, TAG, BUF_A, BUF_B, BUF_C as the command left them.

To issue a command the host writes WID, IV, TAG, BUF_A, BUF_B, BUF_C, CTR and MAC in any order, then writes CMD. It polls STATUS until done is set, reads ERROR, reads the buffers it needs together with RMAC, and accepts the result only if RMAC verifies.

**SPI (tamper MCU to FPGA).** Mode 0, MSB first, receive only (no MISO). One frame of 33 bytes: 0xA5, then S. Wrong header or length is discarded. The frame is accepted once per reset. The system clock must be at least 4 times SCLK.

**Tamper.** Active-high, asynchronous, hold it high while the fault lasts. It zeroes the secret store, Shamir state and engine registers immediately and latches until reset.

**Ceremony.** `ceremony`, active-high level from the tamper MCU, which drives it from the physical key-switch. Synchronised internally and sampled when a command is authenticated. While it is low the commands marked ⚿ in section 6 answer error 8, exactly as an unknown command would. Do not route this pin to the SoC.

**Indicators.** `led_busy`, `led_kek`, `led_tamper`.

## 6. Command set and error codes

All commands carry a valid MAC and a counter greater than the last accepted one. Commands whose high nibble is 0xF are internal and are refused from the host. Commands marked ⚿ need the ceremony pin high.

A command that fails authentication returns error 5, changes nothing, and produces no response MAC. Every other outcome, success or error, carries a response MAC. Any error clears IV, TAG, BUF_A, BUF_B and BUF_C.

| Code | Command | Inputs | Outputs |
| --- | --- | --- | --- |
| 0x10 | KEK_GEN | none (only if no KEK) | KEK loaded |
| 0x11 | KEK_SEAL | none | IV, TAG, A = KEK sealed under seal_key |
| 0x12 | KEK_UNSEAL | IV, TAG, A | KEK loaded (only if none) |
| 0x13 | KEK_ERASE | none | KEK, slot 2, enrolment key and sharing state cleared |
| 0x14 | KEK_NEW_GEN | none | New KEK in slot 2 |
| 0x15 | REWRAP | WID, IV, TAG, A | IV, TAG, A = blob under slot-2 KEK |
| 0x16 | KEK_PROMOTE | none | Slot 2 becomes the KEK; old shares discarded |
| 0x17 | KEK_FP | none | B = HMAC(KEK, "KEK-FP-v1") |
| 0x20 | GEN_WALLET | WID | IV, TAG, A = wrapped key, B/C = public key |
| 0x21 | SIGN | WID, IV, TAG, A, B = digest | A = r, B = s (low-s) |
| 0x22 | PUBKEY | WID, IV, TAG, A | A = x, B = y |
| 0x40 | ENROL_GEN | none | B/C = enrolment public key |
| 0x41 ⚿ / 0x45 ⚿ | KEK_EXPORT / KEK_NEW_EXPORT | B/C = recipient enrolment public key | IV, TAG, A = ciphertext, B/C = ephemeral public key T |
| 0x42 ⚿ / 0x46 ⚿ | KEK_IMPORT / KEK_NEW_IMPORT | IV, TAG, A, B/C = T | KEK (or slot 2) loaded |
| 0x50 ⚿ | SPLIT_BEGIN | B[255:248] = m, B[247:240] = n | WID = header template |
| 0x51 ⚿ | SHARE_GET | WID = header with x, B = card secret r | IV, TAG, A = wrapped share |
| 0x52 | SPLIT_END | none | Sharing polynomial discarded |
| 0x53 ⚿ | SHARE_PUT | WID = header, IV, TAG, A, B = r | Share stored (only if no KEK) |
| 0x54 ⚿ | RESTORE | none | KEK rebuilt, fingerprint checked, loaded |
| 0x55 | RESTORE_ABORT | none | Stored shares discarded |
| 0x56 ⚿ | SHARE_GET_C | As 0x51, with B = r XOR mask | As 0x51 |
| 0x57 ⚿ | SHARE_PUT_C | As 0x53, with B = r XOR mask | As 0x53 |

| Error | Meaning | Error | Meaning |
| --- | --- | --- | --- |
| 0 | OK | 8 | Bad command, or ceremony pin low |
| 1 | No session | 9 | Bad parameter |
| 2 | No KEK | 10 | Unwrap or authentication of a blob failed |
| 3 | KEK already loaded | 11 | Invalid curve point |
| 4 | TRNG failure | 12 | No enrolment key |
| 5 | MAC or counter rejected, or channel locked | 13 | Share rejected (header, duplicate, wrong fingerprint) |
| 6 | Signing failed, or the signature did not pass its check | 14 | Not enough shares, or no active split |
| 7 | Tamper | 15 | No slot-2 KEK |

## 7. Cryptographic specification

All multi-byte values are big-endian. Every construction below is checked against an independent Python implementation or a published vector (section 10).

| Function | Definition |
| --- | --- |
| ECDSA | secp256k1, deterministic-plus-entropy nonce, s normalised to the low half of the range, r and s non-zero. Signer rejects k or d outside [1, n-1] |
| Nonce | RFC 6979 HMAC-SHA256 DRBG with 32 bytes of fresh TRNG data as additional input. If the TRNG fails at that point, plain RFC 6979 is used |
| Scalar multiplication | 256-iteration Montgomery ladder, conditional swap, Renes-Costello-Batina complete formulas (a = 0, b3 = 21). Inversion by Fermat exponentiation. Fixed cycle count independent of the secret |
| Key generation | Two 256-bit TRNG words a, b; d = HMAC-SHA256(key = a, msg = b); redraw unless 1 <= d < n. Same routine makes the KEK, enrolment key and ephemeral scalars |
| Session keys | chan_key = HMAC(S, "SN-CHAN"), seal_key = HMAC(S, "SN-SEAL") |
| Command MAC | HMAC-SHA256(chan_key, nonce(16) \|\| ctr(4) \|\| cmd(1) \|\| wid(16) \|\| iv(12) \|\| tag(16) \|\| A(32) \|\| B(32) \|\| C(32)). Counter must exceed the last accepted one. Eight consecutive failures lock the channel until reset |
| Response MAC | HMAC-SHA256(chan_key, "SN-RESP-v1" \|\| nonce(16) \|\| ctr(4) \|\| cmd(1) \|\| error(1) \|\| wid(16) \|\| iv(12) \|\| tag(16) \|\| A(32) \|\| B(32) \|\| C(32)), over the buffers after the command. cmd is the byte the host wrote |
| Card-secret mask | mask = HMAC-SHA256(chan_key, "SN-CONF-v1" \|\| nonce(16) \|\| ctr(4)), with the counter of the command that carries it. The host sends r XOR mask in BUF_B to SHARE_GET_C and SHARE_PUT_C |
| Signature check | Before release: s·k ≡ ±(z + r·d) mod n, then a second scalar multiplication k·G from a fresh random start point and x(k·G) mod n = r. Together these are equivalent to verifying (r, s) against d·G. Either failing returns error 6 |
| Start-point randomisation | Each scalar multiplication starts from (λ·x : λ·y : λ) with λ a fresh TRNG word in [1, p-1]. The result is unchanged; the intermediate values differ on every run. If the TRNG has failed, λ = 1 |
| Wallet wrap | AES-256-GCM, key = KEK, IV = 96 random bits, AAD = wallet id (16 bytes), plaintext = d (32 bytes), 128-bit tag |
| KEK seal | AES-256-GCM, key = seal_key, random IV, AAD = "KEK-SEAL-v1" padded with zeros to 16 bytes |
| ECIES (KEK transfer) | E = e*G on the recipient. Sender picks t, T = t*G, shared = x(t*E). K = HMAC(shared, "ECIES-KEK-v1" \|\| Tx \|\| Ty \|\| Ex \|\| Ey). Blob = AES-256-GCM(K, random IV, AAD = "KEK-ECIES-v1" padded to 16 bytes, KEK). Both public points are validated on-curve before use |
| KEK fingerprint | HMAC-SHA256(KEK, "KEK-FP-v1"); the share header carries its first 13 bytes |
| Shamir | Byte-wise over GF(2^8), polynomial 0x11B, 32 independent lanes. Random coefficients of degree 1 to m-1 from the TRNG routine. Share points x = 1..n |
| Share header (AAD) | x(1) \|\| m(1) \|\| n(1) \|\| fp(13), 16 bytes |
| Share wrap | AES-256-GCM(K, random IV, AAD = header, share). K = HMAC-SHA256(r, "SHARE-WRAP-v1" \|\| header) |
| Card secret r | HMAC-SHA256(card response, "SN-CARD-v1" \|\| challenge) on the host. The YubiKey response is HMAC-SHA1 over a 32-byte challenge, touch required |

Why these choices: GCM with the wallet id as AAD stops a blob from being replayed under another wallet. A random 96-bit IV per wrap keeps collision risk negligible at about 10,000 wallets per node. The fingerprint lets RESTORE detect wrong or mixed shares, since plain Shamir cannot.

## 8. Lifecycle procedures

**Boot of an existing node**

1. The tamper MCU sends `0xA5 || S` over SPI. The node derives chan_key and seal_key and draws a session nonce.
2. The SoC reads the nonce and starts a counter at 1.
3. The SoC sends the sealed KEK blob from NVMe with KEK_UNSEAL. If S differs (after a tamper event), the unseal fails and the node waits for another recovery path.

**First node in a new cluster**

1. Run KEK_GEN.
2. Run KEK_SEAL and store the blob on that node's NVMe.
3. Run the split ceremony (below) before putting any funds under the cluster.

**Adding a node (ECIES)**

1. On the new node run ENROL_GEN. Read its enrolment public key.
2. An operator compares the key out of band, for example through the console of the new node. The FPGA cannot authenticate this key itself.
3. On an existing node run KEK_EXPORT with that key. Pass the result to the new node.
4. On the new node run KEK_IMPORT, then KEK_SEAL and store the blob. The enrolment key is destroyed on import.

**Backup**

- Wallet blobs: replicate through Raft and take ordinary database backups. They are useless without the KEK.
- Sealed KEK blobs: keep one per node. They open only on that node with that node's S.
- Share records: store the JSON from the split ceremony in several places. They open only with m cards.

**Split ceremony (m of n)**

1. SPLIT_BEGIN with m and n (2 <= m <= n <= 8). The node returns a header template with the KEK fingerprint.
2. For each card: the host sends a random 32-byte challenge, the operator touches the card, and the host derives r and calls SHARE_GET_C with r masked. The record (challenge, header, IV, tag, ciphertext) is saved.
3. SPLIT_END discards the sharing polynomial. Compare KEK_FP across nodes to confirm they hold the same KEK.

Turn the ceremony key-switch on before step 1 and off after step 3. The same applies to adding a node, break-glass recovery and the export and import steps of a rotation.

**Break-glass recovery**

1. Bring a node up with a fresh S. It has no KEK.
2. For each of m operators: the host replays the stored challenge, the operator touches the card, and SHARE_PUT_C stores the share. Duplicates and wrong-card shares are refused.
3. RESTORE interpolates the KEK, checks its fingerprint against the header, loads it, and scrubs the shares. Seal it with KEK_SEAL.

**KEK rotation**

1. KEK_NEW_GEN on one node, then KEK_NEW_EXPORT to each other node, which runs KEK_NEW_IMPORT.
2. Run REWRAP on every wallet blob and store the new blob next to the old one.
3. Run KEK_PROMOTE on every node, reseal, and repeat the split ceremony. Old shares and old blobs are then dead.

## 9. Performance

At a 100 MHz clock a signature takes about 34.7 ms inside the module with the signature check on (the default), and about 37.6 ms per request over a 1 MHz I2C bus. That is roughly **27 signatures per second per node, about half the 55 per second target**. With the check off (`VERIFY_SIGN = 0`) it is about 18.0 ms and 48 per second, as in V0.4. The 100 MHz clock is an assumption, because the design has not been synthesised or timed on silicon.

The cycle counts below were measured in the V0.5 simulation (`tb_v05.v`, lines `CYCLES` in its log) and include command authentication and the response MAC.

| Operation | Cycles | Time at 100 MHz | Basis |
| --- | --- | --- | --- |
| SIGN, signature check on | 3,469,730 | 34.7 ms | Measured: two scalar multiplications, two mod-n multiplications |
| SIGN, signature check off | about 1.80 M | about 18.0 ms | V0.4 core measurement plus measured overheads |
| GEN_WALLET | 1,673,147 | 16.7 ms | Measured: one scalar multiplication |
| PUBKEY, ENROL_GEN, KEK_IMPORT | about 1.67 M | about 16.7 ms | One scalar multiplication, estimate |
| KEK_EXPORT | about 3.34 M | about 33 ms | Two scalar multiplications, estimate |
| Command authentication + response MAC | 816 | 8 us | Measured (refused command) |
| Start-point randomisation | about 520 | 5 us | Two mod-p multiplications per scalar multiplication |
| KEK_GEN, KEK_FP, SPLIT_BEGIN, share commands | 1,000 to 5,500 | under 0.1 ms | Measured |

On the bus, one SIGN request writes about 193 bytes and reads back 96 (r, s and the response MAC), which costs about 2.9 ms at 1 MHz and about 7 ms at 400 kHz.

Ways to recover the target, in order of effort:

1. Add nodes. The module is stateless, so throughput scales linearly: two nodes with the check on match one without.
2. Run the second scalar multiplication of the check in a second signer core, in parallel with the first. It does not depend on r, so the signature time returns to about 18 ms for roughly twice the signer area. Not implemented.
3. Turn the check off on nodes whose enclosure you trust against fault injection. This gives up the protection.
4. Raise the clock. With the check on, 55 per second needs about 230 MHz, which is unlikely for 256-bit carry chains.

## 10. Verification status

Every block passes its own simulation under Icarus Verilog, and the full node passes three system simulations that independent Python checks then re-verify from the bus traffic. Nothing has been run on hardware. The results below are from the V0.5 sources.

| Test | What it covers | Result |
| --- | --- | --- |
| Signer core | Range rejections, signatures and public keys against `refmodel.py`, and the same signature from two randomised start points | 10 of 10 (`tb_ecdsa_sign.v`, 2 signature vectors) |
| Hash and nonce | HMAC-SHA256 for 16 message lengths including the 161-byte command frame and the 172-byte response frame; RFC 6979 plain and hedged, including the published secp256k1 vector | 25 of 25 |
| I2C slave, TRNG | Protocol, health tests (simulation model) | Pass |
| AES-256 and GCM | FIPS-197 block; 6 encrypt and 6 decrypt vectors from the `cryptography` library; 3 tamper cases withhold plaintext; wipe mid-operation | 17 of 17 |
| SPI, point check, ECDH | Frame accept and reject; valid and invalid points; multiplication of arbitrary points against the reference | 17 of 17 |
| Shamir | 4 (m, n) settings, every evaluation point, several subsets, fewer than m shares, rejections, tamper clear | 46 of 46 |
| Node system, protocol 0xB2 (`tb_v05.v`) | Response MAC on success and on error; MAC register cleared; a signature that passes its check; a fault forced into s caught by the scalar check; a bit flipped in the ladder caught by the second ladder; buffers zero after errors; all ten gated commands refused with the ceremony pin low; split and restore with masked card secrets; an unmasked secret refused; seven failures then success; eight failures lock; reset unlocks; tamper clears RMAC | 71 checks, all pass |
| Node system, Phase 1 (`tb_node_system.v`) | Two nodes on one I2C bus: sessions, MAC and replay rejection, wallet wrap and sign, wrong id or tag, ECIES transfer, seal and reboot, tamper mid-signature | 48 checks, all pass |
| Node system, Phase 2 (`tb_phase2.v`) | Split 3-of-5, wrong-card and duplicate shares, tamper wipe, restore on two nodes from different card subsets, rotation with ECIES to a second node, rewrap, promote | 53 checks, all pass |
| Host tools against the software model | `sn_host.py` and `sn_ceremony.py` of V0.5 driving the Rust model of protocol 0xB2: wallet, sign, gated command refused, 3-of-5 split and restore, altered response rejected, lockout reported | Pass |
| Ceremony tool | Split 3-of-5, restore from three card subsets, refuse with two | Pass (software cards) |

The independent Python checks use only what appeared on the bus plus testbench peeks of the KEK and enrolment key. They confirm that every response MAC recomputes from the logged buffers, that the value sent to SHARE_GET_C is the card secret XOR the specified mask and does not itself open the share, that sealed and wrapped blobs decrypt with the stated keys, that the required number of shares rebuild the KEK and fewer do not, that the ECIES blob decrypts, that REWRAP keeps the same wallet key under the new KEK only, and that every signature verifies, is low-s, and differs from its repeat (hedged nonce).

Limits of this evidence:

- The RTL and the software model were each checked against the same written definition of 0xB2, not against each other command by command.
- Fault injection was two simulated faults at chosen points, not a campaign.
- Start-point randomisation was checked for correctness (same result), not for leakage.
- The Phase 1 and Phase 2 testbenches hold the ceremony pin high throughout.
- The builds with `VERIFY_SIGN = 0` or `RAND_Z = 0` were compiled but not simulated.

Not verified: gate-level behaviour, timing, power, side channels, real TRNG output, real YubiKeys.

## 11. Known limitations and residual risks

This is a simulated design, not a certified or deployed one. Do not put real funds behind it before the items below are closed.

**Physical and implementation security**

- Not synthesised, placed or timed. There are no resource, frequency or power figures.
- Side-channel countermeasures are partial. The ladder runs a fixed number of cycles with conditional swaps and starts from a randomised projective point, but there is no scalar blinding and no masking in AES or HMAC. Power and EM leakage are untested.
- Fault-attack countermeasures cover a single fault during signing: the signature is checked before release (section 7). Two matching faults, a fault in the comparison itself, and faults in other commands (key generation, unwrap, ECIES) are not covered.
- With a failed TRNG the start-point randomisation is off (λ = 1), so that signing stays available.
- The TRNG is a ring-oscillator design with placeholder thresholds. Simulation uses a deterministic stand-in that is not random. It needs entropy characterisation on the real device across voltage and temperature.
- Registers are volatile only if the FPGA is. Bitstream protection and readback lockout are your responsibility (section 12).

**Protocol and trust**

- The enrolment public key is not authenticated by the FPGA. A substituted key would receive the KEK, so a person must verify it out of band before KEK_EXPORT.
- A compromised SoC secure world holds chan_key and can request signatures on any digest, because the node signs what it is given. There is no per-request authorisation and no rate limit. It cannot export, import, split or restore a KEK while the key-switch is off.
- A device on the I2C bus can lock the command channel with eight bad MACs. Recovery is a reset, after which the KEK is unsealed again.
- During a ceremony the host sees each card secret r, although the bus does not. Running a ceremony on a compromised host exposes the KEK once m cards are used.
- The protection of the sealed KEK against the SoC depends on the tamper MCU giving the SoC only chan_key. That firmware is not written.
- r has at most 160 bits of strength, because the YubiKey slot uses HMAC-SHA1.
- The YubiKey responder shells out to `ykman` and was not run against real hardware. The tests use a software card.

**Design trade-offs**

- One KEK wraps every wallet. A KEK compromise exposes all wallets until they are rewrapped; rotation exists but is a manual procedure.
- Plain Shamir cannot say which share is bad. RESTORE only reports a fingerprint mismatch.
- The tamper MCU's S is the root for the local seal. Losing S (tamper, MCU failure) makes that node's sealed KEK unrecoverable; recovery then needs another node or m cards.
- Not compatible with the SE050 T=1/APDU protocol. A new driver is required.
- No formal verification and no independent security review.

## 12. Hardware integration requirements and open items

**Integration requirements**

- **I2C.** Connect `sda_oe` to an open-drain driver (`sda = sda_oe ? 0 : Z`), read SDA back on `sda_i`, and add an external pull-up. SCL is input only. Keep the system clock at least 8 times SCL.
- **SPI.** Wire only SCLK, CS and MOSI from the STM32U5. Leave MISO unconnected. Keep the system clock at least 4 times SCLK.
- **Tamper.** Drive `tamper` from the tamper circuit and hold it high for the whole fault. Treat it as asynchronous. Do not gate it with software.
- **Ceremony.** Drive `ceremony` from the tamper MCU, which reads the physical key-switch. Do not connect it to the SoC.
- **Power loss clears the KEK.** Use an SRAM-based FPGA, or an arrangement where loss of power destroys register contents. Do not use a configuration that retains register state.
- **Bitstream protection.** Enable bitstream encryption and authentication, lock JTAG and configuration readback, and keep the key outside reach of the SoC normal world.
- **TRNG.** Build with `SIM_TRNG = 0`. Set oscillator count, sample divider and health-test cut-offs from measured data. Some tools need a combinational-loop waiver for the oscillators.
- **Clock.** Target 100 MHz or higher (section 9).

**Software the integrator supplies**

- STM32U5 firmware that sends the SPI frame after every FPGA boot, drives the tamper line and the ceremony pin, and gives the SoC HMAC(S, "SN-CHAN") but never S.
- SoC secure-world driver. `sn_host.py` is a reference implementation of the framing, command and response MACs and every command.
- Ceremony tooling and a procedure for operators. `sn_ceremony.py` is a reference.

**Open items, in the order I would close them**

1. Synthesise for the chosen device and close timing at the target clock. Record area and power.
2. Characterise the TRNG to SP 800-90B and set the health thresholds.
3. Test the YubiKey responder against real cards, including touch and loss of a card.
4. Add scalar blinding (needs a wider ladder and the microcode generator) and masking of AES and HMAC, then measure leakage on the device.
5. Write the tamper MCU firmware: SPI frame, tamper line, ceremony pin, derived key for the SoC.
6. Run a restore drill and a rotation drill on real hardware.
7. Commission an independent review of the RTL and the protocol.

Closed in V0.5: verify before release, response MACs, lockout after repeated bad MACs, confidential card secrets on the bus, ceremony pin, start-point randomisation.

## Appendix: files and simulation

`V0.5/` is the complete tree for this specification. Its [`README.md`](V0.5/README.md) lists the files and the exact simulation commands. `V0.2` holds the earlier single-key module (`secp256k1_hsm_top.v`, I2C address 0x42, confirm button), which the stateless node superseded; `V0.3` and `V0.4` hold the first two stages of the stateless node (protocol 0xB1).

| Area | Files in `V0.5/` |
| --- | --- |
| Node top level | `sign_node_top.v`, `secret_store.v`, `spi_secret_rx.v`, `point_check.v` |
| Signer | `ecdsa_secp256k1_sign.v`, `modmul_serial.v`, `ecdsa_ucode_rom.v`, `ecdsa_ucode_entries.vh` (generated) |
| Hash and nonce | `sha256_core.v`, `hmac_sha256.v`, `rfc6979_nonce.v` |
| AEAD | `aes256_core.v`, `gf128_mul.v`, `aes_gcm32.v`, `aes_sbox.vh` (generated) |
| Sharing | `shamir_core.v`, `gen_shamir.py` |
| Peripherals | `i2c_slave.v`, `trng_ro.v` |
| Host software | `sn_host.py` (driver), `sn_ceremony.py` (operator-card ceremonies) |
| Reference and vectors | `refmodel.py`, `gen_vectors.py` |
| Testbenches | `tb_v05.v`, `tb_phase2.v`, `tb_node_system.v`, `tb_blocks.v`, `tb_ecdsa_sign.v`, `tb_gcm.v`, `tb_shamir.v`, `tb_hash_nonce.v`, `tb_i2c_slave.v`, `tb_trng.v` |
| Independent checks | `verify_v05.py`, `verify_phase2.py`, `verify_node.py` |

The microcode generator (`gen_ucode.py`) and the generators for the AES S-box and GCM vectors are not in the repository; their outputs are. The simulation TRNG (`SIM_TRNG = 1`) is deterministic and not random.
