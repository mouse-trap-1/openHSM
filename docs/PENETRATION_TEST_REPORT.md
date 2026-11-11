# OpenHSM Simulated Penetration Test Report

Target: OpenHSM prototype 0.5.0 (release binaries built from this repository) and signing-module protocols 0xB1 and 0xB2.
Kind of test: simulated, white-box, automated. Everything runs on one machine against the real binaries; the tamper enclosure is a software model.

<!-- SUMMARY:BEGIN -->
Run: 2026-11-11 04:23:07 GMT, Linux x86_64, Python 3.13.18, source revision `uncommitted`, 38.6 s.

| Tests | Pass | Finding | Info | Error |
| --- | --- | --- | --- | --- |
| 68 | 65 | 2 | 1 | 0 |

| Suite | Target | Tests | Pass | Finding | Info |
| --- | --- | --- | --- | --- | --- |
| A | Signing module at its pins | 19 | 16 | 2 | 1 |
| B | Network API | 11 | 11 | 0 | 0 |
| C | Policy engine | 12 | 12 | 0 | 0 |
| D | Signed output | 5 | 5 | 0 | 0 |
| E | Storage | 6 | 6 | 0 | 0 |
| F | Physical events and ceremonies (simulated) | 8 | 8 | 0 | 0 |
| G | Source and build | 7 | 7 | 0 | 0 |
<!-- SUMMARY:END -->

To reproduce: `cargo build --release && python3 pentest/run.py && python3 pentest/report.py`. Raw results are in [`pentest/results/results.json`](../pentest/results/results.json).

## 1. Conclusions

1. **No attack in scope obtained a wallet key or the KEK from the 0.5.0 node**, and none obtained a signature outside a wallet's policy with the credentials the [threat model](THREAT_MODEL.md) gives each attacker.
2. **The 0xB1 module protocol of FPGA V0.4 has two serious design weaknesses**, both demonstrated by recovering the KEK, and one moderate one. All three are closed in the prototype (section 4.1). Two are now also closed in the RTL (FPGA V0.5, protocol 0xB2); the third needs the supervisor firmware, which is not written.
3. **The test campaign found four defects in the prototype itself**, one of them a published timing vulnerability in a cryptographic dependency. All four were fixed and the tests now pass (section 4.2).
4. **One limitation is structural**: an attacker who fully controls the SoC can request signatures on arbitrary digests, because policy runs on the SoC and the module signs what it is given. The attacker still cannot take any key away. This is residual risk R-1.
5. **Nothing here is evidence about hardware.** Tamper response, fault injection and entropy failure were tested as logic in a model. Side channels were not tested at all.

## 2. Scope and limits

| Tested | Not tested |
| --- | --- |
| `openhsmd` network API over TLS 1.3 | The FPGA bitstream, supervisor firmware, carrier board |
| Signing-module model at register level, protocols 0xB1 and 0xB2 | Power, electromagnetic and timing side channels |
| Policy engine for Ethereum and Bitcoin | Real voltage or clock glitching, laser fault injection |
| On-disk state, audit chain, boot integrity checks | The mesh, sensors, potting, battery domain |
| KEK ceremonies: enrolment, split, restore, rotation | Real YubiKeys |
| Simulated tamper, power loss, entropy failure, fault injection | OP-TEE isolation, secure boot, the Linux image |
| Source tree, release binaries, dependencies | Availability under cluster failure (no cluster layer yet) |

The tester had the source code and wrote the tests alongside the fixes. That is useful for coverage and weak as assurance: it is not an independent assessment, and it should not be presented as one. An external review is the first item under next steps.

## 3. Method

### 3.1 Laboratory

`pentest/lab.py` builds throw-away deployments from the release binaries. Each node is two processes, as on the board: `openhsm-hwsim` (signing module and tamper supervisor) and `openhsmd` (SoC). The lab creates a CA, three admins (quorum two), two application servers, an auditor, and a second unrelated CA with an attacker identity.

The harness gives each suite the access its attacker has: raw I2C registers and pins of the module; a hand-written API client in which every field of a request can be forged; the node's disk while it is stopped; the simulated physical world (sensors, power, key-switch, glitch, entropy fault).

### 3.2 Independence of the checks

All cryptography in the harness uses the Python `cryptography` package or code written for the tests (Keccak-256, RIPEMD-160, RLP, secp256k1 recovery, Bech32, BIP-143, DER). None of it shares code with the Rust implementation. Test D-01 checks that code against published vectors (EIP-155, BIP-143, BIP-173) before it is used to judge the node.

Leak checks use ground truth. The harness reads the tamper secret from inside the enclosure model, derives the KEK and wallet keys the way only the module can, and searches for those exact bytes in bus dumps, API responses, files and process memory.

### 3.3 Result categories

| Result | Meaning |
| --- | --- |
| PASS | The attack was attempted and defeated; the evidence column says how that was observed |
| FINDING | The attack succeeded or a weakness was demonstrated |
| INFO | An observation that is a residual risk, not a pass or fail |

A test that is refused for an unrelated reason (for example rate limiting instead of policy) is an error, not a pass: the policy suite checks the refusal code of every case.

### 3.4 Suites

| Suite | Target | Attacker (threat model) | Techniques |
| --- | --- | --- | --- |
| A | Signing module at its pins | T7 bus device, T6 host with the channel key, T8 physical | Command sweep, replay, bit-flipping, MAC guessing, register scan, blob substitution, response forgery, invalid-curve points, rogue tamper secret, passive ceremony capture, fault injection, entropy failure, nonce statistics |
| B | Network API | T1 network, T2/T3 one credential | TLS downgrade, request forgery, role escalation, quorum bypass, replay, fuzzing (structural, length-prefix, 300 mutations, hostile parameters), connection exhaustion, flooding, leak search, races |
| C | Policy engine | T2 compromised application server | Allow-list bypass, integer encodings and overflow, fee abuse, cross-chain replay, ERC-20 calldata tricks, blind signing, message/transaction confusion, daily-limit race and restart, Bitcoin output, fee and amount abuse, input-amount lies |
| D | Signed output | none (correctness) | Independent decoding and verification of every signed transaction |
| E | Storage | T4 thief, T5 root on the SoC while stopped | Key search at rest, foreign enclosure, state edits, rollback, audit log edits, CA replacement |
| F | Physical events and ceremonies (simulated) | T8, T3, T9, T6 | Every tamper sensor, power loss, ceremony switch, entropy failure, glitch through the full stack, too few or forged cards, KEK diversion, daemon memory dump |
| G | Source and build | T10 supply chain | `unsafe` audit, clippy, panic-site review, ELF hardening, secret scan, dependency inventory, `cargo audit`, `bandit` |

## 4. Findings

Severity is the tester's judgement of impact on funds if the weakness were present in a deployed node.

### 4.1 Weaknesses in the existing 0xB1 design, closed in the prototype

| ID | Severity | Test | Weakness | Demonstration | Fix | Status |
| --- | --- | --- | --- | --- | --- | --- |
| PT-01 | High | A-14 | The SoC is given the tamper secret S (`sn_host.py` takes S). It can derive the module's seal key. | From S and the files on the SoC's own disk, the test opened the sealed KEK offline and decrypted a wallet key, matching it to the wallet's public key. No module needed. | The supervisor gives the SoC two derived keys (`chan`, `SOC-SEAL-v1`) and never S. With those the sealed KEK does not open. | Fixed in the model. **Needs supervisor firmware to match.** |
| PT-02 | High | A-13 | In a split ceremony the card-derived secret crosses I2C in the clear (`SHARE_GET`, 0x51). | A passive probe recorded one 3-of-5 ceremony and rebuilt the KEK from the captured secrets and wrapped shares. | Extension X5: commands 0x56/0x57 mask the secret with a keystream derived from the channel key, nonce and counter. The node uses only these. | Fixed in the model and in the RTL from FPGA V0.5 (simulation: `tb_v05.v`, `verify_v05.py`). |
| PT-03 | Medium | A-10 | Responses are not authenticated in 0xB1. | An active bus device replaced the public key returned by `GEN_WALLET`; a 0xB1 host has no way to notice, and would publish an address the attacker controls. | Extension X1: response MAC over all output buffers; the node also re-derives the public key from the blob before recording a wallet. | Fixed in the model and in the RTL from FPGA V0.5 (simulation). |

A-13 and A-14 are reported as FINDING on every run on purpose: each test first proves the attack against 0xB1, then proves it fails against 0xB2. These tests run against the software model, not the RTL. The RTL's own evidence for X1 to X6 is the V0.5 simulation, which includes injected faults during signing; see `FPGA/V0.5/README.md`.

### 4.2 Defects found in the prototype during testing, fixed

| ID | Severity | Test | Defect | Fix | Re-test |
| --- | --- | --- | --- | --- | --- |
| PT-04 | High | G-06 | `cargo audit` reported RUSTSEC-2026-0387 in `crypto-bigint` 0.5.5 (pulled in by `k256` 0.13.4): secret-dependent branches in operations meant to be constant-time. The signing-module model does its scalar arithmetic with this library. | Upgraded to `k256` 0.14.0 (`crypto-bigint` 0.7.11) and ported the affected code. | G-06 pass: 0 advisories. All 49 unit tests and suites A and D pass on the new version. |
| PT-05 | Low | E-05 | `hsmctl audit-verify` accepted an empty file as a valid audit log, so "replace the log with nothing" passed offline verification. The node itself refused to boot on it. | `verify_file` rejects an empty log and one that does not start with `node_init`; unit test added. | E-05 pass. |
| PT-06 | Low | G-06 | `rustls-pemfile` is unmaintained (RUSTSEC-2025-0134). | Removed; PEM parsing now uses `rustls-pki-types`. | G-06 pass: 0 warnings. |
| PT-07 | Info | G-02 | One clippy warning with warnings denied (`manual_contains` in the policy engine). No security impact. | Fixed. | G-02 pass. |

The exploitability of PT-04 in this code was not measured. It is rated high because the affected library sits under private-key arithmetic and the fix was available.

### 4.3 Observations and residual risks

| ID | Test | Observation | Threat model |
| --- | --- | --- | --- |
| PT-08 | A-15, F-08 | With the channel key (full SoC compromise) an attacker could not export, replace or unseal the KEK in 8 attempts, and the daemon's memory held no KEK, wallet key or tamper secret. The attacker can request signatures on any digest and can erase the KEK. | R-1 |
| PT-09 | A-06 | Eight bad MACs lock the module until reset: guessing is bounded at 8 × 2^-256 per power cycle, and a bus device can use the same mechanism to stop signing. | R-2 |
| PT-10 | B-07 | During a connection flood a client from another address was served at once; a client sharing the attacker's address was refused until the flood stopped. | R-3 |
| PT-11 | E-05 | A truncated copy of the audit log verifies offline as a valid prefix. The node detects truncation at boot through the supervisor counter. | R-4 |
| PT-12 | F-04 | An entropy failure latches until the module is reset. Wallet creation is refused; signing continues with the deterministic RFC 6979 nonce, which is safe without entropy. | none (intended) |

## 5. What the passing tests establish

| Objective (threat model) | Evidence |
| --- | --- |
| O1 Keys never leave the module in the clear | A-07 (register scan), B-09 (API responses), E-01 (disk), F-08 (daemon memory), F-06/F-07 (snapshots and transfers): no secret found by exact-byte search |
| O2 Nothing signed outside policy | C-01 to C-04 and C-08: 62 out-of-policy transactions refused, each for the right reason, with a positive control at each boundary; C-05, C-10, C-11: blind signing, frozen wallets and empty policies refused; C-07: 16 parallel requests cannot exceed the daily cap, and a restart does not reset it; C-09: a false Bitcoin input amount yields a signature the network rejects |
| O3 Quorum and physical presence | B-03, B-04 (48 cross-role calls and 9 quorum-bypass variants refused), F-03 (switch off: even the full quorum cannot move the KEK), F-07 (one admin, a swapped enrolment key, an off-curve key and a replayed transfer all fail) |
| O4 Tamper response (logic) | A-18, F-01: all six sensors erase S, latch across power cycles, stop the API, prevent restart, and leave a signed audit entry |
| O5 Audit integrity | E-03, E-04, E-05: edits to policy or principals, blob swaps, a single appended byte, full-disk rollback, and edited, deleted, reordered, truncated or forged audit entries all stop the boot |
| O6 Captured material is useless | A-04, B-05, B-11 (replay, including after restart and under a 24-way race), A-09 (blobs bound to wallet id), E-02 (drive in a foreign enclosure), F-06 (2 of 3 cards, forged card) |
| O7 Robustness | B-06 (401 hostile frames, no crash, no internal error, resident memory under 10 MiB), B-08 (rate limit per principal), B-10 (audit flooding bounded) |
| Correctness of what is signed | D-02 to D-04: Ethereum EIP-1559, legacy EIP-155, ERC-20 and Bitcoin P2WPKH outputs decode to exactly the requested fields and verify under independent code; D-05, A-19: no nonce reuse in 120 and 3,000 signatures |

## 6. Next steps

1. Commission an independent review of the RTL, the protocol and this node. Give the reviewers this harness.
2. Write the supervisor firmware with derived keys, counter and ceremony pin (closes PT-01 on hardware). X1 to X6 are in the RTL from FPGA V0.5; co-simulate the RTL against the model so the two are proven to agree.
3. Decide how to close R-1: the options are in the threat model. This is the largest remaining design question.
4. On the first synthesised board: TVLA-style leakage assessment of the ladder and AES-GCM, glitch campaign against verify-before-release, SP 800-90B entropy assessment, tamper sensor characterisation.
5. Add the tests this run does not have: coverage-guided fuzzing of the request path (`cargo fuzz`), a restore drill with real YubiKeys, clock-jump behaviour of daily limits (R-7).
6. Run `python3 pentest/run.py` in CI on every change; it takes under a minute.

## 7. Full results

<!-- RESULTS:BEGIN -->

### Suite A: Signing module at its pins

| ID | Test | Attacker | Expected control | Result | Evidence from this run |
| --- | --- | --- | --- | --- | --- |
| A-01 | The existing FPGA host driver (sn_host.py) drives the model unchanged | none (conformance) | Protocol 0xB1 compatibility: every sn_host.py flow works and results verify independently | PASS | sn_host.py: KEK_GEN, GEN_WALLET, SIGN, PUBKEY, SEAL/UNSEAL across reset, ECIES A->B, rotation all pass; signatures verified with python-cryptography |
| A-02 | The existing ceremony tool (sn_ceremony.py) splits and restores against the model | none (conformance) | 3-of-5 split, restore from other card subsets on a wiped module, refusal with 2 cards; shares open only as specified | PASS | sn_ceremony.py split 3-of-5 and restored from two different subsets; 10/10 triples rebuild the KEK and 0/10 pairs do (gen_shamir.py); two cards refused |
| A-03 | Unauthenticated command sweep | device on the I2C bus, no channel key | Every one of the 256 command codes is refused without a valid MAC and changes nothing | PASS | 256/256 command codes refused with E_AUTH; KEK unchanged |
| A-04 | Replay of captured commands | device on the I2C bus that recorded valid traffic | A captured frame is refused in the same session (counter) and in a later session (nonce) | PASS | replay refused in-session (counter must increase) and cross-session (fresh 128-bit nonce in the MAC) |
| A-05 | Modification of an authenticated command in transit | active device on the I2C bus | Changing any bit of any field (command, counter, wallet id, IV, tag, A, B, C) invalidates the MAC | PASS | 24 single-bit modifications across all MAC-covered fields, all refused |
| A-06 | Online guessing of the command MAC | device on the I2C bus | Guessing is cut off: after 8 consecutive failures the channel locks until reset (extension X2) | PASS | 8 guesses per power cycle; success probability per cycle 8 * 2^-256. Side effect: a bus attacker can lock the channel (denial of service until reset) |
| A-07 | Register scan for key material | device on the I2C bus reading every register after every command | No byte of S, the channel key, the seal key, the KEK or a wallet key is ever readable | PASS | 256 registers dumped after each of 12 operations; no 8-byte window of any of 6 secrets found |
| A-08 | Register-pointer abuse | device on the I2C bus | Long writes that wrap the 8-bit pointer, writes to read-only registers and writes under tamper do no harm | PASS | read-only registers hold; a 300-byte wrapped write only produces E_AUTH; registers are not writable under tamper |
| A-09 | Wallet blob substitution and corruption | holder of stolen wrapped blobs with access to a module | A blob opens only under its own wallet id and its own KEK; any altered bit is rejected and nothing is output | PASS | 12 substituted or corrupted blobs, each tried with SIGN and PUBKEY: all E_UNWRAP, output buffers zero |
| A-10 | Forged or altered responses | active device on the I2C bus | A host that checks the response MAC (extension X1) detects any change to a response | PASS | public-key substitution (B/C), blob substitution (A/IV/TAG) and error-code substitution all break the response MAC. A protocol-0xB1 host has no such check: there, a bus attacker can swap the public key returned by GEN_WALLET |
| A-11 | Invalid-curve and degenerate points in ECDH | host with the channel key supplying a chosen enrolment key | Points off the curve, on the twist, at infinity or with coordinates >= p are refused before any scalar multiplication | PASS | 10 malformed points x 3 commands refused (E_POINT, no ciphertext); the valid point is accepted |
| A-12 | Injection of a rogue tamper secret | physical attacker driving the SPI input | A second secret is ignored once a session exists; a module booted with the attacker's secret cannot open a captured sealed KEK | PASS | second SPI frame ignored; under an attacker-chosen secret the module has a session but the sealed KEK does not open (E_UNWRAP) |
| A-13 | Passive capture of a share ceremony on the bus | passive probe on the I2C bus during a split ceremony | The card secrets must not be recoverable from bus traffic | FINDING | Protocol 0xB1 (SHARE_GET, 0x51): the card secret crosses I2C in the clear; a passive probe rebuilt the KEK from one ceremony. Fixed in 0xB2 by SHARE_GET_C / SHARE_PUT_C (extension X5), which the node uses: the same probe recovers nothing. |
| A-14 | Offline KEK recovery by a host that holds the tamper secret | compromised SoC secure world (protocol 0xB1 key distribution) | The SoC must not be able to open the sealed KEK | FINDING | Protocol 0xB1 key distribution: the SoC is given S, so it can derive HMAC(S,'SN-SEAL'), open the sealed KEK offline and decrypt every wallet blob (wallet private key recovered and matched to its public key). Fixed in this prototype: the supervisor hands the SoC derived keys only (openhsm-hw SocKeys); with those keys the sealed KEK does not open. |
| A-15 | Compromised SoC secure world: extraction or replacement of the KEK | attacker with the channel key, ceremony key-switch off | With the key-switch off no command moves a KEK in or out (extension X6) | INFO | 8 extraction/substitution attempts refused. Residual, by design of a digest-signing module: a host with the channel key can still (a) request signatures on any digest with any wallet blob, bypassing SoC policy, and (b) erase the KEK (denial of service). See residual risk R-1. |
| A-16 | Fault injection during signing | physical attacker glitching power or clock | A corrupted signature is never released (extension X3: verify before release) | PASS | 50/50 faulted signatures withheld (E_SIGN, buffers zero); the following signature is valid each time |
| A-17 | Entropy source failure | environmental or physical fault on the TRNG | Key generation and wrapping fail closed; signing stays safe (deterministic RFC 6979); no session without entropy | PASS | 4 key-generating commands refused with E_TRNG; signatures remain valid and become deterministic; no session can start |
| A-18 | Tamper input | physical attacker tripping (or failing to avoid) a tamper sensor | The wipe is immediate and complete, latches until reset, and makes earlier sealed blobs useless | PASS | KEK, session and registers cleared on the tamper edge; latch survives de-assertion; the sealed KEK is dead after re-provisioning |
| A-19 | Nonce quality (white-box) | analyst with the wallet private key and 3,000 signatures | Nonces recovered from signatures are unique, unbiased and not the plain RFC 6979 value (hedging is active) | PASS | 3000 signatures over one digest: 3000 distinct nonces, worst single-bit deviation 2.85 sigma, monobit z = 1.21 over 762000 bits; all signatures low-s |

### Suite B: Network API

| ID | Test | Attacker | Expected control | Result | Evidence from this run |
| --- | --- | --- | --- | --- | --- |
| B-01 | TLS downgrade and unauthenticated connections | network, no credential | Only TLS 1.3 with a client certificate from the cluster CA gets a connection | PASS | no certificate: rejected; foreign-CA certificate: rejected; TLS 1.2: handshake refused; plaintext: no application data returned |
| B-02 | Request forgery with a valid TLS certificate | holder of one TLS certificate | A request is accepted only if signed by the principal whose certificate is on the connection | PASS | 6 forgeries refused with one indistinguishable error (unauthenticated) |
| B-03 | Privilege escalation across roles | holder of one valid credential | Signers only sign, auditors only read, admins cannot sign; every refusal is audited | PASS | 48 cross-role calls refused as 'forbidden'; admin+signer is not a quorum; 49 audit entries written |
| B-04 | Quorum bypass by a single rogue administrator | one admin credential | No sensitive operation runs without signatures of two distinct admins over the same, fresh, node-bound operation | PASS | refused: single signature (quorum_required), same admin twice (unauthenticated), co-signature lifted from another operation (unauthenticated), no expiry (bad_request), validity of one year (stale), already expired (stale), not bound to a node (bad_request), addressed to another node (bad_request), addressed to another cluster (bad_request); replay of an executed quorum operation (replay). Policy unchanged. |
| B-05 | Replay of captured signing requests | network position / stolen request | A captured request yields no second signature, now, later, or after a restart | PASS | identical resend returns the cached response without signing again; nonce reuse, stale, post-dated and post-restart replays refused |
| B-06 | Malformed and hostile frames (fuzzing) | network, valid certificate | No crash, hang or memory blow-up; every bad frame gets a bounded error | PASS | 401 hostile frames (structural, length-prefix, 300 random mutations, hostile parameters): daemon alive, no internal error, RSS 7156 kB |
| B-07 | Connection exhaustion and slow clients | network, valid certificate | Idle or slow connections cannot starve other clients | PASS | 200 idle connections held open from one address (0 of them past TLS, the rest cut off by the per-address cap of 32 and the 5 s handshake deadline); a client from another address was served in 0.00s; a client sharing the attacker's address was refused while the flood lasted (the cap is per address by design); service normal afterwards |
| B-08 | Request flooding by one principal | stolen application-server credential | Per-principal rate limit; other principals keep their budget | PASS | 1500 requests in 0.5s: {'ok': 492, 'rate_limited': 1008}; a second principal was served normally |
| B-09 | Secret leakage through API responses and errors | any credential | No response contains key material; errors do not echo internals | PASS | 13 responses (38132 bytes) searched for 7 secrets (KEK, S, chan_key, seal_key, soc_seal, wallet_key_d69dd8fc, wallet_key_d7487fba) and for internal paths: none found |
| B-10 | Audit-log flooding through failed authentication | network, valid certificate | Failed attempts are recorded but cannot fill the disk | PASS | 400 failed authentications in 0.0s produced 1 audit entry (rate-limited to one per second, with a suppressed count) |
| B-11 | Concurrent requests racing the same nonce | stolen application-server credential | Exactly one signature for one request, however many copies arrive at once | PASS | 24 simultaneous copies: 1 signed, 23 served from the idempotency cache, 1 audit entry |

### Suite C: Policy engine

| ID | Test | Attacker | Expected control | Result | Evidence from this run |
| --- | --- | --- | --- | --- | --- |
| C-01 | Ether to a recipient that is not on the allow-list | compromised application server | Only allow-listed recipients, in any spelling of the address | PASS | 8 refused: unlisted recipient [policy_denied]; unlisted recipient, 1 wei [policy_denied]; recipient = token contract (ether to a contract) [policy_denied]; zero address [policy_denied]; address with wrong EIP-55 checksum [bad_request]; 21-byte address [bad_request]; address without 0x [bad_request]; legacy transaction to unlisted recipient [policy_denied] |
| C-02 | Amount, fee and integer-encoding abuse (Ethereum) | compromised application server | Per-transaction cap and fee cap hold for every numeric encoding | PASS | 17 refused: value = cap + 1 [policy_denied]; value = 2^256 - 1 [policy_denied]; value = 2^256 (wraps to 0) [bad_request]; value = 2^256 + 5 [bad_request]; negative value [bad_request]; value in scientific notation [bad_request]; value with leading '+' [bad_request]; value with whitespace [bad_request]; value as float [bad_request]; fee: gas price 1000x cap [policy_denied]; fee: gas limit 30M [policy_denied]; fee: gas_limit*price overflows 2^256 [policy_denied]; priority fee above max fee [bad_request]; legacy: gas price over fee cap [policy_denied]; both gas_price and max_fee_per_gas [bad_request]; unknown transaction type 0x03 (blob) [bad_request]; gas limit below intrinsic 21000 [bad_request]. Control: value exactly at the cap signs. |
| C-03 | Cross-chain replay and unprotected transactions | compromised application server | Signatures are only produced for the wallet's chain ids, always with replay protection | PASS | 4 refused: chain id 1 (mainnet) on a Sepolia wallet [policy_denied]; chain id 0 (pre-EIP-155, valid on every chain) [bad_request]; chain id 2^64-1 [bad_request]; chain id missing [bad_request] |
| C-04 | ERC-20 abuse on a managed token | compromised application server | Only transfer(address,uint256) to an allow-listed recipient within the token caps | PASS | 16 refused: transfer to unlisted recipient [policy_denied]; transfer above token cap [policy_denied]; transfer of 2^256-1 [policy_denied]; approve(attacker, max) [policy_denied]; approve(listed address, 1) [policy_denied]; transferFrom [policy_denied]; transfer with trailing bytes [policy_denied]; transfer truncated by one byte [policy_denied]; transfer with dirty upper address bytes [policy_denied]; unknown selector [policy_denied]; selector only [policy_denied]; transfer carrying ether [policy_denied]; same calldata to an unmanaged contract [policy_denied]; calldata to the allow-listed EOA [policy_denied]; contract creation [policy_denied]; odd-length hex data [bad_request]. Control: transfer of exactly the token cap to the listed recipient signs. |
| C-05 | Blind signing | compromised application server | The HSM never signs a digest it did not compute from a decoded transaction | PASS | sign_digest on ethereum wallet [policy_denied]; sign_digest on bitcoin wallet [policy_denied]; eth_sign_message [policy_denied]; eth_sign_message with a Bitcoin wallet [bad_request]; btc_sign_transaction with an Ethereum wallet [bad_request]; eth_sign_transaction with a Bitcoin wallet [bad_request] |
| C-06 | Message signing cannot be turned into a transaction signature | compromised application server | With message signing enabled, the signed digest is domain-separated from every transaction digest | PASS | signature over a message that equals an unsigned transaction verifies only under the EIP-191 prefix (0x19 is not a valid RLP list or typed-transaction first byte); it does not authorise the transaction |
| C-07 | Daily limit: accumulation, restart and parallel requests | compromised application server | Total outflow (value + worst-case fee) per UTC day never exceeds the cap, including across a restart and under concurrency | PASS | cap 50000000000000000 wei/day: 3 signed, daemon restarted, 16 parallel requests raced for the remaining 2 -> exactly 2 signed, 14 refused; total debited 50000000000000000 wei; a further 1-wei transfer was refused (policy_denied) |
| C-08 | Bitcoin: outputs, fees and amounts | compromised application server | Every non-change output is allow-listed; amount, fee and fee-rate caps hold | PASS | 17 refused: output to unlisted address [policy_denied]; listed output plus a small unlisted one [policy_denied]; amount above cap [policy_denied]; cap split over two outputs to the listed address [policy_denied]; fee above max_fee (missing change output) [policy_denied]; fee rate above max_fee_rate [policy_denied]; outputs exceed inputs [bad_request]; mainnet address on a testnet wallet [bad_request]; address with a corrupted checksum [bad_request]; mixed-case bech32 [bad_request]; output amount 2^64 [bad_request]; negative output amount [bad_request]; input amount above 21M BTC [bad_request]; duplicate input [bad_request]; no inputs [bad_request]; raw script output field [bad_request]; sighash type field (SIGHASH_NONE) [bad_request]. Control: amount exactly at the cap, with change to the wallet, signs. |
| C-09 | Bitcoin: lying about input amounts to hide a fee | compromised application server | A signature made over a false input amount is invalid on the network (BIP-143 commits to the amount) | PASS | the HSM signed for the claimed 51,000 sat input; verified independently that the signature is valid only for that amount and invalid for the real 1,000,000 sat UTXO, so the network rejects the transaction and no fee is lost |
| C-10 | Frozen wallets and policy tampering by the signer | compromised application server | A signer cannot unfreeze, re-policy or create wallets; a frozen wallet signs nothing | PASS | one admin froze the wallet; signing refused (frozen); unfreeze by one admin refused (quorum_required); signer cannot unfreeze, set policy or create wallets; quorum unfreeze restores service |
| C-11 | Default policy is deny-all | administrator error | A wallet created without a policy cannot sign anything | PASS | wallets created with an empty policy refuse Ethereum, Bitcoin and raw-digest requests (policy_denied) |
| C-12 | Per-wallet signing rate | compromised application server | max_signatures_per_minute bounds how fast a stolen credential can sign | PASS | limit 5/minute: 12 requests -> 5 signed, 7 refused (policy_denied) |

### Suite D: Signed output

| ID | Test | Attacker | Expected control | Result | Evidence from this run |
| --- | --- | --- | --- | --- | --- |
| D-01 | Self-test of the independent verifier | none (test integrity) | The Python re-implementations reproduce published vectors before they are trusted to judge the node | PASS | Keccak-256, RIPEMD-160, RLP, EIP-155 hash and sender recovery, BIP-143 P2WPKH hash, BIP-173 decoding all reproduce their published vectors |
| D-02 | Ethereum EIP-1559 output | none (correctness) | The signed bytes decode to exactly the requested transaction and recover to the wallet address | PASS | raw_tx decodes to the requested fields; sender recovers to 0x3a6be849d39c67be2c17665fc1409525c893d42d; low-s; tx_hash and y_parity consistent |
| D-03 | Ethereum legacy (EIP-155) and ERC-20 output | none (correctness) | v encodes the chain id; calldata is preserved byte for byte | PASS | legacy v = 22310258 (EIP-155, chain 11155111), sender recovers; ERC-20 transfer calldata and target preserved exactly |
| D-04 | Bitcoin P2WPKH output | none (correctness) | Witness signatures verify under an independent BIP-143; strict DER, low-s, SIGHASH_ALL; txid and address are right | PASS | 2-input transaction: outpoints, outputs, locktime as requested; both witness signatures verify under independent BIP-143, strict DER, low-s, SIGHASH_ALL; txid and P2WPKH address re-derived |
| D-05 | Nonce reuse and bias through the API | passive observer of signed transactions | No two signatures share r; repeated signing of one transaction gives different, valid signatures | PASS | 120 signatures over 3 distinct transactions: 120 distinct r values (hedged RFC 6979), 101 distinct leading bytes |

### Suite E: Storage

| ID | Test | Attacker | Expected control | Result | Evidence from this run |
| --- | --- | --- | --- | --- | --- |
| E-01 | Stolen drive: search for key material at rest | thief with the NVMe drive or a backup | No secret is stored in the clear; what is stored opens only with the tamper secret inside the enclosure | PASS | 8 files searched for 7 secrets (raw and hex) and PEM keys: none; 358 32-byte values found on the disk tried as keys against the sealed KEK: none opens it; directory 0700, sealed files 0600 |
| E-02 | Stolen drive in the attacker's own enclosure | thief with the NVMe drive and identical hardware | The drive is useless without the original node's tamper secret | PASS | clone of the drive attached to a freshly provisioned enclosure: boot refused (openhsmd: sealed object does not open under this node's tamper secret) |
| E-03 | Offline edit of wallet policy and principals | root on the SoC normal world (node stopped) | Any change to the state file is detected at boot | PASS | policy raised -> openhsmd: INTEGRITY: state file does not match the hash anchored in the audit log (modified or rolled back); rogue admin + quorum 1 -> openhsmd: INTEGRITY: state file does not match the hash anchored in the audit log (modified or rolled back); wallet blobs swapped -> openhsmd: INTEGRITY: state file does not match the hash anchored in the audit log (modified or rolled back); one byte appended -> openhsmd: INTEGRITY: state file does not match the hash anchored in the audit log (modified or rolled back); unanchored state.json.new planted -> ignored, quorum still 2 |
| E-04 | Rollback of the whole drive to an earlier backup | root on the SoC normal world / backup operator | Restoring an old but internally consistent disk image (to reset spent limits or undo a freeze) is detected | PASS | disk image from before a spend and a wallet freeze restored: boot refused (openhsmd: INTEGRITY: audit log ends at entry 5 but the tamper supervisor's monotonic counter is 8. The log has) |
| E-05 | Audit log manipulation | root on the SoC normal world (node stopped) | Editing, deleting, reordering, truncating or forging entries is detected at boot and by offline verification | PASS | entry body edited: boot refused, offline verification fails; entry deleted from the middle: boot refused, offline verification fails; two entries swapped: boot refused, offline verification fails; last 2 entries truncated: boot refused (counter), offline check passes on the prefix -> compare the head with audit_head; forged entry appended (attacker's key): boot refused, offline verification fails; log replaced by an empty file: boot refused, offline verification fails |
| E-06 | Replacing the trusted CA on disk | root on the SoC normal world (node stopped) | The CA the node trusts for client certificates cannot be swapped by editing a file | PASS | tls/ca.crt replaced with the attacker's CA and the node restarted: the attacker's certificate is still rejected in the TLS handshake (SSLError) and legitimate clients are still served. The trust anchor is the copy inside the state file, whose hash is anchored in the audit chain (E-03). |

### Suite F: Physical events and ceremonies (simulated)

| ID | Test | Attacker | Expected control | Result | Evidence from this run |
| --- | --- | --- | --- | --- | --- |
| F-01 | Tamper response for every sensor | physical access to the chassis | Any sensor trip erases the tamper secret, wipes the signing module, stops the API and prevents a restart | PASS | sensors mesh, lid, light, accelerometer, voltage, temperature: each trip erased S in the supervisor, latched, made the API answer 'tamper', refused restart (also after a power cycle) and left a signed 'tamper' audit entry |
| F-02 | Power loss | physical access to the power feed | The KEK is volatile in the module; after power returns it is only recovered through the seal bound to the tamper secret | PASS | after a power cycle the module holds no KEK (status bit clear); the node unseals it at boot with the tamper secret and signs again |
| F-03 | Ceremony key-switch | administrator quorum acting remotely, or root on the SoC | With the physical switch off, no software path can move the KEK in or out of the module | PASS | switch off: kek_export (full quorum) -> ceremony_required, ceremony_split (full quorum) -> ceremony_required, rotate_export (full quorum) -> ceremony_required, kek_import -> ceremony_required. Switch on: one admin alone is still refused (quorum_required); the quorum can split. Moving the KEK needs a person at the node and a quorum of administrators. |
| F-04 | Entropy source failure | environmental attack on the TRNG | No key or IV is generated from a failed source; signing stays safe | PASS | entropy failure: wallet creation refused (signer_error); signing continued with the deterministic RFC 6979 nonce (safe without entropy); TRNG-failure status bit latched until the module is reset |
| F-05 | Fault injection during a signature, through the full stack | physical (voltage/clock glitch) | A corrupted signature never leaves the node | PASS | 20 faulted signing operations: 0 signatures released (error signer_error), 20 'sign_failed' audit entries, next signature valid |
| F-06 | Break-glass recovery with too few or wrong operator cards | fewer than m operators / stolen share records | The KEK is rebuilt only with m genuine cards; share records alone are useless | PASS | 2 cards -> bad_request; 2 genuine + 1 forged card -> signer_error; 3 genuine cards, one admin -> quorum_required; 3 genuine cards with quorum -> KEK restored, fingerprint equals the original, the recovered node signs for the same address |
| F-07 | Diverting the cluster KEK to rogue hardware | one rogue administrator, or a network attacker during enrolment | The KEK is exported only to an enrolment key that a quorum signed, and only that node can open the transfer | PASS | single admin -> quorum_required; enrolment key swapped inside a signed operation -> unauthenticated; off-curve enrolment key -> signer_error; captured transfer imported on another node -> signer_error; replay into the enrolled node -> signer_error; honest enrolment -> fingerprints match |
| F-08 | Memory dump of the SoC daemon | root on the SoC (normal and secure world) | The daemon's memory holds no wallet key, no KEK and no tamper secret | PASS | 7 MiB of openhsmd memory dumped after 5 signatures: tamper secret, module seal key, KEK and both wallet keys absent. Present, as designed: chan_key, soc_seal (the SoC's session keys; with them an attacker can request signatures while present, see R-1, but cannot take a key away) |

### Suite G: Source and build

| ID | Test | Attacker | Expected control | Result | Evidence from this run |
| --- | --- | --- | --- | --- | --- |
| G-01 | Memory-unsafe code | none (code review) | No `unsafe` in first-party code, enforced by the compiler in every crate | PASS | 30 source files: no `unsafe`; all 7 crate roots carry #![forbid(unsafe_code)] |
| G-02 | Compiler and linter findings | none (code review) | Clean under clippy with warnings denied | PASS | cargo clippy --workspace --all-targets -- -D warnings: clean |
| G-03 | Panics, integer overflow and error handling in the request path | network (denial of service by crashing the node) | Arithmetic is checked; request handling does not unwrap attacker-controlled values | PASS | overflow-checks = true and panic = abort in the release profile; 7 expect() sites in the node and signer libraries, all on the reviewed list as infallible by construction (HMAC key length, 32-byte GCM record, serialising own state, constant divisor, ASCII digits, 20-byte witness program); no unwrap()/panic! on request data |
| G-04 | Binary hardening | exploit developer | Release binaries are position-independent with non-executable stack and full RELRO | PASS | openhsmd: PIE, NX stack, full RELRO; hsmctl: PIE, NX stack, full RELRO |
| G-05 | Secrets and test fixtures in the source tree | anyone with repository access | No private keys or credentials are committed; simulator binaries cannot be reached from the network | PASS | no private key files in the tree; the bus simulator binds 127.0.0.1 only; the enclosure simulator uses owner-only Unix sockets |
| G-06 | Dependency inventory and known vulnerabilities | supply chain | Dependencies are pinned, few, permissively licensed and free of published advisories | PASS | 154 third-party crates, all from crates.io, pinned by Cargo.lock, no copyleft-only or unlicensed crate; cargo audit (1446 advisories, database of 2026-11-10): 0 vulnerabilities, 0 warnings |
| G-07 | Static analysis of the Python tooling | none (code review) | No medium or high severity findings in the host tools and test harness | PASS | bandit (medium and high severity) over pentest/ and FPGA/: no findings |
<!-- RESULTS:END -->
