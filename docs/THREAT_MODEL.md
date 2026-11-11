# OpenHSM Threat Model

Version 0.5.0. This is the model the [penetration tests](PENETRATION_TEST_REPORT.md) are written against. Each attacker below has a test suite; each residual risk has an identifier used across the documents.

## 1. Assets

| Asset | Why it matters | Where it lives |
| --- | --- | --- |
| Wallet private keys | Whoever holds one controls the funds | Only inside the signing module, for the duration of one command; otherwise AES-GCM blobs |
| Cluster KEK | Opens every wallet blob | Module volatile registers; sealed copy per node; card-wrapped shares |
| Tamper secret S | Roots the channel and seal keys of one node | Tamper supervisor, battery-backed |
| Signing authority | A valid signature moves funds even if no key leaks | The policy engine and the credentials that reach it |
| Policy, principals, quorum | Decide who may sign what | `state.json`, anchored in the audit chain |
| Audit log | Evidence for operators, auditors and regulators | `audit.log`, signed and chained |
| Availability | A stopped HSM stops withdrawals | Cluster redundancy (not in this prototype) |

## 2. Attackers and what they are assumed to have

| ID | Attacker | Capabilities | Suite |
| --- | --- | --- | --- |
| T1 | Network attacker | Reaches the API port; no credential | B |
| T2 | Compromised application server | A genuine signer key and certificate | C |
| T3 | Single rogue or phished administrator | One admin key and certificate | B, F |
| T4 | Thief or backup operator | The NVMe drive or any copy of it | E |
| T5 | Root on the SoC normal world | Reads and rewrites every file; restarts the daemon | E |
| T6 | Full SoC compromise | Everything the SoC holds, including the channel key | A (host tests), F-08 |
| T7 | Device on the I2C bus | Reads and injects bus traffic; no channel key | A |
| T8 | Physical attacker at the chassis | Opens, probes, glitches, removes power | A, F (logic only) |
| T9 | Fewer than m operators | Up to m−1 cards and all share records | F |
| T10 | Supply chain | A malicious or vulnerable dependency | G |

Out of scope for this version: an admin quorum acting together with physical access to a node (they are the owners of the system); invasive attacks on the FPGA or supervisor silicon; side-channel and fault attacks on real hardware, which cannot be evaluated on a model.

## 3. Security objectives

| # | Objective | Holds against |
| --- | --- | --- |
| O1 | No wallet key and no KEK leaves a signing module in the clear | T1 to T7, T9 |
| O2 | Nothing is signed outside the wallet's policy | T1 to T5 |
| O3 | Policy, principals and the KEK change only with an admin quorum; the KEK moves only with physical presence as well | T1 to T6 |
| O4 | Tamper destroys the node's ability to use or recover keys | T8 (logic verified; hardware not) |
| O5 | Every signature and every administrative act is recorded in a log that cannot be silently edited, truncated or rolled back | T1 to T5 |
| O6 | A captured request, response, blob or ceremony transcript is useless later or elsewhere | T1, T4, T7 |
| O7 | Malformed or hostile input cannot crash or stall the node for other users | T1, T2 |

O2 does not hold against T6. That is residual risk R-1.

## 4. Residual risks

| ID | Risk | Why it remains | Mitigation today | Path to closing it |
| --- | --- | --- | --- | --- |
| R-1 | A full SoC compromise can ask the module to sign any digest with any wallet blob, and can erase the KEK | The module signs digests; policy lives on the SoC (decision D1) | Secure boot and OP-TEE on the real board; audit chain and supervisor counter make it detectable afterwards; KEK itself still cannot be taken | Move a minimal policy check or a per-request operator co-signature into the module; or sign the request inside OP-TEE with a key the normal world cannot use |
| R-2 | A device on the I2C bus can lock the module's command channel with 8 bad MACs | The lockout that stops guessing is itself a denial of service | Bus is inside the enclosure; reset recovers | Rate-limit instead of locking; alert on lock |
| R-3 | A client sharing an attacker's source address can be refused connections during a flood | The connection cap is per address | Other addresses are unaffected; handshake deadline frees slots in 5 s | Per-certificate accounting after the handshake |
| R-4 | Offline verification of a copied audit log cannot see that its tail was cut | A valid prefix is a valid chain | The node itself detects it by the counter; auditors compare with `audit_head` | Periodic signed checkpoints sent to an external witness |
| R-5 | During a split or restore ceremony the SoC sees each card-derived secret | The card cannot talk to the module directly | Ceremony switch, quorum, run ceremonies on a trusted node; the bus no longer exposes it (X5) | Front-panel reader wired to the module; or PIV key agreement on the card |
| R-6 | Side channels, fault injection, real entropy quality, physical tamper effectiveness are untested | There is no hardware | Constant-time arithmetic library; verify-before-release; health tests | Synthesis, lab evaluation (see FPGA specification section 12) |
| R-7 | Daily limits follow the SoC clock, which only moves forward | The node has no trusted time source | Requires T5/T6; the jump is visible in the audit timestamps | Supervisor real-time clock in the battery domain |
| R-8 | One KEK protects every wallet | Keeps the module stateless | Export needs quorum and physical presence; rotation exists | Per-partition KEKs |
| R-9 | Principal keys are files on operator machines in this prototype | No hardware token integration yet | File mode 0600; quorum for anything sensitive | YubiKey PIV for admin request signing and TLS |
| R-10 | No automatic replication or failover | Raft is not implemented | Manual snapshot export and import | Implement the cluster layer described in the README |
