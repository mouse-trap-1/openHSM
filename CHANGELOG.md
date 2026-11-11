# Changelog

All notable changes to the OpenHSM prototype. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The FPGA design is versioned separately under `FPGA/`.

## [0.5.0] - 2026-11-11

First system-level prototype: the whole signing node in software.

### Added
- `openhsm-signer`: register-level model of the FPGA signing module (protocol 0xB1), driven unchanged by `FPGA/V0.4/sn_host.py`.
- Protocol 0xB2 extensions: X1 response MAC, X2 lockout after 8 failed authentications, X3 verify-before-release, X4 buffer hygiene, X5 confidential card secret, X6 ceremony key-switch.
- `openhsm-hw`: tamper supervisor model with derived SoC keys, monotonic counter and ceremony switch; enclosure as a separate process (`openhsm-hwsim`).
- `openhsm-node` (`openhsmd`): TLS 1.3 API with signed requests, roles and admin quorum; Ethereum (EIP-1559, EIP-155, ERC-20 transfer, optional EIP-191) and Bitcoin (P2WPKH) signing; deny-by-default wallet policy with daily limits; signed, hash-chained audit log anchored against rollback.
- `hsmctl`: PKI, identities, genesis, quorum propose/approve/submit, offline audit verification, software operator cards.
- KEK lifecycle through the API: generate, seal, ECIES enrolment, split to operator cards, break-glass restore, rotation.
- `pentest/`: 68 simulated attacks in 7 suites, with independent verification code.
- Documentation: system design, system specification, threat model, penetration test report, compliance mapping.
- Project files: `SECURITY.md`, `CONTRIBUTING.md`, CI workflow, Dependabot, `Makefile`.

### Security
- Upgraded `k256` 0.13 → 0.14 (`crypto-bigint` 0.7.11) for RUSTSEC-2026-0387 (PT-04).
- Offline audit verification rejects an empty log or one without `node_init` (PT-05).
- Removed unmaintained `rustls-pemfile` (PT-06).

### Known limitations
- No hardware: physical security, side channels and entropy are untested.
- A full SoC compromise can request arbitrary signatures (R-1).
- No Raft replication or failover; replication is by signed snapshot.
