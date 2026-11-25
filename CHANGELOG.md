# Changelog

All notable changes to the OpenHSM prototype. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The FPGA design is versioned separately under `FPGA/`.

## [Unreleased]

### Added
- `docs/POST_QUANTUM.md`: impact of the Ethereum Foundation's move to hash-based signatures (23 November 2026) on each part of OpenHSM, changes made, KEK-transfer and stateful-key designs, order of work.
- `FPGA/V0.6`, protocol 0xB3: SPI host link (`spi_host_slave.v`, mode 0, up to 12.5 MHz) in place of I2C; registers, commands and MACs unchanged. Unit test `tb_spi_host_slave.v`; system testbenches moved to SPI.
- `FPGA/V0.6/keccak256_core.v`: Keccak-256 (Keccak-f[1600], one round per clock), standalone, with `tb_keccak.v` and `gen_keccak_vectors.py` (reference checked against hashlib SHA3 and Ethereum vectors).
- `FPGA/V0.6/sn_host.py`: `SpidevBus` transport for Linux spidev.
- Hybrid post-quantum TLS: X25519MLKEM768 on the API and cluster links. OpenHSM clients offer only the hybrid group; the listener also accepts X25519 for third-party clients. Test `crates/openhsm-node/tests/pq_tls.rs`.
- Threat model T11 (future quantum adversary), residual risks R-11 and R-12; design decision D11; compliance section 2.3 (FIPS 203/204/205, SP 800-208 export rule).
- `FPGA/V0.5`: protocol 0xB2 in the RTL. Response MAC (X1), lockout after 8 failed authentications (X2), verify-before-release (X3), buffer hygiene (X4), confidential card secret (X5), ceremony pin (X6), and a randomised projective start point for every scalar multiplication. New testbench `tb_v05.v` with injected signing faults, and independent checker `verify_v05.py`.
- `FPGA/V0.5/sn_host.py` checks response MACs, masks card secrets and takes the channel key instead of the tamper secret.
- `FPGA/V0.5/refmodel.py` and `gen_vectors.py` replace generators that were missing from the repository.
- `docs/INTERFACE_CONTROL_DOCUMENT.md`.

### Changed
- `FPGA/README.md` now specifies V0.6, protocol 0xB3 (it specified 0xB2 before).
- Carrier schematic draft 0.2: SoC to FPGA link is SPI (ECSPI) with 33 Ω source termination, CS pull-up and MISO pull-down; I2C pull-ups removed. `check.py` verifies the new nets.
- `rustls` uses the `aws-lc-rs` provider (needed for ML-KEM); the build now needs a C compiler for `aws-lc-sys`.
- The signer model reports protocol 0xB3; I2C wording in the crates is now bus-neutral.
- Interface control document: IF-02 and the worked SPI transactions (section 14.2.1).
- Design, specification, interface and penetration-test documents updated for the RTL back-port.

### Known issues
- First synthesis of the RTL (generic Yosys flow, V0.6): about 88,800 LUTs and 38,800 flip-flops, roughly 2.7 times the LUTs of the XC7A50T on the carrier. Over 60% is the sequencer's parallel multiplexing. Vivado synthesis and an area reduction come before any new RTL block (`docs/POST_QUANTUM.md` section 8).

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
- Documentation: system design, system specification, interface control document, threat model, penetration test report, compliance mapping.
- Project files: `SECURITY.md`, `CONTRIBUTING.md`, CI workflow, Dependabot, `Makefile`.

### Security
- Upgraded `k256` 0.13 → 0.14 (`crypto-bigint` 0.7.11) for RUSTSEC-2026-0387 (PT-04).
- Offline audit verification rejects an empty log or one without `node_init` (PT-05).
- Removed unmaintained `rustls-pemfile` (PT-06).

### Known limitations
- No hardware: physical security, side channels and entropy are untested.
- A full SoC compromise can request arbitrary signatures (R-1).
- No Raft replication or failover; replication is by signed snapshot.
