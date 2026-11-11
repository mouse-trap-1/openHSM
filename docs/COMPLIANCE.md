# OpenHSM Compliance Mapping

Version 0.5.0, prepared 11 November 2026.

**OpenHSM is not certified, validated or assessed against any standard or regulation.** This document maps the prototype's design to the requirements a custody HSM is usually measured against, says honestly where each stands, and lists what a deployer would still have to do. It is an engineering aid, not legal advice; regulatory dates below were checked against public sources on the date above (listed at the end) and will change.

Status words used throughout:

| Status | Meaning |
| --- | --- |
| Met in software | Implemented and covered by a test in this repository |
| Design only | Specified, or implemented in a model of hardware that does not exist yet |
| Partial | Some of the requirement is implemented; the gap is stated |
| Not met | Not addressed in 0.5.0 |
| Deployer | Depends on the organisation operating the HSM, not on the product |

## 1. Which rules apply to whom

| Rule | Applies to | Relevance to OpenHSM |
| --- | --- | --- |
| FIPS 140-3 / ISO/IEC 19790 | Cryptographic modules sold to US federal users; widely demanded by insurers and auditors | The reference for module design. The signing module is designed toward Level 3 physical and logical requirements |
| Common Criteria, EN 419221-5 | HSMs used as trust-service or signature devices in the EU | The usual protection profile for an HSM; relevant if a certificate is ever sought under the EU scheme (EUCC) |
| EU Cyber Resilience Act (Regulation (EU) 2024/2847) | Manufacturers placing products with digital elements on the EU market; lighter duties for open-source stewards | An HSM is a critical product (Annex IV: hardware devices with security boxes). Applies to whoever sells devices built from this design, not to non-commercial publication of the source |
| MiCA (Regulation (EU) 2023/1114) and DORA (Regulation (EU) 2022/2554) | Crypto-asset service providers in the EU, including custodians | Apply to the operator. The HSM supplies controls and evidence they need |
| UK cryptoasset regime (FSMA 2000, FCA rules) | Firms safeguarding qualifying cryptoassets in the UK | Applies to the operator |
| CCSS (CryptoCurrency Security Standard) | Voluntary; commonly used to audit custody systems | The most direct checklist for key generation, storage, usage and audit of wallet keys |
| NIST SP 800-57, 800-90A/B/C, 800-131A, 800-186, FIPS 186-5, FIPS 197, FIPS 198-1 | Algorithm and key-management guidance behind FIPS 140-3 | Algorithm choices are checked against these in section 2.2 |
| Export control (EU 2021/821 Annex I Cat. 5 Part 2, UK and US equivalents) | Anyone exporting cryptographic hardware or software | Published open-source cryptography is generally treated more lightly than hardware; shipping devices is a different matter. Take advice before exporting hardware |
| GDPR / UK GDPR | Operators | The audit log contains principal names and certificate fingerprints; these are personal data if they identify individuals |

## 2. FIPS 140-3 (ISO/IEC 19790:2012)

Target: the signing module plus supervisor as the cryptographic module, Level 3. The SoC is outside the boundary.

### 2.1 Requirement areas

| Area | Level 3 expectation | OpenHSM | Status |
| --- | --- | --- | --- |
| Module specification | Defined boundary, approved mode | Boundary is the tamper enclosure; one mode of operation | Design only |
| Interfaces | Logically separated data, control, status; trusted channel for unprotected CSPs | I2C register map separates them; commands and responses are MACed (X1); card secrets masked on the bus (X5) | Design only |
| Roles, services, authentication | Identity-based authentication | The module authenticates one host by MAC. Identity-based authentication of operators is done by the SoC (Ed25519 + client certificate, roles, quorum) | Partial: operator identity is outside the boundary |
| Software/firmware security | Approved integrity check on load | Bitstream authentication is an integration requirement; nothing implemented | Not met |
| Operational environment | Non-modifiable or limited | FPGA with no soft CPU; SoC out of boundary | Design only |
| Physical security | Tamper detection and response with zeroisation; hard opaque enclosure | Mesh, lid, light, accelerometer, voltage and temperature sensors; asynchronous wipe; potting | Design only; logic tested in simulation (tests A-18, F-01) |
| Non-invasive security | Mitigation of side channels (Annex F methods) | Constant-time ladder in RTL; no blinding or masking | Not met |
| Sensitive security parameter management | Approved generation, establishment, entry/output encrypted, zeroisation | TRNG-based generation; keys leave only wrapped (AES-GCM, ECIES) or as split knowledge; zeroise on tamper, power loss, `KEK_ERASE` | Design only; see 2.2 |
| Self-tests | Pre-operational integrity and conditional algorithm tests; entropy health tests | Repetition-count and adaptive-proportion tests latch a failure (tests A-17, F-04); verify-before-release on every signature (X3). No power-up known-answer tests | Partial |
| Life-cycle assurance | Configuration management, design documentation, vendor testing, guidance | Git history, this documentation set, unit and penetration tests, `SECURITY.md` | Partial |
| Mitigation of other attacks | Documented | Fault attacks: verify-before-release, tested in simulation (A-16, F-05) | Design only |

### 2.2 Algorithms

| Function | Algorithm | Standard | FIPS position |
| --- | --- | --- | --- |
| Wrapping | AES-256-GCM | FIPS 197, SP 800-38D | Approved. Random 96-bit IVs require a per-key limit; the node enforces 2^31 wraps per KEK, below the SP 800-38D bound of 2^32 |
| MAC, KDF | HMAC-SHA-256 | FIPS 198-1, FIPS 180-4 | Approved as a MAC. The one-step HMAC key derivations are not laid out as SP 800-108 or SP 800-56C constructions and would need restating |
| Signature | ECDSA over secp256k1, hedged deterministic nonce | FIPS 186-5 includes deterministic ECDSA (the hedged variant adds fresh entropy to it); SP 800-186 lists the recommended curves | **secp256k1 is not a NIST-recommended curve.** Commercial HSMs disable it in their FIPS Level 3 mode. Whether it can be claimed as an allowed, non-approved algorithm for blockchain use has to be settled with a CMVP laboratory against the current Implementation Guidance |
| Key transfer | ECIES on secp256k1 | SP 800-56A patterns | Not approved as specified (curve, KDF). Could be re-specified on P-256 with a one-step KDF without changing the architecture |
| Break-glass | Shamir split | Split knowledge procedure | Acceptable as a procedure; card secret derives from HMAC-SHA-1, which NIST still permits for HMAC but plans to retire by 2030 |
| Random numbers | Ring-oscillator TRNG, von Neumann debiasing, health tests; HMAC conditioning | SP 800-90B, 90A, 90C | Entropy source needs a 90B assessment on silicon; the conditioning chain is not an approved 90A DRBG |
| Ed25519, TLS 1.3, Keccak-256, RIPEMD-160 | On the SoC | Outside the module boundary | Ed25519 is approved in FIPS 186-5; Keccak-256 and RIPEMD-160 are not, and are needed by the chains |

An honest summary: a FIPS 140-3 validation of a secp256k1 signer is possible only with the signature algorithm outside the approved set, and would need the KDFs, the DRBG and the key-transfer scheme re-specified. None of that changes the architecture.

## 3. Common Criteria (EN 419221-5 as reference)

| Objective in the protection profile | OpenHSM | Status |
| --- | --- | --- |
| Keys protected inside the device, exported only wrapped | Wallet keys only as blobs under the KEK; KEK only by ECIES or shares | Met in the model (A-07, A-09, E-01) |
| Authorisation required for key use | Per-request signer authentication plus policy on the SoC | Met in software; outside the module boundary |
| Dual control for sensitive administration | Admin quorum; physical ceremony switch for KEK movement | Met in software (B-04, F-03) |
| Audit records generated and protected | Signed hash chain with rollback anchor | Met in software (E-03 to E-05) |
| Secure backup and restore | Wrapped snapshots; m-of-n cards | Met in software (F-06) |
| Tamper detection and response | Sensors and wipe | Design only |
| Random number quality | TRNG with health tests | Design only |
| Evaluation evidence (ADV, ATE, AVA) | Design, specification, tests, simulated penetration test | Partial; no evaluator |

## 4. EU Cyber Resilience Act

| Question | Answer |
| --- | --- |
| Is the source code in scope? | Free and open-source software that is not made available in the course of a commercial activity is outside the regulation. Accepting donations does not change that. An organisation that sustains the project for commercial use by others would be an open-source steward with lighter duties (a security policy, cooperation with authorities, limited reporting) |
| Is a device built and sold from it in scope? | Yes. The seller is the manufacturer and carries the full obligations |
| Which class? | Critical (Annex IV): "Hardware Devices with Security Boxes", and devices "for secure cryptoprocessing". The route is a European cybersecurity certificate where a scheme is mandated, otherwise third-party assessment (module B+C or H) |
| What applies when? | Reporting of actively exploited vulnerabilities and severe incidents has applied since 11 September 2026 (24 h early warning, 72 h notification, final report, via ENISA's single reporting platform). All other obligations apply from 11 December 2027 |

Annex I essential requirements against the prototype:

| Requirement (Annex I, Part I) | OpenHSM | Status |
| --- | --- | --- |
| No known exploitable vulnerabilities at release | `cargo audit` in CI and in the penetration tests (G-06) | Met in software |
| Secure by default | Policies deny by default; TLS 1.3 only; no default credentials; simulators bind to loopback or owner-only sockets | Met in software (C-11, B-01, G-05) |
| Protection from unauthorised access | Mutual TLS, signed requests, roles, quorum | Met in software (suite B) |
| Confidentiality and integrity of data at rest and in transit | Wrapped keys, sealed secrets, anchored state | Met in software (suite E) |
| Data minimisation | State and audit log hold identifiers, public keys and transaction metadata only | Met in software |
| Availability and resilience against denial of service | Connection caps, deadlines, rate limits; no cluster failover | Partial (B-06 to B-08; R-3, R-10) |
| Limit attack surface | One port, one framing, encode-only transaction handling, no `unsafe` | Met in software (G-01) |
| Logging of security events | Signed audit chain | Met in software |
| Secure updates | No update mechanism is defined | Not met |

| Requirement (Annex I, Part II: vulnerability handling) | OpenHSM | Status |
| --- | --- | --- |
| Software bill of materials | `Cargo.lock` pins every dependency; the CI workflow has a CycloneDX SBOM step | Met in software (workflow not yet run on GitHub) |
| Address vulnerabilities without delay; regular testing | `cargo audit`, clippy, unit tests and the penetration suite are steps of the CI workflow | Met in software |
| Coordinated vulnerability disclosure policy and contact | [`SECURITY.md`](../SECURITY.md) | Met; the reporting address must be filled in by the maintainers |
| Secure distribution of updates; advisories | Not defined | Not met |
| Support period, technical documentation, EU declaration of conformity, CE marking | Manufacturer duties | Deployer |

## 5. MiCA and DORA (operator obligations)

MiCA's transitional period ended on 1 July 2026; custodians serving EU clients need authorisation. In July 2026 ESMA began a common supervisory action on custody that looks at governance, key and storage management, transaction controls, incident detection and response, and reliance on third-party technology. DORA has applied since 17 January 2025 and governs their ICT risk management.

| Obligation on the custodian | What OpenHSM contributes | Status |
| --- | --- | --- |
| Custody policy with internal rules for safekeeping and control of the means of access to crypto-assets (MiCA Art. 75) | Keys generated and kept inside the module; quorum and physical presence for the KEK; documented ceremonies | Met in software; Deployer writes the policy |
| Minimise the risk of loss of clients' crypto-assets or of the means of access (Art. 75) | Wrapped replicas on every node; m-of-n operator cards; KEK rotation | Met in software (F-06); cluster replication is manual |
| Segregation of client holdings | One wallet key per wallet id; blobs bound to their id | Met in software; on-chain segregation is the Deployer's design |
| Register of positions and prompt return of assets | Not an HSM function; the audit log records every signature with wallet, amount and transaction hash | Deployer |
| ICT risk management, protection and prevention (DORA Art. 6 to 9) | Threat model, design and specification; strong authentication; least privilege by role; cryptographic key lifecycle | Partial; Deployer's framework |
| Detection (Art. 10) | Audit events for denials, failed authentication, tamper | Met in software |
| Response, recovery, backup (Art. 11, 12) | Tamper response; restore from cards; snapshot import | Partial (R-10) |
| Incident classification and reporting (Art. 17 to 19) | Signed, time-stamped evidence | Deployer |
| Digital operational resilience testing, including threat-led penetration tests for significant entities (Art. 24 to 26) | Repeatable attack suite in `pentest/` | Partial; a simulated test is not a TLPT |
| ICT third-party risk (Art. 28 to 30) | Open design, reproducible build from pinned dependencies, SBOM | Deployer |

## 6. United Kingdom

The FCA published final rules for the new cryptoasset regime on 30 June 2026. Safeguarding qualifying cryptoassets becomes a regulated activity when the regime commences on 25 October 2027; the authorisation gateway opened on 30 September 2026 and the application window that carries transitional protection closes on 28 February 2027. Custodians face specific safeguarding requirements and the FCA's operational-resilience expectations (outages, cyber security, outsourced technology, incident management, continuity and recovery).

The contribution of the HSM is the same as in section 5: key control, dual control, evidence, recovery. The gaps are also the same: no hardware, no failover.

## 7. CryptoCurrency Security Standard (CCSS), by aspect

| Aspect | Expectation at the higher levels | OpenHSM | Status |
| --- | --- | --- | --- |
| Key/seed generation | Generated on the device that uses it, from a validated entropy source, never seen by people | On-module TRNG generation; no export in the clear | Design only (entropy unvalidated) |
| Wallet creation | Unique key per wallet; multi-party authorisation | Independent key per wallet; quorum `wallet_create` | Met in software |
| Key storage | Encrypted at rest; backups in separate locations with access control | AES-GCM blobs; sealed KEK per node; shares on cards held by different operators | Met in software |
| Key usage | Authenticated, authorised, policy-checked use in a trusted environment; destination and amount verified | Signed requests, allow-lists, caps, daily limits, no blind signing by default | Met in software (suite C); environment is Design only |
| Key compromise protocol | Documented, tested procedure | Freeze by one admin, KEK rotation, tamper response; no written runbook | Partial |
| Keyholder grant/revoke | Documented, audited | Quorum `principal_add` / `principal_remove`, audited | Met in software |
| Third-party security audits | Regular, independent | None yet | Not met |
| Data sanitisation | Keys destroyed on decommission | `kek_erase`; tamper wipe | Design only |
| Proof of reserve | Not an HSM function | n/a | Deployer |
| Audit logs | Complete, tamper-evident, retained | Signed hash chain, offline verification | Met in software |

## 8. Gaps to close before any compliance claim, in order

1. Build the hardware and repeat the physical tests on it (FIPS physical security, non-invasive security; CC AVA).
2. Obtain an independent security review and penetration test.
3. Decide the FIPS position on secp256k1 with a laboratory; re-specify KDFs, DRBG and key transfer on approved constructions.
4. Add power-up self-tests and bitstream authentication to the module.
5. Define the update and vulnerability-advisory process (CRA Part II), fill in the disclosure contact, and set a support period.
6. Implement cluster replication and failover (availability requirements in every regime).
7. Write the operator runbooks: key ceremonies, compromise response, decommissioning.

## Sources checked on 11 November 2026

- [Travers Smith: CRA vulnerability and incident reporting requirements are now live](https://www.traverssmith.com/knowledge/knowledge-container/the-eu-cyber-resilience-acts-vulnerability-and-incident-reporting-requirements-are-now-live/)
- [CMS: CRA scope, definitions and product classification](https://cms.law/en/int/legal-updates/does-the-eu-cyber-resilience-act-apply-to-your-product-scope-definitions-and-the-product-classification-system-explained)
- [CRA Annex IV text (Springlex, unofficial consolidation)](https://www.springlex.eu/en/packages/cra/cra-regulation/annex-4/)
- [Coinpaprika: ESMA custody review as the MiCA transition ends](https://coinpaprika.com/news/eu-regulator-crypto-custody-mica-transition/)
- [Morrison Foerster: UK crypto regulation underway](https://www.mofo.com/resources/insights/261012-uk-crypto-regulation-underway)
- [NIST SP 800-186](https://csrc.nist.gov/pubs/sp/800/186/final)
- [Corsec: FIPS 186-5 and its impact on FIPS 140-3](https://corsec.com/fips-186-5)
- [Entrust nShield: algorithm support and FIPS Level 3 restrictions](https://nshielddocs.entrust.com/app-notes/crypto-support/intro.html)
- [RustSec advisory RUSTSEC-2026-0387](https://github.com/RustCrypto/crypto-bigint/pull/1365)
