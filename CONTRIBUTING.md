# Contributing to OpenHSM

Thank you for looking. This is security-critical code in an early state; careful review is worth more than volume.

## Before you start

- Read [`docs/SYSTEM_DESIGN.md`](docs/SYSTEM_DESIGN.md) and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). Changes are judged against the security objectives there.
- Security problems go through [`SECURITY.md`](SECURITY.md), not public issues.
- For anything larger than a fix, open an issue first and describe the change and its security impact.

## Building and testing

```bash
cargo build --release          # Rust 1.87 or later
make lint test                 # rustfmt, clippy with warnings denied, unit and integration tests
make pentest                   # 68 simulated attacks against the release binaries; needs python3, `cryptography`
scripts/demo.sh                # full lifecycle on three local nodes
```

The RTL tests are described in [`FPGA/README.md`](FPGA/README.md).

## Rules for changes

1. **No `unsafe`.** Every crate forbids it.
2. **No new panic sites on request paths.** Test G-03 keeps a reviewed list; a new `unwrap`, `expect` or `panic!` in library code fails it until it is justified and listed.
3. **Secrets are `Zeroizing`, never logged, never `Debug`-printed, and compared in constant time.**
4. **Fail closed.** A new option defaults to the restrictive value; a new policy field defaults to "deny".
5. **Encode, do not parse**, on the signing path. If a parser is unavoidable, it needs vectors and a fuzz target.
6. **Every security-relevant change comes with a test that would have caught its absence**, preferably an attack in `pentest/suites/`.
7. **Protocol changes** to the signing module must be made in the model and specified for the RTL in the same pull request, with the version byte bumped.
8. **Dependencies**: prefer none. A new crate needs a reason in the pull request, a permissive licence and a clean `cargo audit`.
9. **Documents move with the code.** Update the specification and design documents, and add a line to `CHANGELOG.md`.

## Commits and review

Small commits with a message that says why. Sign your commits if you can (`git commit -S`). Every change to `openhsm-signer`, `policy.rs`, `api.rs`, `audit.rs` or `secure.rs` needs review by someone other than the author.

By contributing you agree that your contribution is licensed under the Apache License 2.0, the licence of this repository.
