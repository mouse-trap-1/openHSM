# openhsm-signer

Software model of the OpenHSM **secp256k1 signing module**, the FPGA design in
[`FPGA/V0.4/sign_node_top.v`](../../FPGA). It is the innermost layer of the
system: the only component that ever holds a wallet private key.

| | |
|---|---|
| Kind | Library (`openhsm_signer`) and test-fixture binary (`openhsm-signer-sim`) |
| Depends on | No other workspace crate |
| Used by | [`openhsm-hw`](../openhsm-hw) (wraps it in an enclosure), [`openhsm-node`](../openhsm-node) (command, register and label constants) |
| `unsafe` | Forbidden (`#![forbid(unsafe_code)]`) |

## What it does

The crate reproduces the module at **register level**, not as a Rust-style API.
A host talks to it exactly as it would talk to the FPGA: I2C register reads and
writes (`Signer::bus_write` / `bus_read`), an SPI frame from the tamper
supervisor (`Signer::spi_frame`), and two input pins (`set_tamper`,
`set_ceremony_enable`). A host driver written for the FPGA (for example
`FPGA/V0.4/sn_host.py`) drives the model unchanged.

Behaviour modelled:

- **Authenticated command channel.** Every command carries a MAC under a
  channel key derived from the tamper secret `S`, with a counter and a nonce.
- **Volatile secret store.** Channel key, seal key, KEK, incoming KEK, and
  enrolment key live only in RAM and are cleared by reset or tamper.
- **KEK lifecycle.** Generate, seal to `S`, unseal, erase, fingerprint, and a
  two-phase rotation (`KEK_NEW_*`, `REWRAP`, `KEK_PROMOTE`).
- **Wallet keys.** `GEN_WALLET` creates a key and returns it only as an
  AES-256-GCM blob under the KEK (AAD = wallet id). `SIGN` unwraps it, signs
  with deterministic ECDSA (RFC 6979) over a supplied 32-byte digest, and
  discards it. `PUBKEY` returns the public key.
- **Cluster KEK transfer.** ECIES export and import so a second node can be
  enrolled without the KEK ever appearing in the clear.
- **Break-glass recovery.** `(m, n)` Shamir splitting of the KEK
  (`shamir.rs`, GF(2^8), constant-time) and restore from operator-card shares.
- **Asynchronous tamper wipe.** The tamper pin clears all secrets at once.

### Hardening beyond protocol 0xB1

The model reports protocol version **0xB2** and implements the open hardening
items of the FPGA specification, intended for back-porting to the RTL:

| Ext. | Feature |
|---|---|
| X1 | Response MAC in register `RMAC` (0xC4) |
| X2 | Lockout after 8 consecutive failed authentications |
| X3 | Verify-before-release: each signature is checked against the recomputed public key before it reaches the buffers |
| X4 | Buffer hygiene: buffers cleared on error, command MAC cleared after each command |
| X5 | Card secret XOR-masked on the bus (`SHARE_GET_C` / `SHARE_PUT_C`) |
| X6 | Ceremony switch: a physical pin gates every command that can move a KEK in or out |

It is **functional, not cycle-accurate**: commands complete inside the bus
write that starts them, so `STATUS.busy` is never observed.

## Source layout

| File | Role |
|---|---|
| `src/lib.rs` | `Signer` state machine; register map (`reg`), commands (`cmd`), error codes (`err`), status bits (`status`), domain-separation labels (`label`), `VERSION`, `MAX_AUTH_FAILURES` |
| `src/crypto.rs` | HMAC-SHA256, AES-256-GCM seal/open of 32-byte records, RFC 6979 nonces, ECDSA sign/verify, point checks. Built on `k256` (constant-time scalar ops) |
| `src/entropy.rs` | `EntropySource` trait; `OsEntropy` (OS CSPRNG) and `SimEntropy` (deterministic, for tests). `HealthTests` runs the SP 800-90B repetition-count and adaptive-proportion tests so a stuck source latches the TRNG-failure flag as the hardware TRNG would |
| `src/shamir.rs` | Byte-wise Shamir sharing, 32 lanes, matching `shamir_core.v` |
| `src/bin/openhsm-signer-sim.rs` | Bus-level simulator over a loopback TCP socket |
| `tests/protocol.rs` | Register-level tests written as a host would drive the FPGA |

## How it plugs into the larger system

```text
 openhsm-node (SoC secure world)
        │  Hardware trait (I2C-style bus_write / bus_read)
        ▼
 openhsm-hw  Enclosure ──► Signer  ◄── SPI frame 0xA5‖S ── tamper-supervisor model
                             ▲
                  tamper pin, ceremony pin
```

- **Instantiated by `openhsm-hw`.** `Enclosure` owns one `Signer` alongside a
  tamper-supervisor model and wires the pins and the SPI link between them. The
  node never links the `Signer` directly into its own address space when run
  with `--hardware unix:PATH`.
- **Shared vocabulary with `openhsm-node`.** The node's `secure.rs` is the Rust
  equivalent of the reference host driver. It imports `reg`, `cmd`, `err`,
  `status`, `label`, plus `crypto::{hmac256, ct_eq}`, so both sides derive
  channel keys, labels and MACs identically.
- **Trust boundary.** Everything above this crate treats it as a black box
  that signs digests and returns wrapped keys. Policy, transaction parsing and
  auditing happen in `openhsm-node`; the module signs whatever digest an
  authenticated caller supplies.
- **Maps to real hardware.** In production this crate is replaced by the FPGA
  itself; the register map is the contract the board driver must honour.

## The `openhsm-signer-sim` binary

Exposes the module's pins on `127.0.0.1` (default port 7700, `--port N`) so
tools written for the FPGA, such as the Python host driver and the attack
scripts in [`pentest/`](../../pentest), run against the model.

```text
request : op(1) arg(1) len(2, BE) data(len)
response: len(2, BE) data(len)

0x01 I2C write   0x02 I2C read   0x10 SPI frame   0x11 tamper pin
0x12 reset       0x13 TRNG fault 0x14 glitch next signature   0x15 ceremony pin
```

**Test fixture only.** It gives its peer the module's physical pins and must
never be deployed.

## Build and test

```bash
cargo build -p openhsm-signer --release
cargo test  -p openhsm-signer --release
cargo run   -p openhsm-signer --bin openhsm-signer-sim -- --port 7700
```

## Further reading

- [`FPGA/README.md`](../../FPGA/README.md): the hardware specification this model follows
- [`docs/INTERFACE_CONTROL_DOCUMENT.md`](../../docs/INTERFACE_CONTROL_DOCUMENT.md): module bus interface
- [`docs/SYSTEM_DESIGN.md`](../../docs/SYSTEM_DESIGN.md): key hierarchy
