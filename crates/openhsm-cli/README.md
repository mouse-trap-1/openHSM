# openhsm-cli (`hsmctl`)

The **operator and client command-line tool** for OpenHSM.

| | |
|---|---|
| Kind | Binary only (`hsmctl`) |
| Depends on | [`openhsm-node`](../openhsm-node) (client, protocol, state types) |
| Used by | Operators, `scripts/demo.sh`, the `pentest/` suite |
| `unsafe` | Forbidden |

## What it does

`hsmctl` has three groups of commands.

### 1. Offline set-up

| Command | Purpose |
|---|---|
| `pki init` | Create the cluster CA used for mutual TLS |
| `pki sign-csr` | Sign a node's certificate request (from `openhsmd init`) |
| `identity` | Create a principal (`admin`, `signer` or `auditor`): TLS client certificate, Ed25519 request-signing key, and a `NAME.principal.json` registration record |
| `genesis` | Build the genesis document (cluster name, quorum, lease divisor, CA, principals) that nodes are initialised from |
| `profile` | Write a connection profile (address, CA, certificate, keys) for a principal |
| `card-new` | Create a software operator card, a test double for a YubiKey |

### 2. Talking to a node

| Command | Purpose |
|---|---|
| `call --profile P METHOD [PARAMS]` | Send one request signed by one principal. `PARAMS` is JSON or `@FILE`. Covers signing, reads, and single-admin operations |
| `propose` | Draft an operation that needs a quorum, naming cluster, node and validity (default 12 h) |
| `approve --id ID --sign-key KEY OP` | Add one admin's signature to the draft |
| `submit --profile P OP` | Submit the draft; the submitter signs it too |

A quorum operation is `propose` by one admin, `approve` by each further admin
(typically on separate machines), then `submit`. The node requires the configured
number of distinct admin signatures over the same payload.

### 3. Verification and simulation

| Command | Purpose |
|---|---|
| `audit-verify --log FILE --identity HEX` | Verify an exported audit log offline with only the node's public identity key (printed by `openhsmd init`) |
| `sim --socket PATH ...` | **Prototype only.** Act on a node's simulated physical world: `tamper <sensor>`, `ceremony on|off`, `power-cycle`, `trng-fail on|off`, `glitch`, `status` |

## How it plugs into the larger system

```text
 hsmctl ──reuses──► openhsm_node::{client, proto, state}
   │
   ├── call / propose / approve / submit ──TLS 1.3 + Ed25519──► openhsmd (openhsm-node)
   ├── audit-verify ───────────────────── reads an exported audit.log (no network)
   └── sim ──Unix socket──► openhsm-hwsim or openhsmd --sim-physical (openhsm-hw)
```

- **Shared types, no drift.** `hsmctl` links `openhsm-node` and uses its `Client`,
  `Profile`, `Payload`, `Frame`, `Principal`, `Role` and `Genesis`, so the wire
  format and genesis schema are defined once, on the server side.
- **Trust-root tool.** It is where a cluster begins: the CA, principals and genesis
  document it produces are the trust anchors every node is initialised with.
- **Key material it handles.** Request-signing keys are 32-byte hex seeds in files
  written with private permissions, so protect them as you would any operator
  credential. It never sees wallet keys; those exist only in the signing module.
- **Cluster operations.** Enrolling a node, rotating the KEK, splitting it onto
  operator cards, and snapshots are all expressed as `call` / `propose` against
  node methods. `scripts/demo.sh` runs the full sequence.

## Typical flow

```bash
hsmctl pki init --out ca
hsmctl identity --ca-dir ca --name alice --role admin --out ids
hsmctl genesis --cluster demo --quorum 2 --ca ca/ca.crt --principal ids/alice.principal.json ... --out genesis.json
openhsmd init --data node1 --genesis genesis.json --node-id node1     # prints CSR path
hsmctl pki sign-csr --ca-dir ca --csr node1/tls/node.csr --out node1/tls/node.crt
openhsmd run --data node1 --listen 127.0.0.1:7443
hsmctl profile --addr 127.0.0.1:7443 --cluster demo --ca ca/ca.crt --identity-dir ids --name alice --out alice.json
hsmctl call --profile alice.json status
```

With a quorum of 2, `genesis` needs at least two admin `--principal` records. Run
`hsmctl <command> --help` for every option, and see
[`scripts/demo.sh`](../../scripts/demo.sh) for a complete working sequence (three
admins, two nodes, KEK transfer, rotation, tamper and recovery).

## Build

```bash
cargo build -p openhsm-cli --release     # produces target/release/hsmctl
```

## Further reading

- [`docs/GETTING_STARTED.md`](../../docs/GETTING_STARTED.md): build, demo, manual walkthrough
- [`docs/INTERFACE_CONTROL_DOCUMENT.md`](../../docs/INTERFACE_CONTROL_DOCUMENT.md): API methods and file formats
