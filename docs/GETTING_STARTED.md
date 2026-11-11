# Getting started with the OpenHSM prototype

Everything below runs on one machine. It was developed and tested on Linux; macOS should work but has not been tried. Nothing here touches real funds: the examples use Sepolia and Bitcoin testnet parameters and never broadcast.

## Requirements

- Rust 1.87 or later (`rustup update stable`)
- Python 3.10 or later with the `cryptography` package, for the demo script and the penetration tests
- Optional: `cargo-audit` and `bandit` for two of the static checks

## Build and test

```bash
cargo build --release
cargo test --release
```

## Run the demonstration

```bash
scripts/demo.sh            # or: scripts/demo.sh /path/to/workdir
```

It starts three nodes (each an enclosure process and a daemon), and walks through: CA and identities, cluster KEK generation by an admin quorum, an Ethereum and a Bitcoin wallet with policies, signed transactions, policy denials, a 3-of-5 split to operator cards, enrolment of a second node, a tamper event, recovery on a third node, KEK rotation and offline audit verification.

## Do it by hand

```bash
BIN=target/release; W=$(mktemp -d)

# Operators: CA, two admins, one application server
$BIN/hsmctl pki init --out $W/pki
for a in alice bob; do $BIN/hsmctl identity --ca-dir $W/pki --name $a --role admin --out $W/ids; done
$BIN/hsmctl identity --ca-dir $W/pki --name app1 --role signer --out $W/ids
$BIN/hsmctl genesis --cluster demo --quorum 2 --ca $W/pki/ca.crt \
  --principal $W/ids/alice.principal.json --principal $W/ids/bob.principal.json \
  --principal $W/ids/app1.principal.json --out $W/genesis.json

# Node: enclosure model, then the daemon
$BIN/openhsm-hwsim provision --state $W/enc
$BIN/openhsm-hwsim run --state $W/enc --soc-socket $W/soc --physical-socket $W/phys &
$BIN/openhsmd init --data $W/node --genesis $W/genesis.json --node-id node-a --hardware unix:$W/soc
$BIN/hsmctl pki sign-csr --ca-dir $W/pki --csr $W/node/tls/node.csr --out $W/node/tls/node.crt
$BIN/openhsmd run --data $W/node --listen 127.0.0.1:7443 --hardware unix:$W/soc &

# Connection profiles
for who in alice app1; do
  $BIN/hsmctl profile --addr 127.0.0.1:7443 --cluster demo --ca $W/pki/ca.crt --identity-dir $W/ids --name $who --out $W/$who.json
done

# Quorum operation: alice drafts, bob approves, alice submits
$BIN/hsmctl propose --cluster demo --node node-a --out $W/op.json kek_generate '{}'
$BIN/hsmctl approve --id bob --sign-key $W/ids/bob.sign $W/op.json
$BIN/hsmctl submit --profile $W/alice.json $W/op.json

$BIN/hsmctl call --profile $W/app1.json status
```

Create a wallet the same way with `wallet_create` (see `scripts/demo.sh` for the parameters), then sign with `hsmctl call --profile $W/app1.json eth_sign_transaction '{…}'`. `hsmctl sim --socket $W/phys tamper lid` trips a simulated sensor.

## Run the penetration tests

```bash
python3 pentest/run.py             # all suites, about a minute
python3 pentest/run.py C- D-04     # only tests whose id starts with these prefixes
python3 pentest/report.py          # refresh the tables in docs/PENETRATION_TEST_REPORT.md
```

## Where things are

| You want | Look at |
| --- | --- |
| Why it is built this way | [SYSTEM_DESIGN.md](SYSTEM_DESIGN.md) |
| Exact interfaces and formats | [SYSTEM_SPECIFICATION.md](SYSTEM_SPECIFICATION.md) |
| Who the attackers are and what remains open | [THREAT_MODEL.md](THREAT_MODEL.md) |
| What was attacked and what happened | [PENETRATION_TEST_REPORT.md](PENETRATION_TEST_REPORT.md) |
| Standards and regulation | [COMPLIANCE.md](COMPLIANCE.md) |
| The FPGA signing module | [../FPGA/README.md](../FPGA/README.md) |
