# Message examples

Regenerates and checks the worked examples in section 14 of `docs/INTERFACE_CONTROL_DOCUMENT.md`.
Needs `cargo build --release` first. Run in this directory:

```
python3 gen_module.py > module.json     # signing-module bus: GEN_WALLET, SIGN, a rejected command
python3 gen_node.py   > node.json       # full node: Ethereum and Bitcoin signing requests
python3 check.py                        # independent verification of node.json
```

Session nonces, wallet keys and timestamps are random, so the hex differs on every run; the layouts do not.
`gen_module.py` also checks the command MAC, the response MAC and the ECDSA signature itself.
