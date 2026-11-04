# OpenHSM
An open source HSM that supports secp256k1, ECDSA, BIP-340 Schnorr and Ed25519. We're sticking it to them and saving millions in the process.

![OpenHSM Architecture](./OpenHSM_Architecture.png)

# System Requirements

| Target | Value |
|--------|-------|
| Sustained signing | 1,000 sig/s with one site (3 nodes) lost |
| Burst | 3,000 sig/s for 60 s with all nodes up |
| Sign latency | p99 under 50 ms at the HSM API |
| Wallets | 10,000 per partition, every node holds every partition |
| Curves | secp256k1 ECDSA + Schnorr (BIP-340), Ed25519 |
| Node failover | under 5 s, no lost requests (client retries with idempotency key) |
| Wallet-creation RPO | 0: a wallet exists only once written to a quorum |
| Site-loss RTO | under 30 s |
