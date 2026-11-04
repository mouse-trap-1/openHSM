# OpenHSM
An open source HSM that supports secp256k1, ECDSA, BIP-340 Schnorr and Ed25519. We're sticking it to them and saving millions in the process. Currently Pre-Alpha project status.

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

# Bill of Materials

| Qty | Item | Notes |
|-----|------|-------|
| 1 | [i.MX 8M Plus quad SOM, 4–8 GB LPDDR4, 32 GB eMMC](https://www.mouser.co.uk/en/ProductDetail/NXP-Semiconductors/8MPLUSLPD4-EVK?qs=sGAEpiMZZMv0WPLDnYsI7z%252BJKhWGmFt4C%252BT8bKH1DJMnMT5qg1wHVg%3D%3D) | Pick a vendor that publishes HAB secure-boot docs and mainline U-Boot/OP-TEE support |
| 1 | Custom carrier PCB, 6-layer | Section 5 |
| 1 | [NXP SE050 (AES + P-256 variant)](https://www.mouser.co.uk/en/ProductDetail/NXP-Semiconductors/SE050C1HQ1-Z01SCZ?qs=uwxL4vQweFPAe9Cpm7Fm%252BQ%3D%3D) | 5.3 |
| 1 | [STM32U5, LQFP64, not U575/585 rev X](https://www.mouser.co.uk/en/ProductDetail/STMicroelectronics/STM32U595RJT6Q?qs=sGAEpiMZZMuI9neUTtPr757IDD%2FwidVOeNx%252BK87m1RZ2F32QVOiwxQ%3D%3D) | Tamper Supervisor |
| 1 | [Low-power 3-axis accelerometer](https://www.mouser.co.uk/en/ProductDetail/STMicroelectronics/AIS328DQTR?qs=LYO3r17CQdPWOQ2wXNVBxw%3D%3D) | Tamper: movement |
| 1 | Photodiode + comparator | Tamper: light |
| 2 | Normally-closed microswitch | Tamper: lid |
| 1 | Mesh flex PCB, 4 serpentine pairs, 0.15 mm |Wraps the inner can |
| 1 | CR123A cell + holder | Tamper domain |
| 2 | Gigabit RGMII PHY + RJ45 magjack | Client and cluster ports |
| 1 | 256–512 GB M.2 NVMe, high-endurance | Audit ring |
| 2 | LM74700 + N-FET | Power ORing |
| 1 | 12 V to 5 V 6 A buck, 5 V load switch, 3.3 V low-Iq LDO, supervisor | 5.1 |
| 1 | Transistor, op-amp, passives for avalanche TRNG | 5.4 |
| 1 | Inner steel can, potting compound, 1U chassis, heatsink | 5.6 |
| 2 | 12 V PSU |One per PDU |
| 1 | USB CCID smartcard reader | Front panel |
