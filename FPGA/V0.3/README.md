# secp256k1 signing module (Verilog)

On-module key generation, key storage and ECDSA signing, controlled over I2C.
The private key is generated from an on-chip TRNG, stored in a key vault (+ your
non-volatile store) and used only by the signer. No register or command reads it out.

## Files

| File | Purpose |
|---|---|
| `secp256k1_hsm_top.v` | **Top level.** I2C register map, command controller, confirm button, tamper handling |
| `key_vault.v` | Holds the key, async tamper zeroize, NVM mirror/restore/erase |
| `i2c_slave.v` | Soft I2C slave (register-pointer protocol, open-drain via `sda_oe`) |
| `trng_ro.v` | Ring-oscillator TRNG, von Neumann debias, RCT/APT health tests |
| `rfc6979_nonce.v` | Hedged RFC 6979 nonce (HMAC-SHA256 DRBG + optional fresh entropy) |
| `hmac_sha256.v`, `sha256_core.v` | HMAC-SHA256 / SHA-256 |
| `ecdsa_secp256k1_sign.v` | Signer core (constant-time ladder, complete formulas, pubkey mode) |
| `modmul_serial.v` | 1-bit/clock modular multiplier (mod p and mod n) |
| `ecdsa_ucode_rom.v`, `ecdsa_ucode_entries.vh` | Generated microcode (do not edit) |
| `gen_ucode.py`, `gen_tests.py` | Microcode generator + bit-exact reference model + test vectors |
| `tb_*.v`, `verify_system.py` | Testbenches and the independent signature check |

## I2C register map (default address 0x42, big-endian, pointer auto-increments)

| Addr | Name | Dir | Notes |
|---|---|---|---|
| 0x00 | STATUS | R | b0 busy, b1 done, b2 error, b3 key present, b4 tamper, b5 TRNG fail, b6 awaiting confirm |
| 0x01 | CMD | W | 01 GENKEY, 02 SIGN, 03 PUBKEY, 04 CANCEL, 05 ERASE |
| 0x02 | ERROR | R | 0 ok, 2 no key, 3 key exists, 4 TRNG failure, 5 confirm timeout, 6 sign failed, 7 tamper, 8 bad cmd, 9 cancelled |
| 0x10-0x2F | HASH | W/R | 32-byte digest to sign |
| 0x30-0x4F | SIG_R | R | |
| 0x50-0x6F | SIG_S | R | low-s normalised |
| 0x70-0x8F | PUB_X | R | |
| 0x90-0xAF | PUB_Y | R | |
| 0xFF | VERSION | R | 0xA1 |

Typical host flow: `GENKEY` -> poll STATUS.done -> `PUBKEY` -> read PUB_X/PUB_Y (register
the address) -> write HASH -> `SIGN` -> poll -> read SIG_R/SIG_S. Press the confirm
button when STATUS.awaiting_confirm is set.

Timing at 100 MHz: GENKEY a few ms, PUBKEY ~17 ms, SIGN ~19 ms.

## Simulate

```bash
python3 gen_ucode.py . && python3 gen_tests.py .          # regenerate microcode + vectors
iverilog -g2005 -o sim_hash tb_hash_nonce.v rfc6979_nonce.v hmac_sha256.v sha256_core.v && vvp sim_hash
iverilog -g2005 -o sim_i2c  tb_i2c_slave.v i2c_slave.v && vvp sim_i2c
iverilog -g2005 -o sim_trng tb_trng.v trng_ro.v && vvp sim_trng
iverilog -g2005 -o sim tb_ecdsa_sign.v ecdsa_secp256k1_sign.v modmul_serial.v ecdsa_ucode_rom.v && vvp sim +NVEC=1
iverilog -g2005 -o sim_sys tb_hsm_system.v secp256k1_hsm_top.v key_vault.v trng_ro.v i2c_slave.v \
         hmac_sha256.v sha256_core.v rfc6979_nonce.v ecdsa_secp256k1_sign.v modmul_serial.v ecdsa_ucode_rom.v
vvp sim_sys | tee sys.log && python3 verify_system.py sys.log
```

## Hardware integration you must do

* **SDA**: connect `sda_oe` to an open-drain output (`sda = sda_oe ? 1'b0 : 1'bz`), read it back on
  `sda_i`, external pull-up. SCL is input only (no clock stretching). Keep `clk` >= 8x SCL.
* **tamper**: your tamper circuit -> `tamper` (async, active high). Hold it high for as long as the
  fault condition lasts. The key is zeroized on the edge, even with the clock stopped.
* **Non-volatile store** (`nvm_*`): connect to storage that is itself wiped by your tamper circuit
  (battery-backed SRAM, FRAM in the protected volume, ...). `nvm_erase` is a level that must erase
  the stored key. A plain flash chip that merely ignores `nvm_erase` defeats the tamper design.
* **confirm**: a debounced, active-high user button.
* **TRNG**: build with `SIM_TRNG=0` (default). Characterise the ring oscillators on your silicon
  (raw entropy, bias, voltage/temperature) and set `N_RO`, `SAMPLE_DIV` and the health-test cut-offs
  accordingly. The defaults are placeholders. Some tools need the combinational-loop waiver for the
  oscillators.
* Set `CONFIRM_TIMEOUT` for your clock (default ~30 s at 100 MHz).

## Not implemented (read before trusting it with real funds)

* Side-channel resistance: no scalar blinding, no randomised projective coordinates, no masking.
* Fault-attack resistance beyond tamper zeroization: signatures are not verified before release.
* Authentication of the I2C host: any bus master can request a signature (the confirm button is the
  only gate). Add an authenticated channel if the bus is exposed.
* Blind signing: the module signs a 32-byte digest and cannot show the user what it covers.
* Key backup/recovery: the key is non-exportable by design, so losing the module loses the key.
* Permanent lock after tamper: reset clears the latch (see `key_vault.v` for the one-line policy change).
* Not synthesised or timing-closed; no formal verification; no independent review.

---

# v2: stateless wrapped-key signing node (`sign_node_top.v`)

The v1 module above stores one key. v2 is the SE050-slot replacement for the cluster design: **no wallet key
is stored on the FPGA**. Each wallet key is an AES-256-GCM blob (AAD = wallet id) wrapped under the cluster
KEK, stored and replicated by the SoC/Raft. The FPGA unwraps, signs, wipes. Only the KEK (volatile) lives in it.

| File | Purpose |
|---|---|
| `sign_node_top.v` | v2 top: I2C register map, MAC-authenticated commands, KEK lifecycle, wallets, ECIES |
| `secret_store.v` | Volatile chan_key / seal_key / KEK / enrolment key, async tamper zeroize |
| `spi_secret_rx.v` | Receives `0xA5 \|\| S` from the STM32U5 tamper MCU (receive-only) |
| `aes256_core.v`, `gf128_mul.v`, `aes_gcm32.v` | AES-256-GCM (96-bit IV, 16 B AAD, 32 B payload); plaintext withheld on tag failure |
| `point_check.v` | On-curve check (invalid-curve defence) before any ECDH |
| `gen_aes.py`, `gen_ecies.py` | S-box + GCM vectors; ECIES reference model + vectors |
| `sn_host.py` | Reference SoC secure-world driver (MAC framing, all commands) |
| `tb_gcm.v`, `tb_blocks.v`, `tb_node_system.v`, `verify_node.py` | Tests; the system sim runs two nodes on one I2C bus |

Boot: STM32U5 sends S over SPI -> `chan_key = HMAC(S,"SN-CHAN")`, `seal_key = HMAC(S,"SN-SEAL")`, fresh nonce.
Every command carries `HMAC(chan_key, nonce||ctr||cmd||wid||iv||tag||A||B||C)` with a strictly increasing counter.
No S = no session. S is accepted once per reset. Register map and command list are in the header of `sign_node_top.v`.

KEK lifecycle: `KEK_GEN` (first node) -> `KEK_SEAL` (blob kept on NVMe, only this node + same S can open it) ->
after reboot `KEK_UNSEAL`. New node: `ENROL_GEN` on the new node -> operator-verified public key ->
`KEK_EXPORT` on an existing node -> `KEK_IMPORT` on the new node. ECIES: T = t*G, shared = x(t*E),
K = HMAC(shared, "ECIES-KEK-v1"||T||E), AES-GCM(K, KEK).

Simulate: see the commands at the top of `tb_node_system.v`; then `python3 verify_node.py node.log`.

Not done in v2 (read before trusting it): the enrolment public key is **not authenticated by the FPGA** -- a
substituted key would receive the KEK, so verify it out of band (operator/YubiKey ceremony = Phase 2);
no Shamir/YubiKey recovery or KEK rotation yet; command *responses* are not MACed (the I2C bus to the SoC is
assumed inside the trust boundary); no scalar blinding / randomised coordinates / verify-before-release;
no lockout after repeated bad MACs; TRNG and timing unproven on silicon; not synthesised; no independent review.
