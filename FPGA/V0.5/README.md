# V0.5: protocol 0xB2

V0.5 closes the protocol and fault-attack items that V0.4 listed as open, and the findings of the system-level penetration tests that concern the module. It is still secp256k1 ECDSA only: no other curve or signature scheme was added.

Unlike V0.2 to V0.4, this folder is complete. Every source, testbench, vector file and host tool needed to build and test the node is here. The full specification is [`../README.md`](../README.md).

## What changed from V0.4

| Change | Where | Why |
| --- | --- | --- |
| **X1 Response MAC.** New read-only register `RMAC` (0xC4). Every authenticated command ends with HMAC-SHA256(chan_key, "SN-RESP-v1" ‖ nonce ‖ ctr ‖ cmd ‖ error ‖ WID ‖ IV ‖ TAG ‖ A ‖ B ‖ C) over the buffers as it left them | `sign_node_top.v` (`CMD_RESP`) | In V0.4 a device on the I2C bus could swap the public key returned by `GEN_WALLET` and the host could not tell (penetration test finding PT-03) |
| **X2 Lockout.** Eight consecutive authentication failures lock the command channel until reset. STATUS2 bit 7 shows the lock. The KEK is kept | `sign_node_top.v` (`CMD_AUTH`) | V0.4 allowed unlimited MAC guesses |
| **X3 Verify before release.** `SIGN` holds (r, s) back, checks s·k ≡ ±(z + r·d) mod n, runs a second scalar multiplication k·G and checks x(k·G) mod n = r. Either failing returns error 6 with cleared buffers. Parameter `VERIFY_SIGN` (default 1) | `sign_node_top.v` (`CMD_SIGN` steps 4 to 9) | A single fault during signing can otherwise leak the wallet key through a wrong signature |
| **X4 Buffer hygiene.** Any error clears IV, TAG, A, B, C. The MAC register is cleared after every command | `sign_node_top.v` (`fin`, `fin_raw`) | Nothing from a failed command stays readable |
| **X5 Confidential card secret.** Commands 0x56 `SHARE_GET_C` and 0x57 `SHARE_PUT_C` take BUF_B XORed with HMAC-SHA256(chan_key, "SN-CONF-v1" ‖ nonce ‖ ctr) | `sign_node_top.v` (`CMD_AUTH` step 2) | In V0.4 the card secret crossed I2C in the clear; a passive probe could rebuild the KEK from one ceremony (PT-02) |
| **X6 Ceremony pin.** New input `ceremony`. While it is low, commands 0x41, 0x42, 0x45, 0x46, 0x50, 0x51, 0x53, 0x54, 0x56, 0x57 answer error 8. STATUS2 bit 4 shows the pin | `sign_node_top.v` | Moving the KEK now needs someone at the node, not only a valid MAC |
| **Randomised start point.** Every scalar multiplication starts from (λ·x : λ·y : λ) with a fresh random λ. Parameter `RAND_Z` (default 1) | `sign_node_top.v` (`SB_RZ_*`), new input `z1_in` on `ecdsa_secp256k1_sign.v` | First side-channel countermeasure: intermediate values of the ladder differ on every run. It also makes the second ladder of X3 independent of the first |
| VERSION reads 0xB2 | `sign_node_top.v` | |
| Host driver checks RMAC, uses 0x56/0x57, and takes `chan_key` instead of the tamper secret S | `sn_host.py` | The SoC must not hold S: with S it can derive the seal key and open the sealed KEK (PT-01). The tamper MCU must hand out HMAC(S, "SN-CHAN") only |
| `refmodel.py`, `gen_vectors.py` | new | The V0.4 checkers imported `gen_ucode.py` and `gen_ecies.py`, which are not in the repository. These replace them, and regenerate the unit-test vectors |

One second `modmul_serial` instance was added to the top level. It multiplies mod p for the start-point randomisation and mod n for the scalar half of X3.

All command codes, registers, error codes and blob formats of V0.4 are unchanged, so blobs, sealed KEKs and share records made by V0.4 still work. A V0.4 host driver also still works, but it ignores RMAC and sends card secrets in the clear, so it gets none of the new protection; and its ceremony commands answer error 8 unless the pin is high.

## What it costs

X3 runs a second scalar multiplication, so a signature takes about twice as long: 3,469,730 clock cycles measured in simulation against about 1.80 M in V0.4. At 100 MHz and a 1 MHz bus that is about 27 signatures per second per node instead of 48, against a target of 55. Section 9 of the specification lists the ways to recover it; the cleanest is a second signer core running the check in parallel, which is not implemented. Building with `VERIFY_SIGN = 0` restores the V0.4 speed and gives up the fault protection. The other changes together add about 1,300 cycles (under 0.1%) to a signature.

## Files

| Area | Files |
| --- | --- |
| Node top level | `sign_node_top.v`, `secret_store.v`, `spi_secret_rx.v`, `point_check.v` |
| Signer | `ecdsa_secp256k1_sign.v`, `modmul_serial.v`, `ecdsa_ucode_rom.v`, `ecdsa_ucode_entries.vh` (generated; the generator is not in the repository) |
| Hash and nonce | `sha256_core.v`, `hmac_sha256.v`, `rfc6979_nonce.v` |
| AEAD | `aes256_core.v`, `gf128_mul.v`, `aes_gcm32.v`, `aes_sbox.vh` |
| Sharing | `shamir_core.v`, `gen_shamir.py` |
| Peripherals | `i2c_slave.v`, `trng_ro.v` |
| Host software | `sn_host.py` (driver, protocol 0xB2), `sn_ceremony.py` (operator-card ceremonies) |
| Reference and vectors | `refmodel.py`, `gen_vectors.py`, `vectors.mem`, `tb_*_vecs.vh`, `tb_core_pub.vh` |
| Testbenches | `tb_v05.v` (new), `tb_phase2.v`, `tb_node_system.v`, `tb_blocks.v`, `tb_ecdsa_sign.v`, `tb_gcm.v`, `tb_shamir.v`, `tb_hash_nonce.v`, `tb_i2c_slave.v`, `tb_trng.v` |
| Independent checks | `verify_v05.py` (new), `verify_phase2.py`, `verify_node.py` |

## Simulate

Python 3 with the `cryptography` package, and Icarus Verilog.

```bash
python3 gen_vectors.py . && python3 refmodel.py

# unit tests
iverilog -g2005 -o sim_hash   tb_hash_nonce.v rfc6979_nonce.v hmac_sha256.v sha256_core.v && vvp sim_hash
iverilog -g2005 -o sim_gcm    tb_gcm.v aes_gcm32.v aes256_core.v gf128_mul.v && vvp sim_gcm
iverilog -g2005 -o sim_shamir tb_shamir.v shamir_core.v && vvp sim_shamir
iverilog -g2005 -o sim_i2c    tb_i2c_slave.v i2c_slave.v && vvp sim_i2c
iverilog -g2005 -o sim_trng   tb_trng.v trng_ro.v && vvp sim_trng
iverilog -g2005 -o sim_core   tb_ecdsa_sign.v ecdsa_secp256k1_sign.v modmul_serial.v ecdsa_ucode_rom.v && vvp sim_core +NVEC=2
iverilog -g2005 -o sim_blocks tb_blocks.v spi_secret_rx.v point_check.v modmul_serial.v ecdsa_secp256k1_sign.v ecdsa_ucode_rom.v && vvp sim_blocks

# system tests (10 to 30 minutes each) and independent checks
SRC="sign_node_top.v secret_store.v spi_secret_rx.v point_check.v shamir_core.v aes_gcm32.v aes256_core.v gf128_mul.v \
     trng_ro.v i2c_slave.v hmac_sha256.v sha256_core.v rfc6979_nonce.v ecdsa_secp256k1_sign.v modmul_serial.v ecdsa_ucode_rom.v"
iverilog -g2005 -o sim_v05  tb_v05.v         $SRC && vvp sim_v05  | tee v05.log  && python3 verify_v05.py v05.log
iverilog -g2005 -o sim_p2   tb_phase2.v      $SRC && vvp sim_p2   | tee p2.log   && python3 verify_phase2.py p2.log
iverilog -g2005 -o sim_node tb_node_system.v $SRC && vvp sim_node | tee node.log && python3 verify_node.py node.log
python3 sn_ceremony.py --selftest
```

The simulation TRNG (`SIM_TRNG = 1`) is deterministic and not random.

`logs/` holds the output of the three system simulations as run for this release (`v05.log`, `p2.log`, `node.log`), so the independent checks can be repeated without the long simulations: `python3 verify_v05.py logs/v05.log`.

## Integration changes

- **`ceremony` pin.** Drive it from the tamper MCU, which reads the physical key-switch. Do not connect it to the SoC.
- **Tamper MCU firmware.** Give the SoC HMAC-SHA256(S, "SN-CHAN") and a separate key for its own sealing. Never give it S. The FPGA side is unchanged: it still receives `0xA5 ‖ S` over SPI.
- **SoC driver.** Read RMAC with every response and reject the response if it does not verify. After error 5, read STATUS2 bit 7; if set, the module needs a reset.

## Still not done

- Scalar blinding. The ladder is fixed at 256 iterations and the microcode generator is not in the repository, so the scalar could not be widened. Start-point randomisation is in; masking of AES and HMAC is not.
- X3 defends against a single fault. Two matching faults, or a fault in the comparison itself, are not covered.
- The start-point randomisation falls back to λ = 1 when the TRNG has failed, so that signing stays available, as the hedged nonce already does.
- Not synthesised or timing-closed. The second multiplier and the 256-bit comparators of X3 add area and may sit on the critical path.
- TRNG uncharacterised; no real YubiKeys; no independent review. See section 11 of the specification.
