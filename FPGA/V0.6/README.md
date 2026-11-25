# V0.6: protocol 0xB3

V0.6 moves the host link from I2C to SPI and adds a Keccak-256 core. Both are preparation for Ethereum's move to hash-based (post-quantum) signatures, announced on 23 November 2026: those signatures are kilobytes long, and Ethereum hashes with Keccak. The module still signs secp256k1 ECDSA only. The reasoning and the plan are in [`docs/POST_QUANTUM.md`](../../docs/POST_QUANTUM.md).

This folder is complete: every source, testbench, vector file and host tool needed to build and test the node is here. The full specification is [`../README.md`](../README.md).

## What changed from V0.5

| Change | Where | Why |
| --- | --- | --- |
| **SPI host link.** `spi_host_slave.v` replaces `i2c_slave.v`. Mode 0, one chip select, write frame `0x02 ptr data…`, read frame `0x03 ptr dummy data…`. Oversampled by the system clock: SCLK up to clk/8, 12.5 MHz at 100 MHz. MISO is tri-stated (`host_miso_oe`) while deselected. Same byte interface towards the register file, so the sequencer is unchanged | `spi_host_slave.v`, `sign_node_top.v` (ports `host_sclk`, `host_cs_n`, `host_mosi`, `host_miso`, `host_miso_oe`; parameter `I2C_ADDR` removed) | About 12 times the raw bandwidth of 1 MHz I2C with no address or ACK overhead. Hash-based signatures of 2.5 to 50 KB per signature cannot be carried over I2C at the node's rate. Today it also cuts about 2.7 ms from every request |
| VERSION reads **0xB3** | `sign_node_top.v` | Commands, registers, MACs, error codes and blob formats are those of 0xB2; only the framing changed. Blobs, sealed KEKs and share records from V0.5 still work |
| **Keccak-256 core.** Keccak-f[1600], one round per clock, 24 cycles per 136-byte block, caller pads (0x01 … 0x80). Standalone: no command uses it yet | `keccak256_core.v`, `tb_keccak.v`, `gen_keccak_vectors.py` | Hash core for a future hash-based signer; with a rate and domain-byte parameter it also gives SHA3-256 and SHAKE for ML-KEM. Lets the module hash transactions itself later |
| Host driver: `SpidevBus` transport for Linux `spidev`; accepts 0xB2 and 0xB3 | `sn_host.py` | The driver logic is unchanged |
| Testbenches drive SPI instead of I2C (shared SCLK/MOSI/MISO, one CS per node) | `tb_v05.v`, `tb_phase2.v`, `tb_node_system.v`; new `tb_spi_host_slave.v` | |

## What it costs

In a generic Yosys flow for Xilinx 7-series, `keccak256_core` alone is about 5,700 LUTs and 1,600 flip-flops, and `spi_host_slave` is 22 LUTs against 70 for the I2C slave it replaces. Signing time inside the module is unchanged.

The same flow puts the whole node at about 88,800 LUTs, roughly 2.7 times what the XC7A50T has. This was true of V0.5 as well; V0.6 is the first version synthesised at all. Section 8 of `docs/POST_QUANTUM.md` has the breakdown and what to do about it.

## Files

| Area | Files |
| --- | --- |
| Node top level | `sign_node_top.v`, `secret_store.v`, `spi_secret_rx.v`, `point_check.v` |
| Signer | `ecdsa_secp256k1_sign.v`, `modmul_serial.v`, `ecdsa_ucode_rom.v`, `ecdsa_ucode_entries.vh` (generated; the generator is not in the repository) |
| Hash and nonce | `sha256_core.v`, `hmac_sha256.v`, `rfc6979_nonce.v`, `keccak256_core.v` (standalone) |
| AEAD | `aes256_core.v`, `gf128_mul.v`, `aes_gcm32.v`, `aes_sbox.vh` |
| Sharing | `shamir_core.v`, `gen_shamir.py` |
| Peripherals | `spi_host_slave.v`, `trng_ro.v` |
| Host software | `sn_host.py` (driver, protocol 0xB3, `SpidevBus`), `sn_ceremony.py` (operator-card ceremonies) |
| Reference and vectors | `refmodel.py`, `gen_vectors.py`, `gen_keccak_vectors.py`, `vectors.mem`, `tb_*_vecs.vh`, `tb_core_pub.vh` |
| Testbenches | `tb_v05.v`, `tb_phase2.v`, `tb_node_system.v`, `tb_blocks.v`, `tb_ecdsa_sign.v`, `tb_gcm.v`, `tb_shamir.v`, `tb_hash_nonce.v`, `tb_spi_host_slave.v` (new), `tb_keccak.v` (new), `tb_trng.v` |
| Independent checks | `verify_v05.py`, `verify_phase2.py`, `verify_node.py`, `check_host_model.py` (driver against the Rust model) |

`tb_v05.v` keeps its name: it tests the 0xB2 extensions, which 0xB3 carries unchanged.

## Simulate

Python 3 with the `cryptography` package, and Icarus Verilog.

```bash
python3 gen_vectors.py . && python3 refmodel.py
python3 gen_keccak_vectors.py .

# unit tests
iverilog -g2005 -o sim_spih   tb_spi_host_slave.v spi_host_slave.v && vvp sim_spih
iverilog -g2005 -o sim_keccak tb_keccak.v keccak256_core.v && vvp sim_keccak
iverilog -g2005 -o sim_hash   tb_hash_nonce.v rfc6979_nonce.v hmac_sha256.v sha256_core.v && vvp sim_hash
iverilog -g2005 -o sim_gcm    tb_gcm.v aes_gcm32.v aes256_core.v gf128_mul.v && vvp sim_gcm
iverilog -g2005 -o sim_shamir tb_shamir.v shamir_core.v && vvp sim_shamir
iverilog -g2005 -o sim_trng   tb_trng.v trng_ro.v && vvp sim_trng
iverilog -g2005 -o sim_core   tb_ecdsa_sign.v ecdsa_secp256k1_sign.v modmul_serial.v ecdsa_ucode_rom.v && vvp sim_core +NVEC=2
iverilog -g2005 -o sim_blocks tb_blocks.v spi_secret_rx.v point_check.v modmul_serial.v ecdsa_secp256k1_sign.v ecdsa_ucode_rom.v && vvp sim_blocks

# system tests (10 to 30 minutes each) and independent checks
SRC="sign_node_top.v secret_store.v spi_secret_rx.v point_check.v shamir_core.v aes_gcm32.v aes256_core.v gf128_mul.v \
     trng_ro.v spi_host_slave.v hmac_sha256.v sha256_core.v rfc6979_nonce.v ecdsa_secp256k1_sign.v modmul_serial.v ecdsa_ucode_rom.v"
iverilog -g2005 -o sim_v05  tb_v05.v         $SRC && vvp sim_v05  | tee v05.log  && python3 verify_v05.py v05.log
iverilog -g2005 -o sim_p2   tb_phase2.v      $SRC && vvp sim_p2   | tee p2.log   && python3 verify_phase2.py p2.log
iverilog -g2005 -o sim_node tb_node_system.v $SRC && vvp sim_node | tee node.log && python3 verify_node.py node.log
python3 sn_ceremony.py --selftest

# host driver against the Rust model (after cargo build --release at the repository root)
python3 check_host_model.py
```

The simulation TRNG (`SIM_TRNG = 1`) is deterministic and not random.

`logs/` holds the output of the three system simulations as run for this release, so the independent checks can be repeated without the long simulations: `python3 verify_v05.py logs/v05.log`.

## Integration changes

- **Host link.** Wire the SoC's ECSPI SCLK, MOSI and SS0 to `host_sclk`, `host_mosi`, `host_cs_n`, and `host_miso` (through an OBUFT enabled by `host_miso_oe`) to its MISO. Pull CS_N up. Keep SCLK at or below clk/8. The carrier schematic (draft 0.2) has the wiring, termination and pin choice.
- **SoC driver.** Use `sn_host.SpidevBus` or the same framing in the secure-world driver. Nothing else in the driver changes.
- The `ceremony` pin, the tamper MCU's SPI frame and the key distribution are as in V0.5.

## Still not done

- Everything listed under "Still not done" in [`../V0.5/README.md`](../V0.5/README.md).
- Quad SPI. The link is single-lane; bank 15 has spare pins, but the SoC side would need FlexSPI.
- The Keccak core is not connected to the sequencer and has no rate or domain parameter yet (needed for SHA3-256/SHAKE and ML-KEM).
- Not synthesised in Vivado or timing-closed; the utilisation figures come from Yosys, and they do not fit the XC7A50T (see above).
