# OpenHSM carrier board: KiCad schematics (draft 0.2)

A KiCad 7 hierarchical schematic for one OpenHSM signing node. It was generated from the repo's v0.6.x documents: `README.md` BOM, `docs/SYSTEM_DESIGN.md`, `docs/INTERFACE_CONTROL_DOCUMENT.md` (IF-02 to IF-06) and `FPGA/README.md` section 12.

Open `openhsm-carrier.kicad_pro` in KiCad 7 or later. `openhsm-carrier.pdf` is the same set rendered by `kicad-cli`.

| Sheet | Contents |
|---|---|
| `power.kicad_sch` | 2x 12 V inputs with LM74700 ideal-diode OR, PSD-45A-5 module connector, SoC kill switch, 3.3 V / 3.3 V NVMe / 1.0 V / 1.8 V / 1.2 V rails, always-on tamper domain (AON LDO, CR123A, diode-OR), 5 V supervisor |
| `fpga.kicad_sch` | XC7A50T-1FTG256C signing module: SPI host link to the SoC (protocol 0xB3), receive-only SPI from the MCU, tamper and ceremony inputs, LEDs, SPI x4 config flash, 100 MHz clock, BBRAM key battery, decoupling |
| `supervisor.kicad_sch` | STM32U595RJT6Q tamper supervisor: pin plan, SMPS, LSE, SWD, FPGA VCCBATT drive |
| `sensors.kicad_sch` | 4-pair mesh connector, lid switches, light sensor, accelerometer, ceremony key-switch, avalanche TRNG |
| `soc.kicad_sch` | DART-MX8M-PLUS SOM (functional symbol), supervisor link, boot straps, reset, debug UART |
| `ethernet.kicad_sch` | Client port (on-SOM PHY to magjack), cluster port (KSZ9031RNX RGMII PHY to magjack) |
| `storage_usb.kicad_sch` | M.2 M-key NVMe (PCIe x1), USB-A for the CCID reader with switch and ESD |

## Checks performed

KiCad 7's CLI has no ERC, so the netlist exported by `kicad-cli` was checked by script:

- every pin is either connected or carries a no-connect flag;
- no single-node nets;
- no output-to-output conflicts;
- every power input is driven or flagged;
- each host-SPI line passes through its series resistor, and no I2C net is left from draft 0.1;
- the ICD interface nets (host SPI, MCU SPI, tamper, ceremony, reset, DONE, mesh, lid, light, accelerometer, RGMII, PCIe, USB) reach the expected parts.

Run ERC in KiCad as well.

## Decisions made for this draft (please review)

| Topic | Choice | Why |
|---|---|---|
| FPGA | Xilinx Artix-7 XC7A50T-1FTG256C | SRAM-based (power loss clears the KEK), AES-256 + HMAC bitstream security. **Size not confirmed:** a generic Yosys synthesis of the V0.6 RTL estimates about 88,800 LUTs against this part's 32,600 (docs/POST_QUANTUM.md section 8). Keep the XC7A100T-1FTG256C (same package) in mind until Vivado figures exist |
| Bitstream key | BBRAM on VCCBATT_0, fed from an MCU GPIO through a divider | Lets a tamper trip erase the key. Use eFUSE if you prefer a permanent key |
| SE050 | Not fitted | SYSTEM_DESIGN D2: the FPGA takes the SE050's place |
| SoC to FPGA link (IF-02) | 4-wire SPI from an ECSPI controller, mode 0, up to 12.5 MHz; 33 Ω source termination on every driven line; CS pulled up, MISO weakly pulled down | Draft 0.2 change. Hash-based (post-quantum) signatures are kilobytes, which I2C cannot carry at the target rate (docs/POST_QUANTUM.md). Bank 15 has spare pins for a later quad-SPI link, but the SoC side would then need FlexSPI instead of ECSPI |
| SoC to supervisor link (IF-05) | UART plus alert line, with 1 kΩ series resistors | The ICD leaves this open |
| Mesh | Pair 1 on hardware active tamper (PA0 to PC13); pairs 2-4 GPIO-scanned | The LQFP64 STM32U5 has only 3 TAMP pins |
| Fail-safe defaults | SN_TAMPER pulled up, SN_CEREMONY pulled down, FPGA_RST_N pulled down, SOC_PWR_EN pulled down | The board is safe if the MCU is in reset |
| Tamper-domain power mux | BAT54C diode-OR | The BOM's TPS2117 has no KiCad symbol |
| Accelerometer | ADXL363 | The BOM's AIS328DQ has no KiCad symbol; the ADXL363's ~270 nA motion wake suits the battery domain |
| Cluster PHY | KSZ9031RNX, gigabit RGMII | The BOM link points to the DP83825I, which is 10/100 RMII |
| Client port | On-SOM gigabit PHY | The DART-MX8M-PLUS has one Ethernet PHY on the module |
| 5 V supervisor | TLV803EA43 drawn with the TPS3839 DBZ symbol | Same SOT-23 pinout. Verify |

## Must do before layout

1. **SOM pins.** The SOM symbol is functional: pins F1 to F95 are placeholders. Map each one to the DART B2B connectors and check the I/O voltage per group from the Variscite datasheet. Pick an ECSPI instance that is free on the DART connector; if its pins run at 1.8 V, add a level translator.
2. **Magjack.** `RJ45 GbE magjack` is a generic symbol. Match its pin numbers and footprint to the part you choose.
3. **FPGA pins.** Confirm the pin assignments in Vivado I/O planning. Refine decoupling per UG483.
4. **Datasheet checks.** Check the ADXL363 RES and ADC_IN pins, the KSZ9031 straps, and the TPS22917's 2 A rating against the SOM's peak current.
5. **Footprints.** Battery holder, PSD-45A-5 connector, mesh FFC and switch connectors are placeholders.
