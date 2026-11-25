"""Build the OpenHSM carrier schematics (KiCad 7)."""
import sys
import kgen
from kgen import Sheet, Project, Flow, box_symbol, snap

OUT = sys.argv[1] if len(sys.argv) > 1 else "/home/claude/out/openhsm-carrier"

kgen.RAILS.update("""GND +12V_IN_A +12V_IN_B +12V +5V +5V_SOM +5V_USB +3V3 +3V3_NVME +1V0 +1V8 +1V2_PHY
+3V3_AON VBAT_CELL VDD_TAMPER VDD11_SUP CHASSIS""".split())

FP_R = "Resistor_SMD:R_0402_1005Metric"
FP_C = "Capacitor_SMD:C_0402_1005Metric"
FP_C0805 = "Capacitor_SMD:C_0805_2012Metric"
FP_C1206 = "Capacitor_SMD:C_1206_3216Metric"


class Refs:
    def __init__(self, base):
        self.base, self.n = base, {}

    def __call__(self, prefix):
        self.n[prefix] = self.n.get(prefix, 0) + 1
        return "%s%d" % (prefix, self.base + self.n[prefix])


def R(f, ref, val, a, b, rot=0, **kw):
    return f.place("Device:R", ref("R"), val, {"1": a, "2": b}, rot=rot, footprint=FP_R, **kw)


def C(f, ref, val, a, b="GND", rot=0, fp=FP_C, **kw):
    return f.place("Device:C", ref("C"), val, {"1": a, "2": b}, rot=rot, footprint=fp, **kw)


def decouple(f, ref, rail, vals):
    for v in vals:
        fp = FP_C if ("n" in v or v in ("1u", "0.47u")) else (FP_C0805 if v in ("4.7u", "10u") else FP_C1206)
        C(f, ref, v, rail, "GND", fp=fp)


# =====================================================================================
# custom symbols
# =====================================================================================
def som_symbol():
    L = [("F1", "VIN", "power_in"), ("F2", "VIN", "power_in"), ("F3", "VIN", "power_in"), None,
         ("F10", "ECSPI_SN_SCLK", "output"), ("F11", "ECSPI_SN_MOSI", "output"),
         ("F25", "ECSPI_SN_MISO", "input"), ("F26", "ECSPI_SN_SS0", "output"), None,
         ("F12", "UART_SUP_TXD", "output"), ("F13", "UART_SUP_RXD", "input"), ("F14", "GPIO_SUP_ALERT_N", "input"), None,
         ("F15", "UART_DBG_TXD", "output"), ("F16", "UART_DBG_RXD", "input"), None,
         ("F17", "BOOT_MODE0", "input"), ("F18", "BOOT_MODE1", "input"), ("F19", "POR_B", "input"), None,
         ("F20", "USB1_DP", "bidirectional"), ("F21", "USB1_DN", "bidirectional"), ("F22", "USB1_VBUS_EN", "output"), None,
         ("F23", "GPIO_ETH1_RST_N", "output"), ("F24", "GPIO_ETH1_INT_N", "input")]
    Rt = [("F30", "ETH0_MDI0_P", "bidirectional"), ("F31", "ETH0_MDI0_N", "bidirectional"),
          ("F32", "ETH0_MDI1_P", "bidirectional"), ("F33", "ETH0_MDI1_N", "bidirectional"),
          ("F34", "ETH0_MDI2_P", "bidirectional"), ("F35", "ETH0_MDI2_N", "bidirectional"),
          ("F36", "ETH0_MDI3_P", "bidirectional"), ("F37", "ETH0_MDI3_N", "bidirectional"),
          ("F38", "ETH0_LED_LINK", "output"), ("F39", "ETH0_LED_ACT", "output"), None,
          ("F40", "ENET_QOS_TXD0", "output"), ("F41", "ENET_QOS_TXD1", "output"),
          ("F42", "ENET_QOS_TXD2", "output"), ("F43", "ENET_QOS_TXD3", "output"),
          ("F44", "ENET_QOS_TX_CTL", "output"), ("F45", "ENET_QOS_TXC", "output"),
          ("F46", "ENET_QOS_RXD0", "input"), ("F47", "ENET_QOS_RXD1", "input"),
          ("F48", "ENET_QOS_RXD2", "input"), ("F49", "ENET_QOS_RXD3", "input"),
          ("F50", "ENET_QOS_RX_CTL", "input"), ("F51", "ENET_QOS_RXC", "input"),
          ("F52", "ENET_QOS_MDC", "output"), ("F53", "ENET_QOS_MDIO", "bidirectional"), None,
          ("F60", "PCIE_TXP", "output"), ("F61", "PCIE_TXN", "output"),
          ("F62", "PCIE_RXP", "input"), ("F63", "PCIE_RXN", "input"),
          ("F64", "PCIE_REFCLKP", "passive"), ("F65", "PCIE_REFCLKN", "passive"),
          ("F66", "PCIE_PERST_N", "passive"), ("F67", "PCIE_CLKREQ_N", "bidirectional"), ("F68", "PCIE_WAKE_N", "input")]
    B = [("F90", "GND", "power_in"), ("F91", "GND", "power_in"), ("F92", "GND", "power_in"),
         ("F93", "GND", "power_in"), ("F94", "GND", "power_in"), ("F95", "GND", "power_in")]
    return box_symbol("openhsm:DART-MX8M-PLUS_functional", "U", "DART-MX8M-PLUS", left=L, right=Rt, bottom=B,
                      width=50.8,
                      description="Variscite DART-MX8M-PLUS SOM, FUNCTIONAL symbol: pin numbers F* are placeholders. "
                                  "Map to the DART B2B connectors from the Variscite datasheet before layout.")


def magjack_symbol():
    L = [("1", "MX1+", "passive"), ("2", "MX1-", "passive"), ("3", "MX2+", "passive"), ("4", "MX2-", "passive"),
         ("5", "MX3+", "passive"), ("6", "MX3-", "passive"), ("7", "MX4+", "passive"), ("8", "MX4-", "passive"),
         None, ("9", "CT", "passive")]
    Rt = [("11", "LED_L_A", "passive"), ("12", "LED_L_K", "passive"), None,
          ("13", "LED_R_A", "passive"), ("14", "LED_R_K", "passive")]
    B = [("SH", "SHIELD", "passive")]
    return box_symbol("openhsm:RJ45_GbE_Magjack", "J", "RJ45 GbE magjack", left=L, right=Rt, bottom=B, width=20.32,
                      description="1-port 10/100/1000 RJ45 with integrated magnetics and 2 LEDs. GENERIC symbol: "
                                  "pin numbers must be matched to the chosen part (e.g. Molex 85793 series) before layout.")


SOM = som_symbol()
MAGJACK = magjack_symbol()

# nets that cross sheets are promoted to global labels automatically (see bottom)

# =====================================================================================
# Sheet: power
# =====================================================================================
def sheet_power():
    sh = Sheet("power.kicad_sch", "Power", paper="A2")
    r = Refs(100)
    sh.text("Power path: 2x 12 V feeds, ideal-diode OR, 12->5 V module, rails for SoC, FPGA, PHY, NVMe and the "
            "always-on tamper domain", 15, 15, size=2.5, bold=True)

    f = Flow(sh, 15, 25, 290, "12 V inputs and ideal-diode ORing (LM74700 + N-FET)")
    f.place("Connector:Screw_Terminal_01x02", "J101", "12V feed A", {"1": "+12V_IN_A", "2": "GND"},
            footprint="TerminalBlock_Phoenix:TerminalBlock_Phoenix_MKDS-1,5-2-5.08_1x02_P5.08mm_Horizontal")
    f.place("Device:D_TVS", r("D"), "SMBJ15A", {"1": "GND", "2": "+12V_IN_A"}, footprint="Diode_SMD:D_SMB")
    f.place("Device:Q_NMOS_GDSD", "Q101", "STN4NF03L", {"1": "ORA_GATE", "2": "+12V", "3": "+12V_IN_A", "4": "+12V"},
            footprint="Package_TO_SOT_SMD:SOT-223-3_TabPin2")
    f.place("Power_Management:LM74700", "U101", "LM74700-Q1",
            {"VCAP": "ORA_VCAP", "GND": "GND", "EN": "+12V_IN_A", "CATHODE": "+12V", "GATE": "ORA_GATE", "ANODE": "+12V_IN_A"},
            footprint="Package_TO_SOT_SMD:SOT-23-6")
    C(f, r, "100n", "ORA_VCAP", "+12V_IN_A")
    f.newrow()
    f.place("Connector:Screw_Terminal_01x02", "J102", "12V feed B", {"1": "+12V_IN_B", "2": "GND"},
            footprint="TerminalBlock_Phoenix:TerminalBlock_Phoenix_MKDS-1,5-2-5.08_1x02_P5.08mm_Horizontal")
    f.place("Device:D_TVS", r("D"), "SMBJ15A", {"1": "GND", "2": "+12V_IN_B"}, footprint="Diode_SMD:D_SMB")
    f.place("Device:Q_NMOS_GDSD", "Q102", "STN4NF03L", {"1": "ORB_GATE", "2": "+12V", "3": "+12V_IN_B", "4": "+12V"},
            footprint="Package_TO_SOT_SMD:SOT-223-3_TabPin2")
    f.place("Power_Management:LM74700", "U102", "LM74700-Q1",
            {"VCAP": "ORB_VCAP", "GND": "GND", "EN": "+12V_IN_B", "CATHODE": "+12V", "GATE": "ORB_GATE", "ANODE": "+12V_IN_B"},
            footprint="Package_TO_SOT_SMD:SOT-23-6")
    C(f, r, "100n", "ORB_VCAP", "+12V_IN_B")
    f.newrow()
    C(f, r, "47u 25V", "+12V", fp=FP_C1206)
    C(f, r, "100n", "+12V")
    f.place("power:PWR_FLAG", "#FLG101", "PWR_FLAG", {"1": "+12V_IN_A"})
    f.place("power:PWR_FLAG", "#FLG102", "PWR_FLAG", {"1": "+12V_IN_B"})
    f.place("power:PWR_FLAG", "#FLG103", "PWR_FLAG", {"1": "GND"})

    f2 = Flow(sh, 300, 25, 580, "12 V -> 5 V (MEAN WELL PSD-45A-5 module) and SoC kill switch")
    f2.place("Connector_Generic:Conn_01x04", "J103", "PSD-45A-5",
             {"1": "+12V", "2": "GND", "3": "+5V", "4": "GND"},
             footprint="Connector_Phoenix_MC:PhoenixContact_MC_1,5_4-G-3.81_1x04_P3.81mm_Horizontal",
             fields={"Note": "Off-board 12 V to 5 V 6 A DC-DC module (BOM). Pin 1 VIN, 2 GND, 3 VOUT, 4 GND"})
    f2.place("power:PWR_FLAG", "#FLG104", "PWR_FLAG", {"1": "+5V"})
    decouple(f2, r, "+5V", ["100u", "10u", "100n"])
    f2.newrow()
    f2.place("Power_Management:TPS22917DBV", "U103", "TPS22917DBV",
             {"VIN": "+5V", "GND": "GND", "ON": "SOC_PWR_EN", "CT": "SOMSW_CT", "QOD": "+5V_SOM", "VOUT": "+5V_SOM"})
    C(f2, r, "1n", "SOMSW_CT")
    R(f2, r, "100k", "SOC_PWR_EN", "GND")
    decouple(f2, r, "+5V_SOM", ["47u", "10u", "100n"])
    sh.text("SoC kill: the tamper MCU drives SOC_PWR_EN. The pull-down keeps the SoC off until supervisor "
            "firmware enables it, and a trip can cut SoC power in hardware.", 300, f2.bottom() + 6)
    sh.text("TPS22917 is rated 2 A. Check the SOM's peak current; use a 4 A switch if needed.", 300, f2.bottom() + 10)

    y = max(f.bottom(), f2.bottom()) + 20
    f3 = Flow(sh, 15, y, 290, "3.3 V main and 3.3 V NVMe (TPS62130, 3 A each, from 5 V)")
    for tag, rail in (("A", "+3V3"), ("B", "+3V3_NVME")):
        sw, fb, ss, pg = "BK%s_SW" % tag, "BK%s_FB" % tag, "BK%s_SS" % tag, ("PG_3V3" if tag == "A" else "PG_3V3_NVME")
        f3.place("Regulator_Switching:TPS62130", "U%d" % (104 if tag == "A" else 105), "TPS62130RGT",
                 {"VIN": "+5V", "EN": "+5V", "VOS": rail, "SW": sw, "PG": pg, "FB": fb, "GND": "GND",
                  "FSW": "GND", "DEF": "GND", "SS/TR": ss})
        f3.place("Device:L", r("L"), "2.2u 4A", {"1": sw, "2": rail}, footprint="Inductor_SMD:L_Taiyo-Yuden_NR-40xx")
        R(f3, r, "560k", rail, fb)
        R(f3, r, "180k", fb, "GND")
        C(f3, r, "3.3n", ss)
        R(f3, r, "100k", pg, rail)
        decouple(f3, r, "+5V", ["10u"])
        decouple(f3, r, rail, ["22u", "22u", "100n"])
        f3.place("power:PWR_FLAG", "#FLG1%d" % (10 if tag == "A" else 11), "PWR_FLAG", {"1": rail})
        f3.newrow()
    sh.text("Vout = 0.8 V x (1 + 560k/180k) = 3.29 V", 15, f3.bottom() + 5)

    f4 = Flow(sh, 300, y, 580, "FPGA core 1.0 V, VCCAUX/VDDIO 1.8 V, PHY core 1.2 V")
    f4.place("Regulator_Switching:TLV62569DBV", "U106", "TLV62569DBV",
             {"EN": "+5V", "GND": "GND", "SW": "BK1V0_SW", "VIN": "+5V", "FB": "BK1V0_FB"})
    f4.place("Device:L", r("L"), "2.2u 2A", {"1": "BK1V0_SW", "2": "+1V0"}, footprint="Inductor_SMD:L_0805_2012Metric")
    R(f4, r, "100k", "+1V0", "BK1V0_FB")
    R(f4, r, "150k", "BK1V0_FB", "GND")
    decouple(f4, r, "+5V", ["10u"])
    decouple(f4, r, "+1V0", ["22u", "22u"])
    f4.place("power:PWR_FLAG", "#FLG112", "PWR_FLAG", {"1": "+1V0"})
    f4.newrow()
    f4.place("Regulator_Linear:AP2112K-1.8", "U107", "AP2112K-1.8",
             {"VIN": "+3V3", "GND": "GND", "EN": "+3V3", "VOUT": "+1V8"})
    decouple(f4, r, "+3V3", ["1u"])
    decouple(f4, r, "+1V8", ["10u"])
    f4.newrow()
    f4.place("Regulator_Linear:AP2112K-1.2", "U108", "AP2112K-1.2",
             {"VIN": "+3V3", "GND": "GND", "EN": "+3V3", "VOUT": "+1V2_PHY"})
    decouple(f4, r, "+3V3", ["1u"])
    decouple(f4, r, "+1V2_PHY", ["10u"])
    sh.text("Vout = 0.6 V x (1 + 100k/150k) = 1.00 V. Artix-7 recommended order VCCINT -> VCCAUX -> VCCO is "
            "not enforced here (DS181 allows any order); add EN chaining if inrush matters.", 300, f4.bottom() + 5)

    y = max(f3.bottom(), f4.bottom()) + 20
    f5 = Flow(sh, 15, y, 580, "Always-on tamper domain: AON LDO + CR123A, diode-OR to VDD_TAMPER; 5 V supervisor")
    f5.place("Regulator_Linear:XC6206PxxxMR", "U109", "XC6206P332MR", {"VI": "+5V", "GND": "GND", "VO": "+3V3_AON"},
             footprint="Package_TO_SOT_SMD:SOT-23")
    decouple(f5, r, "+3V3_AON", ["1u"])
    f5.place("Device:Battery_Cell", "BT101", "CR123A", {"1": "VBAT_CELL", "2": "GND"},
             footprint="Battery:BatteryHolder_Keystone_103_1x20mm",
             fields={"Note": "CR123A holder (BOM: Multicomp MP000356). Footprint placeholder"})
    f5.place("power:PWR_FLAG", "#FLG105", "PWR_FLAG", {"1": "VBAT_CELL"})
    f5.place("Diode:BAT54C", r("D"), "BAT54C", {"1": "+3V3_AON", "2": "VBAT_CELL", "3": "VDD_TAMPER"})
    decouple(f5, r, "VDD_TAMPER", ["10u", "100n"])
    f5.place("power:PWR_FLAG", "#FLG113", "PWR_FLAG", {"1": "VDD_TAMPER"})
    f5.place("Power_Supervisor:TPS3839DBZ", "U110", "TLV803EA43DBZR",
             {"GND": "GND", "~{RESET}": "MAIN_PG", "VDD": "+5V"},
             fields={"Note": "TLV803E (BOM) shares the DBZ pinout 1 GND, 2 RESET, 3 VDD with this symbol. "
                             "Open-drain, 4.38 V threshold on +5V"})
    R(f5, r, "10k", "MAIN_PG", "+3V3")
    sh.text("BOM lists a TPS2117 power mux for this domain; it has no KiCad library symbol, so a BAT54C diode-OR "
            "is drawn instead (about 0.3 V drop, VDD_TAMPER 2.7-3.0 V).", 15, f5.bottom() + 5)
    sh.text("The STM32U5 VBAT pin takes VBAT_CELL directly, so TAMP backup registers (which hold S) survive even "
            "if VDD_TAMPER collapses. MAIN_PG reads low when main power is absent.", 15, f5.bottom() + 9)
    return sh


# =====================================================================================
# Sheet: FPGA signing module
# =====================================================================================
FPGA_IO = {
    # bank 15 user I/O (3.3 V)
    "D13": "CLK_100M",          # IO_L12P_T1_MRCC_15
    "C11": "FPGA_RST_N",        # IO_L11P_T1_SRCC_15
    "B10": "SN_HOST_SCLK",      # IO_L4P_T0_15      host SPI from the SoC (protocol 0xB3)
    "B11": "SN_HOST_MOSI",      # IO_L4N_T0_15
    "B9": "FPGA_HOST_MISO",     # IO_L3P_T0_DQS_AD1P_15  (OBUFT, released while CS is high)
    "A10": "SN_HOST_CS_N",      # IO_L3N_T0_DQS_AD1N_15
    "B12": "SN_SPI_SCLK",       # IO_L5P_T0_AD9P_15
    "A12": "SN_SPI_CS_N",       # IO_L5N_T0_AD9N_15
    "A13": "SN_SPI_MOSI",       # IO_L7P_T1_AD2P_15
    "C8": "SN_TAMPER",          # IO_L1P_T0_AD0P_15
    "C9": "SN_CEREMONY",        # IO_L1N_T0_AD0N_15
    "E15": "FPGA_LED_BUSY",     # IO_L18N_T2_A23_15
    "E16": "FPGA_LED_KEK",      # IO_L17P_T2_A26_15
    "F15": "FPGA_LED_TAMPER",   # IO_L18P_T2_A24_15
    # bank 14 configuration (SPI x4 master)
    "J13": "FPGA_D00",          # IO_L1P_T0_D00_MOSI_14
    "J14": "FPGA_D01",          # IO_L1N_T0_D01_DIN_14
    "K15": "FPGA_D02",          # IO_L2P_T0_D02_14
    "K16": "FPGA_D03",          # IO_L2N_T0_D03_14
    "L12": "FPGA_FCS_B",        # IO_L6P_T0_FCS_B_14
    "L15": "FPGA_PUDC_B",       # IO_L3P_T0_DQS_PUDC_B_14
}
FPGA_CFG = {
    "CFGBVS_0": "+3V3", "VCCO_0": "+3V3", "CCLK_0": "FPGA_CCLK", "DONE_0": "FPGA_DONE", "INIT_B_0": "FPGA_INIT_B",
    "PROGRAM_B_0": "FPGA_PROG_B", "M0_0": "FPGA_M0", "M1_0": "GND", "M2_0": "GND",
    "TCK_0": "JTAG_TCK", "TMS_0": "JTAG_TMS", "TDI_0": "JTAG_TDI", "TDO_0": "JTAG_TDO",
    "VN_0": "GND", "VP_0": "GND", "VREFN_0": "GND", "VREFP_0": "GND", "DXN_0": "GND", "DXP_0": "GND",
}


def fpga_nets(unit):
    from libload import pins as lp
    from kgen import lib_symbol
    sym = lib_symbol("FPGA_Xilinx_Artix7:XC7A50T-FTG256")
    nets = {}
    for p in lp(sym):
        if p["unit"] != unit:
            continue
        n = p["name"]
        if p["number"] in FPGA_IO:
            nets[p["number"]] = FPGA_IO[p["number"]]
        elif n.startswith("IO_"):
            nets[p["number"]] = "NC"
        elif n.startswith("VCCO_"):
            nets[p["number"]] = "+3V3"
        elif n in FPGA_CFG:
            nets[p["number"]] = FPGA_CFG[n]
        elif n in ("GND", "GNDADC_0"):
            nets[p["number"]] = "GND"
        elif n in ("VCCINT", "VCCBRAM"):
            nets[p["number"]] = "+1V0"
        elif n in ("VCCAUX", "VCCADC_0"):
            nets[p["number"]] = "+1V8"
        elif n == "VCCBATT_0":
            nets[p["number"]] = "FPGA_VBATT"
        else:
            raise ValueError("unmapped FPGA pin %s %s" % (p["number"], n))
    return nets


def sheet_fpga():
    sh = Sheet("fpga.kicad_sch", "Signing module (Artix-7 FPGA)", paper="A1")
    r = Refs(200)
    sh.text("Signing module: XC7A50T-1FTG256C running FPGA/V0.6 sign_node_top.v (protocol 0xB3), SPI host link "
            "from the SoC (replaces I2C 0x48)", 15, 15, size=2.5, bold=True)
    lib = "FPGA_Xilinx_Artix7:XC7A50T-FTG256"
    f = Flow(sh, 15, 25, 800, None, gap=10)
    f.place(lib, "U201", "XC7A50T-1FTG256C", fpga_nets(1), unit=1, footprint="Package_BGA:Xilinx_FTG256")
    f.place(lib, "U201", "XC7A50T-1FTG256C", fpga_nets(2), unit=2, footprint="Package_BGA:Xilinx_FTG256")
    f.place(lib, "U201", "XC7A50T-1FTG256C", fpga_nets(3), unit=3, footprint="Package_BGA:Xilinx_FTG256")
    f.place(lib, "U201", "XC7A50T-1FTG256C", fpga_nets(4), unit=4, footprint="Package_BGA:Xilinx_FTG256")
    y = f.bottom() + 15

    g = Flow(sh, 15, y, 400, "Configuration: SPI x4 master boot (M[2:0] = 001), encrypted + authenticated bitstream")
    g.place("Memory_Flash:MX25L3233FM", "U202", "MX25L3233F",
            {"~{CS}": "FPGA_FCS_B", "SO/SIO1": "FPGA_D01", "~{WP}/SIO2": "FPGA_D02", "GND": "GND",
             "SI/SIO0": "FPGA_D00", "SCLK": "FPGA_CCLK", "~{HOLD}/SIO3": "FPGA_D03", "VCC": "+3V3"})
    decouple(g, r, "+3V3", ["100n"])
    R(g, r, "10k", "FPGA_FCS_B", "+3V3")
    R(g, r, "10k", "FPGA_D02", "+3V3")
    R(g, r, "10k", "FPGA_D03", "+3V3")
    g.newrow()
    R(g, r, "1k", "FPGA_M0", "+3V3")
    R(g, r, "1k", "FPGA_PUDC_B", "+3V3")
    R(g, r, "4.7k", "FPGA_PROG_B", "+3V3")
    R(g, r, "4.7k", "FPGA_INIT_B", "+3V3")
    R(g, r, "330", "FPGA_DONE", "+3V3")
    g.newrow()
    g.place("Connector_Generic:Conn_01x06", "J201", "JTAG (DNP)",
            {"1": "+3V3", "2": "GND", "3": "JTAG_TCK", "4": "JTAG_TDO", "5": "JTAG_TDI", "6": "JTAG_TMS"},
            footprint="Connector_PinHeader_2.54mm:PinHeader_1x06_P2.54mm_Vertical", dnp=True)
    sh.text("JTAG is for bring-up only: not fitted in production; disable JTAG and readback in eFUSE "
            "(FPGA/README.md section 12).", 15, g.bottom() + 5)
    sh.text("Bitstream AES-256 key lives in BBRAM, powered on VCCBATT_0 from the tamper MCU (FPGA_VBATT). "
            "A trip can drop it to erase the key.", 15, g.bottom() + 9)

    h = Flow(sh, 420, y, 800, "Clock, host SPI termination, fail-safe defaults, status LEDs")
    h.place("Oscillator:ASE-xxxMHz", "X201", "ASE-100.000MHZ", {"EN": "+3V3", "GND": "GND", "OUT": "CLK_100M", "Vdd": "+3V3"},
            footprint="Oscillator:Oscillator_SMD_Abracon_ASE-4Pin_3.2x2.5mm")
    decouple(h, r, "+3V3", ["100n"])
    R(h, r, "33", "FPGA_HOST_MISO", "SN_HOST_MISO", fields={"Note": "Source termination at the MISO driver"})
    R(h, r, "100k", "SN_HOST_MISO", "GND", fields={"Note": "Keeps MISO defined while the FPGA releases it"})
    R(h, r, "10k", "SN_HOST_CS_N", "+3V3", fields={"Note": "Module deselected while the SoC is off or booting"})
    h.newrow()
    R(h, r, "10k", "SN_TAMPER", "+3V3", fields={"Note": "Fail-safe: tamper asserted unless the MCU drives it low"})
    R(h, r, "10k", "SN_CEREMONY", "GND", fields={"Note": "Fail-closed: ceremony commands disabled by default"})
    R(h, r, "10k", "FPGA_RST_N", "GND", fields={"Note": "Module held in reset until the MCU releases it"})
    h.newrow()
    for net, col in (("FPGA_LED_BUSY", "BUSY"), ("FPGA_LED_KEK", "KEK"), ("FPGA_LED_TAMPER", "TAMPER")):
        R(h, r, "330", net, "LED_%s_A" % col)
        h.place("Device:LED", r("D"), "LED " + col.lower(), {"A": "LED_%s_A" % col, "K": "GND"},
                footprint="LED_SMD:LED_0603_1608Metric")
    h.newrow()
    sh.text("host_miso_oe drives an OBUFT on B9 (Z while CS is high). SCLK, MOSI, CS are inputs, oversampled: "
            "system clock 100 MHz >= 8x host SCLK (12.5 MHz max) and >= 4x MCU SPI SCLK.", 420, h.bottom() + 5)
    sh.text("Pin choice is a draft: confirm in Vivado I/O planning before layout.", 420, h.bottom() + 9)

    y = max(g.bottom(), h.bottom()) + 20
    k = Flow(sh, 15, y, 800, "Decoupling (draft quantities, refine per UG483 for XC7A50T FTG256)")
    decouple(k, r, "+1V0", ["100u", "4.7u", "0.47u", "0.47u", "0.47u", "0.47u"])
    k.newrow()
    decouple(k, r, "+1V8", ["47u", "4.7u", "0.47u", "0.47u"])
    k.newrow()
    decouple(k, r, "+3V3", ["47u", "4.7u", "0.47u", "0.47u", "0.47u", "0.47u", "0.47u", "0.47u"])
    return sh


# =====================================================================================
# Sheet: tamper supervisor
# =====================================================================================
def sheet_supervisor():
    sh = Sheet("supervisor.kicad_sch", "Tamper supervisor (STM32U5)", paper="A2")
    r = Refs(300)
    sh.text("Tamper supervisor: STM32U595RJT6Q (LQFP64, SMPS) on the always-on domain. Holds S in TAMP backup "
            "registers, erased by hardware on a trip", 15, 15, size=2.5, bold=True)
    mcu = {
        "1": "VBAT_CELL", "2": "MESH1_IN", "3": "OSC32_IN", "4": "OSC32_OUT", "5": "NC", "6": "NC",
        "7": "MCU_NRST", "8": "MESH2_OUT", "9": "MESH2_IN", "10": "MESH3_OUT", "11": "MESH3_IN",
        "12": "GND", "13": "VDD_TAMPER", "14": "MESH1_OUT", "15": "LID_LOOP", "16": "LIGHT_TRIP",
        "17": "CEREMONY_SW_IN", "18": "GND", "19": "VDD_TAMPER",
        "20": "SN_SPI_CS_N", "21": "SN_SPI_SCLK", "22": "TRNG_ANALOG", "23": "SN_SPI_MOSI",
        "24": "MESH4_OUT", "25": "MESH4_IN", "26": "ACC_INT1", "27": "NC",
        "28": "SMPS_LX", "29": "VDD_TAMPER", "30": "GND", "31": "VDD11_SUP", "32": "GND", "33": "VDD_TAMPER",
        "34": "ACC_SCLK", "35": "ACC_MISO", "36": "ACC_MOSI", "37": "ACC_CS_N",
        "38": "SN_TAMPER", "39": "SN_CEREMONY", "40": "FPGA_RST_N", "41": "FPGA_DONE",
        "42": "SUP_TX", "43": "SUP_RX", "44": "SUP_ALERT_N", "45": "SOC_PWR_EN",
        "46": "SWDIO", "47": "GND", "48": "VDD_TAMPER", "49": "SWCLK", "50": "MAIN_PG",
        "51": "NC", "52": "NC", "53": "NC", "54": "NC", "55": "SWO", "56": "NC",
        "57": "FPGA_VBATT_DRV", "58": "NC", "59": "NC", "60": "BOOT0", "61": "NC",
        "62": "VDD11_SUP", "63": "GND", "64": "VDD_TAMPER",
    }
    f = Flow(sh, 15, 25, 300, None, gap=10)
    f.place("MCU_ST_STM32U5:STM32U595RJTxQ", "U301", "STM32U595RJT6Q", mcu)

    g = Flow(sh, 330, 25, 580, "Supply, SMPS, reset, boot, LSE")
    decouple(g, r, "VDD_TAMPER", ["10u", "100n", "100n", "100n", "100n", "1u"])
    g.newrow()
    g.place("Device:L", r("L"), "2.2u", {"1": "SMPS_LX", "2": "VDD11_SUP"}, footprint="Inductor_SMD:L_0805_2012Metric")
    decouple(g, r, "VDD11_SUP", ["4.7u", "100n", "100n"])
    g.place("power:PWR_FLAG", "#FLG301", "PWR_FLAG", {"1": "VDD11_SUP"})
    g.place("power:PWR_FLAG", "#FLG302", "PWR_FLAG", {"1": "SMPS_LX"})
    g.newrow()
    C(g, r, "100n", "MCU_NRST")
    R(g, r, "10k", "BOOT0", "GND")
    g.newrow()
    g.place("Device:Crystal", "Y301", "32.768kHz", {"1": "OSC32_IN", "2": "OSC32_OUT"},
            footprint="Crystal:Crystal_SMD_2012-2Pin_2.0x1.2mm")
    C(g, r, "6.8p", "OSC32_IN")
    C(g, r, "6.8p", "OSC32_OUT")
    g.newrow()
    g.place("Connector_Generic:Conn_01x06", "J301", "SWD (DNP)",
            {"1": "VDD_TAMPER", "2": "SWDIO", "3": "SWCLK", "4": "SWO", "5": "MCU_NRST", "6": "GND"},
            footprint="Connector_PinHeader_1.27mm:PinHeader_1x06_P1.27mm_Vertical", dnp=True)

    y = max(f.bottom(), g.bottom()) + 15
    h = Flow(sh, 15, y, 580, "FPGA bitstream-key battery (VCCBATT_0 must stay within 1.0-1.89 V)")
    R(h, r, "1M", "FPGA_VBATT_DRV", "FPGA_VBATT")
    R(h, r, "1M", "FPGA_VBATT", "GND")
    C(h, r, "100n", "FPGA_VBATT")
    h.place("power:PWR_FLAG", "#FLG303", "PWR_FLAG", {"1": "FPGA_VBATT"})
    sh.text("GPIO PB5 high: VDD_TAMPER/2 = 1.35-1.65 V on VCCBATT_0, about 1.5 uA. Driving PB5 low on a trip "
            "erases the FPGA BBRAM key.", 15, h.bottom() + 5)

    pin_tbl = [
        "Pin plan (from docs IF-03 to IF-06):",
        "PA4/PA5/PA7  SPI1 NSS/SCK/MOSI -> FPGA (33-byte frame 0xA5||S, receive-only, no MISO)",
        "PC7 SN_TAMPER (active high), PC8 SN_CEREMONY (from key-switch), PC9 FPGA_RST_N, PA8 FPGA_DONE",
        "PA0 TAMP_OUT1 -> mesh pair 1 -> PC13 TAMP_IN1 (hardware active tamper)",
        "Mesh pairs 2-4 on GPIO (PC0/PC1, PC2/PC3, PB0/PB1), scanned by firmware with LPTIM",
        "PA1 TAMP_IN5 lid loop (2 NC switches in series), PA2 light comparator (WKUP4), PB2 accel INT1 (WKUP1)",
        "PA3 ceremony key-switch input, PA6 ADC1_IN11 avalanche TRNG",
        "PA9/PA10 USART1 <-> SoC (IF-05 link: bus still an open item in the ICD), PA11 alert, PA12 SoC power enable",
        "Voltage and temperature tamper use the STM32U5 internal TAMP monitors",
    ]
    for i, t in enumerate(pin_tbl):
        sh.text(t, 15, h.bottom() + 15 + i * 4, size=1.5, bold=(i == 0))
    return sh


# =====================================================================================
# Sheet: tamper sensors + TRNG
# =====================================================================================
def sheet_sensors():
    sh = Sheet("sensors.kicad_sch", "Tamper sensors, key-switch and TRNG", paper="A2")
    r = Refs(400)
    sh.text("Tamper sensors (always-on domain), ceremony key-switch and avalanche-noise TRNG", 15, 15, size=2.5, bold=True)

    f = Flow(sh, 15, 25, 290, "Active mesh (4 serpentine pairs, 0.15 mm flex) and lid switches")
    f.place("Connector_Generic:Conn_01x10", "J401", "Mesh flex",
            {"1": "MESH1_OUT", "2": "MESH1_IN", "3": "MESH2_OUT", "4": "MESH2_IN", "5": "MESH3_OUT",
             "6": "MESH3_IN", "7": "MESH4_OUT", "8": "MESH4_IN", "9": "GND", "10": "GND"},
            footprint="Connector_FFC-FPC:Hirose_FH12-10S-0.5SH_1x10-1MP_P0.50mm_Horizontal")
    f.newrow()
    f.place("Connector_Generic:Conn_01x02", "J402", "Lid switch 1 (NC)", {"1": "LID_LOOP", "2": "LID_MID"},
            footprint="Connector_JST:JST_SH_SM02B-SRSS-TB_1x02-1MP_P1.00mm_Horizontal")
    f.place("Connector_Generic:Conn_01x02", "J403", "Lid switch 2 (NC)", {"1": "LID_MID", "2": "GND"},
            footprint="Connector_JST:JST_SH_SM02B-SRSS-TB_1x02-1MP_P1.00mm_Horizontal")
    C(f, r, "10n", "LID_LOOP")
    sh.text("Both NC lid switches in series: LID_LOOP is held at GND while the lid is closed; the TAMP_IN5 "
            "pull-up trips on open.", 15, f.bottom() + 5)

    g = Flow(sh, 300, 25, 580, "Light sensor (photodiode + nano-power comparator)")
    g.place("Sensor_Optical:BPW34", "D401", "BPW34", {"K": "VDD_TAMPER", "A": "LIGHT_SENSE"})
    R(g, r, "10M", "LIGHT_SENSE", "GND")
    R(g, r, "10M", "VDD_TAMPER", "LIGHT_REF")
    R(g, r, "1M", "LIGHT_REF", "GND")
    g.newrow()
    g.place("Comparator:TLV7031DBV", "U401", "TLV7031DBV",
            {"V-": "GND", "V+": "VDD_TAMPER", "1": "LIGHT_TRIP", "3": "LIGHT_SENSE", "4": "LIGHT_REF"})
    decouple(g, r, "VDD_TAMPER", ["100n"])
    sh.text("Dark: LIGHT_SENSE about 0 V. Light raises it above LIGHT_REF (about 0.27 V) and LIGHT_TRIP goes high.",
            300, g.bottom() + 5)

    y = max(f.bottom(), g.bottom()) + 18
    h = Flow(sh, 15, y, 290, "Movement: accelerometer on SPI2")
    h.place("Sensor_Motion:ADXL363", "U402", "ADXL363",
            {"V_{DD_I/O}": "VDD_TAMPER", "V_{S}": "VDD_TAMPER", "GND": "GND", "SCLK": "ACC_SCLK", "MOSI": "ACC_MOSI",
             "MISO": "ACC_MISO", "~{CS}": "ACC_CS_N", "INT1": "ACC_INT1", "INT2": "NC", "ADC_IN": "GND",
             "3": "NC", "10": "NC"})
    decouple(h, r, "VDD_TAMPER", ["100n", "1u"])
    sh.text("BOM part AIS328DQ has no KiCad symbol. ADXL363 is drawn instead: it is pin-ready and wakes "
            "on motion at about 270 nA, better for a battery domain.", 15, h.bottom() + 5)
    sh.text("Check the RES pins (3, 10) and ADC_IN against the ADXL363 datasheet before layout.", 15, h.bottom() + 9)

    k = Flow(sh, 300, y, 580, "Ceremony key-switch (physical lock, read by the MCU only)")
    k.place("Connector_Generic:Conn_01x02", "J404", "Ceremony key-switch", {"1": "CEREMONY_SW", "2": "GND"},
            footprint="Connector_JST:JST_SH_SM02B-SRSS-TB_1x02-1MP_P1.00mm_Horizontal")
    R(k, r, "1k", "CEREMONY_SW", "CEREMONY_SW_IN")
    C(k, r, "100n", "CEREMONY_SW_IN")
    sh.text("Never route this to the SoC (ICD IF-04).", 300, k.bottom() + 5)

    y = max(h.bottom(), k.bottom()) + 20
    t = Flow(sh, 15, y, 580, "Avalanche-noise TRNG (reverse-biased B-E junction, main domain) -> MCU ADC")
    R(t, r, "100k", "+12V", "AV_NOISE")
    t.place("Transistor_BJT:MMBT3904", "Q401", "MMBT3904", {"B": "GND", "E": "AV_NOISE", "C": "NC"})
    C(t, r, "100n", "AV_NOISE", "AV_AC")
    R(t, r, "100k", "+3V3", "AV_AC")
    R(t, r, "100k", "AV_AC", "GND")
    t.newrow()
    t.place("Amplifier_Operational:MCP6001-OT", "U403", "MCP6001",
            {"V-": "GND", "V+": "+3V3", "1": "AV_OUT", "3": "AV_AC", "4": "AV_FB"})
    R(t, r, "10k", "AV_OUT", "AV_FB")
    R(t, r, "1k", "AV_FB", "AV_FB2")
    C(t, r, "10u", "AV_FB2", fp=FP_C0805)
    R(t, r, "1k", "AV_OUT", "TRNG_ANALOG")
    decouple(t, r, "+3V3", ["100n"])
    sh.text("AC gain 11 around mid-rail. The 1k series resistor limits back-feed into the battery-powered MCU "
            "when main power is off. The MCU runs the SP 800-90B health tests.", 15, t.bottom() + 5)
    return sh


# =====================================================================================
# Sheet: SoC
# =====================================================================================
def sheet_soc():
    sh = Sheet("soc.kicad_sch", "SoC module (i.MX 8M Plus)", paper="A2")
    r = Refs(500)
    sh.text("SoC: Variscite DART-MX8M-PLUS (i.MX 8M Plus quad), 3.4-5 V supply from the switched +5V_SOM",
            15, 15, size=2.5, bold=True)
    som = {"VIN": "+5V_SOM", "GND": "GND",
           "ECSPI_SN_SCLK": "SOC_HOST_SCLK", "ECSPI_SN_MOSI": "SOC_HOST_MOSI",
           "ECSPI_SN_MISO": "SN_HOST_MISO", "ECSPI_SN_SS0": "SOC_HOST_CS_N",
           "UART_SUP_TXD": "SOC_SUP_TXD", "UART_SUP_RXD": "SOC_SUP_RXD", "GPIO_SUP_ALERT_N": "SOC_SUP_ALERT_N",
           "UART_DBG_TXD": "DBG_TXD", "UART_DBG_RXD": "DBG_RXD",
           "BOOT_MODE0": "SOM_BOOT_MODE0", "BOOT_MODE1": "SOM_BOOT_MODE1", "POR_B": "SOM_POR_B",
           "USB1_DP": "USB1_DP", "USB1_DN": "USB1_DN", "USB1_VBUS_EN": "USB1_VBUS_EN",
           "GPIO_ETH1_RST_N": "ETH1_RST_N", "GPIO_ETH1_INT_N": "ETH1_INT_N",
           "ETH0_LED_LINK": "ETH0_LED_LINK", "ETH0_LED_ACT": "ETH0_LED_ACT",
           "ENET_QOS_MDC": "ETH1_MDC", "ENET_QOS_MDIO": "ETH1_MDIO",
           "ENET_QOS_TX_CTL": "RGMII_TX_CTL", "ENET_QOS_TXC": "RGMII_TXC",
           "ENET_QOS_RX_CTL": "RGMII_RX_CTL", "ENET_QOS_RXC": "RGMII_RXC",
           "PCIE_TXP": "PCIE_TX_P", "PCIE_TXN": "PCIE_TX_N", "PCIE_RXP": "PCIE_RX_P", "PCIE_RXN": "PCIE_RX_N",
           "PCIE_REFCLKP": "PCIE_REFCLK_P", "PCIE_REFCLKN": "PCIE_REFCLK_N",
           "PCIE_PERST_N": "PCIE_PERST_N", "PCIE_CLKREQ_N": "PCIE_CLKREQ_N", "PCIE_WAKE_N": "PCIE_WAKE_N"}
    for i in range(4):
        som["ETH0_MDI%d_P" % i] = "ETH0_MDI%d_P" % i
        som["ETH0_MDI%d_N" % i] = "ETH0_MDI%d_N" % i
        som["ENET_QOS_TXD%d" % i] = "RGMII_TXD%d" % i
        som["ENET_QOS_RXD%d" % i] = "RGMII_RXD%d" % i
    f = Flow(sh, 15, 25, 300, None, gap=10)
    f.place(SOM, "U501", "DART-MX8M-PLUS", som, footprint="")
    sh.text("FUNCTIONAL SYMBOL: pins F1..F95 are placeholders grouped by function. Map each signal to the DART "
            "B2B connector pins from the Variscite datasheet.", 15, f.bottom() + 5)
    sh.text("The I/O voltage per signal group (3.3 V or 1.8 V) also comes from that datasheet. FPGA bank 15 "
            "is 3.3 V; add a level translator if the SOM's ECSPI pins are 1.8 V.", 15, f.bottom() + 9)

    g = Flow(sh, 330, 25, 580, "Supervisor link (IF-05): series resistors limit back-power while the SoC is off")
    R(g, r, "1k", "SUP_TX", "SOC_SUP_RXD", rot=90)
    R(g, r, "1k", "SUP_RX", "SOC_SUP_TXD", rot=90)
    g.newrow()
    R(g, r, "1k", "SUP_ALERT_N", "SOC_SUP_ALERT_N", rot=90)
    R(g, r, "100k", "SOC_SUP_ALERT_N", "+3V3")
    g.newrow()
    sh.text("Host SPI to the signing module (IF-02, protocol 0xB3): 33 R source termination on the SoC-driven "
            "lines", 330, g.bottom() + 4)
    g.cy = g.bottom() + 8
    g.newrow()
    R(g, r, "33", "SOC_HOST_SCLK", "SN_HOST_SCLK", rot=90)
    R(g, r, "33", "SOC_HOST_MOSI", "SN_HOST_MOSI", rot=90)
    R(g, r, "33", "SOC_HOST_CS_N", "SN_HOST_CS_N", rot=90)
    g.newrow()
    sh.text("The ICD leaves the SoC-supervisor bus open: a UART is assumed. soc_keys travels on it, so add "
            "transit protection in firmware.", 330, g.bottom() + 4)
    g.cy = g.bottom() + 12
    g.newrow()
    sh.text("Boot strap, reset, debug console", 330, g.cy - 4, size=2.0, bold=True)
    R(g, r, "10k", "SOM_BOOT_MODE0", "GND", fields={"Note": "Strap values per Variscite boot-mode table (eMMC boot)"})
    R(g, r, "10k", "SOM_BOOT_MODE1", "GND", fields={"Note": "Strap values per Variscite boot-mode table (eMMC boot)"})
    g.newrow()
    g.place("Switch:SW_Push", "SW501", "Reset", {"1": "SOM_POR_B", "2": "GND"},
            footprint="Button_Switch_SMD:SW_SPST_PTS810")
    g.place("Connector_Generic:Conn_01x03", "J501", "Debug UART (DNP)", {"1": "DBG_TXD", "2": "DBG_RXD", "3": "GND"},
            footprint="Connector_PinHeader_2.54mm:PinHeader_1x03_P2.54mm_Vertical", dnp=True)
    sh.text("Fit the debug console for development only. Production builds disable it (see THREAT_MODEL.md).",
            330, g.bottom() + 5)
    return sh


# =====================================================================================
# Sheet: Ethernet
# =====================================================================================
def sheet_ethernet():
    sh = Sheet("ethernet.kicad_sch", "Ethernet: client and cluster ports", paper="A2")
    r = Refs(600)
    sh.text("Ethernet: client port from the SOM's on-module GbE PHY; cluster port from a KSZ9031RNX on ENET_QOS (RGMII)",
            15, 15, size=2.5, bold=True)
    f = Flow(sh, 15, 25, 290, "Client port (IF-01): SOM PHY MDI -> magjack")
    mj = {"MX%d+" % (i + 1): "ETH0_MDI%d_P" % i for i in range(4)}
    mj.update({"MX%d-" % (i + 1): "ETH0_MDI%d_N" % i for i in range(4)})
    mj.update({"CT": "ETH0_CT", "LED_L_A": "+3V3", "LED_L_K": "ETH0_LEDL_K", "LED_R_A": "+3V3",
               "LED_R_K": "ETH0_LEDR_K", "SHIELD": "CHASSIS"})
    f.place(MAGJACK, "J601", "RJ45 GbE magjack", mj, footprint="")
    C(f, r, "100n", "ETH0_CT")
    R(f, r, "330", "ETH0_LEDL_K", "ETH0_LED_LINK")
    R(f, r, "330", "ETH0_LEDR_K", "ETH0_LED_ACT")
    f.newrow()
    sh.text("Center-tap treatment depends on the PHY driver type (Variscite datasheet).", 15, f.bottom() + 3)
    f.cy = f.bottom() + 8
    f.newrow()
    R(f, r, "1M", "CHASSIS", "GND")
    C(f, r, "1n 2kV", "CHASSIS", "GND", fp=FP_C1206)
    f.place("power:PWR_FLAG", "#FLG601", "PWR_FLAG", {"1": "CHASSIS"})

    g = Flow(sh, 300, 25, 580, "Cluster port (IF-12): KSZ9031RNXCA, VDDIO 1.8 V")
    phy = {"1": "+3V3", "12": "+3V3", "4": "+1V2_PHY", "9": "+1V2_PHY", "44": "+1V2_PHY",
           "14": "+1V2_PHY", "18": "+1V2_PHY", "23": "+1V2_PHY", "26": "+1V2_PHY", "30": "+1V2_PHY", "39": "+1V2_PHY",
           "16": "+1V8", "34": "+1V8", "40": "+1V8", "29": "GND", "49": "GND",
           "2": "ETH1_TRX_A_P", "3": "ETH1_TRX_A_N", "5": "ETH1_TRX_B_P", "6": "ETH1_TRX_B_N",
           "7": "ETH1_TRX_C_P", "8": "ETH1_TRX_C_N", "10": "ETH1_TRX_D_P", "11": "ETH1_TRX_D_N",
           "15": "ETH1_LED2", "17": "ETH1_LED1",
           "19": "RGMII_TXD0", "20": "RGMII_TXD1", "21": "RGMII_TXD2", "22": "RGMII_TXD3",
           "24": "RGMII_TXC", "25": "RGMII_TX_CTL",
           "27": "RGMII_RXD3", "28": "RGMII_RXD2", "31": "RGMII_RXD1", "32": "RGMII_RXD0",
           "33": "RGMII_RX_CTL", "35": "RGMII_RXC", "36": "ETH1_MDC", "37": "ETH1_MDIO", "38": "ETH1_INT_N",
           "41": "ETH1_LED_MODE", "42": "ETH1_RST_N", "43": "NC", "45": "ETH1_XO", "46": "ETH1_XI", "48": "ETH1_ISET"}
    g.place("Interface_Ethernet:KSZ9031RNXCA", "U601", "KSZ9031RNXCA", phy)
    g.newrow()
    g.place("Device:Crystal_GND24", "Y601", "25MHz", {"1": "ETH1_XI", "3": "ETH1_XO", "2": "GND", "4": "GND"},
            footprint="Crystal:Crystal_SMD_3225-4Pin_3.2x2.5mm")
    C(g, r, "15p", "ETH1_XI")
    C(g, r, "15p", "ETH1_XO")
    R(g, r, "12.1k 1%", "ETH1_ISET", "GND")
    g.newrow()
    sh.text("Straps: MODE[3:0] = 1111 (RGMII, all speeds), PHYAD = 0b001, CLK125 off, single-LED mode", 300, g.cy + 2,
            size=1.5, bold=True)
    g.cy += 6
    for i in range(4):
        R(g, r, "10k", "RGMII_RXD%d" % i, "+1V8")
    R(g, r, "10k", "RGMII_RX_CTL", "GND")
    R(g, r, "10k", "RGMII_RXC", "GND")
    g.newrow()
    R(g, r, "10k", "ETH1_LED_MODE", "+1V8")
    R(g, r, "1.5k", "ETH1_MDIO", "+1V8")
    R(g, r, "10k", "ETH1_INT_N", "+1V8")
    R(g, r, "10k", "ETH1_RST_N", "GND")

    y = max(f.bottom(), g.bottom()) + 18
    h = Flow(sh, 15, y, 580, "Cluster magjack and PHY decoupling")
    mj = {"MX1+": "ETH1_TRX_A_P", "MX1-": "ETH1_TRX_A_N", "MX2+": "ETH1_TRX_B_P", "MX2-": "ETH1_TRX_B_N",
          "MX3+": "ETH1_TRX_C_P", "MX3-": "ETH1_TRX_C_N", "MX4+": "ETH1_TRX_D_P", "MX4-": "ETH1_TRX_D_N",
          "CT": "ETH1_CT", "LED_L_A": "+3V3", "LED_L_K": "ETH1_LEDL_K", "LED_R_A": "+3V3", "LED_R_K": "ETH1_LEDR_K",
          "SHIELD": "CHASSIS"}
    h.place(MAGJACK, "J602", "RJ45 GbE magjack", mj, footprint="")
    C(h, r, "100n", "ETH1_CT")
    R(h, r, "1k", "ETH1_LEDL_K", "ETH1_LED1")
    R(h, r, "1k", "ETH1_LEDR_K", "ETH1_LED2")
    h.newrow()
    decouple(h, r, "+3V3", ["10u", "100n", "100n"])
    decouple(h, r, "+1V2_PHY", ["10u", "100n", "100n", "100n", "100n"])
    decouple(h, r, "+1V8", ["10u", "100n", "100n"])
    sh.text("KSZ9031 MDI is voltage-mode: magjack centre taps go to GND through 100 nF only, never to a supply. "
            "LDO_O is unused because 1.2 V comes from U108.", 15, h.bottom() + 5)
    sh.text("The BOM links a DP83825I, which is a 10/100 RMII PHY. A gigabit RGMII PHY is drawn here to match "
            "the BOM's description.", 15, h.bottom() + 9)
    return sh


# =====================================================================================
# Sheet: storage + USB
# =====================================================================================
def sheet_storage():
    sh = Sheet("storage_usb.kicad_sch", "NVMe and USB card reader", paper="A3")
    r = Refs(700)
    sh.text("NVMe audit ring (IF-08, PCIe x1) and front-panel USB for the CCID card reader (IF-07)", 15, 15, size=2.5, bold=True)
    f = Flow(sh, 15, 25, 270, "M.2 M-key 2280, PCIe Gen3 x1")
    m2 = {"3.3V": "+3V3_NVME", "GND": "GND",
          "PETn0/SATA-A-": "PCIE_RX_N", "PETp0/SATA-A+": "PCIE_RX_P",
          "PERn0/SATA-B+": "M2_PER0_N", "PERp0/SATA-B-": "M2_PER0_P",
          "REFCLKn": "PCIE_REFCLK_N", "REFCLKp": "PCIE_REFCLK_P",
          "~{PERST}": "PCIE_PERST_N", "~{CLKREQ}": "PCIE_CLKREQ_N", "~{PEWAKE}": "PCIE_WAKE_N",
          "DAS/~{DSS}/~{LED1}": "NC", "DEVSLP": "NC", "SUSCLK": "NC", "PEDET": "NC"}
    for ln in (1, 2, 3):
        for k in ("PETn%d", "PETp%d", "PERn%d", "PERp%d"):
            m2[k % ln] = "NC"
    f.place("Connector:Bus_M.2_Socket_M", "J701", "M.2 M-key", m2,
            footprint="Connector_M.2:M.2_M-Key")
    f.newrow()
    C(f, r, "220n", "PCIE_TX_P", "M2_PER0_P", rot=90)
    C(f, r, "220n", "PCIE_TX_N", "M2_PER0_N", rot=90)
    R(f, r, "10k", "PCIE_CLKREQ_N", "+3V3_NVME")
    R(f, r, "10k", "PCIE_WAKE_N", "+3V3_NVME")
    f.newrow()
    decouple(f, r, "+3V3_NVME", ["47u", "10u", "100n", "100n"])
    sh.text("Host TX AC-coupling caps sit on the carrier. The SSD supplies its own TX caps.", 15, f.bottom() + 5)

    g = Flow(sh, 290, 25, 410, "USB-A for the CCID smartcard reader")
    g.place("Power_Management:TPS22917DBV", "U701", "TPS22917DBV",
            {"VIN": "+5V", "GND": "GND", "ON": "USB1_VBUS_EN", "CT": "NC", "QOD": "+5V_USB", "VOUT": "+5V_USB"})
    R(g, r, "100k", "USB1_VBUS_EN", "GND")
    g.newrow()
    g.place("Connector:USB_A", "J702", "USB-A", {"VBUS": "+5V_USB", "D-": "USB1_DN", "D+": "USB1_DP", "GND": "GND",
                                                 "Shield": "CHASSIS"},
            footprint="Connector_USB:USB_A_Molex_67643_Horizontal")
    g.newrow()
    g.place("Power_Protection:USBLC6-2P6", "U702", "USBLC6-2P6",
            {"1": "USB1_DP", "6": "USB1_DP", "3": "USB1_DN", "4": "USB1_DN", "2": "GND", "5": "+5V_USB"})
    decouple(g, r, "+5V_USB", ["10u", "100n"])
    return sh


# =====================================================================================
# top + write
# =====================================================================================
BUILDERS = [sheet_power, sheet_fpga, sheet_supervisor, sheet_sensors, sheet_soc, sheet_ethernet, sheet_storage]
sheets = [b() for b in BUILDERS]
# promote nets used on more than one sheet to global labels, then rebuild so spacing accounts for them
seen = {}
for sh in sheets:
    for n in sh.nets_here:
        seen.setdefault(n, set()).add(sh.fname)
kgen.GLOBAL_NETS.update(n for n, s in seen.items() if len(s) > 1)
sheets = [b() for b in BUILDERS]

prj = Project("openhsm-carrier", OUT)
top = prj.root
top.text("OpenHSM signing node: carrier board (draft generated from the openHSM repo, v0.6.x docs)", 20, 20, size=3, bold=True)
pos = [(30, 45, "Power path and rails; AON domain"), (110, 45, "FPGA signing module (IF-02/03/04)"),
       (190, 45, "STM32U5 tamper supervisor (IF-05/06)"), (270, 45, "Mesh, lid, light, accel, key-switch, TRNG"),
       (30, 110, "i.MX 8M Plus SOM"), (110, 110, "Client + cluster Ethernet"), (190, 110, "NVMe + USB card reader")]
for sh, (x, y, desc) in zip(sheets, pos):
    prj.add_sheet(sh, x, y, w=60.96, h=30.48)
    top.text(desc, x, y + 36, size=1.5)
notes = [
    "Tamper enclosure contents: FPGA signing module, STM32U5 supervisor, sensors, battery (SYSTEM_DESIGN 3).",
    "SoC <-> FPGA: SPI mode 0 up to 12.5 MHz (ECSPI), every command and response HMAC'd (IF-02, protocol 0xB3). SoC never sees S.",
    "Supervisor -> FPGA: receive-only SPI frame 0xA5||S, tamper line (fail-safe pull-up), ceremony pin (fail-closed pull-down).",
    "Decisions made for this draft (verify): XC7A50T-FTG256 with BBRAM key on VCCBATT; FPGA only (no SE050); UART for IF-05;",
    "  BAT54C diode-OR instead of TPS2117; ADXL363 instead of AIS328DQ; KSZ9031RNX instead of DP83825I; generic GbE magjack and",
    "  functional SOM symbol (pin numbers to be mapped). Mesh pair 1 on hardware TAMP, pairs 2-4 GPIO-scanned (LQFP64 has 3 TAMP pins).",
]
for i, t in enumerate(notes):
    top.text(t, 20, 175 + i * 5, size=1.5)
prj.write()
print("wrote", OUT, "globals:", len(kgen.GLOBAL_NETS))
