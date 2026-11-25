"""Connectivity checks on the kicad-cli XML netlist (KiCad 7 CLI has no ERC)."""
import sys, re, collections
import xml.etree.ElementTree as ET

r = ET.parse(sys.argv[1]).getroot()
comps = {c.get("ref"): c.findtext("value") for c in r.iter("comp")}
nets = {}
for n in r.iter("net"):
    nets[n.get("name")] = [(x.get("ref"), x.get("pin"), x.get("pintype") or "", x.get("pinfunction") or "") for x in n.iter("node")]

import json
flagged = set(json.load(open("/tmp/flagged.json")))
problems = []
# 1. named nets with only one node -> dangling label or missing connection
for name, nodes in nets.items():
    if name.startswith("unconnected-"):
        continue
    real = [x for x in nodes if not x[0].startswith("#")]
    if len(real) < 2:
        problems.append("single-node net %s: %s" % (name, nodes))

# 2. unconnected pins not flagged no_connect (pintype ends with +no_connect when flagged)
unconn = [(name, nodes) for name, nodes in nets.items() if name.startswith("unconnected-")]
unflagged = [(n, x) for n, x in unconn if not any("no_connect" in y[2] for y in x)]
nc_flagged = len(unconn) - len(unflagged)

# 3. driver conflicts and undriven power inputs
for name, nodes in nets.items():
    types = [x[2] for x in nodes]
    outs = [x for x in nodes if x[2] in ("output", "power_out") and not x[0].startswith("#FLG")]
    if len([x for x in nodes if x[2] == "power_out"]) > 1:
        problems.append("multiple power_out on %s: %s" % (name, [x[:2] for x in nodes if x[2] == "power_out"]))
    if len([x for x in nodes if x[2] == "output"]) > 1:
        problems.append("multiple outputs on %s: %s" % (name, [x[:2] for x in nodes if x[2] == "output"]))
    has_pin = any(t.startswith("power_in") for t in types)
    driven = any(t in ("power_out",) for t in types) or name.split("/")[-1] in flagged
    if has_pin and not driven and not name.startswith("unconnected-"):
        problems.append("power_in not driven on %s" % name)

# 4. expected interface endpoints from the ICD
expect = {
    "SN_HOST_SCLK": {"U201"}, "SN_HOST_MOSI": {"U201"}, "SN_HOST_CS_N": {"U201"}, "SN_HOST_MISO": {"U501"},
    "SOC_HOST_SCLK": {"U501"}, "SOC_HOST_MOSI": {"U501"}, "SOC_HOST_CS_N": {"U501"}, "FPGA_HOST_MISO": {"U201"},
    "SN_SPI_SCLK": {"U201", "U301"}, "SN_SPI_MOSI": {"U201", "U301"}, "SN_SPI_CS_N": {"U201", "U301"},
    "SN_TAMPER": {"U201", "U301"}, "SN_CEREMONY": {"U201", "U301"}, "FPGA_RST_N": {"U201", "U301"},
    "FPGA_DONE": {"U201", "U301"}, "FPGA_VBATT": {"U201"}, "CLK_100M": {"U201", "X201"},
    "SUP_TX": {"U301"}, "SOC_SUP_RXD": {"U501"}, "SOC_PWR_EN": {"U301", "U103"},
    "MESH1_OUT": {"U301", "J401"}, "MESH1_IN": {"U301", "J401"}, "MESH4_IN": {"U301", "J401"},
    "LID_LOOP": {"U301", "J402"}, "LIGHT_TRIP": {"U301", "U401"}, "ACC_INT1": {"U301", "U402"},
    "CEREMONY_SW_IN": {"U301"}, "TRNG_ANALOG": {"U301"},
    "RGMII_TXD0": {"U501", "U601"}, "RGMII_RXC": {"U501", "U601"}, "ETH1_MDIO": {"U501", "U601"},
    "PCIE_RX_P": {"U501", "J701"}, "PCIE_REFCLK_P": {"U501", "J701"}, "USB1_DP": {"U501", "J702", "U702"},
    "VDD_TAMPER": {"U301", "U401", "U402"}, "VBAT_CELL": {"U301", "BT101"},
}
for net, refs in expect.items():
    key = [k for k in nets if k.split("/")[-1] == net]
    if not key:
        problems.append("expected net missing: %s" % net)
        continue
    have = {x[0] for x in nets[key[0]]}
    if not refs <= have:
        problems.append("net %s missing %s (has %s)" % (net, refs - have, sorted(have)))

# 5. host SPI (IF-02): each SoC-side net reaches its FPGA-side net through one series resistor
def _net(name):
    k = [k for k in nets if k.split("/")[-1] == name]
    return {x[0] for x in nets[k[0]]} if k else set()
for a, b in (("SOC_HOST_SCLK", "SN_HOST_SCLK"), ("SOC_HOST_MOSI", "SN_HOST_MOSI"),
             ("SOC_HOST_CS_N", "SN_HOST_CS_N"), ("FPGA_HOST_MISO", "SN_HOST_MISO")):
    if not any(ref.startswith("R") for ref in _net(a) & _net(b)):
        problems.append("no series resistor between %s and %s" % (a, b))
for old in ("I2C_SN_SCL", "I2C_SN_SDA"):
    if _net(old):
        problems.append("stale I2C net still present: %s" % old)

print("components:", len([c for c in comps if not c.startswith("#")]))
print("nets:", len(nets), " no-connect pins:", nc_flagged, " unconnected & unflagged pins:", len(unflagged))
for n, x in unflagged[:40]:
    print("  UNFLAGGED", n, x)
print("problems:", len(problems))
for p in problems:
    print("  ", p)
