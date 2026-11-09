#!/usr/bin/env python3
"""
Microcode generator + bit-exact reference model for the secp256k1 ECDSA signer.

* Defines the microprograms (point add / double, inversion step, finalisation)
* Interprets them exactly as the hardware sequencer does (asserting that every
  multiplier operand is already reduced, which the hardware requires)
* Checks the result against an independent textbook ECDSA implementation
* Emits ecdsa_ucode_rom.v and vectors.mem for the Verilog testbench

Usage:  python3 gen_ucode.py [outdir]
"""
import os
import random
import sys

# ---------------------------------------------------------------- curve ----
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
B3 = 21  # 3*b, b = 7
HALF_N = N >> 1

# ------------------------------------------------------ register mapping ---
REGS = [
    "X0", "Y0", "Z0",        # 0-2   ladder accumulator R0
    "X1", "Y1", "Z1",        # 3-5   ladder accumulator R1
    "t0", "t1", "t2", "t3", "t4",   # 6-10 temporaries
    "SX", "SY", "SZ",        # 11-13 sum output
    "DX", "DY", "DZ",        # 14-16 doubling output
    "B3", "ONE", "ZERO",     # 17-19 constants
    "K", "D", "H",           # 20-22 nonce, private key, message hash
    "R", "S", "ACC", "BASE", "TMP", "T5",  # 23-28
]
IDX = {n: i for i, n in enumerate(REGS)}
assert len(REGS) <= 32

OP_END, OP_MUL, OP_ADD, OP_SUB = 0, 1, 2, 3

# ------------------------------------------------------- microprograms -----
def M(d, a, b, mod=0): return (OP_MUL, mod, d, a, b)
def A(d, a, b, mod=0): return (OP_ADD, mod, d, a, b)
def S(d, a, b, mod=0): return (OP_SUB, mod, d, a, b)

# Renes-Costello-Batina complete addition, a=0, b3=21 (Algorithm 7)
# P=(X0,Y0,Z0)  Q=(X1,Y1,Z1)  out=(SX,SY,SZ)
PT_ADD = [
    M("t0", "X0", "X1"), M("t1", "Y0", "Y1"), M("t2", "Z0", "Z1"),
    A("t3", "X0", "Y0"), A("t4", "X1", "Y1"), M("t3", "t3", "t4"),
    A("t4", "t0", "t1"), S("t3", "t3", "t4"), A("t4", "Y0", "Z0"),
    A("SX", "Y1", "Z1"), M("t4", "t4", "SX"), A("SX", "t1", "t2"),
    S("t4", "t4", "SX"), A("SX", "X0", "Z0"), A("SY", "X1", "Z1"),
    M("SX", "SX", "SY"), A("SY", "t0", "t2"), S("SY", "SX", "SY"),
    A("SX", "t0", "t0"), A("t0", "SX", "t0"), M("t2", "B3", "t2"),
    A("SZ", "t1", "t2"), S("t1", "t1", "t2"), M("SY", "B3", "SY"),
    M("SX", "t4", "SY"), M("t2", "t3", "t1"), S("SX", "t2", "SX"),
    M("SY", "SY", "t0"), M("t1", "t1", "SZ"), A("SY", "t1", "SY"),
    M("t0", "t0", "t3"), M("SZ", "SZ", "t4"), A("SZ", "SZ", "t0"),
]

# Renes-Costello-Batina complete doubling, a=0, b3=21 (Algorithm 9)
# in=(X0,Y0,Z0)  out=(DX,DY,DZ)
PT_DBL = [
    M("t0", "Y0", "Y0"), A("DZ", "t0", "t0"), A("DZ", "DZ", "DZ"),
    A("DZ", "DZ", "DZ"), M("t1", "Y0", "Z0"), M("t2", "Z0", "Z0"),
    M("t2", "B3", "t2"), M("DX", "t2", "DZ"), A("DY", "t0", "t2"),
    M("DZ", "t1", "DZ"), A("t1", "t2", "t2"), A("t2", "t1", "t2"),
    S("t0", "t0", "t2"), M("DY", "t0", "DY"), A("DY", "DX", "DY"),
    M("t1", "X0", "Y0"), M("DX", "t0", "t1"), A("DX", "DX", "DX"),
]

# Move the new ladder state into place: R1 <- sum, R0 <- double
MOVE = [
    A("X1", "SX", "ZERO"), A("Y1", "SY", "ZERO"), A("Z1", "SZ", "ZERO"),
    A("X0", "DX", "ZERO"), A("Y0", "DY", "ZERO"), A("Z0", "DZ", "ZERO"),
]

PREP_INVZ = [A("ACC", "ONE", "ZERO"), A("BASE", "Z0", "ZERO")]
PREP_INVK = [A("ACC", "ONE", "ZERO", 1), A("BASE", "K", "ZERO", 1)]
INVP_STEP = [M("ACC", "ACC", "ACC"), M("TMP", "ACC", "BASE")]
INVN_STEP = [M("ACC", "ACC", "ACC", 1), M("TMP", "ACC", "BASE", 1)]

# x = X0 * Z0^-1 (mod p);  r = x mod n
AFFINE = [M("T5", "X0", "ACC"), A("R", "T5", "ZERO", 1)]

# s = k^-1 (z + r d) mod n ;  also T5 = n - s for low-s normalisation
SIGN = [
    M("t1", "R", "D", 1),
    A("H", "H", "ZERO", 1),
    A("t2", "H", "t1", 1),
    M("S", "ACC", "t2", 1),
    S("T5", "ZERO", "S", 1),
]

ROUTINES = [
    ("PT_ADD", PT_ADD), ("PT_DBL", PT_DBL), ("MOVE", MOVE),
    ("PREP_INVZ", PREP_INVZ), ("PREP_INVK", PREP_INVK),
    ("INVP_STEP", INVP_STEP), ("INVN_STEP", INVN_STEP),
    ("AFFINE", AFFINE), ("SIGN", SIGN),
]

def assemble():
    rom, addr = [], {}
    for name, prog in ROUTINES:
        addr[name] = len(rom)
        for (op, mod, d, a, b) in prog:
            rom.append((op, mod, IDX[d], IDX[a], IDX[b]))
        rom.append((OP_END, 0, 0, 0, 0))
    return rom, addr

ROM, ADDR = assemble()

# ------------------------------------------------- microcode interpreter ---
class Machine:
    def __init__(self):
        self.rf = [0] * 32
        self.rf[IDX["B3"]], self.rf[IDX["ONE"]], self.rf[IDX["ZERO"]] = B3, 1, 0
        self.mulcount = 0

    def run(self, name):
        pc = ADDR[name]
        while True:
            op, mod, d, a, b = ROM[pc]
            if op == OP_END:
                return
            m = N if mod else P
            x, y = self.rf[a], self.rf[b]
            if op == OP_MUL:
                assert x < m and y < m, f"unreduced mul operand at pc={pc}"
                self.rf[d] = (x * y) % m
                self.mulcount += 1
            elif op == OP_ADD:
                s = x + y
                assert s < 2 * m
                self.rf[d] = s - m if s >= m else s
            else:
                self.rf[d] = x - y if x >= y else x - y + m
            pc += 1

    def cswap(self, bit):
        if bit:
            for i in range(3):
                self.rf[i], self.rf[3 + i] = self.rf[3 + i], self.rf[i]

    def invert(self, mod_sel):
        m = N if mod_sel else P
        e = m - 2
        step = "INVN_STEP" if mod_sel else "INVP_STEP"
        for i in range(255, -1, -1):
            self.run(step)
            if (e >> i) & 1:
                self.rf[IDX["ACC"]] = self.rf[IDX["TMP"]]

def hw_sign(d, k, z, low_s=True):
    """Bit-exact model of the hardware control flow. Returns (fail, r, s)."""
    if k == 0 or k >= N or d == 0 or d >= N:
        return True, 0, 0
    m = Machine()
    rf = m.rf
    rf[IDX["K"]], rf[IDX["D"]], rf[IDX["H"]] = k, d, z
    rf[IDX["X0"]], rf[IDX["Y0"]], rf[IDX["Z0"]] = 0, 1, 0
    rf[IDX["X1"]], rf[IDX["Y1"]], rf[IDX["Z1"]] = GX, GY, 1
    for i in range(255, -1, -1):
        m.cswap((k >> i) & 1)
        m.run("PT_ADD")
        m.run("PT_DBL")
        m.run("MOVE")
        m.cswap((k >> i) & 1)
    m.run("PREP_INVZ"); m.invert(0)
    m.run("AFFINE")
    if rf[IDX["R"]] == 0:
        return True, 0, 0
    m.run("PREP_INVK"); m.invert(1)
    m.run("SIGN")
    s, nms = rf[IDX["S"]], rf[IDX["T5"]]
    if low_s and s > HALF_N:
        s = nms
    if s == 0:
        return True, 0, 0
    return False, rf[IDX["R"]], s

# ------------------------------------------- independent reference ECDSA ---
def ec_add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1; x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = 3 * x1 * x1 * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return x3, (lam * (x1 - x3) - y1) % P

def ec_mul(k, pt=(GX, GY)):
    r = None
    while k:
        if k & 1: r = ec_add(r, pt)
        pt = ec_add(pt, pt)
        k >>= 1
    return r

def ref_sign(d, k, z, low_s=True):
    R = ec_mul(k)
    r = R[0] % N
    s = pow(k, -1, N) * (z + r * d) % N
    if low_s and s > HALF_N:
        s = N - s
    return r, s

def ref_verify(Q, z, r, s):
    w = pow(s, -1, N)
    pt = ec_add(ec_mul(z * w % N), ec_mul(r * w % N, Q))
    return pt is not None and pt[0] % N == r

# ------------------------------------------------ formula unit tests -------
def proj_to_aff(X, Y, Z):
    if Z == 0: return None
    zi = pow(Z, -1, P)
    return X * zi % P, Y * zi % P

def aff_to_proj(pt):
    return (0, 1, 0) if pt is None else (pt[0], pt[1], 1)

def test_formulas(trials=200):
    rnd = random.Random(1)
    cases = []
    pts = [None, (GX, GY), ec_mul(2), ec_mul(N - 1)]
    pts += [ec_mul(rnd.randrange(1, N)) for _ in range(trials)]
    for a in pts[:8]:
        for b in pts[:8]:
            cases.append((a, b))
    for _ in range(trials):
        cases.append((rnd.choice(pts), rnd.choice(pts)))
    for a, b in cases:
        m = Machine()
        rf = m.rf
        rf[0], rf[1], rf[2] = aff_to_proj(a)
        rf[3], rf[4], rf[5] = aff_to_proj(b)
        m.run("PT_ADD")
        got = proj_to_aff(rf[IDX["SX"]], rf[IDX["SY"]], rf[IDX["SZ"]])
        assert got == ec_add(a, b), ("ADD mismatch", a, b)
        m.run("PT_DBL")
        got = proj_to_aff(rf[IDX["DX"]], rf[IDX["DY"]], rf[IDX["DZ"]])
        assert got == ec_add(a, a), ("DBL mismatch", a)
    print(f"[ok] point add/double microcode: {len(cases)} cases "
          f"(incl. infinity, P+P, P+(-P))")

# ---------------------------------------------------- full-signature tests -
def make_vectors():
    rnd = random.Random(2026)
    v = []
    v.append((1, 1, 0))
    v.append((1, 2, 0xABCDEF))
    v.append((N - 1, N - 1, 2**256 - 1))          # z >= n, max scalars
    v.append((0xC0FFEE, 0x1234567890ABCDEF, N + 12345))
    for _ in range(3):
        v.append((rnd.randrange(1, N), rnd.randrange(1, N), rnd.getrandbits(256)))
    return v

def test_signatures(vectors):
    out = []
    for d, k, z in vectors:
        fail, r, s = hw_sign(d, k, z)
        rr, ss = ref_sign(d, k, z)
        assert not fail and (r, s) == (rr, ss), ("sign mismatch", hex(d), hex(k))
        assert ref_verify(ec_mul(d), z % N, r, s), "signature does not verify"
        out.append((d, k, z, r, s))
    # rejection paths
    assert hw_sign(1, 0, 1)[0] and hw_sign(0, 1, 1)[0]
    assert hw_sign(1, N, 1)[0] and hw_sign(N, 1, 1)[0]
    print(f"[ok] full ECDSA flow: {len(out)} signatures match reference and verify")
    return out

# ----------------------------------------------------------- file output ---
def emit_rom(path):
    names = {v: k for k, v in ADDR.items()}
    lines = []
    lines.append("// AUTO-GENERATED by gen_ucode.py -- do not edit by hand.")
    lines.append("// Instruction word: {op[1:0], mod, rd[4:0], ra[4:0], rb[4:0]}  (18 bits)")
    lines.append("//   op: 0=END 1=MUL 2=ADD 3=SUB    mod: 0=mod p (field), 1=mod n (group order)")
    lines.append("`timescale 1ns/1ps")
    lines.append("module ecdsa_ucode_rom (")
    lines.append("    input  wire [8:0]  addr,")
    lines.append("    output reg  [17:0] instr")
    lines.append(");")
    lines.append("")
    lines.append("    // Routine entry points")
    for name, a in ADDR.items():
        lines.append(f"    //   {name:<10s} = {a}")
    lines.append("")
    lines.append("    always @(*) begin")
    lines.append("        case (addr)")
    for pc, (op, mod, d, a, b) in enumerate(ROM):
        word = (op << 16) | (mod << 15) | (d << 10) | (a << 5) | b
        if op == OP_END:
            cm = "END"
        else:
            sym = {OP_MUL: "*", OP_ADD: "+", OP_SUB: "-"}[op]
            cm = f"{REGS[d]} = {REGS[a]} {sym} {REGS[b]}  (mod {'n' if mod else 'p'})"
        if pc in names:
            lines.append(f"            // ---- {names[pc]} ----")
        lines.append(f"            9'd{pc}: instr = 18'h{word:05X}; // {cm}")
    lines.append("            default: instr = 18'h00000;")
    lines.append("        endcase")
    lines.append("    end")
    lines.append("endmodule")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")

def emit_entries(path):
    with open(path, "w") as f:
        f.write("// AUTO-GENERATED by gen_ucode.py -- microcode routine entry points\n")
        for name, a in ADDR.items():
            f.write(f"localparam [8:0] A_{name} = 9'd{a};\n")
        for name, i in IDX.items():
            f.write(f"localparam [4:0] I_{name} = 5'd{i};\n")

def emit_vectors(path, vecs):
    with open(path, "w") as f:
        for d, k, z, r, s in vecs:
            for w in (d, k, z, r, s):
                f.write(f"{w:064x}\n")

if __name__ == "__main__":
    outdir = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(outdir, exist_ok=True)
    print(f"ROM size: {len(ROM)} words; entry points: {ADDR}")
    test_formulas()
    vecs = test_signatures(make_vectors())
    m = Machine()
    emit_rom(os.path.join(outdir, "ecdsa_ucode_rom.v"))
    emit_entries(os.path.join(outdir, "ecdsa_ucode_entries.vh"))
    emit_vectors(os.path.join(outdir, "vectors.mem"), vecs)
    print("wrote ecdsa_ucode_rom.v, ecdsa_ucode_entries.vh, vectors.mem to", outdir)
