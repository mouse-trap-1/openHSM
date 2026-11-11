#!/usr/bin/env python3
"""
Test vectors for the unit testbenches, computed with refmodel.py and Python's hmac/hashlib.
Deterministic (fixed seed), so the files are reproducible.

  vectors.mem       tb_ecdsa_sign.v   7 x (d, k, z, r, s); s in the low half (LOW_S = 1)
  tb_core_pub.vh    tb_ecdsa_sign.v   public-key mode, and signing from a randomised
                                      projective start point (must give the same r, s)
  tb_hmac_vecs.vh   tb_hash_nonce.v   HMAC-SHA256 for message lengths 0..183, including the
                                      161-byte command frame and the 172-byte response frame
  tb_rfc_vecs.vh    tb_hash_nonce.v   RFC 6979 nonces, plain and hedged
"""
import hashlib
import hmac
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import refmodel as g

def sign(d, k, z):
    r = g.ec_mul(k)[0] % g.N
    s = pow(k, -1, g.N) * (z + r * d) % g.N
    return r, min(s, g.N - s)

def main(out):
    rnd = random.Random(5)
    cases = [(1, 1, 0), (g.N - 1, g.N - 1, (1 << 256) - 1)]           # edge scalars, digest >= n
    cases += [(rnd.randrange(1, g.N), rnd.randrange(1, g.N), rnd.getrandbits(256)) for _ in range(5)]
    with open(os.path.join(out, "vectors.mem"), "w") as f:
        for d, k, z in cases:
            r, s = sign(d, k, z)
            assert r and s and g.ref_verify(g.ec_mul(d), z, r, s)
            for v in (d, k, z, r, s):
                f.write(f"{v:064x}\n")
    print(f"wrote vectors.mem ({len(cases)} vectors)")

    h = lambda v: f"256'h{v:064x}"
    with open(os.path.join(out, "tb_core_pub.vh"), "w") as f:
        for d in (1, g.N - 1, rnd.randrange(1, g.N)):
            x, y = g.ec_mul(d)
            f.write(f"run_pub({h(d)}, {h(x)}, {h(y)});\n")
        for lam in (2, rnd.randrange(1, g.P)):                          # same signature from (lam*Gx : lam*Gy : lam)
            d, k, z = cases[2]
            r, s_ = sign(d, k, z)
            f.write(f"run_randz({h(d)}, {h(k)}, {h(z)}, {h(lam * g.G[0] % g.P)}, {h(lam * g.G[1] % g.P)}, {h(lam)}, {h(r)}, {h(s_)});\n")
    print("wrote tb_core_pub.vh")

    with open(os.path.join(out, "tb_hmac_vecs.vh"), "w") as f:
        for n in (0, 1, 7, 9, 29, 30, 32, 55, 56, 64, 119, 120, 140, 161, 172, 183):
            key, msg = rnd.randbytes(32), rnd.randbytes(n)
            mac = hmac.new(key, msg, hashlib.sha256).hexdigest()
            f.write(f"run_hmac(256'h{key.hex()}, 1536'h{(msg + bytes(192 - n)).hex()}, 8'd{n}, 256'h{mac});\n")
    print("wrote tb_hmac_vecs.vh")

    sat = rfc6979(1, hashlib.sha256(b"Satoshi Nakamoto").digest())
    assert sat == 0x8F8A276C19F4149656B280621E358CCE24F5F52542772691EE69063B74F15D15, "RFC 6979 reference is wrong"
    with open(os.path.join(out, "tb_rfc_vecs.vh"), "w") as f:
        f.write(f"run_rfc({h(1)}, 256'h{hashlib.sha256(b'Satoshi Nakamoto').hexdigest()}, 256'd0, 1'b0, {h(sat)});\n")
        for i in range(4):
            x, h1, extra = rnd.randrange(1, g.N), rnd.randbytes(32), rnd.randbytes(32)
            if i == 0:
                h1 = b"\xff" * 32                                         # digest >= n
            f.write(f"run_rfc({h(x)}, 256'h{h1.hex()}, 256'd0, 1'b0, {h(rfc6979(x, h1))});\n")
            f.write(f"run_rfc({h(x)}, 256'h{h1.hex()}, 256'h{extra.hex()}, 1'b1, {h(rfc6979(x, h1, extra))});\n")
    print("wrote tb_rfc_vecs.vh")

def rfc6979(x, h1, extra=b""):
    """RFC 6979 section 3.2 with HMAC-SHA256 for secp256k1; `extra` is appended to the seed (hedged nonce)."""
    H = lambda k, m: hmac.new(k, m, hashlib.sha256).digest()
    seed = x.to_bytes(32, "big") + (int.from_bytes(h1, "big") % g.N).to_bytes(32, "big") + extra
    V, K = b"\x01" * 32, b"\x00" * 32
    K = H(K, V + b"\x00" + seed); V = H(K, V)
    K = H(K, V + b"\x01" + seed); V = H(K, V)
    while True:
        V = H(K, V)
        k = int.from_bytes(V, "big")
        if 1 <= k < g.N:
            return k
        K = H(K, V + b"\x00"); V = H(K, V)

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
