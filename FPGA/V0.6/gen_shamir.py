#!/usr/bin/env python3
"""
Reference model for the byte-wise GF(2^8) Shamir scheme used by shamir_core.v, plus the
header / key-wrap conventions shared by the node and the ceremony tool.

Field      : GF(2^8), reduction polynomial x^8+x^4+x^3+x+1 (0x11B)
Secret     : 32 bytes; byte lane b is shared independently
f_b(x)     : s[b] ^ c1[b]*x ^ c2[b]*x^2 ^ ... ^ c_{m-1}[b]*x^{m-1}   (coefficients are 32-byte words)
Share i    : (x_i, f(x_i)),  x_i in 1..255 (distinct)
Header     : 16 bytes = x(1) || m(1) || n(1) || fp(13);  fp = first 13 bytes of HMAC-SHA256(KEK,"KEK-FP-v1")
Share wrap : K = HMAC-SHA256(key = r, msg = "SHARE-WRAP-v1" || header),  r = 32-byte card-derived secret
             blob = AES-256-GCM(K, iv, aad = header, pt = 32-byte share value)
Card secret: r = HMAC-SHA256(yubikey_response, "SN-CARD-v1" || challenge)
"""
import hashlib
import hmac
import os
import random
import sys

def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = ((a << 1) ^ 0x11B) & 0xFF if a & 0x80 else (a << 1)
        b >>= 1
    return p

def ginv(a):
    r = 1
    for _ in range(254):
        r = gmul(r, a)
    return r

def eval_share(secret: bytes, coefs, x):
    """coefs[k-1] = 32-byte coefficient word of x^k (k = 1..m-1)."""
    out = bytearray(32)
    for b in range(32):
        y = 0
        for c in reversed(coefs):          # Horner, highest degree first
            y = gmul(y, x) ^ c[b]
        out[b] = gmul(y, x) ^ secret[b]
    return bytes(out)

def combine(shares):
    """shares: list of (x, 32-byte y). Lagrange interpolation at 0."""
    out = bytearray(32)
    for i, (xi, yi) in enumerate(shares):
        num, den = 1, 1
        for j, (xj, _) in enumerate(shares):
            if j != i:
                num = gmul(num, xj)
                den = gmul(den, xi ^ xj)
        L = gmul(num, ginv(den))
        for b in range(32):
            out[b] ^= gmul(yi[b], L)
    return bytes(out)

def kek_fp(kek: bytes) -> bytes:
    return hmac.new(kek, b"KEK-FP-v1", hashlib.sha256).digest()[:13]

def header(x, m, n, fp13):
    return bytes([x, m, n]) + fp13

def share_wrap_key(r: bytes, hdr: bytes) -> bytes:
    return hmac.new(r, b"SHARE-WRAP-v1" + hdr, hashlib.sha256).digest()

def card_secret(yk_response: bytes, challenge: bytes) -> bytes:
    return hmac.new(yk_response, b"SN-CARD-v1" + challenge, hashlib.sha256).digest()

def emit_vectors(path):
    rnd = random.Random(21)
    with open(path, "w") as f:
        for (m, n) in ((3, 5), (2, 3), (5, 7), (8, 8)):
            secret = rnd.randbytes(32)
            coefs = [rnd.randbytes(32) for _ in range(m - 1)]
            for k, c in enumerate(coefs, 1):
                f.write(f"set_coef(3'd{k}, 256'h{c.hex()});\n")
            shares = []
            for x in range(1, n + 1):
                y = eval_share(secret, coefs, x)
                shares.append((x, y))
                f.write(f"run_eval(4'd{m}, 8'd{x}, 256'h{secret.hex()}, 256'h{y.hex()});\n")
            # combine: first m shares, last m shares, a random m-subset, and all n
            subsets = [shares[:m], shares[-m:], rnd.sample(shares, m), shares]
            for sub in subsets:
                assert combine(sub) == secret
                f.write("clr_shares;\n")
                for x, y in sub:
                    f.write(f"put_share(8'd{x}, 256'h{y.hex()});\n")
                f.write(f"run_combine(256'h{secret.hex()}, 1'b1);\n")
            # m-1 shares must NOT reveal the secret (result differs)
            if m > 2:
                f.write("clr_shares;\n")
                for x, y in shares[:m - 1]:
                    f.write(f"put_share(8'd{x}, 256'h{y.hex()});\n")
                bad = combine(shares[:m - 1])
                assert bad != secret
                f.write(f"run_combine(256'h{bad.hex()}, 1'b1);\n")
        # rejections: x = 0, duplicate x
        f.write("clr_shares;\n")
        f.write("put_share(8'd0, 256'h1);\n")
        f.write("expect_rej(1'b1);\n")
        f.write("put_share(8'd9, 256'h2);\nexpect_rej(1'b0);\n")
        f.write("put_share(8'd9, 256'h3);\nexpect_rej(1'b1);\n")

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    emit_vectors(os.path.join(out, "tb_shamir_vecs.vh"))
    # sanity: any m of n reconstructs
    s = os.urandom(32); cs = [os.urandom(32) for _ in range(2)]
    sh = [(x, eval_share(s, cs, x)) for x in range(1, 6)]
    import itertools
    assert all(combine(list(c)) == s for c in itertools.combinations(sh, 3))
    print("wrote tb_shamir_vecs.vh; reference round-trip OK")
