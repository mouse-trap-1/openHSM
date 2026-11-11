#!/usr/bin/env python3
"""
Independent reference arithmetic for the checks in verify_*.py: secp256k1 point arithmetic,
ECDSA verification and the ECIES construction of the signing node.  Plain Python integers,
written for clarity and not for speed or side-channel resistance.  Never use it to sign.
"""
import hashlib
import hmac

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
SEAL_AAD = b"KEK-SEAL-v1" + bytes(5)
ECIES_AAD = b"KEK-ECIES-v1" + bytes(4)

def on_curve(pt):
    if pt is None:
        return False
    x, y = pt
    return 0 <= x < P and 0 <= y < P and (y * y - x * x * x - 7) % P == 0

def ec_add(a, b):
    if a is None: return b
    if b is None: return a
    (x1, y1), (x2, y2) = a, b
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if a == b:
        lam = 3 * x1 * x1 * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return x3, (lam * (x1 - x3) - y1) % P

def ec_mul(k, pt=G):
    acc = None
    while k:
        if k & 1:
            acc = ec_add(acc, pt)
        pt = ec_add(pt, pt)
        k >>= 1
    return acc

def ref_verify(pub, z, r, s):
    """ECDSA verification; z is the digest as an integer."""
    if not (1 <= r < N and 1 <= s < N and on_curve(pub)):
        return False
    w = pow(s, -1, N)
    pt = ec_add(ec_mul(z % N * w % N), ec_mul(r * w % N, pub))
    return pt is not None and pt[0] % N == r

def b32(i):
    return i.to_bytes(32, "big")

def ecies_key(shared_x, T, E):
    return hmac.new(b32(shared_x), b"ECIES-KEK-v1" + b32(T[0]) + b32(T[1]) + b32(E[0]) + b32(E[1]), hashlib.sha256).digest()

def ecies_decrypt(ed, T, iv, ct, tag):
    """Recipient side: ed = enrolment private key, T = sender's ephemeral public key."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    assert on_curve(T)
    shared = ec_mul(ed, T)
    return AESGCM(ecies_key(shared[0], T, ec_mul(ed))).decrypt(iv, ct + tag, ECIES_AAD)

if __name__ == "__main__":
    assert on_curve(G) and ec_mul(N) is None and ec_mul(N - 1)[0] == G[0]
    # RFC 6979 A.2.5-style check on secp256k1 is not published; use a known signature instead
    d = 1; z = int.from_bytes(hashlib.sha256(b"x").digest(), "big"); k = 7
    R = ec_mul(k); r = R[0] % N; s = pow(k, -1, N) * (z + r * d) % N
    assert ref_verify(ec_mul(d), z, r, s) and not ref_verify(ec_mul(d), z ^ 1, r, s)
    print("refmodel self-test OK")
