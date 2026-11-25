#!/usr/bin/env python3
"""
Independent check of the protocol 0xB2 simulation log (tb_v05.v), using only Python's hmac,
the `cryptography` library and refmodel.py.  From what appeared on the bus (plus the
testbench's peek of the KEK) it verifies that
  * X1  every logged response MAC equals HMAC-SHA256(chan_key, "SN-RESP-v1"||nonce||ctr||cmd||
        error||wid||iv||tag||A||B||C), for successful and for failed commands
  * X3  both released signatures verify against the wallet's public key and are low-s, and the
        two faulted signing runs released nothing
  * X5  the value sent in BUF_B to SHARE_GET_C is the card secret XOR
        HMAC-SHA256(chan_key, "SN-CONF-v1"||nonce||ctr); each wrapped share opens with the
        unmasked card secret; any 2 of the 3 shares rebuild the KEK and no single one does
Usage: python3 verify_v05.py v05.log
"""
import hashlib
import hmac
import itertools
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gen_shamir as sh
import refmodel as g
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def H(key, msg):
    return hmac.new(key, msg, hashlib.sha256).digest()

def one(t, key, n=64):
    m = re.search(rf"^{re.escape(key)}=?\s*([0-9a-fA-F]{{{n}}})", t, re.M)
    assert m, f"missing {key}"
    return bytes.fromhex(m.group(1))

def fields(line):
    return {k: bytes.fromhex(v) for k, v in re.findall(r"(\w+)=([0-9a-f]+)", line)}

def main(path):
    t = open(path).read()
    assert "FAIL" not in t, "testbench reported failures"
    assert "ALL V0.5 PROTOCOL TESTS PASSED" in t, "testbench did not finish cleanly"

    chan = H(one(t, "S0"), b"SN-CHAN")
    nonce = one(t, "NONCE0", 32)
    kek = one(t, "KEK")

    # ---- X1
    resp = [fields(m.group(1)) for m in re.finditer(r"^RESP (.*)$", t, re.M)]
    assert len(resp) >= 12
    errs = set()
    for r in resp:
        msg = b"SN-RESP-v1" + nonce + r["ctr"] + r["cmd"] + r["err"] + r["wid"] + r["iv"] + r["tag"] + r["A"] + r["B"] + r["C"]
        assert len(msg) == 172
        assert H(chan, msg) == r["rmac"], f"response MAC mismatch for cmd {r['cmd'].hex()} ctr {r['ctr'].hex()}"
        errs.add(r["err"][0])
        if r["err"][0]:
            assert not any(r["iv"] + r["tag"] + r["A"] + r["B"] + r["C"]), "data left in the buffers after an error"
    assert {0, 6, 8, 10} <= errs
    print(f"[ok] X1: {len(resp)} response MACs recomputed (errors seen: {sorted(errs)}); X4: failed commands returned all-zero buffers")

    # ---- wallet and signatures (X3)
    w = fields(re.search(r"^WALLET (.*)$", t, re.M).group(1))
    d = int.from_bytes(AESGCM(kek).decrypt(w["iv"], w["ct"] + w["tag"], w["wid"]), "big")
    pub = (int.from_bytes(one(t, "PUBX"), "big"), int.from_bytes(one(t, "PUBY"), "big"))
    assert g.ec_mul(d) == pub
    sigs = []
    for tag, hk in (("SIG1", "HASH1"), ("SIG2", "HASH2")):
        r = int(re.search(rf"^{tag} r=([0-9a-f]{{64}})", t, re.M).group(1), 16)
        s = int(re.search(rf"^{tag} s=([0-9a-f]{{64}})", t, re.M).group(1), 16)
        z = int.from_bytes(one(t, hk), "big")
        assert 1 <= r < g.N and 1 <= s <= g.N // 2
        assert g.ref_verify(pub, z, r, s), f"{tag} does not verify"
        sigs.append((r, s))
    assert int.from_bytes(one(t, "HASH2"), "big") >= g.N
    assert len(re.findall(r"^X3 .* caught at SIGN step (8|9)$", t, re.M)) == 2
    sign_fail = [r for r in resp if r["cmd"] == b"\x21" and r["err"] == b"\x06"]
    assert len(sign_fail) == 2
    print("[ok] X3: both released signatures verify (one over a digest >= n) and are low-s; the two faulted runs released nothing")

    # ---- X5
    tmpl = one(t, "TEMPLATE", 32)
    assert tmpl[:3] == bytes([0, 2, 3]) and tmpl[3:] == H(kek, b"KEK-FP-v1")[:13]
    masked = {int(m.group(1)): (bytes.fromhex(m.group(2)), bytes.fromhex(m.group(3)))
              for m in re.finditer(r"^BUSB x=(\d+) ctr=([0-9a-f]{8}) masked=([0-9a-f]{64})", t, re.M)}
    assert sorted(masked) == [1, 2]
    for x, (ctr, mb) in masked.items():
        r = bytes([x]) * 32
        pad = H(chan, b"SN-CONF-v1" + nonce + ctr)
        assert bytes(a ^ b for a, b in zip(mb, pad)) == r and mb != r
    shares = {}
    for m in re.finditer(r"^SHARE x=(\d+) hdr=([0-9a-f]{32}) iv=([0-9a-f]{24}) tag=([0-9a-f]{32}) ct=([0-9a-f]{64})", t, re.M):
        x = int(m.group(1)); hdr = bytes.fromhex(m.group(2))
        iv, tag, ct = (bytes.fromhex(m.group(i)) for i in (3, 4, 5))
        assert hdr[0] == x and hdr[1:] == tmpl[1:]
        shares[x] = AESGCM(sh.share_wrap_key(bytes([x]) * 32, hdr)).decrypt(iv, ct + tag, hdr)
        if x in masked:                                  # the value on the bus must not open the share
            try:
                AESGCM(sh.share_wrap_key(masked[x][1], hdr)).decrypt(iv, ct + tag, hdr)
                raise SystemExit("share opens with the masked bus value!")
            except Exception as ex:
                if isinstance(ex, SystemExit): raise
    assert sorted(shares) == [1, 2, 3]
    for c in itertools.combinations(sorted(shares), 2):
        assert sh.combine([(x, shares[x]) for x in c]) == kek
    assert all(shares[x] != kek for x in shares)
    print("[ok] X5: bus value = card secret XOR keystream; shares open only with the real card secret; any 2 of 3 rebuild the KEK")
    print("ALL EXTERNAL V0.5 CHECKS PASSED")

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "v05.log")
