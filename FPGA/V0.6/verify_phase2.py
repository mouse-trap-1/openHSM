#!/usr/bin/env python3
"""
Independent check of the Phase 2 system simulation log (tb_phase2.v) with the Python
reference code and the `cryptography` library.  Verifies, from what appeared on the bus:
  * the share header carries m, n and the right KEK fingerprint; KEK_FP = HMAC(KEK,"KEK-FP-v1")
  * every wrapped share decrypts under HMAC(r_x, "SHARE-WRAP-v1"||header) and ANY 3 of the 5
    shares interpolate to the cluster KEK (fewer than 3 do not)
  * the wallet blob made before the "disaster" unwraps under the KEK, and the signature made
    after break-glass recovery verifies against its public key
  * the ECIES-delivered slot-2 KEK decrypts with the recipient's enrolment key; the REWRAPped
    blob opens under KEK2 and holds the SAME wallet key as the old blob
  * the signature node B produced with the new KEK on the rewrapped blob verifies
Usage: python3 verify_phase2.py p2.log
"""
import itertools
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import refmodel as g
import refmodel as e
import gen_shamir as sh
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def one(text, key, n=64):
    m = re.search(rf"^{re.escape(key)}=?\s*([0-9a-fA-F]{{{n}}})", text, re.M)
    assert m, f"missing {key}"
    return bytes.fromhex(m.group(1))

def pairs(text, prefix):
    m = re.search(rf"^{re.escape(prefix)} (.*)$", text, re.M)
    assert m, f"missing line {prefix}"
    return {k: bytes.fromhex(v) for k, v in re.findall(r"(\w+(?:\.\w)?)=([0-9a-f]+)", m.group(1))}

def main(path):
    t = open(path).read()
    assert "FAIL" not in t, "testbench reported failures"
    assert "ALL PHASE 2 SYSTEM TESTS PASSED" in t, "testbench did not finish cleanly"

    kek = one(t, "KEK")
    fp = one(t, "FP")
    assert fp == __import__("hmac").new(kek, b"KEK-FP-v1", __import__("hashlib").sha256).digest()
    print("[ok] KEK_FP equals HMAC-SHA256(KEK, 'KEK-FP-v1')")

    tmpl = one(t, "TEMPLATE", 32)
    assert tmpl[0] == 0 and tmpl[1] == 3 and tmpl[2] == 5 and tmpl[3:] == fp[:13]
    print("[ok] share header template = 00 || m=3 || n=5 || KEK fingerprint")

    shares = {}
    for m in re.finditer(r"^SHARE x=(\d+) hdr=([0-9a-f]{32}) iv=([0-9a-f]{24}) tag=([0-9a-f]{32}) ct=([0-9a-f]{64})", t, re.M):
        x = int(m.group(1)); hdr = bytes.fromhex(m.group(2))
        iv, tag, ct = (bytes.fromhex(m.group(i)) for i in (3, 4, 5))
        assert hdr[0] == x and hdr[1:] == tmpl[1:]
        r = bytes([x]) * 32                                   # tb's stand-in card secret
        y = AESGCM(sh.share_wrap_key(r, hdr)).decrypt(iv, ct + tag, hdr)
        shares[x] = y
        try:
            AESGCM(sh.share_wrap_key(bytes([x ^ 1]) * 32, hdr)).decrypt(iv, ct + tag, hdr)
            raise SystemExit("share opened with the wrong card secret!")
        except Exception as ex:
            if isinstance(ex, SystemExit): raise
    assert sorted(shares) == [1, 2, 3, 4, 5]
    print("[ok] all 5 wrapped shares open only with their own card secret (AAD = header)")

    for c in itertools.combinations(sorted(shares), 3):
        assert sh.combine([(x, shares[x]) for x in c]) == kek
    assert sh.combine([(x, shares[x]) for x in sorted(shares)]) == kek
    for c in itertools.combinations(sorted(shares), 2):
        assert sh.combine([(x, shares[x]) for x in c]) != kek
    print("[ok] every 3 of the 5 shares interpolate to the KEK; no 2 of them do")

    # wallet blob + post-recovery signature
    w = pairs(t, "WALLET")
    d = int.from_bytes(AESGCM(kek).decrypt(w["iv"], w["ct"] + w["tag"], w["wid"]), "big")
    px, py = int.from_bytes(one(t, "PUBX"), "big"), int.from_bytes(one(t, "PUBY"), "big")
    assert g.ec_mul(d) == (px, py)
    z = int.from_bytes(one(t, "HASH"), "big")
    def sig(tag):
        r = int(re.search(rf"^{tag} r=([0-9a-f]{{64}})", t, re.M).group(1), 16)
        s = int(re.search(rf"^{tag} s=([0-9a-f]{{64}})", t, re.M).group(1), 16)
        assert 1 <= r < g.N and 1 <= s <= g.N // 2
        assert g.ref_verify((px, py), z % g.N, r, s), f"{tag} does not verify"
    sig("SIG1")
    print("[ok] after break-glass recovery the node signed with the pre-disaster wallet blob; signature verifies")

    # rotation
    kek2 = one(t, "KEK2")
    assert kek2 != kek
    en = re.search(r"^ENROL ex=([0-9a-f]{64}) ey=([0-9a-f]{64})", t, re.M)
    E = (int(en.group(1), 16), int(en.group(2), 16))
    ed = int.from_bytes(one(t, "ENROLD"), "big")
    assert g.ec_mul(ed) == E
    T = (int.from_bytes(one(t, "ECIES T.x"), "big"), int.from_bytes(one(t, "ECIES T.y"), "big"))
    mm = re.search(r"^ECIES (iv=.*)$", t, re.M)
    c = {k: bytes.fromhex(v) for k, v in re.findall(r"(\w+)=([0-9a-f]+)", mm.group(1))}
    assert e.ecies_decrypt(ed, T, c["iv"], c["ct"], c["tag"]) == kek2
    print("[ok] ECIES carried the rotated KEK (slot 2) to node B intact")

    rw = pairs(t, "REWRAP")
    d2 = int.from_bytes(AESGCM(kek2).decrypt(rw["iv"], rw["ct"] + rw["tag"], rw["wid"]), "big")
    assert d2 == d
    try:
        AESGCM(kek).decrypt(rw["iv"], rw["ct"] + rw["tag"], rw["wid"])
        raise SystemExit("rewrapped blob still opens under the old KEK!")
    except Exception as ex:
        if isinstance(ex, SystemExit): raise
    print("[ok] REWRAP: same wallet key, now under the new KEK only")
    sig("SIGB")
    print("[ok] node B signed with the new KEK on the rewrapped blob; signature verifies against the original public key")
    print("ALL EXTERNAL PHASE 2 CHECKS PASSED")

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "p2.log")
