#!/usr/bin/env python3
"""
Independent check of the two-node system simulation log (tb_node_system.v).

Everything is verified with the Python reference code and the `cryptography` library,
using only what appeared on the bus plus the testbench-only peeks of the KEK and the
enrolment private key:
  * the sealed KEK decrypts under HMAC(S,"SN-SEAL") to the KEK the node generated
  * the wrapped wallet key decrypts under the KEK (AAD = wallet id) and d*G = reported pubkey
  * both signatures (and the one made by the *other* node) verify, are low-s, and differ
  * the ECIES transfer decrypts with the recipient's enrolment key to the same KEK
  * the sealed copy made on node B decrypts under B's seal key to the same KEK
Usage: python3 verify_node.py node.log
"""
import hashlib
import hmac
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gen_ucode as g
import gen_ecies as e
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def h(text, key, n=64):
    m = re.search(rf"^{re.escape(key)}=?\s*([0-9a-fA-F]{{{n}}})", text, re.M)
    assert m, f"missing {key}"
    return bytes.fromhex(m.group(1))

def kv(text, line_prefix):
    m = re.search(rf"^{re.escape(line_prefix)} (.*)$", text, re.M)
    assert m, f"missing line {line_prefix}"
    return {k: bytes.fromhex(v) for k, v in re.findall(r"(\w+(?:\.\w)?)=([0-9a-f]+)", m.group(1))}

def main(path):
    t = open(path).read()
    assert "FAIL" not in t, "testbench reported failures"
    assert "ALL NODE SYSTEM TESTS PASSED" in t, "testbench did not finish cleanly"

    S0, S1 = h(t, "S0"), h(t, "S1")
    kek = h(t, "KEK")
    assert kek != bytes(32)

    seal0 = hmac.new(S0, b"SN-SEAL", hashlib.sha256).digest()
    seal1 = hmac.new(S1, b"SN-SEAL", hashlib.sha256).digest()

    # sealed KEK (node A)
    s = kv(t, "SEAL")
    pt = AESGCM(seal0).decrypt(s["iv"], s["ct"] + s["tag"], e.SEAL_AAD)
    assert pt == kek
    print("[ok] sealed KEK decrypts under HMAC(S,'SN-SEAL') to the generated KEK")

    # wrapped wallet key
    w = kv(t, "WALLET")
    wid = w["wid"]
    d = int.from_bytes(AESGCM(kek).decrypt(w["iv"], w["ct"] + w["tag"], wid), "big")
    assert 1 <= d < g.N
    px, py = int.from_bytes(h(t, "PUBX"), "big"), int.from_bytes(h(t, "PUBY"), "big")
    assert g.ec_mul(d) == (px, py)
    print("[ok] wrapped wallet key unwraps under the KEK (AAD = wallet id) and d*G equals the reported public key")
    try:
        AESGCM(kek).decrypt(w["iv"], w["ct"] + w["tag"], bytes([wid[0] ^ 1]) + wid[1:])
        raise SystemExit("blob unwrapped under a wrong wallet id!")
    except Exception as ex:
        if isinstance(ex, SystemExit): raise
    print("[ok] the blob is bound to its wallet id")

    z = int.from_bytes(h(t, "HASH"), "big")
    sigs = []
    for tag in ("SIG1", "SIG2", "SIGB"):
        r = int(re.search(rf"^{tag} r=([0-9a-f]{{64}})", t, re.M).group(1), 16)
        s_ = int(re.search(rf"^{tag} s=([0-9a-f]{{64}})", t, re.M).group(1), 16)
        assert 1 <= r < g.N and 1 <= s_ <= g.N // 2
        assert g.ref_verify((px, py), z % g.N, r, s_), f"{tag} does not verify"
        sigs.append((r, s_))
    assert sigs[0] != sigs[1]
    print("[ok] SIG1, SIG2 verify against the wallet public key (low-s) and differ (hedged nonce)")
    print("[ok] SIGB, signed by node B with the ECIES-delivered KEK on A's wrapped key, verifies too")

    # ECIES transfer
    en = re.search(r"^ENROL ex=([0-9a-f]{64}) ey=([0-9a-f]{64})", t, re.M)
    E = (int(en.group(1), 16), int(en.group(2), 16))
    ed = int.from_bytes(h(t, "ENROLD"), "big")
    assert g.ec_mul(ed) == E and e.on_curve(E)
    T = (int.from_bytes(h(t, "ECIES T.x"), "big"), int.from_bytes(h(t, "ECIES T.y"), "big"))
    m = re.search(r"^ECIES (iv=.*)$", t, re.M); c = {k: bytes.fromhex(v) for k, v in re.findall(r"(\w+)=([0-9a-f]+)", m.group(1))}
    got = e.ecies_decrypt(ed, T, c["iv"], c["ct"], c["tag"])
    assert got == kek and e.on_curve(T)
    print("[ok] ECIES blob (ephemeral key T, KDF, AES-GCM) decrypts with the enrolment key to the cluster KEK")

    # sealed copy on node B
    sb = kv(t, "SEALB")
    assert AESGCM(seal1).decrypt(sb["iv"], sb["ct"] + sb["tag"], e.SEAL_AAD) == kek
    assert seal0 != seal1
    print("[ok] node B's sealed KEK decrypts under B's own seal key (and the two seal keys differ)")
    print("ALL EXTERNAL NODE CHECKS PASSED")

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "node.log")
