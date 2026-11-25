#!/usr/bin/env python3
"""V0.6 host driver (sn_host.py) against the Rust model of the module (protocol 0xB3).

Needs `cargo build --release` first (uses target/release/openhsm-signer-sim through
pentest/lab.py) and the `cryptography` package:

    python3 FPGA/V0.6/check_host_model.py
"""
import hashlib
import hmac
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "pentest"))
sys.path.insert(0, str(HERE))
import lab, sn_host
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, Prehashed
from cryptography.hazmat.primitives import hashes
n_ok = 0
def check(c, m):
    global n_ok
    assert c, m; n_ok += 1; print("ok  ", m)
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
a, b = lab.Bus(), lab.Bus()
try:
    Sa, Sb = os.urandom(32), os.urandom(32)
    a.spi(b"\xa5" + Sa); b.spi(b"\xa5" + Sb)
    na = sn_host.Node(a, chan_key=hmac.new(Sa, b"SN-CHAN", hashlib.sha256).digest())
    nb = sn_host.Node(b, chan_key=hmac.new(Sb, b"SN-CHAN", hashlib.sha256).digest())
    na.start_session(); nb.start_session()
    check(na.version == 0xB3, "model reports 0xB3 and the V0.6 driver accepts it")
    na.kek_generate()
    wid = os.urandom(16); w = na.new_wallet(wid)
    d = hashlib.sha256(b"hello").digest()
    r, s = na.sign(wid, w, d)
    pub = ec.EllipticCurvePublicNumbers(w["pub"][0], w["pub"][1], ec.SECP256K1()).public_key()
    pub.verify(encode_dss_signature(r, s), d, ec.ECDSA(Prehashed(hashes.SHA256())))
    check(s <= N // 2, "signature verifies and is low-s")
    # gated command refused with the key-switch off
    a.ceremony(0)
    ex, ey = nb.enrol_pubkey()
    try:
        na.kek_export(ex, ey); refused = False
    except sn_host.NodeError:
        refused = True
    check(refused, "KEK_EXPORT refused with the ceremony pin low")
    a.ceremony(1); b.ceremony(1)
    ex, ey = nb.enrol_pubkey()
    pkg = na.kek_export(ex, ey); nb.kek_import(pkg)
    check(na.kek_fingerprint() == nb.kek_fingerprint(), "ECIES transfer: same KEK fingerprint on both nodes")
    r2, s2 = nb.sign(wid, w, d)
    pub.verify(encode_dss_signature(r2, s2), d, ec.ECDSA(Prehashed(hashes.SHA256())))
    check((r2, s2) != (r, s), "second node signs the replicated blob; hedged nonce differs")
    # altered response rejected
    orig = a.read
    def evil(ptr, n):
        v = orig(ptr, n)
        return bytes([v[0] ^ 1]) + v[1:] if ptr == 0x44 and n == 32 else v
    a.read = evil
    try:
        na.sign(wid, w, d); caught = False
    except sn_host.NodeError:
        caught = True
    a.read = orig
    check(caught, "response altered on the bus is rejected by RMAC")
finally:
    a.close(); b.close()
print(f"{n_ok} checks passed")
