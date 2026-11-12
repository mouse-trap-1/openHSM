import sys, json, hashlib, hmac
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "pentest"))
import lab
from lab import Bus, Host, REG, hmac256
S = bytes(range(32))
bus = Bus()
h = Host(bus, s=S)
out = {"S": S.hex(), "chan": h.chan.hex(), "nonce": h.nonce.hex(), "version": bus.read(0xFF,1).hex(),
       "status0": bus.read(0,1).hex(), "status2": bus.read(3,1).hex()}
# KEK
h.ok("KEK_GEN")
out["status_after_kek"] = bus.read(0,1).hex()
wid = bytes.fromhex("000102030405060708090a0b0c0d0e0f")[::-1]
wid = bytes.fromhex("a1a2a3a4a5a6a7a8a9aaabacadaeafb0")
# GEN_WALLET frame
f = h.frame(0x20, wid=wid)
out["gen_frame"] = {k: (v.hex() if isinstance(v, bytes) else v) for k, v in f.items()}
h.ctr += 1
r = h.send(f)
out["gen_resp"] = {k: (v.hex() if isinstance(v, bytes) else v) for k, v in r.items()}
w = dict(wid=wid, iv=r["iv"], tag=r["tag"], A=r["A"], px=r["B"], py=r["C"])
digest = hashlib.sha256(b"openhsm worked example").digest()
f = h.frame(0x21, wid=wid, iv=w["iv"], tag=w["tag"], A=w["A"], B=digest)
out["sign_frame"] = {k: (v.hex() if isinstance(v, bytes) else v) for k, v in f.items()}
out["sign_digest"] = digest.hex()
h.ctr += 1
r2 = h.send(f)
out["sign_resp"] = {k: (v.hex() if isinstance(v, bytes) else v) for k, v in r2.items()}
# bad MAC example
f = h.frame(0x21, wid=wid, iv=w["iv"], tag=w["tag"], A=w["A"], B=digest)
f["mac"] = bytes(32)
h.ctr += 1
r3 = h.send(f)
out["badmac_resp"] = {k: (v.hex() if isinstance(v, bytes) else v) for k, v in r3.items()}
out["status_after_bad"] = bus.read(0,1).hex()
# independent checks
msg = h.nonce + bytes.fromhex(out["sign_frame"]["ctr"]) + b"\x21" + wid + w["iv"] + w["tag"] + w["A"] + digest + bytes(32)
out["sign_msg_len"] = len(msg)
out["sign_mac_recomputed"] = hmac.new(h.chan, msg, hashlib.sha256).hexdigest()
out["sign_mac_match"] = out["sign_mac_recomputed"] == out["sign_frame"]["mac"]
out["sign_rmac_ok"] = r2["rmac_ok"]
# verify ECDSA
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
pub = ec.EllipticCurvePublicNumbers(int.from_bytes(w["px"],"big"), int.from_bytes(w["py"],"big"), ec.SECP256K1()).public_key()
pub.verify(utils.encode_dss_signature(int.from_bytes(r2["A"],"big"), int.from_bytes(r2["B"],"big")), digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
out["ecdsa_verified"] = True
s = int.from_bytes(r2["B"],"big"); out["low_s"] = s <= lab.N//2
print(json.dumps(out, indent=1))
bus.close()
