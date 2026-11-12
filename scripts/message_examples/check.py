"""Verify the captured examples (node.json) with code independent of the node."""
import hashlib, json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "pentest"))
from lab import ecdsa_verify
from suites.d_verify import verify_btc
from cryptography.hazmat.primitives.asymmetric import ed25519

d = json.load(open("node.json"))
e = d["eth"]
fr = json.loads(e["frame_layout"])
pk = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(e["app_sign_pub"]["pubkey"]))
pk.verify(bytes.fromhex(fr["sigs"][0]["sig"]), b"OPENHSM-REQ-v1\0" + fr["payload"].encode())
print("API request signature (Ed25519): valid")
print("frame bytes", len(e["frame_layout"].encode()), "payload bytes", len(fr["payload"].encode()),
      "length prefix", len(e["frame_layout"].encode()).to_bytes(4, "big").hex())
assert e["sig_ok"], "Ethereum signature"
assert e["txhash_ok"], "Ethereum tx_hash"
print("Ethereum signature over the independently built digest: valid; tx_hash matches")
b = d["btc"]
assert verify_btc(b["raw"], b["wallet"], [200000]), "Bitcoin signature"
print("Bitcoin BIP-143 signature: valid")
