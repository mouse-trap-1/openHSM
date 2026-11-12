import sys, json, struct, tempfile, hashlib, time
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "pentest"))
from lab import *
from suites.d_verify import keccak256, rlp_encode, rlp_decode, parse_btc, bip143, hash160, parse_der, eth_address
import lab as L
wd = tempfile.mkdtemp(prefix="msgex")
lb = Lab(wd)
n = lb.ready_node("n1")
api = n.api
app = lb.id["app1"]
res = {}
# ---- ETH request, captured on the wire
req = eth_tx(n.eth)
payload = api.payload("eth_sign_transaction", req, ts=1_800_000_000_000, nonce="00112233445566778899aabbccddeeff")
frame = json.dumps(dict(payload=payload, sigs=[dict(id=app.name, sig=app.sign(payload))]))
# freshness: ts must be within 30 s -> send a fresh one for the real call, show fixed one for layout
real = api.payload("eth_sign_transaction", req)
resp = api.send(real, [app])
res["eth"] = dict(request_params=req, payload_layout=payload, frame_layout=frame, response=resp, wallet=n.eth,
                  app_sign_pub=app.record)
# independent re-derivation
r = resp["result"]
tx = req["tx"]
fields = [tx["chain_id"], tx["nonce"], int(tx["max_priority_fee_per_gas"]), int(tx["max_fee_per_gas"]), tx["gas_limit"],
          bytes.fromhex(tx["to"][2:]), int(tx["value"]), b"", []]
pre = b"\x02" + rlp_encode(fields)
dig = keccak256(pre)
res["eth"]["preimage_hex"] = pre.hex(); res["eth"]["digest"] = dig.hex()
raw = bytes.fromhex(r["raw_tx"][2:] if r["raw_tx"].startswith("0x") else r["raw_tx"])
res["eth"]["raw"] = raw.hex()
dec = rlp_decode(raw[1:])
res["eth"]["decoded_len"] = len(dec)
x, y = decompress(bytes.fromhex(n.eth["pubkey"]))
rr = int(r["r"],16).to_bytes(32,"big") if isinstance(r["r"],str) else r["r"]
ss = int(r["s"],16).to_bytes(32,"big") if isinstance(r["s"],str) else r["s"]
res["eth"]["sig_ok"] = ecdsa_verify(x, y, dig, rr, ss)
res["eth"]["txhash_ok"] = keccak256(raw).hex() == r["tx_hash"].replace("0x","")
res["eth"]["addr"] = "0x"+eth_address(x,y).hex() if isinstance(eth_address(x,y), bytes) else eth_address(x,y)
# ---- BTC
breq = btc_tx(n.btc, txid="ab"*32)
bresp = api.send(api.payload("btc_sign_transaction", breq), [app])
res["btc"] = dict(request_params=breq, response=bresp, wallet=n.btc)
raw = bytes.fromhex(bresp["result"]["raw_tx"])
res["btc"]["raw"] = raw.hex()
print(json.dumps(res, indent=1, default=str))
lb.close()
