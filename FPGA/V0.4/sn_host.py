#!/usr/bin/env python3
"""
Reference host-side driver for the sign node (runs in the SoC secure world).

Transport-independent: pass an object with
    write(ptr: int, data: bytes)   # I2C: [addr][ptr][data...]
    read(ptr: int, n: int) -> bytes
Registers (see sign_node_top.v): 0x00 STATUS, 0x01 CMD, 0x02 ERR, 0x04 CTR, 0x08 NONCE,
0x18 WID, 0x28 IV, 0x34 TAG, 0x44 A, 0x64 B, 0x84 C, 0xA4 MAC.
"""
import hashlib
import hmac
import time

CMD = dict(KEK_GEN=0x10, KEK_SEAL=0x11, KEK_UNSEAL=0x12, KEK_ERASE=0x13, KEK_NEW_GEN=0x14, REWRAP=0x15,
           KEK_PROMOTE=0x16, KEK_FP=0x17, GEN_WALLET=0x20, SIGN=0x21, PUBKEY=0x22, ENROL_GEN=0x40,
           KEK_EXPORT=0x41, KEK_IMPORT=0x42, KEK_NEW_EXPORT=0x45, KEK_NEW_IMPORT=0x46,
           SPLIT_BEGIN=0x50, SHARE_GET=0x51, SPLIT_END=0x52, SHARE_PUT=0x53, RESTORE=0x54, RESTORE_ABORT=0x55)
ERR = {0: "ok", 1: "no session", 2: "no KEK", 3: "KEK exists", 4: "TRNG failure", 5: "authentication failed",
       6: "signing failed", 7: "tamper", 8: "bad command", 10: "unwrap failed", 11: "invalid point",
       9: "bad parameter", 12: "no enrolment key", 13: "share rejected", 14: "not enough shares / no split",
       15: "no second KEK"}

class NodeError(Exception):
    pass

class Node:
    def __init__(self, bus, S: bytes):
        """S: the 32-byte secret the tamper MCU sends this node over SPI (you hold the same copy)."""
        self.bus = bus
        self.chan = hmac.new(S, b"SN-CHAN", hashlib.sha256).digest()
        self.seal_key = hmac.new(S, b"SN-SEAL", hashlib.sha256).digest()
        self.nonce = None
        self.ctr = 0

    def start_session(self):
        """Call after the MCU has sent S: reads the fresh per-session nonce."""
        self.nonce = self.bus.read(0x08, 16)
        self.ctr = 0

    def _run(self, cmd, wid=bytes(16), iv=bytes(12), tag=bytes(16), A=bytes(32), B=bytes(32), C=bytes(32), timeout=10):
        assert self.nonce is not None, "start_session() first"
        self.ctr += 1
        ctr = self.ctr.to_bytes(4, "big")
        msg = self.nonce + ctr + bytes([cmd]) + wid + iv + tag + A + B + C
        mac = hmac.new(self.chan, msg, hashlib.sha256).digest()
        for ptr, d in ((0x18, wid), (0x28, iv), (0x34, tag), (0x44, A), (0x64, B), (0x84, C), (0x04, ctr), (0xA4, mac)):
            self.bus.write(ptr, d)
        self.bus.write(0x01, bytes([cmd]))
        t0 = time.time()
        while True:
            st = self.bus.read(0x00, 1)[0]
            if st & 0x02:
                break
            if time.time() - t0 > timeout:
                raise NodeError("timeout")
        err = self.bus.read(0x02, 1)[0] & 0xF
        if err:
            raise NodeError(ERR.get(err, f"error {err}"))
        return dict(iv=self.bus.read(0x28, 12), tag=self.bus.read(0x34, 16), A=self.bus.read(0x44, 32),
                    B=self.bus.read(0x64, 32), C=self.bus.read(0x84, 32))

    # --- wallets: the returned blob is stored in your database / replicated through Raft ---
    def new_wallet(self, wallet_id: bytes):
        r = self._run(CMD["GEN_WALLET"], wid=wallet_id)
        return dict(iv=r["iv"], tag=r["tag"], wrapped=r["A"], pub=(int.from_bytes(r["B"], "big"), int.from_bytes(r["C"], "big")))

    def sign(self, wallet_id, blob, digest32: bytes):
        r = self._run(CMD["SIGN"], wid=wallet_id, iv=blob["iv"], tag=blob["tag"], A=blob["wrapped"], B=digest32)
        return int.from_bytes(r["A"], "big"), int.from_bytes(r["B"], "big")

    def pubkey(self, wallet_id, blob):
        r = self._run(CMD["PUBKEY"], wid=wallet_id, iv=blob["iv"], tag=blob["tag"], A=blob["wrapped"])
        return int.from_bytes(r["A"], "big"), int.from_bytes(r["B"], "big")

    # --- KEK lifecycle ---
    def kek_generate(self): self._run(CMD["KEK_GEN"])
    def kek_seal(self):
        r = self._run(CMD["KEK_SEAL"]); return dict(iv=r["iv"], tag=r["tag"], ct=r["A"])     # keep on NVMe
    def kek_unseal(self, s): self._run(CMD["KEK_UNSEAL"], iv=s["iv"], tag=s["tag"], A=s["ct"])
    def kek_erase(self): self._run(CMD["KEK_ERASE"])

    # --- ECIES enrolment of a new node ---
    def enrol_pubkey(self):
        r = self._run(CMD["ENROL_GEN"]); return r["B"], r["C"]
    def kek_export(self, ex: bytes, ey: bytes):
        r = self._run(CMD["KEK_EXPORT"], B=ex, C=ey); return dict(iv=r["iv"], tag=r["tag"], ct=r["A"], Tx=r["B"], Ty=r["C"])
    def kek_import(self, x):
        self._run(CMD["KEK_IMPORT"], iv=x["iv"], tag=x["tag"], A=x["ct"], B=x["Tx"], C=x["Ty"])

    # --- rotation ---
    def kek_fingerprint(self): return self._run(CMD["KEK_FP"])["B"]
    def kek_new_generate(self): self._run(CMD["KEK_NEW_GEN"])
    def rewrap(self, wallet_id, blob):
        r = self._run(CMD["REWRAP"], wid=wallet_id, iv=blob["iv"], tag=blob["tag"], A=blob["wrapped"])
        return dict(iv=r["iv"], tag=r["tag"], wrapped=r["A"], pub=blob.get("pub"))
    def kek_promote(self): self._run(CMD["KEK_PROMOTE"])
    def kek_new_export(self, ex, ey):
        r = self._run(CMD["KEK_NEW_EXPORT"], B=ex, C=ey); return dict(iv=r["iv"], tag=r["tag"], ct=r["A"], Tx=r["B"], Ty=r["C"])
    def kek_new_import(self, x):
        self._run(CMD["KEK_NEW_IMPORT"], iv=x["iv"], tag=x["tag"], A=x["ct"], B=x["Tx"], C=x["Ty"])

    # --- break-glass shares (see sn_ceremony.py) ---
    def split_begin(self, m, n):
        r = self._run(CMD["SPLIT_BEGIN"], B=bytes([m, n]) + bytes(30))
        return self.bus.read(0x18, 16)                       # header template: 00 || m || n || fp13
    def share_get(self, header16: bytes, r32: bytes):
        r = self._run(CMD["SHARE_GET"], wid=header16, B=r32)
        return dict(iv=r["iv"], tag=r["tag"], ct=r["A"])
    def split_end(self): self._run(CMD["SPLIT_END"])
    def share_put(self, header16: bytes, blob, r32: bytes):
        self._run(CMD["SHARE_PUT"], wid=header16, iv=blob["iv"], tag=blob["tag"], A=blob["ct"], B=r32)
    def restore(self): self._run(CMD["RESTORE"])
    def restore_abort(self): self._run(CMD["RESTORE_ABORT"])
