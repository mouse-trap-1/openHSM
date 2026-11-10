#!/usr/bin/env python3
"""
Operator-card ceremonies for the sign node (run on the SoC secure world, or on a trusted
recovery host that can reach the node).

  split ceremony   : the node splits its KEK m-of-n; each share is wrapped to one operator card
  restore ceremony : m cards re-create the KEK on a node that has lost it (any node, any m of n)

Card = a YubiKey 5 OTP-slot HMAC-SHA1 challenge-response credential (touch required), or
anything else that maps a challenge to a secret response.  The card never sees the share; the
node never sees the card's key.  The host sees the card's *response* during a ceremony, so run
ceremonies only on a trusted node (see the specification, section 2).

  one-time card set-up (per YubiKey, slot 2):   ykman otp chalresp --touch --generate 2
  response               : HMAC-SHA1(card secret, challenge)       (20 bytes)
  card secret r (32 B)   : HMAC-SHA256(response, "SN-CARD-v1" || challenge)
  share blob             : AES-256-GCM(HMAC-SHA256(r, "SHARE-WRAP-v1" || header), share), AAD = header

The YubiKey responder shells out to `ykman`; check the flags against your ykman version.
It has NOT been exercised against real hardware here: the simulated tests use SoftwareCard.
"""
import hashlib
import hmac
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gen_shamir as sh

class Card:
    name = "card"
    def respond(self, challenge: bytes) -> bytes:
        raise NotImplementedError

class YubiKeyOtpCard(Card):
    """HMAC-SHA1 challenge-response in an OTP slot, via the ykman CLI."""
    def __init__(self, serial=None, slot=2):
        self.serial, self.slot = serial, slot
        self.name = f"yubikey-{serial or 'auto'}"
    def respond(self, challenge: bytes) -> bytes:
        cmd = ["ykman"] + (["--device", str(self.serial)] if self.serial else []) + \
              ["otp", "calculate", str(self.slot), challenge.hex()]
        out = subprocess.run(cmd, check=True, capture_output=True, text=True).stdout.strip()
        return bytes.fromhex(out)

class SoftwareCard(Card):
    """Test double with the same interface (HMAC-SHA1 like the YubiKey slot)."""
    def __init__(self, name):
        self.name, self._secret = name, os.urandom(20)
    def respond(self, challenge: bytes) -> bytes:
        return hmac.new(self._secret, challenge, hashlib.sha1).digest()

def split_ceremony(node, cards, m, out_path=None):
    """Returns the records to store (they are useless without m cards)."""
    n = len(cards)
    tmpl = node.split_begin(m, n)
    records = []
    try:
        for x, card in enumerate(cards, 1):
            challenge = os.urandom(32)
            r = sh.card_secret(card.respond(challenge), challenge)
            hdr = bytes([x]) + tmpl[1:]
            blob = node.share_get(hdr, r)
            records.append(dict(x=x, card=card.name, challenge=challenge.hex(), header=hdr.hex(),
                                iv=blob["iv"].hex(), tag=blob["tag"].hex(), ct=blob["ct"].hex()))
    finally:
        node.split_end()
    if out_path:
        with open(out_path, "w") as f:
            json.dump(dict(m=m, n=n, fp=tmpl[3:].hex(), records=records), f, indent=1)
    return records

def restore_ceremony(node, records, cards_by_name, m):
    """records: any >= m of the stored records; cards_by_name: {name: Card} for the cards present."""
    used = 0
    try:
        for rec in records:
            card = cards_by_name.get(rec["card"])
            if card is None:
                continue
            challenge = bytes.fromhex(rec["challenge"])
            r = sh.card_secret(card.respond(challenge), challenge)
            node.share_put(bytes.fromhex(rec["header"]),
                           dict(iv=bytes.fromhex(rec["iv"]), tag=bytes.fromhex(rec["tag"]), ct=bytes.fromhex(rec["ct"])), r)
            used += 1
            if used == m:
                break
        if used < m:
            raise RuntimeError(f"only {used} of the required {m} cards were available")
        node.restore()
    except Exception:
        node.restore_abort()
        raise

# ----------------------------------------------------------------- self-test --
class _RefNode:
    """Pure-Python stand-in for the node's share logic (the real one is exercised in tb_phase2.v)."""
    def __init__(self, kek): self.kek, self.shares, self.coefs, self.have = kek, {}, [], None
    def split_begin(self, m, n):
        self.m, self.n = m, n
        self.coefs = [os.urandom(32) for _ in range(m - 1)]
        return bytes([0, m, n]) + sh.kek_fp(self.kek)
    def share_get(self, hdr, r):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        y = sh.eval_share(self.kek, self.coefs, hdr[0]); iv = os.urandom(12)
        o = AESGCM(sh.share_wrap_key(r, hdr)).encrypt(iv, y, hdr)
        return dict(iv=iv, tag=o[32:], ct=o[:32])
    def split_end(self): self.coefs = []
    def share_put(self, hdr, blob, r):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        y = AESGCM(sh.share_wrap_key(r, hdr)).decrypt(blob["iv"], blob["ct"] + blob["tag"], hdr)
        self.shares[hdr[0]] = y; self.hdr = hdr
    def restore(self):
        k = sh.combine(list(self.shares.items()))
        assert sh.kek_fp(k) == self.hdr[3:], "fingerprint mismatch"
        self.restored = k
    def restore_abort(self): self.shares = {}

def selftest():
    kek = os.urandom(32)
    cards = [SoftwareCard(f"card{i}") for i in range(1, 6)]
    recs = split_ceremony(_RefNode(kek), cards, 3)
    for pick in ([0, 2, 4], [1, 3, 4], [0, 1, 2]):
        node = _RefNode(b"\0" * 32)
        restore_ceremony(node, [recs[i] for i in pick], {cards[i].name: cards[i] for i in pick}, 3)
        assert node.restored == kek
    node = _RefNode(b"\0" * 32)
    try:
        restore_ceremony(node, recs[:2], {c.name: c for c in cards[:2]}, 3)
        raise SystemExit("restored with too few cards")
    except RuntimeError:
        pass
    print("ceremony self-test OK (split 3-of-5, restore from three different card subsets, refuse with two)")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        selftest()
    else:
        print(__doc__)
