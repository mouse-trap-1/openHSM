//! Bitcoin transaction construction for native SegWit (P2WPKH) wallets.
//!
//! The client supplies inputs and outputs as structured fields. The node
//! serialises the transaction, computes the BIP-143 signature hash for every
//! input, signs with SIGHASH_ALL only, and assembles the witness. Because
//! BIP-143 commits to the amount of the input being signed, a client that
//! lies about an input amount obtains a signature the network rejects.

use super::addr::{base58check_decode, segwit_decode, segwit_encode};
use crate::util::{dsha256, hash160, unhex_n};
use serde::{Deserialize, Serialize};

pub const MAX_INPUTS: usize = 128;
pub const MAX_OUTPUTS: usize = 256;
pub const MAX_MONEY: u64 = 21_000_000 * 100_000_000;
const SIGHASH_ALL: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Mainnet,
    Testnet,
    Signet,
    Regtest,
}

impl Network {
    pub fn hrp(&self) -> &'static str {
        match self {
            Network::Mainnet => "bc",
            Network::Testnet | Network::Signet => "tb",
            Network::Regtest => "bcrt",
        }
    }
    fn p2pkh_version(&self) -> u8 {
        if *self == Network::Mainnet {
            0x00
        } else {
            0x6f
        }
    }
    fn p2sh_version(&self) -> u8 {
        if *self == Network::Mainnet {
            0x05
        } else {
            0xc4
        }
    }
}

fn default_sequence() -> u32 {
    0xffff_fffd // opt-in replace-by-fee, no relative lock
}
fn default_version() -> i32 {
    2
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BtcIn {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    #[serde(default = "default_sequence")]
    pub sequence: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BtcOut {
    pub address: String,
    pub amount: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BtcTxRequest {
    #[serde(default = "default_version")]
    pub version: i32,
    #[serde(default)]
    pub locktime: u32,
    pub inputs: Vec<BtcIn>,
    pub outputs: Vec<BtcOut>,
}

#[derive(Debug, Clone)]
pub struct TxIn {
    /// Previous transaction id in serialisation (little-endian) order.
    pub prev_txid: [u8; 32],
    pub vout: u32,
    pub amount: u64,
    pub sequence: u32,
}

#[derive(Debug, Clone)]
pub struct TxOut {
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct BtcTx {
    pub version: i32,
    pub locktime: u32,
    pub ins: Vec<TxIn>,
    pub outs: Vec<TxOut>,
}

/// P2WPKH address of a compressed public key.
pub fn p2wpkh_address(net: Network, pubkey33: &[u8; 33]) -> String {
    segwit_encode(net.hrp(), 0, &hash160(pubkey33)).expect("20-byte program always encodes")
}

pub fn p2wpkh_script(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut s = vec![0x00, 0x14];
    s.extend_from_slice(pubkey_hash);
    s
}

/// Decode an address for `net` into its scriptPubKey. Supports P2WPKH, P2WSH,
/// P2TR (and future witness versions), P2PKH and P2SH.
pub fn address_to_script(net: Network, addr: &str) -> Result<Vec<u8>, String> {
    let lower = addr.to_ascii_lowercase();
    if lower.starts_with("bc1") || lower.starts_with("tb1") || lower.starts_with("bcrt1") {
        let (ver, prog) = segwit_decode(net.hrp(), addr)?;
        let mut s = vec![if ver == 0 { 0x00 } else { 0x50 + ver }, prog.len() as u8];
        s.extend(prog);
        return Ok(s);
    }
    let (version, payload) = base58check_decode(addr)?;
    if payload.len() != 20 {
        return Err("invalid base58 address payload".into());
    }
    if version == net.p2pkh_version() {
        let mut s = vec![0x76, 0xa9, 0x14];
        s.extend(payload);
        s.extend([0x88, 0xac]);
        Ok(s)
    } else if version == net.p2sh_version() {
        let mut s = vec![0xa9, 0x14];
        s.extend(payload);
        s.push(0x87);
        Ok(s)
    } else {
        Err("address is for a different network".into())
    }
}

fn varint(n: usize, out: &mut Vec<u8>) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend((n as u16).to_le_bytes());
        }
        _ => {
            out.push(0xfe);
            out.extend((n as u32).to_le_bytes());
        }
    }
}

/// Strict DER encoding of an ECDSA signature (BIP-66).
pub fn der_encode(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
    fn int(v: &[u8; 32]) -> Vec<u8> {
        let first = v.iter().position(|&b| b != 0).unwrap_or(31);
        let mut o = Vec::with_capacity(33);
        if v[first] & 0x80 != 0 {
            o.push(0);
        }
        o.extend_from_slice(&v[first..]);
        o
    }
    let (r, s) = (int(r), int(s));
    let mut out = vec![0x30, (r.len() + s.len() + 4) as u8, 0x02, r.len() as u8];
    out.extend(r);
    out.extend([0x02, s.len() as u8]);
    out.extend(s);
    out
}

impl BtcTx {
    pub fn parse(net: Network, req: &BtcTxRequest) -> Result<BtcTx, String> {
        if req.version != 1 && req.version != 2 {
            return Err("version must be 1 or 2".into());
        }
        if req.inputs.is_empty() || req.inputs.len() > MAX_INPUTS {
            return Err(format!("between 1 and {MAX_INPUTS} inputs are required"));
        }
        if req.outputs.is_empty() || req.outputs.len() > MAX_OUTPUTS {
            return Err(format!("between 1 and {MAX_OUTPUTS} outputs are required"));
        }
        let mut ins = Vec::new();
        for i in &req.inputs {
            let mut txid: [u8; 32] = unhex_n(&i.txid).map_err(|_| "txid must be 32 bytes of hex".to_string())?;
            txid.reverse(); // display order -> serialisation order
            if i.amount == 0 || i.amount > MAX_MONEY {
                return Err("input amount out of range".into());
            }
            if ins.iter().any(|p: &TxIn| p.prev_txid == txid && p.vout == i.vout) {
                return Err("duplicate input".into());
            }
            ins.push(TxIn { prev_txid: txid, vout: i.vout, amount: i.amount, sequence: i.sequence });
        }
        let mut outs = Vec::new();
        for o in &req.outputs {
            if o.amount > MAX_MONEY {
                return Err("output amount out of range".into());
            }
            outs.push(TxOut { amount: o.amount, script_pubkey: address_to_script(net, &o.address)? });
        }
        let tx = BtcTx { version: req.version, locktime: req.locktime, ins, outs };
        tx.fee()?;
        Ok(tx)
    }

    pub fn total_in(&self) -> Option<u64> {
        self.ins.iter().try_fold(0u64, |a, i| a.checked_add(i.amount)).filter(|v| *v <= MAX_MONEY)
    }

    pub fn total_out(&self) -> Option<u64> {
        self.outs.iter().try_fold(0u64, |a, o| a.checked_add(o.amount)).filter(|v| *v <= MAX_MONEY)
    }

    /// Fee implied by the claimed input amounts.
    pub fn fee(&self) -> Result<u64, String> {
        let tin = self.total_in().ok_or("input total out of range")?;
        let tout = self.total_out().ok_or("output total out of range")?;
        tin.checked_sub(tout).ok_or_else(|| "outputs exceed inputs".to_string())
    }

    /// BIP-143 signature hash for input `idx` spending a P2WPKH output.
    pub fn sighash_p2wpkh(&self, idx: usize, pubkey_hash: &[u8; 20]) -> [u8; 32] {
        let mut prevouts = Vec::new();
        let mut sequences = Vec::new();
        for i in &self.ins {
            prevouts.extend(i.prev_txid);
            prevouts.extend(i.vout.to_le_bytes());
            sequences.extend(i.sequence.to_le_bytes());
        }
        let mut outputs = Vec::new();
        for o in &self.outs {
            outputs.extend(o.amount.to_le_bytes());
            varint(o.script_pubkey.len(), &mut outputs);
            outputs.extend(&o.script_pubkey);
        }
        let i = &self.ins[idx];
        let mut pre = Vec::with_capacity(182);
        pre.extend(self.version.to_le_bytes());
        pre.extend(dsha256(&prevouts));
        pre.extend(dsha256(&sequences));
        pre.extend(i.prev_txid);
        pre.extend(i.vout.to_le_bytes());
        pre.extend([0x19, 0x76, 0xa9, 0x14]);
        pre.extend(pubkey_hash);
        pre.extend([0x88, 0xac]);
        pre.extend(i.amount.to_le_bytes());
        pre.extend(i.sequence.to_le_bytes());
        pre.extend(dsha256(&outputs));
        pre.extend(self.locktime.to_le_bytes());
        pre.extend(SIGHASH_ALL.to_le_bytes());
        dsha256(&pre)
    }

    /// Serialise. With `witness` (one `(der_signature, pubkey)` pair per
    /// input) the BIP-144 format is produced; without, the legacy format
    /// whose double-SHA256 is the txid.
    pub fn serialize(&self, witness: Option<&[(Vec<u8>, [u8; 33])]>) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(self.version.to_le_bytes());
        if witness.is_some() {
            out.extend([0x00, 0x01]);
        }
        varint(self.ins.len(), &mut out);
        for i in &self.ins {
            out.extend(i.prev_txid);
            out.extend(i.vout.to_le_bytes());
            out.push(0x00); // empty scriptSig
            out.extend(i.sequence.to_le_bytes());
        }
        varint(self.outs.len(), &mut out);
        for o in &self.outs {
            out.extend(o.amount.to_le_bytes());
            varint(o.script_pubkey.len(), &mut out);
            out.extend(&o.script_pubkey);
        }
        if let Some(w) = witness {
            for (sig, pk) in w {
                out.push(0x02);
                out.push(sig.len() as u8 + 1);
                out.extend(sig);
                out.push(SIGHASH_ALL as u8);
                out.push(0x21);
                out.extend(pk);
            }
        }
        out.extend(self.locktime.to_le_bytes());
        out
    }

    pub fn txid(&self) -> String {
        let mut h = dsha256(&self.serialize(None));
        h.reverse();
        hex::encode(h)
    }

    /// Virtual size (BIP-141) assuming 72-byte signatures, the worst case
    /// for low-s DER plus the sighash byte.
    pub fn vsize_estimate(&self) -> u64 {
        let base = self.serialize(None).len() as u64;
        let witness = 2 + self.ins.len() as u64 * (1 + 1 + 72 + 1 + 33);
        (base * 4 + witness).div_ceil(4)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::unhex;

    #[test]
    fn bip143_native_p2wpkh_vector() {
        let h32 = |s: &str| -> [u8; 32] { unhex_n(s).unwrap() };
        let tx = BtcTx {
            version: 1,
            locktime: 0x11,
            ins: vec![
                TxIn {
                    prev_txid: h32("fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f"),
                    vout: 0,
                    amount: 625_000_000,
                    sequence: 0xffff_ffee,
                },
                TxIn {
                    prev_txid: h32("ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a"),
                    vout: 1,
                    amount: 600_000_000,
                    sequence: 0xffff_ffff,
                },
            ],
            outs: vec![
                TxOut { amount: 112_340_000, script_pubkey: unhex("76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac").unwrap() },
                TxOut { amount: 223_450_000, script_pubkey: unhex("76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac").unwrap() },
            ],
        };
        let pk: [u8; 33] = unhex_n("025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357").unwrap();
        assert_eq!(hex::encode(hash160(&pk)), "1d0f172a0ecb48aee1be1f2687d2963ae33f71a1");
        assert_eq!(hex::encode(tx.sighash_p2wpkh(1, &hash160(&pk))), "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670");
        assert_eq!(
            hex::encode(tx.serialize(None)),
            "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000"
        );
    }

    #[test]
    fn addresses_and_scripts() {
        let pk: [u8; 33] = unhex_n("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
        assert_eq!(p2wpkh_address(Network::Mainnet, &pk), "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert_eq!(p2wpkh_address(Network::Testnet, &pk), "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx");
        assert_eq!(
            hex::encode(address_to_script(Network::Mainnet, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap()),
            "76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac"
        );
        assert!(address_to_script(Network::Testnet, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").is_err());
        assert!(address_to_script(Network::Testnet, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").is_err());
    }

    #[test]
    fn der_is_minimal() {
        let mut r = [0u8; 32];
        r[31] = 1;
        let mut s = [0u8; 32];
        s[0] = 0x80;
        let d = der_encode(&r, &s);
        assert_eq!(&d[..5], &[0x30, 38, 0x02, 0x01, 0x01]);
        assert_eq!(&d[5..8], &[0x02, 33, 0x00]);
    }

    #[test]
    fn rejects_bad_structure() {
        let req = |j: &str| serde_json::from_str::<BtcTxRequest>(j).unwrap();
        let t = "00".repeat(32);
        let a = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
        let over = format!(r#"{{"inputs":[{{"txid":"{t}","vout":0,"amount":1000}}],"outputs":[{{"address":"{a}","amount":2000}}]}}"#);
        assert!(BtcTx::parse(Network::Testnet, &req(&over)).is_err());
        let dup = format!(
            r#"{{"inputs":[{{"txid":"{t}","vout":0,"amount":1000}},{{"txid":"{t}","vout":0,"amount":1000}}],"outputs":[{{"address":"{a}","amount":500}}]}}"#
        );
        assert!(BtcTx::parse(Network::Testnet, &req(&dup)).is_err());
    }
}
