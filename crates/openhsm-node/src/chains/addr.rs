//! Bitcoin address codecs: Bech32 / Bech32m (BIP-173, BIP-350) and
//! Base58Check. Implemented here, with the BIP test vectors, to keep the
//! dependency set of the signing path small.

use crate::util::sha256;

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_CONST: u32 = 1;
const BECH32M_CONST: u32 = 0x2bc8_30a3;

fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
    let mut chk = 1u32;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ v as u32;
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut v: Vec<u8> = hrp.bytes().map(|c| c >> 5).collect();
    v.push(0);
    v.extend(hrp.bytes().map(|c| c & 31));
    v
}

fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let (mut acc, mut bits, mut out) = (0u32, 0u32, Vec::new());
    let maxv = (1u32 << to) - 1;
    for &v in data {
        if (v as u32) >> from != 0 {
            return None;
        }
        acc = (acc << from) | v as u32;
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return None;
    }
    Some(out)
}

/// Encode a segwit address for witness version `ver` and program `prog`.
pub fn segwit_encode(hrp: &str, ver: u8, prog: &[u8]) -> Option<String> {
    let mut data = vec![ver];
    data.extend(convert_bits(prog, 8, 5, true)?);
    let konst = if ver == 0 { BECH32_CONST } else { BECH32M_CONST };
    let mut values = hrp_expand(hrp);
    values.extend(&data);
    values.extend([0u8; 6]);
    let pm = polymod(&values) ^ konst;
    let mut out = format!("{hrp}1");
    for d in data {
        out.push(CHARSET[d as usize] as char);
    }
    for i in 0..6 {
        out.push(CHARSET[((pm >> (5 * (5 - i))) & 31) as usize] as char);
    }
    Some(out)
}

/// Decode a segwit address and enforce the BIP-173/350 rules. Returns the
/// witness version and program.
pub fn segwit_decode(expected_hrp: &str, addr: &str) -> Result<(u8, Vec<u8>), String> {
    if addr.len() > 90 || addr.len() < 8 {
        return Err("bad address length".into());
    }
    let has_lower = addr.bytes().any(|c| c.is_ascii_lowercase());
    let has_upper = addr.bytes().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err("mixed-case bech32 address".into());
    }
    let addr = addr.to_ascii_lowercase();
    let pos = addr.rfind('1').ok_or("missing bech32 separator")?;
    let (hrp, rest) = (&addr[..pos], &addr[pos + 1..]);
    if hrp != expected_hrp {
        return Err(format!("address is for a different network (prefix {hrp})"));
    }
    if rest.len() < 7 {
        return Err("bech32 data too short".into());
    }
    let mut data = Vec::with_capacity(rest.len());
    for c in rest.bytes() {
        data.push(CHARSET.iter().position(|&x| x == c).ok_or("invalid bech32 character")? as u8);
    }
    let mut values = hrp_expand(hrp);
    values.extend(&data);
    let pm = polymod(&values);
    let ver = data[0];
    let expect = if ver == 0 { BECH32_CONST } else { BECH32M_CONST };
    if pm != expect {
        return Err("bech32 checksum mismatch".into());
    }
    let prog = convert_bits(&data[1..data.len() - 6], 5, 8, false).ok_or("invalid bech32 padding")?;
    if ver > 16 || prog.len() < 2 || prog.len() > 40 {
        return Err("invalid witness program".into());
    }
    if ver == 0 && prog.len() != 20 && prog.len() != 32 {
        return Err("invalid v0 witness program length".into());
    }
    Ok((ver, prog))
}

const B58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Decode Base58Check; returns version byte and payload.
pub fn base58check_decode(s: &str) -> Result<(u8, Vec<u8>), String> {
    if s.is_empty() || s.len() > 50 {
        return Err("bad address length".into());
    }
    let mut num: Vec<u8> = vec![0]; // big-endian base-256 accumulator
    for c in s.bytes() {
        let mut carry = B58.iter().position(|&x| x == c).ok_or("invalid base58 character")? as u32;
        for b in num.iter_mut().rev() {
            let v = (*b as u32) * 58 + carry;
            *b = v as u8;
            carry = v >> 8;
        }
        while carry > 0 {
            num.insert(0, carry as u8);
            carry >>= 8;
        }
    }
    let zeros = s.bytes().take_while(|&c| c == b'1').count();
    let first = num.iter().position(|&b| b != 0).unwrap_or(num.len());
    let mut full = vec![0u8; zeros];
    full.extend_from_slice(&num[first..]);
    if full.len() < 5 {
        return Err("base58 payload too short".into());
    }
    let (body, chk) = full.split_at(full.len() - 4);
    if sha256(&[&sha256(&[body])])[..4] != *chk {
        return Err("base58 checksum mismatch".into());
    }
    Ok((body[0], body[1..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bip173_and_bip350_vectors() {
        let prog = hex::decode("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        assert_eq!(segwit_encode("bc", 0, &prog).unwrap(), "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert_eq!(segwit_encode("tb", 0, &prog).unwrap(), "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx");
        assert_eq!(segwit_decode("bc", "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4").unwrap(), (0, prog.clone()));
        // BIP-350: a v1 (taproot) address uses bech32m.
        let (v, p) = segwit_decode("bc", "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0").unwrap();
        assert_eq!((v, p.len()), (1, 32));
        // v0 with a bech32m checksum, wrong network, bad checksum, mixed case.
        assert!(segwit_decode("bc", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh").is_err());
        assert!(segwit_decode("tb", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").is_err());
        assert!(segwit_decode("bc", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5").is_err());
        assert!(segwit_decode("bc", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kV8f3t4").is_err());
    }

    #[test]
    fn base58check_vectors() {
        let (v, p) = base58check_decode("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();
        assert_eq!((v, hex::encode(p)), (0, "62e907b15cbf27d5425399ebf6f0fb50ebb88f18".into()));
        assert!(base58check_decode("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb").is_err());
        assert!(base58check_decode("0OIl").is_err());
    }
}
