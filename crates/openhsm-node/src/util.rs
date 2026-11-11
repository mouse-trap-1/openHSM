//! Small shared helpers: fixed-width integers, hex, hashing, time.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub fn dsha256(data: &[u8]) -> [u8; 32] {
    sha256(&[&sha256(&[data])])
}

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

pub fn hash160(data: &[u8]) -> [u8; 20] {
    ripemd::Ripemd160::digest(sha256(&[data])).into()
}

pub fn random<const N: usize>() -> Result<[u8; N], String> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).map_err(|e| format!("entropy source unavailable: {e}"))?;
    Ok(b)
}

/// Decode hex with an optional `0x` prefix.
pub fn unhex(s: &str) -> Result<Vec<u8>, String> {
    let t = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    hex::decode(t).map_err(|_| "invalid hex".to_string())
}

pub fn unhex_n<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let v = unhex(s)?;
    <[u8; N]>::try_from(v.as_slice()).map_err(|_| format!("expected {N} bytes"))
}

/// Unsigned 256-bit integer with only the operations the policy engine needs.
/// All arithmetic is checked: overflow is an error, never a wrap.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Debug, Hash)]
pub struct U256 {
    hi: u128,
    lo: u128,
}

impl U256 {
    pub const ZERO: U256 = U256 { hi: 0, lo: 0 };
    pub const MAX: U256 = U256 { hi: u128::MAX, lo: u128::MAX };

    pub fn from_u64(v: u64) -> Self {
        U256 { hi: 0, lo: v as u128 }
    }

    pub fn is_zero(&self) -> bool {
        self.hi == 0 && self.lo == 0
    }

    pub fn to_u64(&self) -> Option<u64> {
        (self.hi == 0 && self.lo <= u64::MAX as u128).then_some(self.lo as u64)
    }

    pub fn from_be_slice(b: &[u8]) -> Option<Self> {
        if b.len() > 32 {
            return None;
        }
        let mut full = [0u8; 32];
        full[32 - b.len()..].copy_from_slice(b);
        Some(U256 { hi: u128::from_be_bytes(full[..16].try_into().ok()?), lo: u128::from_be_bytes(full[16..].try_into().ok()?) })
    }

    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut o = [0u8; 32];
        o[..16].copy_from_slice(&self.hi.to_be_bytes());
        o[16..].copy_from_slice(&self.lo.to_be_bytes());
        o
    }

    /// Minimal big-endian encoding (empty for zero), as RLP requires.
    pub fn to_be_trimmed(&self) -> Vec<u8> {
        let b = self.to_be_bytes();
        let first = b.iter().position(|&x| x != 0).unwrap_or(32);
        b[first..].to_vec()
    }

    pub fn checked_add(&self, o: &U256) -> Option<U256> {
        let (lo, carry) = self.lo.overflowing_add(o.lo);
        let hi = self.hi.checked_add(o.hi)?.checked_add(carry as u128)?;
        Some(U256 { hi, lo })
    }

    fn limbs(&self) -> [u64; 4] {
        [self.lo as u64, (self.lo >> 64) as u64, self.hi as u64, (self.hi >> 64) as u64]
    }

    fn from_limbs(l: [u64; 4]) -> Self {
        U256 { lo: l[0] as u128 | (l[1] as u128) << 64, hi: l[2] as u128 | (l[3] as u128) << 64 }
    }

    pub fn checked_mul_u64(&self, m: u64) -> Option<U256> {
        let mut out = [0u64; 4];
        let mut carry = 0u128;
        for (i, l) in self.limbs().iter().enumerate() {
            let v = (*l as u128) * (m as u128) + carry;
            out[i] = v as u64;
            carry = v >> 64;
        }
        (carry == 0).then(|| Self::from_limbs(out))
    }

    /// Quotient and remainder of division by a non-zero u64.
    pub fn div_rem_u64(&self, d: u64) -> Option<(U256, u64)> {
        if d == 0 {
            return None;
        }
        let mut out = [0u64; 4];
        let mut rem = 0u128;
        let l = self.limbs();
        for i in (0..4).rev() {
            let cur = (rem << 64) | l[i] as u128;
            out[i] = (cur / d as u128) as u64;
            rem = cur % d as u128;
        }
        Some((Self::from_limbs(out), rem as u64))
    }

    pub fn from_dec_str(s: &str) -> Option<U256> {
        if s.is_empty() || s.len() > 78 || !s.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let mut v = U256::ZERO;
        for c in s.bytes() {
            v = v.checked_mul_u64(10)?.checked_add(&U256::from_u64((c - b'0') as u64))?;
        }
        Some(v)
    }

    pub fn from_hex_str(s: &str) -> Option<U256> {
        let t = s.strip_prefix("0x")?;
        if t.is_empty() || t.len() > 64 || !t.bytes().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        let padded = format!("{t:0>64}");
        Self::from_be_slice(&hex::decode(padded).ok()?)
    }

    /// Accepts decimal or `0x`-prefixed hexadecimal.
    pub fn parse(s: &str) -> Option<U256> {
        if s.starts_with("0x") {
            Self::from_hex_str(s)
        } else {
            Self::from_dec_str(s)
        }
    }

    pub fn to_dec_string(&self) -> String {
        if self.is_zero() {
            return "0".into();
        }
        let mut digits = Vec::new();
        let mut v = *self;
        while !v.is_zero() {
            let (q, r) = v.div_rem_u64(10).expect("non-zero divisor");
            digits.push(b'0' + r as u8);
            v = q;
        }
        digits.reverse();
        String::from_utf8(digits).expect("ascii digits")
    }
}

impl std::fmt::Display for U256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_dec_string())
    }
}

impl Serialize for U256 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_dec_string())
    }
}

impl<'de> Deserialize<'de> for U256 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // Amounts are strings (decimal or 0x-hex) or non-negative JSON integers.
        // Floating point is rejected: it cannot represent amounts exactly.
        let v = serde_json::Value::deserialize(d)?;
        match &v {
            serde_json::Value::String(s) => U256::parse(s),
            serde_json::Value::Number(n) => n.as_u64().map(U256::from_u64),
            _ => None,
        }
        .ok_or_else(|| serde::de::Error::custom("amount must be a decimal or 0x-hex string, or a non-negative integer"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u256_parse_format_roundtrip() {
        for s in [
            "0",
            "1",
            "18446744073709551616",
            "340282366920938463463374607431768211456",
            "115792089237316195423570985008687907853269984665640564039457584007913129639935",
        ] {
            assert_eq!(U256::from_dec_str(s).unwrap().to_dec_string(), s);
        }
        assert!(U256::from_dec_str("115792089237316195423570985008687907853269984665640564039457584007913129639936").is_none());
        assert!(U256::from_dec_str("-1").is_none() && U256::from_dec_str("1e18").is_none() && U256::from_dec_str("").is_none());
        assert_eq!(U256::parse("0xde0b6b3a7640000").unwrap(), U256::from_dec_str("1000000000000000000").unwrap());
    }

    #[test]
    fn u256_arithmetic_is_checked() {
        assert!(U256::MAX.checked_add(&U256::from_u64(1)).is_none());
        assert!(U256::MAX.checked_mul_u64(2).is_none());
        let gwei30 = U256::from_dec_str("30000000000").unwrap();
        assert_eq!(gwei30.checked_mul_u64(21000).unwrap().to_dec_string(), "630000000000000");
        let (q, r) = U256::from_dec_str("1000000000000000000001").unwrap().div_rem_u64(6).unwrap();
        assert_eq!((q.to_dec_string().as_str(), r), ("166666666666666666666", 5));
        assert!(U256::from_u64(5) < U256::from_dec_str("340282366920938463463374607431768211456").unwrap());
    }

    #[test]
    fn rejects_float_and_negative_json_amounts() {
        assert!(serde_json::from_str::<U256>("1.5").is_err());
        assert!(serde_json::from_str::<U256>("-1").is_err());
        assert!(serde_json::from_str::<U256>("\"12\"").is_ok());
        assert!(serde_json::from_str::<U256>("12").is_ok());
    }
}
