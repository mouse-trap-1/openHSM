//! Byte-wise (m, n) Shamir secret sharing over GF(2^8), reduction polynomial
//! 0x11B, 32 independent lanes. Matches `FPGA/V0.4/shamir_core.v` and its
//! reference model `gen_shamir.py`. All field operations are branch-free.

use zeroize::Zeroizing;

/// Constant-time multiplication in GF(2^8) mod x^8+x^4+x^3+x+1.
pub fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        p ^= a & 0u8.wrapping_sub(b & 1);
        let hi = 0u8.wrapping_sub(a >> 7);
        a = (a << 1) ^ (0x1B & hi);
        b >>= 1;
    }
    p
}

/// Multiplicative inverse by exponentiation (a^254). `ginv(0) == 0`.
pub fn ginv(a: u8) -> u8 {
    let mut r = 1u8;
    for _ in 0..254 {
        r = gmul(r, a);
    }
    r
}

/// Evaluate the sharing polynomial at `x`. `coefs[k-1]` is the coefficient
/// word of x^k for k = 1..m-1.
pub fn eval_share(secret: &[u8; 32], coefs: &[Zeroizing<[u8; 32]>], x: u8) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    for b in 0..32 {
        let mut y = 0u8;
        for c in coefs.iter().rev() {
            y = gmul(y, x) ^ c[b];
        }
        out[b] = gmul(y, x) ^ secret[b];
    }
    out
}

/// Lagrange interpolation at zero over all supplied shares.
pub fn combine(shares: &[(u8, Zeroizing<[u8; 32]>)]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    for (i, (xi, yi)) in shares.iter().enumerate() {
        let (mut num, mut den) = (1u8, 1u8);
        for (j, (xj, _)) in shares.iter().enumerate() {
            if j != i {
                num = gmul(num, *xj);
                den = gmul(den, xi ^ xj);
            }
        }
        let l = gmul(num, ginv(den));
        for b in 0..32 {
            out[b] ^= gmul(yi[b], l);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_axioms() {
        assert_eq!(gmul(0x57, 0x83), 0xC1); // FIPS-197 example
        for a in 1..=255u8 {
            assert_eq!(gmul(a, ginv(a)), 1);
        }
    }

    #[test]
    fn any_m_of_n_reconstructs_and_fewer_do_not() {
        let secret = [0xA5u8; 32];
        let coefs: Vec<_> = (1..3u8).map(|k| Zeroizing::new([k.wrapping_mul(37) ^ 0x5c; 32])).collect();
        let shares: Vec<_> = (1..=5u8).map(|x| (x, eval_share(&secret, &coefs, x))).collect();
        for a in 0..5 {
            for b in a + 1..5 {
                for c in b + 1..5 {
                    let sub = [shares[a].clone(), shares[b].clone(), shares[c].clone()];
                    assert_eq!(&combine(&sub)[..], &secret[..]);
                }
                let two = [shares[a].clone(), shares[b].clone()];
                assert_ne!(&combine(&two)[..], &secret[..]);
            }
        }
    }
}
