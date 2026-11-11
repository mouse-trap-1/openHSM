//! Cryptographic constructions of the signing module.
//!
//! Every construction here mirrors section 7 of the FPGA specification
//! (`FPGA/README.md`). Field and scalar arithmetic come from the `k256` crate,
//! whose scalar multiplication, inversion and conditional operations are
//! constant-time; this file only composes them.

use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, Tag};
use hmac::{Hmac, Mac};
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::scalar::IsHigh;
use k256::elliptic_curve::sec1::{FromSec1Point, ToSec1Point};
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar, Sec1Point};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// 32-byte big-endian word, the unit of every buffer in the module.
pub type Word = [u8; 32];

/// HMAC-SHA256 over the concatenation of `parts`.
pub fn hmac256(key: &[u8], parts: &[&[u8]]) -> Word {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// Constant-time equality of two byte strings of equal length.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// AES-256-GCM encryption of one 32-byte record (96-bit IV, 128-bit tag).
pub fn gcm_seal(key: &Word, iv: &[u8; 12], aad: &[u8], pt: &Word) -> (Word, [u8; 16]) {
    let cipher = Aes256Gcm::new(key.into());
    let mut buf = *pt;
    let tag = cipher.encrypt_in_place_detached(Nonce::from_slice(iv), aad, &mut buf).expect("32-byte record is within GCM limits");
    let out = buf;
    buf.zeroize();
    (out, tag.into())
}

/// AES-256-GCM decryption. Returns `None` on tag failure; no plaintext is
/// produced in that case (the tag is checked before decryption).
pub fn gcm_open(key: &Word, iv: &[u8; 12], aad: &[u8], ct: &Word, tag: &[u8; 16]) -> Option<Zeroizing<Word>> {
    let cipher = Aes256Gcm::new(key.into());
    let mut buf = Zeroizing::new(*ct);
    cipher.decrypt_in_place_detached(Nonce::from_slice(iv), aad, &mut buf[..], Tag::from_slice(tag)).ok()?;
    Some(buf)
}

/// Parse a big-endian scalar and require 1 <= d < n.
pub fn scalar_in_range(b: &Word) -> Option<Scalar> {
    let s: Option<Scalar> = Scalar::from_repr(FieldBytes::from(*b)).into();
    let s = s?;
    if bool::from(s.is_zero()) {
        return None;
    }
    Some(s)
}

fn affine_xy(p: &AffinePoint) -> Option<(Word, Word)> {
    let ep = p.to_sec1_point(false);
    let x: Word = (*ep.x()?).into();
    let y: Word = (*ep.y()?).into();
    Some((x, y))
}

/// d * G as affine coordinates.
pub fn pubkey(d: &Scalar) -> Option<(Word, Word)> {
    affine_xy(&(ProjectivePoint::GENERATOR * d).to_affine())
}

/// Validate that (x, y) is a point on secp256k1 with coordinates below p.
/// This is the invalid-curve defence that precedes every ECDH.
pub fn check_point(x: &Word, y: &Word) -> Option<AffinePoint> {
    let ep = Sec1Point::from_affine_coordinates(&FieldBytes::from(*x), &FieldBytes::from(*y), false);
    AffinePoint::from_sec1_point(&ep).into_option()
}

/// d * P for a validated point P. Returns `None` for the point at infinity.
pub fn point_mul(d: &Scalar, p: &AffinePoint) -> Option<(Word, Word)> {
    affine_xy(&(ProjectivePoint::from(*p) * d).to_affine())
}

/// RFC 6979 nonce (HMAC-SHA256 DRBG), optionally hedged with 32 bytes of
/// fresh entropy as the "additional data" input of RFC 6979 section 3.6.
/// `h1` is reduced mod n before use (bits2octets).
pub fn rfc6979_k(d: &Word, h1: &Word, extra: Option<&Word>) -> Zeroizing<Word> {
    let h: Word = <Scalar as Reduce<FieldBytes>>::reduce(&FieldBytes::from(*h1)).to_bytes().into();
    let empty: [u8; 0] = [];
    let ex: &[u8] = match extra {
        Some(e) => e,
        None => &empty,
    };
    let mut v = Zeroizing::new([0x01u8; 32]);
    let mut k = Zeroizing::new([0x00u8; 32]);
    *k = hmac256(&k[..], &[&v[..], &[0x00], d, &h, ex]);
    *v = hmac256(&k[..], &[&v[..]]);
    *k = hmac256(&k[..], &[&v[..], &[0x01], d, &h, ex]);
    *v = hmac256(&k[..], &[&v[..]]);
    loop {
        *v = hmac256(&k[..], &[&v[..]]);
        if scalar_in_range(&v).is_some() {
            return Zeroizing::new(*v);
        }
        *k = hmac256(&k[..], &[&v[..], &[0x00]]);
        *v = hmac256(&k[..], &[&v[..]]);
    }
}

/// ECDSA signature with an explicit nonce. `s` is normalised to the low half
/// of the range. Returns `None` if r or s would be zero.
pub fn ecdsa_sign(d: &Scalar, k: &Scalar, z: &Word) -> Option<(Word, Word)> {
    let z = <Scalar as Reduce<FieldBytes>>::reduce(&FieldBytes::from(*z));
    let big_r = (ProjectivePoint::GENERATOR * k).to_affine();
    let (rx, _) = affine_xy(&big_r)?;
    let r = <Scalar as Reduce<FieldBytes>>::reduce(&FieldBytes::from(rx));
    if bool::from(r.is_zero()) {
        return None;
    }
    let k_inv: Option<Scalar> = k.invert().into();
    let mut s = k_inv? * (z + r * d);
    if bool::from(s.is_zero()) {
        return None;
    }
    if bool::from(s.is_high()) {
        s = -s;
    }
    Some((r.to_bytes().into(), s.to_bytes().into()))
}

/// Independent verification path (the `ecdsa` crate's verifier), used for
/// verify-before-release and by tests.
pub fn ecdsa_verify(px: &Word, py: &Word, z: &Word, r: &Word, s: &Word) -> bool {
    let Some(p) = check_point(px, py) else { return false };
    let Ok(vk) = VerifyingKey::from_affine(p) else { return false };
    let Ok(sig) = Signature::from_scalars(*r, *s) else { return false };
    vk.verify_prehash(z, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    fn h(s: &str) -> Word {
        let mut o = [0u8; 32];
        hex::decode_to_slice(s, &mut o).unwrap();
        o
    }

    #[test]
    fn rfc6979_published_secp256k1_vector() {
        // Widely used secp256k1 vector: d = 1, message "Satoshi Nakamoto".
        let d = h("0000000000000000000000000000000000000000000000000000000000000001");
        let z: Word = Sha256::digest(b"Satoshi Nakamoto").into();
        let k = rfc6979_k(&d, &z, None);
        assert_eq!(hex::encode(&k[..]), "8f8a276c19f4149656b280621e358cce24f5f52542772691ee69063b74f15d15");
        let (r, s) = ecdsa_sign(&scalar_in_range(&d).unwrap(), &scalar_in_range(&k).unwrap(), &z).unwrap();
        assert_eq!(hex::encode(r), "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8");
        assert_eq!(hex::encode(s), "2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5");
        let (px, py) = pubkey(&scalar_in_range(&d).unwrap()).unwrap();
        assert!(ecdsa_verify(&px, &py, &z, &r, &s));
    }

    #[test]
    fn hedged_nonce_differs_and_range_checks() {
        let d = h("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
        let z = h("af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf");
        let a = rfc6979_k(&d, &z, None);
        let b = rfc6979_k(&d, &z, Some(&[7u8; 32]));
        let c = rfc6979_k(&d, &z, Some(&[8u8; 32]));
        assert!(a != b && b != c);
        assert!(scalar_in_range(&[0u8; 32]).is_none());
        assert!(scalar_in_range(&h("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")).is_none());
        assert!(scalar_in_range(&h("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")).is_some());
    }

    #[test]
    fn point_validation_rejects_off_curve() {
        let d = scalar_in_range(&h("0000000000000000000000000000000000000000000000000000000000000002")).unwrap();
        let (x, mut y) = pubkey(&d).unwrap();
        assert!(check_point(&x, &y).is_some());
        y[31] ^= 1;
        assert!(check_point(&x, &y).is_none());
        assert!(check_point(&[0u8; 32], &[0u8; 32]).is_none());
        assert!(check_point(&[0xff; 32], &[0xff; 32]).is_none());
    }

    #[test]
    fn gcm_roundtrip_and_tamper() {
        let key = [3u8; 32];
        let (ct, tag) = gcm_seal(&key, &[1; 12], b"0123456789abcdef", &[9u8; 32]);
        assert_eq!(&gcm_open(&key, &[1; 12], b"0123456789abcdef", &ct, &tag).unwrap()[..], &[9u8; 32]);
        assert!(gcm_open(&key, &[1; 12], b"0123456789abcdeX", &ct, &tag).is_none());
        let mut bad = ct;
        bad[0] ^= 1;
        assert!(gcm_open(&key, &[1; 12], b"0123456789abcdef", &bad, &tag).is_none());
    }
}
