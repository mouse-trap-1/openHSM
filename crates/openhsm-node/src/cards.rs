//! Operator cards for break-glass recovery.
//!
//! A card maps a 32-byte challenge to a secret response. The production card
//! is a YubiKey OTP slot in HMAC-SHA1 challenge-response mode with touch
//! required (`ykman otp chalresp --touch --generate 2`), read through the
//! node's front-panel reader. The software card is a test double with the
//! same interface: a file holding a 20-byte HMAC-SHA1 key, placed in the
//! node's card slot directory to "insert" it.
//!
//! The card never sees a share and the signing module never sees the card's
//! key. The node sees the card-derived secret `r` for the duration of one
//! command (see the specification, section on ceremonies).

use crate::state::valid_id;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;
use std::path::Path;
use std::process::Command;
use zeroize::Zeroizing;

/// Ask the named card to answer a challenge.
pub fn respond(slot_dir: &Path, name: &str, challenge: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, String> {
    if let Some(rest) = name.strip_prefix("yubikey:") {
        // "yubikey:<serial>" or "yubikey:<serial>:<slot>". Untested on hardware.
        let mut it = rest.split(':');
        let serial = it.next().unwrap_or("");
        let slot = it.next().unwrap_or("2");
        if !serial.bytes().all(|c| c.is_ascii_digit()) || serial.is_empty() || !matches!(slot, "1" | "2") {
            return Err("invalid YubiKey card name".into());
        }
        let out =
            Command::new("ykman").args(["--device", serial, "otp", "calculate", slot, &hex::encode(challenge)]).output().map_err(|e| format!("ykman: {e}"))?;
        if !out.status.success() {
            return Err("YubiKey did not answer the challenge".into());
        }
        let text = String::from_utf8_lossy(&out.stdout);
        return hex::decode(text.trim()).map(Zeroizing::new).map_err(|_| "unexpected ykman output".to_string());
    }
    if !valid_id(name) {
        return Err("invalid card name".into());
    }
    let path = slot_dir.join(format!("{name}.card"));
    let text = std::fs::read_to_string(&path).map_err(|_| format!("card {name} is not present in the reader"))?;
    let key = Zeroizing::new(hex::decode(text.trim()).map_err(|_| "card file is not hex".to_string())?);
    if key.len() != 20 {
        return Err("card key must be 20 bytes".into());
    }
    let mut m = <Hmac<Sha1> as Mac>::new_from_slice(&key).map_err(|e| e.to_string())?;
    m.update(challenge);
    Ok(Zeroizing::new(m.finalize().into_bytes().to_vec()))
}

/// r = HMAC-SHA256(key = card response, "SN-CARD-v1" || challenge).
pub fn card_secret(response: &[u8], challenge: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(response).expect("HMAC accepts any key length");
    m.update(b"SN-CARD-v1");
    m.update(challenge);
    Zeroizing::new(m.finalize().into_bytes().into())
}
