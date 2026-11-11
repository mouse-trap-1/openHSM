//! Model of the battery-backed tamper supervisor (STM32U5).
//!
//! The real supervisor sits in its own always-on power domain, watches the
//! mesh, lid switches, light sensor and accelerometer, and holds the 256-bit
//! tamper secret S. After every boot it sends `0xA5 || S` to the signing
//! module over a receive-only SPI link. When a sensor trips it erases S in
//! hardware and raises the tamper line; nothing sealed to S can be opened
//! again.
//!
//! Three things in this model go beyond the existing hardware description
//! and are proposed for the supervisor firmware:
//!
//! * the SoC receives **derived keys**, never S (see `SocKeys`);
//! * a **monotonic counter** anchors the node's audit chain against rollback;
//! * a **ceremony key-switch** input is forwarded to the signing module.
//!
//! The model keeps the supervisor's battery-backed RAM in a file. That file
//! stands in for hardware inside the enclosure; it is the one place where the
//! prototype stores a root secret on disk.

use crate::{HwError, SocKeys};
use openhsm_signer::crypto::hmac256;
use openhsm_signer::label;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

pub const SENSORS: &[&str] = &["mesh", "lid", "light", "accelerometer", "voltage", "temperature"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TripRecord {
    pub sensor: String,
    pub ts: u64,
}

#[derive(Serialize, Deserialize)]
struct Ram {
    secret: Option<String>,
    tripped: Option<TripRecord>,
    counter: u64,
}

pub(crate) struct Mcu {
    path: PathBuf,
    ram: Ram,
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

impl Mcu {
    fn file(dir: &Path) -> PathBuf {
        dir.join("mcu-ram.json")
    }

    /// Provision a new supervisor with a fresh secret. Refuses to overwrite.
    pub fn provision(dir: &Path) -> Result<Mcu, HwError> {
        let path = Self::file(dir);
        if path.exists() {
            return Err(HwError("tamper supervisor is already provisioned".into()));
        }
        fs::create_dir_all(dir).map_err(|e| HwError(e.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e| HwError(e.to_string()))?;
        }
        let mut s = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(&mut s[..]).map_err(|e| HwError(format!("entropy source unavailable: {e}")))?;
        let mcu = Mcu { path, ram: Ram { secret: Some(hex::encode(&s[..])), tripped: None, counter: 0 } };
        mcu.persist()?;
        Ok(mcu)
    }

    pub fn open(dir: &Path) -> Result<Mcu, HwError> {
        let path = Self::file(dir);
        let raw = fs::read(&path).map_err(|e| HwError(format!("tamper supervisor is not provisioned ({e})")))?;
        let ram: Ram = serde_json::from_slice(&raw).map_err(|e| HwError(format!("tamper supervisor state unreadable: {e}")))?;
        Ok(Mcu { path, ram })
    }

    fn persist(&self) -> Result<(), HwError> {
        // Battery-backed RAM, not storage: atomic replace, no fsync.
        let tmp = self.path.with_extension("tmp");
        let run = || -> std::io::Result<()> {
            let mut f = fs::File::create(&tmp)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                f.set_permissions(fs::Permissions::from_mode(0o600))?;
            }
            f.write_all(&serde_json::to_vec(&self.ram).unwrap_or_default())?;
            fs::rename(&tmp, &self.path)
        };
        run().map_err(|e| HwError(format!("supervisor RAM: {e}")))
    }

    fn secret(&self) -> Option<Zeroizing<[u8; 32]>> {
        if self.ram.tripped.is_some() {
            return None;
        }
        let mut s = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(self.ram.secret.as_ref()?, &mut s[..]).ok()?;
        Some(s)
    }

    /// The SPI frame for the signing module. Stays inside the enclosure.
    pub fn spi_frame(&self) -> Option<Zeroizing<Vec<u8>>> {
        let s = self.secret()?;
        let mut f = Zeroizing::new(vec![openhsm_signer::SPI_HEADER]);
        f.extend_from_slice(&s[..]);
        Some(f)
    }

    /// What the SoC is given: keys derived from S, never S.
    pub fn soc_keys(&self) -> Option<SocKeys> {
        let s = self.secret()?;
        Some(SocKeys { chan: Zeroizing::new(hmac256(&s[..], &[label::CHAN])), seal: Zeroizing::new(hmac256(&s[..], &[b"SOC-SEAL-v1"])) })
    }

    /// A sensor fired: erase S and latch. This cannot be undone; the node
    /// must be re-provisioned and re-enrolled.
    pub fn trip(&mut self, sensor: &str) {
        self.ram.secret = None;
        if self.ram.tripped.is_none() {
            self.ram.tripped = Some(TripRecord { sensor: sensor.to_string(), ts: now_ms() });
        }
        let _ = self.persist();
    }

    pub fn tripped(&self) -> Option<&TripRecord> {
        self.ram.tripped.as_ref()
    }

    pub fn counter(&self) -> u64 {
        self.ram.counter
    }

    /// Monotonic counter: can only move forward by one.
    pub fn increment(&mut self) -> Result<u64, HwError> {
        self.ram.counter = self.ram.counter.checked_add(1).ok_or_else(|| HwError("monotonic counter exhausted".into()))?;
        self.persist()?;
        Ok(self.ram.counter)
    }
}
