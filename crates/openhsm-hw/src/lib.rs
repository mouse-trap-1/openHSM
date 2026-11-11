//! Hardware abstraction for OpenHSM.
//!
//! [`Hardware`] is everything the SoC can reach inside the tamper enclosure:
//! the I2C bus to the signing module and the services of the tamper
//! supervisor. The node is written against this trait, so the same node code
//! runs against
//!
//! * [`Enclosure`], an in-process model (signing-module model plus tamper
//!   supervisor model), used by tests and single-process demos;
//! * [`RemoteHardware`], the same model in a **separate process**
//!   (`openhsm-hwsim`), which reproduces the real isolation: no key of the
//!   signing module and no tamper secret ever exists in the node's address
//!   space;
//! * a driver for the real board (Linux `i2c-dev` plus the supervisor link),
//!   which is the remaining piece between this prototype and hardware.
//!
//! The physical world (sensors, the ceremony key-switch, power) is not part
//! of `Hardware`: software on the SoC cannot actuate it. The models expose it
//! through [`Enclosure::physical_command`] for simulation.

#![forbid(unsafe_code)]

mod enclosure;
mod mcu;
mod remote;

pub use enclosure::Enclosure;
pub use mcu::{TripRecord, SENSORS};
#[cfg(unix)]
pub use remote::{serve_physical, serve_soc, RemoteHardware};

use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HwError(pub String);

impl std::fmt::Display for HwError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Keys the tamper supervisor derives from the tamper secret S and hands to
/// the SoC secure world. The SoC never receives S itself, so it cannot derive
/// the signing module's seal key and cannot open a sealed KEK.
pub struct SocKeys {
    /// `HMAC(S, "SN-CHAN")`: authenticates commands to the signing module.
    pub chan: Zeroizing<[u8; 32]>,
    /// `HMAC(S, "SOC-SEAL-v1")`: seals the SoC's own keys at rest.
    pub seal: Zeroizing<[u8; 32]>,
}

pub trait Hardware: Send {
    /// I2C write to the signing module: register pointer, then data.
    fn bus_write(&mut self, ptr: u8, data: &[u8]) -> Result<(), HwError>;
    /// I2C read of `n` bytes starting at `ptr`.
    fn bus_read(&mut self, ptr: u8, n: usize) -> Result<Vec<u8>, HwError>;
    /// Ask the supervisor to reset the signing module and re-deliver the
    /// tamper secret to it. Done once at every SoC boot.
    fn restart_signer(&mut self) -> Result<(), HwError>;
    /// The SoC's keys for this boot. Fails after a tamper event.
    fn soc_keys(&mut self) -> Result<SocKeys, HwError>;
    /// Monotonic counter held in the supervisor's battery domain.
    fn counter(&mut self) -> Result<u64, HwError>;
    fn counter_increment(&mut self) -> Result<u64, HwError>;
    /// The supervisor's "kill" line: `Some` once any sensor has tripped.
    fn tamper_status(&mut self) -> Result<Option<TripRecord>, HwError>;
    /// State of the ceremony key-switch.
    fn ceremony_enabled(&mut self) -> Result<bool, HwError>;
}
