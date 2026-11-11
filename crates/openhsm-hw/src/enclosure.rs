//! Software model of everything inside the tamper enclosure except the SoC:
//! the signing module and the tamper supervisor, wired as on the board.

use crate::mcu::Mcu;
use crate::{Hardware, HwError, SocKeys, TripRecord, SENSORS};
use openhsm_signer::entropy::{EntropyFailure, EntropySource, OsEntropy};
use openhsm_signer::Signer;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// OS entropy with a switch that simulates a failed TRNG.
struct Trng {
    inner: OsEntropy,
    fail: Arc<AtomicBool>,
}

impl EntropySource for Trng {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), EntropyFailure> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(EntropyFailure);
        }
        self.inner.fill(out)
    }
}

pub struct Enclosure {
    signer: Signer,
    mcu: Mcu,
    ceremony: bool,
    trng_fail: Arc<AtomicBool>,
}

impl Enclosure {
    fn assemble(mcu: Mcu) -> Enclosure {
        let trng_fail = Arc::new(AtomicBool::new(false));
        let signer = Signer::new(Box::new(Trng { inner: OsEntropy::new(), fail: trng_fail.clone() }));
        let mut e = Enclosure { signer, mcu, ceremony: false, trng_fail };
        e.power_cycle();
        e
    }

    /// Manufacture: provision the supervisor with a fresh tamper secret.
    pub fn provision(dir: &Path) -> Result<Enclosure, HwError> {
        Ok(Self::assemble(Mcu::provision(dir)?))
    }

    /// Power on an already provisioned enclosure.
    pub fn power_on(dir: &Path) -> Result<Enclosure, HwError> {
        Ok(Self::assemble(Mcu::open(dir)?))
    }

    // ---- the physical world: not reachable from software on the SoC ----

    /// Power cycle of the main domain. The signing module forgets everything;
    /// the supervisor (battery domain) keeps S and re-delivers it over SPI.
    pub fn power_cycle(&mut self) {
        self.signer.set_tamper(self.mcu.tripped().is_some());
        self.signer.set_ceremony_enable(self.ceremony);
        self.signer.reset();
        if let Some(frame) = self.mcu.spi_frame() {
            self.signer.spi_frame(&frame);
        }
    }

    /// A tamper sensor fires: the supervisor erases S and asserts the tamper
    /// line; the signing module wipes itself on that edge.
    pub fn trip(&mut self, sensor: &str) {
        self.mcu.trip(sensor);
        self.signer.set_tamper(true);
    }

    /// The ceremony key-switch, read by the supervisor and forwarded to the
    /// signing module as a level.
    pub fn set_ceremony(&mut self, on: bool) {
        self.ceremony = on;
        self.signer.set_ceremony_enable(on);
    }

    /// One line of the physical-simulation protocol. Returns the reply.
    pub fn physical_command(&mut self, line: &str) -> String {
        let mut w = line.split_whitespace();
        match (w.next(), w.next()) {
            (Some("tamper"), Some(sensor)) if SENSORS.contains(&sensor) => {
                self.trip(sensor);
                "ok: tamper response executed".into()
            }
            (Some("ceremony"), Some(v @ ("on" | "off"))) => {
                self.set_ceremony(v == "on");
                format!("ok: ceremony switch {v}")
            }
            (Some("power-cycle"), None) => {
                self.power_cycle();
                "ok: power cycled".into()
            }
            (Some("trng-fail"), Some(v @ ("on" | "off"))) => {
                self.trng_fail.store(v == "on", Ordering::SeqCst);
                format!("ok: entropy source failure {v}")
            }
            (Some("glitch"), None) => {
                self.signer.sim_inject_sign_fault();
                "ok: next signature computation will be corrupted".into()
            }
            (Some("status"), None) => format!(
                "ok: tripped={} ceremony={} counter={} signer_status={:#04x}",
                self.mcu.tripped().map(|t| t.sensor.as_str()).unwrap_or("no"),
                self.ceremony,
                self.mcu.counter(),
                self.signer.status()
            ),
            _ => format!("error: expected 'tamper <{}>', 'ceremony on|off', 'power-cycle', 'trng-fail on|off', 'glitch' or 'status'", SENSORS.join("|")),
        }
    }
}

impl Hardware for Enclosure {
    fn bus_write(&mut self, ptr: u8, data: &[u8]) -> Result<(), HwError> {
        self.signer.bus_write(ptr, data);
        Ok(())
    }
    fn bus_read(&mut self, ptr: u8, n: usize) -> Result<Vec<u8>, HwError> {
        Ok(self.signer.bus_read(ptr, n.min(256)))
    }
    fn restart_signer(&mut self) -> Result<(), HwError> {
        self.power_cycle();
        Ok(())
    }
    fn soc_keys(&mut self) -> Result<SocKeys, HwError> {
        self.mcu.soc_keys().ok_or_else(|| HwError("the tamper secret has been erased".into()))
    }
    fn counter(&mut self) -> Result<u64, HwError> {
        Ok(self.mcu.counter())
    }
    fn counter_increment(&mut self) -> Result<u64, HwError> {
        self.mcu.increment()
    }
    fn tamper_status(&mut self) -> Result<Option<TripRecord>, HwError> {
        Ok(self.mcu.tripped().cloned())
    }
    fn ceremony_enabled(&mut self) -> Result<bool, HwError> {
        Ok(self.ceremony)
    }
}

/// A shared enclosure: lets a test or the physical-simulation socket keep a
/// handle while the node owns the `Hardware` side.
impl Hardware for Arc<Mutex<Enclosure>> {
    fn bus_write(&mut self, ptr: u8, data: &[u8]) -> Result<(), HwError> {
        self.lock().unwrap_or_else(|e| e.into_inner()).bus_write(ptr, data)
    }
    fn bus_read(&mut self, ptr: u8, n: usize) -> Result<Vec<u8>, HwError> {
        self.lock().unwrap_or_else(|e| e.into_inner()).bus_read(ptr, n)
    }
    fn restart_signer(&mut self) -> Result<(), HwError> {
        self.lock().unwrap_or_else(|e| e.into_inner()).restart_signer()
    }
    fn soc_keys(&mut self) -> Result<SocKeys, HwError> {
        self.lock().unwrap_or_else(|e| e.into_inner()).soc_keys()
    }
    fn counter(&mut self) -> Result<u64, HwError> {
        self.lock().unwrap_or_else(|e| e.into_inner()).counter()
    }
    fn counter_increment(&mut self) -> Result<u64, HwError> {
        self.lock().unwrap_or_else(|e| e.into_inner()).counter_increment()
    }
    fn tamper_status(&mut self) -> Result<Option<TripRecord>, HwError> {
        self.lock().unwrap_or_else(|e| e.into_inner()).tamper_status()
    }
    fn ceremony_enabled(&mut self) -> Result<bool, HwError> {
        self.lock().unwrap_or_else(|e| e.into_inner()).ceremony_enabled()
    }
}
