//! Entropy sources for the module model.
//!
//! On the FPGA the source is the ring-oscillator TRNG (`trng_ro.v`) with
//! repetition-count and adaptive-proportion health tests. The software model
//! draws from the operating system CSPRNG and runs the same two continuous
//! tests on the output (SP 800-90B section 4.4), so a stuck or degenerate
//! source latches the TRNG-failure flag exactly as the hardware would.

use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Raised when the source is unavailable or a health test fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntropyFailure;

pub trait EntropySource: Send {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), EntropyFailure>;
}

/// Repetition Count Test cut-off (identical consecutive bytes).
const RCT_CUTOFF: u32 = 6;
/// Adaptive Proportion Test window and cut-off (occurrences of the first byte).
const APT_WINDOW: u32 = 512;
const APT_CUTOFF: u32 = 32;

/// Continuous health tests shared by every source.
#[derive(Default)]
pub struct HealthTests {
    last: Option<u8>,
    run: u32,
    apt_ref: u8,
    apt_seen: u32,
    apt_count: u32,
    failed: bool,
}

impl HealthTests {
    pub fn feed(&mut self, data: &[u8]) -> Result<(), EntropyFailure> {
        for &b in data {
            if self.last == Some(b) {
                self.run += 1;
                if self.run >= RCT_CUTOFF {
                    self.failed = true;
                }
            } else {
                self.last = Some(b);
                self.run = 1;
            }
            if self.apt_seen == 0 {
                self.apt_ref = b;
                self.apt_count = 0;
            }
            if b == self.apt_ref {
                self.apt_count += 1;
                if self.apt_count >= APT_CUTOFF {
                    self.failed = true;
                }
            }
            self.apt_seen = (self.apt_seen + 1) % APT_WINDOW;
        }
        if self.failed {
            Err(EntropyFailure)
        } else {
            Ok(())
        }
    }
}

/// Operating-system CSPRNG with continuous health tests.
#[derive(Default)]
pub struct OsEntropy {
    health: HealthTests,
}

impl OsEntropy {
    pub fn new() -> Self {
        Self::default()
    }
}

impl EntropySource for OsEntropy {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), EntropyFailure> {
        getrandom::getrandom(out).map_err(|_| EntropyFailure)?;
        self.health.feed(out).inspect_err(|_| out.fill(0))
    }
}

/// Deterministic source for reproducible tests (SHA-256 in counter mode).
/// NOT RANDOM. Mirrors `SIM_TRNG = 1` in the RTL. The shared flag lets a test
/// simulate a TRNG failure or a stuck-at fault.
pub struct SimEntropy {
    seed: [u8; 32],
    ctr: u64,
    pub fail: Arc<AtomicBool>,
    pub stuck: Arc<AtomicBool>,
    health: HealthTests,
}

impl SimEntropy {
    pub fn new(seed: &[u8]) -> Self {
        Self {
            seed: Sha256::digest(seed).into(),
            ctr: 0,
            fail: Arc::new(AtomicBool::new(false)),
            stuck: Arc::new(AtomicBool::new(false)),
            health: HealthTests::default(),
        }
    }
}

impl EntropySource for SimEntropy {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), EntropyFailure> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(EntropyFailure);
        }
        if self.stuck.load(Ordering::SeqCst) {
            out.fill(0x55);
        } else {
            for chunk in out.chunks_mut(32) {
                let mut h = Sha256::new();
                h.update(self.seed);
                h.update(self.ctr.to_be_bytes());
                self.ctr += 1;
                chunk.copy_from_slice(&h.finalize()[..chunk.len()]);
            }
        }
        self.health.feed(out).inspect_err(|_| out.fill(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_entropy_passes_health_tests() {
        let mut e = OsEntropy::new();
        let mut buf = [0u8; 4096];
        for _ in 0..64 {
            e.fill(&mut buf).unwrap();
        }
    }

    #[test]
    fn stuck_source_is_detected() {
        let mut e = SimEntropy::new(b"x");
        let mut buf = [0u8; 32];
        e.fill(&mut buf).unwrap();
        e.stuck.store(true, Ordering::SeqCst);
        assert!(e.fill(&mut buf).is_err());
        assert_eq!(buf, [0u8; 32]);
    }
}
