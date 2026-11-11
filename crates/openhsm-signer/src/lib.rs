//! Software model of the OpenHSM secp256k1 signing module.
//!
//! This crate reproduces, at register level, the behaviour of the FPGA design
//! in `FPGA/V0.4/sign_node_top.v`: the I2C register map, MAC-authenticated
//! commands, the volatile secret store, the KEK lifecycle, wrapped wallet keys,
//! ECIES transfer of the cluster KEK, Shamir break-glass recovery and the
//! asynchronous tamper wipe. A host driver written for the FPGA (for example
//! `FPGA/V0.4/sn_host.py`) drives this model unchanged.
//!
//! On top of protocol version 0xB1 the model implements the hardening items
//! that the FPGA specification lists as open (section 12, items 4 and 5). They
//! are reported as protocol version 0xB2 and are intended for back-porting to
//! the RTL:
//!
//! * **X1 response MAC.** Register `RMAC` (0xC4) authenticates every response.
//! * **X2 lockout.** Eight consecutive failed authentications lock the command
//!   channel until reset.
//! * **X3 verify before release.** A signature is verified against the public
//!   key recomputed from the unwrapped key before it is placed in the buffers.
//! * **X4 buffer hygiene.** On any error the data buffers are cleared; the
//!   command MAC is cleared after every command.
//! * **X6 ceremony switch.** An input pin, driven by the tamper supervisor
//!   from a physical key-switch, gates every command that can move a KEK in
//!   or out of the module (export, import, split, share, restore). With the
//!   switch off, code running on the SoC cannot extract or replace the KEK,
//!   whatever keys it holds.
//! * **X5 confidential card secret.** Commands 0x56 / 0x57 are SHARE_GET /
//!   SHARE_PUT with BUF_B XOR-masked by `HMAC(chan_key, "SN-CONF-v1" || nonce
//!   || ctr)`, so a probe on the I2C bus does not see the card secret.
//!
//! The model is functional, not cycle-accurate: commands complete inside the
//! bus write that starts them, so `STATUS.busy` is never observed set.

#![forbid(unsafe_code)]

pub mod crypto;
pub mod entropy;
pub mod shamir;

use crypto::{ct_eq, gcm_open, gcm_seal, hmac256, Word};
use entropy::EntropySource;
use zeroize::{Zeroize, Zeroizing};

/// Register addresses (8-bit pointer, big-endian values, auto-increment).
pub mod reg {
    pub const STATUS: u8 = 0x00;
    pub const CMD: u8 = 0x01;
    pub const ERROR: u8 = 0x02;
    pub const STATUS2: u8 = 0x03;
    pub const CTR: u8 = 0x04;
    pub const NONCE: u8 = 0x08;
    pub const WID: u8 = 0x18;
    pub const IV: u8 = 0x28;
    pub const TAG: u8 = 0x34;
    pub const BUF_A: u8 = 0x44;
    pub const BUF_B: u8 = 0x64;
    pub const BUF_C: u8 = 0x84;
    pub const MAC: u8 = 0xA4;
    /// Extension X1: response MAC, read-only, 32 bytes.
    pub const RMAC: u8 = 0xC4;
    pub const VERSION: u8 = 0xFF;
}

/// Command codes.
pub mod cmd {
    pub const KEK_GEN: u8 = 0x10;
    pub const KEK_SEAL: u8 = 0x11;
    pub const KEK_UNSEAL: u8 = 0x12;
    pub const KEK_ERASE: u8 = 0x13;
    pub const KEK_NEW_GEN: u8 = 0x14;
    pub const REWRAP: u8 = 0x15;
    pub const KEK_PROMOTE: u8 = 0x16;
    pub const KEK_FP: u8 = 0x17;
    pub const GEN_WALLET: u8 = 0x20;
    pub const SIGN: u8 = 0x21;
    pub const PUBKEY: u8 = 0x22;
    pub const ENROL_GEN: u8 = 0x40;
    pub const KEK_EXPORT: u8 = 0x41;
    pub const KEK_IMPORT: u8 = 0x42;
    pub const KEK_NEW_EXPORT: u8 = 0x45;
    pub const KEK_NEW_IMPORT: u8 = 0x46;
    pub const SPLIT_BEGIN: u8 = 0x50;
    pub const SHARE_GET: u8 = 0x51;
    pub const SPLIT_END: u8 = 0x52;
    pub const SHARE_PUT: u8 = 0x53;
    pub const RESTORE: u8 = 0x54;
    pub const RESTORE_ABORT: u8 = 0x55;
    /// Extension X5: as SHARE_GET / SHARE_PUT, with the card secret in BUF_B
    /// masked so that it never crosses the bus in the clear.
    pub const SHARE_GET_C: u8 = 0x56;
    pub const SHARE_PUT_C: u8 = 0x57;
}

/// Error codes (ERROR register, low nibble).
pub mod err {
    pub const OK: u8 = 0;
    pub const NO_SESSION: u8 = 1;
    pub const NO_KEK: u8 = 2;
    pub const KEK_EXISTS: u8 = 3;
    pub const TRNG: u8 = 4;
    pub const AUTH: u8 = 5;
    pub const SIGN: u8 = 6;
    pub const TAMPER: u8 = 7;
    pub const BAD_CMD: u8 = 8;
    pub const PARAM: u8 = 9;
    pub const UNWRAP: u8 = 10;
    pub const POINT: u8 = 11;
    pub const NO_ENROL: u8 = 12;
    pub const SHARE: u8 = 13;
    pub const NO_SHARES: u8 = 14;
    pub const NO_KEK2: u8 = 15;
}

/// STATUS register bits.
pub mod status {
    pub const BUSY: u8 = 1 << 0;
    pub const DONE: u8 = 1 << 1;
    pub const ERROR: u8 = 1 << 2;
    pub const KEK: u8 = 1 << 3;
    pub const TAMPER: u8 = 1 << 4;
    pub const TRNG_FAIL: u8 = 1 << 5;
    pub const SESSION: u8 = 1 << 6;
    pub const ENROL: u8 = 1 << 7;
}

/// Protocol version reported in the VERSION register.
pub const VERSION: u8 = 0xB2;
/// Header byte of the SPI frame from the tamper MCU.
pub const SPI_HEADER: u8 = 0xA5;
/// Extension X2: consecutive authentication failures before lockout.
pub const MAX_AUTH_FAILURES: u8 = 8;

/// Domain-separation labels (identical to the RTL localparams).
pub mod label {
    pub const CHAN: &[u8] = b"SN-CHAN";
    pub const SEAL: &[u8] = b"SN-SEAL";
    pub const KEK_FP: &[u8] = b"KEK-FP-v1";
    pub const ECIES_KDF: &[u8] = b"ECIES-KEK-v1";
    pub const SHARE_WRAP: &[u8] = b"SHARE-WRAP-v1";
    pub const SEAL_AAD: &[u8; 16] = b"KEK-SEAL-v1\0\0\0\0\0";
    pub const ECIES_AAD: &[u8; 16] = b"KEK-ECIES-v1\0\0\0\0";
    /// Extension X1.
    pub const RESP: &[u8] = b"SN-RESP-v1";
    /// Extension X5.
    pub const CONF: &[u8] = b"SN-CONF-v1";
}

type Secret = Zeroizing<Word>;

struct Split {
    m: u8,
    n: u8,
    fp: [u8; 13],
    coefs: Vec<Secret>,
}

/// The signing module.
pub struct Signer {
    entropy: Box<dyn EntropySource>,
    // Host-visible registers.
    ctr_in: [u8; 4],
    last_ctr: u32,
    nonce: [u8; 16],
    wid: [u8; 16],
    iv: [u8; 12],
    tag: [u8; 16],
    a: Word,
    b: Word,
    c: Word,
    mac_in: Word,
    rmac: Word,
    done: bool,
    err: u8,
    // Secret store: volatile only, cleared by tamper and reset.
    chan_key: Option<Secret>,
    seal_key: Option<Secret>,
    kek: Option<Secret>,
    kek2: Option<Secret>,
    enrol_d: Option<Secret>,
    enrol_pub: (Word, Word),
    // Shamir state.
    split: Option<Split>,
    shares: Vec<(u8, Secret)>,
    rest: Option<(u8, u8, [u8; 13])>,
    // Control state.
    tamper_level: bool,
    tamper_latched: bool,
    ceremony_en: bool,
    trng_fail: bool,
    auth_failures: u8,
    locked: bool,
    sim_fault_next_sign: bool,
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material.
        f.debug_struct("Signer").field("status", &format_args!("{:#04x}", self.status())).field("error", &self.err).finish_non_exhaustive()
    }
}

impl Signer {
    pub fn new(entropy: Box<dyn EntropySource>) -> Self {
        Self {
            entropy,
            ctr_in: [0; 4],
            last_ctr: 0,
            nonce: [0; 16],
            wid: [0; 16],
            iv: [0; 12],
            tag: [0; 16],
            a: [0; 32],
            b: [0; 32],
            c: [0; 32],
            mac_in: [0; 32],
            rmac: [0; 32],
            done: false,
            err: 0,
            chan_key: None,
            seal_key: None,
            kek: None,
            kek2: None,
            enrol_d: None,
            enrol_pub: ([0; 32], [0; 32]),
            split: None,
            shares: Vec::new(),
            rest: None,
            tamper_level: false,
            tamper_latched: false,
            ceremony_en: false,
            trng_fail: false,
            auth_failures: 0,
            locked: false,
            sim_fault_next_sign: false,
        }
    }

    // ------------------------------------------------------------ pins ----

    /// Reset (rst_n pulse or power cycle). Clears every register and secret
    /// and the tamper latch; the latch is set again at once if the tamper
    /// input is still asserted.
    pub fn reset(&mut self) {
        self.wipe_all();
        self.last_ctr = 0;
        self.ctr_in = [0; 4];
        self.done = false;
        self.err = 0;
        self.tamper_latched = false;
        self.trng_fail = false;
        self.auth_failures = 0;
        self.locked = false;
        self.sim_fault_next_sign = false;
        if self.tamper_level {
            self.trip();
        }
    }

    /// Tamper input (asynchronous, active high). The wipe happens on the
    /// rising level regardless of what the module is doing.
    pub fn set_tamper(&mut self, level: bool) {
        self.tamper_level = level;
        if level {
            self.trip();
        }
    }

    /// Ceremony switch input (extension X6). Level-sensitive; not affected
    /// by reset because it is a pin, not state.
    pub fn set_ceremony_enable(&mut self, level: bool) {
        self.ceremony_en = level;
    }

    /// One SPI frame from the tamper MCU: `0xA5 || S`. Accepted once per
    /// reset; wrong length or header is discarded.
    pub fn spi_frame(&mut self, frame: &[u8]) {
        if self.tamper_latched || frame.len() != 33 || frame[0] != SPI_HEADER {
            return;
        }
        if self.chan_key.is_some() {
            return; // session already up: ignore
        }
        self.done = false;
        self.err = 0;
        let mut s = Zeroizing::new([0u8; 32]);
        s.copy_from_slice(&frame[1..]);
        let mut n = [0u8; 16];
        if self.trng(&mut n).is_err() {
            self.finish(err::TRNG);
            return;
        }
        self.nonce = n;
        self.chan_key = Some(Zeroizing::new(hmac256(&s[..], &[label::CHAN])));
        self.seal_key = Some(Zeroizing::new(hmac256(&s[..], &[label::SEAL])));
        self.last_ctr = 0;
        self.finish(err::OK);
    }

    // ------------------------------------------------------------- bus ----

    /// I2C write transaction: register pointer followed by data bytes.
    pub fn bus_write(&mut self, ptr: u8, data: &[u8]) {
        let mut p = ptr;
        for &byte in data {
            if p == reg::CMD {
                self.execute(byte);
            } else if !self.tamper_latched {
                self.write_reg(p, byte);
            }
            p = p.wrapping_add(1);
        }
    }

    /// I2C read transaction of `n` bytes starting at `ptr`.
    pub fn bus_read(&self, ptr: u8, n: usize) -> Vec<u8> {
        (0..n).map(|i| self.read_reg(ptr.wrapping_add(i as u8))).collect()
    }

    fn write_reg(&mut self, p: u8, v: u8) {
        fn put(buf: &mut [u8], base: u8, p: u8, v: u8) -> bool {
            let off = p.wrapping_sub(base) as usize;
            if p >= base && off < buf.len() {
                buf[off] = v;
                true
            } else {
                false
            }
        }
        let _ = put(&mut self.ctr_in, reg::CTR, p, v)
            || put(&mut self.wid, reg::WID, p, v)
            || put(&mut self.iv, reg::IV, p, v)
            || put(&mut self.tag, reg::TAG, p, v)
            || put(&mut self.a, reg::BUF_A, p, v)
            || put(&mut self.b, reg::BUF_B, p, v)
            || put(&mut self.c, reg::BUF_C, p, v)
            || put(&mut self.mac_in, reg::MAC, p, v);
    }

    fn read_reg(&self, p: u8) -> u8 {
        fn get(buf: &[u8], base: u8, p: u8) -> Option<u8> {
            let off = p.wrapping_sub(base) as usize;
            (p >= base && off < buf.len()).then(|| buf[off])
        }
        match p {
            reg::STATUS => self.status(),
            reg::ERROR => self.err & 0x0F,
            reg::STATUS2 => self.status2(),
            reg::VERSION => VERSION,
            _ => get(&self.ctr_in, reg::CTR, p)
                .or_else(|| get(&self.nonce, reg::NONCE, p))
                .or_else(|| get(&self.wid, reg::WID, p))
                .or_else(|| get(&self.iv, reg::IV, p))
                .or_else(|| get(&self.tag, reg::TAG, p))
                .or_else(|| get(&self.a, reg::BUF_A, p))
                .or_else(|| get(&self.b, reg::BUF_B, p))
                .or_else(|| get(&self.c, reg::BUF_C, p))
                .or_else(|| get(&self.rmac, reg::RMAC, p))
                .unwrap_or(0), // MAC (0xA4..0xC3) and unmapped addresses read as zero
        }
    }

    pub fn status(&self) -> u8 {
        let mut s = 0;
        if self.done {
            s |= status::DONE;
        }
        if self.err != 0 {
            s |= status::ERROR;
        }
        if self.kek.is_some() {
            s |= status::KEK;
        }
        if self.tamper_latched {
            s |= status::TAMPER;
        }
        if self.trng_fail {
            s |= status::TRNG_FAIL;
        }
        if self.chan_key.is_some() {
            s |= status::SESSION;
        }
        if self.enrol_d.is_some() {
            s |= status::ENROL;
        }
        s
    }

    fn status2(&self) -> u8 {
        let mut s = (self.shares.len() as u8) & 0x0F;
        if self.split.is_some() {
            s |= 1 << 5;
        }
        if self.kek2.is_some() {
            s |= 1 << 6;
        }
        if self.ceremony_en {
            s |= 1 << 4; // extension X6
        }
        if self.locked {
            s |= 1 << 7; // extension X2
        }
        s
    }

    // ------------------------------------------------- simulation hooks ----

    /// Test instrumentation: corrupt the next signature computation, as a
    /// voltage or clock glitch would. Used to demonstrate that
    /// verify-before-release (X3) withholds a faulty signature.
    pub fn sim_inject_sign_fault(&mut self) {
        self.sim_fault_next_sign = true;
    }

    // -------------------------------------------------------- internals ----

    fn trip(&mut self) {
        self.wipe_all();
        self.tamper_latched = true;
        self.err = err::TAMPER;
        self.done = true;
    }

    fn wipe_all(&mut self) {
        self.chan_key = None;
        self.seal_key = None;
        self.kek = None;
        self.kek2 = None;
        self.enrol_d = None;
        self.enrol_pub = ([0; 32], [0; 32]);
        self.split = None;
        self.shares.clear();
        self.rest = None;
        self.nonce.zeroize();
        self.wid.zeroize();
        self.iv.zeroize();
        self.tag.zeroize();
        self.a.zeroize();
        self.b.zeroize();
        self.c.zeroize();
        self.mac_in.zeroize();
        self.rmac.zeroize();
    }

    fn finish(&mut self, e: u8) {
        self.err = e;
        self.done = true;
    }

    fn trng(&mut self, out: &mut [u8]) -> Result<(), u8> {
        self.entropy.fill(out).map_err(|_| {
            self.trng_fail = true;
            err::TRNG
        })
    }

    /// Key-generation routine of the RTL: d = HMAC(key = a, msg = b) for two
    /// TRNG words; redraw unless 1 <= d < n.
    fn rand_scalar(&mut self) -> Result<Secret, u8> {
        loop {
            let mut a = Zeroizing::new([0u8; 32]);
            let mut b = Zeroizing::new([0u8; 32]);
            self.trng(&mut a[..])?;
            self.trng(&mut b[..])?;
            let d = Zeroizing::new(hmac256(&a[..], &[&b[..]]));
            if crypto::scalar_in_range(&d).is_some() {
                return Ok(d);
            }
        }
    }

    fn rand_iv(&mut self) -> Result<(), u8> {
        let mut iv = [0u8; 12];
        self.trng(&mut iv)?;
        self.iv = iv;
        Ok(())
    }

    fn execute(&mut self, cmd_b: u8) {
        self.done = false;
        self.err = 0;
        self.rmac = [0; 32];
        if self.tamper_latched {
            self.finish(err::TAMPER);
            return;
        }
        let Some(chan) = self.chan_key.clone() else {
            self.finish(err::NO_SESSION);
            return;
        };
        // Authenticate: MAC over nonce || ctr || cmd || wid || iv || tag || A || B || C,
        // and a counter strictly greater than the last accepted one.
        let expect = hmac256(&chan[..], &[&self.nonce, &self.ctr_in, &[cmd_b], &self.wid, &self.iv, &self.tag, &self.a, &self.b, &self.c]);
        let ctr = u32::from_be_bytes(self.ctr_in);
        let mac_ok = ct_eq(&expect, &self.mac_in);
        self.mac_in.zeroize();
        if self.locked || !mac_ok || ctr <= self.last_ctr {
            if !self.locked {
                self.auth_failures += 1;
                if self.auth_failures >= MAX_AUTH_FAILURES {
                    self.locked = true;
                }
            }
            self.finish(err::AUTH);
            return;
        }
        self.auth_failures = 0;
        self.last_ctr = ctr;

        let gated = matches!(
            cmd_b,
            cmd::KEK_EXPORT
                | cmd::KEK_NEW_EXPORT
                | cmd::KEK_IMPORT
                | cmd::KEK_NEW_IMPORT
                | cmd::SPLIT_BEGIN
                | cmd::SHARE_GET
                | cmd::SHARE_GET_C
                | cmd::SHARE_PUT
                | cmd::SHARE_PUT_C
                | cmd::RESTORE
        );
        let result = if cmd_b >> 4 == 0xF || (gated && !self.ceremony_en) {
            // X6: KEK-moving commands do not exist while the switch is off.
            Err(err::BAD_CMD)
        } else if cmd_b == cmd::SHARE_GET_C || cmd_b == cmd::SHARE_PUT_C {
            // X5: unmask the card secret, then run the plain command.
            let pad = Zeroizing::new(hmac256(&chan[..], &[label::CONF, &self.nonce, &self.ctr_in]));
            self.b.iter_mut().zip(pad.iter()).for_each(|(b, p)| *b ^= p);
            self.dispatch(if cmd_b == cmd::SHARE_GET_C { cmd::SHARE_GET } else { cmd::SHARE_PUT })
        } else {
            self.dispatch(cmd_b)
        };
        let e = match result {
            Ok(()) => err::OK,
            Err(e) => {
                // X4: nothing is left in the data buffers after a failure.
                self.iv.zeroize();
                self.tag.zeroize();
                self.a.zeroize();
                self.b.zeroize();
                self.c.zeroize();
                e
            }
        };
        // X1: authenticate the response.
        self.rmac = hmac256(&chan[..], &[label::RESP, &self.nonce, &self.ctr_in, &[cmd_b, e], &self.wid, &self.iv, &self.tag, &self.a, &self.b, &self.c]);
        self.finish(e);
    }

    fn need_kek(&self) -> Result<Secret, u8> {
        self.kek.clone().ok_or(err::NO_KEK)
    }

    fn unwrap_wallet(&self, kek: &Word) -> Result<Secret, u8> {
        gcm_open(kek, &self.iv, &self.wid, &self.a, &self.tag).ok_or(err::UNWRAP)
    }

    fn dispatch(&mut self, c: u8) -> Result<(), u8> {
        match c {
            cmd::KEK_GEN => {
                if self.kek.is_some() {
                    return Err(err::KEK_EXISTS);
                }
                self.kek = Some(self.rand_scalar()?);
                Ok(())
            }
            cmd::KEK_SEAL => {
                let kek = self.need_kek()?;
                let seal = self.seal_key.clone().ok_or(err::NO_SESSION)?;
                self.rand_iv()?;
                let (ct, tag) = gcm_seal(&seal, &self.iv, label::SEAL_AAD, &kek);
                self.a = ct;
                self.tag = tag;
                Ok(())
            }
            cmd::KEK_UNSEAL => {
                if self.kek.is_some() {
                    return Err(err::KEK_EXISTS);
                }
                let seal = self.seal_key.clone().ok_or(err::NO_SESSION)?;
                let kek = gcm_open(&seal, &self.iv, label::SEAL_AAD, &self.a, &self.tag).ok_or(err::UNWRAP)?;
                self.kek = Some(kek);
                Ok(())
            }
            cmd::KEK_ERASE => {
                self.kek = None;
                self.kek2 = None;
                self.enrol_d = None;
                self.split = None;
                self.shares.clear();
                self.rest = None;
                Ok(())
            }
            cmd::KEK_NEW_GEN => {
                self.need_kek()?;
                if self.kek2.is_some() {
                    return Err(err::KEK_EXISTS);
                }
                self.kek2 = Some(self.rand_scalar()?);
                Ok(())
            }
            cmd::REWRAP => {
                let kek = self.need_kek()?;
                let kek2 = self.kek2.clone().ok_or(err::NO_KEK2)?;
                let d = self.unwrap_wallet(&kek)?;
                self.rand_iv()?;
                let (ct, tag) = gcm_seal(&kek2, &self.iv, &self.wid, &d);
                self.a = ct;
                self.tag = tag;
                Ok(())
            }
            cmd::KEK_PROMOTE => {
                let kek2 = self.kek2.take().ok_or(err::NO_KEK2)?;
                self.kek = Some(kek2);
                // Old shares belong to the old KEK.
                self.split = None;
                self.shares.clear();
                self.rest = None;
                Ok(())
            }
            cmd::KEK_FP => {
                let kek = self.need_kek()?;
                self.b = hmac256(&kek[..], &[label::KEK_FP]);
                Ok(())
            }
            cmd::GEN_WALLET => {
                let kek = self.need_kek()?;
                let d = self.rand_scalar()?;
                self.rand_iv()?;
                let (ct, tag) = gcm_seal(&kek, &self.iv, &self.wid, &d);
                let ds = crypto::scalar_in_range(&d).ok_or(err::SIGN)?;
                let (px, py) = crypto::pubkey(&ds).ok_or(err::SIGN)?;
                self.a = ct;
                self.tag = tag;
                self.b = px;
                self.c = py;
                Ok(())
            }
            cmd::SIGN => {
                let kek = self.need_kek()?;
                let d = self.unwrap_wallet(&kek)?;
                let ds = crypto::scalar_in_range(&d).ok_or(err::SIGN)?;
                // Hedged RFC 6979: fresh entropy if the TRNG is healthy,
                // otherwise plain deterministic RFC 6979.
                let mut extra = Zeroizing::new([0u8; 32]);
                let hedged = self.trng(&mut extra[..]).is_ok();
                let digest = self.b;
                let k = crypto::rfc6979_k(&d, &digest, hedged.then_some(&*extra));
                let ks = crypto::scalar_in_range(&k).ok_or(err::SIGN)?;
                let (r, mut s) = crypto::ecdsa_sign(&ds, &ks, &digest).ok_or(err::SIGN)?;
                if std::mem::take(&mut self.sim_fault_next_sign) {
                    s[17] ^= 0x04; // simulated computation fault
                }
                // X3: verify before release, through an independent code path.
                let (px, py) = crypto::pubkey(&ds).ok_or(err::SIGN)?;
                if !crypto::ecdsa_verify(&px, &py, &digest, &r, &s) {
                    return Err(err::SIGN);
                }
                self.a = r;
                self.b = s;
                Ok(())
            }
            cmd::PUBKEY => {
                let kek = self.need_kek()?;
                let d = self.unwrap_wallet(&kek)?;
                let ds = crypto::scalar_in_range(&d).ok_or(err::SIGN)?;
                let (px, py) = crypto::pubkey(&ds).ok_or(err::SIGN)?;
                self.a = px;
                self.b = py;
                Ok(())
            }
            cmd::ENROL_GEN => {
                let d = self.rand_scalar()?;
                let ds = crypto::scalar_in_range(&d).ok_or(err::SIGN)?;
                let (px, py) = crypto::pubkey(&ds).ok_or(err::SIGN)?;
                self.enrol_d = Some(d);
                self.enrol_pub = (px, py);
                self.b = px;
                self.c = py;
                Ok(())
            }
            cmd::KEK_EXPORT | cmd::KEK_NEW_EXPORT => {
                let payload = if c == cmd::KEK_NEW_EXPORT { self.kek2.clone().ok_or(err::NO_KEK2)? } else { self.need_kek()? };
                let (ex, ey) = (self.b, self.c);
                let e = crypto::check_point(&ex, &ey).ok_or(err::POINT)?;
                let t = self.rand_scalar()?;
                let ts = crypto::scalar_in_range(&t).ok_or(err::SIGN)?;
                let (shared, _) = crypto::point_mul(&ts, &e).ok_or(err::POINT)?;
                let shared = Zeroizing::new(shared);
                let (tx, ty) = crypto::pubkey(&ts).ok_or(err::SIGN)?;
                let kenc = Zeroizing::new(hmac256(&shared[..], &[label::ECIES_KDF, &tx, &ty, &ex, &ey]));
                self.rand_iv()?;
                let (ct, tag) = gcm_seal(&kenc, &self.iv, label::ECIES_AAD, &payload);
                self.a = ct;
                self.tag = tag;
                self.b = tx;
                self.c = ty;
                Ok(())
            }
            cmd::KEK_IMPORT | cmd::KEK_NEW_IMPORT => {
                if c == cmd::KEK_NEW_IMPORT {
                    self.need_kek()?;
                    if self.kek2.is_some() {
                        return Err(err::KEK_EXISTS);
                    }
                } else if self.kek.is_some() {
                    return Err(err::KEK_EXISTS);
                }
                let d = self.enrol_d.clone().ok_or(err::NO_ENROL)?;
                let (tx, ty) = (self.b, self.c);
                let t = crypto::check_point(&tx, &ty).ok_or(err::POINT)?;
                let ds = crypto::scalar_in_range(&d).ok_or(err::SIGN)?;
                let (shared, _) = crypto::point_mul(&ds, &t).ok_or(err::POINT)?;
                let shared = Zeroizing::new(shared);
                let (ex, ey) = self.enrol_pub;
                let kenc = Zeroizing::new(hmac256(&shared[..], &[label::ECIES_KDF, &tx, &ty, &ex, &ey]));
                let key = gcm_open(&kenc, &self.iv, label::ECIES_AAD, &self.a, &self.tag).ok_or(err::UNWRAP)?;
                self.enrol_d = None; // single use
                if c == cmd::KEK_NEW_IMPORT {
                    self.kek2 = Some(key);
                } else {
                    self.kek = Some(key);
                }
                Ok(())
            }
            cmd::SPLIT_BEGIN => {
                let kek = self.need_kek()?;
                let (m, n) = (self.b[0], self.b[1]);
                if m < 2 || m > n || n > 8 {
                    return Err(err::PARAM);
                }
                let mut fp = [0u8; 13];
                fp.copy_from_slice(&hmac256(&kek[..], &[label::KEK_FP])[..13]);
                let mut coefs = Vec::with_capacity(m as usize - 1);
                for _ in 1..m {
                    coefs.push(self.rand_scalar()?);
                }
                self.split = Some(Split { m, n, fp, coefs });
                self.wid = [0; 16];
                self.wid[1] = m;
                self.wid[2] = n;
                self.wid[3..].copy_from_slice(&fp);
                self.b.zeroize();
                Ok(())
            }
            cmd::SHARE_GET => {
                let kek = self.need_kek()?;
                let (x, y) = {
                    let sp = self.split.as_ref().ok_or(err::NO_SHARES)?;
                    let x = self.wid[0];
                    if self.wid[1] != sp.m || self.wid[2] != sp.n || self.wid[3..] != sp.fp || x == 0 || x > sp.n {
                        return Err(err::SHARE);
                    }
                    (x, shamir::eval_share(&kek, &sp.coefs, x))
                };
                let _ = x;
                self.rand_iv()?;
                let kenc = Zeroizing::new(hmac256(&self.b, &[label::SHARE_WRAP, &self.wid]));
                let (ct, tag) = gcm_seal(&kenc, &self.iv, &self.wid, &y);
                self.a = ct;
                self.tag = tag;
                self.b.zeroize(); // the card secret does not stay in a readable register
                Ok(())
            }
            cmd::SPLIT_END => {
                self.split = None;
                Ok(())
            }
            cmd::SHARE_PUT => {
                if self.kek.is_some() {
                    return Err(err::KEK_EXISTS);
                }
                let (x, m, n) = (self.wid[0], self.wid[1], self.wid[2]);
                if m < 2 || m > n || n > 8 || x == 0 || x > n {
                    return Err(err::PARAM);
                }
                let mut fp = [0u8; 13];
                fp.copy_from_slice(&self.wid[3..]);
                if !self.shares.is_empty() && self.rest != Some((m, n, fp)) {
                    return Err(err::SHARE);
                }
                let kenc = Zeroizing::new(hmac256(&self.b, &[label::SHARE_WRAP, &self.wid]));
                let opened = gcm_open(&kenc, &self.iv, &self.wid, &self.a, &self.tag);
                self.b.zeroize();
                let y = opened.ok_or(err::UNWRAP)?;
                if self.shares.len() >= 8 || self.shares.iter().any(|(sx, _)| *sx == x) {
                    return Err(err::SHARE);
                }
                self.shares.push((x, y));
                if self.shares.len() == 1 {
                    self.rest = Some((m, n, fp));
                }
                Ok(())
            }
            cmd::RESTORE => {
                if self.kek.is_some() {
                    return Err(err::KEK_EXISTS);
                }
                let (m, _, fp) = self.rest.ok_or(err::NO_SHARES)?;
                if self.shares.is_empty() || self.shares.len() < m as usize {
                    return Err(err::NO_SHARES);
                }
                let secret = shamir::combine(&self.shares);
                self.shares.clear();
                self.rest = None;
                let got = hmac256(&secret[..], &[label::KEK_FP]);
                if !ct_eq(&got[..13], &fp) {
                    return Err(err::SHARE);
                }
                self.kek = Some(secret);
                Ok(())
            }
            cmd::RESTORE_ABORT => {
                self.shares.clear();
                self.rest = None;
                Ok(())
            }
            _ => Err(err::BAD_CMD),
        }
    }
}
