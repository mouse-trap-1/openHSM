//! SoC secure-world component: the only code that talks to the signing
//! module and the only holder of the keys derived from the tamper secret.
//!
//! This is the Rust equivalent of the reference driver `FPGA/V0.4/sn_host.py`
//! with one addition: it verifies the response MAC (extension X1), so a
//! device on the I2C bus cannot forge or alter a response.

use crate::state::Blob;
use crate::util::{random, unhex_n};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use ed25519_dalek::SigningKey;
use openhsm_hw::{Hardware, HwError};
use openhsm_signer::crypto::{ct_eq, hmac256};
use openhsm_signer::{cmd, err, label, reg, status};
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerError {
    /// The module returned an error code.
    Code(u8),
    /// The response MAC did not verify: the bus is being interfered with.
    ResponseAuth,
    /// A stored blob is malformed.
    Blob(String),
    /// The link to the enclosure failed.
    Bus(String),
}

impl From<HwError> for SignerError {
    fn from(e: HwError) -> Self {
        SignerError::Bus(e.0)
    }
}

impl SignerError {
    pub fn message(&self) -> String {
        match self {
            SignerError::Code(c) => match *c {
                err::NO_SESSION => "signing module has no session",
                err::NO_KEK => "no KEK loaded",
                err::KEK_EXISTS => "a KEK is already loaded",
                err::TRNG => "entropy source failure",
                err::AUTH => "signing module rejected the command authentication",
                err::SIGN => "signing failed",
                err::TAMPER => "tamper",
                err::BAD_CMD => "bad command",
                err::PARAM => "bad parameter",
                err::UNWRAP => "unwrap or authentication of a blob failed",
                err::POINT => "invalid curve point",
                err::NO_ENROL => "no enrolment key",
                err::SHARE => "share rejected",
                err::NO_SHARES => "not enough shares, or no active split",
                err::NO_KEK2 => "no second KEK",
                _ => "unknown signing module error",
            }
            .to_string(),
            SignerError::ResponseAuth => "response from the signing module failed authentication".into(),
            SignerError::Blob(m) => m.clone(),
            SignerError::Bus(m) => format!("hardware link failure: {m}"),
        }
    }
}

type Res<T> = Result<T, SignerError>;

/// Output buffers of a completed command.
#[derive(Debug, Clone)]
pub struct Out {
    pub wid: [u8; 16],
    pub iv: [u8; 12],
    pub tag: [u8; 16],
    pub a: [u8; 32],
    pub b: [u8; 32],
    pub c: [u8; 32],
}

impl Out {
    fn blob(&self) -> Blob {
        Blob { iv: hex::encode(self.iv), tag: hex::encode(self.tag), ct: hex::encode(self.a) }
    }
}

/// Inputs of a command; unused buffers stay zero.
#[derive(Default)]
struct In {
    wid: [u8; 16],
    iv: [u8; 12],
    tag: [u8; 16],
    a: [u8; 32],
    b: [u8; 32],
    c: [u8; 32],
}

impl In {
    fn with_blob(mut self, b: &Blob) -> Res<In> {
        let bad = |_| SignerError::Blob("malformed blob".into());
        self.iv = unhex_n(&b.iv).map_err(bad)?;
        self.tag = unhex_n(&b.tag).map_err(bad)?;
        self.a = unhex_n(&b.ct).map_err(bad)?;
        Ok(self)
    }
}

/// ECIES package carrying a KEK to another node.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KekTransfer {
    pub iv: String,
    pub tag: String,
    pub ct: String,
    pub tx: String,
    pub ty: String,
}

pub struct SecureWorld {
    /// The wires into the tamper enclosure.
    pub hw: Box<dyn Hardware>,
    chan: Zeroizing<[u8; 32]>,
    soc_seal: Zeroizing<[u8; 32]>,
    nonce: [u8; 16],
    ctr: u32,
    /// Node identity key (Ed25519). Signs the audit chain.
    pub identity: Option<SigningKey>,
}

impl SecureWorld {
    /// Bring up the session at SoC boot: the supervisor resets the signing
    /// module and re-delivers the tamper secret to it, then hands the SoC its
    /// derived keys. The SoC never sees the tamper secret itself.
    pub fn start(mut hw: Box<dyn Hardware>) -> Result<SecureWorld, String> {
        hw.restart_signer().map_err(|e| e.0)?;
        let keys = hw.soc_keys().map_err(|e| e.0)?;
        let st = hw.bus_read(reg::STATUS, 1).map_err(|e| e.0)?;
        if st.first().is_none_or(|s| s & status::SESSION == 0) {
            return Err("signing module has no session (tamper secret not delivered)".into());
        }
        let mut nonce = [0u8; 16];
        let n = hw.bus_read(reg::NONCE, 16).map_err(|e| e.0)?;
        if n.len() != 16 {
            return Err("short read from the signing module".into());
        }
        nonce.copy_from_slice(&n);
        Ok(SecureWorld { hw, chan: keys.chan, soc_seal: keys.seal, nonce, ctr: 0, identity: None })
    }

    fn reg8(&mut self, r: u8) -> u8 {
        self.hw.bus_read(r, 1).ok().and_then(|v| v.first().copied()).unwrap_or(0)
    }

    pub fn status(&mut self) -> u8 {
        self.reg8(reg::STATUS)
    }

    pub fn kek_loaded(&mut self) -> bool {
        self.status() & status::KEK != 0
    }

    pub fn ceremony_enabled(&mut self) -> bool {
        self.hw.ceremony_enabled().unwrap_or(false)
    }

    /// SoC tamper response: drop every key held in the secure world.
    pub fn drop_keys(&mut self) {
        self.chan = Zeroizing::new([0; 32]);
        self.soc_seal = Zeroizing::new([0; 32]);
        self.identity = None;
    }

    fn run(&mut self, c: u8, i: In) -> Res<Out> {
        self.ctr = self.ctr.checked_add(1).ok_or(SignerError::Code(err::AUTH))?;
        let ctr = self.ctr.to_be_bytes();
        let mac = hmac256(&self.chan[..], &[&self.nonce, &ctr, &[c], &i.wid, &i.iv, &i.tag, &i.a, &i.b, &i.c]);
        let hw = &mut self.hw;
        hw.bus_write(reg::WID, &i.wid)?;
        hw.bus_write(reg::IV, &i.iv)?;
        hw.bus_write(reg::TAG, &i.tag)?;
        hw.bus_write(reg::BUF_A, &i.a)?;
        hw.bus_write(reg::BUF_B, &i.b)?;
        hw.bus_write(reg::BUF_C, &i.c)?;
        hw.bus_write(reg::CTR, &ctr)?;
        hw.bus_write(reg::MAC, &mac)?;
        hw.bus_write(reg::CMD, &[c])?;
        // STATUS, CMD (reads 0), ERROR in one transaction.
        let head = hw.bus_read(reg::STATUS, 3)?;
        // WID .. BUF_C are contiguous: one read of 16 + 12 + 16 + 96 bytes.
        let body = hw.bus_read(reg::WID, 140)?;
        let rmac = hw.bus_read(reg::RMAC, 32)?;
        if head.len() != 3 || body.len() != 140 || rmac.len() != 32 {
            return Err(SignerError::Bus("short read".into()));
        }
        if head[0] & status::DONE == 0 {
            return Err(SignerError::Bus("command did not complete".into()));
        }
        let e = head[2] & 0x0F;
        let mut out = Out { wid: [0; 16], iv: [0; 12], tag: [0; 16], a: [0; 32], b: [0; 32], c: [0; 32] };
        out.wid.copy_from_slice(&body[..16]);
        out.iv.copy_from_slice(&body[16..28]);
        out.tag.copy_from_slice(&body[28..44]);
        out.a.copy_from_slice(&body[44..76]);
        out.b.copy_from_slice(&body[76..108]);
        out.c.copy_from_slice(&body[108..140]);
        if e == err::AUTH || e == err::TAMPER || e == err::NO_SESSION {
            // These are raised before the module can authenticate a response.
            return Err(SignerError::Code(e));
        }
        let expect = hmac256(&self.chan[..], &[label::RESP, &self.nonce, &ctr, &[c, e], &out.wid, &out.iv, &out.tag, &out.a, &out.b, &out.c]);
        if !ct_eq(&rmac, &expect) {
            return Err(SignerError::ResponseAuth);
        }
        if e != err::OK {
            return Err(SignerError::Code(e));
        }
        Ok(out)
    }

    // ---- wallets ---------------------------------------------------------

    /// Generate a wallet key in the module. Returns the wrapped blob and the
    /// public key (x, y).
    pub fn new_wallet(&mut self, wid: &[u8; 16]) -> Res<(Blob, [u8; 32], [u8; 32])> {
        let o = self.run(cmd::GEN_WALLET, In { wid: *wid, ..In::default() })?;
        Ok((o.blob(), o.b, o.c))
    }

    pub fn sign(&mut self, wid: &[u8; 16], blob: &Blob, digest: &[u8; 32]) -> Res<([u8; 32], [u8; 32])> {
        let o = self.run(cmd::SIGN, In { wid: *wid, b: *digest, ..In::default() }.with_blob(blob)?)?;
        Ok((o.a, o.b))
    }

    pub fn pubkey(&mut self, wid: &[u8; 16], blob: &Blob) -> Res<([u8; 32], [u8; 32])> {
        let o = self.run(cmd::PUBKEY, In { wid: *wid, ..In::default() }.with_blob(blob)?)?;
        Ok((o.a, o.b))
    }

    // ---- KEK lifecycle ---------------------------------------------------

    pub fn kek_generate(&mut self) -> Res<()> {
        self.run(cmd::KEK_GEN, In::default()).map(|_| ())
    }
    pub fn kek_seal(&mut self) -> Res<Blob> {
        self.run(cmd::KEK_SEAL, In::default()).map(|o| o.blob())
    }
    pub fn kek_unseal(&mut self, sealed: &Blob) -> Res<()> {
        self.run(cmd::KEK_UNSEAL, In::default().with_blob(sealed)?).map(|_| ())
    }
    pub fn kek_erase(&mut self) -> Res<()> {
        self.run(cmd::KEK_ERASE, In::default()).map(|_| ())
    }
    pub fn kek_fingerprint(&mut self) -> Res<[u8; 32]> {
        self.run(cmd::KEK_FP, In::default()).map(|o| o.b)
    }

    // ---- ECIES transfer between nodes ------------------------------------

    pub fn enrol_pubkey(&mut self) -> Res<([u8; 32], [u8; 32])> {
        self.run(cmd::ENROL_GEN, In::default()).map(|o| (o.b, o.c))
    }

    fn export(&mut self, c: u8, ex: &[u8; 32], ey: &[u8; 32]) -> Res<KekTransfer> {
        let o = self.run(c, In { b: *ex, c: *ey, ..In::default() })?;
        Ok(KekTransfer { iv: hex::encode(o.iv), tag: hex::encode(o.tag), ct: hex::encode(o.a), tx: hex::encode(o.b), ty: hex::encode(o.c) })
    }

    fn import(&mut self, c: u8, t: &KekTransfer) -> Res<()> {
        let bad = |_| SignerError::Blob("malformed transfer package".into());
        let i = In { b: unhex_n(&t.tx).map_err(bad)?, c: unhex_n(&t.ty).map_err(bad)?, ..In::default() }.with_blob(&Blob {
            iv: t.iv.clone(),
            tag: t.tag.clone(),
            ct: t.ct.clone(),
        })?;
        self.run(c, i).map(|_| ())
    }

    pub fn kek_export(&mut self, ex: &[u8; 32], ey: &[u8; 32]) -> Res<KekTransfer> {
        self.export(cmd::KEK_EXPORT, ex, ey)
    }
    pub fn kek_import(&mut self, t: &KekTransfer) -> Res<()> {
        self.import(cmd::KEK_IMPORT, t)
    }

    // ---- rotation ---------------------------------------------------------

    pub fn kek_new_generate(&mut self) -> Res<()> {
        self.run(cmd::KEK_NEW_GEN, In::default()).map(|_| ())
    }
    pub fn kek_new_export(&mut self, ex: &[u8; 32], ey: &[u8; 32]) -> Res<KekTransfer> {
        self.export(cmd::KEK_NEW_EXPORT, ex, ey)
    }
    pub fn kek_new_import(&mut self, t: &KekTransfer) -> Res<()> {
        self.import(cmd::KEK_NEW_IMPORT, t)
    }
    pub fn rewrap(&mut self, wid: &[u8; 16], blob: &Blob) -> Res<Blob> {
        self.run(cmd::REWRAP, In { wid: *wid, ..In::default() }.with_blob(blob)?).map(|o| o.blob())
    }
    pub fn kek_promote(&mut self) -> Res<()> {
        self.run(cmd::KEK_PROMOTE, In::default()).map(|_| ())
    }
    pub fn rotation_pending(&mut self) -> bool {
        self.reg8(reg::STATUS2) & (1 << 6) != 0
    }

    // ---- break-glass shares ----------------------------------------------

    /// Returns the share header template `00 || m || n || fp13`.
    pub fn split_begin(&mut self, m: u8, n: u8) -> Res<[u8; 16]> {
        let mut b = [0u8; 32];
        b[0] = m;
        b[1] = n;
        self.run(cmd::SPLIT_BEGIN, In { b, ..In::default() }).map(|o| o.wid)
    }
    /// X5: mask the card secret for the command that will carry counter `ctr + 1`.
    fn masked(&self, card_secret: &[u8; 32]) -> [u8; 32] {
        let next = (self.ctr.wrapping_add(1)).to_be_bytes();
        let pad = Zeroizing::new(hmac256(&self.chan[..], &[label::CONF, &self.nonce, &next]));
        let mut out = *card_secret;
        out.iter_mut().zip(pad.iter()).for_each(|(b, p)| *b ^= p);
        out
    }
    pub fn share_get(&mut self, header: &[u8; 16], card_secret: &[u8; 32]) -> Res<Blob> {
        let b = self.masked(card_secret);
        self.run(cmd::SHARE_GET_C, In { wid: *header, b, ..In::default() }).map(|o| o.blob())
    }
    pub fn split_end(&mut self) -> Res<()> {
        self.run(cmd::SPLIT_END, In::default()).map(|_| ())
    }
    pub fn share_put(&mut self, header: &[u8; 16], blob: &Blob, card_secret: &[u8; 32]) -> Res<()> {
        let b = self.masked(card_secret);
        self.run(cmd::SHARE_PUT_C, In { wid: *header, b, ..In::default() }.with_blob(blob)?).map(|_| ())
    }
    pub fn restore(&mut self) -> Res<()> {
        self.run(cmd::RESTORE, In::default()).map(|_| ())
    }
    pub fn restore_abort(&mut self) -> Res<()> {
        self.run(cmd::RESTORE_ABORT, In::default()).map(|_| ())
    }

    // ---- SoC-side sealing -------------------------------------------------

    /// Seal bytes to this node's tamper secret (AES-256-GCM). Used for the
    /// node identity key and the TLS private key at rest.
    pub fn seal(&self, aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, String> {
        let iv = random::<12>()?;
        let cipher = Aes256Gcm::new((&*self.soc_seal).into());
        let ct = cipher.encrypt(Nonce::from_slice(&iv), aes_gcm::aead::Payload { msg: pt, aad }).map_err(|_| "seal failed".to_string())?;
        let mut out = iv.to_vec();
        out.extend(ct);
        Ok(out)
    }

    pub fn unseal(&self, aad: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
        if sealed.len() < 28 {
            return Err("sealed object too short".into());
        }
        let (iv, ct) = sealed.split_at(12);
        let cipher = Aes256Gcm::new((&*self.soc_seal).into());
        cipher
            .decrypt(Nonce::from_slice(iv), aes_gcm::aead::Payload { msg: ct, aad })
            .map(Zeroizing::new)
            .map_err(|_| "sealed object does not open under this node's tamper secret".to_string())
    }
}
