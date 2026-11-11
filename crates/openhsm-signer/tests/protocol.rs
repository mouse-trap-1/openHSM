//! Register-level tests of the signing-module model, written as a host
//! would drive the FPGA: only the bus, the SPI frame and the pins are used.

use openhsm_signer::crypto::{ecdsa_verify, gcm_open, hmac256, Word};
use openhsm_signer::entropy::SimEntropy;
use openhsm_signer::{cmd, err, label, reg, status, Signer, MAX_AUTH_FAILURES};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Clone, Default)]
struct Io {
    wid: [u8; 16],
    iv: [u8; 12],
    tag: [u8; 16],
    a: Word,
    b: Word,
    c: Word,
}

struct Host {
    sg: Signer,
    s: Word,
    chan: Word,
    nonce: [u8; 16],
    ctr: u32,
    trng_fail: Arc<AtomicBool>,
}

impl Host {
    fn new(seed: &[u8], s: Word) -> Host {
        let ent = SimEntropy::new(seed);
        let trng_fail = ent.fail.clone();
        let mut h = Host { sg: Signer::new(Box::new(ent)), s, chan: [0; 32], nonce: [0; 16], ctr: 0, trng_fail };
        h.sg.set_ceremony_enable(true);
        h.session(s);
        h
    }

    fn session(&mut self, s: Word) {
        let mut frame = vec![0xA5];
        frame.extend(s);
        self.sg.spi_frame(&frame);
        self.s = s;
        self.chan = hmac256(&s, &[label::CHAN]);
        self.nonce.copy_from_slice(&self.sg.bus_read(reg::NONCE, 16));
        self.ctr = 0;
    }

    fn seal_key(&self) -> Word {
        hmac256(&self.s, &[label::SEAL])
    }

    fn write_inputs(&mut self, c: u8, io: &Io, ctr: u32, mac: Option<Word>) {
        let ctr_b = ctr.to_be_bytes();
        let mac = mac.unwrap_or_else(|| hmac256(&self.chan, &[&self.nonce, &ctr_b, &[c], &io.wid, &io.iv, &io.tag, &io.a, &io.b, &io.c]));
        self.sg.bus_write(reg::WID, &io.wid);
        self.sg.bus_write(reg::IV, &io.iv);
        self.sg.bus_write(reg::TAG, &io.tag);
        self.sg.bus_write(reg::BUF_A, &io.a);
        self.sg.bus_write(reg::BUF_B, &io.b);
        self.sg.bus_write(reg::BUF_C, &io.c);
        self.sg.bus_write(reg::CTR, &ctr_b);
        self.sg.bus_write(reg::MAC, &mac);
        self.sg.bus_write(reg::CMD, &[c]);
    }

    fn read_outputs(&self) -> (u8, Io) {
        let g = |p: u8, n: usize| self.sg.bus_read(p, n);
        let mut o = Io::default();
        o.wid.copy_from_slice(&g(reg::WID, 16));
        o.iv.copy_from_slice(&g(reg::IV, 12));
        o.tag.copy_from_slice(&g(reg::TAG, 16));
        o.a.copy_from_slice(&g(reg::BUF_A, 32));
        o.b.copy_from_slice(&g(reg::BUF_B, 32));
        o.c.copy_from_slice(&g(reg::BUF_C, 32));
        (g(reg::ERROR, 1)[0], o)
    }

    /// Run an authenticated command and check the response MAC.
    fn run(&mut self, c: u8, io: &Io) -> (u8, Io) {
        self.ctr += 1;
        self.write_inputs(c, io, self.ctr, None);
        let (e, o) = self.read_outputs();
        assert_ne!(self.sg.status() & status::DONE, 0);
        if e != err::AUTH && e != err::TAMPER && e != err::NO_SESSION {
            let expect = hmac256(&self.chan, &[label::RESP, &self.nonce, &self.ctr.to_be_bytes(), &[c, e], &o.wid, &o.iv, &o.tag, &o.a, &o.b, &o.c]);
            assert_eq!(self.sg.bus_read(reg::RMAC, 32), expect, "response MAC");
        }
        (e, o)
    }

    fn ok(&mut self, c: u8, io: &Io) -> Io {
        let (e, o) = self.run(c, io);
        assert_eq!(e, err::OK, "command {c:#04x}");
        o
    }

    fn fails(&mut self, c: u8, io: &Io, expect: u8) {
        let (e, o) = self.run(c, io);
        assert_eq!(e, expect, "command {c:#04x}");
        if e != err::AUTH {
            assert!(o.iv == [0; 12] && o.tag == [0; 16] && o.a == [0; 32] && o.b == [0; 32] && o.c == [0; 32], "buffers cleared on error");
        }
    }

    fn kek(&mut self) -> Word {
        let o = self.ok(cmd::KEK_SEAL, &Io::default());
        *gcm_open(&self.seal_key(), &o.iv, label::SEAL_AAD, &o.a, &o.tag).expect("sealed KEK opens under HMAC(S, SN-SEAL)")
    }

    /// No secret may ever be visible through any register.
    fn assert_no_leak(&self, secrets: &[&[u8]]) {
        let dump = self.sg.bus_read(0, 256);
        for s in secrets {
            for w in s.windows(8) {
                assert!(!dump.windows(8).any(|d| d == w), "secret bytes visible on the bus");
            }
        }
    }
}

const WID: [u8; 16] = *b"wallet-000000001";

fn wallet(h: &mut Host) -> Io {
    let o = h.ok(cmd::GEN_WALLET, &Io { wid: WID, ..Io::default() });
    Io { wid: WID, iv: o.iv, tag: o.tag, a: o.a, b: o.b, c: o.c }
}

#[test]
fn no_session_without_the_tamper_secret() {
    let mut sg = Signer::new(Box::new(SimEntropy::new(b"a")));
    sg.bus_write(reg::CMD, &[cmd::KEK_GEN]);
    assert_eq!(sg.bus_read(reg::ERROR, 1)[0], err::NO_SESSION);
    sg.spi_frame(&[0x5A; 33]); // wrong header
    sg.spi_frame(&[0xA5; 32]); // wrong length
    assert_eq!(sg.status() & status::SESSION, 0);
    assert_eq!(sg.bus_read(reg::VERSION, 1)[0], 0xB2);
}

#[test]
fn secret_is_accepted_once_per_reset() {
    let mut h = Host::new(b"b", [1; 32]);
    let mut second = vec![0xA5];
    second.extend([2u8; 32]);
    h.sg.spi_frame(&second);
    h.ok(cmd::KEK_GEN, &Io::default()); // still authenticated under the first secret
}

#[test]
fn authentication_replay_and_reserved_commands() {
    let mut h = Host::new(b"c", [1; 32]);
    h.ok(cmd::KEK_GEN, &Io::default());
    // Replay of an accepted counter.
    h.write_inputs(cmd::KEK_FP, &Io::default(), h.ctr, None);
    assert_eq!(h.read_outputs().0, err::AUTH);
    // Forged MAC, and a MAC computed for a different command.
    h.write_inputs(cmd::KEK_FP, &Io::default(), h.ctr + 1, Some([0; 32]));
    assert_eq!(h.read_outputs().0, err::AUTH);
    let other = hmac256(&h.chan, &[&h.nonce, &(h.ctr + 1).to_be_bytes(), &[cmd::KEK_SEAL], &[0u8; 16], &[0u8; 12], &[0u8; 16], &[0u8; 96]]);
    h.write_inputs(cmd::KEK_ERASE, &Io::default(), h.ctr + 1, Some(other));
    assert_eq!(h.read_outputs().0, err::AUTH);
    assert_ne!(h.sg.status() & status::KEK, 0, "KEK survives rejected commands");
    // Internal command codes are refused even with a valid MAC.
    h.fails(0xF0, &Io::default(), err::BAD_CMD);
    h.fails(0xFE, &Io::default(), err::BAD_CMD);
    h.fails(0x99, &Io::default(), err::BAD_CMD);
    h.ok(cmd::KEK_FP, &Io::default());
}

#[test]
fn lockout_after_repeated_failures() {
    let mut h = Host::new(b"d", [1; 32]);
    for _ in 0..MAX_AUTH_FAILURES {
        h.write_inputs(cmd::KEK_GEN, &Io::default(), 1, Some([0xEE; 32]));
        assert_eq!(h.read_outputs().0, err::AUTH);
    }
    assert_ne!(h.sg.bus_read(reg::STATUS2, 1)[0] & 0x80, 0, "locked flag");
    let (e, _) = h.run(cmd::KEK_GEN, &Io::default()); // a correct MAC no longer helps
    assert_eq!(e, err::AUTH);
    h.sg.reset();
    h.session([1; 32]);
    h.ok(cmd::KEK_GEN, &Io::default());
}

#[test]
fn wallet_generation_signing_and_binding() {
    let mut h = Host::new(b"e", [1; 32]);
    h.ok(cmd::KEK_GEN, &Io::default());
    let kek = h.kek();
    let w = wallet(&mut h);
    let (px, py) = (w.b, w.c);
    let d = *gcm_open(&kek, &w.iv, &WID, &w.a, &w.tag).expect("blob opens under the KEK with AAD = wallet id");
    h.assert_no_leak(&[&kek, &d, &h.chan, &h.seal_key()]);

    let digest = [0x42u8; 32];
    let blob = Io { b: digest, c: [0; 32], ..w.clone() };
    let s1 = h.ok(cmd::SIGN, &blob);
    h.assert_no_leak(&[&kek, &d]);
    let s2 = h.ok(cmd::SIGN, &blob);
    assert!(ecdsa_verify(&px, &py, &digest, &s1.a, &s1.b) && ecdsa_verify(&px, &py, &digest, &s2.a, &s2.b));
    assert_ne!((s1.a, s1.b), (s2.a, s2.b), "hedged nonce: repeated signatures differ");
    assert!(s1.b[0] < 0x80 && s2.b[0] < 0x80, "low-s");

    let pk = h.ok(cmd::PUBKEY, &Io { b: [0; 32], c: [0; 32], ..w.clone() });
    assert_eq!((pk.a, pk.b), (px, py));

    // The blob is bound to its wallet id and to every one of its bits.
    let mut other = blob.clone();
    other.wid[15] ^= 1;
    h.fails(cmd::SIGN, &other, err::UNWRAP);
    for flip in [0usize, 31] {
        let mut bad = blob.clone();
        bad.a[flip] ^= 0x80;
        h.fails(cmd::SIGN, &bad, err::UNWRAP);
    }
    let mut bad = blob.clone();
    bad.tag[0] ^= 1;
    h.fails(cmd::SIGN, &bad, err::UNWRAP);
    let mut bad = blob.clone();
    bad.iv[0] ^= 1;
    h.fails(cmd::SIGN, &bad, err::UNWRAP);
}

#[test]
fn seal_survives_reset_only_with_the_same_secret() {
    let mut h = Host::new(b"f", [1; 32]);
    h.ok(cmd::KEK_GEN, &Io::default());
    h.fails(cmd::KEK_GEN, &Io::default(), err::KEK_EXISTS);
    let w = wallet(&mut h);
    let sealed = h.ok(cmd::KEK_SEAL, &Io::default());
    let sealed = Io { iv: sealed.iv, tag: sealed.tag, a: sealed.a, ..Io::default() };

    h.sg.reset();
    assert_eq!(h.sg.status() & (status::KEK | status::SESSION), 0, "reset clears the KEK");
    h.session([1; 32]);
    h.fails(cmd::SIGN, &Io { b: [1; 32], c: [0; 32], ..w.clone() }, err::NO_KEK);
    h.ok(cmd::KEK_UNSEAL, &sealed);
    h.fails(cmd::KEK_UNSEAL, &sealed, err::KEK_EXISTS);
    h.ok(cmd::SIGN, &Io { b: [1; 32], c: [0; 32], ..w.clone() });

    // A different tamper secret (as after a tamper event) cannot open it.
    h.sg.reset();
    h.session([9; 32]);
    h.fails(cmd::KEK_UNSEAL, &sealed, err::UNWRAP);
    assert_eq!(h.sg.status() & status::KEK, 0);
}

#[test]
fn ecies_transfer_and_invalid_points() {
    let mut a = Host::new(b"g1", [1; 32]);
    let mut b = Host::new(b"g2", [2; 32]);
    a.ok(cmd::KEK_GEN, &Io::default());
    let w = wallet(&mut a);
    b.fails(cmd::KEK_IMPORT, &Io::default(), err::NO_ENROL);
    let e = b.ok(cmd::ENROL_GEN, &Io::default());
    let pkg = a.ok(cmd::KEK_EXPORT, &Io { b: e.b, c: e.c, ..Io::default() });

    // Invalid-curve and degenerate points are refused before any ECDH.
    let mut off = e.clone();
    off.c[31] ^= 1;
    a.fails(cmd::KEK_EXPORT, &Io { b: off.b, c: off.c, ..Io::default() }, err::POINT);
    a.fails(cmd::KEK_EXPORT, &Io::default(), err::POINT);
    a.fails(cmd::KEK_EXPORT, &Io { b: [0xFF; 32], c: [0xFF; 32], ..Io::default() }, err::POINT);

    // A package altered in transit does not load.
    let mut bad = pkg.clone();
    bad.a[5] ^= 1;
    b.fails(cmd::KEK_IMPORT, &Io { wid: [0; 16], ..bad }, err::UNWRAP);
    b.ok(cmd::KEK_IMPORT, &Io { wid: [0; 16], ..pkg.clone() });
    // The enrolment key is single-use and the KEK slot is now taken.
    b.fails(cmd::KEK_IMPORT, &Io { wid: [0; 16], ..pkg }, err::KEK_EXISTS);
    assert_eq!(b.sg.status() & status::ENROL, 0);

    assert_eq!(a.ok(cmd::KEK_FP, &Io::default()).b, b.ok(cmd::KEK_FP, &Io::default()).b);
    let sig = b.ok(cmd::SIGN, &Io { b: [7; 32], c: [0; 32], ..w.clone() });
    assert!(ecdsa_verify(&w.b, &w.c, &[7; 32], &sig.a, &sig.b), "node B signs with A's wallet blob");
}

fn split(h: &mut Host, m: u8, n: u8) -> Vec<(Io, Word)> {
    let mut b = [0u8; 32];
    b[0] = m;
    b[1] = n;
    let template = h.ok(cmd::SPLIT_BEGIN, &Io { b, ..Io::default() }).wid;
    let mut out = Vec::new();
    for x in 1..=n {
        let r = [x.wrapping_mul(17); 32];
        let mut hdr = template;
        hdr[0] = x;
        let o = h.ok(cmd::SHARE_GET, &Io { wid: hdr, b: r, ..Io::default() });
        assert_eq!(o.b, [0; 32], "card secret is not left in a readable register");
        out.push((Io { wid: hdr, iv: o.iv, tag: o.tag, a: o.a, ..Io::default() }, r));
    }
    h.ok(cmd::SPLIT_END, &Io::default());
    out
}

#[test]
fn shamir_break_glass_recovery() {
    let mut h = Host::new(b"h", [1; 32]);
    h.ok(cmd::KEK_GEN, &Io::default());
    let fp = h.ok(cmd::KEK_FP, &Io::default()).b;
    let w = wallet(&mut h);
    let mut bad_params = [0u8; 32];
    bad_params[0] = 1;
    bad_params[1] = 5;
    h.fails(cmd::SPLIT_BEGIN, &Io { b: bad_params, ..Io::default() }, err::PARAM);
    let shares = split(&mut h, 3, 5);
    h.fails(cmd::SHARE_GET, &Io { wid: shares[0].0.wid, b: [1; 32], ..Io::default() }, err::NO_SHARES);

    // Disaster: the node loses everything and comes back with a new secret.
    h.sg.reset();
    h.session([5; 32]);
    let put = |h: &mut Host, i: usize, r: Word| h.run(cmd::SHARE_PUT, &Io { b: r, ..shares[i].0.clone() }).0;

    assert_eq!(put(&mut h, 0, shares[0].1), err::OK);
    assert_eq!(put(&mut h, 0, shares[0].1), err::SHARE, "duplicate share");
    assert_eq!(put(&mut h, 1, [0xAB; 32]), err::UNWRAP, "wrong card");
    let mut forged = shares[1].0.clone();
    forged.wid[1] = 2; // claims to be 2-of-5
    assert_eq!(h.run(cmd::SHARE_PUT, &Io { b: shares[1].1, ..forged }).0, err::SHARE);
    assert_eq!(put(&mut h, 1, shares[1].1), err::OK);
    h.fails(cmd::RESTORE, &Io::default(), err::NO_SHARES); // two of three
    assert_eq!(put(&mut h, 4, shares[4].1), err::OK);
    h.ok(cmd::RESTORE, &Io::default());
    assert_eq!(h.ok(cmd::KEK_FP, &Io::default()).b, fp, "recovered KEK is the original");
    let sig = h.ok(cmd::SIGN, &Io { b: [3; 32], c: [0; 32], ..w.clone() });
    assert!(ecdsa_verify(&w.b, &w.c, &[3; 32], &sig.a, &sig.b));
    assert_eq!(h.sg.bus_read(reg::STATUS2, 1)[0] & 0x0F, 0, "shares scrubbed after restore");
}

#[test]
fn rotation_rewraps_under_the_new_kek_only() {
    let mut h = Host::new(b"i", [1; 32]);
    h.ok(cmd::KEK_GEN, &Io::default());
    let old_fp = h.ok(cmd::KEK_FP, &Io::default()).b;
    let w = wallet(&mut h);
    let blob = Io { b: [0; 32], c: [0; 32], ..w.clone() };
    h.fails(cmd::REWRAP, &blob, err::NO_KEK2);
    h.fails(cmd::KEK_PROMOTE, &Io::default(), err::NO_KEK2);
    h.ok(cmd::KEK_NEW_GEN, &Io::default());
    let re = h.ok(cmd::REWRAP, &blob);
    let new_blob = Io { wid: WID, iv: re.iv, tag: re.tag, a: re.a, ..Io::default() };
    h.ok(cmd::KEK_PROMOTE, &Io::default());
    assert_ne!(h.ok(cmd::KEK_FP, &Io::default()).b, old_fp);
    h.fails(cmd::PUBKEY, &blob, err::UNWRAP);
    let pk = h.ok(cmd::PUBKEY, &new_blob);
    assert_eq!((pk.a, pk.b), (w.b, w.c), "same wallet key under the new KEK");
}

#[test]
fn tamper_wipes_everything_and_latches() {
    let mut h = Host::new(b"j", [1; 32]);
    h.ok(cmd::KEK_GEN, &Io::default());
    let kek = h.kek();
    let w = wallet(&mut h);
    let sealed = h.ok(cmd::KEK_SEAL, &Io::default());
    h.sg.set_tamper(true);
    assert_eq!(h.sg.status() & (status::KEK | status::SESSION | status::ENROL), 0);
    assert_ne!(h.sg.status() & status::TAMPER, 0);
    assert!(h.sg.bus_read(reg::NONCE, 16 + 16 + 12 + 16 + 96).iter().all(|&b| b == 0), "registers zeroised");
    h.assert_no_leak(&[&kek]);
    let (e, _) = h.run(cmd::SIGN, &Io { b: [1; 32], c: [0; 32], ..w.clone() });
    assert_eq!(e, err::TAMPER);
    // Writes are ignored while latched; the latch survives until reset.
    h.sg.bus_write(reg::BUF_A, &[0x77; 32]);
    assert_eq!(h.sg.bus_read(reg::BUF_A, 32), [0u8; 32]);
    h.sg.set_tamper(false);
    assert_ne!(h.sg.status() & status::TAMPER, 0);
    // A reset while the fault persists re-latches.
    h.sg.set_tamper(true);
    h.sg.reset();
    assert_ne!(h.sg.status() & status::TAMPER, 0);
    // After the fault clears and the node is re-provisioned with a new secret,
    // the old sealed KEK is useless.
    h.sg.set_tamper(false);
    h.sg.reset();
    h.session([0x33; 32]);
    h.fails(cmd::KEK_UNSEAL, &Io { iv: sealed.iv, tag: sealed.tag, a: sealed.a, ..Io::default() }, err::UNWRAP);
}

#[test]
fn faulted_signature_is_withheld() {
    let mut h = Host::new(b"k", [1; 32]);
    h.ok(cmd::KEK_GEN, &Io::default());
    let w = wallet(&mut h);
    h.sg.sim_inject_sign_fault();
    h.fails(cmd::SIGN, &Io { b: [9; 32], c: [0; 32], ..w.clone() }, err::SIGN);
    h.ok(cmd::SIGN, &Io { b: [9; 32], c: [0; 32], ..w.clone() });
}

#[test]
fn entropy_failure_is_fail_closed_for_keys_and_safe_for_signing() {
    let mut h = Host::new(b"l", [1; 32]);
    h.ok(cmd::KEK_GEN, &Io::default());
    let w = wallet(&mut h);
    h.trng_fail.store(true, Ordering::SeqCst);
    h.fails(cmd::GEN_WALLET, &Io { wid: WID, ..Io::default() }, err::TRNG);
    h.fails(cmd::KEK_SEAL, &Io::default(), err::TRNG);
    assert_ne!(h.sg.status() & status::TRNG_FAIL, 0);
    // Signing falls back to plain RFC 6979: still valid, now deterministic.
    let blob = Io { b: [4; 32], c: [0; 32], ..w.clone() };
    let s1 = h.ok(cmd::SIGN, &blob);
    let s2 = h.ok(cmd::SIGN, &blob);
    assert_eq!((s1.a, s1.b), (s2.a, s2.b));
    assert!(ecdsa_verify(&w.b, &w.c, &[4; 32], &s1.a, &s1.b));
    // No session can start without entropy for the session nonce.
    let mut fresh = Signer::new(Box::new({
        let e = SimEntropy::new(b"m");
        e.fail.store(true, Ordering::SeqCst);
        e
    }));
    fresh.spi_frame(&[0xA5; 33]);
    assert_eq!(fresh.status() & status::SESSION, 0);
}

#[test]
fn ceremony_switch_gates_every_kek_moving_command() {
    let mut h = Host::new(b"n", [1; 32]);
    h.ok(cmd::KEK_GEN, &Io::default());
    let e = h.ok(cmd::ENROL_GEN, &Io::default());
    h.sg.set_ceremony_enable(false);
    assert_eq!(h.sg.bus_read(reg::STATUS2, 1)[0] & 0x10, 0);
    // A host that holds the channel key (a compromised SoC) still cannot move the KEK.
    let mut two_of_three = [0u8; 32];
    two_of_three[0] = 2;
    two_of_three[1] = 3;
    for (c, io) in [
        (cmd::KEK_EXPORT, Io { b: e.b, c: e.c, ..Io::default() }),
        (cmd::KEK_NEW_EXPORT, Io { b: e.b, c: e.c, ..Io::default() }),
        (cmd::KEK_IMPORT, Io::default()),
        (cmd::KEK_NEW_IMPORT, Io::default()),
        (cmd::SPLIT_BEGIN, Io { b: two_of_three, ..Io::default() }),
        (cmd::SHARE_GET, Io::default()),
        (cmd::SHARE_GET_C, Io::default()),
        (cmd::SHARE_PUT, Io::default()),
        (cmd::SHARE_PUT_C, Io::default()),
        (cmd::RESTORE, Io::default()),
    ] {
        h.fails(c, &io, err::BAD_CMD);
    }
    // Everyday operation is unaffected.
    let w = wallet(&mut h);
    h.ok(cmd::SIGN, &Io { b: [1; 32], c: [0; 32], ..w });
    h.ok(cmd::KEK_SEAL, &Io::default());
    h.sg.set_ceremony_enable(true);
    h.ok(cmd::KEK_EXPORT, &Io { b: e.b, c: e.c, ..Io::default() });
}

#[test]
fn masked_card_secret_matches_the_plain_command() {
    // X5: SHARE_GET_C with a masked secret yields a share that SHARE_PUT (plain) accepts.
    let mut h = Host::new(b"o", [1; 32]);
    h.ok(cmd::KEK_GEN, &Io::default());
    let fp = h.ok(cmd::KEK_FP, &Io::default()).b;
    let mut b = [0u8; 32];
    b[0] = 2;
    b[1] = 2;
    let template = h.ok(cmd::SPLIT_BEGIN, &Io { b, ..Io::default() }).wid;
    let mut shares = Vec::new();
    for x in 1..=2u8 {
        let r = [x; 32];
        let pad = hmac256(&h.chan, &[label::CONF, &h.nonce, &(h.ctr + 1).to_be_bytes()]);
        let mut masked = r;
        masked.iter_mut().zip(pad.iter()).for_each(|(m, p)| *m ^= p);
        assert_ne!(masked, r);
        let mut hdr = template;
        hdr[0] = x;
        let o = h.ok(cmd::SHARE_GET_C, &Io { wid: hdr, b: masked, ..Io::default() });
        shares.push((Io { wid: hdr, iv: o.iv, tag: o.tag, a: o.a, ..Io::default() }, r));
    }
    h.ok(cmd::SPLIT_END, &Io::default());
    h.ok(cmd::KEK_ERASE, &Io::default());
    for (io, r) in &shares {
        h.ok(cmd::SHARE_PUT, &Io { b: *r, ..io.clone() });
    }
    h.ok(cmd::RESTORE, &Io::default());
    assert_eq!(h.ok(cmd::KEK_FP, &Io::default()).b, fp);
}
