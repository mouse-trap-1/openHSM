//! Bus-level simulator of the signing module.
//!
//! Exposes the module's pins over a local TCP socket so that host drivers and
//! attack tools written for the FPGA can be run against the software model:
//!
//! ```text
//! request : op(1) arg(1) len(2, big-endian) data(len)
//! response: len(2, big-endian) data(len)
//!
//! op 0x01  I2C write   arg = register pointer, data = bytes
//! op 0x02  I2C read    arg = register pointer, len = bytes to read, no data
//! op 0x10  SPI frame   data = frame from the tamper MCU (0xA5 || S)
//! op 0x11  tamper pin  arg = level (0/1)
//! op 0x12  reset
//! op 0x13  TRNG fault  arg = 1 forces the entropy source to fail
//! op 0x14  glitch      corrupt the next signature computation
//! op 0x15  ceremony    arg = level (0/1) of the ceremony switch pin
//! ```
//!
//! This binary is a test fixture. It binds to loopback only and must never be
//! deployed: it gives its peer the physical pins of the module.

#![forbid(unsafe_code)]

use openhsm_signer::entropy::{EntropyFailure, EntropySource, OsEntropy};
use openhsm_signer::Signer;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

struct Switchable {
    inner: OsEntropy,
    fail: Arc<AtomicBool>,
}

impl EntropySource for Switchable {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), EntropyFailure> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(EntropyFailure);
        }
        self.inner.fill(out)
    }
}

fn serve(mut s: TcpStream, signer: Arc<Mutex<Signer>>, fail: Arc<AtomicBool>) -> std::io::Result<()> {
    s.set_nodelay(true)?;
    loop {
        let mut hdr = [0u8; 4];
        if s.read_exact(&mut hdr).is_err() {
            return Ok(());
        }
        let (op, arg, len) = (hdr[0], hdr[1], u16::from_be_bytes([hdr[2], hdr[3]]) as usize);
        let mut data = vec![0u8; if op == 0x02 { 0 } else { len }];
        s.read_exact(&mut data)?;
        let mut sg = signer.lock().unwrap_or_else(|e| e.into_inner());
        let out = match op {
            0x01 => {
                sg.bus_write(arg, &data);
                vec![]
            }
            0x02 => sg.bus_read(arg, len.min(256)),
            0x10 => {
                sg.spi_frame(&data);
                vec![]
            }
            0x11 => {
                sg.set_tamper(arg != 0);
                vec![]
            }
            0x12 => {
                sg.reset();
                vec![]
            }
            0x13 => {
                fail.store(arg != 0, Ordering::SeqCst);
                vec![]
            }
            0x14 => {
                sg.sim_inject_sign_fault();
                vec![]
            }
            0x15 => {
                sg.set_ceremony_enable(arg != 0);
                vec![]
            }
            _ => vec![],
        };
        drop(sg);
        let mut resp = (out.len() as u16).to_be_bytes().to_vec();
        resp.extend(out);
        s.write_all(&resp)?;
    }
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let port = args.iter().position(|a| a == "--port").and_then(|i| args.get(i + 1)).and_then(|p| p.parse::<u16>().ok()).unwrap_or(7700);
    let fail = Arc::new(AtomicBool::new(false));
    let signer = Arc::new(Mutex::new(Signer::new(Box::new(Switchable { inner: OsEntropy::new(), fail: fail.clone() }))));
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    eprintln!("openhsm-signer-sim: TEST FIXTURE, loopback only, listening on 127.0.0.1:{port}");
    for conn in listener.incoming() {
        let Ok(conn) = conn else { continue };
        let (signer, fail) = (signer.clone(), fail.clone());
        std::thread::spawn(move || {
            let _ = serve(conn, signer, fail);
        });
    }
    Ok(())
}
