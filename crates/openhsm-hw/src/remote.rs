//! The enclosure model in a separate process.
//!
//! `openhsm-hwsim` serves two Unix sockets: one carries the [`Hardware`]
//! interface to the node (the wires between the SoC and the enclosure), the
//! other carries the physical-simulation commands (sensors, key-switch,
//! power). The node process holds neither the signing module's keys nor the
//! tamper secret; reading its memory yields no wallet key and no KEK.
//!
//! ```text
//! request : op(1) len(2, big-endian) payload(len)
//! response: status(1; 0 = ok) len(2) payload(len)   (payload = error text if status != 0)
//!
//! 1 bus_write   payload = ptr || data
//! 2 bus_read    payload = ptr || n(2)
//! 3 restart_signer
//! 4 soc_keys    -> chan(32) || seal(32)
//! 5 counter     -> u64
//! 6 counter_increment -> u64
//! 7 tamper_status -> empty, or JSON trip record
//! 8 ceremony_enabled -> 0/1
//! ```

#![cfg(unix)]

use crate::{Enclosure, Hardware, HwError, SocKeys, TripRecord};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

fn io_err(e: std::io::Error) -> HwError {
    HwError(format!("hardware link: {e}"))
}

pub struct RemoteHardware {
    stream: UnixStream,
}

impl RemoteHardware {
    pub fn connect(path: &Path) -> Result<RemoteHardware, HwError> {
        Ok(RemoteHardware { stream: UnixStream::connect(path).map_err(|e| HwError(format!("{}: {e}", path.display())))? })
    }

    fn rpc(&mut self, op: u8, payload: &[u8]) -> Result<Vec<u8>, HwError> {
        let mut req = Vec::with_capacity(3 + payload.len());
        req.push(op);
        req.extend((payload.len() as u16).to_be_bytes());
        req.extend_from_slice(payload);
        self.stream.write_all(&req).map_err(io_err)?;
        let mut hdr = [0u8; 3];
        self.stream.read_exact(&mut hdr).map_err(io_err)?;
        let mut body = vec![0u8; u16::from_be_bytes([hdr[1], hdr[2]]) as usize];
        self.stream.read_exact(&mut body).map_err(io_err)?;
        if hdr[0] != 0 {
            return Err(HwError(String::from_utf8_lossy(&body).into_owned()));
        }
        Ok(body)
    }

    fn rpc_u64(&mut self, op: u8) -> Result<u64, HwError> {
        let b = self.rpc(op, &[])?;
        Ok(u64::from_be_bytes(b.as_slice().try_into().map_err(|_| HwError("malformed reply".into()))?))
    }
}

impl Hardware for RemoteHardware {
    fn bus_write(&mut self, ptr: u8, data: &[u8]) -> Result<(), HwError> {
        let mut p = vec![ptr];
        p.extend_from_slice(data);
        self.rpc(1, &p).map(|_| ())
    }
    fn bus_read(&mut self, ptr: u8, n: usize) -> Result<Vec<u8>, HwError> {
        let n = (n.min(256)) as u16;
        self.rpc(2, &[ptr, (n >> 8) as u8, n as u8])
    }
    fn restart_signer(&mut self) -> Result<(), HwError> {
        self.rpc(3, &[]).map(|_| ())
    }
    fn soc_keys(&mut self) -> Result<SocKeys, HwError> {
        let b = Zeroizing::new(self.rpc(4, &[])?);
        if b.len() != 64 {
            return Err(HwError("malformed reply".into()));
        }
        let mut chan = Zeroizing::new([0u8; 32]);
        let mut seal = Zeroizing::new([0u8; 32]);
        chan.copy_from_slice(&b[..32]);
        seal.copy_from_slice(&b[32..]);
        Ok(SocKeys { chan, seal })
    }
    fn counter(&mut self) -> Result<u64, HwError> {
        self.rpc_u64(5)
    }
    fn counter_increment(&mut self) -> Result<u64, HwError> {
        self.rpc_u64(6)
    }
    fn tamper_status(&mut self) -> Result<Option<TripRecord>, HwError> {
        let b = self.rpc(7, &[])?;
        if b.is_empty() {
            return Ok(None);
        }
        serde_json::from_slice(&b).map(Some).map_err(|e| HwError(e.to_string()))
    }
    fn ceremony_enabled(&mut self) -> Result<bool, HwError> {
        Ok(self.rpc(8, &[])? == [1])
    }
}

fn handle_soc(mut s: UnixStream, enc: Arc<Mutex<Enclosure>>) -> std::io::Result<()> {
    loop {
        let mut hdr = [0u8; 3];
        if s.read_exact(&mut hdr).is_err() {
            return Ok(());
        }
        let mut p = vec![0u8; u16::from_be_bytes([hdr[1], hdr[2]]) as usize];
        s.read_exact(&mut p)?;
        let result: Result<Vec<u8>, HwError> = {
            let mut e = enc.lock().unwrap_or_else(|x| x.into_inner());
            match (hdr[0], p.as_slice()) {
                (1, [ptr, data @ ..]) => e.bus_write(*ptr, data).map(|_| vec![]),
                (2, [ptr, hi, lo]) => e.bus_read(*ptr, u16::from_be_bytes([*hi, *lo]) as usize),
                (3, []) => e.restart_signer().map(|_| vec![]),
                (4, []) => e.soc_keys().map(|k| [&k.chan[..], &k.seal[..]].concat()),
                (5, []) => e.counter().map(|c| c.to_be_bytes().to_vec()),
                (6, []) => e.counter_increment().map(|c| c.to_be_bytes().to_vec()),
                (7, []) => e.tamper_status().map(|t| t.map(|t| serde_json::to_vec(&t).unwrap_or_default()).unwrap_or_default()),
                (8, []) => e.ceremony_enabled().map(|on| vec![on as u8]),
                _ => Err(HwError("malformed request".into())),
            }
        };
        let (status, body) = match result {
            Ok(b) => (0u8, b),
            Err(e) => (1u8, e.0.into_bytes()),
        };
        let mut resp = vec![status];
        resp.extend((body.len() as u16).to_be_bytes());
        resp.extend(body);
        s.write_all(&resp)?;
    }
}

fn bind(path: &Path) -> std::io::Result<UnixListener> {
    let _ = std::fs::remove_file(path);
    let l = UnixListener::bind(path)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(l)
}

/// Serve the SoC-facing interface. Blocks.
pub fn serve_soc(path: &Path, enc: Arc<Mutex<Enclosure>>) -> std::io::Result<()> {
    for s in bind(path)?.incoming().flatten() {
        let enc = enc.clone();
        std::thread::spawn(move || {
            let _ = handle_soc(s, enc);
        });
    }
    Ok(())
}

/// Serve the physical-simulation socket on a background thread. One command
/// per connection, one line of reply.
pub fn serve_physical(path: &Path, enc: Arc<Mutex<Enclosure>>) -> std::io::Result<()> {
    let listener = bind(path)?;
    std::thread::spawn(move || {
        for mut s in listener.incoming().flatten() {
            let mut line = String::new();
            if BufReader::new(&s).read_line(&mut line).is_err() {
                continue;
            }
            let reply = enc.lock().unwrap_or_else(|x| x.into_inner()).physical_command(&line);
            let _ = s.write_all(format!("{reply}\n").as_bytes());
        }
    });
    Ok(())
}
