//! openhsm-hwsim: the tamper enclosure (signing module + tamper supervisor)
//! as a separate process.
//!
//! ```text
//! openhsm-hwsim provision --state DIR
//! openhsm-hwsim run --state DIR --soc-socket PATH --physical-socket PATH
//! ```
//!
//! PROTOTYPE FIXTURE. It stands in for hardware. The state directory holds
//! the supervisor's battery-backed RAM, including the tamper secret; on the
//! real board that RAM is inside the mesh and is erased when it is breached.

#![forbid(unsafe_code)]

use std::process::ExitCode;

#[cfg(unix)]
fn run() -> Result<(), String> {
    use openhsm_hw::{serve_physical, serve_soc, Enclosure};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    let args: Vec<String> = std::env::args().skip(1).collect();
    let value = |flag: &str| args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned();
    let need = |flag: &str| value(flag).ok_or_else(|| format!("missing {flag}"));
    let state = PathBuf::from(need("--state")?);
    match args.first().map(String::as_str) {
        Some("provision") => {
            Enclosure::provision(&state).map_err(|e| e.0)?;
            println!("tamper supervisor provisioned in {}", state.display());
            Ok(())
        }
        Some("run") => {
            let enc = Arc::new(Mutex::new(Enclosure::power_on(&state).map_err(|e| e.0)?));
            let (soc, phys) = (PathBuf::from(need("--soc-socket")?), PathBuf::from(need("--physical-socket")?));
            serve_physical(&phys, enc.clone()).map_err(|e| format!("{}: {e}", phys.display()))?;
            eprintln!("openhsm-hwsim: PROTOTYPE enclosure model; SoC link {}, physical simulation {}", soc.display(), phys.display());
            serve_soc(&soc, enc).map_err(|e| format!("{}: {e}", soc.display()))
        }
        _ => Err("usage: openhsm-hwsim provision --state DIR | run --state DIR --soc-socket PATH --physical-socket PATH".into()),
    }
}

#[cfg(not(unix))]
fn run() -> Result<(), String> {
    Err("openhsm-hwsim needs a Unix platform".into())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("openhsm-hwsim: {e}");
            ExitCode::FAILURE
        }
    }
}
