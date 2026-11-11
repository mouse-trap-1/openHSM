//! openhsmd: the OpenHSM node daemon.
//!
//! ```text
//! openhsmd init --data DIR --genesis FILE --node-id ID [--san NAME]... [--hardware HW]
//! openhsmd run  --data DIR --listen ADDR [--hardware HW] [--sim-physical] [--no-audit-fsync]
//! ```
//!
//! `HW` selects how the node reaches the tamper enclosure:
//!
//! * `unix:PATH` connects to `openhsm-hwsim` (the enclosure model in its own
//!   process). This reproduces the hardware isolation and is the mode the
//!   penetration tests use.
//! * `inproc` (default) runs the enclosure model inside the daemon, with its
//!   state under `DIR/enclosure`. Convenient for a first look; the daemon then
//!   contains the signing module's keys, which the real node never does.

#![forbid(unsafe_code)]

use openhsm_hw::{Enclosure, Hardware};
use openhsm_node::node::{Node, NodeOptions};
use openhsm_node::server;
use openhsm_node::state::Genesis;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

struct Args(Vec<String>);

impl Args {
    fn value(&self, flag: &str) -> Option<String> {
        self.0.iter().position(|a| a == flag).and_then(|i| self.0.get(i + 1)).cloned()
    }
    fn values(&self, flag: &str) -> Vec<String> {
        self.0.windows(2).filter(|w| w[0] == flag).map(|w| w[1].clone()).collect()
    }
    fn flag(&self, flag: &str) -> bool {
        self.0.iter().any(|a| a == flag)
    }
    fn required(&self, flag: &str) -> Result<String, String> {
        self.value(flag).ok_or_else(|| format!("missing {flag}"))
    }
}

const USAGE: &str = "usage:
  openhsmd init --data DIR --genesis FILE --node-id ID [--san NAME]... [--hardware inproc|unix:PATH]
  openhsmd run  --data DIR --listen ADDR [--hardware inproc|unix:PATH] [--sim-physical] [--no-audit-fsync]";

type Shared = Arc<Mutex<Enclosure>>;

/// Open the link to the tamper enclosure.
fn hardware(a: &Args, dir: &Path, provision: bool) -> Result<(Box<dyn Hardware>, Option<Shared>), String> {
    match a.value("--hardware").as_deref().unwrap_or("inproc") {
        "inproc" => {
            let state = dir.join("enclosure");
            let enc = if provision { Enclosure::provision(&state) } else { Enclosure::power_on(&state) }.map_err(|e| e.0)?;
            let shared = Arc::new(Mutex::new(enc));
            Ok((Box::new(shared.clone()), Some(shared)))
        }
        #[cfg(unix)]
        hw if hw.starts_with("unix:") => {
            let link = openhsm_hw::RemoteHardware::connect(Path::new(&hw[5..])).map_err(|e| e.0)?;
            Ok((Box::new(link), None))
        }
        other => Err(format!("unknown --hardware {other:?}")),
    }
}

fn init(a: &Args) -> Result<(), String> {
    let dir = PathBuf::from(a.required("--data")?);
    let genesis_path = a.required("--genesis")?;
    let genesis: Genesis =
        serde_json::from_slice(&std::fs::read(&genesis_path).map_err(|e| format!("{genesis_path}: {e}"))?).map_err(|e| format!("genesis: {e}"))?;
    let mut sans = a.values("--san");
    if sans.is_empty() {
        sans = vec!["localhost".into(), "127.0.0.1".into()];
    }
    let (hw, _) = hardware(a, &dir, true)?;
    let summary = Node::init(&dir, &genesis, &a.required("--node-id")?, &sans, hw)?;
    println!("node initialised in {}", dir.display());
    println!("identity public key (verifies the audit log): {}", summary.identity_pubkey);
    println!("certificate signing request: {}", summary.csr_path.display());
    println!("next: sign the request with the cluster CA and place the certificate at {}", dir.join("tls").join("node.crt").display());
    Ok(())
}

fn run(a: &Args) -> Result<(), String> {
    let dir = PathBuf::from(a.required("--data")?);
    let listen = a.required("--listen")?;
    let opts = NodeOptions { audit_fsync: !a.flag("--no-audit-fsync"), ..NodeOptions::default() };
    let (hw, shared) = hardware(a, &dir, false)?;
    let mut node = Node::boot(&dir, opts, hw)?;
    let cfg = server::tls_config(&node)?;
    let listener = TcpListener::bind(&listen).map_err(|e| format!("listen on {listen}: {e}"))?;
    eprintln!(
        "openhsmd {}: node {} of cluster {} listening on {listen} (KEK {}, {} wallets, audit entry {})",
        env!("CARGO_PKG_VERSION"),
        node.state.node_id,
        node.state.cluster,
        if node.sw.kek_loaded() { "loaded" } else { "not loaded" },
        node.state.wallets.len(),
        node.audit.seq
    );
    let node = Arc::new(Mutex::new(node));
    if a.flag("--sim-physical") {
        #[cfg(unix)]
        {
            let enc = shared.ok_or("--sim-physical applies to --hardware inproc; with unix: hardware, use the simulator's own physical socket")?;
            let path = dir.join("sim.sock");
            openhsm_hw::serve_physical(&path, enc).map_err(|e| format!("physical simulation socket: {e}"))?;
            eprintln!("openhsmd: PROTOTYPE physical-world simulation enabled at {}", path.display());
        }
        #[cfg(not(unix))]
        return Err("--sim-physical needs a Unix platform".into());
    }
    let _ = shared;
    server::serve(node, listener, cfg);
    Ok(())
}

fn main() -> ExitCode {
    let mut argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.is_empty() {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }
    let sub = argv.remove(0);
    let args = Args(argv);
    let result = match sub.as_str() {
        "init" => init(&args),
        "run" => run(&args),
        _ => Err(USAGE.to_string()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("openhsmd: {e}");
            ExitCode::FAILURE
        }
    }
}
