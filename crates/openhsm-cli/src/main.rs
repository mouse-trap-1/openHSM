//! hsmctl: operator and client tool for OpenHSM.
//!
//! Three groups of commands:
//!
//! * offline set-up: `pki`, `identity`, `genesis`, `profile`, `card-new`;
//! * talking to a node: `call` (one signer), `propose` / `approve` / `submit`
//!   (operations that need a quorum of admins);
//! * verification and simulation: `audit-verify`, `sim`.

#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use ed25519_dalek::{SigningKey, VerifyingKey};
use openhsm_node::client::{build_payload, load_sign_key, unwrap_response, Client, Profile};
use openhsm_node::proto::{sign_payload, Frame, Payload, SigEntry};
use openhsm_node::state::{valid_id, write_atomic, write_private, Genesis, Principal, Role};
use rcgen::{BasicConstraints, CertificateParams, CertificateSigningRequestParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "hsmctl", version, about = "Operator and client tool for OpenHSM")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Certificate authority for the cluster's mutual TLS.
    #[command(subcommand)]
    Pki(Pki),
    /// Create a principal: TLS client certificate, request-signing key and the registration record.
    Identity {
        #[arg(long)]
        ca_dir: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long, value_parser = ["admin", "signer", "auditor"])]
        role: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Write a genesis document from principal records.
    Genesis {
        #[arg(long)]
        cluster: String,
        #[arg(long)]
        quorum: usize,
        #[arg(long, default_value_t = 1)]
        lease_divisor: u64,
        #[arg(long)]
        ca: PathBuf,
        /// Principal record files written by `hsmctl identity` (NAME.principal.json).
        #[arg(long = "principal", required = true)]
        principals: Vec<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Write a connection profile for a principal.
    Profile {
        #[arg(long)]
        addr: String,
        #[arg(long, default_value = "localhost")]
        server_name: String,
        #[arg(long)]
        cluster: String,
        #[arg(long)]
        ca: PathBuf,
        /// Directory written by `hsmctl identity`.
        #[arg(long)]
        identity_dir: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Call a method signed by one principal. PARAMS is JSON, or @FILE.
    Call {
        #[arg(long)]
        profile: PathBuf,
        method: String,
        #[arg(default_value = "{}")]
        params: String,
    },
    /// Draft an operation that needs a quorum of admins.
    Propose {
        #[arg(long)]
        cluster: String,
        /// Node the operation is for; it is rejected anywhere else.
        #[arg(long)]
        node: String,
        #[arg(long, default_value_t = 12)]
        validity_hours: u64,
        #[arg(long)]
        out: PathBuf,
        method: String,
        #[arg(default_value = "{}")]
        params: String,
    },
    /// Add an admin's signature to a drafted operation.
    Approve {
        #[arg(long)]
        id: String,
        #[arg(long)]
        sign_key: PathBuf,
        op: PathBuf,
    },
    /// Submit a drafted operation; the submitter signs it too.
    Submit {
        #[arg(long)]
        profile: PathBuf,
        op: PathBuf,
    },
    /// Verify an audit log offline against a node's identity key.
    AuditVerify {
        #[arg(long)]
        log: PathBuf,
        /// Node identity public key (hex), printed by `openhsmd init`.
        #[arg(long)]
        identity: String,
    },
    /// Create a software operator card (test double for a YubiKey).
    CardNew {
        #[arg(long)]
        out: PathBuf,
    },
    /// PROTOTYPE: act on the simulated physical world of a node
    /// (e.g. `tamper lid`, `ceremony on`, `power-cycle`, `status`).
    Sim {
        /// Physical-simulation socket (DATA/sim.sock, or the one given to openhsm-hwsim).
        #[arg(long)]
        socket: PathBuf,
        #[arg(required = true)]
        command: Vec<String>,
    },
}

#[derive(Subcommand)]
enum Pki {
    /// Create the cluster CA.
    Init {
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value = "OpenHSM cluster CA")]
        name: String,
    },
    /// Sign a node's certificate signing request.
    SignCsr {
        #[arg(long)]
        ca_dir: PathBuf,
        #[arg(long)]
        csr: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
}

type Res<T> = Result<T, String>;

fn es<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

fn read(p: &Path) -> Res<String> {
    std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))
}

fn validity(params: &mut CertificateParams, days: i64) {
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::minutes(5);
    params.not_after = now + time::Duration::days(days);
}

fn load_ca(dir: &Path) -> Res<(rcgen::Certificate, KeyPair)> {
    let key = KeyPair::from_pem(&read(&dir.join("ca.key"))?).map_err(es)?;
    let params = CertificateParams::from_ca_cert_pem(&read(&dir.join("ca.crt"))?).map_err(es)?;
    let cert = params.self_signed(&key).map_err(es)?;
    Ok((cert, key))
}

fn fingerprint(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

fn params_arg(s: &str) -> Res<Value> {
    let text = match s.strip_prefix('@') {
        Some(file) => read(Path::new(file))?,
        None => s.to_string(),
    };
    serde_json::from_str(&text).map_err(|e| format!("params are not valid JSON: {e}"))
}

fn load_profile(p: &Path) -> Res<Profile> {
    serde_json::from_str(&read(p)?).map_err(|e| format!("{}: {e}", p.display()))
}

fn print_json(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
}

fn run(cli: Cli) -> Res<()> {
    match cli.cmd {
        Cmd::Pki(Pki::Init { out, name }) => {
            std::fs::create_dir_all(&out).map_err(es)?;
            if out.join("ca.key").exists() {
                return Err("a CA already exists in this directory".into());
            }
            let key = KeyPair::generate().map_err(es)?;
            let mut p = CertificateParams::new(Vec::<String>::new()).map_err(es)?;
            p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
            p.distinguished_name = rcgen::DistinguishedName::new();
            p.distinguished_name.push(DnType::CommonName, name);
            p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            validity(&mut p, 3650);
            let cert = p.self_signed(&key).map_err(es)?;
            write_atomic(&out.join("ca.crt"), cert.pem().as_bytes())?;
            write_private(&out.join("ca.key"), key.serialize_pem().as_bytes())?;
            println!("CA written to {}. Keep ca.key offline.", out.display());
        }
        Cmd::Pki(Pki::SignCsr { ca_dir, csr, out }) => {
            let (ca, ca_key) = load_ca(&ca_dir)?;
            let mut req = CertificateSigningRequestParams::from_pem(&read(&csr)?).map_err(es)?;
            req.params.is_ca = IsCa::NoCa;
            req.params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            req.params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            validity(&mut req.params, 365);
            let cert = req.signed_by(&ca, &ca_key).map_err(es)?;
            write_atomic(&out, cert.pem().as_bytes())?;
            println!("node certificate written to {} (fingerprint {})", out.display(), fingerprint(cert.der()));
        }
        Cmd::Identity { ca_dir, name, role, out } => {
            if !valid_id(&name) {
                return Err("name may contain letters, digits, '-', '_' and '.' only".into());
            }
            std::fs::create_dir_all(&out).map_err(es)?;
            let (ca, ca_key) = load_ca(&ca_dir)?;
            // TLS client certificate.
            let key = KeyPair::generate().map_err(es)?;
            let mut p = CertificateParams::new(Vec::<String>::new()).map_err(es)?;
            p.distinguished_name = rcgen::DistinguishedName::new();
            p.distinguished_name.push(DnType::CommonName, name.as_str());
            p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            validity(&mut p, 365);
            let cert = p.signed_by(&key, &ca, &ca_key).map_err(es)?;
            write_atomic(&out.join(format!("{name}.crt")), cert.pem().as_bytes())?;
            write_private(&out.join(format!("{name}.key")), key.serialize_pem().as_bytes())?;
            // Request-signing key.
            let mut seed = zeroize_seed()?;
            let sk = SigningKey::from_bytes(&seed);
            write_private(&out.join(format!("{name}.sign")), hex::encode(seed).as_bytes())?;
            seed.fill(0);
            let role = match role.as_str() {
                "admin" => Role::Admin,
                "signer" => Role::Signer,
                _ => Role::Auditor,
            };
            let record = Principal { role, pubkey: hex::encode(sk.verifying_key().to_bytes()), cert_fp: fingerprint(cert.der()) };
            let record_json = serde_json::to_string_pretty(&record).map_err(es)?;
            write_atomic(&out.join(format!("{name}.principal.json")), record_json.as_bytes())?;
            println!("{record_json}");
        }
        Cmd::Genesis { cluster, quorum, lease_divisor, ca, principals, out } => {
            let mut map = BTreeMap::new();
            for path in principals {
                let id = path
                    .file_name()
                    .and_then(|f| f.to_str())
                    .and_then(|f| f.strip_suffix(".principal.json"))
                    .ok_or_else(|| format!("{}: expected NAME.principal.json", path.display()))?
                    .to_string();
                let p: Principal = serde_json::from_str(&read(&path)?).map_err(|e| format!("{}: {e}", path.display()))?;
                map.insert(id, p);
            }
            let g = Genesis { cluster, quorum, lease_divisor, ca_cert_pem: read(&ca)?, principals: map };
            g.validate()?;
            write_atomic(&out, serde_json::to_string_pretty(&g).map_err(es)?.as_bytes())?;
            println!("genesis written to {}", out.display());
        }
        Cmd::Profile { addr, server_name, cluster, ca, identity_dir, name, out } => {
            let abs = |p: PathBuf| std::fs::canonicalize(&p).map_err(|e| format!("{}: {e}", p.display()));
            let profile = Profile {
                addr,
                server_name,
                cluster,
                id: name.clone(),
                ca: abs(ca)?,
                cert: abs(identity_dir.join(format!("{name}.crt")))?,
                key: abs(identity_dir.join(format!("{name}.key")))?,
                sign_key: abs(identity_dir.join(format!("{name}.sign")))?,
            };
            write_atomic(&out, serde_json::to_string_pretty(&profile).map_err(es)?.as_bytes())?;
        }
        Cmd::Call { profile, method, params } => {
            let client = Client::new(load_profile(&profile)?)?;
            print_json(&client.call(&method, params_arg(&params)?)?);
        }
        Cmd::Propose { cluster, node, validity_hours, out, method, params } => {
            if validity_hours == 0 || validity_hours > 24 {
                return Err("validity must be between 1 and 24 hours".into());
            }
            let payload = build_payload(&cluster, Some(&node), &method, params_arg(&params)?, Some(validity_hours * 3_600_000))?;
            let frame = Frame { payload, sigs: vec![] };
            write_atomic(&out, serde_json::to_string_pretty(&frame).map_err(es)?.as_bytes())?;
            println!("operation drafted in {}; collect approvals with `hsmctl approve`", out.display());
        }
        Cmd::Approve { id, sign_key, op } => {
            let mut frame: Frame = serde_json::from_str(&read(&op)?).map_err(es)?;
            // Show the approver exactly what they are signing.
            let p: Payload = serde_json::from_str(&frame.payload).map_err(es)?;
            eprintln!("approving: cluster={} node={} method={} params={}", p.cluster, p.node.as_deref().unwrap_or("-"), p.method, p.params);
            if frame.sigs.iter().any(|s| s.id == id) {
                return Err(format!("{id} has already approved this operation"));
            }
            let key = load_sign_key(&sign_key)?;
            frame.sigs.push(SigEntry { id, sig: sign_payload(&key, &frame.payload) });
            write_atomic(&op, serde_json::to_string_pretty(&frame).map_err(es)?.as_bytes())?;
            println!("{} approval(s) on {}", frame.sigs.len(), op.display());
        }
        Cmd::Submit { profile, op } => {
            let client = Client::new(load_profile(&profile)?)?;
            let mut frame: Frame = serde_json::from_str(&read(&op)?).map_err(es)?;
            // The submitter's signature goes first: it is the one bound to the TLS channel.
            frame.sigs.retain(|s| s.id != client.profile.id);
            frame.sigs.insert(0, client.sign(&frame.payload));
            print_json(&unwrap_response(client.send(&frame)?)?);
        }
        Cmd::AuditVerify { log, identity } => {
            let mut pk = [0u8; 32];
            hex::decode_to_slice(identity.trim(), &mut pk).map_err(|_| "identity must be 32 bytes of hex".to_string())?;
            let vk = VerifyingKey::from_bytes(&pk).map_err(es)?;
            let entries = openhsm_node::audit::verify_file(&log, &vk)?;
            println!("audit log verified: {} entries, chain and signatures intact", entries.len());
            if let Some(last) = entries.last() {
                println!("last entry: seq {} event {} actor {} ts {}", last.seq, last.event, last.actor, last.ts);
            }
        }
        Cmd::CardNew { out } => {
            let mut key = [0u8; 20];
            getrandom::getrandom(&mut key).map_err(es)?;
            write_private(&out, hex::encode(key).as_bytes())?;
            key.fill(0);
            println!("software operator card written to {}", out.display());
        }
        Cmd::Sim { socket, command } => {
            #[cfg(unix)]
            {
                use std::io::{Read, Write};
                let mut s = std::os::unix::net::UnixStream::connect(&socket).map_err(|e| format!("{}: {e}", socket.display()))?;
                s.write_all(format!("{}\n", command.join(" ")).as_bytes()).map_err(es)?;
                let mut reply = String::new();
                s.read_to_string(&mut reply).map_err(es)?;
                print!("{reply}");
                if reply.starts_with("error") {
                    return Err("the simulator rejected the command".into());
                }
            }
            #[cfg(not(unix))]
            {
                let _ = (socket, command);
                return Err("sim needs a Unix platform".into());
            }
        }
    }
    Ok(())
}

fn zeroize_seed() -> Res<[u8; 32]> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(es)?;
    Ok(seed)
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hsmctl: {e}");
            ExitCode::FAILURE
        }
    }
}
