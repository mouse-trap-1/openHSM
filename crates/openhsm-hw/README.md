# openhsm-hw

Hardware abstraction for OpenHSM: the boundary between the node's SoC software
and everything inside the **tamper enclosure** (signing module and tamper
supervisor), plus software models of that enclosure.

| | |
|---|---|
| Kind | Library (`openhsm_hw`) and binary (`openhsm-hwsim`) |
| Depends on | [`openhsm-signer`](../openhsm-signer) |
| Used by | [`openhsm-node`](../openhsm-node) (the `Hardware` trait and `Enclosure`; `openhsmd` also uses `RemoteHardware` and `serve_physical`) |
| `unsafe` | Forbidden |

## What it does

The central item is the **`Hardware` trait**: everything the SoC can reach inside
the enclosure.

| Method | Purpose |
|---|---|
| `bus_write(ptr, data)` / `bus_read(ptr, n)` | I2C access to the signing module |
| `restart_signer()` | Supervisor resets the module and re-delivers the tamper secret; done at every SoC boot |
| `soc_keys()` | Derived keys for this boot: `chan` (`HMAC(S,"SN-CHAN")`, authenticates module commands) and `seal` (`HMAC(S,"SOC-SEAL-v1")`, seals the SoC's own keys). The SoC never receives `S` itself, so it cannot open a sealed KEK. Fails after a tamper event |
| `counter()` / `counter_increment()` | Monotonic counter in the supervisor's battery domain; anchors the audit chain against rollback |
| `tamper_status()` | The kill line: `Some(TripRecord)` once any sensor has tripped |
| `ceremony_enabled()` | State of the physical ceremony key-switch |

The physical world (sensors, key-switch, power) is deliberately **not** in the
trait: software on the SoC cannot actuate it. The models expose it separately for
simulation.

### Implementations

| Implementation | Where it runs | Use |
|---|---|---|
| `Enclosure` | In-process: a `Signer` plus a supervisor model (`mcu.rs`) | Tests and single-process demos |
| `RemoteHardware` | Client of an `Enclosure` in **another process** over a Unix socket (Unix only) | Reproduces real isolation: no module key and no tamper secret ever exists in the node's address space |
| Board driver (not yet written) | Linux `i2c-dev` plus the supervisor link | The remaining piece between this prototype and hardware |

`Arc<Mutex<Enclosure>>` also implements `Hardware`, which lets the daemon share one
enclosure between the SoC link and the physical-simulation socket.

### The supervisor model (`mcu.rs`)

Models the battery-backed STM32U5. Sensors: `mesh`, `lid`, `light`,
`accelerometer`, `voltage`, `temperature` (`SENSORS`). On a trip it erases `S`
and raises the kill line; nothing sealed to `S` can then be opened. Three
behaviours go beyond the existing hardware description and are proposed for the
supervisor firmware: derived SoC keys, the monotonic counter, and forwarding the
ceremony switch to the signing module.

Its battery-backed RAM is persisted as `mcu-ram.json` in the state directory.
That file stands in for hardware inside the enclosure and is **the one place the
prototype stores a root secret on disk**.

### Physical simulation (`Enclosure::physical_command`)

A line-based command set for driving the simulated world:
`tamper <sensor>`, `ceremony on|off`, `power-cycle`, `trng-fail on|off`, `glitch`,
`status`.

## Source layout

| File | Role |
|---|---|
| `src/lib.rs` | `Hardware` trait, `HwError`, `SocKeys`, re-exports |
| `src/enclosure.rs` | `Enclosure`: wires signer + supervisor, power cycle, trip, ceremony, `physical_command` |
| `src/mcu.rs` | Tamper supervisor model, `TripRecord`, `SENSORS` |
| `src/remote.rs` | Socket protocol: `RemoteHardware` (client), `serve_soc`, `serve_physical` |
| `src/bin/openhsm-hwsim.rs` | The enclosure as a stand-alone process |

## The `openhsm-hwsim` binary

```bash
openhsm-hwsim provision --state DIR
openhsm-hwsim run --state DIR --soc-socket PATH --physical-socket PATH
```

It serves two Unix sockets: the **SoC socket** carries the `Hardware` interface
(the wires between SoC and enclosure), and the **physical socket** carries
simulation commands (used by `hsmctl sim`). SoC-link frames are
`op(1) len(2 BE) payload`, with ops 1-8 mapping one-to-one onto the trait methods.
It is a prototype fixture that stands in for hardware.

## How it plugs into the larger system

```text
 hsmctl sim ──► physical socket ─┐
                                 ▼
 openhsmd ──Hardware trait──► Enclosure ──► openhsm_signer::Signer
 (openhsm-node, secure.rs)       │              ▲
        via RemoteHardware       └─ mcu.rs ─────┘  SPI 0xA5‖S, tamper pin, ceremony pin
        (unix:PATH) or in-process
```

- **`openhsm-node`** is written purely against `Box<dyn Hardware>`. `openhsmd`
  selects the implementation with `--hardware inproc` (default; enclosure state
  under `DATA/enclosure`) or `--hardware unix:PATH` (connect to `openhsm-hwsim`).
  `inproc` puts the module's keys inside the daemon and is for a first look only.
- **`openhsm-signer`** is the component being enclosed. This crate adds the
  supervisor, SPI delivery of `S`, and the pins around it.
- **`hsmctl sim`** reaches the physical socket to trip sensors, flip the
  ceremony switch and power-cycle, which is how the demo and the penetration
  tests exercise tamper response and ceremonies.
- **Tamper response.** The node polls `tamper_status()` on every request; on a
  trip it records the event, drops its in-memory keys and refuses further work.

## Build and test

```bash
cargo build -p openhsm-hw --release
cargo run -p openhsm-hw --bin openhsm-hwsim -- provision --state /tmp/enc
```

This crate has no tests of its own; it is exercised through `openhsm-node`'s
end-to-end tests and the penetration suite.

## Further reading

- [`docs/INTERFACE_CONTROL_DOCUMENT.md`](../../docs/INTERFACE_CONTROL_DOCUMENT.md): supervisor and module interfaces
- [`docs/THREAT_MODEL.md`](../../docs/THREAT_MODEL.md): physical attacker assumptions
