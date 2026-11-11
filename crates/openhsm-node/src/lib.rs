//! OpenHSM node.
//!
//! The node is the software that runs on the signing node's SoC. It exposes
//! an authenticated API to application servers and operators, applies policy
//! to every signing request, drives the signing module, and keeps a signed
//! audit chain. Private keys never exist in this process: they are generated,
//! unwrapped and used inside the signing module (`openhsm-signer`, a model of
//! the FPGA in `FPGA/`).
//!
//! Module map, by trust domain:
//!
//! | Domain | Modules |
//! | --- | --- |
//! | Tamper enclosure (signing module, supervisor) | crate `openhsm-hw`, reached through `openhsm_hw::Hardware` |
//! | Secure world (holds session keys) | [`secure`], [`node`], [`policy`], [`audit`], [`cards`] |
//! | Normal world (network-facing) | [`server`], [`proto`], [`api`] |
//! | Pure functions | [`chains`], [`util`] |

#![forbid(unsafe_code)]

pub mod api;
pub mod audit;
pub mod cards;
pub mod chains {
    pub mod addr;
    pub mod btc;
    pub mod eth;
    pub mod rlp;
}
pub mod client;
pub mod node;
pub mod policy;
pub mod proto;
pub mod secure;
pub mod server;
pub mod state;
pub mod util;
