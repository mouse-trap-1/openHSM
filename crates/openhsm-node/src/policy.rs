//! Per-wallet signing policy, enforced inside the node before the signing
//! module is asked for anything.
//!
//! The policy is fail-closed: every limit defaults to zero and every
//! permission to "no". A wallet created with an empty policy cannot sign.

use crate::chains::btc::{self, BtcTx, Network};
use crate::chains::eth::{self, Erc20Call, EthTx};
use crate::util::U256;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};

pub const DAY_MS: u64 = 86_400_000;

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct TokenPolicy {
    pub max_per_tx: U256,
    pub max_per_day: U256,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct Policy {
    /// Largest native amount (wei or satoshi) one transaction may send out.
    pub max_per_tx: U256,
    /// Native amount, fees included, that may leave per UTC day (cluster-wide).
    pub max_per_day: U256,
    /// Largest total fee of one transaction (wei or satoshi).
    pub max_fee: U256,
    /// Bitcoin only: largest fee rate in satoshi per virtual byte.
    pub max_fee_rate: u64,
    /// If true (default), every recipient must be on `allowlist`.
    pub require_allowlist: bool,
    pub allowlist: Vec<String>,
    /// Ethereum only: chain ids this wallet may sign for.
    pub chain_ids: Vec<u64>,
    /// Ethereum only: managed tokens. Only `transfer` is permitted on them.
    pub erc20: BTreeMap<String, TokenPolicy>,
    /// Ethereum only: arbitrary calls, restricted to `contract_allowlist`.
    pub allow_contract_calls: bool,
    pub contract_allowlist: Vec<String>,
    pub allow_contract_creation: bool,
    /// Ethereum only: EIP-191 personal messages.
    pub allow_message_signing: bool,
    /// Sign a caller-supplied 32-byte digest. This is blind signing.
    pub allow_raw_digest: bool,
    pub max_signatures_per_minute: u32,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            max_per_tx: U256::ZERO,
            max_per_day: U256::ZERO,
            max_fee: U256::ZERO,
            max_fee_rate: 0,
            require_allowlist: true,
            allowlist: vec![],
            chain_ids: vec![],
            erc20: BTreeMap::new(),
            allow_contract_calls: false,
            contract_allowlist: vec![],
            allow_contract_creation: false,
            allow_message_signing: false,
            allow_raw_digest: false,
            max_signatures_per_minute: 600,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Chain {
    Ethereum,
    Bitcoin,
}

/// One debit against a daily budget.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Spend {
    pub asset: String,
    pub amount: U256,
    #[serde(skip)]
    pub cap_per_day: U256,
}

fn eth_key(a: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(a))
}

impl Policy {
    /// Validate and canonicalise a policy for a wallet on `chain`.
    pub fn normalize(mut self, chain: Chain, net: Option<Network>) -> Result<Policy, String> {
        if self.allowlist.len() > 4096 || self.contract_allowlist.len() > 4096 || self.erc20.len() > 256 {
            return Err("policy lists too long".into());
        }
        match chain {
            Chain::Ethereum => {
                let canon = |list: &[String]| -> Result<Vec<String>, String> {
                    let mut v = list.iter().map(|a| eth::parse_address(a).map(|x| eth_key(&x))).collect::<Result<Vec<_>, _>>()?;
                    v.sort();
                    v.dedup();
                    Ok(v)
                };
                self.allowlist = canon(&self.allowlist)?;
                self.contract_allowlist = canon(&self.contract_allowlist)?;
                let mut tokens = BTreeMap::new();
                for (k, v) in std::mem::take(&mut self.erc20) {
                    tokens.insert(eth_key(&eth::parse_address(&k)?), v);
                }
                self.erc20 = tokens;
                if self.max_fee_rate != 0 {
                    return Err("max_fee_rate applies to Bitcoin wallets only".into());
                }
            }
            Chain::Bitcoin => {
                let net = net.ok_or("a Bitcoin wallet needs a network")?;
                for a in &self.allowlist {
                    btc::address_to_script(net, a)?;
                }
                if !self.chain_ids.is_empty()
                    || !self.erc20.is_empty()
                    || self.allow_contract_calls
                    || self.allow_contract_creation
                    || self.allow_message_signing
                    || !self.contract_allowlist.is_empty()
                {
                    return Err("Ethereum-only policy fields set on a Bitcoin wallet".into());
                }
            }
        }
        Ok(self)
    }

    fn allowed(&self, key: &str) -> bool {
        !self.require_allowlist || self.allowlist.iter().any(|a| a == key)
    }

    /// Decide whether an Ethereum transaction may be signed.
    pub fn check_eth(&self, tx: &EthTx) -> Result<Vec<Spend>, String> {
        if !self.chain_ids.contains(&tx.chain_id) {
            return Err(format!("chain id {} is not permitted for this wallet", tx.chain_id));
        }
        let fee = tx.max_fee().ok_or("fee overflows")?;
        if fee > self.max_fee {
            return Err(format!("worst-case fee {fee} exceeds max_fee {}", self.max_fee));
        }
        let native = |value: U256| -> Result<Spend, String> {
            Ok(Spend { asset: "native".into(), amount: value.checked_add(&fee).ok_or("amount overflows")?, cap_per_day: self.max_per_day })
        };
        let Some(to) = tx.to else {
            if !self.allow_contract_creation {
                return Err("contract creation is not permitted".into());
            }
            if tx.value > self.max_per_tx {
                return Err("value exceeds max_per_tx".into());
            }
            return Ok(vec![native(tx.value)?]);
        };
        let to_key = eth_key(&to);
        if tx.data.is_empty() {
            if !self.allowed(&to_key) {
                return Err(format!("recipient {to_key} is not on the allow-list"));
            }
            if tx.value > self.max_per_tx {
                return Err(format!("value {} exceeds max_per_tx {}", tx.value, self.max_per_tx));
            }
            return Ok(vec![native(tx.value)?]);
        }
        if let Some(tp) = self.erc20.get(&to_key) {
            if !tx.value.is_zero() {
                return Err("a token transfer must not carry ether".into());
            }
            return match eth::decode_erc20(&tx.data) {
                Some(Erc20Call::Transfer { to: rcpt, amount }) => {
                    let rk = eth_key(&rcpt);
                    if !self.allowed(&rk) {
                        return Err(format!("token recipient {rk} is not on the allow-list"));
                    }
                    if amount > tp.max_per_tx {
                        return Err(format!("token amount {amount} exceeds the token max_per_tx {}", tp.max_per_tx));
                    }
                    Ok(vec![native(U256::ZERO)?, Spend { asset: format!("erc20:{to_key}"), amount, cap_per_day: tp.max_per_day }])
                }
                _ => Err("only transfer(address,uint256) is permitted on a managed token".into()),
            };
        }
        if !self.allow_contract_calls || !self.contract_allowlist.contains(&to_key) {
            return Err(format!("contract call to {to_key} is not permitted"));
        }
        if tx.value > self.max_per_tx {
            return Err("value exceeds max_per_tx".into());
        }
        Ok(vec![native(tx.value)?])
    }

    /// Decide whether a Bitcoin transaction may be signed. `own_script` is
    /// the wallet's own scriptPubKey; outputs paying it are change.
    pub fn check_btc(&self, net: Network, tx: &BtcTx, own_script: &[u8]) -> Result<Vec<Spend>, String> {
        let fee = tx.fee()?;
        if U256::from_u64(fee) > self.max_fee {
            return Err(format!("fee {fee} sat exceeds max_fee {}", self.max_fee));
        }
        if self.max_fee_rate == 0 {
            return Err("policy has no max_fee_rate".into());
        }
        let vsize = tx.vsize_estimate();
        if fee > self.max_fee_rate.saturating_mul(vsize) {
            return Err(format!("fee rate {} sat/vB exceeds max_fee_rate {}", fee / vsize.max(1), self.max_fee_rate));
        }
        let allowed: Vec<Vec<u8>> = self.allowlist.iter().filter_map(|a| btc::address_to_script(net, a).ok()).collect();
        let mut external = 0u64;
        for o in &tx.outs {
            if o.script_pubkey == own_script {
                continue;
            }
            if self.require_allowlist && !allowed.contains(&o.script_pubkey) {
                return Err("an output pays an address that is not on the allow-list".into());
            }
            external = external.checked_add(o.amount).ok_or("amount overflows")?;
        }
        if U256::from_u64(external) > self.max_per_tx {
            return Err(format!("external amount {external} sat exceeds max_per_tx {}", self.max_per_tx));
        }
        let total = external.checked_add(fee).ok_or("amount overflows")?;
        Ok(vec![Spend { asset: "native".into(), amount: U256::from_u64(total), cap_per_day: self.max_per_day }])
    }
}

/// Running totals for the current UTC day and the per-minute signing rate.
/// Rebuilt from the audit log at boot, so it cannot be reset by restarting.
#[derive(Debug, Default)]
pub struct Ledger {
    day: u64,
    spent: HashMap<(String, String), U256>,
    recent: HashMap<String, VecDeque<u64>>,
}

impl Ledger {
    fn roll(&mut self, now_ms: u64) {
        let day = now_ms / DAY_MS;
        if day != self.day {
            self.day = day;
            self.spent.clear();
        }
    }

    pub fn spent_today(&mut self, now_ms: u64, wallet: &str, asset: &str) -> U256 {
        self.roll(now_ms);
        self.spent.get(&(wallet.to_string(), asset.to_string())).copied().unwrap_or_default()
    }

    /// Check budgets and rate without changing anything.
    /// `lease_divisor` is the number of signing nodes sharing the daily cap:
    /// each node may spend its share without consulting the others.
    pub fn check(&mut self, now_ms: u64, wallet: &str, spends: &[Spend], rate_per_min: u32, sigs: usize, lease_divisor: u64) -> Result<(), String> {
        self.roll(now_ms);
        let q = self.recent.entry(wallet.to_string()).or_default();
        while q.front().is_some_and(|t| now_ms.saturating_sub(*t) >= 60_000) {
            q.pop_front();
        }
        if q.len() + sigs > rate_per_min as usize {
            return Err(format!("wallet signing rate exceeds {rate_per_min} per minute"));
        }
        for s in spends {
            let lease = s.cap_per_day.div_rem_u64(lease_divisor.max(1)).map(|(q, _)| q).unwrap_or_default();
            let used = self.spent.get(&(wallet.to_string(), s.asset.clone())).copied().unwrap_or_default();
            let after = used.checked_add(&s.amount).ok_or("daily total overflows")?;
            if after > lease {
                return Err(format!("daily limit for {} exceeded: {used} already used, {} requested, {lease} leased to this node", s.asset, s.amount));
            }
        }
        Ok(())
    }

    /// Record spends after the audit entry for them is durable.
    pub fn commit(&mut self, ts_ms: u64, wallet: &str, spends: &[Spend], sigs: usize) {
        self.roll(ts_ms);
        for s in spends {
            let e = self.spent.entry((wallet.to_string(), s.asset.clone())).or_default();
            *e = e.checked_add(&s.amount).unwrap_or(U256::MAX);
        }
        let q = self.recent.entry(wallet.to_string()).or_default();
        for _ in 0..sigs {
            q.push_back(ts_ms);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::eth::EthTxRequest;

    fn pol(json: &str) -> Policy {
        serde_json::from_str::<Policy>(json).unwrap().normalize(Chain::Ethereum, None).unwrap()
    }
    fn tx(json: &str) -> EthTx {
        EthTx::parse(&serde_json::from_str::<EthTxRequest>(json).unwrap()).unwrap()
    }
    const A: &str = "0x1111111111111111111111111111111111111111";
    const B: &str = "0x2222222222222222222222222222222222222222";
    const TOKEN: &str = "0x3333333333333333333333333333333333333333";

    fn base_policy() -> Policy {
        pol(&format!(
            r#"{{"max_per_tx":"1000","max_per_day":"100000000000000","max_fee":"63000000000000","chain_ids":[11155111],
                "allowlist":["{A}"],"erc20":{{"{TOKEN}":{{"max_per_tx":"500","max_per_day":"800"}}}}}}"#
        ))
    }
    fn transfer(to: &str, value: &str, chain: u64) -> EthTx {
        tx(&format!(
            r#"{{"chain_id":{chain},"nonce":0,"gas_limit":21000,"to":"{to}","value":"{value}","max_fee_per_gas":"3000000000","max_priority_fee_per_gas":"1"}}"#
        ))
    }

    #[test]
    fn empty_policy_denies_everything() {
        let p = Policy::default().normalize(Chain::Ethereum, None).unwrap();
        assert!(p.check_eth(&transfer(A, "1", 1)).is_err());
    }

    #[test]
    fn eth_policy_matrix() {
        let p = base_policy();
        assert!(p.check_eth(&transfer(A, "1000", 11155111)).is_ok());
        assert!(p.check_eth(&transfer(A, "1001", 11155111)).is_err(), "over per-tx cap");
        assert!(p.check_eth(&transfer(B, "1", 11155111)).is_err(), "not allow-listed");
        assert!(p.check_eth(&transfer(A, "1", 1)).is_err(), "wrong chain");
        let pricey = tx(&format!(
            r#"{{"chain_id":11155111,"nonce":0,"gas_limit":21001,"to":"{A}","value":"1","max_fee_per_gas":"3000000000","max_priority_fee_per_gas":"1"}}"#
        ));
        assert!(p.check_eth(&pricey).is_err(), "fee cap");
        let create = tx(r#"{"chain_id":11155111,"nonce":0,"gas_limit":21000,"data":"0x6000","max_fee_per_gas":"1","max_priority_fee_per_gas":"1"}"#);
        assert!(p.check_eth(&create).is_err(), "contract creation");
    }

    fn token_call(selector: &str, rcpt: &str, amount: u64, to: &str, value: &str) -> EthTx {
        let data = format!("0x{selector}{:0>64}{:064x}", &rcpt[2..], amount);
        tx(&format!(
            r#"{{"chain_id":11155111,"nonce":0,"gas_limit":21000,"to":"{to}","value":"{value}","data":"{data}","max_fee_per_gas":"1","max_priority_fee_per_gas":"1"}}"#
        ))
    }

    #[test]
    fn erc20_rules() {
        let p = base_policy();
        let ok = p.check_eth(&token_call("a9059cbb", A, 500, TOKEN, "0")).unwrap();
        assert_eq!(ok[1].asset, format!("erc20:{TOKEN}"));
        assert!(p.check_eth(&token_call("a9059cbb", A, 501, TOKEN, "0")).is_err(), "token cap");
        assert!(p.check_eth(&token_call("a9059cbb", B, 1, TOKEN, "0")).is_err(), "recipient hidden in calldata");
        assert!(p.check_eth(&token_call("095ea7b3", A, 1, TOKEN, "0")).is_err(), "approve");
        assert!(p.check_eth(&token_call("a9059cbb", A, 1, TOKEN, "1")).is_err(), "ether attached");
        assert!(p.check_eth(&token_call("a9059cbb", A, 1, B, "0")).is_err(), "unmanaged contract");
    }

    #[test]
    fn ledger_daily_limit_and_lease() {
        let mut l = Ledger::default();
        let s = |n: u64| vec![Spend { asset: "native".into(), amount: U256::from_u64(n), cap_per_day: U256::from_u64(1000) }];
        let t0 = 20_000 * DAY_MS + 5;
        assert!(l.check(t0, "w", &s(600), 100, 1, 1).is_ok());
        l.commit(t0, "w", &s(600), 1);
        assert!(l.check(t0 + 1, "w", &s(401), 100, 1, 1).is_err());
        assert!(l.check(t0 + 1, "w", &s(400), 100, 1, 1).is_ok());
        assert!(l.check(t0 + 1, "w", &s(400), 100, 1, 2).is_err(), "half the cap is leased to this node");
        assert!(l.check(t0 + DAY_MS, "w", &s(1000), 100, 1, 1).is_ok(), "new day");
    }

    #[test]
    fn ledger_rate_limit() {
        let mut l = Ledger::default();
        let t0 = 20_000 * DAY_MS;
        for i in 0..3 {
            assert!(l.check(t0 + i, "w", &[], 3, 1, 1).is_ok());
            l.commit(t0 + i, "w", &[], 1);
        }
        assert!(l.check(t0 + 10, "w", &[], 3, 1, 1).is_err());
        assert!(l.check(t0 + 60_001, "w", &[], 3, 1, 1).is_ok());
    }
}
