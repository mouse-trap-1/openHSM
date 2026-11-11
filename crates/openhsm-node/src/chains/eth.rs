//! Ethereum transaction construction: EIP-1559 (type 2) and legacy EIP-155.
//!
//! The client supplies structured fields. The node encodes the transaction
//! itself, applies policy to the decoded meaning (recipient, value, fee,
//! contract call), and only then asks the signing module for a signature over
//! the hash it computed. The module never signs a digest the node cannot
//! explain, unless the wallet policy explicitly allows raw digests.

use super::rlp::{encode, Item};
use crate::util::{keccak256, unhex, unhex_n, U256};
use serde::Deserialize;

pub const MAX_DATA_LEN: usize = 128 * 1024;
pub const MAX_ACCESS_LIST: usize = 256;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessItem {
    pub address: String,
    #[serde(default)]
    pub storage_keys: Vec<String>,
}

fn default_type() -> String {
    "eip1559".into()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EthTxRequest {
    #[serde(rename = "type", default = "default_type")]
    pub ty: String,
    pub chain_id: u64,
    pub nonce: u64,
    pub gas_limit: u64,
    #[serde(default)]
    pub to: Option<String>,
    #[serde(default)]
    pub value: U256,
    #[serde(default)]
    pub data: String,
    #[serde(default)]
    pub max_fee_per_gas: Option<U256>,
    #[serde(default)]
    pub max_priority_fee_per_gas: Option<U256>,
    #[serde(default)]
    pub gas_price: Option<U256>,
    #[serde(default)]
    pub access_list: Vec<AccessItem>,
}

/// A validated transaction.
#[derive(Debug, Clone)]
pub struct EthTx {
    pub eip1559: bool,
    pub chain_id: u64,
    pub nonce: u64,
    pub gas_limit: u64,
    pub to: Option<[u8; 20]>,
    pub value: U256,
    pub data: Vec<u8>,
    /// maxFeePerGas (type 2) or gasPrice (legacy).
    pub fee_per_gas: U256,
    pub priority_fee_per_gas: U256,
    pub access_list: Vec<([u8; 20], Vec<[u8; 32]>)>,
}

/// What a call to a token contract means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Erc20Call {
    Transfer { to: [u8; 20], amount: U256 },
    Approve { spender: [u8; 20], amount: U256 },
    TransferFrom { from: [u8; 20], to: [u8; 20], amount: U256 },
}

fn abi_address(word: &[u8]) -> Option<[u8; 20]> {
    if word[..12].iter().any(|&b| b != 0) {
        return None;
    }
    word[12..32].try_into().ok()
}

/// Decode the three ERC-20 calls that move or delegate funds. Anything that
/// does not match one of these shapes exactly returns `None`.
pub fn decode_erc20(data: &[u8]) -> Option<Erc20Call> {
    if data.len() < 4 {
        return None;
    }
    let (sel, args) = data.split_at(4);
    match (sel, args.len()) {
        ([0xa9, 0x05, 0x9c, 0xbb], 64) => Some(Erc20Call::Transfer { to: abi_address(&args[..32])?, amount: U256::from_be_slice(&args[32..64])? }),
        ([0x09, 0x5e, 0xa7, 0xb3], 64) => Some(Erc20Call::Approve { spender: abi_address(&args[..32])?, amount: U256::from_be_slice(&args[32..64])? }),
        ([0x23, 0xb8, 0x72, 0xdd], 96) => {
            Some(Erc20Call::TransferFrom { from: abi_address(&args[..32])?, to: abi_address(&args[32..64])?, amount: U256::from_be_slice(&args[64..96])? })
        }
        _ => None,
    }
}

/// EIP-55 mixed-case checksum encoding.
pub fn to_checksum(addr: &[u8; 20]) -> String {
    let lower = hex::encode(addr);
    let hash = keccak256(lower.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in lower.chars().enumerate() {
        let nibble = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0xF;
        out.push(if c.is_ascii_alphabetic() && nibble >= 8 { c.to_ascii_uppercase() } else { c });
    }
    out
}

/// Parse an address. A mixed-case address must carry a valid EIP-55 checksum.
pub fn parse_address(s: &str) -> Result<[u8; 20], String> {
    let t = s.strip_prefix("0x").ok_or("address must start with 0x")?;
    if t.len() != 40 {
        return Err("address must be 20 bytes".into());
    }
    let a: [u8; 20] = unhex_n(t).map_err(|_| "invalid address hex".to_string())?;
    let has_upper = t.bytes().any(|c| c.is_ascii_uppercase());
    let has_lower = t.bytes().any(|c| c.is_ascii_lowercase());
    if has_upper && has_lower && to_checksum(&a) != s {
        return Err("address checksum (EIP-55) mismatch".into());
    }
    Ok(a)
}

/// Address of an uncompressed public key (x || y, 64 bytes).
pub fn address_from_pubkey(xy: &[u8; 64]) -> [u8; 20] {
    let h = keccak256(xy);
    let mut a = [0u8; 20];
    a.copy_from_slice(&h[12..]);
    a
}

/// EIP-191 personal-message hash.
pub fn personal_message_hash(msg: &[u8]) -> [u8; 32] {
    let mut buf = format!("\x19Ethereum Signed Message:\n{}", msg.len()).into_bytes();
    buf.extend_from_slice(msg);
    keccak256(&buf)
}

impl EthTx {
    pub fn parse(req: &EthTxRequest) -> Result<EthTx, String> {
        let eip1559 = match req.ty.as_str() {
            "eip1559" => true,
            "legacy" => false,
            _ => return Err("type must be \"eip1559\" or \"legacy\"".into()),
        };
        if req.chain_id == 0 || req.chain_id > (u64::MAX - 36) / 2 {
            return Err("chain_id out of range (replay protection is mandatory)".into());
        }
        if req.gas_limit < 21_000 {
            return Err("gas_limit below the intrinsic minimum of 21000".into());
        }
        let to = req.to.as_deref().map(parse_address).transpose()?;
        let data = unhex(&req.data)?;
        if data.len() > MAX_DATA_LEN {
            return Err("data too large".into());
        }
        let (fee_per_gas, priority_fee_per_gas) = if eip1559 {
            if req.gas_price.is_some() {
                return Err("gas_price is not valid for an EIP-1559 transaction".into());
            }
            let max = req.max_fee_per_gas.ok_or("max_fee_per_gas is required")?;
            let prio = req.max_priority_fee_per_gas.ok_or("max_priority_fee_per_gas is required")?;
            if prio > max {
                return Err("max_priority_fee_per_gas exceeds max_fee_per_gas".into());
            }
            (max, prio)
        } else {
            if req.max_fee_per_gas.is_some() || req.max_priority_fee_per_gas.is_some() || !req.access_list.is_empty() {
                return Err("EIP-1559 fields are not valid for a legacy transaction".into());
            }
            (req.gas_price.ok_or("gas_price is required")?, U256::ZERO)
        };
        if req.access_list.len() > MAX_ACCESS_LIST {
            return Err("access list too long".into());
        }
        let mut access_list = Vec::new();
        for item in &req.access_list {
            if item.storage_keys.len() > MAX_ACCESS_LIST {
                return Err("access list too long".into());
            }
            let keys = item.storage_keys.iter().map(|k| unhex_n::<32>(k)).collect::<Result<Vec<_>, _>>()?;
            access_list.push((parse_address(&item.address)?, keys));
        }
        Ok(EthTx {
            eip1559,
            chain_id: req.chain_id,
            nonce: req.nonce,
            gas_limit: req.gas_limit,
            to,
            value: req.value,
            data,
            fee_per_gas,
            priority_fee_per_gas,
            access_list,
        })
    }

    /// Worst-case fee in wei: gas_limit * fee_per_gas.
    pub fn max_fee(&self) -> Option<U256> {
        self.fee_per_gas.checked_mul_u64(self.gas_limit)
    }

    fn base_items(&self) -> Vec<Item> {
        let to = Item::Str(self.to.map(|a| a.to_vec()).unwrap_or_default());
        if self.eip1559 {
            let al = self
                .access_list
                .iter()
                .map(|(a, keys)| Item::List(vec![Item::Str(a.to_vec()), Item::List(keys.iter().map(|k| Item::Str(k.to_vec())).collect())]))
                .collect();
            vec![
                Item::u64(self.chain_id),
                Item::u64(self.nonce),
                Item::uint(&self.priority_fee_per_gas),
                Item::uint(&self.fee_per_gas),
                Item::u64(self.gas_limit),
                to,
                Item::uint(&self.value),
                Item::Str(self.data.clone()),
                Item::List(al),
            ]
        } else {
            vec![Item::u64(self.nonce), Item::uint(&self.fee_per_gas), Item::u64(self.gas_limit), to, Item::uint(&self.value), Item::Str(self.data.clone())]
        }
    }

    /// The hash the signature covers.
    pub fn sighash(&self) -> [u8; 32] {
        let mut items = self.base_items();
        if self.eip1559 {
            let mut buf = vec![0x02];
            buf.extend(encode(&Item::List(items)));
            keccak256(&buf)
        } else {
            items.extend([Item::u64(self.chain_id), Item::u64(0), Item::u64(0)]);
            keccak256(&encode(&Item::List(items)))
        }
    }

    /// The signed transaction ready for `eth_sendRawTransaction`.
    pub fn encode_signed(&self, recid: u8, r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
        let mut items = self.base_items();
        let trim = |w: &[u8; 32]| Item::uint(&U256::from_be_slice(w).unwrap_or_default());
        if self.eip1559 {
            items.extend([Item::u64(recid as u64), trim(r), trim(s)]);
            let mut buf = vec![0x02];
            buf.extend(encode(&Item::List(items)));
            buf
        } else {
            items.extend([Item::u64(self.chain_id * 2 + 35 + recid as u64), trim(r), trim(s)]);
            encode(&Item::List(items))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(json: &str) -> EthTxRequest {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn eip155_example_sighash() {
        // The worked example from EIP-155.
        let tx = EthTx::parse(&req(r#"{"type":"legacy","chain_id":1,"nonce":9,"gas_price":"20000000000","gas_limit":21000,
                "to":"0x3535353535353535353535353535353535353535","value":"1000000000000000000"}"#))
        .unwrap();
        assert_eq!(hex::encode(tx.sighash()), "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53");
        let r = U256::from_dec_str("18515461264373351373200002665853028612451056578545711640558177340181847433846").unwrap();
        let s = U256::from_dec_str("46948507304638947509940763649030358759909902576025900602547168820602576006531").unwrap();
        let raw = tx.encode_signed(0, &r.to_be_bytes(), &s.to_be_bytes());
        // v = chain_id * 2 + 35 + recid = 37 (0x25); r and s follow as 32-byte strings.
        let expect = format!(
            "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a0{}a0{}",
            hex::encode(r.to_be_bytes()),
            hex::encode(s.to_be_bytes())
        );
        assert_eq!(hex::encode(raw), expect);
    }

    #[test]
    fn checksum_addresses() {
        let a = parse_address("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed").unwrap();
        assert_eq!(to_checksum(&a), "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
        assert!(parse_address("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD").is_err());
        assert!(parse_address("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").is_ok());
        assert!(parse_address("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").is_err());
    }

    #[test]
    fn rejects_malformed_requests() {
        assert!(serde_json::from_str::<EthTxRequest>(r#"{"chain_id":1,"nonce":0,"gas_limit":21000,"evil":1}"#).is_err());
        let base = r#"{"chain_id":0,"nonce":0,"gas_limit":21000,"max_fee_per_gas":"1","max_priority_fee_per_gas":"1"}"#;
        assert!(EthTx::parse(&req(base)).is_err());
        let prio = r#"{"chain_id":1,"nonce":0,"gas_limit":21000,"max_fee_per_gas":"1","max_priority_fee_per_gas":"2"}"#;
        assert!(EthTx::parse(&req(prio)).is_err());
        let mixed = r#"{"type":"legacy","chain_id":1,"nonce":0,"gas_limit":21000,"gas_price":"1","max_fee_per_gas":"1"}"#;
        assert!(EthTx::parse(&req(mixed)).is_err());
    }

    #[test]
    fn erc20_decoding_is_exact() {
        let mut d = hex::decode("a9059cbb").unwrap();
        d.extend([0u8; 12]);
        d.extend([0x11u8; 20]);
        d.extend(U256::from_u64(5).to_be_bytes());
        assert_eq!(decode_erc20(&d), Some(Erc20Call::Transfer { to: [0x11; 20], amount: U256::from_u64(5) }));
        let mut longer = d.clone();
        longer.push(0);
        assert_eq!(decode_erc20(&longer), None);
        let mut dirty = d.clone();
        dirty[4] = 1; // non-zero padding in the address word
        assert_eq!(decode_erc20(&dirty), None);
    }
}
