//! RLP encoding (Ethereum yellow paper, appendix B). Encode-only by design:
//! the node builds transactions from structured fields and never parses RLP
//! from the network, which removes a parser from the attack surface.

use crate::util::U256;

#[derive(Debug, Clone)]
pub enum Item {
    Str(Vec<u8>),
    List(Vec<Item>),
}

impl Item {
    pub fn uint(v: &U256) -> Item {
        Item::Str(v.to_be_trimmed())
    }
    pub fn u64(v: u64) -> Item {
        Item::uint(&U256::from_u64(v))
    }
}

fn header(len: usize, short: u8, out: &mut Vec<u8>) {
    if len < 56 {
        out.push(short + len as u8);
    } else {
        let be = (len as u64).to_be_bytes();
        let first = be.iter().position(|&b| b != 0).unwrap_or(7);
        out.push(short + 55 + (8 - first) as u8);
        out.extend_from_slice(&be[first..]);
    }
}

pub fn encode(item: &Item) -> Vec<u8> {
    let mut out = Vec::new();
    match item {
        Item::Str(b) if b.len() == 1 && b[0] < 0x80 => out.push(b[0]),
        Item::Str(b) => {
            header(b.len(), 0x80, &mut out);
            out.extend_from_slice(b);
        }
        Item::List(items) => {
            let body: Vec<u8> = items.iter().flat_map(encode).collect();
            header(body.len(), 0xC0, &mut out);
            out.extend_from_slice(&body);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yellow_paper_examples() {
        assert_eq!(encode(&Item::Str(b"dog".to_vec())), hex::decode("83646f67").unwrap());
        assert_eq!(encode(&Item::List(vec![Item::Str(b"cat".to_vec()), Item::Str(b"dog".to_vec())])), hex::decode("c88363617483646f67").unwrap());
        assert_eq!(encode(&Item::Str(vec![])), vec![0x80]);
        assert_eq!(encode(&Item::List(vec![])), vec![0xc0]);
        assert_eq!(encode(&Item::u64(0)), vec![0x80]);
        assert_eq!(encode(&Item::u64(15)), vec![0x0f]);
        assert_eq!(encode(&Item::u64(1024)), hex::decode("820400").unwrap());
        let long = Item::Str(vec![b'a'; 56]);
        assert_eq!(&encode(&long)[..2], &[0xb8, 56]);
    }
}
