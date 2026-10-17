//! Minimal Ethereum ABI encoding for the subset Uniswap integration needs:
//! uint256, address, bool, dynamic address[] and function selectors.

use crate::rlp::u256_from_u128;
use tiny_keccak::{Hasher, Keccak};

pub const SELECTOR_LEN: usize = 4;

/// keccak256 of arbitrary bytes.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut k = Keccak::v256();
    k.update(data);
    k.finalize(&mut out);
    out
}

/// Function selector: first 4 bytes of keccak256("name(types...)").
pub fn selector(signature: &str) -> [u8; SELECTOR_LEN] {
    let h = keccak256(signature.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

/// One head-slot word (32 bytes, left-padded).
fn word(bytes: &[u8]) -> Vec<u8> {
    assert!(bytes.len() <= 32, "word overflow");
    let mut w = [0u8; 32];
    w[32 - bytes.len()..].copy_from_slice(bytes);
    w.to_vec()
}

/// An ABI argument (already encoded to its 32-byte head or a tail segment).
pub enum AbiArg {
    /// uint256 / int256 / bool / bytes32
    Word([u8; 32]),
    /// address (20 bytes, left-padded)
    Address([u8; 20]),
    /// dynamic address[] (encoded as offset + length + words)
    AddressArray(Vec<[u8; 20]>),
}

impl AbiArg {
    pub fn uint_u128(v: u128) -> Self {
        AbiArg::Word(u256_from_u128(v))
    }

    pub fn uint_u64(v: u64) -> Self {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&v.to_be_bytes());
        AbiArg::Word(w)
    }

    pub fn boolean(b: bool) -> Self {
        let mut w = [0u8; 32];
        if b {
            w[31] = 1;
        }
        AbiArg::Word(w)
    }
}

/// Encode a function call: selector + head/tail encoded arguments.
pub fn encode_call(sig: &str, args: &[AbiArg]) -> Vec<u8> {
    let mut out = selector(sig).to_vec();

    // static heads; dynamic args place an offset into their tail
    let static_heads: Vec<Vec<u8>> = args
        .iter()
        .map(|a| match a {
            AbiArg::Word(w) => word(w),
            AbiArg::Address(a) => word(a),
            AbiArg::AddressArray(_) => word(&[]), // placeholder, fixed below
        })
        .collect();

    let dynamic_count = args
        .iter()
        .filter(|a| matches!(a, AbiArg::AddressArray(_)))
        .count();
    if dynamic_count == 0 {
        for h in static_heads {
            out.extend_from_slice(&h);
        }
        return out;
    }

    // head size = one word per arg; tail starts after that
    let head_words = args.len();
    let mut tails: Vec<Vec<u8>> = Vec::new();
    let mut tail_size = 0usize;
    for a in args {
        if let AbiArg::AddressArray(items) = a {
            // length word + one word per address
            let sz = 32 * (1 + items.len());
            tails.push(encode_address_array(items));
            tail_size += sz;
        }
    }
    // assign offsets in argument order
    let mut offsets = Vec::with_capacity(args.len());
    let mut running = head_words * 32;
    let mut dyn_idx = 0usize;
    for a in args {
        if matches!(a, AbiArg::AddressArray(_)) {
            offsets.push(running);
            running += tails[dyn_idx].len();
            dyn_idx += 1;
        } else {
            offsets.push(0);
        }
    }

    let mut dyn_i = 0usize;
    for (i, a) in args.iter().enumerate() {
        match a {
            AbiArg::AddressArray(_) => {
                out.extend_from_slice(&word(&u128_to_be32(offsets[i])));
                out.extend_from_slice(&tails[dyn_i]);
                dyn_i += 1;
            }
            _ => out.extend_from_slice(&static_heads[i]),
        }
    }
    let _ = tail_size;
    out
}

fn u128_to_be32(v: usize) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&(v as u64).to_be_bytes());
    w
}

fn encode_address_array(items: &[[u8; 20]]) -> Vec<u8> {
    let mut out = word(&(items.len() as u128).to_be_bytes());
    for a in items {
        out.extend_from_slice(&word(a));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_selectors() {
        // Uniswap V2 Router02 selectors (well-known).
        assert_eq!(selector("getAmountsOut(uint256,address[])"), [0xd0, 0x6c, 0xa6, 0x1f]);
        assert_eq!(
            selector("swapExactTokensForTokens(uint256,uint256,address[],address,uint256)"),
            [0x38, 0xed, 0x17, 0x39]
        );
        assert_eq!(
            selector("swapExactETHForTokens(uint256,address[],address,uint256)"),
            [0x7f, 0xf3, 0x6a, 0xb5]
        );
        assert_eq!(
            selector("swapExactTokensForETH(uint256,uint256,address[],address,uint256)"),
            [0x18, 0xcb, 0xaf, 0xe5]
        );
        // ERC20
        assert_eq!(selector("approve(address,uint256)"), [0x09, 0x5e, 0xa7, 0xb3]);
        assert_eq!(selector("deposit()"), [0xd0, 0xe3, 0x0d, 0xb0]);
    }

    #[test]
    fn approve_encoding() {
        // approve(spender=0x1111..11, amount=1000)
        let mut spender = [0x11u8; 20];
        spender[19] = 0x11;
        let data = encode_call("approve(address,uint256)", &[
            AbiArg::Address(spender),
            AbiArg::uint_u128(1000),
        ]);
        assert_eq!(&data[0..4], &[0x09, 0x5e, 0xa7, 0xb3]);
        assert_eq!(data.len(), 4 + 64);
        // address word: 12 zero bytes then 20 address bytes
        assert_eq!(&data[4..16], &[0u8; 12]);
        assert_eq!(&data[16..36], &spender);
        // amount word: 1000 = 0x03E8 -> last two bytes
        assert_eq!(data[4 + 62], 0x03);
        assert_eq!(data[4 + 63], 0xe8);
    }

    #[test]
    fn address_array_offsets() {
        let a = [1u8; 20];
        let b = [2u8; 20];
        let data = encode_call("getAmountsOut(uint256,address[])", &[
            AbiArg::uint_u128(1234),
            AbiArg::AddressArray(vec![a, b]),
        ]);
        assert_eq!(&data[0..4], &[0xd0, 0x6c, 0xa6, 0x1f]);
        assert_eq!(data.len(), 4 + 64 + 32 * 3);
        // offset of array tail = 2 words = 64 (second head slot)
        assert_eq!(data[4 + 31], 0xd2); // uint 1234 = 0x04d2 last byte
        assert_eq!(data[4 + 63], 64); // offset word
        // length
        let tail = &data[4 + 64..];
        assert_eq!(tail[31], 2);
        // first address starts after 32 zero-padding bytes
        assert_eq!(&tail[32 + 12..32 + 32], &a);
        assert_eq!(&tail[64 + 12..64 + 32], &b);
    }
}
