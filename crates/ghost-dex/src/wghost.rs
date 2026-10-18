//! wGHOST helpers: the ERC20 side of the Ghost bridge on Ethereum.
//!
//! The token contract lives in `contracts/wGHOST.sol`. Until it is deployed,
//! set the address with [`set_wghost`] at startup (or persist it in config).

use crate::abi::{encode_call, AbiArg};
use crate::tx::Address;
use std::sync::OnceLock;

static WGHOST: OnceLock<Address> = OnceLock::new();

/// Configure the deployed wGHOST address (call once at startup).
pub fn set_wghost(addr: Address) -> bool {
    WGHOST.set(addr).is_ok()
}

/// Current wGHOST address or the zero address placeholder.
///
/// Resolution order:
/// 1. an address already set via [`set_wghost`]
/// 2. the `WGHOST_ADDRESS` environment variable (0x-prefixed 20-byte hex);
///    a successfully parsed value is cached into the same slot, as if
///    [`set_wghost`] had been called
/// 3. the zero address placeholder
pub fn wghost() -> Address {
    if let Some(addr) = WGHOST.get() {
        return *addr;
    }
    if let Ok(raw) = std::env::var("WGHOST_ADDRESS") {
        if let Some(addr) = parse_address(&raw) {
            let _ = WGHOST.set(addr);
            return addr;
        }
    }
    Address([0u8; 20])
}

/// Parse a 0x-prefixed (or bare) 20-byte hex EVM address.
pub fn parse_address(raw: &str) -> Option<Address> {
    let s = raw.trim();
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 20 {
        return None;
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Some(Address(out))
}

/// burn(amount): destroy wGHOST to trigger native GHOST release on the
/// Ghost side (bridge contract watches Burn events).
pub fn burn(amount: u128) -> crate::uniswap::Call {
    crate::uniswap::Call {
        to: wghost(),
        data: encode_call("burn(uint256)", &[AbiArg::uint_u128(amount)]),
        value_wei: [0u8; 32],
    }
}

/// Burn event topic (keccak256("Burn(address,uint256)")) for bridge
/// relayer indexing.
pub fn burn_event_topic() -> [u8; 32] {
    crate::abi::keccak256(b"Burn(address,uint256)")
}

/// Mint event topic.
pub fn mint_event_topic() -> [u8; 32] {
    crate::abi::keccak256(b"Mint(address,uint256)")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::selector;

    #[test]
    fn burn_calldata_and_topics() {
        set_wghost(Address([0xab; 20]));
        let call = burn(1_000);
        assert_eq!(call.to, Address([0xab; 20]));
        assert_eq!(&call.data[0..4], &selector("burn(uint256)"));
        // 1000 = 0x03E8
        assert_eq!(call.data[4 + 30], 0x03);
        assert_eq!(call.data[4 + 31], 0xe8);
        // keccak("Burn(address,uint256)") — stable topic; just assert shape.
        let topic = burn_event_topic();
        assert_ne!(topic, [0u8; 32]);
        assert_ne!(burn_event_topic(), mint_event_topic());
    }

    #[test]
    fn parse_address_shapes() {
        let ok = "0x1111111111111111111111111111111111111111";
        let a = parse_address(ok).expect("valid");
        assert_eq!(a.0[0], 0x11);
        assert_eq!(a.0[19], 0x11);
        assert_eq!(parse_address(&ok.to_uppercase()).expect("valid").0[0], 0x11);
        assert_eq!(parse_address(&ok[2..]).expect("bare").0[5], 0x11);
        assert!(parse_address("0x1234").is_none());
        assert!(parse_address("0xzz11111111111111111111111111111111111111").is_none());
        assert!(parse_address("").is_none());
        assert!(parse_address("0x11111111111111111111111111111111111111").is_none());
    }
}
