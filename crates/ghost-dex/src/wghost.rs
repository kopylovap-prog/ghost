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
pub fn wghost() -> Address {
    *WGHOST.get().unwrap_or(&Address([0u8; 20]))
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
}
