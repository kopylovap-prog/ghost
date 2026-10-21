//! Uniswap V2 Router02 calldata builders (mainnet Router02:
//! 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D).

use crate::abi::{encode_call, AbiArg};
use crate::tx::Address;

pub const ROUTER_V2_MAINNET: Address = Address([
    0x7a, 0x25, 0x0d, 0x56, 0x30, 0xb4, 0xcf, 0x53, 0x97, 0x39, 0xdf, 0x2c, 0x5d, 0xac, 0xb4,
    0xc6, 0x59, 0xf2, 0x48, 0x8d,
]);

/// WETH9 on Ethereum mainnet.
pub const WETH_MAINNET: Address = Address([
    0xc0, 0x02, 0xaa, 0x39, 0xb2, 0x23, 0xfe, 0x8d, 0x0a, 0x0e, 0x5c, 0x4f, 0x27, 0xea, 0xd9,
    0x08, 0x3c, 0x75, 0x6c, 0xc2,
]);

/// A prepared call: target contract + calldata + optional ETH value.
#[derive(Clone, Debug)]
pub struct Call {
    pub to: Address,
    pub data: Vec<u8>,
    /// ETH value in wei (msg.value).
    pub value_wei: [u8; 32],
}

fn deadline_now_plus(seconds: u64) -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() + seconds)
        .unwrap_or(u64::MAX)
}

/// Off-chain quote: `getAmountsOut(amountIn, path)` (read-only eth_call).
pub fn get_amounts_out(amount_in: u128, path: &[Address]) -> Call {
    let data = encode_call(
        "getAmountsOut(uint256,address[])",
        &[
            AbiArg::uint_u128(amount_in),
            AbiArg::AddressArray(addrs(path)),
        ],
    );
    Call {
        to: ROUTER_V2_MAINNET,
        data,
        value_wei: [0u8; 32],
    }
}

/// Token -> token swap.
pub fn swap_exact_tokens_for_tokens(
    amount_in: u128,
    amount_out_min: u128,
    path: &[Address],
    to: Address,
    deadline_secs_from_now: u64,
) -> Call {
    let data = encode_call(
        "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
        &[
            AbiArg::uint_u128(amount_in),
            AbiArg::uint_u128(amount_out_min),
            AbiArg::AddressArray(addrs(path)),
            AbiArg::Address(to.0),
            AbiArg::uint_u64(deadline_now_plus(deadline_secs_from_now)),
        ],
    );
    Call {
        to: ROUTER_V2_MAINNET,
        data,
        value_wei: [0u8; 32],
    }
}

/// ETH (wrapped on the fly by sending value) -> token swap.
pub fn swap_exact_eth_for_tokens(
    amount_eth_wei: u128,
    amount_out_min: u128,
    path: &[Address],
    to: Address,
    deadline_secs_from_now: u64,
) -> Call {
    assert_eq!(path[0], WETH_MAINNET, "ETH swap path must start with WETH");
    let data = encode_call(
        "swapExactETHForTokens(uint256,address[],address,uint256)",
        &[
            AbiArg::uint_u128(amount_out_min),
            AbiArg::AddressArray(addrs(path)),
            AbiArg::Address(to.0),
            AbiArg::uint_u64(deadline_now_plus(deadline_secs_from_now)),
        ],
    );
    Call {
        to: ROUTER_V2_MAINNET,
        data,
        value_wei: crate::rlp::u256_from_u128(amount_eth_wei),
    }
}

/// Token -> ETH swap.
pub fn swap_exact_tokens_for_eth(
    amount_in: u128,
    amount_out_min: u128,
    path: &[Address],
    to: Address,
    deadline_secs_from_now: u64,
) -> Call {
    assert_eq!(
        path[path.len() - 1],
        WETH_MAINNET,
        "token->ETH swap path must end with WETH"
    );
    let data = encode_call(
        "swapExactTokensForETH(uint256,uint256,address[],address,uint256)",
        &[
            AbiArg::uint_u128(amount_in),
            AbiArg::uint_u128(amount_out_min),
            AbiArg::AddressArray(addrs(path)),
            AbiArg::Address(to.0),
            AbiArg::uint_u64(deadline_now_plus(deadline_secs_from_now)),
        ],
    );
    Call {
        to: ROUTER_V2_MAINNET,
        data,
        value_wei: [0u8; 32],
    }
}


/// Convert a swap path to raw 20-byte addresses.
fn addrs(path: &[Address]) -> Vec<[u8; 20]> {
    path.iter().map(|a| a.0).collect()
}

/// Wrap ETH into WETH (payable deposit()).
pub fn wrap_eth(amount_wei: u128) -> Call {
    Call {
        to: WETH_MAINNET,
        data: crate::abi::selector("deposit()").to_vec(),
        value_wei: crate::rlp::u256_from_u128(amount_wei),
    }
}

/// ERC20 approve calldata.
pub fn approve(token: Address, spender: Address, amount: u128) -> Call {
    Call {
        to: token,
        data: encode_call(
            "approve(address,uint256)",
            &[AbiArg::Address(spender.0), AbiArg::uint_u128(amount)],
        ),
        value_wei: [0u8; 32],
    }
}

/// ERC20 transfer calldata.
pub fn transfer(token: Address, recipient: Address, amount: u128) -> Call {
    Call {
        to: token,
        data: encode_call(
            "transfer(address,uint256)",
            &[AbiArg::Address(recipient.0), AbiArg::uint_u128(amount)],
        ),
        value_wei: [0u8; 32],
    }
}

/// ERC20 balanceOf calldata.
pub fn balance_of(token: Address, owner: Address) -> Call {
    Call {
        to: token,
        data: encode_call("balanceOf(address)", &[AbiArg::Address(owner.0)]),
        value_wei: [0u8; 32],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::selector;

    #[test]
    fn quote_call_shape() {
        let token = Address([1; 20]);
        let call = get_amounts_out(1_000_000, &[token, WETH_MAINNET]);
        assert_eq!(call.to, ROUTER_V2_MAINNET);
        assert_eq!(&call.data[0..4], &selector("getAmountsOut(uint256,address[])"));
        assert_eq!(call.value_wei, [0u8; 32]);
    }

    #[test]
    fn eth_swap_carries_value() {
        let call = swap_exact_eth_for_tokens(
            1_000_000_000_000_000_000,
            1,
            &[WETH_MAINNET, Address([9; 20])],
            Address([8; 20]),
            600,
        );
        // 1 ETH = 10^18 wei = 0xDE0B6B3A7640000 (last 8 bytes of the word).
        let expect_last8 = [0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00];
        assert_eq!(call.value_wei[24..32], expect_last8);
        assert_eq!(&call.value_wei[..24], &[0u8; 24]);
        assert_eq!(
            &call.data[0..4],
            &selector("swapExactETHForTokens(uint256,address[],address,uint256)")
        );
    }

    #[test]
    fn approve_router() {
        let call = approve(Address([7; 20]), ROUTER_V2_MAINNET, u128::MAX);
        assert_eq!(call.to, Address([7; 20]));
        assert_eq!(&call.data[0..4], &[0x09, 0x5e, 0xa7, 0xb3]);
        // amount = u128::MAX in the last 16 bytes of the amount word (data[36..68])
        assert_eq!(call.data[4 + 48..4 + 64], [0xff; 16]);
    }
}
