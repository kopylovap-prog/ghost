//! # ghost-dex
//!
//! Uniswap (Ethereum) integration for Ghost.
//!
//! Layered pipeline:
//! 1. [`rlp`] / [`abi`] — minimal RLP + ABI encoders (no codegen).
//! 2. [`tx`] — legacy EIP-155 transaction signing with k256.
//! 3. [`uniswap`] — Uniswap V2 Router02 calldata: quotes, token/ETH swaps,
//!    ERC20 approve/transfer/balance, WETH wrapping.
//! 4. [`rpc`] — Ethereum JSON-RPC client (eth_call / gas / nonce /
//!    sendRawTransaction) over any [`rpc::Transport`].
//!
//! wGHOST flow (see `contracts/wGHOST.sol` in the repo):
//! 1. Lock native GHOST with the bridge (ghost-bridge).
//! 2. Bridge quorum attests; wGHOST is minted to your EVM address.
//! 3. `approve(wGHOST, Router)` then `swap_exact_tokens_for_tokens(...)`.
//! 4. To return: swap back to wGHOST, `burn` via the bridge, unlock native.

pub mod abi;
pub mod rlp;
pub mod rpc;
pub mod tx;
pub mod uniswap;
pub mod wghost;

pub use tx::{Address, TxParams};
