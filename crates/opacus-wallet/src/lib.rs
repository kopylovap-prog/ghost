//! Ghost Wallet
pub mod light_wallet;

pub use light_wallet::{Balance, LightWallet, UnspentNote, WalletError};

pub mod zk_spend;
pub mod tx_v4;
