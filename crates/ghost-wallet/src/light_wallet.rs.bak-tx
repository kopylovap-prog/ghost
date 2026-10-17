//! Light Wallet

use ghost_crypto::keys::SpendingKey;
use ghost_crypto::stealth::{PublicAddress, RecipientKeys};
use std::collections::HashMap;

#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("Insufficient funds: need {needed}, have {available}")]
    InsufficientFunds { needed: u64, available: u64 },
    #[error("Not synced")]
    NotSynced,
}

#[derive(Clone, Debug, Default)]
pub struct Balance {
    pub total: u64,
    pub spendable: u64,
    pub pending: u64,
}

#[derive(Clone, Debug)]
pub struct UnspentNote {
    pub commitment: [u8; 32],
    pub amount: u64,
    pub onetime_privkey: [u8; 32],
    pub tree_position: u64,
}

pub struct LightWallet {
    keys: RecipientKeys,
    address: String,
    unspent_notes: HashMap<[u8; 32], UnspentNote>,
    balance: Balance,
}

impl LightWallet {
    pub fn new(spending_key: &SpendingKey) -> Self {
        let keys = RecipientKeys {
            view_key: spending_key.view_key,
            spend_key: spending_key.spend_key,
        };
        let address = PublicAddress::from_keys(&keys).to_string();
        Self { keys, address, unspent_notes: HashMap::new(), balance: Balance::default() }
    }

    pub fn get_address(&self) -> &str { &self.address }
    pub fn get_balance(&self) -> &Balance { &self.balance }

    pub fn add_note(&mut self, note: UnspentNote) {
        self.balance.total += note.amount;
        self.balance.spendable += note.amount;
        self.unspent_notes.insert(note.commitment, note);
    }
}