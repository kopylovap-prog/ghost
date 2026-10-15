//! Block

use borsh::{BorshDeserialize, BorshSerialize};
use crate::transaction::Transaction;

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct BlockHeader {
    pub version: u8,
    pub prev_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub timestamp: u64,
    pub difficulty: u64,
    pub nonce: u64,
    pub height: u64,
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Block {
    pub fn hash(&self) -> [u8; 32] {
        let serialized = borsh::to_vec(&self.header).expect("serialize header");
        blake3::hash(&serialized).into()
    }
}

pub fn block_reward(height: u64) -> u64 {
    const INITIAL_REWARD: u64 = 10_000_000_000;
    const HALVING_INTERVAL: u64 = 210_000;
    let halvings = height / HALVING_INTERVAL;
    INITIAL_REWARD >> halvings.min(60)
}