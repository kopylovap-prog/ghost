//! Transaction

use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct Transaction {
    pub version: u8,
    pub inputs: Vec<[u8; 32]>,
    pub outputs: Vec<TxOutput>,
    pub fee: u64,
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct TxOutput {
    pub commitment: [u8; 32],
    pub ephemeral_key: [u8; 32],
    pub encrypted_note: Vec<u8>,
}

impl Transaction {
    pub fn hash(&self) -> [u8; 32] {
        let serialized = borsh::to_vec(self).expect("serialize tx");
        blake3::hash(&serialized).into()
    }
}