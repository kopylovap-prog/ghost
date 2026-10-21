//! Compact state

use blake3;
use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct CompactState {
    pub height: u64,
    pub last_block_hash: [u8; 32],
    pub commitment_count: u64,
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct CompactBlock {
    pub height: u64,
    pub prev_hash: [u8; 32],
    pub output_commitments: Vec<CompactOutput>,
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct CompactOutput {
    pub note_commitment: [u8; 32],
    pub ephemeral_key: [u8; 32],
    pub encrypted_note: Vec<u8>,
    pub tree_position: u64,
}

impl CompactState {
    pub fn genesis() -> Self {
        Self { height: 0, last_block_hash: [0u8; 32], commitment_count: 0 }
    }

    pub fn apply_block(&mut self, block: &CompactBlock) -> Result<(), crate::LightClientError> {
        if self.height != 0 && block.prev_hash != self.last_block_hash {
            return Err(crate::LightClientError::OutOfSync);
        }
        self.commitment_count += block.output_commitments.len() as u64;
        self.height = block.height;
        let bytes = borsh::to_vec(block).unwrap_or_default();
        self.last_block_hash = blake3::hash(&bytes).into();
        Ok(())
    }
}