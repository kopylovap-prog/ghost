//! Ghost Consensus Layer
pub mod block;
pub mod transaction;

pub use block::{block_reward, Block, BlockHeader};
pub use transaction::{Transaction, TxOutput};

pub const BLOCK_TIME_SECONDS: u64 = 120;
pub const MAX_BLOCK_SIZE: u64 = 2 * 1024 * 1024;