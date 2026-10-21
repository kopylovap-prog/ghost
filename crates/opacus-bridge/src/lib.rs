//! Ghost Bridge - Monero <-> Ghost atomic swaps

pub mod adaptor;
pub mod swap;

pub use adaptor::{AdaptorSignature, SwapSecret};
pub use swap::{SwapEngine, SwapId, SwapState};

pub const BRIDGE_PROTOCOL_VERSION: u32 = 1;
pub const MAX_RELAYER_FEE_BPS: u64 = 100;
pub mod xmr_dleq;
pub mod xmr_swap;
pub mod xmr_rpc;
pub mod swap_p2p;
