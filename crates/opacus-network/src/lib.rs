//! Opacus Network Layer
pub mod p2p;

pub use p2p::{NetworkConfig, PeerInfo};
pub mod handshake;
pub mod identity;
pub mod swap_node;
