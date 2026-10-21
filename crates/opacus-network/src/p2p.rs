//! P2P config (full libp2p stack in v0.3)

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub listen_port: u16,
    pub use_tor: bool,
    pub max_peers: usize,
    pub bootstrap_nodes: Vec<String>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_port: 18080,
            use_tor: false,
            max_peers: 50,
            bootstrap_nodes: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub peer_id: String,
    pub addr: String,
    pub last_seen: u64,
}