//! Node daemon

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("Initialization failed: {0}")]
    InitFailed(String),
}

#[derive(Clone, Debug)]
pub struct DaemonConfig {
    pub p2p_port: u16,
    pub rpc_port: u16,
    pub data_dir: PathBuf,
    pub network: String,
    pub use_tor: bool,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            p2p_port: 18080,
            rpc_port: 18081,
            data_dir: dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".ghost"),
            network: "mainnet".to_string(),
            use_tor: false,
        }
    }
}

pub struct GhostDaemon {
    config: DaemonConfig,
    height: u64,
}

impl GhostDaemon {
    pub fn new(config: DaemonConfig) -> Result<Self, DaemonError> {
        std::fs::create_dir_all(&config.data_dir)
            .map_err(|e| DaemonError::InitFailed(e.to_string()))?;
        tracing::info!("Ghost daemon initialized at {:?}", config.data_dir);
        Ok(Self { config, height: 0 })
    }

    pub async fn run(&mut self) -> Result<(), DaemonError> {
        tracing::info!(
            "Ghost node running | P2P: {} | RPC: {} | net: {}",
            self.config.p2p_port, self.config.rpc_port, self.config.network
        );
        tracing::info!("Press Ctrl+C to stop");
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            self.height += 1;
            tracing::debug!("heartbeat, height={}", self.height);
        }
    }

    pub fn height(&self) -> u64 { self.height }
}