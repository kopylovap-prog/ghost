//! Node daemon

use std::path::PathBuf;

use ghost_consensus::v4::{accept_transaction, ConsensusParams, ConsensusState};

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("Initialization failed: {0}")]
    InitFailed(String),
    #[error("Transaction rejected by consensus: {0}")]
    TxRejected(String),
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
    consensus: ConsensusState,
    params: ConsensusParams,
}

impl GhostDaemon {
    pub fn new(config: DaemonConfig) -> Result<Self, DaemonError> {
        std::fs::create_dir_all(&config.data_dir)
            .map_err(|e| DaemonError::InitFailed(e.to_string()))?;
        tracing::info!("Ghost daemon initialized at {:?}", config.data_dir);
        Ok(Self {
            config,
            height: 0,
            consensus: ConsensusState::mainnet(),
            params: ConsensusParams::testnet(),
        })
    }

    /// Submit a raw transaction payload to the node's consensus gate.
    ///
    /// Phase 4 [S4 9, S4 9 activation]: the payload runs through the
    /// normative v4 validation order and the activation height gate; on
    /// success the daemon's frontier and seen-set are updated, on failure
    /// the state is untouched and the reason is reported. The full v0.4
    /// wire acceptance path lives in `ghost-consensus::v4`; the daemon is
    /// the node-facing wrapper.
    pub fn submit_transaction(
        &mut self,
        height: u64,
        raw: &[u8],
    ) -> Result<(), DaemonError> {
        accept_transaction::<32>(&self.params, height, raw, &mut self.consensus)
            .map_err(|e| DaemonError::TxRejected(e.to_string()))?;
        tracing::info!("tx accepted at height {height}");
        Ok(())
    }

    /// Read-only view of the node's shielded-pool state (frontier root,
    /// leaf and seen-set counters).
    pub fn consensus(&self) -> &ConsensusState {
        &self.consensus
    }

    pub fn params(&self) -> &ConsensusParams {
        &self.params
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

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_daemon() -> GhostDaemon {
        let dir = std::env::temp_dir().join(format!(
            "ghost-daemon-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        GhostDaemon::new(DaemonConfig {
            data_dir: dir,
            ..DaemonConfig::default()
        })
        .expect("daemon init")
    }

    #[test]
    fn submit_rejects_non_v4_after_activation() {
        // Testnet params: activation height 0, so every height is at-or-
        // after activation and only version-4 wire is accepted [S4 9
        // activation].
        let mut d = tmp_daemon();
        let err = d
            .submit_transaction(7, &[3, 1, 0, 0, 1, 2, 3])
            .expect_err("v3-style payload must be rejected after activation");
        assert!(err.to_string().contains("only version 4"), "{err}");
        assert!(matches!(err, DaemonError::TxRejected(_)));
    }

    #[test]
    fn submit_rejects_garbage_and_keeps_state_clean() {
        let mut d = tmp_daemon();
        let before = d.consensus().leaf_count();
        let err = d
            .submit_transaction(0, b"not a transaction at all")
            .expect_err("garbage must be rejected");
        assert!(matches!(err, DaemonError::TxRejected(_)));
        assert_eq!(d.consensus().leaf_count(), before, "state untouched");
        assert_eq!(d.consensus().seen_count(), 0);
    }

    #[test]
    fn daemon_state_starts_fresh_mainnet_shape() {
        let d = tmp_daemon();
        assert_eq!(d.consensus().leaf_count(), 0);
        assert_eq!(d.consensus().seen_count(), 0);
        assert_eq!(d.params().fee_floor, 0);
        assert_eq!(d.params().v4_activation_height, 0);
    }
}
