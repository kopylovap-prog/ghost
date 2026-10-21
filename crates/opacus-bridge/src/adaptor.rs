//! Adaptor Signatures

use rand::{CryptoRng, RngCore};
use sha3::{Digest, Sha3_256};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, thiserror::Error)]
pub enum AdaptorError {
    #[error("Invalid adaptor signature")]
    InvalidSignature,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SwapSecret {
    pub t: [u8; 32],
}

impl SwapSecret {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut t = [0u8; 32];
        rng.fill_bytes(&mut t);
        Self { t }
    }

    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(self.t);
        hasher.finalize().into()
    }
}

#[derive(Clone, Debug)]
pub struct AdaptorSignature {
    pub r_point: [u8; 32],
    pub s_adaptor: [u8; 32],
    pub t_point: [u8; 32],
}

impl AdaptorSignature {
    /// Full Ed25519 adaptor sig implementation - v0.3
    pub fn verify_placeholder(&self) -> bool {
        !self.s_adaptor.iter().all(|&b| b == 0)
    }
}
