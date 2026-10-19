//! # ghost-zk
//!
//! Halo2-based FCMP-style zero-knowledge membership proofs for Ghost.
//!
//! One proof (`FcmpCircuit`) simultaneously demonstrates:
//! - **ownership**: the spender knows the note's spending key;
//! - **membership**: the note commitment is a leaf of the (2^DEPTH) Merkle tree;
//! - **spending**: the public nullifier is the unique nullifier of that note.
//!
//! Building blocks live in [`poseidon`] (hash), [`merkle`] (tree) and
//! [`circuit`] (proof). With the `real-prover` feature, [`prover`] wraps the
//! full IPA-based prover/verifier over the Pallas/Vesta cycle.

pub mod circuit;
pub mod merkle;
pub mod poseidon;
pub mod v4;
pub mod fixed_base;
pub mod spend;
#[cfg(feature = "real-prover")]
pub mod prover;

/// Everything a wallet (or any downstream crate) typically needs from
/// ghost-zk, in one import: `use ghost_zk::prelude::*;`
pub mod prelude {
    pub use crate::circuit::FcmpWitness;
    pub use crate::{merkle, Note, TREE_DEPTH_MAINNET};
    pub use ff::{Field, PrimeField};
    pub use pasta_curves::Fp;
    pub use rand::rngs::OsRng;
    #[cfg(feature = "real-prover")]
    pub use crate::prover::{prove, verify, FcmpProof};
}

use pasta_curves::Fp;
use thiserror::Error;

/// Mainnet tree depth: 2^32 leaves (anonymity set of about 4.3 billion).
pub const TREE_DEPTH_MAINNET: usize = 32;

#[derive(Debug, Error)]
pub enum ZkError {
    #[error("authentication path length mismatch: expected {expected}, got {got}")]
    PathLength { expected: usize, got: usize },
    #[error("proof verification failed")]
    VerificationFailed,
    #[error("halo2 error: {0}")]
    Halo2(#[from] halo2_proofs::plonk::Error),
}

/// A spendable shielded note.
#[derive(Clone, Debug)]
pub struct Note {
    /// Spending key.
    pub sk: Fp,
    /// Note nonce.
    pub rho: Fp,
    /// Amount in atoms.
    pub value: u64,
}

impl Note {
    pub fn new(sk: Fp, rho: Fp, value: u64) -> Self {
        Self { sk, rho, value }
    }

    /// Public key commitment derived from the spending key.
    pub fn spending_key_pub(&self) -> Fp {
        poseidon::h_pk(self.sk)
    }

    /// Note commitment — this is what leaves the tree.
    pub fn commitment(&self) -> Fp {
        poseidon::h_leaf(self.spending_key_pub(), self.rho, Fp::from(self.value))
    }

    /// Nullifier — published when the note is spent.
    pub fn nullifier(&self) -> Fp {
        poseidon::h_null(self.spending_key_pub(), self.rho)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use rand::rngs::OsRng;

    #[test]
    fn note_hashes_are_consistent() {
        let n = Note::new(Fp::random(OsRng), Fp::random(OsRng), 42);
        assert_eq!(n.commitment(), n.commitment());
        assert_eq!(n.nullifier(), n.nullifier());
        assert_ne!(n.commitment(), n.nullifier());
        assert_ne!(n.commitment(), n.spending_key_pub());

        // Different notes never share commitments or nullifiers.
        let m = Note::new(n.sk, n.rho, n.value + 1);
        assert_ne!(n.commitment(), m.commitment());
        // Nullifier must not depend on the value.
        assert_eq!(n.nullifier(), m.nullifier());
    }
}
