//! Real IPA prover/verifier over the Vesta curve (scalar field = Pallas base
//! field `Fp`), feature-gated behind `real-prover`.
//!
//! Key generation, proving and verification all run locally with no trusted
//! setup (IPA + Blake2b Fiat-Shamir).

use crate::circuit::{FcmpCircuit, FcmpWitness};
use halo2_proofs::{
    circuit::Value,
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use pasta_curves::{vesta, Fp};
use rand::rngs::OsRng;

/// A complete, verifiable spend proof: proof bytes plus the two public inputs.
#[derive(Clone, Debug)]
pub struct FcmpProof {
    pub proof: Vec<u8>,
    pub root: Fp,
    pub nullifier: Fp,
}

/// Generate parameters, proving key, and the proof itself.
pub fn prove<const DEPTH: usize>(
    k: u32,
    witness: &FcmpWitness,
    root: Fp,
    nullifier: Fp,
) -> Result<FcmpProof, halo2_proofs::plonk::Error> {
    let circuit: FcmpCircuit<DEPTH> = FcmpCircuit {
        witness: Value::known(witness.clone()),
    };

    let params = Params::<vesta::Affine>::new(k);
    let vk = keygen_vk(&params, &circuit)?;
    let pk = keygen_pk(&params, vk, &circuit)?;

    let mut transcript = Blake2bWrite::<_, vesta::Affine, Challenge255<_>>::init(Vec::new());
    create_proof::<
        vesta::Affine,
        Challenge255<vesta::Affine>,
        OsRng,
        Blake2bWrite<Vec<u8>, vesta::Affine, Challenge255<vesta::Affine>>,
        _,
    >(
        &params,
        &pk,
        std::slice::from_ref(&circuit),
        &[&[&[root], &[nullifier]]],
        OsRng,
        &mut transcript,
    )?;

    Ok(FcmpProof {
        proof: transcript.finalize(),
        root,
        nullifier,
    })
}

/// Verify a proof against its public inputs.
pub fn verify<const DEPTH: usize>(
    k: u32,
    p: &FcmpProof,
) -> Result<(), halo2_proofs::plonk::Error> {
    let circuit: FcmpCircuit<DEPTH> = FcmpCircuit {
        witness: Value::unknown(),
    };

    let params = Params::<vesta::Affine>::new(k);
    let vk = keygen_vk(&params, &circuit)?;

    let mut transcript = Blake2bRead::<_, vesta::Affine, Challenge255<_>>::init(&p.proof[..]);
    let strategy = SingleVerifier::new(&params);
    verify_proof::<vesta::Affine, Challenge255<vesta::Affine>, _, _>(
        &params,
        &vk,
        strategy,
        &[&[&[p.root], &[p.nullifier]]],
        &mut transcript,
    )?;
    Ok(())
}

#[cfg(all(test, feature = "real-prover"))]
mod tests {
    use super::*;
    use crate::{merkle, Note};
    use ff::Field;

    #[test]
    fn prove_and_verify_depth4() {
        const DEPTH: usize = 4;
        let notes: Vec<Note> = (0..5)
            .map(|i| Note::new(Fp::random(OsRng), Fp::random(OsRng), 100 + i as u64))
            .collect();
        let leaves: Vec<Fp> = notes.iter().map(|n| n.commitment()).collect();
        let root = merkle::build_root(&leaves, DEPTH);
        let path = merkle::auth_path(&leaves, 1, DEPTH);
        let witness = FcmpWitness {
            sk: notes[1].sk,
            rho: notes[1].rho,
            value: notes[1].value,
            path,
        };
        let nf = notes[1].nullifier();

        let proof = prove::<DEPTH>(10, &witness, root, nf).unwrap();
        verify::<DEPTH>(10, &proof).unwrap();

        // Tampered public root must not verify.
        let mut bad = proof.clone();
        bad.root = bad.root + Fp::ONE;
        assert!(verify::<DEPTH>(10, &bad).is_err());
    }
}
