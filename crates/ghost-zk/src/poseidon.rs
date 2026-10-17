//! Poseidon-style cryptographic hash over the Pallas base field (`pasta_curves::Fp`).
//!
//! Design notes:
//! - State width `t = 3` (rate 2 + capacity 1), S-box `x^5`.
//! - Uniform schedule: all 64 rounds are *full* rounds (S-box applied to every
//!   state element). This costs more S-boxes than the paper's partial-round
//!   schedule but makes the in-circuit gadget perfectly uniform (one gate for
//!   every round row), which keeps the Halo2 circuit simple and auditable.
//! - Round constants and domain tags are derived deterministically from
//!   blake3 with a fixed protocol label, so scalar and circuit sides always
//!   agree without shipping magic numbers.
//! - `h_tree` is *commutative*: `H(a,b) = H(b,a)`, implemented as
//!   `P(D_tree, a+b, a*b)`. Merkle paths therefore need no direction bits.

use ff::Field;
use pasta_curves::Fp;
use std::sync::OnceLock;

/// State width (t = 3): two rate elements + one capacity element.
pub const T: usize = 3;
/// Total number of rounds (all of them full rounds).
pub const ROUNDS: usize = 64;
/// Number of elements absorbed per permutation (the rate).
pub const RATE: usize = 2;

/// MDS matrix: circulant(2, 1, 1) — provably MDS over Fp (all 2x2 minors
/// and the determinant are small nonzero integers, invertible mod p).
const MDS: [[u64; 3]; 3] = [[2, 1, 1], [1, 2, 1], [1, 1, 2]];

const PROTOCOL_LABEL: &[u8] = b"ghost-zk-poseidon-v1";

/// Domain-separation indices into [`domains`].
pub const DOMAIN_PK: usize = 0;
pub const DOMAIN_LEAF: usize = 1;
pub const DOMAIN_TREE: usize = 2;
pub const DOMAIN_NULLIFIER: usize = 3;

static ROUND_CONSTANTS: OnceLock<Vec<[Fp; T]>> = OnceLock::new();
static DOMAINS: OnceLock<[Fp; 4]> = OnceLock::new();

/// Deterministically map 16 bytes to an Fp element:
/// interpret as two little-endian u64 limbs and reduce via Horner with 2^64.
/// Every 128-bit integer is < p, so no rejection sampling is needed.
fn fp_from_16(b: &[u8]) -> Fp {
    debug_assert!(b.len() >= 16);
    let lo = u64::from_le_bytes(b[0..8].try_into().unwrap());
    let hi = u64::from_le_bytes(b[8..16].try_into().unwrap());
    // 2^64 mod p  (u64::MAX + 1)
    let two64 = Fp::from(u64::MAX) + Fp::ONE;
    Fp::from(hi) * two64 + Fp::from(lo)
}

/// Derive `n` field elements deterministically from a tag using blake3.
fn derive_field_elements(tag: &str, n: usize) -> Vec<Fp> {
    let mut out = Vec::with_capacity(n);
    let mut counter: u64 = 0;
    while out.len() < n {
        let mut h = blake3::Hasher::new();
        h.update(PROTOCOL_LABEL);
        h.update(tag.as_bytes());
        h.update(&counter.to_le_bytes());
        let d = h.finalize();
        let bytes = d.as_bytes();
        out.push(fp_from_16(&bytes[0..16]));
        if out.len() < n {
            out.push(fp_from_16(&bytes[16..32]));
        }
        counter += 1;
    }
    out
}

/// Poseidon round constants (ROUNDS x T), derived once and shared.
pub fn round_constants() -> &'static Vec<[Fp; T]> {
    ROUND_CONSTANTS.get_or_init(|| {
        let flat = derive_field_elements("rc", ROUNDS * T);
        flat.chunks_exact(T)
            .map(|c| [c[0], c[1], c[2]])
            .collect()
    })
}

/// Domain-separation constants for the protocol hashes.
pub fn domains() -> &'static [Fp; 4] {
    DOMAINS.get_or_init(|| {
        let v = derive_field_elements("domain", 4);
        [v[0], v[1], v[2], v[3]]
    })
}

#[inline]
fn sbox(x: Fp) -> Fp {
    // x^5 = (x^2)^2 * x
    let x2 = x.square();
    let x4 = x2.square();
    x4 * x
}

#[inline]
fn mds(p: [Fp; 3]) -> [Fp; 3] {
    let m = |v: u64| Fp::from(v);
    [
        m(MDS[0][0]) * p[0] + m(MDS[0][1]) * p[1] + m(MDS[0][2]) * p[2],
        m(MDS[1][0]) * p[0] + m(MDS[1][1]) * p[1] + m(MDS[1][2]) * p[2],
        m(MDS[2][0]) * p[0] + m(MDS[2][1]) * p[1] + m(MDS[2][2]) * p[2],
    ]
}

/// One Poseidon permutation with absorb fused into round 0, exactly matching
/// the circuit gadget in [`crate::circuit`]:
///
/// - initial state is `[0, 0, 0]`;
/// - in round 0, `abs0` and `abs1` are added to state elements 0 and 1, and
///   `domain` is added to the capacity element 2;
/// - rounds 1..ROUNDS absorb nothing;
/// - every round applies `x^5` to all three elements, then the MDS matrix.
///
/// Returns the final state; callers squeeze `state[0]`.
pub fn poseidon_absorb(domain: Fp, abs0: Fp, abs1: Fp) -> [Fp; 3] {
    let rcs = round_constants();
    let zero = Fp::ZERO;
    let mut s = [zero, zero, Fp::ZERO];
    for r in 0..ROUNDS {
        let (a0, a1, d2) = if r == 0 {
            (abs0, abs1, domain)
        } else {
            (Fp::ZERO, Fp::ZERO, Fp::ZERO)
        };
        let u0 = s[0] + a0 + rcs[r][0];
        let u1 = s[1] + a1 + rcs[r][1];
        let u2 = s[2] + d2 + rcs[r][2];
        s = mds([sbox(u0), sbox(u1), sbox(u2)]);
    }
    s
}

/// Spending-key commitment: `pk = P(D_pk, sk, sk)`.
pub fn h_pk(sk: Fp) -> Fp {
    poseidon_absorb(domains()[DOMAIN_PK], sk, sk)[0]
}

/// Note commitment (two absorb stages): `cm = P(D_leaf, value, P(D_leaf, pk, rho))`.
pub fn h_leaf(pk: Fp, rho: Fp, value: Fp) -> Fp {
    let t1 = poseidon_absorb(domains()[DOMAIN_LEAF], pk, rho)[0];
    poseidon_absorb(domains()[DOMAIN_LEAF], value, t1)[0]
}

/// Nullifier: `nf = P(D_null, pk, rho)` — unlinkable, bound to the note's key.
pub fn h_null(pk: Fp, rho: Fp) -> Fp {
    poseidon_absorb(domains()[DOMAIN_NULLIFIER], pk, rho)[0]
}

/// Commutative tree hash: `H(a,b) = P(D_tree, a+b, a*b) = H(b,a)`.
pub fn h_tree(a: Fp, b: Fp) -> Fp {
    poseidon_absorb(domains()[DOMAIN_TREE], a + b, a * b)[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_distinct() {
        let a = Fp::from(12345u64);
        let b = Fp::from(67890u64);

        // Deterministic.
        assert_eq!(poseidon_absorb(domains()[0], a, b), poseidon_absorb(domains()[0], a, b));

        // Distinct domains give distinct hashes.
        for d in 0..4 {
            for e in 0..4 {
                if d != e {
                    assert_ne!(
                        poseidon_absorb(domains()[d], a, b)[0],
                        poseidon_absorb(domains()[e], a, b)[0]
                    );
                }
            }
        }

        // Outputs are nonzero.
        for d in 0..4 {
            assert_ne!(poseidon_absorb(domains()[d], a, b)[0], Fp::ZERO);
        }
    }

    #[test]
    fn h_tree_is_commutative() {
        let a = Fp::from(7u64);
        let b = Fp::from(11u64);
        assert_eq!(h_tree(a, b), h_tree(b, a));
        assert_ne!(h_tree(a, b), h_tree(a, a));
    }

    #[test]
    fn round_constants_are_stable() {
        let rcs = round_constants();
        assert_eq!(rcs.len(), ROUNDS);
        // Re-derivation must be identical (OnceLock caches, force a second call).
        assert_eq!(rcs[0], round_constants()[0]);
        assert_ne!(rcs[0][0], Fp::ZERO);
    }
}
