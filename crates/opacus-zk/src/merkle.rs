//! Fixed-depth Merkle tree over the commutative Poseidon tree hash.
//!
//! Because [`crate::poseidon::h_tree`] is commutative (`H(a,b) = H(b,a)`),
//! authentication paths carry only sibling values — no direction bits.
//!
//! Missing leaves are zero, so the empty subtree root at level `d` is
//! `Z_d = H(Z_{d-1}, Z_{d-1})` with `Z_0 = 0`. This lets us handle mainnet
//! depth (2^32 leaves) in time proportional to the number of *real* leaves —
//! we never materialize the padded tree.

use crate::poseidon::h_tree;
use ff::Field;
use pasta_curves::Fp;

/// Mainnet tree depth: 2^32 leaf slots.
pub const TREE_DEPTH: usize = 32;

/// Empty-subtree root at level `d`: `Z_0 = 0`, `Z_d = H(Z_{d-1}, Z_{d-1})`.
pub fn empty_root_at(depth: usize) -> Fp {
    let mut z = Fp::ZERO;
    for _ in 0..depth {
        z = h_tree(z, z);
    }
    z
}

/// Root of an empty tree of `2^depth` leaves.
pub fn empty_root(depth: usize) -> Fp {
    empty_root_at(depth)
}

/// Collapse the `n` real nodes of the current level one step, pairing the
/// trailing odd node with the empty-subtree root `Z_d` when needed.
fn collapse(level: &[Fp], n: usize, z: Fp) -> Vec<Fp> {
    let mut next = Vec::with_capacity(n.div_ceil(2));
    let mut i = 0;
    while i < n {
        let left = level[i];
        let right = if i + 1 < n { level[i + 1] } else { z };
        next.push(h_tree(left, right));
        i += 2;
    }
    next
}

/// Root of a tree of `2^depth` leaf slots where missing leaves are zero.
/// Cost is O(leaves.len() + depth), never O(2^depth).
pub fn build_root(leaves: &[Fp], depth: usize) -> Fp {
    assert!(leaves.len() <= 1usize << depth, "too many leaves for depth");
    let mut level: Vec<Fp> = leaves.to_vec();
    let mut n = level.len();
    for d in 0..depth {
        let z = empty_root_at(d);
        level = collapse(&level, n, z);
        n = level.len();
    }
    if level.is_empty() {
        empty_root_at(depth)
    } else {
        level[0]
    }
}

/// Authentication path (one sibling per level, bottom-up) for `leaves[index]`.
/// Siblings beyond the real frontier are empty-subtree roots `Z_d`.
pub fn auth_path(leaves: &[Fp], index: usize, depth: usize) -> Vec<Fp> {
    assert!(index < leaves.len(), "index out of range");
    assert!(leaves.len() <= 1usize << depth, "too many leaves for depth");
    let mut level: Vec<Fp> = leaves.to_vec();
    let mut n = level.len();
    let mut idx = index;
    let mut path = Vec::with_capacity(depth);
    for d in 0..depth {
        let sib = idx ^ 1;
        path.push(if sib < n {
            level[sib]
        } else {
            empty_root_at(d)
        });
        idx >>= 1;
        level = collapse(&level, n, empty_root_at(d));
        n = level.len();
    }
    path
}

/// Recompute the root from a leaf and its authentication path.
pub fn recompute_root(leaf: Fp, path: &[Fp]) -> Fp {
    let mut node = leaf;
    for &sib in path {
        node = h_tree(node, sib);
    }
    node
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use rand::rngs::OsRng;

    fn random_leaves(n: usize) -> Vec<Fp> {
        (0..n).map(|_| Fp::random(OsRng)).collect()
    }

    #[test]
    fn path_roundtrip_all_indices() {
        for depth in [1usize, 3, 5] {
            let leaves = random_leaves(1usize << (depth - 1)); // half-full tree
            let root = build_root(&leaves, depth);
            for (i, leaf) in leaves.iter().enumerate() {
                let path = auth_path(&leaves, i, depth);
                assert_eq!(path.len(), depth);
                assert_eq!(recompute_root(*leaf, &path), root, "leaf {i}");
            }
        }
    }

    #[test]
    fn empty_root_matches_build_root() {
        for depth in [1usize, 4, 8] {
            assert_eq!(build_root(&[], depth), empty_root(depth));
        }
    }

    #[test]
    fn mainnet_depth_is_cheap() {
        // Must not materialize 2^32 leaves: sparse frontier only.
        let leaves = random_leaves(3);
        let root = build_root(&leaves, TREE_DEPTH);
        let path = auth_path(&leaves, 2, TREE_DEPTH);
        assert_eq!(path.len(), TREE_DEPTH);
        assert_eq!(recompute_root(leaves[2], &path), root);
    }
}
