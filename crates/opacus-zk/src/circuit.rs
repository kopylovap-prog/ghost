//! FCMP-style Halo2 circuit: one proof binds note ownership, tree membership
//! and the nullifier at the same time.
//!
//! Layout: the whole proof lives in a single region. Each Poseidon
//! permutation occupies `ROUNDS + 1` rows (one row per round + a final row):
//!
//! ```text
//! row 0     : state [0,0,0] (constrained by s_init), absorb inputs in0/in1,
//!             fixed domain D (capacity), fixed absorb flag = 1
//! rows 1..63: state after each round, absorb inputs forced to 0 via the
//!             fixed absorb flag and the masking constraints
//! row 64    : final state; element 0 is the squeezed output
//! ```
//!
//! Witness flow (all hashes are [`crate::poseidon`] hashes):
//! 1. `pk  = H_pk(sk, sk)`
//! 2. `t1  = H_leaf(pk, rho)`          (stage 1 of the note commitment)
//! 3. `cm  = H_leaf(value, t1)`        (stage 2 — the tree leaf)
//! 4. `nf  = H_null(pk, rho)`          (exposed as a public instance)
//! 5. DEPTH tree steps: `node = H_tree(node + sib, node * sib)` starting from
//!    `cm`; the final node is exposed as the public root.
//!
//! Security note: `value` is bound only through the note commitment. A full
//! FCMP++ design (value accumulator + EC chips) lands in v0.4.

use crate::poseidon::{self, ROUNDS};
use ff::Field;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector,
    },
    poly::Rotation,
};
use pasta_curves::Fp;

/// Rows consumed by one permutation (64 round rows + 1 final row).
pub const ROWS_PER_PERM: usize = ROUNDS + 1;

#[derive(Clone, Debug)]
pub struct FcmpConfig {
    /// Poseidon state columns [s0, s1, s2].
    pub state: [Column<Advice>; 3],
    /// Absorb input columns [in0, in1].
    pub absorb: [Column<Advice>; 2],
    /// Scratch operand columns for the tree add/mul gates [a, b].
    pub src: [Column<Advice>; 2],
    /// Round-constant columns.
    pub rc: [Column<Fixed>; 3],
    /// Capacity domain constant (D at round 0, 0 elsewhere).
    pub domain: Column<Fixed>,
    /// Absorb flag (1 at round 0, 0 elsewhere) used to mask the inputs.
    pub is_absorb: Column<Fixed>,
    /// Poseidon round gate.
    pub s_round: Selector,
    /// Initial-state-is-zero gate.
    pub s_init: Selector,
    /// `in0 = src0 + src1` gate (tree step).
    pub s_add: Selector,
    /// `in1 = src0 * src1` gate (tree step).
    pub s_mul: Selector,
    /// Public root.
    pub instance_root: Column<Instance>,
    /// Public nullifier.
    pub instance_nf: Column<Instance>,
}

impl FcmpConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        let state = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let absorb = [meta.advice_column(), meta.advice_column()];
        let src = [meta.advice_column(), meta.advice_column()];
        let rc = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        let domain = meta.fixed_column();
        let is_absorb = meta.fixed_column();
        let s_round = meta.selector();
        let s_init = meta.selector();
        let s_add = meta.selector();
        let s_mul = meta.selector();
        let instance_root = meta.instance_column();
        let instance_nf = meta.instance_column();

        for c in state.iter().chain(absorb.iter()).chain(src.iter()) {
            meta.enable_equality(*c);
        }
        meta.enable_equality(instance_root);
        meta.enable_equality(instance_nf);

        // Poseidon round transition with fused absorb + input masking.
        meta.create_gate("poseidon-round", |meta| {
            let sel = meta.query_selector(s_round);
            let s0 = meta.query_advice(state[0], Rotation::cur());
            let s1 = meta.query_advice(state[1], Rotation::cur());
            let s2 = meta.query_advice(state[2], Rotation::cur());
            let in0 = meta.query_advice(absorb[0], Rotation::cur());
            let in1 = meta.query_advice(absorb[1], Rotation::cur());
            let rc0 = meta.query_fixed(rc[0]);
            let rc1 = meta.query_fixed(rc[1]);
            let rc2 = meta.query_fixed(rc[2]);
            let dom = meta.query_fixed(domain);
            let flag = meta.query_fixed(is_absorb);
            let n0 = meta.query_advice(state[0], Rotation::next());
            let n1 = meta.query_advice(state[1], Rotation::next());
            let n2 = meta.query_advice(state[2], Rotation::next());

            let u0 = s0 + in0.clone() + rc0;
            let u1 = s1 + in1.clone() + rc1;
            let u2 = s2 + dom + rc2;

            let fiv = |x: Expression<Fp>| {
                let a = x.clone();
                let b = a.clone() * a;
                b.clone() * b * x // x^5
            };
            let p0 = fiv(u0);
            let p1 = fiv(u1);
            let p2 = fiv(u2);

            let m = |v: u64| Expression::Constant(Fp::from(v));
            let o0 = m(2) * p0.clone() + m(1) * p1.clone() + m(1) * p2.clone();
            let o1 = m(1) * p0.clone() + m(2) * p1.clone() + m(1) * p2.clone();
            let o2 = m(1) * p0 + m(1) * p1 + m(2) * p2;

            let one = Expression::Constant(Fp::ONE);
            let mask0 = in0 * (one.clone() - flag.clone());
            let mask1 = in1 * (one - flag);

            vec![
                sel.clone() * (n0 - o0),
                sel.clone() * (n1 - o1),
                sel.clone() * (n2 - o2),
                sel.clone() * mask0,
                sel * mask1,
            ]
        });

        // Initial state must be zero; the domain enters through the fixed
        // `domain` column, which the prover cannot change.
        meta.create_gate("init-zero", |meta| {
            let sel = meta.query_selector(s_init);
            let s0 = meta.query_advice(state[0], Rotation::cur());
            let s1 = meta.query_advice(state[1], Rotation::cur());
            let s2 = meta.query_advice(state[2], Rotation::cur());
            let zero = Expression::Constant(Fp::ZERO);
            vec![
                sel.clone() * (s0 - zero.clone()),
                sel.clone() * (s1 - zero.clone()),
                sel * (s2 - zero),
            ]
        });

        // Tree step linear operand: in0 = src0 + src1.
        meta.create_gate("tree-add", |meta| {
            let sel = meta.query_selector(s_add);
            let a = meta.query_advice(src[0], Rotation::cur());
            let b = meta.query_advice(src[1], Rotation::cur());
            let z = meta.query_advice(absorb[0], Rotation::cur());
            vec![sel * (z - a - b)]
        });

        // Tree step quadratic operand: in1 = src0 * src1.
        meta.create_gate("tree-mul", |meta| {
            let sel = meta.query_selector(s_mul);
            let a = meta.query_advice(src[0], Rotation::cur());
            let b = meta.query_advice(src[1], Rotation::cur());
            let z = meta.query_advice(absorb[1], Rotation::cur());
            vec![sel * (z - a * b)]
        });

        Self {
            state,
            absorb,
            src,
            rc,
            domain,
            is_absorb,
            s_round,
            s_init,
            s_add,
            s_mul,
            instance_root,
            instance_nf,
        }
    }
}

/// Assign the state rows for one permutation starting at `base`, simulate the
/// honest run in `Value` space, and return the squeezed output cell + value.
fn state_rows(
    region: &mut Region<'_, Fp>,
    config: &FcmpConfig,
    base: usize,
    domain: Fp,
    in0v: Value<Fp>,
    in1v: Value<Fp>,
) -> Result<(AssignedCell<Fp, Fp>, Value<Fp>), Error> {
    let rcs = poseidon::round_constants();
    let zero = || Value::known(Fp::ZERO);
    let mut s = [zero(), zero(), zero()];
    let mut out_cell: Option<AssignedCell<Fp, Fp>> = None;

    for r in 0..ROUNDS {
        for k in 0..3 {
            region.assign_advice(
                || format!("state{}-r{}", k, r),
                config.state[k],
                base + r,
                || s[k],
            )?;
        }
        let iv0 = if r == 0 { in0v } else { zero() };
        let iv1 = if r == 0 { in1v } else { zero() };
        region.assign_advice(|| "in0", config.absorb[0], base + r, || iv0)?;
        region.assign_advice(|| "in1", config.absorb[1], base + r, || iv1)?;

        region.assign_fixed(|| "rc0", config.rc[0], base + r, || Value::known(rcs[r][0]))?;
        region.assign_fixed(|| "rc1", config.rc[1], base + r, || Value::known(rcs[r][1]))?;
        region.assign_fixed(|| "rc2", config.rc[2], base + r, || Value::known(rcs[r][2]))?;
        let dom = if r == 0 { domain } else { Fp::ZERO };
        let flag = if r == 0 { Fp::ONE } else { Fp::ZERO };
        region.assign_fixed(|| "domain", config.domain, base + r, || Value::known(dom))?;
        region.assign_fixed(
            || "absorb",
            config.is_absorb,
            base + r,
            || Value::known(flag),
        )?;

        config.s_round.enable(region, base + r)?;

        // Honest simulation of the next state (must mirror the gate exactly).
        let rc0 = Value::known(rcs[r][0]);
        let rc1 = Value::known(rcs[r][1]);
        let rc2 = Value::known(rcs[r][2]);
        let domv = Value::known(dom);
        let u0 = s[0] + iv0 + rc0;
        let u1 = s[1] + iv1 + rc1;
        let u2 = s[2] + domv + rc2;
        let fiv = |x: Value<Fp>| {
            let a = x;
            let b = a * a;
            b * b * x // x^5
        };
        let p0 = fiv(u0);
        let p1 = fiv(u1);
        let p2 = fiv(u2);
        let two = Value::known(Fp::from(2u64));
        let n0 = p0 * two + p1 + p2;
        let n1 = p0 + p1 * two + p2;
        let n2 = p0 + p1 + p2 * two;
        s = [n0, n1, n2];
    }

    // Final row: gate disabled, everything zeroed except the final state.
    let fr = base + ROUNDS;
    for k in 0..3 {
        let cell =
            region.assign_advice(|| format!("state{}-final", k), config.state[k], fr, || s[k])?;
        if k == 0 {
            out_cell = Some(cell);
        }
    }
    region.assign_advice(|| "in0", config.absorb[0], fr, zero)?;
    region.assign_advice(|| "in1", config.absorb[1], fr, zero)?;
    region.assign_fixed(|| "rc0", config.rc[0], fr, zero)?;
    region.assign_fixed(|| "rc1", config.rc[1], fr, zero)?;
    region.assign_fixed(|| "rc2", config.rc[2], fr, zero)?;
    region.assign_fixed(|| "domain", config.domain, fr, zero)?;
    region.assign_fixed(|| "absorb", config.is_absorb, fr, zero)?;

    Ok((out_cell.expect("state0 cell"), s[0]))
}

/// One plain permutation whose absorb inputs are constrained cells.
fn perm_step(
    region: &mut Region<'_, Fp>,
    config: &FcmpConfig,
    base: usize,
    domain: Fp,
    a: AssignedCell<Fp, Fp>,
    b: AssignedCell<Fp, Fp>,
) -> Result<(AssignedCell<Fp, Fp>, Value<Fp>), Error> {
    let in0v = a.value().cloned();
    let in1v = b.value().cloned();
    a.copy_advice(|| "in0-copy", region, config.absorb[0], base)?;
    b.copy_advice(|| "in1-copy", region, config.absorb[1], base)?;
    state_rows(region, config, base, domain, in0v, in1v)
}

/// One commutative tree step: node' = H_tree(node, sib).
fn tree_step(
    region: &mut Region<'_, Fp>,
    config: &FcmpConfig,
    base: usize,
    node_cell: AssignedCell<Fp, Fp>,
    node_val: Value<Fp>,
    sib_val: Value<Fp>,
) -> Result<(AssignedCell<Fp, Fp>, Value<Fp>), Error> {
    node_cell.copy_advice(|| "src-node", region, config.src[0], base)?;
    region.assign_advice(|| "src-sib", config.src[1], base, || sib_val)?;

    let sum = node_val + sib_val;
    let prod = node_val * sib_val;
    region.assign_advice(|| "sum", config.absorb[0], base, || sum)?;
    region.assign_advice(|| "prod", config.absorb[1], base, || prod)?;

    config.s_add.enable(region, base)?;
    config.s_mul.enable(region, base)?;

    state_rows(
        region,
        config,
        base,
        poseidon::domains()[poseidon::DOMAIN_TREE],
        sum,
        prod,
    )
}

/// Private witness for an FCMP spend proof.
#[derive(Clone, Debug)]
pub struct FcmpWitness {
    /// Spending key.
    pub sk: Fp,
    /// Note nonce.
    pub rho: Fp,
    /// Amount.
    pub value: u64,
    /// Authentication path: exactly `DEPTH` siblings, bottom-up.
    /// Missing entries (if any) are treated as zero.
    pub path: Vec<Fp>,
}

/// The FCMP circuit, generic over the tree depth.
pub struct FcmpCircuit<const DEPTH: usize> {
    pub witness: Value<FcmpWitness>,
}

impl<const DEPTH: usize> FcmpCircuit<DEPTH> {
    /// Total rows needed (witness rows + one region per permutation).
    pub fn rows_needed() -> usize {
        // 2 witness rows + (1 pk + 2 leaf stages + 1 nullifier + DEPTH tree steps)
        2 + (4 + DEPTH) * ROWS_PER_PERM
    }

    /// Smallest k such that the circuit fits (add a small margin for blinding).
    pub fn required_k() -> u32 {
        let rows = Self::rows_needed() + 16;
        let mut k = 1u32;
        while (1usize << k) < rows {
            k += 1;
        }
        k
    }
}

impl<const DEPTH: usize> Circuit<Fp> for FcmpCircuit<DEPTH> {
    type Config = FcmpConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            witness: Value::unknown(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        FcmpConfig::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let (root_cell, nf_cell) = layouter.assign_region(
            || "fcmp",
            |mut region| {
                let w = self.witness.clone();
                let mut base = 0usize;

                // Witness rows (no gates enabled here).
                let sk_val = w.clone().map(|x| x.sk);
                let rho_val = w.clone().map(|x| x.rho);
                let value_val = w.clone().map(|x| Fp::from(x.value));
                let path_val = w.clone().map(|x| x.path.clone());
                let sk_cell = region.assign_advice(|| "sk", config.src[0], base, || sk_val)?;
                let rho_cell = region.assign_advice(|| "rho", config.src[1], base, || rho_val)?;
                base += 1;
                let value_cell =
                    region.assign_advice(|| "value", config.state[0], base, || value_val)?;
                base += 1;

                // 1) pk = H_pk(sk, sk)
                let (pk_cell, _pk_val) = perm_step(
                    &mut region,
                    &config,
                    base,
                    poseidon::domains()[poseidon::DOMAIN_PK],
                    sk_cell.clone(),
                    sk_cell,
                )?;
                base += ROWS_PER_PERM;

                // 2) t1 = H_leaf(pk, rho)
                let (t1_cell, _t1_val) = perm_step(
                    &mut region,
                    &config,
                    base,
                    poseidon::domains()[poseidon::DOMAIN_LEAF],
                    pk_cell.clone(),
                    rho_cell.clone(),
                )?;
                base += ROWS_PER_PERM;

                // 3) cm = H_leaf(value, t1)
                let (cm_cell, cm_val) = perm_step(
                    &mut region,
                    &config,
                    base,
                    poseidon::domains()[poseidon::DOMAIN_LEAF],
                    value_cell,
                    t1_cell,
                )?;
                base += ROWS_PER_PERM;

                // 4) nf = H_null(pk, rho)
                let (nf_cell, _nf_val) = perm_step(
                    &mut region,
                    &config,
                    base,
                    poseidon::domains()[poseidon::DOMAIN_NULLIFIER],
                    pk_cell,
                    rho_cell,
                )?;
                base += ROWS_PER_PERM;

                // 5) tree walk up to the root
                let mut node_cell = cm_cell;
                let mut node_val = cm_val;
                for i in 0..DEPTH {
                    let sib = path_val
                        .clone()
                        .map(|v| v.get(i).copied().unwrap_or(Fp::ZERO));
                    let (c, v) = tree_step(&mut region, &config, base, node_cell, node_val, sib)?;
                    node_cell = c;
                    node_val = v;
                    base += ROWS_PER_PERM;
                }

                Ok((node_cell, nf_cell))
            },
        )?;

        layouter.constrain_instance(root_cell.cell(), config.instance_root, 0)?;
        layouter.constrain_instance(nf_cell.cell(), config.instance_nf, 0)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{merkle, Note};
    use ff::Field;
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    const DEPTH: usize = 4;

    fn setup(index: usize) -> (FcmpWitness, Fp, Fp) {
        let notes: Vec<Note> = (0..5)
            .map(|i| Note::new(Fp::random(OsRng), Fp::random(OsRng), 100 + i as u64))
            .collect();
        let leaves: Vec<Fp> = notes.iter().map(|n| n.commitment()).collect();
        let root = merkle::build_root(&leaves, DEPTH);
        let path = merkle::auth_path(&leaves, index, DEPTH);
        let w = FcmpWitness {
            sk: notes[index].sk,
            rho: notes[index].rho,
            value: notes[index].value,
            path,
        };
        let nf = notes[index].nullifier();
        (w, root, nf)
    }

    #[test]
    fn happy_path() {
        let (w, root, nf) = setup(2);
        let circuit = FcmpCircuit::<DEPTH> {
            witness: Value::known(w),
        };
        let prover = MockProver::run(10, &circuit, vec![vec![root], vec![nf]]).unwrap();
        prover.verify().unwrap();
    }

    #[test]
    fn wrong_root_fails() {
        let (w, root, nf) = setup(1);
        let circuit = FcmpCircuit::<DEPTH> {
            witness: Value::known(w),
        };
        let bad_root = root + Fp::ONE;
        let prover = MockProver::run(10, &circuit, vec![vec![bad_root], vec![nf]]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn wrong_sibling_fails() {
        let (mut w, root, nf) = setup(3);
        w.path[1] += Fp::ONE;
        let circuit = FcmpCircuit::<DEPTH> {
            witness: Value::known(w),
        };
        let prover = MockProver::run(10, &circuit, vec![vec![root], vec![nf]]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    #[ignore] // heavier: mainnet-depth tree, run with `cargo test --release -- --ignored`
    fn mainnet_depth_mock() {
        const D: usize = crate::TREE_DEPTH_MAINNET;
        let notes: Vec<Note> = (0..3)
            .map(|i| Note::new(Fp::random(OsRng), Fp::random(OsRng), 7 + i as u64))
            .collect();
        let leaves: Vec<Fp> = notes.iter().map(|n| n.commitment()).collect();
        let root = merkle::build_root(&leaves, D);
        let path = merkle::auth_path(&leaves, 0, D);
        let w = FcmpWitness {
            sk: notes[0].sk,
            rho: notes[0].rho,
            value: notes[0].value,
            path,
        };
        let circuit = FcmpCircuit::<D> {
            witness: Value::known(w),
        };
        let k = FcmpCircuit::<D>::required_k();
        assert_eq!(k, 12);
        let prover =
            MockProver::run(k, &circuit, vec![vec![root], vec![notes[0].nullifier()]]).unwrap();
        prover.verify().unwrap();
    }
}
