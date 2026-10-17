cd $env:USERPROFILE\projects\ghost
 $root = (Get-Location).ProviderPath
 $utf8 = New-Object System.Text.UTF8Encoding($false)

function Write-File([string]$Rel, [string]$Content) {
    $full = Join-Path $root $Rel
    $dir = Split-Path $full -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllText($full, $Content, $utf8)
    Write-Host "  OK $Rel" -ForegroundColor Green
}

Write-Host "[1/3] Файлы ghost-zk..." -ForegroundColor Cyan

Write-File 'crates\ghost-zk\Cargo.toml' @'
[package]
name = "ghost-zk"
version.workspace = true
edition.workspace = true

[features]
default = []
real-prover = []

[dependencies]
halo2_proofs = "0.3"
ff = "0.13"
blake3.workspace = true
thiserror.workspace = true

[dev-dependencies]
rand.workspace = true
'@

Write-File 'crates\ghost-zk\src\lib.rs' @'
//! ghost-zk — Halo 2 реализация механизма FCMP++ для Ghost.
//!
//! Circuit доказывает одновременно: владение нотой (pk = H(sk) внутри leaf),
//! членство в дереве всей цепочки (path -> root) и nullifier (анти-double-spend).
//! Хеш дерева коммутативный: H(a,b) = H(b,a) — направление пути не нужно.

pub mod circuit;
pub mod merkle;
pub mod poseidon;
#[cfg(feature = "real-prover")]
pub mod prover;

pub use circuit::{required_k, FcmpCircuit, FcmpWitness};
pub use merkle::{verify_path, MerkleTree};
pub use poseidon::{domain, h_leaf, h_null, h_pk, h_tree, h_val, poseidon3, Fp};

/// Глубина дерева mainnet: 2^32 ~ 4.29 млрд выходов (вся история цепочки)
pub const TREE_DEPTH_MAINNET: usize = 32;

#[derive(Clone, Debug)]
pub struct Note {
    pub sk: Fp,
    pub value: u64,
    pub rho: Fp,
}

impl Note {
    pub fn pk(&self) -> Fp {
        h_pk(self.sk)
    }
    pub fn leaf(&self) -> Fp {
        h_leaf(self.pk(), h_val(self.value, self.rho))
    }
    pub fn nullifier(&self, index: u64) -> Fp {
        h_null(self.sk, index)
    }
}
'@

Write-File 'crates\ghost-zk\src\poseidon.rs' @'
//! Poseidon над полем Pallas (Fp): t=3, alpha=5, RF=8, RP=56.
//! Round constants детерминированы (blake3, domain-separated).
//! Для mainnet заменить на аудированный набор констант — API не меняется.

use blake3::Hasher;
use ff::{Field, PrimeField};
use halo2_proofs::pasta::pallas;
use std::sync::OnceLock;

pub type Fp = pallas::Base;

pub const RF: usize = 8;
pub const RP: usize = 56;
pub const ROUNDS: usize = RF + RP;

/// 256-бит -> Fp: (lo + hi * 2^128) mod p
pub fn bytes_to_fp(b: &[u8]) -> Fp {
    let lo = u128::from_le_bytes(b[0..16].try_into().unwrap());
    let hi = u128::from_le_bytes(b[16..32].try_into().unwrap());
    let two128 = {
        let mut x = Fp::ONE;
        for _ in 0..128 {
            x = x.double();
        }
        x
    };
    Fp::from_u128(lo) + Fp::from_u128(hi) * two128
}

pub fn domain(tag: &[u8]) -> Fp {
    bytes_to_fp(blake3::hash(tag).as_bytes())
}

fn rc(i: u64) -> Fp {
    let mut h = Hasher::new();
    h.update(b"ghost-zk-poseidon-rc-v1");
    h.update(&i.to_le_bytes());
    bytes_to_fp(h.finalize().as_bytes())
}

static RCS: OnceLock<Vec<[Fp; 3]>> = OnceLock::new();
pub fn round_constants() -> &'static [[Fp; 3]] {
    RCS.get_or_init(|| {
        (0..ROUNDS as u64)
            .map(|r| [rc(3 * r), rc(3 * r + 1), rc(3 * r + 2)])
            .collect()
    })
}

#[inline]
pub fn pow5(x: Fp) -> Fp {
    let x2 = x.square();
    let x4 = x2.square();
    x4 * x
}

/// MDS: циркулянт (2,1,1) — все миноры ненулевые => MDS
#[inline]
pub fn mds(s: [Fp; 3]) -> [Fp; 3] {
    [
        s[0].double() + s[1] + s[2],
        s[0] + s[1].double() + s[2],
        s[0] + s[1] + s[2].double(),
    ]
}

/// Нативная перестановка Poseidon: s = [d, x, y]
pub fn poseidon3(d: Fp, x: Fp, y: Fp) -> Fp {
    let rcs = round_constants();
    let mut s = [d, x, y];
    for r in 0..ROUNDS {
        for i in 0..3 {
            s[i] += rcs[r][i];
        }
        let full = r < RF / 2 || r >= RF / 2 + RP;
        if full {
            for i in 0..3 {
                s[i] = pow5(s[i]);
            }
        } else {
            s[0] = pow5(s[0]);
        }
        s = mds(s);
    }
    s[0]
}

pub fn h_pk(sk: Fp) -> Fp {
    poseidon3(domain(b"ghost.pk.v1"), sk, Fp::ZERO)
}
pub fn h_val(value: u64, rho: Fp) -> Fp {
    poseidon3(domain(b"ghost.val.v1"), Fp::from_u64(value), rho)
}
pub fn h_leaf(pk: Fp, hvr: Fp) -> Fp {
    poseidon3(domain(b"ghost.leaf.v1"), pk, hvr)
}
/// Коммутативный: H(a,b) == H(b,a)
pub fn h_tree(a: Fp, b: Fp) -> Fp {
    poseidon3(domain(b"ghost.tree.v1"), a + b, a * b)
}
pub fn h_null(sk: Fp, index: u64) -> Fp {
    poseidon3(domain(b"ghost.null.v1"), sk, Fp::from_u64(index))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let a = poseidon3(Fp::ONE, Fp::from_u64(2), Fp::from_u64(3));
        let b = poseidon3(Fp::ONE, Fp::from_u64(2), Fp::from_u64(3));
        assert_eq!(a, b);
    }

    #[test]
    fn domains_separate() {
        assert_ne!(h_pk(Fp::from_u64(7)), h_null(Fp::from_u64(7), 0));
    }

    #[test]
    fn tree_hash_commutative() {
        let (a, b) = (Fp::from_u64(11), Fp::from_u64(29));
        assert_eq!(h_tree(a, b), h_tree(b, a));
    }
}
'@

Write-File 'crates\ghost-zk\src\merkle.rs' @'
//! Дерево фиксированной глубины. Незаполненные листья = Fp::ZERO.

use crate::poseidon::{h_tree, Fp};

pub struct MerkleTree {
    levels: Vec<Vec<Fp>>,
    pub depth: usize,
}

impl MerkleTree {
    pub fn new(leaves: &[Fp], depth: usize) -> Self {
        assert!(depth >= 1, "depth must be >= 1");
        let n = leaves.len().max(1);
        let mut width = 1usize;
        while width < n {
            width <<= 1;
        }
        let mut lvl: Vec<Fp> = leaves.to_vec();
        lvl.resize(width, Fp::ZERO);

        let mut levels = vec![lvl];
        while levels.len() < depth {
            let cur = levels.last().unwrap();
            let next: Vec<Fp> = cur
                .chunks(2)
                .map(|pr| h_tree(pr[0], *pr.get(1).unwrap_or(&Fp::ZERO)))
                .collect();
            levels.push(next);
        }
        Self { levels, depth }
    }

    pub fn root(&self) -> Fp {
        self.levels.last().unwrap()[0]
    }

    /// Путь длиной ровно depth (над реальной высотой — сиблинги ZERO)
    pub fn path(&self, idx: usize) -> Vec<Fp> {
        let mut p = Vec::with_capacity(self.depth);
        let mut i = idx;
        for lvl in &self.levels {
            p.push(*lvl.get(i ^ 1).unwrap_or(&Fp::ZERO));
            i >>= 1;
        }
        p
    }
}

pub fn verify_path(mut node: Fp, path: &[Fp], root: Fp) -> bool {
    for s in path {
        node = h_tree(node, *s);
    }
    node == root
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::PrimeField;

    #[test]
    fn tree_roundtrip() {
        let leaves: Vec<Fp> = (1u64..=5).map(Fp::from_u64).collect();
        let tree = MerkleTree::new(&leaves, 4);
        for i in 0..leaves.len() {
            assert!(verify_path(leaves[i], &tree.path(i), tree.root()));
        }
    }

    #[test]
    fn wrong_leaf_fails() {
        let leaves: Vec<Fp> = (1u64..=5).map(Fp::from_u64).collect();
        let tree = MerkleTree::new(&leaves, 4);
        assert!(!verify_path(Fp::from_u64(999), &tree.path(0), tree.root()));
    }
}
'@

Write-File 'crates\ghost-zk\src\circuit.rs' @'
//! FCMP++ circuit: владение + членство + nullifier в одном Halo 2 circuit.
//!
//! Публичные входы: root, nullifier
//! Секреты: sk, value, rho, path, leaf_index

use crate::poseidon::{domain, round_constants, Fp, RF, ROUNDS};
use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    pasta::pallas,
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector,
    },
    poly::Rotation,
};

#[derive(Clone, Debug)]
pub struct FcmpWitness {
    pub sk: Fp,
    pub value: u64,
    pub rho: Fp,
    pub path: Vec<Fp>,
    pub leaf_index: u64,
}

#[derive(Clone)]
pub struct FcmpCircuit {
    pub wit: Value<FcmpWitness>,
    pub depth: usize,
}

#[derive(Clone)]
pub struct FcmpConfig {
    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Advice>,
    out: Column<Advice>,
    ka: Column<Fixed>,
    kb: Column<Fixed>,
    kc: Column<Fixed>,
    kadd: Column<Fixed>,
    q_mul: Selector,
    q_lin: Selector,
    q_addc: Selector,
    inst_root: Column<Instance>,
    inst_nul: Column<Instance>,
}

impl Circuit<Fp> for FcmpCircuit {
    type Config = FcmpConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self { wit: Value::unknown(), depth: self.depth }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let (a, b, c, out) = (
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        );
        let (ka, kb, kc, kadd) = (
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        );
        let (q_mul, q_lin, q_addc) = (meta.selector(), meta.selector(), meta.selector());
        let (inst_root, inst_nul) = (meta.instance_column(), meta.instance_column());

        for col in [a, b, c, out] {
            meta.enable_equality(col);
        }
        meta.enable_equality(inst_root);
        meta.enable_equality(inst_nul);

        meta.create_gate("mul", |meta| {
            let q = meta.query_selector(q_mul);
            let av = meta.query_advice(a, Rotation::cur());
            let bv = meta.query_advice(b, Rotation::cur());
            let ov = meta.query_advice(out, Rotation::cur());
            vec![q * (ov - av * bv)]
        });

        meta.create_gate("lin", |meta| {
            let q = meta.query_selector(q_lin);
            let av = meta.query_advice(a, Rotation::cur());
            let bv = meta.query_advice(b, Rotation::cur());
            let cv = meta.query_advice(c, Rotation::cur());
            let kav = meta.query_fixed(ka, Rotation::cur());
            let kbv = meta.query_fixed(kb, Rotation::cur());
            let kcv = meta.query_fixed(kc, Rotation::cur());
            let ov = meta.query_advice(out, Rotation::cur());
            vec![q * (ov - kav * av - kbv * bv - kcv * cv)]
        });

        meta.create_gate("addc", |meta| {
            let q = meta.query_selector(q_addc);
            let av = meta.query_advice(a, Rotation::cur());
            let kv = meta.query_fixed(kadd, Rotation::cur());
            let ov = meta.query_advice(out, Rotation::cur());
            vec![q * (ov - av - kv)]
        });

        Self::Config { a, b, c, out, ka, kb, kc, kadd, q_mul, q_lin, q_addc, inst_root, inst_nul }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let depth = self.depth;

        layouter.assign_region(
            || "fcmp",
            |mut region| {
                let mut b = Builder { region: &mut region, cfg: config.clone(), off: 0 };

                // Строки 0 и 1 — публичные входы (копии из instance)
                b.instance_row(config.inst_root, 0)?;
                b.instance_row(config.inst_nul, 1)?;

                let wit = self.wit.clone();
                let sk_cell = b.assign_known(config.a, wit.as_ref().map(|w| w.sk))?;
                let val_cell =
                    b.assign_known(config.b, wit.as_ref().map(|w| Fp::from_u64(w.value)))?;
                let rho_cell = b.assign_known(config.c, wit.as_ref().map(|w| w.rho))?;
                let zero = b.assign_known(config.c, Value::known(Fp::ZERO))?;

                // pk = P3(D_pk, sk, 0)
                let pk = b.poseidon3(domain(b"ghost.pk.v1"), sk_cell.clone(), zero.clone())?;

                // hvr = P3(D_val, value, rho)
                let hvr = b.poseidon3(domain(b"ghost.val.v1"), val_cell, rho_cell)?;

                // leaf = P3(D_leaf, pk, hvr)
                let leaf = b.poseidon3(domain(b"ghost.leaf.v1"), pk, hvr)?;

                // Путь: node_{i+1} = H_tree(node_i, sib_i) — коммутативный хеш
                let path = wit.as_ref().map(|w| w.path.clone());
                let mut node = leaf;
                for i in 0..depth {
                    let sib = b.assign_known(config.b, path.as_ref().map(|p| p[i]))?;
                    let sum = b.lin3(node.clone(), sib.clone(), zero.clone(), 1, 1, 0)?;
                    let prod = b.mul(node, sib)?;
                    node = b.poseidon3(domain(b"ghost.tree.v1"), sum, prod)?;
                }

                // node == root
                let root_cell = b.instance_cell(config.inst_root)?;
                b.region.constrain_equal(node.cell(), root_cell.cell())?;

                // nullifier = P3(D_null, sk, index)
                let idx =
                    b.assign_known(config.b, wit.as_ref().map(|w| Fp::from_u64(w.leaf_index)))?;
                let nul = b.poseidon3(domain(b"ghost.null.v1"), sk_cell, idx)?;
                let nul_cell = b.instance_cell(config.inst_nul)?;
                b.region.constrain_equal(nul.cell(), nul_cell.cell())?;

                Ok(())
            },
        )
    }
}

struct Builder<'r, 'l> {
    region: &'r mut Region<'l, Fp>,
    cfg: FcmpConfig,
    off: usize,
}

impl<'r, 'l> Builder<'r, 'l> {
    fn fill_fixed_zero(&mut self, off: usize) -> Result<(), Error> {
        for col in [self.cfg.ka, self.cfg.kb, self.cfg.kc, self.cfg.kadd] {
            self.region
                .assign_fixed(|| "z", col, off, || Value::known(Fp::ZERO))?;
        }
        Ok(())
    }

    fn def(&mut self, col: Column<Advice>, off: usize) -> Result<(), Error> {
        self.region
            .assign_advice(|| "pad", col, off, || Value::known(Fp::ZERO))?;
        Ok(())
    }

    /// Заполнить advice-столбцы, не указанные в skip (все столбцы с
    /// enable_equality должны быть назначены в каждой строке региона)
    fn pad_advice(&mut self, off: usize, skip: &[Column<Advice>]) -> Result<(), Error> {
        for col in [self.cfg.a, self.cfg.b, self.cfg.c, self.cfg.out] {
            if !skip.contains(&col) {
                self.def(col, off)?;
            }
        }
        Ok(())
    }

    fn advance(&mut self) {
        self.off += 1;
    }

    fn copy_at(
        &mut self,
        col: Column<Advice>,
        src: &AssignedCell<Fp, Fp>,
        off: usize,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let cell = self
            .region
            .assign_advice(|| "copy", col, off, || src.value().copied())?;
        self.region.constrain_equal(cell.cell(), src.cell())?;
        Ok(cell)
    }

    fn assign_known(
        &mut self,
        col: Column<Advice>,
        v: Value<Fp>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let off = self.off;
        self.fill_fixed_zero(off)?;
        let cell = self.region.assign_advice(|| "w", col, off, || v)?;
        self.pad_advice(off, &[col])?;
        self.advance();
        Ok(cell)
    }

    fn instance_row(&mut self, col: Column<Instance>, row: usize) -> Result<(), Error> {
        let off = self.off;
        self.fill_fixed_zero(off)?;
        self.region
            .assign_advice_from_instance(|| "inst", col, row, self.cfg.a, off)?;
        self.pad_advice(off, &[self.cfg.a])?;
        self.advance();
        Ok(())
    }

    fn instance_cell(&mut self, col: Column<Instance>) -> Result<AssignedCell<Fp, Fp>, Error> {
        let off = self.off;
        self.fill_fixed_zero(off)?;
        let cell = self
            .region
            .assign_advice_from_instance(|| "inst", col, 0, self.cfg.a, off)?;
        self.pad_advice(off, &[self.cfg.a])?;
        self.advance();
        Ok(cell)
    }

    fn mul(
        &mut self,
        x: AssignedCell<Fp, Fp>,
        y: AssignedCell<Fp, Fp>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let off = self.off;
        self.fill_fixed_zero(off)?;
        let _a = self.copy_at(self.cfg.a, &x, off)?;
        let _b = self.copy_at(self.cfg.b, &y, off)?;
        let v = x.value().copied() * y.value().copied();
        let out = self
            .region
            .assign_advice(|| "mul", self.cfg.out, off, || v)?;
        self.cfg.q_mul.enable(self.region, off)?;
        self.pad_advice(off, &[self.cfg.a, self.cfg.b, self.cfg.out])?;
        self.advance();
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    fn lin3(
        &mut self,
        x: AssignedCell<Fp, Fp>,
        y: AssignedCell<Fp, Fp>,
        z: AssignedCell<Fp, Fp>,
        kx: u64,
        ky: u64,
        kz: u64,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let off = self.off;
        let (kx, ky, kz) = (Fp::from_u64(kx), Fp::from_u64(ky), Fp::from_u64(kz));
        self.region
            .assign_fixed(|| "ka", self.cfg.ka, off, || Value::known(kx))?;
        self.region
            .assign_fixed(|| "kb", self.cfg.kb, off, || Value::known(ky))?;
        self.region
            .assign_fixed(|| "kc", self.cfg.kc, off, || Value::known(kz))?;
        self.region
            .assign_fixed(|| "kz", self.cfg.kadd, off, || Value::known(Fp::ZERO))?;
        let _a = self.copy_at(self.cfg.a, &x, off)?;
        let _b = self.copy_at(self.cfg.b, &y, off)?;
        let _c = self.copy_at(self.cfg.c, &z, off)?;
        let v = x.value().copied() * Value::known(kx)
            + y.value().copied() * Value::known(ky)
            + z.value().copied() * Value::known(kz);
        let out = self
            .region
            .assign_advice(|| "lin", self.cfg.out, off, || v)?;
        self.cfg.q_lin.enable(self.region, off)?;
        self.advance();
        Ok(out)
    }

    fn addc(&mut self, x: AssignedCell<Fp, Fp>, k: Fp) -> Result<AssignedCell<Fp, Fp>, Error> {
        let off = self.off;
        self.region
            .assign_fixed(|| "ka", self.cfg.ka, off, || Value::known(Fp::ONE))?;
        self.region
            .assign_fixed(|| "kb", self.cfg.kb, off, || Value::known(Fp::ZERO))?;
        self.region
            .assign_fixed(|| "kc", self.cfg.kc, off, || Value::known(Fp::ZERO))?;
        self.region
            .assign_fixed(|| "kadd", self.cfg.kadd, off, || Value::known(k))?;
        let _a = self.copy_at(self.cfg.a, &x, off)?;
        let v = x.value().copied() + Value::known(k);
        let out = self
            .region
            .assign_advice(|| "addc", self.cfg.out, off, || v)?;
        self.cfg.q_addc.enable(self.region, off)?;
        self.pad_advice(off, &[self.cfg.a, self.cfg.out])?;
        self.advance();
        Ok(out)
    }

    fn pow5(&mut self, x: AssignedCell<Fp, Fp>) -> Result<AssignedCell<Fp, Fp>, Error> {
        let x2 = self.mul(x.clone(), x)?;
        let x4 = self.mul(x2.clone(), x2)?;
        self.mul(x4, x)
    }

    /// Poseidon в circuit: base-строка + 64 раунда (ARK / SBOX / MDS)
    fn poseidon3(
        &mut self,
        d: Fp,
        x: AssignedCell<Fp, Fp>,
        y: AssignedCell<Fp, Fp>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let off = self.off;
        self.fill_fixed_zero(off)?;
        let s0 = self
            .region
            .assign_advice(|| "d", self.cfg.a, off, || Value::known(d))?;
        let s1 = self.copy_at(self.cfg.b, &x, off)?;
        let s2 = self.copy_at(self.cfg.c, &y, off)?;
        self.pad_advice(off, &[self.cfg.a, self.cfg.b, self.cfg.c])?;
        self.advance();

        let rcs = round_constants();
        let mut s = [s0, s1, s2];

        for r in 0..ROUNDS {
            for i in 0..3 {
                s[i] = self.addc(s[i].clone(), rcs[r][i])?;
            }
            let full = r < RF / 2 || r >= RF / 2 + RP;
            if full {
                for i in 0..3 {
                    s[i] = self.pow5(s[i].clone())?;
                }
            } else {
                s[0] = self.pow5(s[0].clone())?;
            }
            let old = s.clone();
            s[0] = self.lin3(old[0].clone(), old[1].clone(), old[2].clone(), 2, 1, 1)?;
            s[1] = self.lin3(old[0].clone(), old[1].clone(), old[2].clone(), 1, 2, 1)?;
            s[2] = self.lin3(old[0], old[1], old[2], 1, 1, 2)?;
        }
        Ok(s[0].clone())
    }
}

/// Требуемое k для заданной глубины дерева
pub fn required_k(depth: usize) -> u32 {
    // 625 строк на poseidon3; вызовов: 3 + depth + 1; уровни добавляют 2 строки
    let rows = 625 * (3 + depth + 1) + 2 * depth + 16;
    (rows as usize - 1).next_power_of_two().trailing_zeros() as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::MerkleTree;
    use crate::poseidon::{h_leaf, h_null, h_pk, h_val};
    use rand::rngs::OsRng;

    const DEPTH: usize = 8;
    const K: u32 = 13;

    fn make_world() -> (FcmpWitness, Fp, Fp) {
        let sk = Fp::random(&mut OsRng);
        let value = 1234u64;
        let rho = Fp::random(&mut OsRng);
        let index = 3usize;

        let pk = h_pk(sk);
        let hvr = h_val(value, rho);
        let leaf = h_leaf(pk, hvr);

        let mut leaves: Vec<Fp> = (0..6).map(|i| Fp::from_u64(1000 + i)).collect();
        leaves[index] = leaf;
        let tree = MerkleTree::new(&leaves, DEPTH);

        let wit = FcmpWitness {
            sk,
            value,
            rho,
            path: tree.path(index),
            leaf_index: index as u64,
        };
        (wit, tree.root(), h_null(sk, index as u64))
    }

    #[test]
    fn fcmp_valid_spend_passes() {
        let (wit, root, nul) = make_world();
        let circuit = FcmpCircuit { wit: Value::known(wit), depth: DEPTH };
        let prover =
            halo2_proofs::dev::MockProver::<Fp>::run(K, &circuit, vec![vec![root], vec![nul]])
                .unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn tampered_path_fails() {
        let (mut wit, root, nul) = make_world();
        wit.path[0] += Fp::ONE;
        let circuit = FcmpCircuit { wit: Value::known(wit), depth: DEPTH };
        let prover =
            halo2_proofs::dev::MockProver::<Fp>::run(K, &circuit, vec![vec![root], vec![nul]])
                .unwrap();
        assert!(prover.verify().is_err(), "изменённый путь должен ломать proof");
    }

    #[test]
    fn wrong_sk_fails() {
        let (wit, root, nul) = make_world();
        let wrong = FcmpWitness { sk: Fp::random(&mut OsRng), ..wit };
        let circuit = FcmpCircuit { wit: Value::known(wrong), depth: DEPTH };
        let prover =
            halo2_proofs::dev::MockProver::<Fp>::run(K, &circuit, vec![vec![root], vec![nul]])
                .unwrap();
        assert!(prover.verify().is_err(), "чужой ключ не должен проходить");
    }

    #[test]
    fn native_tree_matches_circuit_hash() {
        let (wit, root, _) = make_world();
        let pk = h_pk(wit.sk);
        let leaf = h_leaf(pk, h_val(wit.value, wit.rho));
        let node = wit.path.iter().fold(leaf, |acc, s| crate::poseidon::h_tree(acc, *s));
        assert_eq!(node, root, "native и circuit должны давать идентичные корни");
    }
}
'@

Write-File 'crates\ghost-zk\src\prover.rs' @'
//! Настоящие keygen/prove/verify (halo2 0.3, IPA).
//! Включение: cargo test -p ghost-zk --features real-prover --release -- --ignored

use crate::circuit::{required_k, FcmpCircuit};
use halo2_proofs::{
    pasta::pallas,
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, ProvingKey, VerifyingKey},
    poly::{
        commitment::Params as _,
        ipa::{
            commitment::{IPACommitmentScheme, Params},
            multiopen::{ProverIPA, VerifierIPA},
            strategy::SingleStrategy,
        },
    },
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use rand::RngCore;

type G1 = pallas::Affine;

pub struct Setup {
    pub params: Params<G1>,
    pub pk: ProvingKey<G1>,
    pub vk: VerifyingKey<G1>,
}

pub fn setup(depth: usize) -> Result<Setup, halo2_proofs::plonk::Error> {
    let params = Params::new(required_k(depth));
    let circuit = FcmpCircuit { wit: halo2_proofs::circuit::Value::unknown(), depth };
    let vk = keygen_vk(&params, &circuit)?;
    let pk = keygen_pk(&params, vk.clone(), &circuit)?;
    Ok(Setup { params, pk, vk })
}

pub fn prove(
    s: &Setup,
    circuit: &FcmpCircuit,
    root: crate::poseidon::Fp,
    nul: crate::poseidon::Fp,
    rng: &mut impl RngCore,
) -> Result<Vec<u8>, halo2_proofs::plonk::Error> {
    let mut tw = Blake2bWrite::<_, G1, Challenge255<_>>::init(vec![]);
    create_proof::<IPACommitmentScheme<G1>, ProverIPA<'_, _, _, _>, _, SingleStrategy<'_, G1>, _, _>(
        &s.params,
        &s.pk,
        std::slice::from_ref(circuit),
        &[&[&[root], &[nul]]],
        rng,
        &mut tw,
    )?;
    Ok(tw.finalize())
}

pub fn verify(
    s: &Setup,
    proof: &[u8],
    root: crate::poseidon::Fp,
    nul: crate::poseidon::Fp,
) -> Result<bool, halo2_proofs::plonk::Error> {
    let mut tr = Blake2bRead::<_, G1, Challenge255<_>>::init(proof);
    let strategy = SingleStrategy::new(&s.params);
    verify_proof::<IPACommitmentScheme<G1>, VerifierIPA<'_, _, _>, _, _, _>(
        &s.params,
        &s.vk,
        strategy,
        &[&[&[root], &[nul]]],
        &mut tr,
    )
    .map(|_| true)
}
'@

Write-Host "[2/3] Добавление ghost-zk в workspace members..." -ForegroundColor Cyan
 $tomlPath = Join-Path $root 'Cargo.toml'
 $t = [System.IO.File]::ReadAllText($tomlPath)
if ($t -notmatch 'ghost-zk') {
    $needle = '"crates/ghost-miner",'
    $repl = '"crates/ghost-miner",' + "`n" + '    "crates/ghost-zk",'
    $t = $t.Replace($needle, $repl)
    [System.IO.File]::WriteAllText($tomlPath, $t, $utf8)
    Write-Host "  OK: member добавлен" -ForegroundColor Green
} else {
    Write-Host "  OK: уже есть" -ForegroundColor Green
}

Write-Host "[3/3] Тесты (первая сборка halo2 - 3-6 минут)..." -ForegroundColor Cyan
cargo test -p ghost-zk --release