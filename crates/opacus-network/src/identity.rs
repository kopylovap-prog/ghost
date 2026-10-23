//! Node identity for the opacus P2P network (v0.6 networking, phase N1).
//!
//! One secret scalar controls BOTH key groups; the cross-group property is
//! proven by `opacus_bridge::xmr_dleq`:
//!
//! * `pe = sk * G_ed`  (Edwards / Monero basepoint)
//! * `pr = sk * G_ri`  (Ristretto basepoint)
//!
//! `node_id` is a 16-byte blake3 truncation over the two compressed public
//! keys, so a peer can check Hello-consistency without any secret material.
//! The identity persists as a small JSON file (`version`, secret scalar,
//! node_id); public keys are always DERIVED from the scalar, so a tampered
//! file is detected by re-deriving `node_id` and comparing. The secret
//! scalar is scrubbed from memory when the identity is dropped (F4).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, RISTRETTO_BASEPOINT_POINT};
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use opacus_bridge::xmr_dleq::KeyPair;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Domain tag for node_id derivation.
pub const NODE_ID_TAG: &[u8] = b"opacus-node-id-v1";
/// On-disk identity file format version.
pub const IDENTITY_FILE_VERSION: u32 = 1;

/// Zeroizing wrapper over the node secret scalar (F4): the scalar is
/// overwritten with zeros when the wrapper is dropped. Copy is
/// intentionally NOT implemented so an identity cannot be duplicated
/// by accident (the Debug output of the owner skips this field).
#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub(crate) struct SecretScalar(Scalar);

/// A DLEq-bound node identity.
#[derive(Clone, PartialEq, Eq)]
pub struct NodeIdentity {
    pub(crate) sk: SecretScalar,
    pub pe: CompressedEdwardsY,
    pub pr: CompressedRistretto,
    pub node_id: [u8; 16],
}

impl std::fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeIdentity")
            .field("pe", &hex::encode(self.pe.as_bytes()))
            .field("pr", &hex::encode(self.pr.as_bytes()))
            .field("node_id", &hex::encode(self.node_id))
            .finish_non_exhaustive()
    }
}

/// Derive the 16-byte node_id from the two compressed public keys.
pub fn node_id_of(pe: &CompressedEdwardsY, pr: &CompressedRistretto) -> [u8; 16] {
    let mut h = blake3::Hasher::new();
    h.update(NODE_ID_TAG);
    h.update(pe.as_bytes());
    h.update(pr.as_bytes());
    let out = h.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&out.as_bytes()[0..16]);
    id
}

impl NodeIdentity {
    /// Fresh identity from the OS randomness source.
    pub fn generate() -> NodeIdentity {
        NodeIdentity::from_secret(Scalar::random(&mut OsRng))
    }

    /// Deterministic construction; also the load path.
    pub fn from_secret(sk: Scalar) -> NodeIdentity {
        let pe = (sk * ED25519_BASEPOINT_POINT).compress();
        let pr = (sk * RISTRETTO_BASEPOINT_POINT).compress();
        let node_id = node_id_of(&pe, &pr);
        NodeIdentity {
            sk: SecretScalar(sk),
            pe,
            pr,
            node_id,
        }
    }

    /// Secret scalar (handshake signing, N1/N3).
    pub fn secret(&self) -> &Scalar {
        &self.sk.0
    }

    /// Key pair for `opacus_bridge::xmr_dleq::verify`.
    pub fn dleq_keypair(&self) -> KeyPair {
        KeyPair {
            monero_pub: self.pe,
            ristretto_pub: self.pr,
        }
    }

    /// Persist as JSON (secret scalar + node_id, both hex).
    ///
    /// Atomic-ish: the payload is written to a temp file in the same
    /// directory and renamed over the target, so a crash mid-write can
    /// never leave a torn identity file (a torn file would silently
    /// rotate the node identity via the quarantine path). On unix the
    /// file is created owner-only (0600).
    pub fn save(&self, path: &Path) -> io::Result<()> {
        use std::io::Write;
        let file = IdentityFile {
            version: IDENTITY_FILE_VERSION,
            sk_hex: hex::encode(self.sk.0.to_bytes()),
            node_id_hex: hex::encode(self.node_id),
        };
        let json = serde_json::to_vec_pretty(&file).map_err(json_io)?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let tmp = path.with_extension(format!(
            "tmp-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        ));
        {
            let mut opts = fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&tmp)?;
            f.write_all(&json)?;
            f.sync_all()?;
        }
        if let Err(e) = fs::rename(&tmp, path) {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
        Ok(())
    }

    /// Load the identity from `path`; generate and persist a fresh one when
    /// the file is absent; quarantine a corrupt/tampered file as
    /// `<path>.corrupt-<unix>` and regenerate.
    pub fn load_or_generate(path: &Path) -> io::Result<(NodeIdentity, IdentityLoad)> {
        if path.exists() {
            if let Some(id) = Self::load(path) {
                return Ok((id, IdentityLoad::Loaded));
            }
            let backup = corrupt_backup_path(path);
            let _ = fs::rename(path, &backup);
            let id = NodeIdentity::generate();
            id.save(path)?;
            return Ok((id, IdentityLoad::RecoveredCorrupt { backup }));
        }
        let id = NodeIdentity::generate();
        id.save(path)?;
        Ok((id, IdentityLoad::Fresh))
    }

    fn load(path: &Path) -> Option<NodeIdentity> {
        let raw = fs::read(path).ok()?;
        let file: IdentityFile = serde_json::from_slice(&raw).ok()?;
        if file.version != IDENTITY_FILE_VERSION {
            return None;
        }
        let sk_b = hex::decode(&file.sk_hex).ok()?;
        if sk_b.len() != 32 {
            return None;
        }
        let mut sb = [0u8; 32];
        sb.copy_from_slice(&sk_b);
        let sk = Scalar::from_canonical_bytes(sb).into_option()?;
        if sk.to_bytes() == [0u8; 32] {
            // degenerate all-zero identity: treat the file as corrupt
            return None;
        }
        let id = NodeIdentity::from_secret(sk);
        let nid = hex::decode(&file.node_id_hex).ok()?;
        if nid.as_slice() != id.node_id.as_slice() {
            return None;
        }
        Some(id)
    }
}

/// How an identity was obtained by `load_or_generate`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityLoad {
    Loaded,
    Fresh,
    RecoveredCorrupt { backup: PathBuf },
}

#[derive(Serialize, Deserialize)]
struct IdentityFile {
    version: u32,
    sk_hex: String,
    node_id_hex: String,
}

fn json_io(e: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

fn corrupt_backup_path(path: &Path) -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    PathBuf::from(format!(
        "{}.corrupt-{}-{}",
        path.display(),
        ts,
        std::process::id()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_zero_scalar_rejected() {
        let dir = std::env::temp_dir().join(format!("opacus-id-zero-{}", std::process::id()));
        let path = dir.join("network-identity.json");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // the all-zero scalar is canonical but degenerate: load must reject
        // it and load_or_generate must quarantine the file
        let file = IdentityFile {
            version: IDENTITY_FILE_VERSION,
            sk_hex: hex::encode([0u8; 32]),
            node_id_hex: hex::encode([0u8; 16]),
        };
        fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
        let (_, kind) = NodeIdentity::load_or_generate(&path).unwrap();
        assert!(matches!(kind, IdentityLoad::RecoveredCorrupt { .. }));
        fs::remove_dir_all(&dir).unwrap();
    }

    fn scalar_from_seed(seed: u8) -> Scalar {
        let mut buf = [0u8; 32];
        buf[0] = seed;
        buf[31] = seed.wrapping_add(1);
        Scalar::from_bytes_mod_order(buf)
    }

    #[test]
    fn identity_deterministic_from_secret() {
        let a = NodeIdentity::from_secret(scalar_from_seed(9));
        let b = NodeIdentity::from_secret(scalar_from_seed(9));
        assert_eq!(a.pe, b.pe);
        assert_eq!(a.pr, b.pr);
        assert_eq!(a.node_id, b.node_id);
        let c = NodeIdentity::from_secret(scalar_from_seed(10));
        assert_ne!(a.node_id, c.node_id);
        assert_eq!(a.node_id, node_id_of(&a.pe, &a.pr));
    }

    #[test]
    fn identity_file_roundtrip() {
        let dir = std::env::temp_dir().join(format!("opacus-id-test-{}", std::process::id()));
        let path = dir.join("network-identity.json");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let (id, kind) = NodeIdentity::load_or_generate(&path).unwrap();
        assert!(matches!(kind, IdentityLoad::Fresh));
        let (id2, kind2) = NodeIdentity::load_or_generate(&path).unwrap();
        assert!(matches!(kind2, IdentityLoad::Loaded));
        assert_eq!(id.node_id, id2.node_id);
        assert_eq!(id.sk.0.to_bytes(), id2.sk.0.to_bytes());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn identity_save_atomic_no_temp_leftovers() {
        let dir = std::env::temp_dir().join(format!("opacus-id-atomic-{}", std::process::id()));
        let path = dir.join("network-identity.json");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let id = NodeIdentity::generate();
        id.save(&path).unwrap();
        id.save(&path).unwrap(); // overwrite existing via rename
        let mut leftovers = 0;
        for entry in fs::read_dir(&dir).unwrap().flatten() {
            if entry.file_name().to_string_lossy().contains("tmp-") {
                leftovers += 1;
            }
        }
        assert_eq!(leftovers, 0, "temp files left behind");
        let (id2, kind) = NodeIdentity::load_or_generate(&path).unwrap();
        assert!(matches!(kind, IdentityLoad::Loaded));
        assert_eq!(id.node_id, id2.node_id);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn identity_corrupt_and_tampered_recovered() {
        let dir = std::env::temp_dir().join(format!("opacus-id-corrupt-{}", std::process::id()));
        let path = dir.join("network-identity.json");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let (id, _) = NodeIdentity::load_or_generate(&path).unwrap();

        // not JSON at all
        fs::write(&path, b"{ not json ").unwrap();
        let (id2, kind2) = NodeIdentity::load_or_generate(&path).unwrap();
        assert!(matches!(kind2, IdentityLoad::RecoveredCorrupt { .. }));
        assert_ne!(id.node_id, id2.node_id);

        // valid scalar, WRONG node_id (tamper detection)
        let file = IdentityFile {
            version: IDENTITY_FILE_VERSION,
            sk_hex: hex::encode(id2.sk.0.to_bytes()),
            node_id_hex: hex::encode([0u8; 16]),
        };
        fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
        let (id3, kind3) = NodeIdentity::load_or_generate(&path).unwrap();
        assert!(matches!(kind3, IdentityLoad::RecoveredCorrupt { .. }));
        assert_ne!(id2.node_id, id3.node_id);

        fs::remove_dir_all(&dir).unwrap();
    }
}
