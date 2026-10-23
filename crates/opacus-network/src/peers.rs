//! Persistent peer store for the opacus P2P network (v0.6 networking, N2-a).
//!
//! `PeerStore` keeps the dial-list of known peers:
//!
//! * identity = `peer_id`: the 32-char lowercase hex of the peer 16-byte
//!   `node_id` (blake3 over its DLEq-bound public keys, see `identity.rs`);
//! * address = a canonical `ip:port` `SocketAddr` string, the only thing a
//!   dialer needs (bootstrap hostnames stay in `NetworkConfig`);
//! * `last_seen` = unix seconds, bumped monotonically on every contact.
//!
//! Persistence mirrors `identity.rs`: pretty JSON, atomic temp+rename save
//! (0600 unix temp file, dir-fsync after the rename) and corrupt-file
//! quarantine to `<path>.corrupt-<unix>-<pid>` with a fresh store returned
//! afterwards. Persistence is EXPLICIT: call `save()` after mutating when
//! the file should be refreshed.
//!
//! Discovery ingest (`merge_remote`) is defensive by design: entries arrive
//! over unauthenticated gossip, so the batch is capped at
//! `handshake::DISCO_MAX_PEERS`, every field is re-validated, self-entries
//! and our own dial address are dropped, and an address we already know
//! keeps its first-claimed identity (only `last_seen` is refreshed). Remote
//! timestamps are never trusted - ingested contacts are stamped locally.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::handshake::{DiscoPeer, DISCO_MAX_PEERS, MAX_ADDR_LEN, PEER_ID_HEX_LEN};
use crate::p2p::PeerInfo;

/// On-disk peer store file format version.
pub const PEERS_FILE_VERSION: u32 = 1;

static SAVE_SEQ: AtomicU64 = AtomicU64::new(0);

/// How a peer store was obtained by `load_or_new`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerStoreLoad {
    Loaded,
    Fresh,
    RecoveredCorrupt { backup: PathBuf },
}

/// Peer store errors (validation, persistence).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerStoreError {
    Io(String),
    Json(String),
    InvalidAddr(String),
    InvalidPeerId(String),
}

impl std::fmt::Display for PeerStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerStoreError::Io(m) => write!(f, "io: {m}"),
            PeerStoreError::Json(m) => write!(f, "json: {m}"),
            PeerStoreError::InvalidAddr(a) => write!(f, "invalid addr: {a}"),
            PeerStoreError::InvalidPeerId(p) => write!(f, "invalid peer_id: {p}"),
        }
    }
}

impl std::error::Error for PeerStoreError {}

#[derive(Serialize, Deserialize)]
struct PeersFile {
    version: u32,
    peers: Vec<PeerInfo>,
}

/// Registry of known peers keyed by canonical dial address.
pub struct PeerStore {
    path: Option<PathBuf>,
    max_peers: usize,
    entries: HashMap<String, PeerInfo>,
}

impl PeerStore {
    /// In-memory store (never persisted).
    pub fn in_memory(max_peers: usize) -> PeerStore {
        PeerStore {
            path: None,
            max_peers: max_peers.max(1),
            entries: HashMap::new(),
        }
    }

    /// Load from `path`; create a fresh empty file when absent; quarantine a
    /// corrupt or wrong-version file as `<path>.corrupt-<unix>-<pid>` and
    /// continue with an empty store.
    pub fn load_or_new(
        path: &Path,
        max_peers: usize,
    ) -> Result<(PeerStore, PeerStoreLoad), PeerStoreError> {
        let max_peers = max_peers.max(1);
        if !path.exists() {
            let st = PeerStore {
                path: Some(path.to_path_buf()),
                max_peers,
                entries: HashMap::new(),
            };
            st.save()?;
            return Ok((st, PeerStoreLoad::Fresh));
        }
        let mut st = PeerStore {
            path: Some(path.to_path_buf()),
            max_peers,
            entries: HashMap::new(),
        };
        let loaded: Option<PeersFile> = (|| {
            let raw = fs::read(path).ok()?;
            let file: PeersFile = serde_json::from_slice(&raw).ok()?;
            if file.version != PEERS_FILE_VERSION {
                return None;
            }
            Some(file)
        })();
        match loaded {
            Some(file) => {
                for p in file.peers {
                    match st.entries.get_mut(&p.addr) {
                        Some(e) => {
                            if p.last_seen > e.last_seen {
                                *e = p;
                            }
                        }
                        None => {
                            st.entries.insert(p.addr.clone(), p);
                        }
                    }
                }
            }
            None => {
                let backup = corrupt_backup_path(path);
                fs::rename(path, &backup).map_err(io_err)?;
                st.save()?;
                return Ok((st, PeerStoreLoad::RecoveredCorrupt { backup }));
            }
        }
        while st.entries.len() > st.max_peers {
            st.evict_oldest();
        }
        Ok((st, PeerStoreLoad::Loaded))
    }

    /// Current peer count.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the store holds no peers.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Configured capacity.
    pub fn max_peers(&self) -> usize {
        self.max_peers
    }

    /// Persist path, if any.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Look one peer up by canonical address.
    pub fn get(&self, addr: &str) -> Option<&PeerInfo> {
        self.entries.get(addr)
    }

    /// Drop one peer by address; true when it existed.
    pub fn remove(&mut self, addr: &str) -> bool {
        self.entries.remove(addr).is_some()
    }

    /// All peers sorted by address (deterministic listing).
    pub fn list(&self) -> Vec<PeerInfo> {
        let mut v: Vec<PeerInfo> = self.entries.values().cloned().collect();
        v.sort_by(|a, b| a.addr.cmp(&b.addr));
        v
    }

    /// Up to `k` most recently seen peers (ties broken by address asc).
    pub fn candidates(&self, k: usize) -> Vec<PeerInfo> {
        let mut v: Vec<PeerInfo> = self.entries.values().cloned().collect();
        v.sort_by(|a, b| b.last_seen.cmp(&a.last_seen).then(a.addr.cmp(&b.addr)));
        v.truncate(k);
        v
    }

    /// Validate and upsert one LOCAL contact (authenticated handshake
    /// handoff). The address is canonicalized through `SocketAddr`;
    /// `peer_id` must be 32 hex chars (case-insensitive, normalized to
    /// lowercase). Returns true when a NEW peer was added, false when an
    /// existing one was touched.
    pub fn insert_or_touch(&mut self, addr: &str, peer_id: &str) -> Result<bool, PeerStoreError> {
        self.insert_or_touch_at(addr, peer_id, Self::now())
    }

    /// Deterministic variant of `insert_or_touch` with an explicit clock.
    pub fn insert_or_touch_at(
        &mut self,
        addr: &str,
        peer_id: &str,
        now: u64,
    ) -> Result<bool, PeerStoreError> {
        let pid = norm_peer_id(peer_id)
            .ok_or_else(|| PeerStoreError::InvalidPeerId(peer_id.to_string()))?;
        let addr_s =
            norm_addr(addr).ok_or_else(|| PeerStoreError::InvalidAddr(addr.to_string()))?;
        Ok(self.upsert(addr_s, pid, now))
    }

    /// Ingest one Disco batch from a (remote) peer. Returns the number of
    /// NEWLY added peers. Self-entries (by `peer_id` or by our dial
    /// address), known addresses and invalid entries are skipped; at most
    /// `DISCO_MAX_PEERS` entries of the batch are considered. Remote
    /// `last_seen` values are ignored - contacts are stamped locally.
    pub fn merge_remote(
        &mut self,
        peers: &[DiscoPeer],
        self_peer_id: &str,
        self_addr: Option<&str>,
    ) -> usize {
        let now = Self::now();
        let mut added = 0usize;
        for d in peers.iter().take(DISCO_MAX_PEERS) {
            if d.peer_id.eq_ignore_ascii_case(self_peer_id) {
                continue;
            }
            let (Some(pid), Some(addr_s)) = (norm_peer_id(&d.peer_id), norm_addr(&d.addr)) else {
                continue;
            };
            if let Some(sa) = self_addr {
                if addr_s.eq_ignore_ascii_case(sa) {
                    continue;
                }
            }
            // an address we already know keeps its first-claimed identity
            let pid = match self.entries.get(&addr_s) {
                Some(e) => e.peer_id.clone(),
                None => pid,
            };
            if self.upsert(addr_s, pid, now) {
                added += 1;
            }
        }
        added
    }

    /// Build one outbound Disco batch (at most `DISCO_MAX_PEERS` entries,
    /// most recently seen first).
    pub fn to_disco_batch(&self, k: usize) -> Vec<DiscoPeer> {
        self.candidates(k.min(DISCO_MAX_PEERS))
            .into_iter()
            .map(|p| DiscoPeer {
                peer_id: p.peer_id,
                addr: p.addr,
            })
            .collect()
    }

    /// Persist the store (explicit). No-op for in-memory stores.
    pub fn save(&self) -> Result<(), PeerStoreError> {
        let Some(path) = self.path.as_deref() else {
            return Ok(());
        };
        let peers = self.list();
        let file = PeersFile {
            version: PEERS_FILE_VERSION,
            peers,
        };
        let json =
            serde_json::to_vec_pretty(&file).map_err(|e| PeerStoreError::Json(e.to_string()))?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(io_err)?;
            }
        }
        let millis = Self::now_millis();
        let seq = SAVE_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp = path.with_extension(format!("tmp-{}-{}-{}", std::process::id(), millis, seq));
        if let Err(e) = write_temp_and_rename(&tmp, path, &json) {
            let _ = fs::remove_file(&tmp);
            return Err(io_err(e));
        }
        fsync_parent(path);
        Ok(())
    }

    fn upsert(&mut self, addr: String, peer_id: String, last_seen: u64) -> bool {
        match self.entries.get_mut(&addr) {
            Some(e) => {
                e.last_seen = e.last_seen.max(last_seen);
                false
            }
            None => {
                while self.entries.len() >= self.max_peers && self.evict_oldest() {}
                self.entries.insert(
                    addr.clone(),
                    PeerInfo {
                        peer_id,
                        addr,
                        last_seen,
                    },
                );
                true
            }
        }
    }

    fn evict_oldest(&mut self) -> bool {
        let oldest = self
            .entries
            .values()
            .min_by_key(|p| (p.last_seen, p.addr.as_str()));
        match oldest {
            Some(p) => {
                let key = p.addr.clone();
                self.entries.remove(&key).is_some()
            }
            None => false,
        }
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn now_millis() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    }
}

fn io_err(e: std::io::Error) -> PeerStoreError {
    PeerStoreError::Io(e.to_string())
}

fn corrupt_backup_path(path: &Path) -> PathBuf {
    let ts = PeerStore::now();
    PathBuf::from(format!(
        "{}.corrupt-{}-{}",
        path.display(),
        ts,
        std::process::id()
    ))
}

fn norm_peer_id(raw: &str) -> Option<String> {
    if raw.len() != PEER_ID_HEX_LEN {
        return None;
    }
    let lower = raw.to_ascii_lowercase();
    if !lower.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(lower)
}

fn norm_addr(raw: &str) -> Option<String> {
    if raw.is_empty() || raw.chars().any(char::is_whitespace) {
        return None;
    }
    if raw.len() > MAX_ADDR_LEN {
        return None;
    }
    let sa: SocketAddr = raw.parse().ok()?;
    Some(sa.to_string())
}

/// Atomic file replace: write `json` to `tmp` (0600 on unix), fsync it,
/// rename over `path`.
#[cfg(unix)]
fn write_temp_and_rename(tmp: &Path, path: &Path, json: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(tmp)?;
    f.write_all(json)?;
    f.sync_all()?;
    fs::rename(tmp, path)
}

#[cfg(not(unix))]
fn write_temp_and_rename(tmp: &Path, path: &Path, json: &[u8]) -> std::io::Result<()> {
    let mut f = fs::File::create(tmp)?;
    f.write_all(json)?;
    f.sync_all()?;
    fs::rename(tmp, path)
}

/// Best-effort parent-directory fsync so the rename itself is durable.
#[cfg(unix)]
fn fsync_parent(path: &Path) {
    if let Some(parent) = path.parent() {
        if let Ok(d) = fs::File::open(parent) {
            let _ = d.sync_all();
        }
    }
}

#[cfg(not(unix))]
fn fsync_parent(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid_hex(i: u64) -> String {
        format!("{:032x}", i)
    }

    fn temp_store_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("opacus-peers-{}-{}", tag, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn peers_roundtrip_save_load() {
        let dir = temp_store_dir("rt");
        let path = dir.join("peers.json");
        let (mut st, kind) = PeerStore::load_or_new(&path, 8).unwrap();
        assert!(matches!(kind, PeerStoreLoad::Fresh));
        assert!(st.insert_or_touch("127.0.0.1:9001", &pid_hex(1)).unwrap());
        assert!(!st.insert_or_touch("127.0.0.1:9001", &pid_hex(1)).unwrap());
        assert!(st.insert_or_touch("127.0.0.1:9002", &pid_hex(2)).unwrap());
        st.save().unwrap();
        let (st2, kind2) = PeerStore::load_or_new(&path, 8).unwrap();
        assert!(matches!(kind2, PeerStoreLoad::Loaded));
        assert_eq!(st2.len(), 2);
        assert_eq!(st2.get("127.0.0.1:9001").unwrap().peer_id, pid_hex(1));
        assert_eq!(st2.list()[0].addr, "127.0.0.1:9001");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn peers_corrupt_quarantined() {
        let dir = temp_store_dir("corrupt");
        let path = dir.join("peers.json");
        fs::write(&path, b"{ not json ").unwrap();
        let (mut st, kind) = PeerStore::load_or_new(&path, 8).unwrap();
        assert!(matches!(kind, PeerStoreLoad::RecoveredCorrupt { .. }));
        assert_eq!(st.len(), 0);
        let quarantined = fs::read_dir(&dir).unwrap().filter_map(|e| e.ok()).any(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("peers.json.corrupt-")
        });
        assert!(quarantined);
        // wrong file version is corrupt too
        let bad = serde_json::to_vec(&PeersFile {
            version: PEERS_FILE_VERSION + 7,
            peers: Vec::new(),
        })
        .unwrap();
        fs::write(&path, bad).unwrap();
        let (_, kind2) = PeerStore::load_or_new(&path, 8).unwrap();
        assert!(matches!(kind2, PeerStoreLoad::RecoveredCorrupt { .. }));
        // the store stays usable after recovery
        assert!(st.insert_or_touch("127.0.0.1:7001", &pid_hex(3)).unwrap());
        st.save().unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn peers_insert_dedupe_monotonic_last_seen() {
        let mut st = PeerStore::in_memory(8);
        assert!(st
            .insert_or_touch_at("127.0.0.1:1", &pid_hex(1), 100)
            .unwrap());
        assert!(!st
            .insert_or_touch_at("127.0.0.1:1", &pid_hex(1), 50)
            .unwrap());
        assert_eq!(st.get("127.0.0.1:1").unwrap().last_seen, 100);
        assert!(!st
            .insert_or_touch_at("127.0.0.1:1", &pid_hex(1), 200)
            .unwrap());
        assert_eq!(st.get("127.0.0.1:1").unwrap().last_seen, 200);
        assert_eq!(st.len(), 1);
        assert!(matches!(
            st.insert_or_touch("bogus", &pid_hex(1)),
            Err(PeerStoreError::InvalidAddr(_))
        ));
        assert!(matches!(
            st.insert_or_touch("127.0.0.1:2", "xyz"),
            Err(PeerStoreError::InvalidPeerId(_))
        ));
    }

    #[test]
    fn peers_cap_evicts_oldest() {
        let mut st = PeerStore::in_memory(3);
        for i in 0..5u64 {
            assert!(st
                .insert_or_touch_at(&format!("127.0.0.1:{}", 10 + i), &pid_hex(i), 1000 + i)
                .unwrap());
        }
        assert_eq!(st.len(), 3);
        assert!(st.get("127.0.0.1:14").is_some());
        assert!(st.get("127.0.0.1:10").is_none());
        assert!(st.get("127.0.0.1:12").is_some());
    }

    #[test]
    fn peers_merge_remote_skips_self_known_conflicts() {
        let mut st = PeerStore::in_memory(16);
        let me = pid_hex(0);
        assert!(st
            .insert_or_touch_at("10.0.0.1:8000", &pid_hex(1), 10)
            .unwrap());
        let batch = vec![
            DiscoPeer {
                peer_id: me.clone(),
                addr: "10.0.0.9:8000".to_string(),
            },
            DiscoPeer {
                peer_id: pid_hex(2),
                addr: "10.0.0.1:8000".to_string(),
            },
            DiscoPeer {
                peer_id: pid_hex(1),
                addr: "10.0.0.1:8000".to_string(),
            },
            DiscoPeer {
                peer_id: pid_hex(3),
                addr: "10.0.0.3:8000".to_string(),
            },
            DiscoPeer {
                peer_id: pid_hex(4),
                addr: "127.0.0.1:18443".to_string(),
            },
        ];
        let added = st.merge_remote(&batch, &me, Some("127.0.0.1:18443"));
        assert_eq!(added, 1);
        assert_eq!(st.len(), 2);
        assert_eq!(st.get("10.0.0.1:8000").unwrap().peer_id, pid_hex(1));
    }

    #[test]
    fn peers_merge_remote_caps_batch() {
        let mut st = PeerStore::in_memory(64);
        let batch: Vec<DiscoPeer> = (0..DISCO_MAX_PEERS + 10)
            .map(|i| DiscoPeer {
                peer_id: pid_hex(i as u64),
                addr: format!("10.1.0.{}:9000", 10 + i),
            })
            .collect();
        let added = st.merge_remote(&batch, &pid_hex(999), None);
        assert_eq!(added, DISCO_MAX_PEERS);
        assert_eq!(st.len(), DISCO_MAX_PEERS);
    }

    #[test]
    fn peers_merge_remote_skips_invalid_entries() {
        let mut st = PeerStore::in_memory(16);
        let batch = vec![
            DiscoPeer {
                peer_id: "zz".to_string(),
                addr: "10.2.0.1:9000".to_string(),
            },
            DiscoPeer {
                peer_id: pid_hex(5),
                addr: "not an addr".to_string(),
            },
            DiscoPeer {
                peer_id: pid_hex(6),
                addr: "10.2.0.2:70000".to_string(),
            },
            DiscoPeer {
                peer_id: pid_hex(7),
                addr: "10.2.0.3:9000".to_string(),
            },
        ];
        let added = st.merge_remote(&batch, &pid_hex(999), None);
        assert_eq!(added, 1);
        assert!(st.get("10.2.0.3:9000").is_some());
        assert_eq!(st.len(), 1);
    }

    #[test]
    fn peers_candidates_most_recent_first() {
        let mut st = PeerStore::in_memory(8);
        st.insert_or_touch_at("10.3.0.1:1", &pid_hex(1), 100)
            .unwrap();
        st.insert_or_touch_at("10.3.0.2:1", &pid_hex(2), 300)
            .unwrap();
        st.insert_or_touch_at("10.3.0.3:1", &pid_hex(3), 200)
            .unwrap();
        let c = st.candidates(2);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].addr, "10.3.0.2:1");
        assert_eq!(c[1].addr, "10.3.0.3:1");
        let l = st.list();
        let addrs: Vec<&str> = l.iter().map(|p| p.addr.as_str()).collect();
        assert_eq!(addrs, vec!["10.3.0.1:1", "10.3.0.2:1", "10.3.0.3:1"]);
    }

    #[test]
    fn peers_save_atomic_no_temp_leftovers() {
        let dir = temp_store_dir("atomic");
        let path = dir.join("peers.json");
        let (mut st, _) = PeerStore::load_or_new(&path, 8).unwrap();
        assert!(st.insert_or_touch("127.0.0.1:8001", &pid_hex(1)).unwrap());
        st.save().unwrap();
        assert!(st.insert_or_touch("127.0.0.1:8002", &pid_hex(2)).unwrap());
        st.save().unwrap();
        let leftovers: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.contains("tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "leftovers: {leftovers:?}");
        let (st2, _) = PeerStore::load_or_new(&path, 8).unwrap();
        assert_eq!(st2.len(), 2);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn peers_to_disco_batch_roundtrip() {
        let mut a = PeerStore::in_memory(16);
        for i in 0..5u64 {
            assert!(a
                .insert_or_touch_at(&format!("10.4.0.{}:1", 10 + i), &pid_hex(1 + i), 1000 + i)
                .unwrap());
        }
        let batch = a.to_disco_batch(usize::MAX);
        assert_eq!(batch.len(), 5);
        let wire =
            crate::handshake::encode_net_frame(&crate::handshake::NetMsg::Disco { peers: batch })
                .unwrap();
        let peers = match crate::handshake::decode_net_frame(&wire).unwrap() {
            crate::handshake::NetMsg::Disco { peers } => peers,
            other => panic!("unexpected frame: {other:?}"),
        };
        let mut b = PeerStore::in_memory(16);
        let added = b.merge_remote(&peers, &pid_hex(777), None);
        assert_eq!(added, 5);
        assert_eq!(b.len(), 5);
        assert_eq!(b.get("10.4.0.10:1").unwrap().peer_id, pid_hex(1));
    }
}
