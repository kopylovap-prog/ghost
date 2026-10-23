//! Authenticated network node (v0.6 networking, phase N2-b).
//!
//! [`NetNode`] glues the N1 handshake onto real TCP sockets and the N2-a
//! peer store into one control-plane node:
//!
//! * every connection runs the mutual DLEq handshake in both roles (the
//!   dialer is the Initiator, the listener is the Responder);
//! * a connection is STRICTLY single-shot (audit F5): exactly one Hello
//!   and one Auth per direction in the fixed frame order; after the
//!   handshake only Disco frames are accepted - any other frame (including
//!   a second handshake) closes the connection;
//! * right after the handshake both sides exchange one bounded Disco
//!   batch. The batch leads with a SELF-entry (our advertised dialable
//!   address), so the receiving store always gains an address worth
//!   dialing; the responder never records the raw inbound source address
//!   (that is the initiator's ephemeral port, not a dial address) - the
//!   initiator records the address it actually dialed;
//! * contacts land in the persistent `PeerStore` (`insert_or_touch` for
//!   direct dials, `merge_remote` for gossip, explicit save after every
//!   change);
//! * the transcript replay window is per node (shared `ReplayCache`),
//!   so a captured (Hello, Auth) pair cannot be replayed on a new
//!   connection;
//! * the declared frame length is checked BEFORE the body is allocated,
//!   so a lying prefix cannot force a huge allocation (default cap:
//!   `MAX_NET_FRAME`, closing the N1 backlog item on read_frame caps).
//!
//! std-only, thread-per-connection, mirroring `swap_node.rs` (opacusd
//! embeds this node through `opacus_node::net_service`).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::handshake::{
    decode_net_frame, encode_net_frame, DiscoPeer, HandshakeError, HandshakeSide, NetMsg,
    ReplayCache, Role, VerifiedPeer, DISCO_MAX_PEERS, MAX_NET_FRAME, REPLAY_CACHE_CAP,
};
use crate::identity::NodeIdentity;
use crate::p2p::PeerInfo;
use crate::peers::{PeerStore, PeerStoreError};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Net node errors (socket, handshake, peer store).
#[derive(Debug)]
pub enum NetNodeError {
    Io(std::io::Error),
    Handshake(HandshakeError),
    PeerStore(PeerStoreError),
}

impl std::fmt::Display for NetNodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetNodeError::Io(e) => write!(f, "io: {e}"),
            NetNodeError::Handshake(e) => write!(f, "handshake: {e}"),
            NetNodeError::PeerStore(e) => write!(f, "peer store: {e}"),
        }
    }
}

impl std::error::Error for NetNodeError {}

impl From<std::io::Error> for NetNodeError {
    fn from(e: std::io::Error) -> Self {
        NetNodeError::Io(e)
    }
}

impl From<HandshakeError> for NetNodeError {
    fn from(e: HandshakeError) -> Self {
        NetNodeError::Handshake(e)
    }
}

impl From<PeerStoreError> for NetNodeError {
    fn from(e: PeerStoreError) -> Self {
        NetNodeError::PeerStore(e)
    }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Net node configuration.
#[derive(Clone, Debug)]
pub struct NetNodeConfig {
    /// Address to listen on ("ip:port"; port 0 = ephemeral).
    pub listen_addr: String,
    /// The dialable address advertised to peers as the Disco self-entry.
    /// Must parse as a `SocketAddr`. Loopback testing: any parseable
    /// ip:port; real deployments: the public ip:port of this node.
    pub advertise_addr: String,
    /// Peers to dial (and run the handshake with) on start.
    pub bootstrap_peers: Vec<String>,
    /// Per-read socket timeout; an idle authenticated peer is disconnected.
    pub read_timeout: Duration,
    /// Hard cap for one incoming frame (prefix + body); enforced BEFORE
    /// the body is allocated.
    pub max_frame_len: usize,
    /// Persistent peer store path; `None` = in-memory store.
    pub peers_path: Option<PathBuf>,
    /// Peer store capacity.
    pub max_peers: usize,
    /// Known peers per outbound Disco batch (self-entry excluded,
    /// capped at `DISCO_MAX_PEERS - 1`).
    pub disco_batch: usize,
}

impl Default for NetNodeConfig {
    fn default() -> Self {
        NetNodeConfig {
            listen_addr: "0.0.0.0:18080".to_string(),
            advertise_addr: "127.0.0.1:18080".to_string(),
            bootstrap_peers: Vec::new(),
            read_timeout: Duration::from_secs(30),
            max_frame_len: MAX_NET_FRAME,
            peers_path: None,
            max_peers: 512,
            disco_batch: 16,
        }
    }
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// Bounded observability log (newest last).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetEvent {
    /// Mutual handshake completed; the connection is now authenticated.
    Authenticated {
        node_id: String,
        addr: String,
        inbound: bool,
    },
    /// Handshake or post-auth protocol failure; the connection is closed.
    Rejected { addr: String, reason: String },
    /// A Disco batch was merged into the peer store.
    DiscoMerged { node_id: String, added: usize },
    /// The authenticated peer disconnected (clean EOF or idle timeout).
    Disconnected { node_id: String },
}

const EVENT_CAP: usize = 1024;

fn kind_of(m: &NetMsg) -> &'static str {
    match m {
        NetMsg::Hello { .. } => "Hello",
        NetMsg::Auth { .. } => "Auth",
        NetMsg::Disco { .. } => "Disco",
    }
}

// ---------------------------------------------------------------------------
// Node
// ---------------------------------------------------------------------------

/// Authenticated P2P control-plane node: handshake + disco + peer store.
pub struct NetNode {
    cfg: NetNodeConfig,
    identity: NodeIdentity,
    /// Canonical advertised dial address (parsed once at start).
    advert: String,
    listener: TcpListener,
    store: Arc<Mutex<PeerStore>>,
    cache: Arc<Mutex<ReplayCache>>,
    /// Authenticated connections: hex node_id -> write half.
    conns: Arc<Mutex<HashMap<String, TcpStream>>>,
    events: Arc<Mutex<Vec<NetEvent>>>,
}

impl NetNode {
    /// Validate the config, bind, spawn the accept loop and dial the
    /// bootstrap peers (dial failures are logged, not fatal).
    pub fn start(cfg: NetNodeConfig, identity: NodeIdentity) -> Result<Arc<Self>, NetNodeError> {
        let advert_sock: SocketAddr = cfg.advertise_addr.parse().map_err(|e| {
            NetNodeError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("bad advertise_addr {}: {e}", cfg.advertise_addr),
            ))
        })?;
        let store = match &cfg.peers_path {
            Some(p) => PeerStore::load_or_new(p, cfg.max_peers)?.0,
            None => PeerStore::in_memory(cfg.max_peers),
        };
        let listener = TcpListener::bind(&cfg.listen_addr)?;
        let node = Arc::new(NetNode {
            cfg,
            identity,
            advert: advert_sock.to_string(),
            listener,
            store: Arc::new(Mutex::new(store)),
            cache: Arc::new(Mutex::new(ReplayCache::new(REPLAY_CACHE_CAP))),
            conns: Arc::new(Mutex::new(HashMap::new())),
            events: Arc::new(Mutex::new(Vec::new())),
        });
        node.spawn_listener();
        let boot = node.cfg.bootstrap_peers.clone();
        for peer in boot {
            if let Err(e) = node.dial(&peer) {
                node.log(NetEvent::Rejected {
                    addr: peer,
                    reason: format!("dial: {e}"),
                });
            }
        }
        Ok(node)
    }

    pub fn local_addr(&self) -> Result<SocketAddr, NetNodeError> {
        Ok(self.listener.local_addr()?)
    }

    /// Our hex node_id (the Disco self-entry peer_id).
    pub fn node_id_hex(&self) -> String {
        hex::encode(self.identity.node_id)
    }

    /// The canonical advertised dial address.
    pub fn advertise_addr(&self) -> &str {
        &self.advert
    }

    /// Snapshot of the peer store (sorted by address).
    pub fn peers(&self) -> Vec<PeerInfo> {
        self.store.lock().unwrap().list()
    }

    /// Hex node_ids of currently authenticated connections (sorted).
    pub fn connected(&self) -> Vec<String> {
        let mut v: Vec<String> = self.conns.lock().unwrap().keys().cloned().collect();
        v.sort();
        v
    }

    /// Snapshot of recent events (bounded ring, newest last).
    pub fn events(&self) -> Vec<NetEvent> {
        self.events.lock().unwrap().clone()
    }

    fn log(&self, ev: NetEvent) {
        let mut evs = self.events.lock().unwrap();
        if evs.len() >= EVENT_CAP {
            evs.remove(0);
        }
        evs.push(ev);
    }

    fn drop_conn(&self, peer_hex: &str) {
        self.conns.lock().unwrap().remove(peer_hex);
    }

    /// Dial a peer and run the authenticated handshake as Initiator; the
    /// whole connection flow (handshake + disco + keep-alive loop) runs on
    /// its own thread. Dial errors are returned; later failures land in
    /// events.
    pub fn dial(self: &Arc<Self>, addr: &str) -> Result<(), NetNodeError> {
        let stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true).ok();
        let node = Arc::clone(self);
        let addr = addr.to_string();
        std::thread::spawn(move || node.conn_run(stream, Role::Initiator, addr));
        Ok(())
    }

    /// Accept loop: one handler thread per inbound connection.
    fn spawn_listener(self: &Arc<Self>) {
        let node = Arc::clone(self);
        std::thread::spawn(move || {
            for stream in node.listener.incoming().flatten() {
                let node = Arc::clone(&node);
                let addr = stream
                    .peer_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| "?".to_string());
                std::thread::spawn(move || node.conn_run(stream, Role::Responder, addr));
            }
        });
    }

    /// Our outbound Disco batch: the self-entry (advertised dial address)
    /// followed by the most recently seen known peers, capped at
    /// `DISCO_MAX_PEERS` entries in total.
    fn our_batch(&self) -> Vec<DiscoPeer> {
        let self_entry = DiscoPeer {
            peer_id: self.node_id_hex(),
            addr: self.advert.clone(),
        };
        let rest = self
            .store
            .lock()
            .unwrap()
            .to_disco_batch(self.cfg.disco_batch.min(DISCO_MAX_PEERS - 1));
        let mut batch = Vec::with_capacity(1 + rest.len());
        batch.push(self_entry);
        batch.extend(rest);
        batch.truncate(DISCO_MAX_PEERS);
        batch
    }
}

// ---------------------------------------------------------------------------
// Frame IO over sockets (u32-LE prefix + JSON body, net framing)
// ---------------------------------------------------------------------------

fn read_full(stream: &mut TcpStream, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut off = 0;
    while off < buf.len() {
        match stream.read(&mut buf[off..]) {
            Ok(0) => break,
            Ok(n) => off += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(off)
}

/// Read one full net frame (prefix + body). `Ok(None)` means the peer
/// closed the connection cleanly between frames. The declared length is
/// checked BEFORE the body is allocated.
fn read_net_frame(
    stream: &mut TcpStream,
    max_frame_len: usize,
) -> Result<Option<Vec<u8>>, NetNodeError> {
    let mut prefix = [0u8; 4];
    let got = read_full(stream, &mut prefix)?;
    if got == 0 {
        return Ok(None);
    }
    if got < 4 {
        return Err(NetNodeError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "connection closed inside a frame prefix",
        )));
    }
    let len = u32::from_le_bytes(prefix) as usize;
    if len > max_frame_len {
        return Err(NetNodeError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame too large: {len} bytes"),
        )));
    }
    let mut body = vec![0u8; len];
    read_full(stream, &mut body)?;
    let mut wire = Vec::with_capacity(4 + len);
    wire.extend_from_slice(&prefix);
    wire.extend_from_slice(&body);
    Ok(Some(wire))
}

fn write_net_frame(stream: &mut TcpStream, msg: &NetMsg) -> Result<(), NetNodeError> {
    let wire = encode_net_frame(msg)?;
    stream.write_all(&wire)?;
    stream.flush()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Per-connection flow: handshake (strict single-shot) -> disco -> keep-alive
// ---------------------------------------------------------------------------

impl NetNode {
    fn conn_run(self: &Arc<Self>, mut stream: TcpStream, role: Role, peer_addr: String) {
        stream.set_read_timeout(Some(self.cfg.read_timeout)).ok();
        stream.set_nodelay(true).ok();

        let (vp, batch) = match self.handshake_phase(&mut stream, role) {
            Ok(ok) => ok,
            Err(e) => {
                self.log(NetEvent::Rejected {
                    addr: peer_addr,
                    reason: e.to_string(),
                });
                return;
            }
        };

        let peer_hex = hex::encode(vp.node_id);
        match stream.try_clone() {
            Ok(half) => {
                self.conns.lock().unwrap().insert(peer_hex.clone(), half);
            }
            Err(e) => {
                self.log(NetEvent::Rejected {
                    addr: peer_addr,
                    reason: format!("try_clone: {e}"),
                });
                return;
            }
        }
        self.log(NetEvent::Authenticated {
            node_id: peer_hex.clone(),
            addr: peer_addr.clone(),
            inbound: role == Role::Responder,
        });
        // The initiator records the address it actually dialed; the
        // responder waits for the peer's advertised self-entry instead
        // (the inbound source address is an ephemeral port, not dialable).
        if role == Role::Initiator {
            let mut st = self.store.lock().unwrap();
            let _ = st.insert_or_touch(&peer_addr, &peer_hex);
            let _ = st.save();
        }

        // Disco exchange: both sides push one bounded batch, then read the
        // peer's batch in the keep-alive loop below.
        if let Err(e) = write_net_frame(&mut stream, &NetMsg::Disco { peers: batch }) {
            self.drop_conn(&peer_hex);
            self.log(NetEvent::Rejected {
                addr: peer_addr,
                reason: e.to_string(),
            });
            return;
        }
        loop {
            match read_net_frame(&mut stream, self.cfg.max_frame_len) {
                Ok(None) => break,
                Ok(Some(wire)) => match decode_net_frame(&wire) {
                    Ok(NetMsg::Disco { peers }) => {
                        let added = {
                            let mut st = self.store.lock().unwrap();
                            let added =
                                st.merge_remote(&peers, &self.node_id_hex(), Some(&self.advert));
                            let _ = st.save();
                            added
                        };
                        self.log(NetEvent::DiscoMerged {
                            node_id: peer_hex.clone(),
                            added,
                        });
                    }
                    Ok(other) => {
                        // strict single-shot (audit F5): after the
                        // handshake only Disco frames are accepted
                        self.drop_conn(&peer_hex);
                        self.log(NetEvent::Rejected {
                            addr: peer_addr,
                            reason: format!("unexpected {} frame after handshake", kind_of(&other)),
                        });
                        return;
                    }
                    Err(e) => {
                        self.drop_conn(&peer_hex);
                        self.log(NetEvent::Rejected {
                            addr: peer_addr,
                            reason: e.to_string(),
                        });
                        return;
                    }
                },
                Err(NetNodeError::Io(e))
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    self.drop_conn(&peer_hex);
                    self.log(NetEvent::Disconnected { node_id: peer_hex });
                    return;
                }
                Err(e) => {
                    self.drop_conn(&peer_hex);
                    self.log(NetEvent::Rejected {
                        addr: peer_addr,
                        reason: e.to_string(),
                    });
                    return;
                }
            }
        }
        self.drop_conn(&peer_hex);
        self.log(NetEvent::Disconnected { node_id: peer_hex });
    }

    /// Strict single-shot handshake phase (audit F5): exactly one Hello and
    /// one Auth per direction, in the fixed frame order. The responder
    /// pushes its Hello and Auth back-to-back; the initiator verifies the
    /// responder Auth before answering with its own. Returns the verified
    /// peer and OUR Disco batch.
    fn handshake_phase(
        &self,
        stream: &mut TcpStream,
        role: Role,
    ) -> Result<(VerifiedPeer, Vec<DiscoPeer>), NetNodeError> {
        let (mut side, hello) = HandshakeSide::start(role, &self.identity);
        let mut cache = self.cache.lock().unwrap();

        let read_msg = |stream: &mut TcpStream| -> Result<NetMsg, NetNodeError> {
            let wire = read_net_frame(stream, self.cfg.max_frame_len)?.ok_or_else(|| {
                NetNodeError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed during handshake",
                ))
            })?;
            Ok(decode_net_frame(&wire)?)
        };

        match role {
            Role::Initiator => {
                write_net_frame(stream, &NetMsg::Hello { hello })?;
                let peer_hello = match read_msg(stream)? {
                    NetMsg::Hello { hello } => hello,
                    other => {
                        return Err(NetNodeError::Handshake(HandshakeError::Malformed(format!(
                            "expected Hello frame, got {}",
                            kind_of(&other)
                        ))))
                    }
                };
                side.on_peer_hello(&peer_hello)?;
                let peer_auth = match read_msg(stream)? {
                    NetMsg::Auth { auth } => auth,
                    other => {
                        return Err(NetNodeError::Handshake(HandshakeError::Malformed(format!(
                            "expected Auth frame, got {}",
                            kind_of(&other)
                        ))))
                    }
                };
                let vp = side.verify_auth(&peer_auth, &mut cache)?;
                let my_auth = side.produce_auth()?;
                write_net_frame(stream, &NetMsg::Auth { auth: my_auth })?;
                Ok((vp, self.our_batch()))
            }
            Role::Responder => {
                let peer_hello = match read_msg(stream)? {
                    NetMsg::Hello { hello } => hello,
                    other => {
                        return Err(NetNodeError::Handshake(HandshakeError::Malformed(format!(
                            "expected Hello frame, got {}",
                            kind_of(&other)
                        ))))
                    }
                };
                side.on_peer_hello(&peer_hello)?;
                let my_auth = side.produce_auth()?;
                write_net_frame(stream, &NetMsg::Hello { hello })?;
                write_net_frame(stream, &NetMsg::Auth { auth: my_auth })?;
                let peer_auth = match read_msg(stream)? {
                    NetMsg::Auth { auth } => auth,
                    other => {
                        return Err(NetNodeError::Handshake(HandshakeError::Malformed(format!(
                            "expected Auth frame, got {}",
                            kind_of(&other)
                        ))))
                    }
                };
                let vp = side.verify_auth(&peer_auth, &mut cache)?;
                Ok((vp, self.our_batch()))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::Hello;
    use std::time::Instant;

    fn start_node(n: u8, peers_path: Option<PathBuf>) -> Arc<NetNode> {
        let cfg = NetNodeConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            advertise_addr: format!("127.0.0.1:{}", 46_000 + n as u16),
            bootstrap_peers: Vec::new(),
            read_timeout: Duration::from_secs(20),
            max_frame_len: MAX_NET_FRAME,
            peers_path,
            max_peers: 64,
            disco_batch: 16,
        };
        NetNode::start(cfg, NodeIdentity::generate()).unwrap()
    }

    fn wait_until(secs: u64, mut cond: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < deadline {
            if cond() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("condition not met within {secs}s");
    }

    /// Manually run the initiator flow on a raw stream (test helper): the
    /// responder completes its handshake, but this stream sends no Disco
    /// batch, so the caller stays in full control of what is written next.
    fn raw_dial_handshake_only(addr: &str) -> TcpStream {
        let id = NodeIdentity::generate();
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.set_nodelay(true).ok();
        let (mut side, hello) = HandshakeSide::start(Role::Initiator, &id);
        write_net_frame(&mut stream, &NetMsg::Hello { hello }).unwrap();
        let wire = read_net_frame(&mut stream, MAX_NET_FRAME).unwrap().unwrap();
        let peer_hello = match decode_net_frame(&wire).unwrap() {
            NetMsg::Hello { hello } => hello,
            other => panic!("expected Hello, got {}", kind_of(&other)),
        };
        side.on_peer_hello(&peer_hello).unwrap();
        let wire = read_net_frame(&mut stream, MAX_NET_FRAME).unwrap().unwrap();
        let peer_auth = match decode_net_frame(&wire).unwrap() {
            NetMsg::Auth { auth } => auth,
            other => panic!("expected Auth, got {}", kind_of(&other)),
        };
        let mut cache = ReplayCache::new(16);
        let _vp = side.verify_auth(&peer_auth, &mut cache).unwrap();
        let my_auth = side.produce_auth().unwrap();
        write_net_frame(&mut stream, &NetMsg::Auth { auth: my_auth }).unwrap();
        stream
    }

    #[test]
    fn two_nodes_handshake_disco_and_store() {
        let a = start_node(1, None);
        let b = start_node(2, None);
        a.dial(&b.local_addr().unwrap().to_string()).unwrap();
        let a_id = a.node_id_hex();
        let b_id = b.node_id_hex();

        wait_until(10, || a.connected().contains(&b_id));
        wait_until(10, || b.connected().contains(&a_id));

        // A's store gains B both from the dialed address and from the
        // disco self-entry; B's store gains A from the self-entry only.
        wait_until(10, || a.peers().iter().any(|p| p.peer_id == b_id));
        wait_until(10, || b.peers().iter().any(|p| p.peer_id == a_id));

        assert!(a
            .events()
            .iter()
            .any(|e| matches!(e, NetEvent::Authenticated { inbound: false, .. })));
        assert!(b.events().iter().any(|e| matches!(
            e,
            NetEvent::Authenticated { ref node_id, inbound: true, .. } if *node_id == a_id
        )));
        // both sides merged exactly one NEW peer (the self-entry of the
        // other side; the entry carrying the recipient's own identity is
        // skipped as self)
        assert!(b
            .events()
            .iter()
            .any(|e| matches!(e, NetEvent::DiscoMerged { added: 1, .. })));
        assert!(a
            .events()
            .iter()
            .any(|e| matches!(e, NetEvent::DiscoMerged { added: 1, .. })));
    }

    #[test]
    fn disco_gossip_propagates_through_common_peer() {
        let a = start_node(1, None);
        let b = start_node(2, None);
        let c = start_node(3, None);
        let a_id = a.node_id_hex();
        let c_id = c.node_id_hex();

        b.dial(&a.local_addr().unwrap().to_string()).unwrap();
        // B must have merged A's self-entry before C connects, so B's
        // batch to C already carries A
        wait_until(10, || b.peers().iter().any(|p| p.peer_id == a_id));

        c.dial(&b.local_addr().unwrap().to_string()).unwrap();
        wait_until(10, || b.peers().iter().any(|p| p.peer_id == c_id));
        // C learns A purely from B's gossip
        wait_until(10, || c.peers().iter().any(|p| p.peer_id == a_id));
    }

    #[test]
    fn second_hello_after_auth_rejected() {
        let b = start_node(2, None);
        let addr = b.local_addr().unwrap().to_string();
        let mut stream = raw_dial_handshake_only(&addr);
        // post-handshake: a second Hello frame must kill the connection
        let hello = Hello::build(&NodeIdentity::generate(), &[7u8; 32]);
        write_net_frame(&mut stream, &NetMsg::Hello { hello }).unwrap();
        wait_until(10, || {
            b.events().iter().any(|e| {
                matches!(
                    e,
                    NetEvent::Rejected { reason, .. } if reason.contains("unexpected")
                )
            })
        });
    }

    #[test]
    fn garbage_first_frame_rejected() {
        let b = start_node(2, None);
        let mut s = TcpStream::connect(b.local_addr().unwrap().to_string()).unwrap();
        s.write_all(b"not json at all").unwrap();
        s.flush().unwrap();
        wait_until(10, || {
            b.events()
                .iter()
                .any(|e| matches!(e, NetEvent::Rejected { .. }))
        });
    }

    #[test]
    fn wrong_protocol_frame_rejected() {
        let b = start_node(2, None);
        let mut s = TcpStream::connect(b.local_addr().unwrap().to_string()).unwrap();
        // well-formed envelope carrying the SWAP protocol tag: the net
        // node must reject it as a protocol mismatch
        let body = br#"{"protocol":"ghost-swap-p2p-v1","Hello":{"hello":{"version":1,"node_id":"aa","pe":"","pr":"","nonce":""}}}"#;
        s.write_all(&(body.len() as u32).to_le_bytes()).unwrap();
        s.write_all(body).unwrap();
        s.flush().unwrap();
        wait_until(10, || {
            b.events().iter().any(|e| {
                matches!(
                    e,
                    NetEvent::Rejected { reason, .. } if reason.contains("protocol mismatch")
                )
            })
        });
    }

    #[test]
    fn oversized_declared_frame_rejected_before_allocation() {
        let b = start_node(2, None);
        let mut s = TcpStream::connect(b.local_addr().unwrap().to_string()).unwrap();
        let n = (MAX_NET_FRAME + 1) as u32;
        s.write_all(&n.to_le_bytes()).unwrap();
        s.flush().unwrap();
        wait_until(10, || {
            b.events().iter().any(|e| {
                matches!(
                    e,
                    NetEvent::Rejected { reason, .. } if reason.contains("too large")
                )
            })
        });
    }

    #[test]
    fn bootstrap_dial_persists_peer_store() {
        let dir = std::env::temp_dir().join(format!(
            "opacus-net-persist-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("peers.json");

        let a = start_node(1, None);
        let b = start_node(2, Some(path.clone()));
        a.dial(&b.local_addr().unwrap().to_string()).unwrap();
        let a_id = a.node_id_hex();
        wait_until(10, || b.peers().iter().any(|p| p.peer_id == a_id));

        // merged contacts are persisted (atomic save after every change)
        wait_until(10, || {
            let (st, _) = PeerStore::load_or_new(&path, 64).unwrap();
            st.list().iter().any(|p| p.peer_id == a_id)
        });
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
