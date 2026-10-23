# Changelog

All notable changes to the **Opacus** monorepo are documented in this file.
The initial public release consolidates the full pre-history of the private
development phase; every further change will be added here following the
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format and
[Semantic Versioning](https://semver.org/).

Opacus is a privacy payment network that fuses Monero-style ring-CT semantics
with Zcash-style Halo2 FCMP++ spend proofs, plus an Ethereum-side wrapped
token (wGHOST) and tooling for bridging, DEX swaps and atomic swaps.

## [Unreleased]

## [0.6.0] - 2026-10-23

Networking release: the P2P layer grows a persistent node identity, a
DLEq-authenticated handshake, persistent peer discovery with disco gossip,
and encrypted wallet note transmission - all inside crates/opacus-network
with the workspace gate (fmt, tests, clippy -D warnings) fully green.

### Added

#### crates/opacus-network - networking phases N1-N3
- identity.rs (N1): persistent node identity - ristretto scalar plus
  compressed public key, deterministic from a 32-byte secret, atomic save
  with 0600 permissions and backup-collision guard, zero-scalar rejection.
- handshake.rs (N1): DLEq-authenticated handshake over the length-prefixed
  opacus-net-v1 wire: transcript hashing, forged-transcript and tampered
  DLEq rejection, wrong-key and replay rejection, replay cache with cap
  eviction, strict frame-size and peer-id caps, and a notes frame during
  the handshake disconnects (HandshakeError::NotesTooLarge).
- peers.rs (N2): persistent peer store - bounded cap with oldest eviction,
  insert dedupe with monotonic last_seen, remote-batch merge with
  self/conflict skips, corrupt-file quarantine, disco batch roundtrip.
- net_node.rs (N2-b): authenticated network node - every post-auth frame
  is Disco | Notes bound to the authenticated peer, disco gossip
  propagates through common peers, a bounded NoteInbox dedupes by the
  public note id, the bounded flood relay decrements the hop budget and
  recomputes the public id, send_notes targets one authenticated peer,
  NotesObserved event, opacusd wiring.
- notes.rs (N3): encrypted note feed - blake3-only ECIES to the recipient
  ristretto identity key (shared = e * pr; session keys via blake3
  derive_key over epk/pr/shared/nonce; keyed-blake3 keystream),
  encrypt-then-MAC verified BEFORE any decryption, an OPAQUE payload
  owned by the wallet layer, a public blake3 id digest any relay can
  verify and dedupe on, and a hop budget a relay can decrement WITHOUT
  keys (the MAC does not cover hops; the relaying node recomputes the
  public id); zero-hop blobs are stored but never relayed.
- Tests: opacus-network 10 -> 61, opacus-node 7 -> 8.

### Changed
- Workspace version bump 0.5.0 -> 0.6.0 (workspace.package plus the
  explicit crate versions in opacus-dex and opacus-zk).
- README: status line retargeted to v0.6.0; networking sections in the
  workspace layout, components, and the test matrix; roadmap updated
  (networking items shipped).
- CI: the rust job now enforces clippy with -D warnings on the whole
  workspace (the README warning-free claim is CI-checked).
- v0.6.0 annotated tag and GitHub release notes.

### Fixed
- CHANGELOG: stray literal backtick-r artifacts in the 0.5.0 entry.

## [0.5.0] - 2026-10-21

- daemon binary renamed to opacusd; daemon struct renamed to OpacusDaemon (crate opacus-node)
- workspace version bump 0.4.0 -> 0.5.0
### Changed
- Rebrand: the workspace moved to the opacusio GitHub org and every crate
  was renamed `ghost-*` -> `opacus-*` (packages, libraries, the
  `cli/ghost` -> `cli/opacus` binary `ghost` -> `opacus`, workspace
  members, cross-crate dependencies, imports, benches, CI and docs).
  Deliberately unchanged: wire-protocol strings (`ghost-swap-p2p-v1,
  `ghost-swap-offer-id-v1`), circuit domain labels (`GHOST/v4/*`), the
  Poseidon label (`ghost-zk-poseidon-v1`) and the wGHOST token.

- Deferred: v4 prover optimization (EC-chain column count, membership-path count) retargeted to the next minor release.
## [0.4.0] - 2026-10-20

Value conservation release: the full FCMP++-style v4 spend pipeline now
enforces in-circuit balance end to end - zk circuit, transaction
serialization, wallet, and consensus - with an activation-height gate, a
prover benchmark, and a documentation refresh
(docs/specs/v0.4-value-conservation.md, sections [S4 1-13]).

### Added

#### crates/ghost-zk - v4 gates and the full spend circuit (phases 1a, 1b, 2)
- v4 foundations: rc-limb range-check gates, v4-hash gates, generator test
  vectors.
- Fixed-base scalar-mul chip: RC = v*V + r*R and the H_leaf*G3 term are
  computed in-circuit as public instances over hashgen constants - no
  in-curve arithmetic needed, the bit columns are shared with the
  range-checked limbs.
- Nullifier-v4 linking, leaf-v2 note commitments, and the value
  commitment primitives (value_commit / value_gen / blind_gen).
- V4SpendCircuit: 1-in / 2-out spend topology (MAX_IN = 2, MAX_OUT = 4)
  with balance padding; 15-slot normative public instance vector
  [root, N_0..N_1, RC_in_0..RC_in_1, RC_out_0..RC_out_3]; k = 13 at
  mainnet tree depth 2^32; binding signature over the instance vector
  (unbalanced or tampered spends fail verification).
- v4_prover: normative instance reconstruction (spend_instances), a
  mock-prover self-check available WITHOUT the real-prover feature, and
  real IPA prove_v4 / verify_v4 (params + keygen + create_proof /
  params + vk rebuild + verify_proof).
- acc_root_point bridge between the Fp accumulator root and the
  curve-point form consumed by sighash_v4.

#### crates/ghost-wallet - tx v4 serialization and zk-native flow (phase 3)
- tx_v4.rs: canonical v4 transaction serialization feeding the exact
  15-slot instance vector; build_zk_spend_v4 and confirm_zk_tx mirroring
  the consensus confirmation order.
- The wallet end-to-end cycle (build / prove / verify / confirm) is green
  at mainnet tree depth 2^32.

#### crates/ghost-consensus - consensus v4 validation (phase 4)
- accept_transaction: v4 validation order [S4 9] - parse, proof verify,
  balance and binding signature, nullifier seen-set, tree root, fee
  floor, commit - with zero state mutation before ALL checks pass.
- Activation-height gate: after CONSENSUS_V4_ACTIVATION_HEIGHT only v4
  transactions are accepted (v3 rejected; a v4 transaction earlier than
  the height is rejected as EarlyV4; legacy structure remains valid only
  before activation).
- ConsensusParams (with testnet()) and ConsensusState (mainnet(), tree +
  seen-set), the Accept/Reject taxonomy, and confirm_v4_consensus.

#### crates/ghost-node - daemon submit gate (phase 4)
- submit_transaction routes every incoming transaction through consensus
  accept_transaction; rejections surface as TxRejected before any pool or
  state effect; the daemon exposes params() and consensus().

#### repository - bench, docs, release (phase 5)
- crates/ghost-zk/benches/prover.rs: deterministic full-pipeline v4 spend
  benchmark (prove_v4 / verify_v4 stage timing) at 2^32 leaves; zero new
  dependencies; run with
  `cargo bench -p ghost-zk --features real-prover --bench prover`.
- README.md refreshed for v0.4.0 (v4 sections, bench, updated test
  matrix, Apache-2.0 license note); workspace version bumped to 0.4.0;
  CHANGELOG updated; v0.4.0 tag and GitHub release published via the
  release_ghost.ps1 path.

### Performance

- Full v4 spend at 2^32 leaves (real IPA, k = 13): the new bench measures
  the prove pipeline at about 16 s on the reference machine against the
  10 s budget [S4 8]; the optimization work (EC-chain column count,
  membership-path count) is queued for v0.5. The membership-only v0.3.0
  baseline (2.1 s prove + verify) is unchanged.

### Security

- Consensus v4 mutates state only after every validation step passes;
  nullifier replay is rejected via the seen-set; the fee floor is
  enforced at consensus level; the activation-height gate prevents mixed
  v3/v4 replay across the fork boundary.

## [0.3.0] - 2026-10-18

Initial public release.

### Added

#### crates/ghost-zk - Halo2 FCMP++ zero-knowledge layer
- Poseidon permutation (t=3, x^5 S-box, 64 uniform full rounds, circ(2,1,1)
  MDS matrix, blake3-derived round constants) over the Pasta (Vesta) scalar
  field, with a commutative tree hash h_tree = P(D, a+b, a*b) that removes
  direction bits from the witness path.
- Sparse Merkle frontier at mainnet tree depth 2^32: empty-subtree-root
  padding gives O(leaves + depth) root and authentication-path computation,
  so the mainnet-size tree is never materialized in memory.
- FcmpCircuit: single-region Halo2 circuit (65 rows per permutation), gates:
  poseidon-round (degree 5 + absorb masking), init-zero, tree-add, tree-mul;
  public instances expose the note-commitment-tree root and the nullifier.
- Real (non-mock) prover/verifier over Vesta behind the `real-prover`
  feature, using the halo2_proofs 0.3.5 IPA commitment scheme (zcash
  lineage): batch create_proof, plonk::SingleVerifier verification.
- Tests: 10 default + 11 with `real-prover` (real IPA prove/verify plus
  tamper rejection) + a mainnet-depth MockProver check (k=12, 2342 rows);
  a real spend proof at mainnet tree depth 2^32 proves and verifies in
  about 2.1 s.

#### crates/ghost-wallet - shielded wallet layer
- zk_spend.rs: canonical Fp <-> 32-byte serialization, persistable
  WalletNote, in-memory TreeState with a mainnet() constructor, witness
  builder, and ZkSpendTx build/verify helpers that prove and self-verify
  BEFORE any wallet state mutation.
- light_wallet.rs rewritten zk-native while preserving the public API:
  shielded balance (total/spendable/pending), incoming-note confirmation,
  build_zk_spend with single-note selection and change handling,
  confirm_zk_tx mirroring consensus (all output commitments appended to
  the tree in transaction order), a nullifier seen-set registry, and tree
  introspection helpers.
- End-to-end mainnet-depth test: full build/prove/verify/confirm cycle of
  a shielded payment at tree depth 2^32.

#### crates/ghost-bridge - Monero bridge
- xmr_dleq.rs: cross-group Schnorr DLEq proving that one scalar controls
  both the Monero/Edwards key and the Ristretto key (blake3 challenge,
  wide mod-l reduction, 96-byte serialization).
- xmr_swap.rs: atomic-swap state machine Offered -> Accepted -> XmrLocked
  -> GhostLocked -> Claimed/Refunded with fund/claim timeouts, Maker/Taker
  roles, blake3 hashlock, and observable lock transitions.
- xmr_rpc.rs: monero-wallet-rpc client (transfer with unlock_time and
  payment_id = hashlock, get_transfers filtered by payment_id, balance and
  address queries) plus monerod get_info, behind a Transport trait with
  fake-transport tests.
- swap_p2p.rs: swap P2P protocol core - SwapNetMessage enum (Offer, Accept,
  XmrLocked, GhostLocked carrying the preimage, Claim, Refund), u32-LE
  length-prefixed JSON framing, tamper-evident blake3 offer ids, and a
  session registry that reuses the xmr_swap state machine as the single
  source of truth (replay, duplicate, forged-claim and timeout validation).

#### crates/ghost-dex - Ethereum side (new crate)
- Minimal RLP encoder/decoder verified against known vectors.
- ABI encoding with keccak selectors (Uniswap V2 well-known selectors
  verified), including head/tail encoding with dynamic offsets.
- Legacy EIP-155 transaction signer (k256 ecdsa): keccak256 prehash, v =
  parity + 35 + 2*chainId, with a raw-transaction roundtrip test that
  recovers the sender address.
- Uniswap Router02 (0x7a25...) calldata builders: getAmountsOut,
  swapTokensForTokens / swapTokensForETH, WETH wrap, ERC-20
  approve/transfer/balanceOf.
- Ethereum JSON-RPC client (eth_call, gasPrice, transaction nonce,
  estimateGas, sendRawTransaction) over blocking HTTP with fake-transport
  tests.
- wGHOST helpers: set_wghost/burn calldata and Mint/Burn event topics.

#### crates/ghost-network - swap node
- swap_node.rs: TCP swap node reusing ghost-bridge::swap_p2p - framed
  socket I/O with declared-length caps, SwapNodeConfig, listener plus
  bootstrap dialing, a full-duplex connection loop with automatic protocol
  replies (Offer->Accept, GhostLocked->Claim) on the same socket,
  protocol-violation disconnects, and a bounded node-event ring log.
- End-to-end test: complete swap choreography Offer -> Accept -> XmrLocked
  -> GhostLocked (preimage) -> Claim across two live TCP nodes on
  127.0.0.1:0.

#### contracts/ - wGHOST token
- wGHOST.sol: ERC-20 wrapper with quorum-gated mint (sorted-signature
  ecrecover check) and burn-for-release; deployed to the Sepolia testnet
  (address tracked in contracts/wghost.address), quorum threshold 1/1 for
  testnet. Marked AUDIT REQUIRED.
- wGHOST.s.sol + foundry.toml: reproducible forge deployment script with
  environment-configured quorum signers (kept minimal pending forge-std
  restore).

#### Repository root - zero-typing Windows tooling (PowerShell)
- Sepolia deploy chain: run_sepolia_deploy.ps1 (funds gate, in-process
  deployer key) -> deploy_wghost.ps1 -> finalize_wghost.ps1 (bytecode gate,
  soft token calls, hard quorum cross-checks, WGHOST_ADDRESS persistence).
- fix_deployer_key.ps1: zero-input deployer key rotation with
  cross-verification.
- publish_ghost.ps1: safe one-command GitHub publish (secret gates, no
  force-push).

### Fixed
- ghost-zk did not compile (16 errors: E0061/E0382/E0425/E0599): the crate
  was adapted to the actual halo2_proofs 0.3.5 (zcash lineage) API -
  closure-based assign_advice/assign_fixed, query_fixed without rotation,
  Selector::enable instead of Region::enable_selector, AssignedCell::
  copy_advice instead of assign_advice_from, constrain_instance taking
  Cell by value, batch create_proof with triple-nested instances, and
  plonk::SingleVerifier; ff 0.13 has no Fp::from_u64.
- Out-of-memory in tree root computation: materializing 2^32 leaves
  (about 137 GB) replaced by empty-subtree-root padding.
- EIP-155 signing originally used SHA-256 as the prehash - replaced with
  keccak256 and the correct v = parity + 35 + 2*chainId.
- ghost-bridge Cargo.toml crashed cargo ("cannot extend value of type
  inline table with a dotted key") when dependency insertion met
  workspace-inheritance manifests (serde.workspace = true): the manifest
  was repaired to a self-contained form; non-conflicting workspace
  inheritance is preserved.
- u128_to_be32 wrote 16 bytes into an 8-byte slot; approve test word
  offset; RLP long-form list header (0xF8) offset; RPC fake envelope
  shape.

### Security
- Deployer key hygiene: the globally known public Foundry anvil #0 key
  (0xf39F...92266) was detected as the Sepolia deployer and sole quorum
  member (anyone could mint wGHOST) and rotated to a freshly generated
  random key. deployer.key is never committed; the old key is kept only in
  a local git-ignored .bak file.
- Repository publishing excludes secrets by construction: a .gitignore
  guard set (deployer.key*, *.key, *.pem, .env*, *.bak*, tools/, build
  artifacts) plus an index-level secret gate that untracks offenders while
  keeping the files on disk; commits use the noreply GitHub identity.

### Test status (zero warnings in all crates)
- ghost-zk: 10 + 11 (real-prover) + 1 mainnet-depth mock
- ghost-wallet: 7 fast + 2 mainnet-depth end-to-end
- ghost-bridge: 27 | ghost-dex: 13 | ghost-network: 8

### Known limitations / roadmap
- Value conservation is not yet enforced in-circuit (v0.4 accumulator per
  the complete FCMP++ design); nullifier-reuse prevention is currently
  consensus-side.
- Swap enforcement is off-chain in v0.1: hashlock-in-circuit and CLSAG
  adaptor signatures are planned for v0.4; Refund frames are notices;
  swap heights are taken from configuration.
- ghost-network has direct dials only; peer discovery/gossip and peer
  authentication (DLEq-bound identities) are planned next.
- Encrypted note transmission between wallets (out-of-band note-secret
  transfer today) is a networking-phase item.
- An external audit is REQUIRED before any mainnet use; testnet keys are
  throwaway and never committed.
