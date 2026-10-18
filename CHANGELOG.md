# Changelog

All notable changes to the **Ghost** monorepo are documented in this file.
The initial public release consolidates the full pre-history of the private
development phase; every further change will be added here following the
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format and
[Semantic Versioning](https://semver.org/).

Ghost is a privacy payment network that fuses Monero-style ring-CT semantics
with Zcash-style Halo2 FCMP++ spend proofs, plus an Ethereum-side wrapped
token (wGHOST) and tooling for bridging, DEX swaps and atomic swaps.

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
