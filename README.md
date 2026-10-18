# Ghost

Ghost is a privacy payment network that fuses the proven transaction model of
Monero (ring-CT semantics, stealth addresses, Pedersen commitments) with
zk-SNARK spend anonymity in the spirit of Zcash Halo2 / FCMP++: every spend
carries a succinct proof that its key material belongs to the global set of
all wallet keys. Around the shielded core, Ghost ships an Ethereum-side
wrapped token (wGHOST), a DEX/bridge toolchain, and an atomic-swap stack for
Monero <-> Ghost exchange, together with a zero-typing Windows (PowerShell)
tooling chain.

> **Status: v0.3.0 - first public release. Test networks only. An independent
> security audit is REQUIRED before any mainnet use.**

## How the privacy works

- **Monero-style transaction layer.** Payments follow ring-CT semantics:
  Pedersen commitments hide amounts, stealth addresses hide recipients.
- **FCMP++-style membership proofs.** A Halo2 circuit (FcmpCircuit) proves in
  zero knowledge that the spend key is a member of the global
  note-commitment tree at mainnet depth 2^32, and reveals only a nullifier.
- **Transparent proving system.** Proofs are built and verified with
  halo2_proofs 0.3.5 (zcash lineage) and its IPA commitment scheme over the
  Pasta (Vesta) scalar field - no trusted setup.
- **Commutative tree hashing.** The tree hash is h_tree = P(D, a+b, a*b) with
  Poseidon (t=3, x^5 S-box, 64 uniform full rounds, circ(2,1,1) MDS matrix,
  blake3-derived round constants), which removes direction bits from the
  witness path.
- **Constant-memory tree.** A sparse Merkle frontier with empty-subtree-root
  padding computes the 2^32-leaf root and authentication paths in
  O(leaves + depth) without ever materializing the tree (the naive approach
  would need about 137 GB of RAM).

## Workspace layout

| Path | Contents |
|------|----------|
| `crates/ghost-zk` | Halo2 FCMP++ zero-knowledge layer: Poseidon, sparse frontier, FcmpCircuit, real IPA prover |
| `crates/ghost-wallet` | Shielded wallet: zk spend build/prove/self-verify, zk-native light wallet |
| `crates/ghost-bridge` | Monero bridge: cross-group DLEq, atomic-swap state machine, Monero RPC, swap P2P protocol |
| `crates/ghost-dex` | Ethereum side: RLP, ABI, EIP-155 signer, Uniswap Router02 calldata, JSON-RPC client, wGHOST helpers |
| `crates/ghost-network` | TCP swap node with automatic protocol replies |
| `contracts/` | wGHOST.sol (quorum-mint ERC-20 wrapper) + Foundry deployment script and tests |
| repo root | Zero-typing PowerShell tooling: Sepolia deploy chain, key rotation, GitHub publish |

## Components

### ghost-zk (Halo2 FCMP++ zero-knowledge layer)

- Poseidon permutation over the Pasta (Vesta) scalar field (t=3, x^5 S-box,
  64 uniform full rounds, circ(2,1,1) MDS matrix, blake3-derived round
  constants).
- Sparse Merkle frontier at mainnet tree depth 2^32; empty-subtree-root
  padding gives O(leaves + depth) root and authentication-path computation.
- FcmpCircuit: single-region circuit (65 rows per permutation) with gates
  poseidon-round (degree 5 + absorb masking), init-zero, tree-add, tree-mul;
  public instances expose the note-commitment-tree root and the nullifier.
- Real (non-mock) prover/verifier behind the `real-prover` feature: batch
  create_proof and plonk::SingleVerifier verification on
  halo2_proofs 0.3.5 (IPA, zcash lineage).

### ghost-wallet (shielded wallet layer)

- `zk_spend.rs`: canonical Fp <-> 32-byte serialization, persistable
  WalletNote, in-memory TreeState with a `mainnet()` constructor, witness
  builder, and ZkSpendTx build/verify helpers that prove and self-verify
  BEFORE any wallet state mutation.
- `light_wallet.rs` is zk-native while preserving the public API: shielded
  balance (total/spendable/pending), incoming-note confirmation,
  `build_zk_spend` with single-note selection and change handling,
  `confirm_zk_tx` mirroring consensus, a nullifier seen-set registry, and
  tree introspection helpers.
- End-to-end mainnet-depth test: full build/prove/verify/confirm cycle of a
  shielded payment at tree depth 2^32.

### ghost-bridge (Monero bridge)

- `xmr_dleq.rs`: cross-group Schnorr DLEq proving that one scalar controls
  both the Monero/Edwards key and the Ristretto key (blake3 challenge, wide
  mod-l reduction, 96-byte serialization).
- `xmr_swap.rs`: atomic-swap state machine Offered -> Accepted -> XmrLocked
  -> GhostLocked -> Claimed/Refunded with fund/claim timeouts, Maker/Taker
  roles, blake3 hashlock.
- `xmr_rpc.rs`: monero-wallet-rpc client (transfer with unlock_time and
  payment_id = hashlock, get_transfers filtered by payment_id, balance and
  address queries) plus monerod get_info, behind a Transport trait.
- `swap_p2p.rs`: SwapNetMessage protocol with u32-LE length-prefixed JSON
  framing, tamper-evident blake3 offer ids, and a session registry that
  reuses the swap state machine as the single source of truth (replay,
  duplicate, forged-claim and timeout validation).

### ghost-dex (Ethereum side)

- Minimal RLP encoder/decoder verified against known vectors.
- ABI encoding with keccak selectors (Uniswap V2 well-known selectors
  verified), including head/tail encoding with dynamic offsets.
- Legacy EIP-155 transaction signer (k256): keccak256 prehash,
  v = parity + 35 + 2*chainId, with a roundtrip test that recovers the
  sender address.
- Uniswap Router02 (0x7a25...) calldata builders: getAmountsOut,
  swapTokensForTokens / swapTokensForETH, WETH wrap, ERC-20
  approve/transfer/balanceOf.
- Ethereum JSON-RPC client (eth_call, gasPrice, nonce, estimateGas,
  sendRawTransaction) with fake-transport tests.
- wGHOST helpers: set_wghost/burn calldata and Mint/Burn event topics.

### ghost-network (swap node)

- TCP swap node reusing ghost-bridge::swap_p2p: framed socket I/O with
  declared-length caps, SwapNodeConfig, listener plus bootstrap dialing, a
  full-duplex connection loop with automatic protocol replies
  (Offer -> Accept, GhostLocked -> Claim) on the same socket,
  protocol-violation disconnects, and a bounded node-event ring log.
- End-to-end test: complete swap choreography across two live TCP nodes on
  127.0.0.1:0.

### contracts (wGHOST token)

- `wGHOST.sol`: ERC-20 wrapper with quorum-gated mint (sorted-signature
  ecrecover check) and burn-for-release; deployed to the Sepolia testnet
  (address tracked in `contracts/wghost.address`), quorum threshold 1/1 for
  testnet. Marked AUDIT REQUIRED.
- `wGHOST.s.sol` + `foundry.toml`: reproducible forge deployment script with
  environment-configured quorum signers.

## Build and test

Prerequisites: a recent stable Rust toolchain (rustup), Git; Foundry (forge)
for the contracts.

```
git clone https://github.com/kopylovap-prog/ghost.git
cd ghost

cargo build --release
cargo test --workspace

# real (non-mock) IPA prover tests:
cargo test -p ghost-zk --features real-prover

# contracts (Foundry):
forge build --root contracts
forge test --root contracts
```

Test status (zero warnings in all crates):

| Crate | Tests |
|-------|-------|
| ghost-zk | 10 default + 11 real-prover + 1 mainnet-depth mock (k=12, 2342 rows) |
| ghost-wallet | 7 fast + 2 mainnet-depth end-to-end |
| ghost-bridge | 27 |
| ghost-dex | 13 |
| ghost-network | 8 |

A real spend proof at mainnet tree depth (2^32 leaves) proves and verifies
in about 2.1 s.

## Sepolia deployment (zero-typing PowerShell chain)

1. `run_sepolia_deploy.ps1` - funds gate, in-process deployer key.
2. `deploy_wghost.ps1` - deploys wGHOST.sol to Sepolia.
3. `finalize_wghost.ps1` - bytecode gate, soft token calls, hard quorum
   cross-checks, persists the address to `contracts/wghost.address`.

Also at the repo root: `fix_deployer_key.ps1` (zero-input deployer key
rotation with cross-verification) and `publish_ghost.ps1` (safe one-command
GitHub publish with secret gates and no force-push).

## Security notes

- `deployer.key*` is never committed; the globally known public Foundry
  anvil #0 test key was detected as the deployer and rotated to a freshly
  generated random key (the old key survives only in a local git-ignored
  .bak file).
- Publishing excludes secrets by construction: a `.gitignore` guard set
  (`deployer.key*`, `*.key`, `*.pem`, `.env*`, `*.bak*`, `tools/`, build
  artifacts) plus an index-level secret gate that untracks offenders while
  keeping the files on disk.
- Commits use the noreply GitHub identity.
- The wGHOST mint is quorum-gated; the testnet quorum is 1/1. An external
  audit is REQUIRED before any mainnet use; testnet keys are throwaway.

## Roadmap (v0.4)

- Value conservation enforced in-circuit (accumulator per the complete
  FCMP++ design); nullifier-reuse prevention is currently consensus-side.
- Hashlock-in-circuit and CLSAG adaptor signatures for on-chain swap
  enforcement (Refund frames are notices in v0.1).
- Peer discovery/gossip and DLEq-bound peer authentication for
  ghost-network.
- Encrypted note transmission between wallets.
- External audit before any mainnet use.

## Versioning and changelog

`CHANGELOG.md` follows the
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format and
[Semantic Versioning](https://semver.org/). The current release is
**v0.3.0** (first public release).

## License

No open-source license has been selected yet; all rights are reserved by the
author until a LICENSE file is added.
