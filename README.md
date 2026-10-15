# Ghost

**Private. Instant. Bridgeable.**

Privacy L1: mandatory privacy (FCMP++), light client sync, XMR bridge, CPU miner.

## Quick start

    cargo build --release
    .\target\release\ghost.exe create-wallet
    .\target\release\ghost.exe mine --solo --duration 60
    .\target\release\ghostd.exe

## Commands

| Command | Description |
|---|---|
| ghost create-wallet | Create wallet |
| ghost restore-wallet --seed ... | Restore from seed |
| ghost address / ghost balance | Address / balance |
| ghost start | Start node |
| ghost mine --solo --duration N | Solo mining N seconds |

## Crates

ghost-crypto, ghost-consensus, ghost-light-client, ghost-wallet,
ghost-network, ghost-node, ghost-bridge, ghost-miner

BSD-3-Clause