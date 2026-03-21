# IronDivi

**A modern Rust implementation of the Divi cryptocurrency full node.**

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![CI](https://github.com/DiviDomains/IronDivi/actions/workflows/ci.yml/badge.svg)](https://github.com/DiviDomains/IronDivi/actions/workflows/ci.yml)
[![Language: Rust](https://img.shields.io/badge/Language-Rust-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)]()

## Overview

IronDivi is a ground-up Rust reimplementation of the [Divi Core](https://github.com/DiviProject/Divi) full node. It supports full block validation, Proof-of-Stake (PoS) consensus, wallet management with HD key derivation, peer-to-peer networking, and JSON-RPC API compatibility with Divi Core.

The goal is to provide a memory-safe, performant, and well-structured alternative to the C++ reference implementation while maintaining full consensus compatibility.

## Features

- [x] Full block validation and chain sync
- [x] Proof-of-Stake (PoS) staking with coin-age weighting
- [x] HD wallet with BIP39/BIP32 key derivation
- [x] Masternode tier support (Copper through Diamond)
- [x] Lottery and treasury block validation
- [x] Vault staking support
- [x] JSON-RPC API (Divi Core compatible)
- [x] Peer-to-peer network protocol (protocol v70920)
- [x] UTXO set management with RocksDB
- [x] Address and spent indexing (txindex)
- [x] Fee estimation
- [x] Multi-chain support (Divi, PrivateDivi)

## Architecture

```
┌─────────────────────────────────────────────┐
│                  irondivid                   │
│              (Full Node Binary)              │
├──────────┬──────────┬──────────┬────────────┤
│ divi-rpc │ divi-node│divi-wallet│divi-network│
├──────────┴──────────┴──────────┴────────────┤
│            divi-consensus                    │
├──────────┬──────────┬───────────────────────┤
│divi-script│divi-storage│  divi-masternode    │
├──────────┴──────────┴───────────────────────┤
│   divi-crypto    │    divi-primitives        │
└──────────────────┴──────────────────────────┘
```

The codebase is organized as a Cargo workspace with clearly separated concerns. Low-level primitives and cryptography sit at the bottom, with higher-level node logic, wallet, networking, and RPC built on top.

## Getting Started

### Prerequisites

- **Rust 1.75+** (install via [rustup](https://rustup.rs/))
- **C compiler** (gcc or clang, required for sphlib Quark hash)
- **RocksDB dependencies** (`libclang-dev` on Debian/Ubuntu)

### Build from Source

```bash
git clone https://github.com/DiviDomains/IronDivi.git
cd IronDivi
cargo build --release
```

Binaries are written to `target/release/irondivid` (full node) and `target/release/irondivi-cli` (RPC client).

## Usage

```bash
# Run on Divi mainnet
./target/release/irondivid --mode divi

# Run on Divi testnet
./target/release/irondivid --mode divi --testnet

# Run on PrivateDivi testnet
./target/release/irondivid --mode privatedivi --testnet
```

### RPC Example

Query the node via JSON-RPC (default port 51473 for Divi mainnet):

```bash
curl -u rpc:rpc http://127.0.0.1:51473 \
  -d '{"jsonrpc":"2.0","method":"getblockchaininfo","params":[],"id":1}'
```

## Crate Overview

| Crate | Description |
|-------|-------------|
| `divi-primitives` | Core types: blocks, transactions, hashes, amounts, compact targets |
| `divi-crypto` | Cryptographic operations: secp256k1 keys, BIP38, Quark hashing, signatures |
| `divi-script` | Script parsing, evaluation, and standard script templates |
| `divi-consensus` | Consensus rules: block subsidies, PoS target calculation, lottery logic |
| `divi-masternode` | Masternode tier definitions and collateral validation |
| `divi-storage` | RocksDB-backed block index, UTXO cache, address/spent indexes, spork store |
| `divi-network` | P2P protocol: message serialization, peer management, handshake |
| `divi-wallet` | HD wallet: key derivation, coin selection, coinstake building, signing |
| `divi-rpc` | JSON-RPC server with Divi Core-compatible command set |
| `divi-node` | Full node orchestration: chain management, staking loop, fee estimation |

## Testing

```bash
# Run the full test suite
cargo test --workspace

# Check formatting
cargo fmt --all -- --check

# Run lints
cargo clippy --workspace -- -D warnings
```

## RPC Compatibility

IronDivi implements a subset of the Divi Core JSON-RPC interface. Supported commands include `getblockchaininfo`, `getblock`, `getrawtransaction`, `sendrawtransaction`, `getbalance`, `listunspent`, `getnewaddress`, `signmessage`, `verifymessage`, and more. The goal is wire-level compatibility so that existing tools and scripts work without modification.

## License

IronDivi is licensed under the **GNU Affero General Public License v3.0** (AGPL-3.0-only). See [LICENSE](LICENSE) for the full text.

Portions of this software are derived from [Divi Core](https://github.com/DiviProject/Divi), which is licensed under the MIT License. See [LICENSE-MIT-UPSTREAM](LICENSE-MIT-UPSTREAM) for details.

**Commercial licensing** is available for organizations that cannot comply with the AGPL. Contact [license@cri.xyz](mailto:license@cri.xyz) for details.

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to get started.

## Security

If you discover a security vulnerability, please report it responsibly. See [SECURITY.md](SECURITY.md) for details.

## Acknowledgments

IronDivi builds on the work of many open-source projects and their contributors:

- [Bitcoin Core](https://github.com/bitcoin/bitcoin) -- the original cryptocurrency implementation
- [Dash](https://github.com/dashpay/dash) -- masternode and governance extensions
- [PIVX](https://github.com/PIVX-Project/PIVX) -- Proof-of-Stake consensus
- [Divi Core](https://github.com/DiviProject/Divi) -- the reference C++ implementation this project reimplements
