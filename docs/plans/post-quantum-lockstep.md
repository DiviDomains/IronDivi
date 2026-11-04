# Plan: Lockstep Post-Quantum Cryptography & Protocol Upgrades (`divid` C++ + `irondivid` Rust)

Status: active architectural policy & phased engineering plan, 2026-11-04.
Applies to: canonical C++ Divi Core (`DiviProject/Divi`, `divid` v3.0.0, commit `9e2f76c44`) and Rust IronDivi (`DiviDomains/IronDivi`, `irondivid`).

---

## 1. Standing Architectural Policy: Dual-Client Lockstep (No C++ Sunset)

IronDivi does **not** replace, deprecate, or retire the canonical C++ Divi Core (`divid`) implementation (`https://github.com/DiviProject/Divi`).

Both `divid` (C++11) and `irondivid` (Rust) are permanently maintained as first-class, co-equal mainnet implementations that evolve in **strict consensus and protocol lockstep**:

1. **Client diversity is a consensus safety guarantee.** Maintaining two independent implementations (C/C++11 and Rust) with independent memory models, independent cryptographic libraries, and shared side-by-side verification harnesses (`scripts/*`, `tools/block-comparator`, `tools/cpp-test-extractor`) ensures that an implementation bug in either codebase halts cleanly at a disagreement rather than silently corrupting the chain.
2. **One specification, two implementations, simultaneous activation.** Every change to block validity, transaction serialization, script evaluation, Proof-of-Stake block signing, Spork verification, or cross-wallet mnemonic/HD address derivation must be specified once in a Divi Improvement Proposal (DIP) with canonical JSON test vectors, implemented in **both** `divid` and `irondivid`, proven interoperable on mixed regtest/testnet clusters, and activated at the exact same MedianTimePast (`divi/src/ForkActivation.cpp`) or BIP9 version bit (`divi/src/BIP9Deployment.h`).
3. **Intentional differences remain strictly non-consensus.** Operational, storage, and RPC ergonomics where `irondivid` intentionally differs from `divid` remain bounded and test-pinned in [`docs/divid-differences.md`](../divid-differences.md). Consensus rules never diverge.

---

## 2. Cryptographic Baseline & Quantum Exposure Summary

### 2.1 Primitives Already Post-Quantum Safe (Keep Unchanged)

Against **Grover's algorithm** ($O(\sqrt{N})$ quantum search), 256-bit hashes, KDFs, and authenticated symmetric ciphers retain $\ge 128$-bit post-quantum security (NIST Category 5) and require **no replacement**:

| Subsystem | C++ `divid` (`divi/src/`) | Rust `irondivid` (`crates/`) | Quantum Margin |
|---|---|---|---|
| Block, Merkle, txid & PoS kernel hashing | `CHash256` double SHA-256 (`hash.h:32-58`); legacy `nVersion < 4` 9-stage 512-bit `HashQuark` (`hash.h:274-360`) | `double_sha256` (`divi-crypto/src/hash.rs:36-40`) & `hash_quark` (`divi-crypto/src/quark.rs`) | $2^{128}$ preimage (Safe) |
| BIP39 master seed & hardened BIP32 | `HMAC-SHA512` (`key.cpp:224-261`, `bip39.cpp`) | `PBKDF2-HMAC-SHA512` + hardened `HMAC-SHA512` (`divi-wallet/src/hd.rs`) | $\ge 2^{128}$ (Safe — existing 24-word mnemonics can deterministically derive future PQ keys) |
| IronDivi wallet at rest | *See §3.1 for C++ `CCrypter` upgrade* | `Argon2id` (`64 MiB, t=3, p=1`) + `XChaCha20-Poly1305` AEAD (`divi-wallet/src/at_rest.rs:29-223`) | $2^{128}$ key + information-theoretic MAC (Safe) |
| BIP38 symmetric key wrap | `scrypt` + `AES-256` (`bip38.cpp`) | `scrypt(N=16384, r=8, p=8)` + `Aes256` (`divi-crypto/src/bip38.rs:51-125`) | Cipher is $2^{128}$ safe (inner `secp256k1` key requires PQ counterpart) |

### 2.2 Primitives Broken by a Cryptographically Relevant Quantum Computer (Shor's Algorithm)

Every elliptic-curve discrete-logarithm primitive (`secp256k1`, `X25519`, `ed25519`) is broken in polynomial time by **Shor's algorithm**. Because early fault-tolerant quantum machines will require hours to days per key recovery (rather than sub-minute mempool attacks), **static public keys already exposed on-chain or over P2P fail years before unspent `Hash160` addresses**:

1. **Hardcoded Network Spork Key (`P0` — Offline Governance Target):**
   - `divi/src/chainparams.cpp:254` and `crates/divi-network/src/spork.rs` verify `CSporkMessage` signatures against a single hardcoded compressed `secp256k1` public key (`strSporkKey`). Compromising `strSporkKey` offline allows forging consensus-affecting Sporks (`SPORK_8`, `SPORK_13_BLOCK_PAYMENTS`, `SPORK_14_TX_FEE`, `SPORK_15_BLOCK_VALUE`, `SPORK_16_LOTTERY_TICKET_MIN_VALUE`).
2. **Harvest-Now-Decrypt-Later Transport & Diagnostic Uploads (`P0` — Active Wire Recording):**
   - `crates/divi-diag/src/consent.rs:62` encrypts diagnostic bundles to a static `age::x25519::Recipient`.
   - `crates/divi-electrum/Cargo.toml:24` and `bin/irondivid/Cargo.toml:75` configure `rustls 0.23` with `ring` (classical `ECDHE` only, without hybrid `X25519MLKEM768`).
3. **Direct PoS Staking & Un-Swept Legacy Masternode Keys (`P1` — Exposed On-Chain `CPubKey`):**
   - `divi/src/BlockSigning.cpp:128-139` and `crates/divi-node/src/staker.rs:1008-1038` sign PoS blocks with a 65-byte compact recoverable `secp256k1` signature (`vchBlockSig`), from which peers recover the full `CPubKey` (`RecoverCompact`) on the staker's very first minted block.
   - Although `Fork::DeprecateMasternodes` (`divi/src/ForkActivation.cpp:31`) activated on mainnet in August 2023, any historical Masternode collateral UTXO that previously broadcast `mnb.pubKeyCollateralAddress` (`divi/src/MasternodeBroadcastFactory.cpp:165`) and has never been swept to a fresh address already has its `CPubKey` recorded publicly.
4. **BIP32 Non-Hardened `xpub` Sharing (`P1`):**
   - Exporting an account extended public key (`m/44'/301'/account'`) exposes the parent `secp256k1` public key + chain code; Shor recovery of the parent private key compromises every non-hardened child (`change/index`) even if no child has ever spent.
5. **Staking Vault Insulation (`P2` — Architectural Bright Spot):**
   - `STAKING_VAULT(ownerKeyHash, vaultKeyHash)` (`divi/src/script/StakingVaultScript.cpp:9-12`, `crates/divi-script/src/vault.rs:19-27`) reveals only the manager key (`vaultKeyHash`) during coinstake signing, keeping `ownerKeyHash` hidden behind `Hash160` until an owner-branch (`OP_IF`) spend.
   - Consensus enforces that vault coinstake outputs return principal + stake reward to the exact `vaultScript` (`divi/src/BlockTransactionChecker.cpp:57-109`), burns all PoS transaction fees (`divi/src/BlockConnectionService.cpp:67-74`), and credits lottery payouts to `vaultScript` (`divi/src/BlockIncentivesPopulator.cpp:123-138`). Breaking `vaultKeyHash` via Shor **cannot** steal principal, stake rewards, fees, or lottery payouts while `ownerKeyHash` remains unexposed.
6. **160-Bit Address Hashing (`CHash160` — Long-Term Grover Bound):**
   - `RIPEMD160(SHA256(pk))` has a $2^{80}$ quantum preimage bound. New post-quantum output types will upgrade script/key commitments to full 256-bit `SHA-256` ($2^{128}$ quantum preimage margin).

---

## 3. Upgrade Boundary Classification: Independent vs. Negotiated vs. Strict Lockstep

To avoid accidental forks while keeping engineering velocity high, every quantum-readiness task is assigned to one of three coordination tiers:

| Tier | Rule | Scope |
|---|---|---|
| **Tier A — Client-Local / Off-Chain** | May ship in `irondivid` or `divid` independently on normal point releases; zero wire or consensus change | 1. `divi-diag` hybrid `X25519 + ML-KEM-768` encryption (`irondivid` only)<br>2. `divi-electrum` & RPC TLS 1.3 hybrid `X25519MLKEM768` (`irondivid` + OpenSSL 3.5+ on `divid` TLS proxies)<br>3. C++ `divid` `wallet.dat` KDF upgrade (`CCrypter` `nDerivationMethod = 1` in `divi/src/crypter.cpp:48-56` adding `Argon2id` + authenticated key wrapping while keeping `nDerivationMethod = 0` readable)<br>4. Wallet UI/CLI Vault-first staking defaults & hardened-only HD account option |
| **Tier B — Capability-Negotiated P2P** | Negotiated per peer via `nServices` / version handshake with automatic v1 plaintext TCP fallback; designed from one shared spec for both clients | Post-quantum hybrid encrypted P2P transport (v2 framing with `X25519 + ML-KEM-768` + `ChaCha20-Poly1305`, inspired by BIP-324 + FIPS 203) in `divi/src/net.cpp` and `crates/divi-network/` |
| **Tier C — Strict Dual-Client Lockstep** | **MUST** be specified in a shared DIP, pass cross-FFI differential fuzzing + `scripts/interop` mixed-cluster gates, and activate at the exact same MedianTimePast / BIP9 deployment in **both** `divid` and `irondivid` | 1. Deterministic PQ HD key derivation from BIP39 24-word mnemonics (`-mnemonic` / `dumphdinfo` restore parity across `divid` and `irondivid`)<br>2. Hybrid & post-quantum Spork signing/verification (`DIP-PQ-2`)<br>3. Segregated post-quantum witness serialization, 256-bit `P2PQPKH` & `PQ_STAKING_VAULT` scripts (`DIP-PQ-3`)<br>4. Post-quantum PoS `vchBlockSig` block signing (`DIP-PQ-4`) |

---

## 4. Solving Dual-Language Consensus Bit-Parity (C/C++11 vs. Rust)

The single highest technical risk in a dual-client post-quantum upgrade is a **verification edge-case divergence** between C++ `divid` and Rust `irondivid` — for example, one verifier accepting a non-canonical `ML-DSA` hint vector, trailing signature byte, or borderline `FN-DSA` $L_2$ norm that the other rejects, splitting mainnet.

### 4.1 Build & Dependency Architecture in Each Client

1. **Canonical C++ `Divi` (`divi/src/pqcrypto/`):**
   - `divi/configure.ac:59-60` enforces strict `-std=c++11` (`AX_CXX_COMPILE_STDCXX([11], [noext], [mandatory])`) and builds embedded C subtrees (`src/secp256k1` in `divi/src/Makefile.am:1,23,55-56`) plus deterministic cross-compiled `depends/packages/*.mk`.
   - Rather than pulling in CMake-heavy external C++17 libraries, vendor audited, self-contained **C99** implementations derived from **PQClean / NIST reference code** (`CC0` / `MIT` / public domain) under `divi/src/pqcrypto/`, wired into `Makefile.am` (`libdivi_pqcrypto.a`) with portable C99 baseline builds for all targets (`x86_64`, `aarch64`, `armv7` 32-bit ARM, `mingw`, `macOS`, `FreeBSD`) and optional runtime CPU-dispatched AVX2/NEON backends.
2. **Rust `IronDivi` (`crates/divi-crypto/src/pq/`):**
   - Use pure-Rust, permissively licensed (`Apache-2.0 OR MIT`) crates (`ml-dsa`, `slh-dsa`, `ml-kem`, and integer-verified `fn-dsa`) that preserve static `musl` builds across all release tarballs (`README.md:56-66`) and pass `tools/release-check.sh` (`cargo deny` against `deny.toml` + `cargo audit`).
3. **Zero Floating-Point in Consensus Verification:**
   - Every consensus signature verifier (`ML-DSA`, `FN-DSA`, `SLH-DSA`, `LMS`) executes strictly in fixed-width integer arithmetic. (While `FN-DSA` / Falcon *signing* uses floating-point or emulated fixed-point Gaussian sampling off-consensus, `FN-DSA` *verification* is pure `uint16_t` NTT modulo `12289` plus exact integer squared-norm comparison.)

### 4.2 Mandatory Cross-Implementation Differential Fuzzing Gate

No post-quantum primitive may be wired into `divi-script`, `divi-consensus`, or `BlockSigning` until all three parity gates pass in CI:

1. **Shared Canonical Vector Suite (`tests/vectors/pq/`):**
   - NIST ACVP Known-Answer Tests (KATs) **plus** adversarial consensus edge-case vectors: non-canonical bit packings, out-of-range polynomial coefficients (`>= q`), malformed `ML-DSA` hint ordering/counts, exact norm-boundary signatures (`norm == bound` and `norm == bound + 1`), empty/oversized public keys, and domain-separation tag mismatches.
   - Consumed identically by `divi/src/test/pqcrypto_tests.cpp` (Boost.Test) and `crates/divi-crypto/tests/pq_vectors.rs`.
2. **Direct C-vs-Rust Differential Fuzzer (`tools/pq-diff-fuzz`):**
   - A `cargo fuzz` / `libfuzzer` harness that compiles `divi/src/pqcrypto/*.c` via `cc` and calls C `divi_pq_verify(...)` and Rust `divi_crypto::pq::verify(...)` on identical fuzzed `(scheme, pubkey, domain_tag, msg, sig)` inputs.
   - **Exit criterion:** `>= 10,000,000` mutated/structure-aware fuzz executions per algorithm with **zero** boolean return-value discrepancies (`assert_eq!(c_ok, rust_ok)`).
3. **Deterministic HD Seed-to-Key Vector Parity:**
   - Given the same 24-word BIP39 mnemonic + optional passphrase, `divid` and `irondivid` must derive byte-for-byte identical PQ secret keys, public keys, and encoded addresses across mainnet (`coin_type = 301`) and testnet/regtest (`coin_type = 1`), extending [`docs/divid-differences.md`](../divid-differences.md) `W5` and `scripts/hdseed-mnemonic`.

---

## 5. Candidate Post-Quantum Signature Trade-Offs (`2 MB` / `60 s` PoS Envelope)

Divi enforces `MAX_BLOCK_SIZE_CURRENT = 2,000,000` bytes (`divi/src/defaultValues.h:43`) on a **60-second** block target and supports low-power ARM stakers (including 32-bit `armv7` Raspberry Pi nodes):

| Scheme | Standard | PubKey | Signature | Input Witness (`pk + sig`) | Role in Divi Lockstep Design |
|---|---|---|---|---|---|
| `secp256k1` ECDSA | Legacy | `33 B` | `~71 B` (`65 B` compact) | `~104 B` | Legacy baseline; preserved pre-cutoff, phased out for exposed roles |
| **`LMS` / `HSS` (SHA-256)** | NIST SP 800-208 / RFC 8554 | `60 B` | `~2,500 B` | *Spork only* | **Primary choice for `strSporkKey` (`DIP-PQ-2`):** pure SHA-256 security, zero lattice assumptions, stateful counter trivial for low-frequency Spork signing |
| **`FN-DSA-512` (Falcon-512)** | NIST FIPS 206 | `897 B` | `~666 B` | `~1,563 B` | **Primary candidate for `vchBlockSig` & high-throughput tx witness (`DIP-PQ-3/4`)** once final FIPS 206 vectors ship: smallest bandwidth (`~600` 2-in/2-out txs per `2 MB` block) and sub-millisecond integer verification on ARM |
| **`ML-DSA-44` (Dilithium2)** | NIST FIPS 204 (Final) | `1,312 B` | `2,420 B` | `3,732 B` | **Finalized pure-integer lattice baseline** (simple constant-time signing in C99, Rust, WASM, and hardware wallets; `~260` 2-in/2-out txs per `2 MB` block; supported alongside or as fallback if FIPS 206 slips) |
| **`SLH-DSA-128s` (SPHINCS+)** | NIST FIPS 205 (Final) | `32 B` | `7,856 B` | `7,888 B` | **Optional cold-vault catastrophe-recovery spend path:** stateless SHA-256 security even if algebraic lattices face future cryptanalysis |

---

## 6. Phased Lockstep Roadmap, Deliverables & Verification Gates (`2026–2030`)

Target completion aligns with **NIST IR 8547's 2030 deprecation milestone** for classical `ECDSA`/`ECDHE`, leaving holders a multi-year migration runway ahead of early 2030s CRQC hardware roadmaps.

```
2026–2027 (Phase 0)       2027 (Phase 1)              2028 (Phase 2)           2028–2029 (Phase 3)          2029–2030 (Phase 4)
───────────────────  ──►  ──────────────────────  ──►  ───────────────────  ──►  ───────────────────────  ──►  ────────────────────────
Tier A HNDL Defense       Shared DIPs + Regtest        DIP-PQ-2 Lockstep        DIP-PQ-3/4 Segregated         Dual Mainnet Release
(diag ML-KEM, TLS,        Fork Harness + Inert         Hybrid Spork Key         PQ Witness, 256-Bit           (divid + irondivid) &
C++/Rust Vault UX)        C99 & Rust PQ + Fuzz         (divid + irondivid)      PQ Vaults & vchBlockSig       Holder Migration Runway
```

### Phase 0 — Immediate Non-Consensus HNDL Defense & Key Hygiene (`2026–2027`, Tier A)

1. **`P0.1` (`irondivid`): Hybrid PQ `divi-diag` encryption.** Upgrade `crates/divi-diag/src/consent.rs` and `bin/irondivi-diag-receiver` from classical `age::x25519` to hybrid `X25519 + ML-KEM-768` (`age` post-quantum recipient) before public diagnostic collection scales.
2. **`P0.2` (`irondivid` & TLS endpoints): Hybrid PQ TLS 1.3 (`X25519MLKEM768`).** Migrate `rustls` in `crates/divi-electrum` and `bin/irondivid` to negotiate hybrid post-quantum key exchange while preserving classical TLS fallback for older clients, and verify static/cross release builds in `tools/release-check.sh`.
3. **`P0.3` (`divid` & `irondivid`): Wallet KDF & Staking Vault hygiene.**
   - Document Staking Vaults (`ownerKeyHash` kept cold and unspent) as the recommended staking posture across both `divid` and `irondivid`.
   - Specify optional `nDerivationMethod = 1` (`Argon2id` + authenticated key wrapping) in C++ `divi/src/crypter.cpp` so newly encrypted `divid` `wallet.dat` files gain memory-hard AEAD protection matching `irondivid`'s `at_rest.rs`.

### Phase 1 — Regtest Fork-Control Parity, DIP Specifications & Dual Crypto Libraries (`2027`, Tier C Prep)

1. **`P1.1`: Regtest fork-activation parity across `divid` and `irondivid`.**
   - Today `divid` supports `-manual_fork=<timestamp>` (`divi/src/ForkActivation.cpp:50-55`), whereas `irondivid` treats `-manual_fork` as unsupported (`docs/divid-differences.md` `S2`).
   - Implement regtest-only fork-timestamp / BIP9 override support in `irondivid` so `scripts/interop/run.sh`, `scripts/block-rules`, and `scripts/fork-warning` can test pre-fork, exact activation-block boundary, reorg-across-fork, and post-fork consensus transitions across mixed `divid` + `irondivid` clusters.
2. **`P1.2`: Publish `DIP-PQ-1` (Algorithms, Canonical Encodings & BIP39 PQ HD Derivation).**
   - Fix exact NIST parameter sets, strict canonical byte encodings, domain-separation tags (`"Divi-PQ-TxSig-v1"`, `"Divi-PQ-BlockSig-v1"`, `"Divi-PQ-Spork-v1"`), and hardened `HMAC-SHA512` key-derivation paths from the existing BIP39 512-bit seed (`PRF -> PQ keygen seed`) so a user's existing 24 words deterministically restore the exact same PQ addresses in both `divid` and `irondivid`.
3. **`P1.3`: Land consensus-inert PQ libraries in both repos + cross-FFI fuzz gate.**
   - Add `divi/src/pqcrypto/` (C99) in `Divi` and `crates/divi-crypto/src/pq/` (Rust) in `IronDivi` with zero active consensus call sites.
   - Pass all shared KAT/edge vectors + `10M+` `tools/pq-diff-fuzz` iterations + `armv7` Raspberry Pi verification benchmarks.

### Phase 2 — Lockstep Hybrid Spork Authority Upgrade (`2028`, `DIP-PQ-2`, Tier C)

1. **`P2.1`: Dual-signed Spork messages (`CSporkMessage` v2).**
   - Implement hybrid `secp256k1` + post-quantum (`LMS` SHA-256 or `ML-DSA-65`) Spork signing and verification in `divi/src/spork.cpp` + `divi/src/chainparams.cpp` and `crates/divi-network/src/spork.rs`.
   - Extend `scripts/dial-sporks` to prove bidirectional Spork relay, persistence, and signature rejection between `divid` and `irondivid`.
2. **`P2.2`: Consensus cutoff for `secp256k1`-only Sporks.**
   - Once mainnet nodes upgrade, activate the lockstep MedianTimePast rule requiring valid post-quantum signatures on all newly signed Sporks, neutralizing the hardcoded `secp256k1` `strSporkKey` exposure years ahead of CRQC estimates.

### Phase 3 — Lockstep Segregated PQ Witness, 256-Bit PQ Vaults & PQ `vchBlockSig` (`2028–2029`, `DIP-PQ-3` & `DIP-PQ-4`, Tier C)

1. **`P3.1`: Segregated Witness Framing & Weight Accounting.**
   - Legacy script caps individual stack pushes at `520` bytes (`MAX_SCRIPT_ELEMENT_SIZE`), which cannot hold `1.5 KB–3.7 KB` post-quantum keys and signatures.
   - Implement segregated witness transaction framing, `wtxid` commitment in the block header / coinbase-coinstake commitment, and witness weight limits inside the `2 MB` / `60 s` envelope identically in `Divi` and `IronDivi`.
2. **`P3.2`: Versioned 256-Bit PQ Output & Vault Templates.**
   - Introduce `SHA-256` (32-byte, $2^{128}$ Grover preimage) address commitments (`Bech32m` `divi1...` / `tdivi1...` encoding) supporting:
     - Standard single-key PQ spend (`P2PQPKH`), and
     - **Post-Quantum Staking Vault (`PQ_STAKING_VAULT`)** preserving Divi's two-tier `ownerKeyHash256` / `vaultKeyHash256` + `OP_REQUIRE_COINSTAKE` + `CheckCoinstakeForVaults` guarantees (with optional `SLH-DSA-128s` cold-owner recovery leaf).
   - Finish and enable fatal coinstake script verification in `irondivid` (`docs/plans/coinstake-script-enforcement.md` gates 1–4) prior to `DIP-PQ-3` activation so `divid` and `irondivid` enforce identical fatal coinstake script checks.
3. **`P3.3`: Post-Quantum `vchBlockSig` (`DIP-PQ-4`).**
   - Extend `divi/src/BlockSigning.cpp` and `crates/divi-node/src/staker.rs` so PoS blocks staked by PQ outputs / PQ Vaults authenticate block headers with compact post-quantum signatures (`FN-DSA-512` `~666 B` + witness/header pubkey binding), eliminating `secp256k1` `RecoverCompact` exposure.
4. **`P3.4`: Mixed-Client Consensus & Reorg Gauntlet.**
   - Prove `1,000+` mixed-staker blocks across `divid` and `irondivid` nodes in `scripts/interop` and `scripts/block-rules`, covering PoW -> PoS -> pre-fork PoS -> activation boundary -> PQ PoS, vault splits (`>= 10,000 DIVI`), lottery blocks, treasury superblocks, reorgs across the fork timestamp, and mutated witness/signature rejection.

### Phase 4 — Stagenet Burn-In, Coordinated Dual Release & Holder Migration (`2029–2030`)

1. **Public Testnet / Stagenet Soak (`>= 6` months):** Run mixed `divid` (C++) and `irondivid` (Rust) public testnet validators, Electrum servers, explorers, and Web/Browser/CLI wallets through live activation.
2. **Coordinated Mainnet Release:** Ship synchronized `Divi Core` and `IronDivi` releases embedding the identical mainnet activation MedianTimePast (`ForkActivation.cpp` and `divi-consensus`).
3. **Voluntary Migration Tooling (Zero Forced Confiscation):** Provide one-command `Vault / PQ Sweep` workflows in `divi-cli`, `irondivi-cli`, `divi-webui`, and browser/web wallets so holders with historically exposed `secp256k1` public keys (direct stakers, reused addresses, un-swept legacy Masternode collaterals) can migrate cleanly into PQ Staking Vaults well ahead of the 2030s CRQC horizon.
