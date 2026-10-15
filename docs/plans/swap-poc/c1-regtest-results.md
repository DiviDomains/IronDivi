# C1 regtest results: design tests 5 and 7

Date: 2026-10-15. Branch `c1-regtest` (from `c1-impl`). Design reference:
`docs/plans/swap-poc/xmr-c1-design.md` §7, tests 5 and 7.

## Verdicts

| Test | What it shows | Verdict |
|---|---|---|
| 5a | A Tx_cancel with a high-S (S-flipped) σ_J is mined; the Tx_refund keyed to that mined txid confirms; the taker recovers s_m from it | **PASS** |
| 5b | A Tx_cancel with σ_J pushed with OP_PUSHDATA1 (non-minimal) is mined; the Tx_refund keyed to that mined txid confirms; the taker recovers s_m from it | **PASS** |
| 7 | A Tx_lock with an S-flipped input signature is mined under a different txid; the presigned Tx_cancel cannot be spent; the maker recovers the coins alone through the t_late branch after t_late | **PASS** |

**No protocol bug found.** The protocol code (maker.rs, taker.rs, jsig.rs,
lock_scripts.rs) was not modified.

## Environment

- Host: hp2, x86_64 Linux.
- Divi build: `~/bsx-b/bin/divi/divid`, release tarball
  `divi-3.0.0-x86_64-linux-gnu-9e2f76c`. `getinfo`: version 3.0.0.0,
  protocolversion 70915.
- Chain: private `-regtest`, two nodes, datadirs
  `/mnt/storage1/bshuler-xmr/c1-regtest/{a,b}`.
  - Node A: RPC 51990, P2P 51991. Mines and takes the RPC calls.
  - Node B: RPC 51992, P2P 51993, `connect=127.0.0.1:51991`. A peer that
    validates every block on its own. After each block the harness checks
    that B's tip equals A's.
  - Both nodes: `txindex=1`, `rpcuser=c1rt`, and a random `rpcpassword`
    (never printed or committed). Started with
    `nohup divid -datadir=... -regtest -daemon >/dev/null 2>&1 </dev/null`.
- No other divid or monero process on hp2 was touched.
- Final chain: height 39, tip
  `41f05a671127d80d982a48a06eb9521b443450e97325a8cf98a04e225d94f893`.
  Median time past at the start of the tests was 1792072024.
- Harness: `crates/divi-swap-xmr/examples/c1_regtest.rs`, run on hp2 with
  `bash hp2-cargo.sh c1rt run --example c1_regtest -p divi-swap-xmr`.
  It uses the crate's real code throughout: `LockScript` and `CancelScript`,
  `cancel_variants`, `after_cancel`, `taker_encrypts_tx_refund` and
  `maker_completes_tx_refund`, `crypto::recover`, and two in-process `JSession`s
  (cggmp21 0.6.3) for J. It does not edit any of them. `spend()` copies
  `maker::spend`.

### Reproduce

The `divi.conf` for node A (node B is the same, but with `rpcport=51992`,
`port=51993` and `connect=127.0.0.1:51991`):

```
regtest=1
server=1
listen=1
rpcport=51990
port=51991
rpcallowip=127.0.0.1
bind=127.0.0.1
staking=0
rpcuser=c1rt
rpcpassword=<random, generate locally>
txindex=1
```

On hp2:

```
D=/mnt/storage1/bshuler-xmr/c1-regtest
nohup ~/bsx-b/bin/divi/divid -datadir=$D/a -daemon >/dev/null 2>&1 </dev/null
nohup ~/bsx-b/bin/divi/divid -datadir=$D/b -daemon >/dev/null 2>&1 </dev/null
# from a checkout of this branch:
C1RT_DIR=$D cargo run --example c1_regtest -p divi-swap-xmr
```

The harness reads the RPC credentials from `$C1RT_DIR/{a,b}/divi.conf`. It
starts from a fresh chain (wipe `$D/{a,b}/regtest` first) and mines to
height 30 itself. Test 7 sleeps about 90 s until t_late. A full run takes a
few minutes. Most of that is the cggmp21 keygen, plus the Paillier primes on
the first run.

## Script flags that applied

All file references are to the Divi 3.0 C++ source.

- **Block validation** (`BlockTransactionChecker.cpp:113-121`): it uses
  `MANDATORY_SCRIPT_VERIFY_FLAGS` = P2SH | DERSIG | REQUIRE_COINSTAKE
  (`script/standard.h:24-26`). It adds CHECKLOCKTIMEVERIFY and LIMIT_TRANSFER
  once ForkActivation sees median time past ≥ 1692792000. The chain's MTP was
  1792072024, so **CLTV was enforced** in every block of these tests.
  LOW_S, MINIMALDATA and STRICTENC are not consensus rules.
- **Mempool** (`script/standard.h:32-46`; `MempoolConsensus.cpp:398` checks the
  standard flags, then `:411` re-checks the mandatory flags):
  STANDARD = MANDATORY | DERSIG | STRICTENC | MINIMALDATA | NULLDUMMY | CLTV |
  LIMIT_TRANSFER | DISCOURAGE_UPGRADABLE_NOPS. **LOW_S is not in the standard
  set**, so high-S signatures relay.
- **Finality:** the mempool checks `IsFinalTx` against the node's adjusted
  time (`MempoolConsensus.cpp:61`). A block checks it against the block's
  own time.

## How "a block that bypasses the mempool" was made

The brief asked for the malleated transactions to be mined in a block that
skips the mempool. I used the regtest RPC
`generateblock {"extratx":[hex],"ignoreMempool":true}`
(`rpcmining.cpp:120-212`) for this. It builds a block with that transaction and
no mempool policy checks. It then runs the block through full consensus
validation (`ProcessNewBlock`). If the block is invalid, the RPC fails with
-25 "failed to generate a valid block" and the tip does not move. Node B
then validates the same block again over P2P. This is a valid stand-in for
a hand-built block: the consensus checks are identical, and it is how a
staker would include a non-standard transaction.

Normal broadcasts used `sendrawtransaction`, followed by `setgenerate [1]`.

## Test 5a: high-S σ_J

Timelocks: t_cancel 1792071425, t_punish 1792075625, t_late 1792079225.

1. J = `037d64ffa2f60119de7791236a827ad8c34b305fd2b596a43bbb013c750b350d83`
   was made with two in-process JSessions.
2. Tx_lock `eb84b7645f83d84a29653afccd53d4727325adb100038183dab1aef3f6143729`
   (10 DIVI to the C1 P2SH) was mined in block
   `3815939388776dd0207241e12faf56c2c6414a91c4e56d9b4ccaca0dfe629c37`.
3. Tx_cancel was signed with J. The canonical Tx_cancel txid is
   `69a27a5dac2e6ecaf6d3c8298a35d1ca1d5028d4092621feed1c7f6d61103f07`.
   The taker built adaptor encsigs for Tx_refund over all 120
   `cancel_variants`, keyed by txid. This mirrors `finish_keying`.
4. The malleated Tx_cancel replaces σ_J with (r, n − s). Its txid is
   `fa4797f212367b9acffc9f47aa1fbd2d378dbb874e74e014df333b06dcd3b9cb`.
   The harness asserted that this txid is among the 120 variants and that
   `after_cancel` classifies it as the Cancel branch.
5. `sendrawtransaction` of the malleated Tx_cancel was **ACCEPTED**. A
   high-S signature passes the mempool on Divi 3.0.0 (see the finding below).
6. It was mined with `generateblock` in block
   `5c7bac537fd4ea08718d2c2546d3803ad90fa319da5c7171e1b3f64083936b3c`.
   The mined scriptSig matched the malleated bytes, and node B agreed.
7. The maker looked up the encsig by the **mined** txid and decrypted it with
   s_m. It added its own signature and built Tx_refund
   `fee4bd04615c005978bc5c002a8474904d5f7eafe5fd35fdfc5fae34cbec27c5`.
   `sendrawtransaction` **ACCEPTED** it. It was mined in block
   `7f98926c74332693c6d31d5405ddf142aab096cd52027887c4664cd009b7bcd7`,
   and node B agreed.
8. The taker ran `crypto::recover` on the mined refund signature and its
   own encsig. The recovered s_m **matches** the maker's s_m. This is
   checked by an assert; the value is never printed.

## Test 5b: non-minimal push of σ_J

Timelocks: t_cancel 1792071450, t_punish 1792075650, t_late 1792079250.

1. J = `0210216220e6f0344613918e16d298e2b51889649ed38cc43e7be19f3d1a000bcf`.
2. Tx_lock `03efe7913c0359a448d41f2e844ddf18a7e5342b10df4cd09e29fb2aaa92be6e`
   was mined in block
   `76dc8a7a429a578e856945ccd6a24f44162f2e63dcbb50f1aef9dbb26e9f0d76`.
3. The canonical Tx_cancel txid is
   `964155d7f5355ff744b58d2bc55d3f88d0b9aaa09f0ec1b813eeb99cd76e6bc7`.
   The taker made 120 encsigs as in 5a.
4. In the malleated Tx_cancel, the scriptSig is
   `OP_PUSHDATA1 <len> σ_J`, `OP_2`, `<push redeem>`. Its txid is
   `8a58fb648f9a71a772a7488f6e49505e4ae0be5c39ca246536e42974b2d8ade8`.
   The harness asserted it is among the variants and classified as Cancel.
5. `sendrawtransaction` was **REJECTED**:
   `rpc -26: 64: non-mandatory-script-verify-flag (No error)`. The debug.log
   reads `CScriptCheck(): 8a58fb648f:0 VerifySignature failed: Data push
   larger than necessary`. This is MINIMALDATA, a mempool-only rule.
6. It was mined with `generateblock` in block
   `55112ce50faa52482b5c05131dcbc75a07fbf1ae4f474979ee4023942edca702`.
   The block is consensus-valid, and node B accepted it.
7. Tx_refund
   `082ac1964faf17eb8aa25f16d9cd8b32f9f07548f2dfe18a9f62bed8e6c90def`
   was built from the encsig for the mined txid. `sendrawtransaction`
   **ACCEPTED** it, and it was mined in block
   `2fb2dec256e36cdc1895743c0d274c960b1a0f2b784a7a10d65d7af1b5ebf27b`.
   Node B agreed.
8. The taker's recovered s_m **matches**.

## Test 7: malleated Tx_lock, maker recovers alone through t_late

Timelocks: t_cancel 1792071475, t_punish 1792071775, t_late 1792072165.
t_late was set about 90 s ahead so the test could wait for it.

1. J = `039e1eee2999791415455a9f96c9ce9d32205e591161d5ed19a85b7492716eed6c`.
2. The canonical Tx_lock
   `9feb1506207e7c44e5b52c3a2a90f86b394bd42117e4abe9f0e8e44df88c387e` was
   built and signed but **never broadcast**. Tx_cancel was J-signed against it.
   That presigned Tx_cancel is
   `f1b866138c14b623539d6ca09ae86032275ff67c390e6837edee51d11ac1b055`.
3. The malleated Tx_lock flips S in the funding P2PKH input signature. Its
   txid is `6a97cb590060e9d83ef23a404c6ba94603369dcf92fb8ee01ff500fa347ba582`.
   `sendrawtransaction` **ACCEPTED** it, because high-S relays. The harness then
   mined it with `generateblock` in block
   `079764f237ceb5a1a2fb1702a192e0baa4acdd10867ce3fec0a40705216c1bc4`,
   and node B agreed.
4. The presigned Tx_cancel is useless:
   - `sendrawtransaction` of the canonical Tx_lock was REJECTED:
     `rpc -26: Unknown inputs being spent`. Its funding input is already
     spent by the malleated copy.
   - `sendrawtransaction` of the presigned Tx_cancel was REJECTED:
     `rpc -26: Unknown inputs being spent`. Outpoint 9feb…387e:0 does not
     exist.
   - `generateblock` with the presigned Tx_cancel was REJECTED: `rpc -25:
     failed to generate a valid block`. The debug.log reads `ERROR: Check:
     tx has invalid input` and `connectTip : ConnectBlock
     2af889f823879c0377d39a24dd97d383ee7fbce759e9678e7cd7df18978e38cb
     failed`. The height stayed at 38.
   - `gettxout 6a97…a582 0` shows the lock output unspent, 10.0 DIVI.

   Divi 3.0 also has a "bare txid" notion. Outpoints are still keyed by the
   full txid (`txmempool.cpp:313`), and the results above confirm this.
5. The maker built the late spend
   `721da6265f83cc3f8984d2f07cbcfa8a6d12e36b2fc60c70cb78cff247d3f80d`.
   It spends 6a97…a582:0 through selector 0x03 (`OP_CHECKLOCKTIMEVERIFY
   t_late`, maker key `a`), with nLockTime = t_late = 1792072165. It is
   signed with the maker key only. The harness asserted that `after_cancel`
   classifies it as the Late branch.
6. `sendrawtransaction` before t_late was **REJECTED**: `64: non-final`
   (hp2 clock 1792072099 < t_late).
7. After t_late + 5 s, `sendrawtransaction` was **ACCEPTED**. The spend was
   mined in block
   `41f05a671127d80d982a48a06eb9521b443450e97325a8cf98a04e225d94f893`,
   and node B agreed. `gettxout` on the lock output now returns null. The
   maker recovered 999,000,000 sat (10 DIVI minus the 0.01 fee) with no
   help from the taker.

## Findings and observations

1. **High-S signatures relay on Divi 3.0.0.** LOW_S is not in
   `STANDARD_SCRIPT_VERIFY_FLAGS`. Both a high-S Tx_cancel (5a) and a high-S
   P2PKH Tx_lock (7) were accepted by `sendrawtransaction`. So any relaying
   node can malleate these transactions, not just a staker. This is no
   protocol bug, because C1 already handles it:
   - the 120 Tx_refund encsigs cover the high-S Tx_cancel (5a);
   - the t_late branch covers a malleated Tx_lock (7).

   The threat model in xmr-c1-design.md should say plainly that S-flip
   malleation is relay-level on Divi, not staker-only.
2. **Non-minimal pushes are mempool-rejected but consensus-valid.** Only a
   staker can mine one (5b). C1 covers this too.
3. **The refund path depends on the encsig lookup by mined txid.** This works
   for both forms as built. The maker must read the Tx_cancel from the chain,
   not from its own copy. maker.rs already does this.

## Scope limits and deviations

- Test 7 shows the coins are safe on the maker's side. The taker-side rule
  that "the taker never locks XMR while Tx_lock is malleated" (taker.rs
  513-524) was checked by reading the code. It was not run on regtest, since
  no Monero chain is involved here.
- The datadirs live under `/mnt/storage1/bshuler-xmr/c1-regtest/` because I
  had no permission to create a directory directly under `/mnt/storage1`.
- `generateblock` was used in place of a hand-ground block. See the section
  on how the block was made for why the two are equivalent.
- The chain stayed below height 100, so every block was PoW. Block-level
  script flags are chosen in `BlockTransactionChecker.cpp:113-121`, and that
  code does not branch on PoW vs PoS. So the result carries over to staked
  blocks.
- Every key and secret was made fresh in memory for this run. None was
  printed or written to disk. The Paillier primes cache
  (`/tmp/divi-swap-xmr-test-primes.json` on hp2) contains no swap secrets.
