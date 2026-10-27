# Random wallet and chain sequences next to Divi Core

Each of the other scripts checks one area with a fixed sequence. This one runs a long, seeded mix of wallet and chain
operations, so a fault that needs two areas together (a send while locked coins exist and a block is invalidated, a
restart between a vault fund and a reorg) is found too.

`run.sh` starts two pairs on regtest:
- **pair C:** two Divi Core 3.0.0 `divid` nodes connected to each other;
- **pair I:** two irondivid nodes connected to each other, restored from the phrases of their divid twins (I1 from
  C1, I2 from C2).

Each step is drawn from a seeded list and applied to node n of both pairs the same way, the two pairs at once. After
every step each pair settles, and node n and the other node of pair C are compared with their twins in pair I. Only
what does not depend on keys or hashes is compared:

- the step's outcome: success, or the error code and its text (for a raw transaction, of the call that failed; for a
  helper call that failed, without the node's name);
- `getbalance "*" 0`, `getbalance "*" 1`, `getunconfirmedbalance`, and `getwalletinfo`'s `immature_balance`;
- the amounts of `listunspent 0`, as a sorted list (so their number too);
- the number of locked coins (`listlockunspent`);
- `getwalletinfo`'s `keypoolsize` and `encryption_status`, and whether `unlocked_until` is there and set (it is a
  time, so its value is not compared);
- the mempool size and the height;
- for `invalidate`, all of these also between `invalidateblock` and `reconsiderblock`.

Txids and block hashes can differ between the pairs (a block made a second later, a stake kernel found at another
time), so which coin a send spends or which coin stakes can differ, and with it the change values and which stake
outputs are still immature. Those fields are still compared exactly. A difference
that one of divid's accidental choices explains (below) is logged as `KNOWN`, with its reason, and the run goes on
with four fresh nodes. For the stake outputs, the rules check that each side's balance plus immature balance agree.

The first difference ends the run with one `FAIL` line naming the seed, the episode and the step, both values, the
coins and mempools of both pairs, and the steps of the episode. The run ends with `FAILS <n>`; the exit code is the
number of FAILs (255: usage error, interrupted, or out of time).

```sh
scripts/random-sequences/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
SEED=7 scripts/random-sequences/run.sh target/release ~/divi-3.0.0/bin 53850 /var/tmp
```

- `<port-base>`: ports `<port-base>` to `<port-base>+7` on 127.0.0.2 (p2p and RPC of C1, C2, I1, I2).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

| Variable | Meaning |
|---|---|
| `SEED` | the seed of the steps (random when not set; the first line prints it) |
| `STEPS` | number of steps (200) |
| `REPLAY` | a file with a JSON list of steps, as a FAIL line prints them, run instead of drawn ones |
| `RANDOM_SEQUENCES_ENCRYPTED` | for a replay: the nodes (`1,2`) whose wallets were encrypted when the episode started, as the FAIL lines print it |
| `RANDOM_SEQUENCES_INJECT` | a step number whose irondivid outcome is changed, to show a difference is caught |
| `RANDOM_SEQUENCES_GO_ON` | `1`: go on after a FAIL (for looking into a difference) |
| `RANDOM_SEQUENCES_TIMEOUT` | seconds before the run is stopped (1500) |
| `RANDOM_SEQUENCES_LOGS` | a folder to copy the four logs to, for each episode and on a FAIL |
| `RANDOM_SEQUENCES_DEBUG` | `1`: irondivid logs at debug level and divid with `debug=mempool` |
| `RANDOM_SEQUENCES_TWIN` | `1`: the second pair runs divid too, in irondivid's place, to see the differences divid has with itself on the same seed. The twins restore the phrases from `-mnemonic`, a line of their 0600 `divi.conf`. The line is taken out again once the wallet is made, as divid reads it at every start |
| `RANDOM_SEQUENCES_ROWS` | `0`: leave out the fixed rows (below) that a seeded run starts with |
| `RANDOM_SEQUENCES_MID_TRACE` | `1`: for each `invalidate`, each side's mempool (txids) with the time, before it, when `invalidateblock` returns, at the read and for 4 s after, and the transactions of the blocks it disconnects |
| `RANDOM_SEQUENCES_MID_DELAY` | seconds to wait between `invalidateblock` returning and the read of the middle state (0) |
| `RANDOM_SEQUENCES_MID_BARRIER` | `1`: the two pairs read the middle state of an `invalidate` together, once both calls have returned |
| `RANDOM_SEQUENCES_TRACE` | `1`: before and after each `invalidateblock`, the node's mempool is printed, each transaction with its inputs (`txid:vout@height/kind`) and its outputs |

A run of 200 steps takes 2 to 10 minutes. However it ends, all nodes are stopped and their directories deleted. It
needs bash and python3 (standard library only).

Secrets:
- The phrases are read from the divid nodes' `dumphdinfo` and handed to irondivid in its environment
  (`WALLET_MNEMONIC`).
- The wallet passphrase is made at random and sent only in RPC requests.
- RPC passwords are made at random and kept in each node's 0600 `divi.conf`.
- The keys `importprivkey` steps import are derived from a salt made fresh for the run, and sent only in RPC requests.
- None of them is printed or put on a command line. The only file one goes to is a twin's 0600 `divi.conf` in
  `RANDOM_SEQUENCES_TWIN` runs: it holds the phrase for the twin's first start and is rewritten without it right after.

## Setup of each episode

1. Node 1 mines 15 blocks, node 2 mines 15, node 1 mines 25, so both nodes have mature coins.
2. The wallets start unencrypted. Each node's wallet is encrypted by one `encryptwallet` step at a point drawn from the
   seed. A node whose step has already run in an earlier episode is encrypted at the setup and unlocked for 99999 s.
3. The nodes run with `staking=0` (blocks come from `setgenerate` and `generateblock`) and `keypool=5`, so a locked
   wallet runs out of keypool keys within a few calls.

## Fixed rows

A seeded run first runs the stored episodes in `rows/`, each on four fresh nodes of its own, then the seeded steps
on fresh nodes again (with the encryption state they would have had without the rows). Each row is a case the draw
reaches only now and then, so it is checked on every run. They are left out with `REPLAY` or `RANDOM_SEQUENCES_ROWS=0`.

- `rows/mid-invalidate.json`: seed 14, steps 143-160, ending in a three-block `invalidate` on node 1 with sends of
  both nodes in the mempool. In about half the runs the two sides' mempools differ in the middle of it. Both nodes
  put the disconnected blocks' transactions back before `invalidateblock` returns: divid in `disconnectTip`
  (`ChainTipManager.cpp:176-183`), irondivid in the RPC's reorg hook (`blockchain.rs` `invalidate_block_family`,
  `node.rs` `update_mempool_after_reorg`). Traced runs, loaded or not, read early or late, never saw a mempool change
  after the call returned. The middle sizes differ because the two sides had spent different coins of one value
  before the invalidate (divid's coin choice among equal coins is by txid order), so a different send spends a coin
  that is immature at the lowered height. That is the **maturity after a reorg** or **maturity in the middle of a
  reorg** row below, and every other field is still compared. The two sides parted this way far more often than two
  divid pairs did (26 of 218 middle states against 1 of 66), because irondivid's work blocks wrote a coinbase
  scriptSig of their own: the height, then the height again as four raw bytes, where divid writes the height, then the
  extra nonce 1 (`BlockFactory.cpp:38-52`). So no coinbase txid matched divid's, even for a block made in the same
  second. irondivid now writes divid's.

  With the coinbases the same, the row's sends often have the same txids on both sides. That showed a second,
  rarer difference, at the end of the step (5 of 140 runs, in both directions). Node 1 is restarted by its
  `encryptwallet` (step 156), so it lacks node 2's earlier sends, and in the middle it drops its own send that spends
  an immature coin. Each comes back only by node 2's random mempool rebroadcast (divid `main.cpp:1280-1294`,
  irondivid `rebroadcast.rs`). In the logs, that rebroadcast came 19 s after `reconsiderblock` on one side and later
  than the end read on the other. So after `reconsiderblock` the script offers each node of the pair the transactions
  of its peer's mempool that it lacks (`sendrawtransaction`, parents first), as that rebroadcast would. It does this
  on both sides alike and compares every field after it. A node that refuses one still shows as a difference.

## Steps

Each step names a node (1 or 2) and a random number `draw`, which picks amounts, coins and depths.

| Kind | What it does on node n |
|---|---|
| `getnewaddress` | a new address |
| `send own`, `send other` | `sendtoaddress` to a new address of node n or of the other node. The amount is dust (0.000001), tiny (0.0001), small (0.1 to 20), large (100 to 2600), the whole confirmed balance, the whole balance with `sweep_funds`, or small with `receiver_pays` |
| `sendmany` | `sendmany ""` to a new address of node n and one of the other node |
| `lock` | `lockunspent false` on a coin of `listunspent 0`, picked by `draw` in amount order |
| `unlock one`, `unlock all` | `lockunspent true` on one coin locked by an earlier step (in the order they were locked), or with no list |
| `fundvault` | `fundvault "<own address>:<other node's address>" <1 to 50>` |
| `reclaim` | `reclaimvaultfunds <own address> <0.5 to 20>` |
| `mine` | `setgenerate 1` to `3`: work blocks, and stake blocks past the last work block |
| `invalidate` | `invalidateblock` of the block 1 to 3 below the tip, the state compared, then `reconsiderblock`, and each node offered its peer's mempool transactions it lacks |
| `restart` | `stop`, then a start on the same datadir |
| `kill` | `kill -9`, then a start (see below for divid) |
| `walletlock`, `walletpassphrase` | lock the wallet, or unlock it for 99999 s |
| `walletpassphrase timeout` | unlock it for 120 to 720 s |
| `walletpassphrase staking` | unlock it for staking only (`walletpassphrase … 99999 true`) |
| `encryptwallet` | once per node and run (see the setup), then a restart |
| `keypoolrefill` | `keypoolrefill <1 to 10>` |
| `drain getnewaddress`, `drain getrawchangeaddress` | the call until the keypool runs out (-12), or 15 times: an unlocked wallet tops the keypool up each time |
| `importprivkey` | a throwaway key, derived from a salt made fresh for the run and the step number, so both pairs import the same key; with rescan for an even `draw`. Neither the salt nor the key is printed |
| `send imported` | a small `sendtoaddress` to a key an `importprivkey` step of this episode brought in |
| `generateblock` | `generateblock {}` |

Every step runs whatever the wallet's state is: locked, unlocked for staking only, unlocked, or not encrypted. So the
sends, stakes, key handouts and imports also show their refusals (-13, -15, -17, -12, -25, and -1 for a stake signed
with a key of the locked HD seed).
| `rawtx` | a coin of `listunspent` (picked by `draw`, unlocked) spent to a new address of node n by `createrawtransaction`, `signrawtransaction` and `sendrawtransaction`, with a fee of 0.001 |

## Differences that come from divid's accidental choices

The txids differ between the pairs, so where divid's choice depends on a txid the two sides can part without either
being wrong. These differences are recognised, logged as `KNOWN`, and the run goes on with four fresh nodes (a new
episode) and the remaining steps, so every comparison stays exact:

- **coin choice:** a send where each side spent one coin, of different values. divid ranks the coins that each cover
  a send by signature size alone (`MinimumFeeCoinSelectionAlgorithm.cpp:127-139`), so among them it takes the first
  in its wallet map, ordered by txid.
- **maturity after a reorg:** after an `invalidateblock`, the two sides dropped different mempool transactions, and
  every one of them spends a coinbase or coinstake output that is immature at the new height. divid's
  `removeCoinbaseSpends` drops these too (`txmempool.cpp:139-157`), at each block it disconnects
  (`ChainTipManager.cpp:175-182`). Each side had spent a different coin of the same value, since divid's coin choice
  among equal coins is by txid order. The dropped transactions are those the invalidated node held before the
  invalidate (its own sends count: the other node may never have had them, when it was restarted and a send reaches it
  again only by the random rebroadcast) and those the other node holds, less what the chain confirms again. A dropped
  transaction may also spend, instead, an output of a transaction in a disconnected block that itself spends such a
  coin: divid refuses that parent when it puts the block's transactions back and removes the parent's descendants from
  the mempool with it (`remove(..., true)`, `txmempool.cpp:91-126`). `reconsiderblock` confirms the parent again, but
  the child stays gone. A transaction it lacks that spends no immature coin is allowed only when the other side's node
  lacks one with the same output values: a node restarted earlier gets its peer's sends back only by divid's random
  rebroadcast (`main.cpp:1280-1294`), on both sides alike.
- **stake coin choice:** a `mine` or `generateblock` step past the last work block, after which only node n's balances
  and coins differ. On both sides each new block staked a coin of divid's stake set (`CWallet::SelectStakeCoins`,
  `wallet.cpp:1433-1465`): unlocked, 10 confirmations at that block (no coin age on regtest, `chainparams.cpp:498`),
  not spent by an earlier block of the step. Two more kinds of coin are not listed by `listunspent` when the step
  begins but count: a vault output the wallet holds, and a coinbase or coinstake output that matures during the step.
  divid counts a generated coin from 21 confirmations (`MerkleTxConfirmationNumberCalculator.cpp:54-59`). divid tries
  the set in outpoint order (`StakableCoin.h:21-24`, `PoSTransactionCreator.cpp:261`; shuffled only with `-vault`,
  `:63-72`, `:99`) and takes the first coin with a kernel hash under the target. That target is weighted by the coin's
  value (`ProofOfStakeCalculator.cpp:19-24`, `:53-54`), so a small coin is often passed over. Which coin wins depends
  on the txids, and those differ between the pairs, so the script checks only that each kernel is in the set. A
  coinstake's outputs are immature, so the balances part by the difference. The rule also checks that node n's balance
  plus immature balance agree, so the two fields are compared by their total.
- **divid balance cache:** divid's `getbalance` disagrees with its own unspent coins (`listunspent 1`), while
  irondivid's agrees with the same coins. divid keeps each wallet transaction's balance in
  `CachedUtxoBalanceCalculator` (`CachedUtxoBalanceCalculator.cpp:13-30`), recomputed only when a wallet transaction
  spending it is added (`wallet.cpp:1242-1333`). So a spend that the mempool drops still counts as spending the coin.
  The coins compared are `listunspent 1` and the confirmed locked coins, which `getbalance` counts and `listunspent`
  leaves out.
- **maturity window:** only the middle of an `invalidate` differs, by one or two coins of one value, with mempools
  of one size, and the end states agree. The two sides had spent different coins of that value (divid's choice among
  equal coins is by txid order, which shows only in the coins' depths). With the tip lowered, one of those coins sits
  in the block between the mempool's coinbase maturity (20, `txmempool.cpp:151`) and the wallet's (21,
  `MerkleTxConfirmationNumberCalculator.cpp:54-59`). The run goes on without a new episode.
- **maturity in the middle of a reorg:** only the middle of an `invalidate` differs (balances, coins, the mempool's
  size), and the end states agree. While its tip was lowered, one side dropped transactions from the disconnected
  blocks or its mempool, and each spends a coinbase or coinstake output immature at that height, or an output of a
  disconnected transaction that does. divid drops these with their descendants (`txmempool.cpp:139-157`, `:91-126`),
  and `reconsiderblock` confirms them again. The other side had spent an older coin of the same value, so the two
  sides lost transactions of different output values. The run goes on without a new episode.
- **divid balance cache in the middle of a reorg:** only the middle of an `invalidate` differs, in node n's
  balances alone (immature, `getbalance`, unconfirmed), and the end states agree. Both sides lost as many
  transactions while the tip was lowered: spends of coins immature at that height (`removeCoinbaseSpends`), and the
  transactions of the disconnected blocks it refuses. divid's wallet keeps the balances it cached for a mempool
  transaction the reorg dropped (`CachedUtxoBalanceCalculator.cpp:13-30`, recomputed only when a wallet transaction
  spending it is added, `wallet.cpp:1242-1333`). So the coins that transaction spends stay spent, and its outputs to
  node n stay unconfirmed, although the transaction is now at -1 confirmations
  (`MerkleTxConfirmationNumberCalculator.cpp:51`). A transaction of a disconnected block reaches the wallet again
  through the disconnect (`ChainTipManager.cpp:189`), which recomputes its cache entries, so it leaves no gap.
  irondivid's wallet counts neither, so its balances agree with the coins it lists, as with **divid balance cache**.

  The rule does the accounting exactly. It takes the coins of node n's wallet (`validateaddress`) that the lost
  mempool transactions spent and that exist at the lowered height. divid's immature balance must be below irondivid's
  by just those immature for the wallet there (under 21 confirmations), and both `getbalance` fields by just the
  others. irondivid's unconfirmed balance must be the sum of the 0-confirmation coins it lists. This showed once
  irondivid's coinbases matched divid's (see "Fixed rows"), because the two sides then drop the same sends. The run
  goes on without a new episode.
- **divid reindex after a kill:** see below. divid's reindex runs on a thread of its own (`init.cpp:1580`), while
  its wallet's unconfirmed transactions are offered to the mempool at the end of the start (`init.cpp:1646`), before
  the chain is rebuilt. So they are refused, and divid's wallet counts their inputs unspent.
- **divid wallet after a kill:** after a kill, divid's restarted node holds fewer transactions (or blocks) than
  irondivid's.
  divid writes its wallet to disk 2 s after the last change (`ThreadFlushWalletDB`,
  `LegacyWalletDatabaseEndpointFactory.cpp:23-50`), so a send made just before a `kill -9` is lost. irondivid stores
  a send before the RPC that made it answers.
- **divid loses a key imported into an encrypted wallet:** divid's node no longer holds an address an
  `importprivkey` step brought in, and irondivid's does. `CWallet::AddKeyPubKey` writes a key to the wallet file only
  when the wallet is not encrypted (`wallet.cpp:611-613`). On an encrypted wallet, `CCryptoKeyStore::AddCryptedKey`
  keeps it in memory alone (`crypter.cpp:295-305`). So divid's next start no longer has the key, nor the coins paid to
  it. irondivid stores the key, and copying divid would throw a private key and its coins away. In a twin run both
  divid pairs lose the key alike.
- **rebroadcast timing:** after a restart, only the restarted node's mempool, unconfirmed balance or unconfirmed coins
  differ, and each side's restarted node holds only transactions its peer holds too, besides transactions of the same
  output values on both sides (its own sends, which reach the peer again by the same rebroadcast). divid sends some
  mempool transactions to its peers again at a random time within 30 minutes (`PeriodicallyRebroadcastMempoolTxs`,
  `main.cpp:1280-1294`; irondivid does the same since `fix/random-sequences`). Whether the restarted node has the
  peer's transactions back by then is chance.

**Settling.** After each step, each pair waits until its two nodes are connected again (after a restart, the
`-connect` node dials again within seconds) and on one tip, and until both mempools are equal or still for 8 s. A
transaction made while the two are apart would reach the other node only through the random mempool rebroadcast.
An `invalidate` first offers each node the transactions of its peer's mempool that it lacks, as that rebroadcast
would (see "Fixed rows").

**divid after `kill -9`:** divid refuses to start (or aborts while loading its block index) ("Block database corruption detected! Failed to find best block in
block index", `BlockIndexLoading.cpp:275`, `init.cpp:1082`) until it is started with `-reindex`. That is the recovery
it asks for, so the script does it and notes it on the step; irondivid starts without it.

`KNOWN` in `check.py` (a step kind with a reason) is for an accidental divid behaviour tied to a step kind; it is
empty at present.

## Shortening a difference

A `FAIL` prints the steps of its episode as JSON. Saved to a file and run with `REPLAY=<file>`, they reach the same
point on four fresh nodes, with `RANDOM_SEQUENCES_ENCRYPTED` set as the FAIL prints it (a wallet encrypted in an
earlier episode is encrypted again at the next one's setup). Removing steps from the file and running it again finds the shortest list that still shows
the difference. Some differences need a particular coin choice, so a replay can take a few tries.
