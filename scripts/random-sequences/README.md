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

Txids and block hashes differ between the pairs, so which coin a send spends or which coin stakes can differ, and with
it the change values and which stake outputs are still immature. Those fields are still compared exactly. A difference
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
| `invalidate` | `invalidateblock` of the block 1 to 3 below the tip, the state compared, then `reconsiderblock` |
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
- **stake coin choice:** a `mine` or `generateblock` step where each side's new blocks staked coins of different
  values, only balances and coins differ, and each node's balance plus immature balance agree. divid tries its stake
  set in outpoint order (`StakableCoin.h:20-23`, `PoSTransactionCreator.cpp:261`), so the first coin whose kernel
  meets the target depends on the txids, which differ between the pairs. The staked coin and its reward move from
  the balance to the immature balance, so the two fields are compared here by their total.
- **maturity after a reorg:** after an `invalidateblock`, the two sides dropped different mempool transactions, and
  every one of them spends a coinbase or coinstake output that is immature at the new height. divid's
  `removeCoinbaseSpends` drops these too (`txmempool.cpp:139-157`), at each block it disconnects
  (`ChainTipManager.cpp:175-182`). Each side had spent a different coin of the same value, since divid's coin choice
  among equal coins is by txid order. The dropped transactions are those the invalidated node held before the
  invalidate (its own sends count: the other node may never have had them, when it was restarted and a send reaches it
  again only by the random rebroadcast) and those the other node holds, less what the chain confirms again. A
  transaction it lacks that spends no immature coin is allowed only when the other side's node lacks one with the same
  output values: a node restarted earlier gets its peer's sends back only by divid's random rebroadcast
  (`main.cpp:1280-1294`), on both sides alike.
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
