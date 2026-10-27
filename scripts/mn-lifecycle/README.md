# The rest of a masternode's life, next to Divi Core

`run.sh` takes masternodes through the steps scripts/mn-life does not take, on a regtest network of Divi Core 3.0.0
`divid` and irondivid nodes, and compares what each daemon answers and what each does with the masternodes. Each row
prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with a count of the rows and `FAILS <n>`; the exit code is the number of FAILs (255: usage error,
interrupted, or over the time limit).

```sh
scripts/mn-lifecycle/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/mn-lifecycle/run.sh target/release ~/divi-3.0.0/bin 46370 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+7` on 127.0.0.2 (two per node, four nodes). The ports sit inside
  Linux's ephemeral range, where other programs' 127.0.0.1 sockets can hold them.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end, unless
  `MN_LIFECYCLE_KEEP=1` is set (to read each node's debug.log after a run).

A run takes about five minutes and is stopped after 15. However it ends, every node is stopped and the directories
deleted. Needs bash and python3 (standard library only).

Secrets:
- RPC passwords are made at random for each run and kept in each node's 0600 `divi.conf`.
- `setupmasternode`'s `config_line` holds the masternode's private key. Replies are compared by their shape; the key
  is compared only with the one the same node gave before, and never printed.

## The network

- **C** (divid) and **I** (irondivid) are the controllers; C mines (proof of work: the run stays below height 101).
- **CN** (divid) and **IN** (irondivid) run with `txindex=0` and only follow the network.
- The masternodes run on no node. A broadcast carries a ping, so a masternode is ENABLED from its start until that
  ping is two hours old: the way a masternode whose node stopped is seen. scripts/mn-life runs masternode nodes.

## Steps and rows (Core paths under `divi/src/`)

| step | rows |
|---|---|
| set-up | each controller allocates a diamond, platinum and gold collateral, then a copper one, and runs `setupmasternode` for the copper one while it is still in the mempool (GetTransaction looks there first, `TransactionDiskAccessor.cpp:58-61`; by shape); the collateral amount of each tier (`chainparams.cpp:147-153`) |
| set-up again | 16 blocks on, `setupmasternode` for the copper alias again: whether it gives the same masternode key, and how many addresses the account `reserved-><alias>` holds (`rpcmasternode.cpp:207`, `rpcwallet.cpp:334-375`) |
| stored broadcasts | each broadcast signed and imported; `listmnbroadcasts`: the count, and whether it is in collateral order (std::map of COutPoint, the txid as a number, `StoredMasternodeBroadcasts.h:19`, `OutPoint.cpp:14-17`, `uint256.cpp:139-147`) |
| start | `broadcaststartmasternode` of each tier; the tier and status each controller lists for its own and the other's; `getmasternodecount`; the same broadcast again once listed (seen: success, `masternodeman.cpp:420-424`) |
| txindex=0 | how many masternodes CN and IN took from the network, and the misbehaviour scores of their peers (the collateral is found through the coins view, `masternodeman.cpp:62-77`, `TransactionDiskAccessor.cpp:87-110`) |
| a late broadcast | 13 blocks on, the copper broadcasts, whose ping now names a block 25 deep: the reply and whether it is listed (the list refuses it, `masternodeman.cpp:342-352`, and divid answers from the list, `RpcMasternodeFeatures.cpp:104-121`) |
| missed pings | every node's clock is moved on with `setmocktime` in steps of at most 15 minutes, a block at each step: statuses and `getmasternodecount` a minute before the pings are two hours old, just after, after each controller spends its gold collateral, past 130 minutes, and a minute's pass later |

Timing:
- A masternode is EXPIRED once its last ping is at least 120 minutes old and REMOVE at 130, on the node's clock
  plus the network offset (`TimeSinceLastPingIsWithin`, `MasternodeHelpers.cpp:172-181`). divid checks a masternode
  when `getmasternodecount` is called, which the rows call first, and once a minute (`MasternodeModule.cpp:502-529`),
  which also drops the REMOVE and spent ones; that pass runs within a second of the clock moving.
- Check looks at the collateral only after the ping times (`masternodeman.cpp:160-178`): a masternode that expired
  before its collateral was spent stays EXPIRED and leaves at REMOVE.
- The steps are at most 15 minutes: a peer that sent nothing for 20 minutes on the node's clock is dropped
  (`Node.cpp:812-834`), and a gap over an hour counts as a stalled chain (`MasternodeHelpers.cpp:27-34`).
- A block is mined at each step so the tip stays within ten minutes of the clock (`IsBlockchainSynced`,
  `MasternodeHelpers.cpp:35-63`), which divid's minute pass needs.

Not here:
- The payment queue's IsScheduled filter applies off regtest only (`masternode-payments.cpp:451-458`); it is
  checked by `crates/divi-rpc/tests/mn_lifecycle.rs` on a testnet chain.
- Votes pruned 1000 blocks down and the seen pings forgotten after 260 minutes are checked by the same tests.
- A reorg across a paying block is section 10 of scripts/mn-life (with `MN_LIFE_PAYMENTS=1`).
- irondivid runs no masternode (scripts/mn-options), so the mixed set-up is only a divid masternode controlled by
  irondivid, which scripts/mn-life runs.

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c).

## KNOWN differences

None.

## Proving a difference is caught

`MN_LIFECYCLE_INJECT=<row name>` changes irondivid's reply of that row before it is compared, for example
`MN_LIFECYCLE_INJECT='gold: broadcaststartmasternode'`: that row prints `FAIL` and the run exits non-zero. Or run the
build of base 07a0745, which fails 15 rows.
