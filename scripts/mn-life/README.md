# A masternode from setup to payment, next to Divi Core

`run.sh` takes masternodes through their life on a regtest network of Divi Core 3.0.0 `divid` and irondivid nodes,
and compares what each daemon answers and what the network does with the masternodes. scripts/masternode-replies
compares each masternode call's reply on its own; this script follows one masternode from its collateral to its
payments. Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with a count of the rows and `FAILS <n>`; the exit code is the number of FAILs (255: usage error,
interrupted, or over the time limit).

```sh
scripts/mn-life/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/mn-life/run.sh target/release ~/divi-3.0.0/bin 53900 /var/tmp

# with the payment phase (about 45 minutes)
MN_LIFE_PAYMENTS=1 scripts/mn-life/run.sh target/release ~/divi-3.0.0/bin 53900 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+11` on 127.0.0.2 (two per node, six nodes). The ports sit inside
  Linux's ephemeral range, where other programs' 127.0.0.1 sockets can hold them.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about six minutes and is stopped after 10 minutes. With `MN_LIFE_PAYMENTS=1` it waits for the masternodes
to be ranked and the limit is 50 minutes. However it ends, every node is stopped and the directories deleted. Needs
bash and python3 (standard library only).

Secrets:
- RPC passwords are made at random for each run and kept in each node's 0600 `divi.conf`.
- `setupmasternode`'s `config_line` holds the masternode's private key. It goes only into the masternode node's 0600
  `masternode.conf`, and is compared by its shape and by its parts other than the key.
- The broadcasts are compared by their shape. No key is printed.

## The network: why it is mixed

irondivid cannot run as a masternode: it refuses `-masternode=<alias>`. So every masternode runs on divid, and
irondivid takes the other role a masternode has, the controller wallet that funds and starts it.
- **C** (divid) and **I** (irondivid) are controllers.
- **M1** and **M3** (divid) run C's copper and silver masternodes; **M2** and **M4** (divid) run I's.
- All six nodes are connected to each other, so each divid node has the three spork-synced peers its masternode sync
  needs to move through its stages (`divi/src/masternode-sync.cpp:425-455`).
- C mines the chain (proof of work below height 100).

Every controller step is made on C and on I with their own masternodes, and the two replies are compared. What the
network does is read on C and on I side by side. The masternode nodes' own replies are compared M1 against M2: both are
divid, but their masternodes were set up and started by different controllers.

## Steps and rows

| step | rows |
|---|---|
| before | `mnsync status`, `listmasternodes`, `getmasternodecount`, `getmasternodestatus` (not a masternode), `listmnbroadcasts` |
| copper set-up, on C and on I | `allocatefunds masternode <alias> copper` (by shape) and the collateral amount (100 DIVI on regtest, `divi/src/chainparams.cpp:147-148`); 16 blocks for the 15 confirmations a broadcast needs (`divi/src/masternode.h:16`); `setupmasternode` (by shape; `protocol_version`; `config_line` is alias, the masternode node's address, key, txhash, index); `signmnbroadcast` (by shape); `importmnbroadcast` twice; `listmnbroadcasts` (by shape, and the entry's txhash and outidx); `startmasternode <alias>` and `<alias> true` on the controller |
| masternode nodes | M1 and M2 start with `masternode=<alias>` and the controller's config line; `mnsync status` once the divid nodes finished their sync; `getmasternodestatus` on M1 and M2 before the start |
| start | `broadcaststartmasternode <signed broadcast>` from each controller; each masternode ENABLED on C and on I within 120 s (the seconds it took are printed) |
| views after each step below | `listmasternodes` (in txhash order); whether the controller's own masternode is listed first; `getmasternodecount`; `mnsync status`; `getmasternodestatus` on a controller and on M1 and M2; `getmasternodewinners 5` |
| silver | the same set-up and start for a second masternode of each controller (300 DIVI), on M3 and M4 |
| restarts | C and I stopped and started; then M1 and M2 |
| collateral spent | each controller spends its copper collateral; its status on C and on I 1, 2 and 6 blocks later |
| payments (`MN_LIFE_PAYMENTS=1`) | 25 minutes after the starts, 20 blocks mined in turn by C and by I: `getmasternodewinners 1` before each, the masternode paid in each block (printed), and how many blocks of each miner pay a masternode |

How a row compares:
- the same outcome; an error with the same code and first line;
- a result with the same fields, JSON types and values, the members compared as sets (see KNOWN for their order).
- Left out, because they change from one moment to the next: `lastseen`, `activetime`, `lastpaid`, `sigtime`,
  `timestamp`.
- `mnsync status` is compared by its fields and by `IsBlockchainSynced` and `currentMasternodeSyncStatus`; its counters
  and times are each node's own.
- `getmasternodestatus` on M1 and M2 is compared without txhash, outputidx, netaddr and addr, which are each
  masternode's own.

Timing:
- divid shows the state of its last check in `listmasternodes`. It checks every masternode once a minute and on
  `getmasternodecount`, each at most every 5 s (`divi/src/MasternodeModule.cpp:524-529`, `divi/src/masternode.h:22`,
  `divi/src/masternodeman.cpp:152-180`).
- So after a collateral is spent, the rows wait 6 s and call `getmasternodecount` on both before reading the list.
- A masternode is ranked, so it can vote and be paid, only 25 minutes after its broadcast was signed on regtest
  (`divi/src/masternode-payments.cpp:558`). That is why the payment phase is optional.

Not compared:
- `verifymasternodesetup`: divid aborts on every call (`divi/src/rpcserver.cpp:397`, `:1045`; see
  scripts/masternode-replies).
- `startmasternode` on a masternode node: only divid can be one. Its reply with `deferRelay` is printed for M1 and M2.

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c).

## KNOWN differences

- **Member order** (one row, for `setupmasternode`): irondivid writes a result's members in name order
  (`docs/divid-differences.md` R6). Every other row compares the members as sets.
- **`getmasternodecount: tier counts divid lacks`**: irondivid adds `copper`, `silver`, `gold`, `platinum`,
  `diamond`, as in scripts/masternode-replies.
- **`mnsync status`, while divid is still in a sync stage** (the rows before the network is up and right after the
  restarts): irondivid has no masternode sync stages and reports 999 (finished). A row where both report 999 is a
  plain PASS.

## Proving a difference is caught

`MN_LIFE_INJECT=<row name>` changes irondivid's reply of that row before it is compared, for example
`MN_LIFE_INJECT='copper: signmnbroadcast'`: that row prints `FAIL` and the run exits non-zero.
