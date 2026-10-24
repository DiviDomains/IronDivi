# Masternode and spork RPC replies next to Divi Core

`run.sh` starts a fresh Divi Core 3.0.0 `divid` and a fresh irondivid on one regtest chain with no masternode
running, makes the same masternode and spork calls on both, with good arguments and with wrong or missing ones, and
compares the replies field by field, before and after a restart of both nodes. Each row prints one line:

- `PASS`: same as divid (or, for an `[irondivid only]` row, the reply divid's handler gives);
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with a count of the rows and `FAILS <n>`; the exit code is the number of FAILs (255: usage error,
interrupted, or over 10 minutes).

```sh
scripts/masternode-replies/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/masternode-replies/run.sh target/release ~/divi-3.0.0/bin 54300 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` (divid p2p and RPC, then irondivid's), on 127.0.0.1, or on
  the address in `MASTERNODE_REPLIES_HOST` (127.0.0.2 keeps clear of other programs' clients when the ports are
  inside the host's ephemeral range).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about a minute and is stopped after 10 minutes. However it ends, both nodes are stopped and their
directories deleted. Needs bash and python3 (standard library only). RPC passwords are made at random for each run
and kept in each node's 0600 `divi.conf`. `setupmasternode` returns a masternode private key inside `config_line`;
that reply and `signmnbroadcast`'s are compared by their shape only, and no key is printed.

## Nodes and steps

divid listens; irondivid dials it (`connect=`), so both see one chain. Both run with `staking=0`. divid mines 130
blocks (past height 101, so `getmasternodewinners` has heights to score: height h is scored with the block at
h - 101, `MasternodeHelpers.cpp:75-86`) and pays irondivid 3000 DIVI; each node then funds a copper collateral of its
own (100 DIVI on regtest, `chainparams.cpp:147-148`) with `allocatefunds`, and divid mines one more block.

Parameters are JSON strings, as divi-cli sends them for these methods (divid's `rpcclient.cpp` converts none of
them); a few rows send a number or a string where divid reads another type, for json_spirit's type error.

## Rows

| calls | forms |
|---|---|
| state (before and after the restart) | `spork show`, `spork active`, `mnsync status`, `listmasternodes`, `getmasternodecount`, `getmasternodestatus` (not a masternode), `getmasternodewinners`, `listmnbroadcasts` |
| `spork` | an unknown name (`Invalid spork name`), a set without the spork key (`failure`), the value as a number, no arguments, an unknown mode, `show` with a value, three arguments |
| `mnsync` | no arguments, an unknown mode, two arguments, `reset`, `status` after the reset |
| `listmasternodes` | a filter, two arguments, the filter as a number |
| `getmasternodecount`, `getmasternodestatus` | with an argument |
| `getmasternodewinners` | `5`, `5 Unknown`, `5 nomatch`, `abc` (atoi 0), the count as a number, four arguments |
| `allocatefunds` | no arguments, two, another purpose, an unknown tier, `masternode mn1 copper` (by shape) |
| `setupmasternode` | no arguments, four, seven, an unknown collateral; `mn1` with each node's own allocation (by shape; `protocol_version`; `config_line` without the key: alias, address, and the node's own txhash and index) |
| `verifymasternodesetup` | `[irondivid only]`: four good arguments, a sigtime that is not a number, three arguments |
| `signmnbroadcast`, `importmnbroadcast`, `listmnbroadcasts` | no arguments, `zz`, `00`, `listmnbroadcasts x`; the setup broadcast signed (by shape), imported twice, listed (by shape), listed after the restart |
| `broadcaststartmasternode`, `startmasternode` | no arguments, not a broadcast, three arguments; an unknown alias, a defer flag that is not a boolean, three arguments |
| not divid methods | `masternode`, `masternodelist`, `masternodeconnect`, `fundmasternode`, `getpoolinfo`, `mnbudget`, `mnbudgetvote`, `mnfinalbudget`, `getbudgetinfo`, `getbudgetprojection`, `getbudgetvotes`, `checkbudgets`, `createmasternodekey`, `getmasternodeoutputs`, `listmasternodeconf`, `startmasternodes`, `obfuscation`: `Method not found` (-32601) on both (`rpcserver.cpp:325-409`) |

How a row compares: the same outcome; an error with the same code and message, where for divid's help texts (a -1
error of several lines, `runtime_error(help)`) the first line; a result with the same fields, JSON types (an
integer and a number with a fraction differ) and values, list items in order. Left out of the value comparison,
because they change from one moment to the next: `timestamp`, `lastseen`, `activetime`, `lastpaid`, `sigtime`. A
row marked by shape compares field names and types only.

divid aborts on every `verifymasternodesetup` call, before it reads the arguments: its table entry is thread-safe
and asks for the wallet lock (`rpcserver.cpp:397`), which the assertion at `rpcserver.cpp:1045` forbids; after the
abort divid needs `-reindex` to start. So irondivid's replies are checked against what the handler would answer
(`rpcmasternode.cpp:122-159`), and divid is not called.

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c).

## KNOWN differences

Each is a row of its own, so the rest of the reply is still compared:

- `getmasternodecount: tier counts divid lacks`: irondivid adds `copper`, `silver`, `gold`, `platinum`, `diamond`
  (divid's 8 counts, `rpcmasternode.cpp:327-358`; by design, as in `scripts/net-replies`).
- `mnsync status: currentMasternodeSyncStatus` (and after `reset`, and after the restart): irondivid has no masternode
  sync stages and reports 999 (finished). divid's stages move on only with 3 spork-synced peers
  (`masternode-sync.cpp:425-455`), so on this two-node chain divid stays at its first stage (0).

No other row differs from divid.

## Proving a difference is caught

`MASTERNODE_REPLIES_INJECT=<row name>` changes irondivid's reply of that row before it is compared, e.g.
`MASTERNODE_REPLIES_INJECT='spork show'`: that row prints `FAIL` and the run exits 1.
