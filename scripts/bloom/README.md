# Bloom filters and filtered blocks next to Divi Core

`run.sh` starts a Divi Core 3.0.0 `divid` and an irondivid on one regtest chain (irondivid dials divid) and a peer of
the script's own that speaks the wire protocol to each in turn: it sends both the same messages and compares what comes
back. Each row prints one line:

- `PASS`: irondivid answers as divid;
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not, a `KNOWN` row that differs in another way, or a `KNOWN` row that now matches divid.

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 10 minutes).

```sh
scripts/bloom/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/bloom/run.sh target/release ~/divi-3.0.0/bin 53900 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: **4 ports**, `<port-base>` to `<port-base>+3` on 127.0.0.1 (divid's p2p and RPC, then irondivid's).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes a few minutes and is stopped after 10 minutes. However it ends, both nodes are stopped and their
directories deleted. Needs bash and python3 (standard library only). RPC passwords are made at random for each run and
kept in each node's 0600 `divi.conf`. A node that exits while starting is reported with its exit code and the last 15
lines of its log, and one whose ports are taken is started again on free ones.

The script's peer connects from **127.0.0.3**, so the bans it earns do not touch the two nodes' own connection on
127.0.0.1 (each ban is cleared with `clearbanned` before the next row). Its filters are made in the script exactly as
divid's `CBloomFilter(nElements, nFPRate, nTweak, nFlags)` makes them (MurmurHash3 with its seeds, the size and hash
function maths of `bloom.cpp`), so the same filter goes to both nodes.

## Rows

| step | rows |
|---|---|
| services | NODE_BLOOM in each node's `version`, with the default `-peerbloomfilters` (divid: on, `defaultValues.h:100`, `net.cpp:1722-1723`) |
| filter messages | whether each earns a ban (score 100, `main.cpp:892-939`): `filterload` within the limits; `filteradd` before any `filterload`; `filteradd` of 520 bytes; `filterclear`; `filterload` of 36,001 bytes; with 51 hash functions; `filteradd` of 521 bytes |
| filtered blocks | a block paying three addresses; one filter per update flag (`BLOOM_UPDATE_ALL`, `NONE`, `P2PUBKEY_ONLY`) on one address each; `getdata` of the block as a filtered block (inv type 3): the `merkleblock` payload **bit for bit** and the `tx` messages after it; a block with no match; and with no filter message at all (every peer's filter matches all) |
| announcements | after each flag's merkleblock, a spend of the matched output: announced (`inv`) or not, by whether the flag added that output to the filter; a send to an address no filter has, to a filtered peer, to a peer that said relay=0 in its `version`, and to a peer with no filter message |
| vault, coinstake | the merkleblock of a block with a `fundvault` transaction, filtered on the owner's and on the manager's key hash; of a proof-of-stake block, filtered on the coinstake's key |
| `-peerbloomfilters=0` | both restarted with it: NODE_BLOOM; `filterload`, `filteradd`, `filterclear` each banned; a filtered `getdata` still answered with the default filter |

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c).

## KNOWN differences

None: every row matches divid with `fix/bloom`. Without it (irondivid 9769f39) irondivid does not advertise
NODE_BLOOM, bans every filter message, answers no filtered `getdata` and announces every transaction to every peer.

## Proving a difference is caught

`BLOOM_INJECT=<row name>` changes irondivid's result of that row before it is compared, e.g.
`BLOOM_INJECT='filterclear: banned'`: that row prints `FAIL` and the run exits 1.
`BLOOM_DUMP=<dir>` writes both results of every row that differs to `<dir>`.
