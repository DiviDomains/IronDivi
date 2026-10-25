# The last start options next to Divi Core

`run.sh` starts a Divi Core 3.0.0 `divid` and an irondivid on regtest, row by row, with the same options, and compares
what shows from outside: whether the node starts (or its exit code and first error line), the `debug.log` lines that
name the option, the DNS seed lines of `debug.log`, and RPC replies. The options are the last five irondivid used to
warn about as "not supported; ignored":

- `-dbcache` (MiB): divid clamps it to 4..4096 and splits it, an eighth to the block tree database (at most 2 MiB
  without `-txindex`), half the rest to the coin database, the rest at 300 bytes a coin to the coins kept in memory
  (`init.cpp:1030`, `:1046-1056`, `defaultValues.h:27-31`). It never refuses a value: a word reads as 0.
- `-forcednsseed`, with `-dnsseed` and `-connect`: divid's DNS seed thread runs unless `-dnsseed=0` (`net.cpp:1448-1450`,
  "DNS seeding disabled"), which `-connect` soft-sets (`net.cpp:1683-1685`, "parameter interaction: -connect set ->
  setting -dnsseed=0"). With addresses in its book and no `-forcednsseed` it first waits 11 s, and if two peers are
  connected by then it logs "P2P peers available. Skipped DNS seeding." and stops (`net.cpp:1015-1030`). Otherwise it
  logs "Loading addresses from DNS seeds (could take a while)" and "<n> addresses found from DNS seeds" (`:1034`,
  `:1059`).
- `-mining`, `-genproclimit`, `-disablesystemnotifications`: only listed in divid's help (`LicenseAndInfo.cpp:142`,
  `:186-187`, `:205`); no code reads them.

Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not, a `KNOWN` row that differs in another way, or a `KNOWN` row that now matches
  divid (the list below is out of date).

The run ends with `# rows: ...` and `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted,
or over 15 minutes).

```sh
scripts/last-options/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/last-options/run.sh target/release ~/divi-3.0.0/bin 54350 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` on 127.0.0.2 (divid p2p and RPC, then irondivid's);
  `<port-base>+49`, which nothing listens on, is the `-connect` peer of the rows that name `-connect`.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 6 minutes and is stopped after 15. However it ends, both nodes are stopped and their directories
deleted. Needs bash and python3 (standard library only). RPC passwords are made at random for each run and kept in
each node's 0600 `divi.conf`.

## Nodes

Each node is started once and stopped, and its data directory kept as the template every row starts from. Both
listen on 127.0.0.2 with `discover=0` and `externalip=1.0.0.255` (so divid keeps gossiped IPv4 addresses,
`NetworkLocalAddressHelpers.cpp:81-104`). At that first start a raw peer gives divid 10 public addresses; the
`peers.dat` divid then writes is the non-empty book of the rows that name one, planted in both data directories
(irondivid reads divid's layout). A book is only planted in rows with `-connect`, so neither node dials what it
holds.

Regtest has no DNS seeds, so no lookup is made: a row that asks the seeds logs "0 addresses found from DNS seeds".

## Rows

| group | rows (each on both nodes) |
|---|---|
| `-dbcache` | 0, 3, 4, 100, 4096 (the maximum), 4097, -1, `abc` on the command line, 50 in `divi.conf`: the start, and the log lines naming `-dbcache` (none on divid). The sizes cannot be seen from outside: irondivid's split is tested in Rust (`crates/divi-node/src/config.rs` `db_cache_is_split_as_divid_splits_it`) |
| help only | `-mining=1`, `-genproclimit` -1/0/4, `-disablesystemnotifications=1` on the command line, and the last of each in `divi.conf`: the start, and the log lines naming the option (none on divid) |
| DNS seeds, empty book | no options; `-dnsseed=0`; `-forcednsseed` 1 and 0; `-dnsseed=0 -forcednsseed=1`; `-connect`; `-connect -dnsseed=1`; `-connect -forcednsseed=1`: the DNS seed lines 14 s after the start, and the log lines naming `-forcednsseed` |
| DNS seeds, a book | with `-connect -dnsseed=1`: none after 4 s, loading after 14 s; with two raw peers connected in the first 11 s, skipped; with `-forcednsseed=1` loading at once (after 4 s), also with two peers; `-connect` alone: disabled. `forcednsseed=1 dnsseed=1` in `divi.conf`: loading after 4 s |

## KNOWN

None.

## Not seen from outside

- divid shifts a negative `-dbcache` into an unsigned size (`init.cpp:1030`) and so takes the maximum, 4096 MiB;
  irondivid takes the minimum, 4 MiB. Both start, and the rows cannot tell them apart.
- irondivid keeps its own cache sizes when `-dbcache` is not given (a 128 MiB block cache and 10 000 000 coins in
  memory, or `-utxocachesize`); `-dbcache` replaces them with divid's split, the block tree and coin database caches
  making the chain database's one block cache. `-utxocachesize` still sets the coins in memory when given.
