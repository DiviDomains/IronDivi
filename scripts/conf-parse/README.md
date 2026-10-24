# divi.conf parsing next to Divi Core

`run.sh` checks how the config file itself is read. A `divi.conf` written for divid must mean the same to irondivid.
Each row writes the same file for a fresh Divi Core 3.0.0 `divid` and a fresh irondivid, starts both on regtest
with the same command line, and compares:
- whether the start succeeds, or the exact error it prints;
- the values the file set, seen through RPC.

Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not, a `KNOWN` row that differs in another way, or a `KNOWN` row that now matches
  divid (the list below is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 10 minutes).

```sh
scripts/conf-parse/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/conf-parse/run.sh target/release ~/divi-3.0.0/bin 53900 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` on 127.0.0.2 (divid p2p and RPC, then irondivid's). The
  ports sit inside Linux's ephemeral range, where other programs' 127.0.0.1 sockets can hold them.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes under a minute and is stopped after 10 minutes. However it ends, both nodes are stopped and their
directories deleted. Needs bash and python3 (standard library only).

## Files and command lines

- **RPC credentials:** made at random for each node in each row, as numbers, and kept in the 0600 config file. They
  never go on a command line.
- **The base lines:** `rpcuser=<number>` and `rpcpassword=<number>`. Alone they are a valid TOML document too, so a
  row whose own lines are TOML-valid shows how irondivid reads a divi.conf that happens to be TOML. Rows meant for
  the divi.conf format add `addnode=127.0.0.2:1`, which is not TOML.
- **The command line:** `-regtest`, `-datadir`, `-port`, `-rpcport`, `-bind`/`-rpcbind` on 127.0.0.2,
  `-rpcallowip=127.0.0.0/8`, `-listen=0`, `-dnsseed=0`, `-discover=0`, `-staking=0`, and `-keypool=10` (each row makes
  new wallets; the two nodes start at once).
- **Each node's home:** a folder of its own, so a start without `-datadir` keeps its default data directory inside the
  run.

What a row looks at:
- **`relayfee`:** `getnetworkinfo` relayfee, set by `-minrelaytxfee`, a single-value option.
- **`wallet`:** whether `getwalletinfo` answers, set by `-disablewallet`, a boolean.
- **`added`:** the `getaddednodeinfo false` list, set by `-addnode`, a repeated option: divid's added nodes start as
  every `-addnode` value (`divi/src/net.cpp:1218`).
- **`chain`:** `getblockchaininfo` chain.

## Rows

How divid reads the file: `Settings::ReadConfigFile` (`divi/src/Settings.cpp:186-205`) with boost's config file
parser. Then:
- each key gets a `-` in front and goes through `SetParameter` (`:96-117`): a doubled `--` is cut to `-`, a tripled
  one is dropped, and `-no<key>` is `<key>` negated (`:32-39`);
- the file only fills what the command line left unset, and its first value wins (`setOnceOnly`), while a repeated
  option keeps every value;
- a `[section]` header or a `net.key` prefix is cut off on every network (`ParseNetworkSpecificFlag`, `:159-184`,
  tests `testnet` without its dash, so it never sees the network).

| row | file lines (besides the base) | expected, as divid |
|---|---|---|
| default | none | relayfee 0.0001 |
| comments | `# a comment`, `#minrelaytxfee=0.0009`, `minrelaytxfee=0.0002 # after the value` | 0.0002 |
| whitespace | blank lines, `   minrelaytxfee   =   0.0003   `, a tab line | 0.0003 |
| CRLF | every line ending in CRLF | 0.0004 |
| byte order mark | `﻿minrelaytxfee=0.0004` first | 0.0001: the mark is part of the key, an unknown key |
| empty value | `disablewallet=` | no wallet (empty is true) |
| `no<key>` | `nodisablewallet=1`; `nodisablewallet=0`; `disablewallet=0` | wallet; no wallet; wallet |
| dash spelling | `-minrelaytxfee=0.0005`; `--minrelaytxfee=0.0005` | 0.0005; 0.0001 (dropped) |
| a key twice | `minrelaytxfee=0.0006`, then `0.0007` | 0.0006, the first |
| repeated key | `addnode=127.0.0.2:11`, `:12`, and `-addnode=127.0.0.2:10` on the command line | `[:10, :11, :12]`, the command line's first |
| unknown key | `nosuchoption=1` | starts |
| `[section]` | `[test]` then `minrelaytxfee=0.0008`, in a divi.conf-only file and in a TOML-valid one | 0.0008 both |
| `net.key` | `regtest.minrelaytxfee=0.0008` | 0.0008 |
| quoted value | `minrelaytxfee="0.0002"`, in a divi.conf-only file and in a TOML-valid one | refused: `Error: Invalid amount for -minrelaytxfee=<amount>: '"0.0002"'`. The quotes are part of the value. See KNOWN for the exit code |
| `=` in a value | `rpcpassword=1=2` (before the base lines) | RPC answers with the password `1=2` |
| file and command line | `minrelaytxfee=0.0002` in the file, `-minrelaytxfee=0.0003` on the command line | 0.0003 |
| `-conf=<relative path>` | the file at `sub/other.conf`, `-conf=sub/other.conf` | read from under the data directory: 0.0009 |
| `datadir=` | `-conf=<absolute path>`, no `-datadir`, `datadir=<folder>` in the file | the chain is written in that folder (`ClearDatadirCache`, `:203-204`) |
| `regtest=1` | `regtest=1` in the file, not on the command line | chain `regtest` |
| a very long line | `nosuchoption=` and 200,000 characters | starts; the next line is read |
| `-conf=<a directory>` | no file, `-conf=<the data directory>`, with `-server=0` (there is no password) | see KNOWN |

Covered by `scripts/start-errors`, so not repeated here: a line with no `=`, `-conf=<a missing file>`, an unreadable
`divi.conf`, and the start (not the values) for comments, spaces, sections, repeated keys and the command line over
the file.

## KNOWN differences

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c). Each KNOWN row checks that the
difference is exactly this one; any other outcome is a FAIL.

- **`-conf=<a directory>`:** divid opens the directory as a stream. On Linux the stream reports no error but has no
  lines, so divid runs without a config file: `ReadConfigFile` takes only a stream that is not `good()` as missing
  (`divi/src/Settings.cpp:186-195`). That is accidental. irondivid says it cannot read the file and stops.

- **A quoted value** (two rows): the same `Error:` line on both. divid then aborts (SIGABRT, exit -6): the shutdown
  after this early `InitError` flushes the chain state (`divi/src/init.cpp:381`), and `ChainstateManager::Get`
  asserts (`divi/src/ChainstateManager.cpp:102`) because no chain state exists yet. irondivid exits 1, as in
  `scripts/restart-options`.

## Proving a difference is caught

`CONF_PARSE_INJECT=dash` gives irondivid `--minrelaytxfee=0.0005` (dropped) where divid reads
`-minrelaytxfee=0.0005`. That row then prints `FAIL` and the run exits 1.
