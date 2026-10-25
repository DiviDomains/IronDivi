# Masternode start options next to Divi Core

`run.sh` starts a fresh Divi Core 3.0.0 `divid` and a fresh irondivid on regtest with the same masternode start options:
- `-masternode`, `-masternodeaddr`, `-masternodeprivkey`;
- `-mnconf`, `-mnconflock`;
- `-litemode`, `-budgetvotemode`.

For each, it compares whether the start succeeds (or the exact error it prints) and the RPC replies that show the
option's effect. Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not, a `KNOWN` row that differs in another way, or a `KNOWN` row that now matches
  divid (the list below is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 10 minutes).

```sh
scripts/mn-options/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/mn-options/run.sh target/release ~/divi-3.0.0/bin 53900 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` on 127.0.0.2 (divid p2p and RPC, then irondivid's).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes a few minutes and is stopped after 10 minutes. However it ends, both nodes are stopped and their
directories deleted. Needs bash and python3 (standard library only).

Secrets:
- RPC credentials are made at random per node and row, kept in the 0600 `divi.conf`.
- **Masternode keys:** every masternode key, in masternode.conf or as `-masternodeprivkey`, is a throwaway regtest key
  made by the script at run time (a random compressed WIF, version 239), plus one random mainnet-version key for the
  "a mainnet key" row. Keys go only into the test datadir's 0600 conf files; no key is printed or put on a command
  line.
- The collateral rows use regtest coins each node mines itself.

## Rows

Each start row writes `divi.conf` (the RPC lines and the row's options) and masternode.conf into a fresh datadir.
- masternode.conf lives in divid's network folder `<datadir>/regtest` and in irondivid's datadir.
- Its entry is `mn1 127.0.0.2:<own port> <new key> <txid of 11s> 0`. The start checks do not look the outpoint up.

| rows | what divid does (Core paths under `divi/src/`) |
|---|---|
| no masternode option: a valid masternode.conf; a line of three fields; a comment and an empty line | masternode.conf is read at every start (`MasternodeModule.cpp:210-226`). A non-empty line whose first word does not start with `#` needs five words, else exit 1 with `Error: Error reading masternode configuration file: Could not parse masternode.conf`, then `Line: <n>` and the line (`masternodeconfig.cpp:66-88`) |
| `-masternode=mn1` with `-txindex=0` (with and without an entry) | exit 1: `Error: Enabling Masternode support requires turning on transaction indexing.Please add txindex=1 to your configuration and start with -reindex` (`MasternodeModule.cpp:228-233`; txindex is checked before the alias) |
| `-masternode=mn1` and its entry | starts as a masternode (see KNOWN) |
| `-masternode=mn1` and no entry for it; no lines at all | exit 1: `Error: Unknown masternode configuration for masternode=<alias>.` (`:186-189`) |
| `-masternode=` with an entry whose line starts with a space | the line is malformed: the masternode.conf error above |
| `-masternode=mn1`, the entry's key not a key; a mainnet key | exit 1: `Error: Invalid masternodeprivkey. Please see documenation.` (`:178-183`, the typo is divid's) |
| `-masternodeprivkey` good over a bad entry key; bad over a good one; without `-masternode` | it replaces the entry's key once the alias is found (`:179`); alone it does nothing |
| `-masternodeaddr` good; not an address; bad without `-masternode` | exit 1: `Error: Invalid -masternodeaddr address: <value>` (`:197-205`), checked before the alias; alone it does nothing |
| `-mnconf=<relative>` with a bad line; with `-masternode`; `-mnconf=<absolute>` with a bad line; `-mnconf=<missing>`; no masternode.conf | the file is `-mnconf`, relative to the network data folder (`masternodeconfig.cpp:33-38`). A missing file is made with divid's three-line header and the start goes on (`:53-65`); no default masternode.conf is made beside a `-mnconf` file |
| `-litemode=1 -budgetvotemode=auto` | starts; no code of divid reads them (only `LicenseAndInfo.cpp:209`, `:226`) and its log says nothing of them; the row checks that the node's log does not call them unsupported |
| `-mnconflock` default, `=1`, `=0`; `-mnconf=<relative>` naming the collateral | each node mines 31 blocks, makes a copper collateral with `allocatefunds`, and names it in masternode.conf (or the `-mnconf` file). `listlockunspent` after a restart: the collateral is locked unless `-mnconflock=0` (`MasternodeModule.cpp:454-466`, `init.cpp:1246-1258`) |

How a row compares:
- the start: up on both, or the same exit code and the same first stderr line starting with `Error`;
- then the probes: `getmasternodestatus` (both "This is not a masternode" without `-masternode`);
- and the row's check: a file made, a lock taken, a log line.

## KNOWN differences

- **A valid `-masternode`** (four rows: `-masternode=mn1 and its entry`, `-masternodeprivkey good over a bad entry
  key`, `-masternodeaddr good`, `-mnconf=<relative> and -masternode`):
  - divid starts as that masternode (`MasternodeModule.cpp:221-240`).
  - irondivid has no active masternode (no pings, no payment votes of its own). Once every check divid makes has
    passed, in divid's order, it stops with `Error: -masternode=<alias>: irondivid does not run as a masternode;
    remove the masternode= line to start it`.

## Proving a difference is caught

`MN_OPTIONS_INJECT` is reserved; break a row on purpose with an irondivid build that skips a check (for example the
build of e8a42dc, which fails 16 rows).
