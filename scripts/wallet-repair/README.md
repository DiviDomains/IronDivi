# Wallet repair and upgrade start options, next to Divi Core

`run.sh` builds a wallet history on regtest, then runs each wallet repair and upgrade start option on fresh copies of
the wallets' datadirs. It has three nodes:
- **S**, a Divi Core 3.0.0 `divid` that mines and pays;
- **C**, a `divid` wallet;
- **I**, an irondivid restored from C's phrase, so C and I hold the same keys.

The twins get:
- deep coinbases (C mines blocks 51–100);
- receives from S, one of them to an address labelled `savings`;
- a send;
- a vault S owns and the twins manage (`fundvault` by S, `addvault` on both);
- a proof-of-stake block of C's;
- a locked coin.

Then every node stops. Each start option runs on a fresh copy of C's datadir and then on a fresh copy of I's, one copy
at a time and alone (`connect=0`). The copy is deleted after.

Each row prints one line:
- `PASS`: same as divid;
- `KNOWN`: differs, in exactly the way listed below;
- `FAIL`: differs and should not, a `KNOWN` row that differs in another way, or one that now matches divid.

Rows marked `[divid only]` are runs only divid can have: its `wallet.dat` can be damaged in place. They check divid
against the outcome its code gives.

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 25 minutes).

```sh
scripts/wallet-repair/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/wallet-repair/run.sh target/release ~/divi-3.0.0/bin 53950 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+5` on 127.0.0.2.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 9 minutes (measured on hp1) and is stopped after 25. However it ends, every node is stopped and every
directory deleted. Needs bash and python3 (standard library only). `WALLET_REPAIR_INJECT=<row name>` makes that row
differ, to show a difference is caught.

**Secrets:**
- C's phrase is read from its `dumphdinfo` reply and given to irondivid in its environment (`WALLET_MNEMONIC`).
- The damaged-key rows need a key record. They use a throwaway regtest key made in the run, imported over RPC only.
- Neither is printed, written to a file or put on a command line.

## What divid does (Divi Core 3.0.0, `divi/src/`)

| option | divid |
|---|---|
| `-salvagewallet` | sets `-rescan` unless it is given, and logs `InitializeDivi : parameter interaction: -salvagewallet=1 -> setting -rescan=1` (EnableWalletFeatures, init.cpp:763-766). Nothing more: the salvage (CWalletDB::Recover, walletdb.cpp:630-700, which would leave `wallet.<time>.bak`) is never called, as CDBEnv::Verify is given no recover function (DatabaseWrapper.cpp:24). |
| `-rescan` | scans the active chain again from the genesis block for the wallet (verifySyncToActiveChain, init.cpp:1242), logging `Rescanning... from height …` |
| `-upgradewallet`, `-upgradewallet=<n>` | read only when a wallet is made (wallet.cpp:1963-1971). Absent or the client version: the latest version. Otherwise the base version, and a limit below it (1000) refuses: the log line `Unable to downgrade wallet version. -upgradewallet=<custom_version> might be incorrectly set`, then `Errors detected during wallet loading`, then `Error: Error loading wallet.dat: database load failure` (init.cpp:1175, :1299-1305). An existing wallet ignores it. |
| `-zapwallettxes=1`, `=2` | not an option of divid 3.0.0 (not in LicenseAndInfo.cpp); kept and ignored, unsaid (Settings.cpp:130-150) |
| `-disablewallet` | no wallet is loaded; the wallet calls answer -32601 (init.cpp:807, :1380) |
| `-dbloadfailexit` | read as a number; a wallet that loads with the warning below then stops the start, exit 1, with no error line (init.cpp:1307-1309) |
| a record that cannot be read | a key (key, wkey, mkey, ckey) is DB_CORRUPT: `Error: Error loading wallet.dat: Wallet corrupted`, exit 1. Any other record is DB_NONCRITICAL_ERROR: `Warning: Warning: error reading wallet.dat! All keys read correctly, but transaction data or address book entries might be missing or incorrect.` on stderr, and the node starts. A tx record also soft-sets `-rescan`, which finds the transaction again (walletdb.cpp:495-511, init.cpp:1143-1177, :1296-1310). |

## Rows

Each start option is run on the copies:
- **Starts that repair or scan:** a plain restart; `-rescan`; `-salvagewallet`; `-salvagewallet -rescan=0`.
- **Upgrades on this wallet:** `-upgradewallet`, `-upgradewallet=10500`, `-upgradewallet=1000`.
- **zapwallettxes:** `-zapwallettxes=1`, `=2`, and `=1 -rescan`.
- **With the wallet off:** `-disablewallet`, alone, with `-rescan` and with `-salvagewallet`.
- **`-dbloadfailexit=1`** on a good wallet.
- **A start without `allowunencryptedwallet=1`** (every other start has it in `divi.conf`): the warning about an unencrypted wallet (init.cpp:1228-1231).

After each start these are compared:
- whether it started, or its exit code and the first `Error`/`Warning: Warning` line on stderr;
- **getwalletinfo:** walletversion, balance, txcount, keypoolsize;
- **getbalance** and **listlockunspent**;
- **listtransactions** `"*" 1000`: category, amount, txid;
- the label of the `savings` address, and the vault coins (getcoinavailability's Stakable);
- **the log lines it wrote:** the salvagewallet interaction, `Errors detected during wallet loading`, the noncritical
  warning, the downgrade refusal, a full rescan, an unknown-option line, the encrypt warning;
- **what it left:** a new start-up backup, a `.bak` file.

**A new wallet** with `-upgradewallet=1000`, `10500`, `60000`, `120200` and `3000000`: whether it starts, the wallet
version, and the log lines.

**divid only**, on throwaway copies of C's `wallet.dat`, each copy of the record damaged:
- a transaction record (the send, its input count made unreadable), alone, with `-salvagewallet`, and with
  `-dbloadfailexit=1`;
- a key record (an imported key, one byte of the secret changed), alone and with `-salvagewallet`.

irondivid's wallet is a RocksDB folder whose blocks carry checksums, so a record cannot be damaged in place. The same
cases are pinned for irondivid by `bin/irondivid/tests/wallet_repair.rs`, which writes the unreadable record through
RocksDB.

Not compared: the time of a start-up backup's name.

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c).

## KNOWN

Each KNOWN row is KNOWN only for the difference described; any other difference in it is a FAIL.

- **`-zapwallettxes…: log lines`:** irondivid adds `an unknown-option line`. divid keeps an option it does not know
  and says nothing (Settings.cpp:130-150); irondivid logs `Unknown option -zapwallettxes; ignored`
  (docs/divid-differences.md S1).
