# Wallet options next to Divi Core

`run.sh` starts three regtest nodes on one chain:
- **S**, a Divi Core 3.0.0 `divid` wallet that mines, sends and owns the vaults;
- **C**, a `divid` wallet with `vault=1`;
- **I**, an irondivid with `vault=1` restored from C's phrase, so C and I own the same coins and manage the same vaults.

Each option below is set on both twins at its default and at other values, and what it changes is compared. Each row
prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 15 minutes).

```sh
scripts/wallet-options/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/wallet-options/run.sh target/release ~/divi-3.0.0/bin 53950 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+5` on 127.0.0.2, the p2p and RPC port of S, C and I. S listens; C
  and I dial it.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes 3 to 6 minutes (measured on hp1) and is stopped after 15. However it ends, all three nodes are stopped and their directories
deleted; every backup is made inside those directories. Needs bash and python3 (standard library only). C's phrase is
read from its `dumphdinfo` reply and handed to irondivid in its environment (`WALLET_MNEMONIC`); it is never printed,
written to a file or put on a command line. `WALLET_OPTIONS_INJECT=<row name>` makes that row differ, to show a
difference is caught.

## What divid does (Divi Core 3.0.0, `divi/src/`)

| option | divid | default |
|---|---|---|
| `-vault_min=<n>` | whole DIVI times COIN (AvailableUtxoCollector.cpp:22); a managed vault coin below it is not a stakable coin (AvailableUtxoCalculator.cpp:22-27). Plain coins, owned vaults and spending are unchanged. | 0 |
| `-createwalletbackups=<n>` | the backup at start, before the wallet opens (init.cpp:933-941, called at :1479): a copy in `backups/`, and in `monthlyBackups/` when the newest there is 30 days old or there is none, n kept in each, a negative n as 0 (WalletBackupCreator.cpp:21). With n > 0 each folder is pruned to n even when no copy was made (a backup of that minute already there, no wallet yet); with 0 nothing is made or removed; the folders are made either way (:103-121). A backup is named `<wallet>.%Y-%m-%d-%H-%M` in UTC (:59). Only regular files whose name less its last extension is the wallet file's are counted or removed (FilteredBoostFileSystem.cpp:35-56). | 20 (init.cpp:124) |
| `-monthlybackups=<n>` | n > 0 starts a thread (init.cpp:1284) that, a day after start and a day after each check, makes a backup in `monthlyBackups/` when the newest there is 30 days old, n kept (LegacyWalletDatabaseEndpointFactory.cpp:75-121). On regtest the day is counted on mock time (MockLoopForever, ThreadManagementHelpers.h:60-80; MockMilliSleep, utiltime.cpp:54-60), and the age and the name come from GetTime, which setmocktime sets. | 12 |
| `-txconfirmtarget=<n>` | in the help only (LicenseAndInfo.cpp:143); nothing reads it. | 1 |
| `-sendfreetransactions` | in the help only (LicenseAndInfo.cpp:135); nothing reads it, and sends pay the usual fee. | 0 |

## Rows

- **Coins:** S mines 111 blocks and pays the twins twelve coins of 50.
- **-vault_min:** S funds two vaults it owns and the twins manage, of 100 and 1000; both twins `addvault` them.
  `getcoinavailability` (Stakable, Spendable, Vaulted) with `-vault_min` not given, 500, 1000 (a coin at the minimum
  stays), 2000 and -5.
- **-txconfirmtarget, -sendfreetransactions:** for each of not given, `-txconfirmtarget=1`, `=25`,
  `-sendfreetransactions=1`, `=0`, and both: the fee and size of a 10 DIVI send from each twin, whether it went without
  a fee, and whether the start logged a warning naming the option.
- **-createwalletbackups:** with `backups/` and `monthlyBackups/` emptied but for a `notes.txt` that is no backup,
  six starts in turn with `=2` three times, `=0`, `=-1` and not given. After each: the number of the wallet's backups
  in both folders, the time suffix of what that start made, whether `notes.txt` is still there, and (first start)
  the base name. Both twins start in the same UTC minute. What each start made is renamed after it (`<name>-k<step>`,
  keeping the wallet's name before the last dot, so divid still counts it) so the next start's name is free.
- **-monthlybackups:** a start with `=1`, the clock set 31 days ahead with `setmocktime`; a start with `=0`, 62 days
  ahead; a start with `=3`, 93 days ahead. After each: the count in `monthlyBackups/` before and after, and whether a
  backup named by the mock date was made.

## KNOWN

Each KNOWN row is KNOWN only for the difference described; any other difference in it is a FAIL.

- `backup base name in backups/` and `in monthlyBackups/`: divid's wallet is the file `wallet.dat`, irondivid's the
  folder `wallet`, and a backup takes the wallet's name (docs/divid-differences.md W1, W2): divid `["wallet.dat"]`,
  irondivid `["wallet"]`. The time suffix and the count are compared exactly.
