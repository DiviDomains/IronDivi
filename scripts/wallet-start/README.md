# Wallet start options next to Divi Core

`run.sh` starts a fresh Divi Core 3.0.0 `divid` and a fresh irondivid on regtest and restarts both, in step, with
the same wallet options:
- `-wallet=<name>` (new and existing);
- `-rescan`, `-salvagewallet`;
- `-spendzeroconfchange=0` and `=1`;
- `-keypool=<n>`;
- `-upgradewallet`;
- `-zapwallettxes=1` and `=2`;
- `-sendfreetransactions`, `-txconfirmtarget`;
- `-disablewallet`;
- `backupwallet` restored on the same daemon and given to the other one.

A start that is refused is compared by exit code and by the error it prints on stderr. Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not, a `KNOWN` row that differs in another way, or a `KNOWN` row that now matches
  divid (the list below is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 10 minutes).

```sh
scripts/wallet-start/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/wallet-start/run.sh target/release ~/divi-3.0.0/bin 53900 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` on 127.0.0.1 (divid p2p and RPC, then irondivid's).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about a minute and a half and is stopped after 10 minutes. However it ends, both nodes are stopped and
their directories deleted. Needs bash and python3 (standard library only). RPC passwords are made at random for each
run and kept in the 0600 `divi.conf`. The regtest private keys the `-rescan` rows import go over RPC only and are
never printed.

## Nodes

The two nodes are not connected: each mines its own regtest chain (30 blocks, then a few for the transactions below)
and is restarted on the same datadir again and again, with `staking=0`. Each, from its own coins:

- labels an address `lbl` in its default wallet;
- pays 7 and 8 DIVI to two new keys of the default wallet, then mines three blocks. A new wallet's first scan starts
  at the tip it was made at, inclusive (`divi/src/wallet.cpp:263`, `:285-302`), so the payments must lie below it;
- takes those two keys' private keys (`dumpprivkey`) for other wallets to import without a rescan.

`-wallet=<name>` lives in divid's `regtest/` folder and in irondivid's datadir (irondivid's wallet is a folder there).

## Rows

| step | rows (each on both nodes) |
|---|---|
| fresh start | starts; `walletversion` |
| `-wallet=other.dat`, a new wallet | made in the datadir; balance 0; the default wallet's address is not its own; `importprivkey <first key> "" false` accepted, balance still 0 |
| restart `-wallet=other.dat` | the imported key is still there, balance still 0 (no rescan) |
| restart `-wallet=other.dat -rescan` | the 7 is found, one coin (`divi/src/init.cpp:1242`, `divi/src/wallet.cpp:279-313`) |
| `-wallet=salvage.dat`, new; the second key imported without a rescan; restarted plain, then with `-salvagewallet` | balance 0, then the 8 is found: `-salvagewallet` sets `-rescan` (`divi/src/init.cpp:763-766`) |
| restart, default wallet | balance as before the other wallets; it pays 10 to `other.dat` and mines a block |
| `-wallet=other.dat -spendzeroconfchange=0` | `other.dat` sees the 10; pays 9.5 out of it, leaving about 0.5 of unconfirmed change; a send of 7.2, which needs that change, is refused (-4) (`divi/src/wallet.cpp:1848`) |
| restart `-wallet=other.dat -spendzeroconfchange=1` | the same send of 7.2 goes (unconfirmed outputs of our own transactions may be spent: `divi/src/AvailableUtxoCollector.cpp:33-43`, `divi/src/AvailableUtxoCalculator.cpp:84-85`) |
| `-wallet=keypool.dat -keypool=5`, new | `keypoolsize` 9 (5 of each chain, less the default key); 9 after `getnewaddress` (topped up before a key is taken) |
| restart `-wallet=keypool.dat -keypool=8` | `keypoolsize` 9 at the start (no top-up at load: `divi/src/wallet.cpp:2122-2131`); 16 after `keypoolrefill` (`divi/src/wallet.cpp:2071-2080`) |
| restart `-upgradewallet`, default wallet | starts; `walletversion` unchanged |
| `-wallet=upgrade.dat -upgradewallet`, new | refused: exit 1, `Error: Error loading wallet.dat: database load failure`. A bare `-upgradewallet` reads as version 0, below the base version a new wallet starts at (`divi/src/wallet.cpp:183`, `:1963-1971`; `divi/src/init.cpp:1175`) |
| restart `-zapwallettxes=1`, then `=2` | starts (not an option of divid 3.0.0); the wallet's transactions, the label and the balance are all kept |
| restart, then restart `-sendfreetransactions=1 -txconfirmtarget=10` | the fee of the same 1 DIVI send to the wallet itself: the same on both, and the options change nothing (divid only lists them in its help: `divi/src/LicenseAndInfo.cpp:135`, `:143`) |
| restart, default wallet | `backupwallet <file>` accepted; `dumpwallet` and `importwallet` are -32601 `Method not found` (not in divid's table: `divi/src/rpcserver.cpp:421-425`) |
| `-wallet=restored.dat`, each daemon's own backup placed in its wallet folder | starts; balance as at the backup; the label |
| `-wallet=cross.dat`, the other daemon's backup | refused on both: compared by exit code only. divid cannot open irondivid's folder as a Berkeley DB file; irondivid refuses a Core wallet file (`docs/divid-differences.md` S5, W1) |
| `-wallet=sub/x.dat` | see KNOWN |
| `-disablewallet` | starts; `getbalance`, `getnewaddress`, `getwalletinfo`, `listunspent`, `sendtoaddress`, `backupwallet`, `dumpprivkey`, `keypoolrefill` are -32601 `Method unavailable due to manually disabled wallet`; `dumpwallet` -32601 `Method not found`; `getinfo` has none of `balance`, `walletversion`, `keypoolsize` (`divi/src/rpcmisc.cpp:139-144`); `validateaddress` still has `ismine` |

How a row compares: same outcome (`up` or the process exit); for an exit the same code and the same `Error:` line on
stderr. For an RPC, the same result shape (a txid, or the value itself), or for an error the same code and message.

Covered elsewhere and not repeated here: `-walletnotify` (`bin/irondivid/tests/divid_start_options.rs`
`blocknotify_and_walletnotify_run_their_commands`).

Not compared: `-upgradewallet=<n>` for a new wallet with `n` at or above the base version and not the client version.
divid then keeps the base version and limits later upgrades to `n`; irondivid's wallet has one format.

## KNOWN differences

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c). Each KNOWN row checks that the
difference is exactly this one; any other outcome is a FAIL.

- **`-wallet=sub/x.dat`**: divid refuses it with `Error: Unexpected wallet filename sub/x.dat` and then aborts (exit
  -6, the same abort after an early `InitError` as in `scripts/restart-options`) (`divi/src/init.cpp:866-871`). divid
  takes only a file name, as its Berkeley DB environment is the datadir. irondivid starts: its wallet is a folder of
  its own, and `-wallet` names that folder, inside the datadir when relative (`docs/divid-differences.md` S5, W1).

## Proving a difference is caught

`WALLET_START_INJECT=rescan` starts irondivid without `-rescan` where both should rescan. The `-rescan` rows then print
`FAIL` and the run exits non-zero.
