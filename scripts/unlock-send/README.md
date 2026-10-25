# Unlock, staking-only and send checks next to Divi Core

`run.sh` starts a fresh Divi Core 3.0.0 `divid` and a fresh irondivid on regtest and runs the same wallet steps on
both: encryption, calls on a locked wallet, staking-only unlock, full unlock, unlock timeouts, lock, wrong passphrases,
passphrase change, and the send refusals. Each row compares the two outcomes and prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 10 minutes).

```sh
scripts/unlock-send/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/unlock-send/run.sh target/release ~/divi-3.0.0/bin 53900 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` on 127.0.0.1 (divid p2p and RPC, then irondivid's).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 15 seconds and is stopped after 10 minutes. However it ends, both nodes are stopped and their
directories deleted. Needs bash and python3 (standard library only). Passphrases are made at random for each run,
live only in memory and in RPC request bodies, and are never printed or put on a command line; no key, seed or
signature is printed either (rows show `ok`, `txid`, `null` or the error).

## Nodes

divid listens; irondivid dials it (`connect=`), so both see one chain. divid mines 30 blocks and pays irondivid four
coins of 1000, then one more block. Each side then sends to the other's address. Both run with `staking=0`.

## Rows

How a row compares: same outcome (a result or an error); for an error the same code, and the same message where
divid's is a fixed text. For a result, the shape: `null`, a txid, `ok`; `getwalletinfo` by `unlocked_until`
(absent, `0`, `>0`) and `encryption_status`; `getstakingstatus` by `walletunlocked`.

| state | steps (each on both nodes) |
|---|---|
| unencrypted | `getwalletinfo`, `getstakingstatus`; `walletlock`, `walletpassphrase`, `walletpassphrasechange` give -15 |
| encrypt | `encryptwallet <p>` (divid reloads the wallet and keeps running), then again: -15 |
| locked | `getwalletinfo`, `getstakingstatus`; `sendtoaddress`, `dumpprivkey`, `signmessage`, `dumphdinfo`, `signrawtransaction` (no keys given) give -13; `getnewaddress`; `walletlock`; `walletpassphrase <wrong> 60`: -14 |
| staking only | `walletpassphrase <p> 300 true`; the info calls; send, dump, sign rows give -13; the same unlock again: -17 |
| unlocked | `walletpassphrase <p> 300` (from staking-only); the info calls; send, dump and sign rows succeed; sends of 0.00001 (dust, -4), to a mainnet address (-5), above the balance (-6), of 0 (-3) |
| timeouts | `walletlock`; `walletpassphrase <p> 2`, after 4 s locked and send -13; staking-only then `walletpassphrase <p> 2`, after 4 s back to staking-only, send -13 |
| change | `walletpassphrasechange <wrong> <p2>`: -14; `<p> <p2>`; old passphrase -14; new one unlocks and sends; `walletlock` |

The mainnet address is made from random bytes for each run (version 30), so nobody holds a key for it.

Two rows compare the code only, because divid's message is not a fixed text:

- send above the balance: divid builds `Insufficient funds: <requested>(total requested) is greater than
  <available>(total available)` (`divi/src/rpcwallet.cpp:756-761`); irondivid answers -6 with divid's coin-selection
  text `Insufficient funds to meet coin selection algorithm requirements.` (`divi/src/wallet.cpp:1779`).
- `encryptwallet`: divid returns `Wallet reloaded!` (`divi/src/rpcwallet.cpp:2722-2723`); compared as a result.

Neither node spends unconfirmed change by default (divid `-spendzeroconfchange=0`, `divi/src/wallet.cpp:1848`), so
irondivid gets four coins: each send has a confirmed coin to use.

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c).

## KNOWN differences

None at the time of writing: every row matches divid. A difference found later goes here and in `KNOWN` in
`check.py` (row name, divid's source line, the reason), so the row prints `KNOWN` instead of `FAIL`.

## Proving a difference is caught

`UNLOCK_SEND_INJECT=wrong-passphrase` makes the wrong-passphrase row use the right passphrase on irondivid only. That
row then prints `FAIL` and the run exits 1.
