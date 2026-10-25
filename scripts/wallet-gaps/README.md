# Wallet cases no other script compares

`run.sh` starts three regtest nodes on one chain:
- **S**, a Divi Core 3.0.0 `divid` that mines and pays;
- **C**, a `divid` wallet with `vault=1`;
- **I**, an irondivid with `vault=1` restored from C's phrase, so C and I own the same coins.

Each case below runs on both twins, and its outcome is compared (never its timing). Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, in the way listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid, or differs in another way (the list below
  is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 15 minutes).

```sh
scripts/wallet-gaps/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/wallet-gaps/run.sh target/release ~/divi-3.0.0/bin 53950 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+5` on 127.0.0.2, the p2p and RPC port of S, C and I. S listens;
  C and I dial it.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 6 minutes (measured on hp1) and is stopped after 15. However it ends, every node is stopped and its
directory deleted. Needs bash and python3 (standard library only).

Secrets stay off command lines and out of the output:
- C's phrase is read from its `dumphdinfo` reply and handed to irondivid in its environment (`WALLET_MNEMONIC`).
- The passphrases are random (`secrets.token_hex`) and go over RPC only.
- The imported keys are S's own regtest keys, read with `dumpprivkey` and sent over RPC.
- S's words for the restore case are written only into the `divi.conf` of a copied datadir under the run's directory.

None of these is printed. `WALLET_GAPS_INJECT=<row name>` makes that row differ, to show a difference is caught.

## Rows (Divi Core 3.0.0, `divi/src/`)

| case | divid |
|---|---|
| `sendtoaddress <payee> 1 "donation"`, with `"a shop"`, with `""`, with `null` | The third argument is a fee mode or `"metadata"`, not a comment (rpcwallet.cpp:1336-1356). Compared: the outcome; for a send, the fee and the amounts paid. |
| `sendmany "" {payee: 1} 6 "testing"`, and `{payee: 1} "testing"` | The third argument is the comment; a minconf there is a type error (rpcwallet.cpp:1716-1723). |
| `sendmany` to `"notanaddress"`, alone and after a good address | -5 `Invalid DIVI address: notanaddress` (rpcwallet.cpp:1660-1661). |
| `sendmany` with the same address twice, written as JSON text | json_spirit keeps both pairs: -8 `Invalid parameter, duplicated address: <a>` (rpcwallet.cpp:1682-1683). |
| `sendtoaddress <payee> <v> "receiver_pays"` for v = 0.0001, 0.00008, 0.00006, 0.00002 | The fee comes off the amount; refused when what is left is dust or nothing (wallet.cpp:1653-1680, :1788-1793). |
| `importaddress` of S's address, then `importprivkey` of its key | The watched address becomes mine, under the new label (wallet.cpp:604-608). Compared: `validateaddress` and `getaddressesbyaccount`. |
| `importprivkey` with rescan false, then another with rescan true | The rescan finds the first key's coin too (rpcdump.cpp:96-99). Compared: the balance changes and `listunspent`. |
| `addvault` of a funding still in the mempool, then once mined | rpcwallet.cpp:1280-1290. |
| `fundvault {<owner:manager>: 3}`, `{…: {"amount": 2, "repetitions": 2}}`, `{…: {"amount": "x"}}`, `{…: [1]}` | The object form (rpcwallet.cpp:989-1036): one output, two, -8 `Unable to parse amount for: <enc>`, -8 `Unknown json input. Unable to parse input for <enc>`. |
| `sendmany` while locked, and unlocked for staking only | -13 (EnsureWalletIsUnlocked). |
| `walletpassphrase <wrong> 60` while fully unlocked, then the status | divid returns before it checks the passphrase (wallet.cpp:781-784). **KNOWN**, below. |
| `walletpassphrase <passphrase> 60 true` while fully unlocked, then the status | Unlocked for staking only. |
| `walletpassphrasechange` while unlocked, then the status | Changed; still unlocked (wallet.cpp:843-844). |
| `walletpassphrase <passphrase> 0`: the status 3 s later, and `unlocked_until` | Never locks again; `unlocked_until` is the time of the unlock (rpcserver.cpp:1201-1235). |
| Unlocked for 2 s, then for 60 s: the status after 4 s | The second unlock replaces the first one's timer. |
| Unlocked for staking for 2 s: the status after 4 s | Locked. |
| On a copy of each twin's datadir, `mnemonic=` with twelve `abandon` (they fail their checksum) | The wallet is moved to `<wallet><time>.moved`, then the start stops: `Error: Error loading or creating wallet.dat, SetMnemonic: invalid mnemonic: please check your words\``, exit 1 (init.cpp:864-888, :1203-1209; hdchain.cpp:63-65). |
| On a copy, `mnemonic=<S's words>` with the wallet already there | The wallet is moved aside, and a new one is made from S's words and rescanned (init.cpp:864-888, wallet.cpp:2282-2331). Compared: the start, whether a `.moved` wallet was left, whether the old savings address and S's first address are mine, and whether the balance is above 0. |

## KNOWN

| row | difference | why |
|---|---|---|
| `fully unlocked: walletpassphrase <wrong> 60` | divid answers `null`: on a wallet already fully unlocked, Unlock returns true without checking the passphrase (wallet.cpp:781-784), and the relock timer restarts. irondivid checks it, answers -14 `Error: The wallet passphrase entered was incorrect.` and leaves the unlock as it was. | A wrong passphrase never changes the wallet's lock state (docs/divid-differences.md R17). The row is KNOWN only with exactly those two replies (check.py `KNOWN`). |
