# Wallet rows on a plain regtest chain, next to Divi Core

`run.sh` starts three regtest nodes on one chain:
- **S**, a Divi Core 3.0.0 `divid` that mines and pays;
- **C**, a `divid` wallet with `vault=1`;
- **I**, an irondivid with the same options, restored from C's phrase, so C and I own the same coins.

Each case below runs on both twins, and its outcome is compared (never its timing). Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, in the way listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid, or differs in another way (the list below
  is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, a port in use, interrupted, or
over 15 minutes).

```sh
scripts/wallet-gaps-4/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/wallet-gaps-4/run.sh target/release ~/divi-3.0.0/bin 54150 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+5` on 127.0.0.150, the p2p and RPC port of S, C and I, checked
  to be free first. S listens; C and I dial it.
- `[root]`: a fresh directory (mode 0700) is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.
- `WALLET_GAPS_4_INJECT=<row name>` makes that row differ, to show a difference is caught;
  `WALLET_GAPS_4_WIDE=1` prints each value whole (otherwise cut at 260 characters).

A run takes about four minutes on hp1 and is stopped after 15. However it ends, every node is stopped and its
directory deleted. Needs bash, `ss` and python3 (standard library only).

Secrets stay off command lines and out of the output:
- C's phrase is read from its `dumphdinfo` reply and handed to irondivid in its environment (`WALLET_MNEMONIC`).
- The wallet and bip38 passphrases are random (`secrets.token_hex`) and go over RPC only.
- The key the twins import is S's own regtest key, read with `dumpprivkey` and sent over RPC.

None of these is printed.

## Cases

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c).

| case | rows | divid |
|---|---|---|
| sendfrom from an account named `comment`, `to`, and `shop` | the fee, the inputs, and the transaction's `comment`, `to` and `FromAccount` | SendMoney erases the note named after the account, not FromAccount (wallet.cpp:1915-1922): `comment` keeps no comment, `to` no comment-to |
| bip38decrypt of a key the wallet holds and has labelled `paper` | the reply, then the address's account | the label is cleared before -4 "Key already held by wallet" (rpcdump.cpp:329-336) |
| bip38paperwallet `""` and `"a b\"c"` | the reply's members | any passphrase is taken (rpcdump.cpp:262-288) |
| backupwallet to a file | the log line | "copied wallet.dat to <file>" (walletdb.cpp:619) |
| a send the mempool refuses after it is committed | the reply; whether the send is in the wallet; the balance, the coin, the send's confirmations and the mempool; the same after a restart, and after the transaction it conflicts with is mined | -4 "Error: Invalid transaction committed to wallet!"; the send stays in the wallet at depth -1, and is back in the mempool after the restart (rpcwallet.cpp:774-782, wallet.cpp:1866-1878, init.cpp:1262-1275) |
| starts with `-prunewalletconfs=20`, `=5`, `=100` and none | the "Pruned wallet transactions" line; which of five watched transactions `listtransactions` lists; `gettransaction` of a pruned one; balance; unspent coins; the "Key Pool size" and "Address Book size" lines | max(N, 20) (wallet.cpp:1162-1240, init.cpp:1574-1577); the start's debug print (init.cpp:1613-1618) |
| encryptwallet and walletpassphrasechange | the log lines | "Encrypting Wallet with an nDeriveIterations of <n>", "Wallet passphrase changed to an nDeriveIterations of <n>" (wallet.cpp:949, :836); the count is timed, so only the text is compared |
| a new wallet with no `-upgradewallet` and with 10499, 10500, 61000, 120200, 3000000, 3000001 | the start, `walletversion`, and `walletversion` after encryptwallet | below the base version the load fails; otherwise the version rises to the HD version (wallet.cpp:854-887, :1963-1979, :2336) |

**The refused send.** S pays a key of its own, then spends that coin in X, which every mempool holds. The twins
import the key with a rescan. The rescan reads blocks only, so the coin looks unspent to them, and their send of it is
committed to the wallet, then refused by their own mempool (MempoolConsensus.cpp:296-305).

**The pruned transactions.** Two pairs, each a funding from S and a sweep of its coin from C 25 blocks back, the sweep
built as a raw transaction whose txid is picked to sort above (A) or below (B) its funding's. divid's prune looks at the
transactions in txid order (below), so the two pairs cover both orders whatever the run's txids.

## KNOWN

| rows | why |
|---|---|
| `start with -prunewalletconfs=100: listed`, `: balance`, `: unspent`, `: log: pruned` | divid's PruneWallet sorts the wallet's transactions from its coinbases, finds none in a wallet that does not mine, and goes on in txid order (wallet.cpp:1092-1133, :1185-1197). Pair B's sweep, whose txid sorts below its funding's, is looked at first and left out, though the funding is kept, so the swept coin counts as unspent again: the listing lacks the sweep, the balance is 10 higher, there is one more unspent coin, and the log has one transaction fewer in memory ("Current"). irondivid looks at a transaction only after those it spends and keeps the sweep [on purpose: copying it would count a spent coin as spendable; docs/divid-differences.md W4] |

## Results on hp1 (divid 3.0.0)

| irondivid | PASS | KNOWN | FAIL | time |
|---|---|---|---|---|
| `fix/wallet-gaps-4` (f9fb61c), run 1 | 71 | 4 | 0 | 1 m 53 s |
| `fix/wallet-gaps-4` (f9fb61c), run 2 | 71 | 4 | 0 | 2 m 3 s |
| its base, base-8ff9377 | 45 | 3 | 27 | 1 m 38 s |

On the base the 27 FAILs are:
- the notes of sendfrom from `comment` and `to` (2);
- backupwallet's log line (1);
- the refused send (7);
- `-prunewalletconfs` at 20 and 5 (3 each) and its line at 100 (1);
- the start's key pool and address book lines (8);
- the two encryption lines (2).

Without a prune, irondivid lists all five watched transactions, so the three `=100` KNOWN rows have their shape on the
base too.
