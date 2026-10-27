# The wallet's log lines next to Divi Core

`run.sh` starts three regtest nodes on one chain:
- **S**, a Divi Core 3.0.0 `divid` that mines and pays;
- **C**, a `divid` wallet;
- **I**, an irondivid wallet.

C and I are new wallets of their own. They share no keys, because the keypool's numbers follow what each wallet has
done. Each step runs on both in the same order, and the log lines it writes are compared. Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, in the way listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid, or differs in another way.

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or
over 15 minutes).

```sh
scripts/wallet-logs/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/wallet-logs/run.sh target/release ~/divi-3.0.0/bin 54150 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+5` on 127.0.0.150, the p2p and RPC port of S, C and I, checked
  to be free first.
- `[root]`: a fresh directory (mode 0700) is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.
- `WALLET_LOGS_INJECT=<row name>` makes that row differ, to show a difference is caught; `WALLET_LOGS_WIDE=1`
  prints each value whole.

A run takes about two minutes on hp1. However it ends, every node is stopped and its directory deleted. Needs bash,
`ss` and python3 (standard library only). The passphrase is random and goes over RPC; no key or passphrase is
printed.

## The lines

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c). After each step the script
waits until the log stops growing, then reads what the step wrote.

| lines | divid | compared |
|---|---|---|
| `keypool added key <n>, size=<n>, internal=<0\|1>` | each key TopUpKeyPool adds: its pool index (one past the newest in the pool), the pool's size after it, its chain (wallet.cpp:2093-2112) | every line, in order; a run of more than six is compared by its count, first two and last two |
| `keypool reserve <n>`, `keypool keep <n>`, `keypool return <n>` | a key taken from the pool (the oldest of its chain), kept when used, returned when a send needs no change (wallet.cpp:2154, :2162, :2176) | every line, in order |
| `nFileVersion = <n>`, `Keys: <n> plaintext, <n> encrypted, <n> w/ metadata, <n> total`, `Some keys lack metadata. Wallet may require a rescan` | LoadWallet at each start (walletdb.cpp:529-537) | the lines |
| `CommitTransaction:` and the transaction | CTransaction::ToString of the send (wallet.cpp:1866; primitives/transaction.cpp:51-63, :115-118, :261-280; OutPoint.cpp:29-32) | the header (the hash checked against the send's txid; version, sizes, lock time), each input (whether it spends the funding coin, checked by hash and index rather than compared, since S puts the coin at a random index; the length of the cut scriptSig, a sequence if any), each output (value, and the scriptPubKey as written for the payee, `<own>` for the wallet's change) |
| `<txid's first 10 digits>: Relaying wtx SendMoney` | after the mempool takes a send, SendMoney's format with its arguments the other way round (rpcwallet.cpp:785-788) | that the line is there, for the send's txid |
| the order of a send's lines | the change key reserved as the change output is made, returned at once when the send needs no change, and kept after CommitTransaction's dump (wallet.cpp:1786, :1813-1816, :1866-1868) | the order of its `keypool reserve`, `keep` and `return` lines, the dump and the relay line |

## Steps

1. Each wallet's first start (a new wallet): the keypool lines (2,000 keys added, then the default key reserved and
   kept), LoadWallet's lines, `keypoolsize`.
2. `getnewaddress` twice, `getrawchangeaddress`, `getaccountaddress acct` twice (the second gives the same address).
3. Two coins from S, then sends from each with the other locked: `sendtoaddress <payee> 1` (with change) and
   `sendtoaddress <payee> 1 "sweep_funds"` (no change: the change key is reserved and returned): keypool lines, the
   dump, the relay line, and the order of the lines.
4. `keypoolrefill 1003`, then `keypoolsize`.
5. A restart: keypool lines and LoadWallet's lines.
6. `encryptwallet` (an HD wallet's keypool stays), `keypoolsize`; locked `getnewaddress` and `getrawchangeaddress`
   (no top-up while locked); a restart; unlocked `getnewaddress`.

## KNOWN

None.

## Results on hp1 (divid 3.0.0)

Each run is 35 rows.

| irondivid | PASS | KNOWN | FAIL |
|---|---|---|---|
| before the keep-order fix (base-d1f3fd1) | 34 | 0 | 1 |
| with it, run 1 | 35 | 0 | 0 |
| with it, run 2 | 35 | 0 | 0 |

Before the fix, irondivid logged the change key's `keypool keep` before CommitTransaction's dump: the row for the send
with change read `reserve, keep, dump, relay` where divid's reads `reserve, dump, keep, relay`.
