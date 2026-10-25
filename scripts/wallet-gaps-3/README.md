# Wallet cases with stakes, a block taken off the chain, or a damaged wallet

`run.sh` starts three regtest nodes on one chain:
- **S**, a Divi Core 3.0.0 `divid` that mines and stakes;
- **C**, a `divid` wallet;
- **I**, an irondivid restored from C's phrase, so C and I own the same coins and parse the same transactions.

Each case below runs on both twins, and its outcome is compared. The damaged-key case is the exception: it runs on
divid alone, checked against what its code does (see the last section). Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, in the way listed below with the reason (none at present);
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid.

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 15 minutes).

```sh
scripts/wallet-gaps-3/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/wallet-gaps-3/run.sh target/release ~/divi-3.0.0/bin 53950 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+9` on 127.0.0.2. These are the p2p and RPC ports of S, C and I, then of the two divid-only nodes. S listens; C and I dial it.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 7 minutes (measured on hp1) and is stopped after 15. However it ends, every node is stopped and its
directory deleted. Needs bash and python3 (standard library only). `WALLET_GAPS_3_INJECT=<row name>` makes that row
differ, to show a difference is caught.

**Secrets.** C's phrase is read from its `dumphdinfo` reply and handed to irondivid in its environment (`WALLET_MNEMONIC`).
The two imported keys are a throwaway divid's, read with `dumpprivkey`, and the passphrase is random; both go over RPC
only. None is printed, written to a file of the run's own, or put on a command line.

## Rows (Divi Core 3.0.0, `divi/src/`)

| case | divid |
|---|---|
| C mines blocks 1-5; both twins `invalidateblock` block 5. Compared: block 5's coinbase in `listtransactions`, its `gettransaction` confirmations and details, `getbalance`; then again after `reconsiderblock` | A coinbase at depth below 1 would list as `orphan` (rpcwallet.cpp:2193-2199). divid drops the coinbase of a block taken off the chain, though: it is not listed at all, confirmations -1, no details. Back on the chain it is `immature`. |
| C stakes at an ordinary height (S has mined to 100 and paid C six coins of 12000 at one address, so each stakes alone, PoSTransactionCreator.cpp:172-210) | One entry, vout 1. It is `stake_reward` when the staker's outputs come to more than the height's stake reward, else `stake_reward+` (rpcwallet.cpp:2049-2081). On regtest no masternode is paid, so the staker takes that part too: `stake_reward`. |
| that stake in `listtransactions ""` and `listtransactions "savings"` | A stake is listed only for its own account, `""` (rpcwallet.cpp:2051-2052) |
| S stakes a lottery block (every 10th from 101, not a treasury block, every 50th from 102) after a cycle in which C staked | C's winnings in S's coinstake: one `lottery` entry per output (rpcwallet.cpp:2082-2110); in `listtransactions ""` too (the address's account), not in `"savings"`; `gettransaction` details |
| C stakes the next lottery block | C's entries, and `gettransaction` amount, fee and details |
| after the stakes | `getbalance`, and how many entries of each category `listtransactions "*"` gives |
| `signmessage <C's address> <text> "hex"` for `6869zz`, `68 69 7a`, `zz6869`, `686`, `6g69` and `""` | ParseHex reads pairs of hex digits, skips spaces between them, and stops at the first pair that is not hex. The message signed is what it read (rpcwallet.cpp:1389-1395). The twins hold the same key and sign deterministically, so the signatures are compared. |

## divid only: an imported key damaged

On a throwaway divid:
1. Two imported keys, `encryptwallet`, stop.
2. In `wallet.dat`, one byte of one key's ciphertext is changed, in every copy of its `ckey` record. The record's value sits just before its key item: a 3-byte header, the length 48, then the ciphertext.
3. Start, then `walletpassphrase`.

CCryptoKeyStore::Unlock decrypts the keys in CKeyID order (crypter.cpp:225-250):
- **the first key damaged:** -14 `Error: The wallet passphrase entered was incorrect.`, the node stays up, nothing is logged;
- **the second key damaged:** `The wallet is probably corrupted: Some keys decrypt but not all.` is logged, and the node stops on an assert, with no reply.

Rows are `divid only, …`: the outcome divid's code gives, then what divid did.

irondivid's database cannot be damaged in place by this script, so its side is a Rust test,
`crates/divi-wallet/tests/encryption_tests.rs` `a_damaged_imported_key_is_a_wrong_passphrase_or_logged_as_corruption`:
- the same order and the same log line;
- -14 in both cases;
- irondivid stays up and locked where divid stops (on purpose: a damaged key is no reason to end the process).
