# Received-by, account address, sendfrom, multisig and staking-status replies next to Divi Core

`run.sh` starts a fresh Divi Core 3.0.0 `divid`, an irondivid restored from divid's phrase, and a second divid with a
wallet of its own (the miner), on one regtest chain. It compares, field by field, the replies of:

- `getreceivedbyaddress`, `getreceivedbyaccount`, `listreceivedbyaddress`, `listreceivedbyaccount`;
- `getunconfirmedbalance`, `getaccountaddress`, `sendfrom`, `addmultisigaddress`, `getstakingstatus`.

The replies are compared across confirmations, a reorganization, watch-only and multisig addresses, change, stake
rewards and a locked wallet. Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 10 minutes).

```sh
scripts/received/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/received/run.sh target/release ~/divi-3.0.0/bin 54150 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+5` on 127.0.0.2 (p2p and RPC of divid, irondivid, the miner).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about a minute and is stopped after 10 minutes. However it ends, the nodes are stopped and their
directories deleted. Needs bash and python3 (standard library only).

- **The phrase:** read from divid's `dumphdinfo` reply and handed to irondivid in its environment
  (`WALLET_MNEMONIC`). It is never printed, written to a file or put on a command line.
- **The wallet passphrase:** made by the run and kept in memory; it is sent only in RPC calls.

`RECEIVED_INJECT=<row name>` changes irondivid's reply of that row before it is compared (the row then FAILs).
`RECEIVED_DUMP=<dir>` writes both replies of every row that is not PASS into `<dir>`.

## Nodes and steps

divid listens; irondivid and the miner dial it (`connect=`). The twins (divid and irondivid) own the same keys and run
with `staking=0`.

**Why a miner.** A block divid makes takes a key from its keypool for the coinbase. irondivid does not see that, so it
would hand out that key next. The miner makes the blocks, so the twins hand out the same keys throughout, and it also
pays the twins as another wallet.

1. **Fresh wallets:** `getstakingstatus`, `getunconfirmedbalance`, and the list calls with `0 true`.
2. **Addresses:** both hand out the same five addresses: X (account `acct1`), Y (`""`), K1..K3 (`keys`).
3. **One coinbase of the wallet:** divid makes one block, whose coinbase key is irondivid's next key. irondivid hands
   out that key and the next, and divid names its coinbase key alike (`setaccount <key> skip`), so the books match
   again.
4. **Watched and other addresses:** W (random bytes) is watched on both (`importaddress W watch false`). OTHER is an
   address of nobody here.
5. **`addmultisigaddress` rows**, then `validateaddress` and `getaccount` of each multisig address.
6. **Coins:** the miner makes blocks to 100 and pays Y 4×5000, and 21 stake blocks mature them.
7. **Stakes and funds:** each twin stakes one block (a stake reward of the wallet). The miner pays Y 12×1000 for the
   sends.
8. **Sends, on both (divid first, irondivid once it has divid's):**
   - X 10, Y 4, W 3, OTHER 2;
   - the 2-of-[K1,K2] multisig 2, and the watched 1-of-[G] multisig 1;
   - the miner pays X 7, unconfirmed (not the wallet's own, so not trusted).
9. **The over-time views:** the received-by and balance replies, each time:
   - while the sends are unconfirmed;
   - at 1 and at 6 confirmations;
   - after `invalidateblock` of the block with the sends, on all three nodes (and `getrawmempool`);
   - after `reconsiderblock`.
10. **Arguments** of the received-by calls.
11. **`getaccountaddress` rows**, then `sendfrom` rows.
12. **Locked wallet:** both wallets are encrypted; rows locked, unlocked for staking only, and unlocked.

## Rows

| call | forms |
|---|---|
| `getreceivedbyaddress` | X, the coinbase key and the stake address with minconf none, 0, 1, 6, 100, -1; Y, W, OTHER, the two multisig addresses, both sends' change with none, 0, 6; minconf `"1"`, 1.5, true, null; `notanaddress`, `""`, 5, a wrong checksum, an address of another network; OTHER with null and `"1"` (0 before minconf is read); `notanaddress "1"` |
| `getreceivedbyaccount` | `""` and `acct1` with minconf none, 0, 1, 6, 100, -1; `keys`, `msig`, `watch`, `watchms`, `skip`, `nosuch` with none, 0; `"*"`, 5, `acct1 "1"`, `5 "1"` (minconf read first), null, `" spaced "`, `"Zürich ✓"` |
| `listreceivedbyaddress`, `listreceivedbyaccount` | none, 0, 1, 6, 100, -1, `0 true`, `1 true`, `0 false true`, `0 true true`, `1 true true`, `100 true false` at each step; `"1"`, `1 "true"`, `1 true "true"`, `1 1`, null, 1.0; the order of the address entries; after `getaccountaddress` and after `sendfrom` |
| `getunconfirmedbalance` | at each step, locked, and with an argument |
| `getaccountaddress` | a new account, twice; `acct1` (X was paid), twice; `keys` (never paid); `""`, twice; `watch`, `msig`; `"*"`, 5, null, `" spaced "`, `"Zürich ✓"`, 300 characters; no account; two; a new account after it was paid, twice; locked |
| `sendfrom` | `""`, `acct1` with coins, `nosuch` without; more than the account or the wallet has; comments; a minconf in place of the comment; empty and null comments; six arguments; to OTHER and W; account `"*"` and 5; bad, wrong-checksum and number addresses; 0, -1, `"1"`, below a satoshi; a number as comment; locked, staking-only and unlocked; then each own send's `amount`, `fee`, `comment`, `to`, `account` |
| `addmultisigaddress` | nrequired 0, -1, n+1, `"1"`; keys not an array, empty, 17, an address not in the wallet, `notakey`, `"00"`, a number; account `"*"`, 5, null; then 1 of [K1], 2 of [K1,K2], 3 of 3, keys as hex, an address and a hex key, a key not in the wallet, one key of each, the same key twice, `""` and another account for one address; locked |
| `getstakingstatus` | fresh, immature coins only, mature coins, after stake blocks, locked, unlocked for staking only, unlocked; `mnsync` and `staking status` on rows of their own |

**How a row compares.** The outcome must be the same: a result, or an error with the same code and message.

- **Results:** every field, value and type, list items in divid's order. Amounts are compared as divid writes them
  (the text of the number).
- **Addresses each twin hands out** (the multisig addresses, `getaccountaddress` results) are written as names in
  both replies, the same name for the n-th address of the same call.
- **The order of a reply's members** is compared once per call, in a `<call>: member order` row.
- **A help text given as an error:** compared with sample addresses written `diviaddress`, as `scripts/help-replies`
  does.
- **divid's non-ASCII text** is read as divi-cli reads it (see KNOWN).

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c).

## KNOWN differences

- **`getstakingstatus (...): mnsync`** (after the first blocks): irondivid has no masternode sync stages and reports
  whether the chain is synced. divid's stages need 3 spork-synced peers to move on (`masternode-sync.cpp:425-455`),
  so on this chain it stays false (as in `scripts/masternode-replies`).
- **`getstakingstatus (after stake blocks): staking status`:** divid counts a stake search made through `setgenerate`
  as staking for 5 minutes (`init.cpp:157-174`). irondivid reports its staker, which is off here (`staking=0`).
- **`<call>: member order`** for `getstakingstatus`, `listreceivedbyaddress`, `listreceivedbyaccount` and
  `validateaddress`: irondivid writes a reply's members in name order (`docs/divid-differences.md` R6).
- **`listreceivedbyaddress: fields divid lacks`:** irondivid adds `label` (as in `scripts/wallet-replies`).
- **`getstakingstatus: fields divid lacks`:** irondivid adds `staking status text`, the staker's state in words.
- **`getaccountaddress ""`** (both rows):
  - divid's last address of an account is the last one ever given that name, even after `setaccount` or
    `addmultisigaddress` moved it to another account (`AddressBookManager`, `rpcwallet.cpp:339-341`).
  - Here divid answers the 1-of-[K3] multisig address, which is now in `msig`.
  - irondivid answers the account's last address that still has the name.
- **`getaccountaddress "fresh" (locked, divid's greatest fresh address the paid one)`:** divid reloads its wallet
  after `encryptwallet` ("Wallet reloaded!"). A wallet read back takes an account's greatest address as its last (the
  address records come in key order). When that is the paid fresh#1 (about half the runs, the keys being random),
  divid hands out a new address; irondivid keeps running its wallet, whose last address is still the unpaid fresh#3.
  In the other runs the row is `getaccountaddress "fresh" (locked)` and both answer fresh#3. (After a restart irondivid does as divid, `crates/divi-wallet/tests/account_order_tests.rs`.)
- **`getaccount <the "Zürich ✓" address>: the text as written`:** divid writes each byte of non-ASCII text as its own
  `\u00XX` escape (json_spirit), which divi-cli reads back as bytes. irondivid writes the text as UTF-8. Every other
  row reads divid's text as divi-cli does.

No other row differs from divid.
