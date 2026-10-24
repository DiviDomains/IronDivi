# Vault RPC replies next to Divi Core

`run.sh` starts four regtest nodes on one chain:
- Divi Core 3.0.0's `divid` as a vault owner, and as a vault manager (`vault=1`);
- an irondivid owner and an irondivid manager (`vault=1`), restored from the two divid phrases.

It makes the same vault steps on both sides and compares the replies and the wallet views field by field, before and after a restart of all four. Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 10 minutes).

```sh
scripts/vault-replies/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/vault-replies/run.sh target/release ~/divi-3.0.0/bin 53700 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: five ports on 127.0.0.1:
  - `<port-base>`: the divid owner's p2p port (the only node that listens);
  - `+1`, `+2`: the RPC ports of the divid owner and the divid manager;
  - `+3`, `+4`: the RPC ports of the irondivid owner and the irondivid manager.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about a minute and is stopped after 10 minutes. However it ends, all four nodes are stopped and their directories deleted.

Needs bash and python3 (standard library only). The two phrases are read from the divid nodes' `dumphdinfo` replies and handed to irondivid in its environment (`WALLET_MNEMONIC`). The wallet passphrase used for the locked rows is random and lives only in memory. None of them is ever printed, written to a file or put on a command line.

The ports are inside Linux's ephemeral range (32768-60999), so one can be held for a moment by the local end of an outbound connection, or for up to a minute by a closed connection in TIME-WAIT from an earlier run. A node that cannot bind is therefore started again, 2 s apart, for up to a minute.

## Nodes and steps

The divid owner listens; the other three dial it (`connect=`), so all four see one chain. Each irondivid wallet holds the same keys as its divid twin. All run with `staking=0`; the managers stake through `setgenerate`.

Every step that sends is made on divid first, then on irondivid once every node has seen divid's transaction. The two replies are compared with txids masked, and the two transactions are compared by the roles and values of their outputs: destination, vault (whose keys), wallet change, other.

1. **Coins:** divid's owner mines 101 blocks. The owner address `OWN` is the divid owner's and the manager address `MGR` the divid manager's.
2. **fundvault**, two forms:
   - `"OWN:MGR" 100`;
   - the manager-only form `"MGR" 50`, where the owner key comes from each wallet's own keypool, so the owner half of the encoding is compared as "a new key".
3. **addvault** `"OWN:MGR" <funding txid>` on both managers, for divid's and for irondivid's funding.
4. **The owner spends**, a block between each:
   - `debitvaultbyname "OWN:MGR" DEST 10`, plain and with `receiver_pays`;
   - `reclaimvaultfunds DEST 10`, plain, `receiver_pays`, and `metadata "rent" "landlord"`;
   - `debitvaultbyname ... sweep_funds` on a vault funded just before each side, since a sweep empties a vault.
5. **Spending a vault whose only coins are unconfirmed change** while another vault has confirmed coins.
6. **The managers stake a vault coin with `setgenerate 1`.** Each manager first gets fresh vault coins, and the script waits until the clock passes the tip's time, because divid looks for a stake time back from the clock. The coinstakes are compared by the roles of their outputs, since the coins each combines differ.
7. **removevault** `"OWN:MGR"`, then again (the vault is no longer registered), then with a second `tx_hash` argument.
8. **Refusals:**
   - a bad manager-only encoding, a bad owner, a bad manager;
   - an amount too high;
   - addvault or removevault without `:`, on the wrong wallet, with an unknown funding txid;
   - debitvaultbyname from the manager wallet, with a bad destination, with a bad fee mode;
   - reclaimvaultfunds with a bad address, an amount too high, a bad fee mode.
9. **Restart:** all four nodes are stopped and started again, and the views are compared again (`after restart:` rows).
10. **Locked:** both owner wallets are encrypted with one random passphrase, then `fundvault`, `debitvaultbyname` and `reclaimvaultfunds` are refused (`locked:` rows).

After each step, the views of each twin pair (owner against owner, manager against manager):
- `getbalance` with no arguments, with `* 1 true`, and with `* 0`;
- `listunspent`;
- `listtransactions * 100 0 true`;
- `gettransaction` of every vault transaction made so far, with includeWatchonly;
- `getcoinavailability`, and `getcoinavailability true`;
- `getwalletinfo` (divid's fields; irondivid's extra fields are left out, as in `scripts/wallet-replies`).

## How a row compares

The same outcome: a result, or an error with the same code and message. For a result, every field and value must match.

Left out of the comparison:
- `time` and `timereceived`, which come from the moment a node saw a transaction;
- the notes `comment`, `to` and `FromAccount`, which only the sending node has.

List items are compared sorted (txid, vout, category). `getcoinavailability`'s `txids` and vault lists are compared as sets.

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c).

## KNOWN differences

By design:
- `getcoinavailability`: irondivid adds `total_vaults` and `vaults`; divid has `Vaulted`, `Stakable` and `Spendable` only (`rpcwallet.cpp:818-987`). Compared without them; their names are checked in the `getcoinavailability: fields divid lacks` rows.
- `removevault` with a second argument: irondivid still takes it for older IronDivi callers (its help says so); divid takes exactly one and answers with its help text (`rpcwallet.cpp:1194-1201`).

Open, not closed yet. Each is listed so the run stays usable; a fix turns the row into a FAIL until it is taken out here and in `KNOWN` in `check.py`.
- **`owner listunspent`:** irondivid gives `account ""` on coins of keys divid never put in its address book (its miner takes them from the keypool); divid leaves `account` out (`rpcrawtransaction.cpp:320-325`). The same row is open in `scripts/wallet-replies`.
- **`reclaimvaultfunds` replies:** divid answers the txid as a string (`rpcwallet.cpp:1189`), irondivid an object `{amount, fee, txid}`. This is RPC-LEFT row 2, open: rpc-left.
- **After `removevault`, the manager's `listtransactions` and the manager's `gettransaction` of the vault transactions:**
  - divid's `removevault` only drops the vault script from memory (`wallet.cpp:707-716`). It keeps the wallet's transactions and amounts, and reads the script back from its wallet file at the next start, so after a restart the vault is managed again.
  - irondivid removes the vault and its records for good.
- **`after restart: getwalletinfo`:** `keypoolsize` is 1999 on divid and 2000 on irondivid after the restart (equal before it). The same row is open in `scripts/wallet-replies`.

Fixed on branch `fix/vault-replies`, which takes them out of this list:
- `removevault` reply: irondivid adds `result` and `message`; divid answers `{removal_status}` only (`rpcwallet.cpp:1226`).
- `removevault` of a vault the wallet does not hold: divid answers `{removal_status: true}`, since `RemoveVault` is true in vault mode (`wallet.cpp:707-713`); irondivid refuses with -4.
- `removevault` with a bad owner or manager: divid -5 "Vault Registry Failed: Invalid owner DIVI address" / "...manager..." (`rpcwallet.cpp:1215-1221`); irondivid -1 with its own text.
- `debitvaultbyname` from a wallet without the owner key: divid's text names the ownership type, "Vault owner key is unknown: ownership=0 address=..." (`rpcwallet.cpp:1103-1104`).
- `debitvaultbyname` of a vault with only unconfirmed coins while another vault has confirmed coins:
  - divid's balance check is over all vaults and passes (`rpcwallet.cpp:727-734`); its coin selection then fails with -4 "Insufficient funds to meet coin selection algorithm requirements." (`rpcwallet.cpp:796-800`, `wallet.cpp:1779`);
  - irondivid answers -6 "No funds available in vault ...".

## Proving a difference is caught

`VAULT_REPLIES_INJECT=<row name>` changes irondivid's reply of that row before it is compared, for example `VAULT_REPLIES_INJECT='after fundvault: owner getbalance []'`. That row prints `FAIL` and the run exits 1.

`VAULT_REPLIES_DUMP=<dir>` writes both replies of every row that differs to `<dir>`, for looking into a FAIL.
