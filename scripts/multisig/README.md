# A multisig address from creation to spend, next to Divi Core

`run.sh` starts a Divi Core 3.0.0 `divid` that mines a regtest chain, and five wallets of each daemon on that chain:
five `divid` and five irondivid nodes. It makes the same multisig calls on each daemon's wallets and compares the
replies field by field: `createmultisig` and `addmultisigaddress` in many forms, the address funded with
`sendtoaddress`, the wallet views of it (all keys, one key, watch-only without and with rescan), the address index,
signing a spend of it with partial and complete signatures, `sendrawtransaction`, and a restart. Each row prints one
line:

- `PASS`: same as divid;
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not, a `KNOWN` row that differs in another way, or a `KNOWN` row that now matches
  divid (the list below is out of date).

The run ends with a count of the rows and `FAILS <n>`; the exit code is the number of FAILs (255: usage error,
interrupted, or over 10 minutes).

```sh
scripts/multisig/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/multisig/run.sh target/release ~/divi-3.0.0/bin 54300 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+21` on 127.0.0.2 (`MULTISIG_HOST`): p2p and RPC of the miner,
  then of the five divid and five irondivid wallets.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes under a minute and is stopped after 10. However it ends, every node is stopped and its directory deleted.
Needs bash and python3 (standard library only). RPC passwords are made at random and kept in each node's 0600
`divi.conf`. The three private keys are made on the miner and handed to the wallets with `importprivkey`; they live
only in memory and in RPC request bodies and are never printed or put on a command line.

## Nodes and keys

The miner listens; every wallet node dials it (`connect=`), so all see one chain. All run with `staking=0`,
`txindex=1`, `addressindex=1`, `spentindex=1`. The miner mines 40 blocks and makes three keys (and 14 more public
keys, for the many-key forms). Each daemon gets five wallets:

| wallet | holds |
|---|---|
| `all` | the three keys |
| `k1`, `k2` | key 1, key 2 |
| `w0`, `w1` | no key: the address imported with `importaddress` without (`w0`) and with (`w1`) rescan |

The address of the run is the 2-of-3 of the three keys, added with `addmultisigaddress` on `all`, `k1` and `k2`.
Each `k2` wallet pays it 50 from its own coins (`sendtoaddress`), and the miner pays it 30: the coin both daemons
sign alike.

## Rows

| group | forms |
|---|---|
| createmultisig (on `k1`) | 1-of-1; 2-of-3 and 3-of-3 of hex keys; 2-of-3 of addresses, of a mix, with an uncompressed key; 15, 16 (redeemScript over 520 bytes) and 17 keys; nrequired 0, above the key count, negative, as text; a duplicate key; bad hex; a key of the wrong length; an empty array; keys as text; an address whose key the wallet lacks; three arguments; none |
| addmultisigaddress (on `all`) | the same forms; with an account, the account as a number, four arguments; the run's address on `k1` and `k2` |
| the address | `validateaddress` on `all`, `k1`, `w0` before and after its import; `decodescript` of the redeemScript; `getaddressesbyaccount`; `getaccount` |
| funding | `sendtoaddress` to it |
| import | `importaddress` without rescan (`w0`), with rescan (`w1`), again, on a wallet that holds the keys, of the redeemScript hex |
| wallet views (each of `all`, `k1`, `w0`, `w1`) | `listunspent 0` (its entries), `getbalance`, `getbalance * 0 true`, `listtransactions * 100 0 true` (its entries), `getreceivedbyaddress` with 1 and 0 confirmations: after funding, after the spend, after a restart |
| address index (on `all`) | `getaddressbalance`, `getaddressutxos`, `getaddresstxids`, `getaddressdeltas`: before and after the spend |
| signing the miner's coin | `createrawtransaction`; `signrawtransaction` with one key (`k1`), the partial hex with the second key (`k2`), the same key again, all keys, no key; private keys with prevtxs without and with redeemScript, two keys, no prevtxs, a wrong key, a bad key; prevtxs with redeemScript on a wallet; prevtxs without scriptPubKey, with a wrong one; each sighash type and an unknown one; not hex; no arguments. Signatures are deterministic (RFC 6979), so the hex compares byte for byte |
| spending | each daemon's own coin: `sendrawtransaction` of the partial hex (the error), the complete hex (a txid), and again |
| restart | every wallet node stopped and started; the wallet views, `validateaddress`, `getaddressesbyaccount` |

How a row compares: the same outcome; an error with the same code and message (divid's help texts by their first
line); a result with the same fields, JSON types and values. Lists are compared sorted by txid/vout; `confirmations`
and the time fields of `listtransactions` are left out (the nodes see a block a moment apart).

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c): `rpcmisc.cpp` (createmultisig
:445, `_createmultisig_redeemScript` :388, validateaddress :320, DescribeAddressVisitor :226), `rpcwallet.cpp`
(addmultisigaddress :1736), `rpcrawtransaction.cpp` (decodescript :527, signrawtransaction :602), `rpcdump.cpp`
(importaddress :105).

## KNOWN differences

- `listunspent: fields divid lacks`: irondivid's `ischange` and `solvable`, kept as extra fields (as in
  `scripts/wallet-replies`); the entries are compared without them.
- `decodescript: fields divid lacks`: irondivid's `hex`, the script given (as in `scripts/raw-replies` and
  `chain-replies`; divid's decodescript calls ScriptPubKeyToJSON without it, rpcrawtransaction.cpp:556-563).
- `importaddress of the redeemScript hex (w0)`: irondivid watches P2PKH and P2SH scripts only (its watch list is kept
  by address) and refuses another script with -4; divid watches any script (rpcdump.cpp:122-148). A watched script
  never brings a transaction into divid's wallet (wallet.cpp:1299-1309 adds only what credits or debits a spendable
  output), so the reply is the only difference.

No other row differs from divid.

## Proving a difference is caught

`MULTISIG_INJECT=<row name>` changes irondivid's reply of that row before it is compared, e.g.
`MULTISIG_INJECT='validateaddress of it (k1)'`: that row prints `FAIL` and the run exits 1.
`MULTISIG_DUMP=<dir>` writes both replies of every row that differs to `<dir>`.
