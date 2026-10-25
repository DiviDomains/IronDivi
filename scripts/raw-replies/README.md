# Raw-transaction RPC replies next to Divi Core

`run.sh` starts a fresh Divi Core 3.0.0 `divid` and an irondivid restored from divid's phrase on one regtest chain
that divid mines. Both nodes therefore hold the same keys and the same coins. The raw transactions are made once, on
divid, and the same ones go to both nodes. The script compares the raw-transaction replies field by field: names,
JSON types, values in divid's units, and error codes and texts. Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with `FAILS <n>`. The exit code is the number of FAILs. It is 255 for a usage error, an interrupted
run, or a run over 10 minutes.

```sh
scripts/raw-replies/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/raw-replies/run.sh target/release ~/divi-3.0.0/bin 54150 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` on 127.0.0.1 (divid p2p and RPC, then irondivid's).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

**Run time and clean-up.** A run takes about 10 seconds and is stopped after 10 minutes. However it ends, both nodes
are stopped and their directories deleted.

**Requirements.** bash and python3 (standard library only).

**Secrets.** The phrase is read from divid's `dumphdinfo` reply and handed to irondivid in its environment
(`WALLET_MNEMONIC`). The two private keys the given-key rows pass to `signrawtransaction` come from divid's
`dumpprivkey`. None of these is printed, written to a file or put on a command line; they travel only in RPC
messages to the two local nodes.

## Nodes and steps

divid listens and irondivid dials it (`connect=`). Both run with `staking=0` and `txindex=1`.

1. divid mines 30 blocks.
2. Five wallet addresses, A, B, N, Y and Z. Two multisig addresses from A's and B's keys (`createmultisig`): 1-of-2
   and 2-of-2.
3. One block with the coins the raw transactions spend: 50 and 30 DIVI to A, 20 DIVI to each multisig address, 1 DIVI
   to B (for the low fee), and 150 DIVI to B (for the high fee). The coins to A and B are locked on divid
   (`lockunspent`), so no send of its wallet takes them.
4. The raw transactions are made on divid (`createrawtransaction`, `signrawtransaction`), with outputs given in name
   order (see KNOWN below). The 1-of-2 P2SH spend, signed with A's key and the redeemScript, goes to both mempools.
5. The rows below. The last rows send a wallet-signed spend: to divid first, then the same hex to irondivid. Then
   `getrawtransaction` of it on both.

## Rows

| call | forms |
|---|---|
| `createrawtransaction` | one output; two inputs and two outputs; outputs as an array; no inputs; no outputs; a script as the output key; 8 decimals; amount as text; negative amount; over 21 million; bad address; the same address twice (array form); txid not hex; txid of 2 digits; missing vout; negative vout; vout as text; an input that is not an object; inputs not an array; outputs a number; one, none and three arguments |
| `decoderawtransaction` | unsigned, wallet-signed, two outputs, a P2SH spend, a half-signed 2-of-2, a funding transaction, a coinbase, no inputs; not hex, odd length, not a transaction, empty, a number, none, two arguments |
| `decodescript` | 1-of-2 and 2-of-2 redeemScripts, P2SH, P2PKH, P2PK, OP_META, nonstandard, empty, a truncated push; not hex, a number, none, two arguments |
| `signrawtransaction` | **keys:** wallet keys; given prevtxs and a private key; a private key without prevtxs; the key of another address<br>**P2SH:** 1-of-2 with redeemScript and key; 1-of-2 with redeemScript and wallet keys; 1-of-2 without the redeemScript; 2-of-2 with one key, then the second key on the half-signed hex<br>**prevtxs:** an unknown input; a prevtx for it; a prevtx whose script differs from the coin's; without scriptPubKey; negative vout; txid not hex; not an object; not an array<br>**privkeys:** a bad private key; not an array<br>**sighash:** ALL, NONE, SINGLE and each `\|ANYONECANPAY`; lower case; a bad one; a number<br>**other:** not hex, not a transaction, a number, none, five arguments |
| `sendrawtransaction` | already in the chain; an unknown input; a fee below the relay fee (1 DIVI coin, 100 satoshis); a fee above the maximum (149 DIVI); allowhighfees as text; not hex; not a transaction; a number; none; three arguments; and, last, a good spend on both |
| `getrawtransaction` | a block transaction 0/1/default; the mempool spend 0/1; a coinbase; the P2SH funding; verbose 2; verbose as text; unknown; not hex; a 2-digit txid; a number; none; three arguments; the sent spend |
| `createmultisig`, `addmultisigaddress` | 1 of 2 keys; 2 of 3; an address and a key; an address without a key; a P2SH address; 0 required; more required than keys; 17 keys; a key that is not hex; a key that is no point; nrequired as text; keys not an array; one, none and too many arguments; `addmultisigaddress` with an account, then `getaddressesbyaccount` of it |

**How a row compares.** The two nodes must have the same outcome: a result, or an error with the same code and
message. For a result, every field must match in name, JSON type and value, with list items in divid's order. Reals
are compared as the text of the number.

**Wrong argument count.** divid answers -1 with the call's whole help text, so for these rows only the code is
compared (both -1), as in `scripts/chain-replies`.

**Not compared here.** Rows `crates/divi-rpc/tests/core_replies.rs` already pins, and blockchain calls
(`scripts/chain-replies`).

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c).

## KNOWN differences

By design (the same rows as in `scripts/chain-replies`):

- `decoderawtransaction`: irondivid adds `valueSat` beside `value` on each output, as divid's getrawtransaction
  writes it (`rpcrawtransaction.cpp:96-97`). divid's decoderawtransaction writes value only (`TxToJSON`,
  `JsonTxHelpers.cpp:66`).
- `decodescript`: irondivid adds `hex`, the script given (divid: `rpcrawtransaction.cpp:556-563`).

**Outputs in name order.** `createrawtransaction` with outputs given as an object keeps them in the order given on
divid, and sorted by address on irondivid. That is an open row in `scripts/chain-replies`. Here the outputs are given
in name order, so the transactions this script builds are the same on both.

## Proving a difference is caught

- `RAW_REPLIES_INJECT=<row name>` changes irondivid's reply of that row before it is compared. For example,
  `RAW_REPLIES_INJECT="signrawtransaction with the wallet's keys"` makes that row print `FAIL` and the run exit 1.
- `RAW_REPLIES_DUMP=<dir>` writes both replies of every row that differs to `<dir>`.
