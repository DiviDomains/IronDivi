# Number arguments of every call, next to Divi Core

`run.sh` starts a fresh Divi Core 3.0.0 `divid` and a fresh irondivid on regtest, side by side on one chain. Both
wallets come from the same phrase. It sends every number argument of divid's command table the same values on both,
and compares the replies. Each row is one (call, argument, value) and prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, or is not sent, for the reason listed below;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with a count of each and `FAILS <n>`. The exit code is the number of FAILs (255: usage error,
interrupted, or over 10 minutes).

```sh
scripts/int-args/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/int-args/run.sh target/release ~/divi-3.0.0/bin 54300 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` (divid p2p and RPC, then irondivid's), on 127.0.0.2, or on
  `INT_ARGS_HOST` when it is set.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 2 minutes and is stopped after 10. However it ends, both nodes are stopped and their directories
deleted. Needs bash and python3 (standard library only). RPC passwords are made at random for each run and kept in
each node's 0600 `divi.conf`. The wallet phrase is passed to irondivid in its environment only.

## How divid reads a number

divid's calls read a number with one of three json_spirit getters (`json/json_spirit_value.h:339-417`). Any other
JSON type makes the getter throw "value is type X, expected Y", which the server answers as -1
(`rpcserver.cpp:1107-1108`).

| getter | takes | what it gives |
|---|---|---|
| `get_int()` | an integer | its 64 bits cut to a C++ `int` (`static_cast<int>`, :385-390): 2^32+41 is 41, 2^31 is -2^31 |
| `get_int64()` | an integer | the integer |
| `get_real()` | an integer or a real | a double (`AmountFromValue`, `JsonTxHelpers.cpp:98-111`) |

json_spirit reads `1e3` as a real. A `"5"` is a string, and `true` a bool. A `null` is refused by every getter, and a
call reads it whenever its code tests only the argument count. `RPCTypeCheck` refuses with -3 "Expected type X, got
Y" before a getter runs (`rpcserver.cpp:195-231`).

## Values

Each argument below is sent each of:

| value | what get_int() makes of it |
|---|---|
| 2^31-1 | 2147483647 |
| 2^31 | -2147483648 |
| 2^31+41 | -2147483607 |
| 2^32 | 0 |
| 2^32+41 | 41 |
| 2^32+2^31 | -2147483648 |
| -2^32+2 | 2 |
| -1 | -1 |
| 2^53+1 | 1 |
| 1.5, 1e3 | refused: real |
| "5" | refused: str |
| true | refused: bool |
| null | refused: null |

The values go into the request as their JSON text, so `1e3` stays a real.

## Calls

divid mines 40 blocks, pays 10 to its address A, and mines to block 112, past the first lottery block (101). Both
wallets share the phrase; irondivid gets A's account "" with `setaccount`, as divid's address book has it.

| call | argument | getter (Divi Core `divi/src/`) |
|---|---|---|
| getblockhash | height | get_int, `rpcblockchain.cpp:168` |
| gettxout | n | get_int, `rpcblockchain.cpp:369` |
| verifychain | numblocks (second argument: divid reads `params[1]` whenever one is given, :418-420) | get_int, `rpcblockchain.cpp:420` |
| getlotteryblockwinners | height | get_int, `rpclottery.cpp:50` |
| getrawtransaction | verbose | get_int, `rpcrawtransaction.cpp:207` |
| listunspent | minconf, maxconf | RPCTypeCheck int, get_int, `rpcrawtransaction.cpp:286-294` |
| createrawtransaction | an input's vout; an output's amount | get_int, `:420-422`; get_real, `:438` |
| signrawtransaction | a prevtx's vout | RPCTypeCheck int, get_int, `:722-726` |
| signtransactionwithaddresskey | input index | get_int, `:572` |
| createmultisig, addmultisigaddress | nrequired | get_int, `rpcmisc.cpp:390` |
| getaddresstxids, getaddressdeltas | start, end | get_int, `rpcmisc.cpp:645-646`, `:735-736` |
| getspentinfo | index | get_int, `rpcmisc.cpp:909` |
| getreceivedbyaddress, getreceivedbyaccount | minconf | get_int, `rpcwallet.cpp:1461`, `:1520` |
| getbalance | minconf, for "*" and for an account | get_int, `rpcwallet.cpp:1582`; for "*" not read (:1576-1577) |
| listreceivedbyaddress, listreceivedbyaccount | minconf | get_int, `rpcwallet.cpp:1798` |
| listtransactions | count, from | get_int, `rpcwallet.cpp:2276`, `:2279` |
| listaccounts | minconf | get_int, `rpcwallet.cpp:2343` |
| listsinceblock | target-confirmations | get_int, `rpcwallet.cpp:2420` |
| prioritisetransaction | fee delta | get_int64, `rpcmining.cpp:272` |
| lockunspent | an output's vout (then `listlockunspent`, then all unlocked) | RPCTypeCheck int, get_int, `rpcwallet.cpp:2795-2801` |
| keypoolrefill | newsize | get_int, `rpcwallet.cpp:2559-2561` |
| walletpassphrase | timeout (an unencrypted wallet is refused first) | get_int64, `rpcwallet.cpp:2622` |
| sendtoaddress, sendfrom | amount | get_real, `rpcwallet.cpp:1331`, `:1635` |
| sendmany | an amount; a repeated output's amount and repetitions | get_real, `:1679`; RPCTypeCheck real and int, get_real, get_int, `:1668-1675` |
| fundvault | amount | get_real, `rpcwallet.cpp:998` |
| setmocktime | timestamp (then set back to 0) | RPCTypeCheck int, get_int64, `rpcmisc.cpp:539-540` |
| setgenerate | numberofblocks | get_int, `rpcmining.cpp:79` |
| generateblock | blockBitsShift | RPCTypeCheck int, get_int, `rpcmining.cpp:144`, `:202` |

The calls that move the clock or the chain come last. Other calls in the table take no number: `getmasternodewinners`
and `startmasternode` read numbers from strings with `atoi` (`rpcmasternode.cpp:544-578`), and the rest take strings,
bools, arrays and objects.

How a row compares:
- Both must have the same outcome: a result, or an error with the same code and message. A help text is compared by
  its code -1 and its first word.
- An "Insufficient funds" error is compared without its total available: each wallet has paid its own fees by then.
- A result is compared field by field. Wallet lists are compared as sorted (txid, vout, category, amount, address,
  account) entries. A send's or a mined block's hash counts as "a txid", and a vault fund as "funded".
- `gettxout` is compared without irondivid's `coinstake` field, as `scripts/chain-replies` does. divid gives `coinbase`
  only (`rpcblockchain.cpp:398-399`).

## KNOWN differences and rows not sent

- **`getlotteryblockwinners height 2^31`, `2^31+41`, `2^32+2^31`, `-1`:** not sent to divid. A height below 0 after
  get_int() makes divid read a null block (`rpclottery.cpp:50-53`) and stop. irondivid's answer, for genesis, is
  shown only.
- **`signtransactionwithaddresskey input index`** `2^31-1`, `2^31`, `2^31+41`, `2^32+41`, `2^32+2^31`, `-2^32+2`,
  `-1`, `2^53+1`: not sent to divid. An index past the transaction's one input makes divid read `vin[index]`
  (`rpcrawtransaction.cpp:572`, `:589`) and abort. irondivid's answer is shown only.
- **`signrawtransaction prevtxs vout 2^31-1`:** divid's answer is an accident. It sizes a coins entry for output
  2^31-1 (`rpcrawtransaction.cpp:726`, `:740-741`), fails to allocate it, and answers -1 "vector::_M_default_append".
  irondivid takes the outpoint as given.
- **Sent to neither node:**
  - `setgenerate numberofblocks 2^31-1`: divid's get_int() keeps 2^31-1 blocks, which take days. `2^31` and
    `2^31+41` are below 0 for divid, but irondivid before this check mined that many.
  - `keypoolrefill newsize 2^31-1`: 2^31-1 keys take days on either node.
  - `sendmany repetitions` `2^31-1`, `2^31`, `2^31+41`, `2^32`, `2^32+41`, `2^32+2^31`, `2^53+1`: get_int() makes up
    to 2^31-1 outputs (`rpcwallet.cpp:1675`), and irondivid before this check made the uncut count, billions of
    outputs.

The object form of `fundvault` (`{"owner:manager": {"amount", "repetitions"}}`, `rpcwallet.cpp:1004-1035`) has no
rows: irondivid takes the `"[owner:]manager" amount` form only.

No other row differs from divid.

## Proving a difference is caught

`INT_ARGS_INJECT=<row name>` changes irondivid's reply of that row before it is compared, e.g.
`INT_ARGS_INJECT='getblockhash height 2^32+41'`: that row prints `FAIL` and the run exits 1.
`INT_ARGS_DUMP=<dir>` writes both replies of every row that differs to `<dir>`.
