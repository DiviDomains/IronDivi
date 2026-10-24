# Utility RPC replies next to Divi Core

`run.sh` starts a fresh Divi Core 3.0.0 `divid` and an irondivid restored from divid's phrase on one regtest chain, and
compares the replies of the utility calls (validateaddress, signmessage, verifymessage, the fee estimates, getinfo,
getmininginfo, getdifficulty, verifychain, help, and calls neither node has), each with good arguments and with wrong
or missing ones, before and after a restart of both nodes. Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 10 minutes).

```sh
scripts/util-replies/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/util-replies/run.sh target/release ~/divi-3.0.0/bin 53950 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` on 127.0.0.1 (divid p2p and RPC, then irondivid's).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 30 seconds and is stopped after 10 minutes. However it ends, both nodes are stopped and their
directories deleted. Needs bash and python3 (standard library only). The phrase is read from divid's `dumphdinfo`
reply and handed to irondivid in its environment (`WALLET_MNEMONIC`); it is never printed, written to a file or put
on a command line.

## Nodes and steps

divid listens; irondivid dials it (`connect=`), so both see one chain, and both wallets own the same keys. Both run
with `staking=0`.

1. divid mines 40 blocks.
2. Addresses: `X`, handed out by divid with `getnewaddress acct1` and given the same account on irondivid
   (`setaccount`); `W`, random bytes, imported on both with `importaddress <W> watch false`; `F`, random bytes, in
   neither wallet; `M`, divid's `createmultisig 1 [X's key]` (P2SH, in neither wallet); `D`, random bytes as a main
   network address (version 30).
3. One send from divid to `F` stays in both mempools (so `getmininginfo`'s `pooledtx` is not 0); divid signs `hello`
   with `X` for the verifymessage rows.
4. The replies below; both nodes are stopped and started again; the replies again (`after restart:` rows).

## Rows

| call | forms |
|---|---|
| `validateaddress` | own `X`, watched `W`, foreign `F`, foreign multisig `M`, other network `D`, garbage, `""`, no arguments, one too many, not a string |
| `signmessage` | `X hello`; hex message; b64 message; hex signature; `W`, `F`, `M`, garbage address; message missing; no arguments; one too many; address not a string |
| `verifymessage` | divid's signature: good; wrong address `F`; watched address `W`; wrong message; bad base64; short signature; garbage address; multisig address; message missing; no arguments; one too many; signature not a string |
| `estimatefee`, `estimatepriority` | none and `2`; `2` |
| `getinfo`, `getmininginfo`, `getdifficulty` | none; one argument too many |
| `getnetworkhashps`, `settxfee`, `getblocktemplate` | none and with arguments (neither node has them) |
| `verifychain` | none, `4 10`, `9 10`, `0 0`, `1 2 3`; `4` and `"x"` on irondivid only (below) |
| `help` | none (the list), `""`, each of validateaddress, signmessage, verifymessage, getinfo, getmininginfo, getdifficulty, verifychain, help; an unknown call; not a string; one too many |

How a row compares: the same outcome (a result, or an error with the same code and the whole message); for a result
every field and value. `timeoffset` is left out of `getinfo` (it moves with the clock). A wrong argument count makes
divid answer -1 with the call's whole help text, so those rows and the `help <call>` rows compare the whole text,
Examples included. divid's examples name sample addresses of other coins' main networks (e.g. `rpcmisc.cpp:338`);
irondivid's examples say `diviaddress`, so on example lines (`> ...`) a quoted address reads as `diviaddress` on both
sides. The `help` list row compares divid's list with irondivid's list up to its first `(irondivid)` section.

`verifychain` with one argument: divid reads a second argument that is not there (`rpcblockchain.cpp:419-420`,
`params[1]` when `params.size() == 1`), so its reply is undefined (seen: -1 "value is type <random text>, expected
int", and once the RPC connection closed without a reply). The call is not made on divid; those rows check irondivid
only: `4` answers `true` (one argument is numblocks, as the help text says); `"x"` answers `true` or an error.

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c).

## KNOWN differences

All by design:

- `estimatefee`, `estimatepriority`: irondivid answers them (BasicSwap prices its transactions with `estimatefee`);
  divid has no such calls (not in `rpcserver.cpp:323-466`) and answers -32601 (docs/divid-differences.md R1).
- `getinfo`: irondivid adds `keypoololdest`, `keypoolsize`, `paytxfee` (divid: `rpcmisc.cpp:136-157`), the same
  KNOWN row as in `scripts/chain-replies`.
- `help`: irondivid lists its own calls (those divid does not have) after divid's list, under sections marked
  `(irondivid)`; the run checks there are some.

No other row differs from divid.

## Proving a difference is caught

`UTIL_REPLIES_INJECT=<row name>` changes irondivid's reply of that row before it is compared, e.g.
`UTIL_REPLIES_INJECT='validateaddress own'`: that row prints `FAIL` and the run exits 1.
`UTIL_REPLIES_DUMP=<dir>` writes both replies of every compared row to `<dir>`, for looking into a FAIL.
