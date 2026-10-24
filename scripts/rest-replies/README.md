# REST replies next to Divi Core

`run.sh` starts a fresh Divi Core 3.0.0 `divid` and an irondivid on one regtest chain, both with `-rest=1` and
`-txindex=1`. It asks both the same REST paths without credentials and compares status, `Content-Type` and body.
Then it restarts both with `-rest=0` and asks again. Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 10 minutes).

```sh
scripts/rest-replies/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/rest-replies/run.sh target/release ~/divi-3.0.0/bin 53950 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` on 127.0.0.1 (divid p2p and RPC, then irondivid's).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 10 seconds and is stopped after 10 minutes. However it ends, both nodes are stopped and their
directories deleted. Needs bash and python3 (standard library only). The RPC passwords are random, written only to
each node's 0600 `divi.conf`, and kept in memory; REST requests carry no credentials (divid's REST needs none).

## What Divi Core 3.0.0 has

Core paths are under `src/` of the Divi Core source at v3.0.0 (commit 9e2f76c).

**REST** (`rest.cpp`), served on the RPC port when `-rest` is on (default off; `rpcserver.cpp:1025`,
`LicenseAndInfo.cpp:242`), without credentials (only `/` checks them, `rpcserver.cpp:1019-1033`):

| path | formats | Core | irondivid |
|---|---|---|---|
| `/rest/tx/<txid>` | `.bin`, `.hex`, `.json` | `rest.cpp:181-230` (GetTransaction with mempool, `-txindex` or the block of an unspent output; JSON is TxToJSON, `JsonTxHelpers.cpp:39-95`) | yes, `-rest` (crates/divi-rpc/src/rest.rs) |
| `/rest/block/<hash>` | `.bin`, `.hex`, `.json` | `rest.cpp:102-171` (JSON is blockToJSON with each transaction as TxToJSON, `JsonBlockHelpers.cpp:38-77`) | yes |
| `/rest/block/notxdetails/<hash>` | `.bin`, `.hex`, `.json` | `rest.cpp:173-179` (JSON with txids only) | yes |

There is nothing else. `/rest/headers`, `/rest/chaininfo`, `/rest/mempool/info`, `/rest/mempool/contents` and
`/rest/getutxos` (newer Bitcoin releases) do not exist in 3.0.0: divid answers them `404 Not Found`
(`rest.cpp:268`), as it answers any path but `/` when `-rest` is off (`rpcserver.cpp:1030-1031`).

How divid answers:
- **Format:** the part after the first dot. `.json.hex` is JSON; a missing, empty or unknown part, or a query
  string in it, is no format (`rest.cpp:65-75`).
- **Checks, in order:**
  1. the hash: 64 hex digits, else `400 Invalid hash: <text>`;
  2. the lookup: `404 <text> not found`;
  3. the format: `404 output format not found (available: .bin, .hex, .json)`.

  Error bodies are the message and `\r\n`, as `text/plain` (`rest.cpp:113-157`, `:263-265`).
- **Replies:**
  - `.bin`: `application/octet-stream`;
  - `.hex`: `text/plain`, the hex and `\n`;
  - `.json`: `application/json`, compact json_spirit text and `\n`;
  - `404 Not Found`: `text/plain`, body `Not Found` (`rpcprotocol.cpp:85-136`).
- **Methods:** GET and POST are both served (`rpcprotocol.cpp:149-152`).
- **Warm-up:** divid answers `503 Service temporarily unavailable: …` while its RPC is warming up
  (`rest.cpp:253-254`). irondivid starts its RPC server only once the node is ready, so it has no warm-up state to
  answer from.

**ZMQ** (`src/zmq/`), each topic published on the address given by its option. Every message has three parts:
topic, body, and a 4-byte little-endian sequence number per notifier (`zmqpublishnotifier.cpp:129-141`):

| topic | option | body | Core | irondivid |
|---|---|---|---|---|
| `hashblock` | `-zmqpubhashblock=<address>` | the new tip's hash, 32 bytes | `zmqpublishnotifier.h:11`, `.cpp:146-154` | no (option accepted as unsupported) |
| `hashtx` | `-zmqpubhashtx=<address>` | a transaction's hash, 32 bytes | `.h:12`, `.cpp:156-164` | no |
| `rawblock` | `-zmqpubrawblock=<address>` | the serialized block | `.h:13`, `.cpp:166-186` | no |
| `rawtx` | `-zmqpubrawtx=<address>` | the serialized transaction | `.h:14`, `.cpp:188-195` | no |

## Nodes and steps

divid listens; irondivid dials it (`connect=`), so both see one chain. Both run with `staking=0` and `txindex=1`.

1. divid mines 30 blocks, sends 12.5 to its own new address, mines one more block, and sends 3.25 that stays in the
   mempool. The run waits until irondivid has divid's tip and the mempool transaction.
2. The REST rows below, with `-rest=1`.
3. Both restart with `-rest=0`; the `rest=0:` rows.

## Rows

| rows | paths |
|---|---|
| `tx confirmed`, `tx in the mempool`, `tx coinbase` | `/rest/tx/<txid>` in `.json`, `.hex`, `.bin` |
| `block tip`, `block notxdetails tip` | `/rest/block/[notxdetails/]<tip>` in `.json`, `.hex`, `.bin` |
| `block genesis`, `block notxdetails genesis` | `.json` |
| `tx uppercase hash`, `tx by POST`, `tx two extensions` | the confirmed tx, `.json` |
| `tx bad hash`, `tx short hash`, `tx unknown txid`, `tx wrong format`, `tx missing extension`, `tx empty extension`, `tx with a query`, `tx bad hash and wrong format`, `tx unknown txid and wrong format` | the errors, in divid's order |
| `block bad hash`, `block unknown hash`, `block wrong format`, `block missing extension`, `block notxdetails unknown hash` | the same for blocks |
| `headers`, `chaininfo`, `mempool info`, `mempool contents`, `getutxos one outpoint`, `getutxos several outpoints`, `getutxos too many outpoints`, `rest root`, `not a rest path` | paths divid does not serve |
| `rest=0: …` | a tx and both block paths, an unknown txid, a non-REST path, with `-rest=0` |
| `zmq hashblock`, `zmq hashtx`, `zmq rawblock`, `zmq rawtx` | not compared (below) |

How a row compares:
- the same status and the same `Content-Type`;
- `.hex`, `.bin` and every text body: byte for byte;
- JSON bodies: field by field, reals as each node writes them (the text of the number), and both ending in a
  newline. Members are compared in any order: irondivid writes them in name order, as all its JSON replies.

## KNOWN differences

- `zmq hashblock`, `zmq hashtx`, `zmq rawblock`, `zmq rawtx`: irondivid has no ZMQ publisher; `-zmqpub*` are
  accepted and named unsupported at start. They are not compared because a ZMQ subscriber needs pyzmq, which is not
  in the Python standard library.

No other row differs from divid.

## Proving a difference is caught

`REST_REPLIES_INJECT=<row name>` adds a byte to irondivid's body of that row before it is compared, e.g.
`REST_REPLIES_INJECT='rest=1: block tip .hex'`: that row prints `FAIL` and the run exits 1.
`REST_REPLIES_DUMP=<dir>` writes both replies of every compared row to `<dir>`, for looking into a FAIL.
