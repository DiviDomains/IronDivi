# RPC HTTP replies next to Divi Core

`run.sh` starts a fresh Divi Core 3.0.0 `divid` and a fresh irondivid on regtest and sends both the same raw HTTP
requests: missing and wrong credentials, other HTTP methods and paths, empty, malformed and large bodies, batches,
request objects with odd `id`/`method`/`params`/`jsonrpc`, RPC errors, several requests on one connection, and a
client that `-rpcallowip` refuses. Each row compares the status line, the headers that matter (`Content-Type`,
`WWW-Authenticate`, `Connection`) and the body, and prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not, a `KNOWN` row that differs in another way, or a `KNOWN` row that now matches
  divid (the list below is out of date).

The run ends with a count of the rows and `FAILS <n>`; the exit code is the number of FAILs (255: usage error,
interrupted, or over 10 minutes).

```sh
scripts/http-replies/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/http-replies/run.sh target/release ~/divi-3.0.0/bin 54300 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` (divid p2p and RPC, then irondivid's), on 127.0.0.1, or on
  the address in `HTTP_REPLIES_HOST` (127.0.0.2 keeps clear of other programs' clients when the ports are inside the
  host's ephemeral range). `<port-base>+49` is named as both nodes' only peer, so nothing is dialled.
- `HTTP_REPLIES_OUTSIDE_IP`: a local address outside 127.0.0.0/8 for the `-rpcallowip` rows (default: the address
  the host would use towards 192.0.2.1; the rows are left out when there is none). For those rows both nodes are
  started again listening on that address only, with `rpcallowip=192.0.2.1` (TEST-NET), so nothing else can reach
  them and a client on that address is refused.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 40 seconds and is stopped after 10 minutes. However it ends, both nodes are stopped and their
directories deleted. Needs bash and python3 (standard library only). RPC passwords are made at random for each run
and kept in each node's 0600 `divi.conf`; the Authorization header is built in memory and never printed.

## Rows

Each request goes on a connection of its own (with `Connection: close`) unless the row says otherwise.

| group | forms |
|---|---|
| credentials | no Authorization header, wrong user, wrong password, a scheme other than Basic, `basic` in lower case, `Basic` with nothing after it; the 401's Connection header on a row of its own; whether a reply comes after a delay (divid waits 250 ms before refusing given credentials, `rpcserver.cpp:948-952`, and not when there are none) |
| methods and paths | GET with a request body, PUT, HEAD, PUT without credentials, `/x`, `/x` without credentials, `/wallet/w1`, `/?a=1`; no Content-Type, `text/plain` |
| bodies | empty, invalid JSON, JSON with trailing text, a number, a string, `null` |
| batches | two requests, `[]`, a batch with a number, a member without method, a method that is a number, an unknown method and an RPC error, `[[]]` |
| the request object | `id` missing, null, a string, 1.5, an object; `method` missing, null, a number; `params` missing, null, an object, a string; `jsonrpc` "1.0", "2.0", absent; `method` given twice |
| RPC errors and their HTTP status | unknown method (404), -8, -1 (help), -3, -5 (500) |
| one connection | two requests on HTTP/1.1; two on HTTP/1.0; `Connection: close` then a second; an RPC error then a second; wrong password then a second; HTTP/1.0 with `Connection: keep-alive` then a second: each reply, and whether the server closed the connection after |
| size | a 3 MiB body (whitespace, then a request), a batch of 60000 requests (2.4 MiB), a Content-Length above divid's 32 MiB (`MAX_SIZE`, `serialize.h:34`) with no body sent |
| clients | a client on another 127.0.0.0/8 address (allowed, `rpcserver.cpp:634-635`); a client on the outside address with and without credentials (refused, `rpcserver.cpp:612-616`) |

How a row compares: the status code and reason phrase; `Content-Type`, `WWW-Authenticate` and `Connection` (absent
counts as a value); the body as JSON when it is JSON (field names, types and values, items in order), else as text.
divid's help texts (a -1 error of several lines) are compared by their first line; the other replies scripts compare
the help texts themselves. Not compared: `Date`, `Server`, the HTTP version.

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c): `rpcprotocol.cpp` (replies,
HTTP reading) and `rpcserver.cpp` (`ServiceConnection`, `HTTPReq_JSONRPC`, `JSONRequest::parse`, `ErrorReply`).

## KNOWN differences

Each KNOWN row checks irondivid's reply is exactly the one below; any other reply is a FAIL.

- `401 replies: Connection header`: divid writes its 401 as an HTTP/1.0 reply with no Connection header and closes
  the connection (`rpcprotocol.cpp:85-108`); irondivid's HTTP server (hyper) closes a connection only after a reply
  that says `Connection: close`, so it says it. Both close (the "wrong password, then a second request" rows).
- `PUT`, `HEAD`, `PUT without credentials`: divid closes the connection without a reply to a method other than GET or
  POST (`rpcprotocol.cpp:150-152`); irondivid's HTTP server answers every request: `405 Method Not Allowed`,
  `text/plain`, `Connection: close` (no body for HEAD).
- `path /wallet/w1`: irondivid serves JSON-RPC on `/wallet/<name>` too, which `irondivi-cli -rpcwallet` uses
  (`bin/irondivi-cli/src/main.rs`); divid serves `/` only (`rpcserver.cpp:1019-1031`).

No other row differs from divid.

## Proving a difference is caught

`HTTP_REPLIES_INJECT=<row name>` changes irondivid's reply of that row before it is compared, e.g.
`HTTP_REPLIES_INJECT='batch of two'`: that row prints `FAIL` and the run exits 1.
