# The RPC server under concurrent load, next to Divi Core

`run.sh` starts a fresh Divi Core 3.0.0 `divid` and an irondivid restored from divid's phrase on one regtest chain,
with the same options. It loads both RPC servers the same way and compares what each one does, case by case:
- parallel clients;
- keep-alive and `Connection: close`;
- stalled and idle clients;
- many connections at once;
- wrong credentials;
- a long call next to a short one;
- `-rpcthreads`, `-rpckeepalive`;
- `stop` while clients are mid-call.

Each row prints one line:

- `PASS`: the same outcome as divid (and, for the parallel rows, every reply right);
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with a count of each and `FAILS <n>`. The exit code is the number of FAILs (255: usage error,
interrupted, or over 10 minutes).

```sh
scripts/rpc-load/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/rpc-load/run.sh target/release ~/divi-3.0.0/bin 53950 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` on 127.0.0.1 (divid p2p and RPC, then irondivid's).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end. Give an
  absolute path.

A run takes about 3 minutes and is stopped after 10 minutes. However it ends, both nodes are stopped and their
directories deleted. Needs bash and python3 (standard library only); the HTTP is written on raw sockets. The phrase is
handed to irondivid in its environment (`WALLET_MNEMONIC`) and never printed, written or put on a command line. RPC
passwords are made by the run and live only in memory and in each node's mode-600 `divi.conf`.

## Nodes and steps

divid listens; irondivid dials it (`connect=`). Both run with `staking=0`. divid mines 25 blocks, and the chain stays
below block 100 (proof of work) for the whole run. Both nodes are restarted for each option set:
- the default options;
- `rpcthreads=1`;
- `rpcthreads=2`;
- `rpckeepalive=0`.

## Rows

"Answered" means a reply within 3 s.

| row | what is done | compared |
|---|---|---|
| N parallel clients (N = 1, 4, 16, 64; and 16 with `rpcthreads=2` and with `rpckeepalive=0`) | each client, on one keep-alive connection, makes a fixed mix of 9 read calls 3 times (`getblockcount`, `getbestblockhash`, `getblockhash`, `getblock`, `getblockheader`, `getdifficulty`, `validateaddress`, `gettxoutsetinfo`, `help getblock`), reconnecting when a reply says `Connection: close` | every reply equals the node's one-at-a-time reply; no refused connection, no lost reply; the node answers afterwards. The time each node takes is shown, not compared. |
| 5 calls on one HTTP/1.1 connection | five calls, one connection | each status and `Connection` header; whether the connection stays open |
| `Connection: close`; HTTP/1.0 without and with `Connection: keep-alive` | one call each | status, `Connection` header, whether the node closes the connection |
| a half request and an idle connection, then others' calls | a client sends half a request, another connects and sends nothing; four calls from others | how many are answered; whether the two sockets are still open |
| a stalled client and an idle keep-alive connection, over 40 s | a half request, and a connection idle after one reply, watched for 40 s | whether and when (5 s steps) each node closes them |
| 48 connections opened at once, one call each | 48 sockets connected first, then one call on each, in parallel | the tally of statuses |
| 32 clients with wrong credentials at once, then right ones | 32 parallel calls with a wrong password, then one right call | the tally of statuses; the right call answered |
| a short call while a long call runs (default and `rpcthreads=1`) | `keypoolrefill` with a larger pool each time (3000 keys and up, 2 to 6 s on either node), and 0.3 s later `getblockcount` | whether the short reply comes before the long one. The long call's time is printed (`# long call` line). |
| `rpcthreads=1`: a call while another client holds its connection open; `rpcthreads=2`: while one, and while two, hold theirs | the holders each make one call and keep the keep-alive connection | the other client's call answered; and answered once they close |
| `rpckeepalive=0`: an HTTP/1.1 call, without and with `Connection: keep-alive` | one call each | `Connection` header, whether the node closes the connection |
| stop while 8 clients are mid-call | 8 clients loop on `gettxoutsetinfo`; `stop` | the `stop` status, whether the node exits within 30 s and its exit code, whether every client ends cleanly (a reply or a closed connection, none hangs) |

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c).

## What irondivid does with `-rpcthreads` and `-rpckeepalive`

- **`-rpcthreads`:** irondivid accepts it, logs `Option -rpcthreads is not supported by irondivid; ignored`
  (bin/irondivid/src/main.rs, `UNSUPPORTED_OPTIONS`), and does not use it.
  - irondivid's RPC server serves each connection on a task of its own and runs calls side by side, with no limit
    on how many.
  - divid starts `-rpcthreads` threads (default 4, rpcserver.cpp:755-757). Each thread serves one connection from
    accept to close, keep-alive included (rpcserver.cpp:578-622, ServiceConnection :1000-1033).
- **`-rpckeepalive`:** irondivid reads it. With `rpckeepalive=0` every reply carries `Connection: close` and the
  connection is closed after it, as in divid, where the connection's loop ends after the reply
  (rpcserver.cpp:1014-1017).

## KNOWN differences

- **`rpcthreads=1`: a call while another client holds its connection open; `rpcthreads=2`: while two clients hold
  theirs.** divid's threads are all taken by the held keep-alive connections, so a new client is not answered until
  one closes (rpcserver.cpp:578-622, :755-757, :1000-1033). irondivid serves each connection on its own task and does
  not use `-rpcthreads`, so the call is answered. Both answer once the holders close. With `rpcthreads=2` and one
  holder, both answer.
- **A short call while a long call runs.** divid runs a call its table does not mark thread-safe only while it holds
  cs_main, which it tries for every 50 ms (rpcserver.cpp:1072-1096). `keypoolrefill` (rpcserver.cpp:442) holds
  cs_main while it makes the keys, so `getblockcount` (rpcserver.cpp:345) comes back only after the long call.
  irondivid runs calls side by side, and its chain reads take no wallet lock, so the short call comes first.
- **`rpcthreads=1`: a short call while a long call runs.** Both reasons above: divid's one thread serves the long
  call's connection, and the short call also waits for cs_main. irondivid answers the short call first.

No other row differs from divid.

## Proving a difference is caught

A KNOWN row that starts to match divid prints `FAIL`. A row that differs and is not listed prints `FAIL`.
