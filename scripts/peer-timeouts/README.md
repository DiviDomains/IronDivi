# When a node drops a peer: irondivid next to Divi Core

`run.sh` starts one Divi Core 3.0.0 `divid` and one `irondivid` at once on regtest (each on a chain of five blocks of
its own) and joins to each the same raw peers, which misbehave in time. It records when the node closed each
connection, in seconds after the connection opened, or that it was still up when the watch ended (25 minutes). The
two count as the same within 10 s. Each row prints one line:

- `PASS`: the same as divid;
- `KNOWN`: differs, in the way listed below with the reason (none at present);
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid.

The run ends with a count of each and `FAILS <n>`. The exit code is the number of FAILs (255: usage error,
interrupted, or over 40 minutes).

```sh
scripts/peer-timeouts/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a build of this tree
cargo build -p irondivid
scripts/peer-timeouts/run.sh target/debug ~/divi-3.0.0/bin 55400 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+13` on 127.0.0.2 (p2p and RPC of the two nodes, then the raw
  peers each node dials).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end. Give an
  absolute path.

A run takes about 27 minutes; `PEER_TIMEOUTS_WATCH=<s>` shortens the watch (90 s covers the rows that end within a
minute), `PEER_TIMEOUTS_TRACE=1` prints what each peer was sent. However it ends, both nodes are stopped and their
directories deleted. Needs bash and python3 (standard library only). divid's timers are not shortened.

## The rule

Divi Core checks each peer on every pass of its socket thread (`CNode::CheckForInnactivity`, `Node.cpp:812-834`,
called from `net.cpp:830` after the peer's socket was read and written). The clock is `GetTime()` in seconds;
"sent" and "received" are any bytes written to or read from the socket (`CommunicationLogger`, `Node.cpp:154-172`,
recorded in `SendData`, `Node.cpp:252`, and on receive, `Node.cpp:292`). Nothing here changes with `-timeout` (the
connect timeout, `net.cpp:1719`) or with regtest.

| check | after |
|---|---|
| nothing received from the peer, or nothing sent to it | 60 s from the connection (`Node.cpp:819-822`) |
| nothing sent to the peer | 20 minutes from the last send (`:823-825`) |
| nothing received from the peer | 20 minutes from the last receive, 90 minutes for a peer of protocol 60000 or below (`:826-828`; such a peer is refused at its version anyway) |
| a ping not answered | 20 minutes from the ping (`:829-831`, on `GetTimeMicros`) |

Bytes count as they arrive, part of a message or not: half a message moves the receive clock, and counts as
"something received" for the 60 s check.

There is no deadline of its own for the version message. An inbound peer is sent nothing before its version
(`main.cpp:407`), so one that has not sent its version by 60 s is dropped; a peer the node dialled has been sent its
version, so it is dropped at 60 s only if it has sent nothing at all. A dialled peer that never sends its sporks is
sent nothing after `getaddr` (`Node.cpp:1025-1034`), so it is dropped 20 minutes later by the sending timeout,
however much it talks.

## Rows

| peer | divid |
|---|---|
| dialled, no sporks, talks every 30 s (an unasked pong) | closed at about 1200 s (sending timeout) |
| dialled, `sporkcount 0`, then silent | closed at about 1200 s (receive timeout; its pings go unanswered too) |
| dialled, sends nothing | closed at 60 s |
| dialled, answers with its version at 45 s | up |
| dialled it, answers pings (control) | up |
| dialled it, silent after the handshake | closed at about 1200 s |
| dialled it, talks every 30 s, never answers a ping | closed at about 1200 s (ping timeout) |
| dialled it, sends nothing | closed at 60 s |
| dialled it, a ping every 10 s, no version | closed at 60 s (it was sent nothing) |
| dialled it, its version at 45 s | up |
| dialled, half a version at 5 s (24-byte header naming 100 bytes, then 40), then nothing | closed at about 1200 s (it sent something, and was sent the node's version) |
| dialled, `sporkcount 0`, half an inv at 60 s, then nothing | closed at about 1260 s (20 minutes after the half message) |
| dialled it, half a version at 5 s, then nothing | closed at 60 s (it was sent nothing) |
| dialled it, half an inv at 60 s, then nothing | closed at about 1260 s |
