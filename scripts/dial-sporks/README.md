# What a node sends a peer it dialled before that peer's sporks arrive

`run.sh` starts one Divi Core 3.0.0 `divid` and one `irondivid` on the same regtest chain of five blocks. Each dials a
raw peer that shakes hands and then sends `sporkcount 0` at once, after 10 s, or never; in two cases the node also
makes a block 3 s after the handshake. Every command the node sends the peer is recorded, in order. Each row prints:

- `PASS`: the same as divid;
- `KNOWN`: differs, in the way listed below with the reason (none at present);
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid.

The run ends with a count of each and `FAILS <n>`. The exit code is the number of FAILs (255: usage error,
interrupted, or over 10 minutes).

```sh
scripts/dial-sporks/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a build of this tree
cargo build -p irondivid
scripts/dial-sporks/run.sh target/debug ~/divi-3.0.0/bin 55400 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+5` on 127.0.0.2 (p2p and RPC of the two nodes, then the raw
  peer's port).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end. Give an
  absolute path.

A run takes about 5 minutes. However it ends, every node is stopped and its directory deleted. Needs bash and python3
(standard library only). `DIAL_SPORKS_TRACE=1` prints every message with its time after the handshake;
`DIAL_SPORKS_ONLY=<text>` runs only the rows whose name has `<text>`.

## The rule

Divi Core's network thread sends a peer its ping (`MaybeSendPing`) and everything `SendMessages` makes (the start
`getblocks`, `inv` of blocks and transactions, `getdata`, `addr`, masternode asks) only when `CanSendMessagesToPeer`
holds (`net.cpp:871-893`). For a peer it dialled that needs the peer's `sporkcount` and as many sporks as it named
(`Node.cpp:1018-1034`; `SetSporkCount`, `Node.cpp:1008-1016`, takes 0 or less as none to wait for). What its message
handlers push goes at once: `verack` and `getaddr` with the version (`main.cpp:416-442`), `getsporks` for the
`sporkcount` (`spork.cpp:269-274`), a `pong`, the answers to `getdata`/`getblocks`. What `SendMessages` would have
sent is kept until then (`vInventoryToSend`, `vAddrToSend`, `mapAskFor`, `fPingQueued`), and goes out after the start
`getblocks`. A peer that never sends sporks gets only the handler answers; it is dropped by `CheckForInnactivity`
(`Node.cpp:812-834`) 20 minutes after the last thing sent to it or received from it.

## Rows

| row | divid (and irondivid now) |
|---|---|
| `sporkcount 0` at once | `getaddr`, `getsporks`, `ping`, `getblocks` |
| `sporkcount 0` after 10 s | `getaddr`; then `getsporks`, `ping`, `getblocks` |
| no `sporkcount` in 25 s | `getaddr` only; still connected |
| at once, a block made at 3 s | as the first row, then `inv` at 3 s |
| after 10 s, a block made at 3 s | `getaddr`; then `getsporks`, `ping`, `getblocks`, `inv` (the block made while waiting) |
| none, a block made at 3 s | `getaddr` only |

## Not compared

- **The 20-minute drop.** divid drops the peer 20 minutes after it last sent it anything; irondivid 20 minutes after it
  last heard from it. For a silent peer both drop it at 20 minutes; a peer that keeps talking without sending sporks
  keeps an irondivid connection. Not run here (it takes 20 minutes).
- **A peer that names a count and sends fewer sporks.** Handled the same way (it is not synced until the count is
  reached); not run here.
