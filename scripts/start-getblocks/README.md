# Which peers are asked for blocks when they connect: irondivid next to Divi Core

`run.sh` starts one Divi Core 3.0.0 `divid` and one `irondivid` on the same regtest chain of five blocks, joins raw
peers to each (some the node dials, some that dial it) and records which of them is sent `getblocks` or `getheaders`
in the seconds after the handshake, and which are asked after a dialled peer has gone. Each row prints one line:

- `PASS`: the same as divid;
- `KNOWN`: differs, in the way listed below with the reason (none at present);
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid.

The run ends with a count of each and `FAILS <n>`. The exit code is the number of FAILs (255: usage error,
interrupted, or over 15 minutes).

```sh
scripts/start-getblocks/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a build of this tree
cargo build -p irondivid
scripts/start-getblocks/run.sh target/debug ~/divi-3.0.0/bin 55400 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+9` on 127.0.0.2 (p2p and RPC of the two nodes, then the ports
  of the raw peers the nodes dial).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end. Give an
  absolute path.

A run takes about 5 minutes. However it ends, every node is stopped and its directory deleted. Needs bash and
python3 (standard library only). `START_GETBLOCKS_TRACE=1` prints every message each peer got, with its time after
the handshake; `START_GETBLOCKS_ONLY=<text>` runs only the rows whose name has `<text>`.

## The rule

Divi Core asks a peer for blocks (`getblocks` from the tip) once, in `SendMessages` (`main.cpp:1304-1311`), when the
peer is one it prefers to download from, or when it has no such peer and this one is a full node that is not
one-shot. A preferred peer is one the node dialled or a whitelisted one, not one-shot, with `NODE_NETWORK`
(`CNode::IsPreferredDownloadSource`, `Node.cpp:1075`). The ask is made only if no peer has been asked yet or the best
header is less than six hours old (`BeginSyncingWithPeer`, `main.cpp:1130-1143`). The test runs on every pass, so
the peers that dialled the node while a preferred peer was there are asked when the last preferred peer goes
(`CNodeState::Finalize`, `NodeState.cpp:34-63`).

Divi Core sends nothing to a peer it dialled until that peer has sent its sporks or a `sporkcount` of 0
(`Node.cpp:1031-1032`); the peers the nodes dial here send `sporkcount` 0, as a node with no sporks does.

## Rows

| rows | what is compared |
|---|---|
| two dialled and three that dialled it | the two dialled are asked; none of the three is |
| three that dialled it, none dialled | all three are asked (no preferred peer) |
| an `addnode onetry` peer and one that dialled it | the `onetry` peer is asked, the other is not |
| a peer that is not a full node, with a dialled peer | the dialled one is asked; the other (no `NODE_NETWORK`) is not |
| a whitelisted peer that dialled it, with a dialled peer | both are asked |
| restart, the peers naming a longer chain | the first row again after a restart of both, the peers' start height 400 |
| a dialled peer leaves, the two that dialled it | neither is asked while it is there; both are asked after it has gone |

## Not compared

- **When a dialled peer is asked.** divid waits for the peer's sporks before it sends anything; irondivid asks at
  the handshake. The raw peers here send `sporkcount` 0 at once, so the two are asked within the same moment.
- **The six-hour test and the sync of an old chain.** The chain here is minutes old, so every peer that is due is
  asked; the unit tests in `crates/divi-network/src/sync.rs` (`sync::tests`) cover an old tip, where one peer is
  asked.
