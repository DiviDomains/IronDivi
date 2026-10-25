# What a node answers a peer, next to Divi Core

`run.sh` starts a Divi Core 3.0.0 `divid` and an irondivid on regtest, on the same chain of 1200 blocks, and has a
raw P2P client (Python, standard library only) send both the same requests: `getblocks`, `getheaders`, `getdata`,
`getaddr` and `mempool`. Each row compares, message by message, what comes back (command, count, hashes, order), and
whether the peer is still connected.

Divi Core's code is in `divi/src/main.cpp`:
- `ProcessGetData` `:283-347`;
- `getdata` `:613-622`;
- `getblocks`/`getheaders` `:624-668`;
- the `headers` request `:680-702`;
- `getaddr` `:863-869`.

The relay map is `divi/src/net.cpp:1565-1590`, and the address sample `divi/src/addrman.cpp:451-470`.

Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not, a `KNOWN` row that differs in another way, or a `KNOWN` row that now matches
  divid (the list below is out of date).

The run ends with `# rows: ...` and `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted,
or over 25 minutes).

```sh
scripts/block-serve/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/block-serve/run.sh target/release ~/divi-3.0.0/bin 54100 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` on 127.0.0.2 (divid p2p and RPC, then irondivid's), and
  `<port-base>+4` on 127.0.0.60, where the client listens for the nodes' outbound connection.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.
- `BLOCK_SERVE_FORCE_REBROADCAST=<row name>`: in that row divid is made to rebroadcast its mempool: once its raw
  peer is connected, its clock is moved 40 minutes ahead (`setmocktime`), in steps of 10 minutes each answered by a
  ping (divid drops a peer it heard nothing from for 20 minutes, `Node.cpp:815-830`), and back after the request. The run prints how
  many rebroadcast invs the rule below left out there; the row still passes.
- `BLOCK_SERVE_INJECT_INV=<row name>`: irondivid is taken to have sent, in that row, an inv of a transaction that is
  in no mempool; the row FAILs (the proof that the rule leaves out nothing else).

A run takes about eight minutes, most of it divid mining the chain, and is stopped after 25. However it ends, both
nodes are stopped and their directories deleted. RPC passwords are made at random for each run and kept in the 0600
`divi.conf`. The wallet phrase is read from divid's `dumphdinfo` and handed to irondivid in its environment
(`WALLET_MNEMONIC`); it is never printed or put on a command line.

## The chain and the peers

- **The chain:** divid mines 1200 blocks: work blocks to 100, then stake blocks. irondivid, with a wallet from the
  same phrase, follows them. A transaction of divid's wallet is given to both mempools. Then irondivid restarts with
  no peer, and divid has none.
- **The peers:** each row uses a fresh raw peer from its own loopback address (127.0.1.x). The peer waits 3 s after
  the handshake, so the node's own messages then (`sporkcount`, its `getblocks`) are not taken for replies. A row
  ends after 2 s with no message.
- **A mempool rebroadcast is not a reply:** each node announces some of its mempool again, unasked, at a random time
  within 30 minutes of the last time:
  - divid: `PeriodicallyRebroadcastMempoolTxs`, `main.cpp:1245-1294`;
  - irondivid: `crates/divi-node/src/rebroadcast.rs`.

  So an `inv` that lists only transactions this run put in the mempools (the mempool transaction, then the relayed
  one) is left out of the messages a row compares, wherever it comes. Every other message nobody asked for is kept:
  an `inv` of any other transaction or of a block, or one that mixes them, still counts. The run ends with
  `# rebroadcast invs left out: divid <n>, irondivid <n>`.

## Rows

| request | what is compared (each on both nodes) |
|---|---|
| after the handshake | the commands a node sends a new inbound peer unasked: `getblocks` and `sporkcount` |
| `getblocks` / `getheaders` from genesis, then `getdata` of the 500th block | `inv` of blocks 1..500; then `block 500` and an `inv` of the tip (hashContinue, `main.cpp:651-656`, `:310-318`) |
| from height 700, then `getdata` of the tip | `inv` 701..1200; the tip, then an `inv` of the tip |
| from 300 with hashStop 350 | `inv` 301..350 |
| from 300 with hashStop 200 | `inv` 301..800: a hashStop below the locator never stops the walk |
| an unknown locator; an empty locator | `inv` 1..500: an unknown locator is genesis (`FindForkInGlobalIndex`, `main.cpp:84-96`) |
| an unknown hash, then height 1000 | `inv` 1001..1200 |
| from the tip | no answer |
| empty locator, hashStop 10; an unknown hashStop | `inv` 1..10; `inv` 1101..1200 |
| `getdata` of block 5, of genesis, of three blocks | the blocks, in order |
| `getdata` of an unknown block | no answer (only a block it has is sent, `main.cpp:300-319`) |
| `getdata` of a mempool transaction | the `tx` |
| `getdata` of an unknown transaction; of a confirmed one never relayed (a coinbase) | `notfound` naming it (`main.cpp:321-326`, `:337-345`) |
| `getdata` of a mix: tx, block 6, unknown tx, block 7, unknown block | `tx`, `block 6`, `block 7`, then `notfound [the unknown tx]`: a pass ends after each block item, with that pass's `notfound` (`main.cpp:331-332`) |
| `getdata` of unknown tx, block 11, unknown tx | `block 11`, `notfound [first]`, `notfound [second]` |
| `getdata` of type 99; of nothing | no answer |
| `getdata` of 50001 items | banscore 20 (`main.cpp:617-619`) |
| `mempool` | no answer: Divi Core 3.0.0 has no `mempool` branch in ProcessMessage |
| `getaddr`, no routable local address | see KNOWN |
| `getaddr` with `-externalip=240.0.0.9`, after 100 addresses (one /16 each) | 1..23 addresses: 23% of the book, at most 2500 (`addrman.cpp:451-470`); the book's bucket placement is random, so the count is not compared exactly |
| `getaddr` on an outbound connection (the node connects to the client, `addnode … onetry`) | no addresses, still connected: only an inbound peer is answered (`main.cpp:863`) |
| a transaction relayed by the client, in the mempool, then in a block | `getdata` of it: the `tx` both times. divid keeps what it relays for 15 minutes and answers from there (`net.cpp:1565-1590`) |

## KNOWN

| row | divid | irondivid | reason |
|---|---|---|---|
| `getaddr after 100 addresses, no routable local address` | 0 | 1 or more | divid keeps no address of a network it has no routable local address in. IPv4 is reachable only once one is known, from `-externalip` or discovery (`NetworkLocalAddressHelpers.cpp:73-106`), and its `addr` handler keeps only reachable addresses (`main.cpp:544-553`). irondivid keeps them: matching it would leave a node without a public address (behind NAT, or `-discover=0`) with an empty address book |
