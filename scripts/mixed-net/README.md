# divid and irondivid on one network, for hours

`run.sh` runs three Divi Core 3.0.0 `divid` and three irondivid nodes as one regtest network for `HOURS`. It sends
traffic, mines on both kinds, restarts and kills nodes, adds a node from nothing, and splits the network twice and
joins it again. Throughout, it checks that every node keeps agreeing on the chain and the mempool.

```sh
SEED=7 HOURS=1 OUT=/var/tmp/mn-results scripts/mixed-net/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+13` on 127.0.0.2, two per node (p2p, RPC), seven nodes with the
  one that joins.
- `[root]`: a fresh directory is made under it for the datadirs (default `$TMPDIR`, else `/tmp`) and deleted at the
  end.
- `SEED` (default 1) draws every random choice; `HOURS` (default 1) is how long the traffic runs.
- `OUT` (default `[root]/mixed-net-results`) keeps what the run found:
  - `seed<N>.jsonl`: every step, send and snapshot;
  - `seed<N>-summary.json`: steps, blocks, transactions, reorg depths, restarts;
  - on a disagreement, `seed<N>-disagreement.json` (the step, the last 60 steps, every node's view, the links) and
    `seed<N>-<node>-debug-tail.log` (the last 200 lines of each node's debug.log).

The exit code is 0 when the nodes agreed to the end, 1 on a disagreement, 2 when the run itself failed (a node that
does not start, an RPC that does not answer), 124 past `HOURS` + 1 hour. However it ends, every node is stopped and
its datadir deleted. Needs bash and python3 (standard library only). RPC passwords are made at random for each run
and kept in the 0600 `divi.conf`. Wallet keys are throwaway regtest keys each node makes in its own datadir; none is
printed or put on a command line.

## The network

- **The nodes:** the six are shuffled into node indexes by `SEED`.
- **The links:** a random spanning tree, then edges added until every node has 2–3 peers and at least one of the
  other kind. Each link is one `connect=` line on one end; every node listens.
- **Blocks:** only `setgenerate` makes blocks (`staking=0`), on a node drawn each time, so each kind makes blocks the
  other must take. The 100 work blocks rotate over all six nodes, so every wallet has coins to stake; 25 stake blocks
  follow. Each block waits for agreement before the next. A node with no coin to stake (the one that joined) hands
  its block to another node.
- **Ties:** tips of equal height are a tie, which both kinds keep until a block comes on one of them (the first block
  seen stays). When the nodes still differ after 60 s but are all at one height, one more block is mined to break the
  tie; only a difference that outlasts that counts.
- **Links before blocks:** after every start, restart and partition change, the run waits until every node has its
  links up before anything is mined. A block announced before a peer connects is never announced to it, and a node
  fetches only from its outbound peers (`divi/src/main.cpp:1301-1311`). So a node whose only link to a miner is
  inbound would otherwise stay one block behind, on divid as on irondivid.

## Steps (drawn by weight from `SEED`, 2–6 s apart)

| step | weight | what it does, and the check after it |
|---|---|---|
| mine | 36 | a node mines one block; its connected part has one best hash within 60 s |
| race | 6 | a divid and an irondivid each mine 1–3 blocks at the same moment, as two miners finding blocks close together do; one side reorganizes |
| send | 20 | a wallet sends 0.5 to 50 DIVI to another's address; the transaction is in every mempool of the part within 60 s (or mined) |
| sendmany | 8 | to three other wallets |
| dust | 3 | 0.00001 DIVI (refused by the wallet, or relayed as any send) |
| whole balance | 3 | `sendtoaddress <address> <balance> receiver_pays` |
| raw | 6 | made and signed on one node with `createrawtransaction`, sent by another with `sendrawtransaction` |
| vault fund | 3 | `fundvault owner:manager`, the manager another node |
| vault reclaim | 3 | `reclaimvaultfunds` of 1 DIVI by an owner |
| double spend | 3 | one coin spent twice, each spend sent to one of the two nodes farthest apart; after the next block no mempool may hold the spend that lost |
| restart | 3 | a clean stop and start of a node; the chain agrees again within 60 s |
| unclean stop | 3 | SIGKILL of a node, then a start |

Two **partitions** at 30% and 70% of the run:
- the running nodes split in two halves, each with both kinds, by restarting them with only the links inside their
  half;
- one half mines 1–6 blocks, the other 1–3 more;
- then the links come back; the shorter half must reorganize onto the longer half's tip, a reorg of 1–6;
- a snapshot follows 60 s after the rejoin.

A **new node** of a drawn kind joins from nothing at 50% of the run, connected to two running nodes, and must reach
the tip.

Before a restart, an unclean stop or a partition, blocks are mined until every mempool is empty. divid keeps no
mempool across a restart, so a transaction lost there would otherwise read as a disagreement.

Every 30 s (between steps) a snapshot of every node is written: height, best hash, mempool txids, chain tips, peers
and ban scores. The best hash must then agree in each connected part.

## Not covered

- Masternodes: none is set up, so no masternode list is compared.
- Agreement is checked on the chain (best hash) and the mempool (each transaction sent, except the double spends).
  Other RPC replies are left to the reply scripts.
