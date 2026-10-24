# irondivid next to Divi Core: regtest interop check

`run.sh` starts Divi Core 3.0.0 and irondivid on regtest, each from its own `divi.conf`, and checks that they work
together the way two divid nodes would. Each check prints a `PASS` or `FAIL` line. The exit code is the number of
FAILs, so 0 means everything passed.

```sh
scripts/interop/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid -p irondivi-cli
scripts/interop/run.sh target/release ~/divi-3.0.0/bin 53850 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid` and `irondivi-cli`.
- `<core-bin-dir>` holds Divi Core's `divid` and `divi-cli`.
- `<port-base>`: the run uses ports `<port-base>` to `<port-base>+29` on 127.0.0.1. Nothing else may be using them.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about two minutes and is stopped after 10 minutes (`INTEROP_LIMIT=<seconds>` changes that). However it ends —
finished, failed, interrupted or timed out — every node it started is stopped and its directory deleted. Needs bash,
python3 and `ss`. No other dependencies.

## Nodes

| Node | Started from | Connections |
|---|---|---|
| Divi Core A | `divi.conf` (`daemon=1`, listens) | — |
| irondivid X | `divi.conf`, `-datadir` only | dials A (`connect=`), listens |
| Divi Core B | `divi.conf` (`daemon=1`, `listen=0`) | dials X only (`connect=`) |
| Divi Core C | `divi.conf` (`daemon=1`, listens) | — (a second node on A's IP) |
| irondivid Y, Divi Core D | `divi.conf`, `listen=0` | `addnode=` A and `addnode=` C |
| irondivid P | `divi.conf` with `mnemonicpassphrase=` only, new wallet | dials A |
| Divi Core E, F | `divi.conf` with P's words, E also with its passphrase | dial A; E listens |

B reaches the network only through X. So a block reaching B shows that irondivid relays to an inbound Divi Core peer,
and a block from X reaching A shows that it announces to an outbound one.

## Checks

- **Default ports:** with no `port`/`rpcport` set, irondivid uses divid's regtest ports 51475 (RPC) and 51476 (P2P).
  The run reads them from the start banner with `server=0` and `listen=0`, so they are never bound.
- **Start-up:** all three nodes start from `divi.conf`. Without `-daemon` irondivid writes its pid file
  (`pid=node.pid`, inside the datadir).
- **Connections:** irondivid dials Divi Core, and Divi Core dials irondivid.
- **Blocks both ways, each within 10 s:**
  - a block Divi Core A mines reaches X, and through X reaches B;
  - a block X mines (`setgenerate 1`) reaches A and B.
- **Divi Core's `divi-cli`** pointed at irondivid's datadir answers.
- **`getblockhash`** of 99999 and of -1 gives divid's error (code and message, compared with A's reply).
- **Sends both ways:**
  - A → X 5000: X's balance rises by 5000; `gettransaction` amount and block agree; `listunspent` shows the coin.
  - X → A 1234.5: the transaction reaches A's mempool within 10 s; after a block both sides agree on amount and block
    (X's `gettransaction` amount is the amount sent and the fee, with a positive `fee`, as Divi Core's sender shows
    them: `divi/src/rpcwallet.cpp:2504-2510`), and A's `listunspent` shows the coin.
- **Stops:**
  - RPC `stop`: X ends within 60 s, the pid file is removed, and after a restart the height, tip, balance and coins
    are the same.
  - SIGTERM while A mines 30 blocks: X shuts down cleanly and removes the pid file; after a restart it catches up to
    A's tip with its balance unchanged; no ERROR in its log.
  - With `-daemon`: the pid file holds the daemon's pid and is removed at a clean stop.
- **One connection per address:**
  - Y and D are each given two `addnode=` lines for one IP (A and C, two ports). After their dial loops have run
    (40 s) each holds exactly one outbound connection.
  - `addnode <E> onetry` on Y connects within 10 s, and `getaddednodeinfo true` does not list it.
- **Words made with a passphrase:**
  - P starts a new wallet with only `mnemonicpassphrase=` set, and `dumphdinfo` reports that passphrase.
  - Divi Core E, given P's words and the passphrase, owns P's first address (`validateaddress` ismine). F, given the
    words without it, does not.
  - The passphrase is random, kept in a 0600 file and the nodes' `divi.conf`. It and the words are never printed or
    put on a command line.
  - Neither appears in any node's logs (`debug.log*`, Core's `db.log`, captured output). Database files, where a
    wallet keeps its own words, are not searched.
- **Divi Core's files:**
  - irondivid refuses B's datadir (both B itself and `B/regtest`), and leaves it byte for byte as it was.
  - `-wallet=wallet.dat` at Core's wallet file gets a plain refusal.
  - A Core `wallet.dat` in irondivid's datadir is named in a warning and left unchanged.
