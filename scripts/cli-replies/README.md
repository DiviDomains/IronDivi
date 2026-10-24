# Command-line client output next to Divi Core

`run.sh` starts a fresh Divi Core 3.0.0 `divid` and an irondivid restored from divid's phrase on one regtest chain
that divid mines. It runs Divi Core's `divi-cli` and `irondivi-cli` with the same arguments against the same node,
once against divid and once against irondivid, and compares their exit code, stdout and stderr exactly. Each row
prints one line:

- `PASS`: irondivi-cli prints what divi-cli prints;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divi-cli (the list below is out of date).

The run ends with `FAILS <n>`. The exit code is the number of FAILs. It is 255 for a usage error, an interrupted
run, or a run over 10 minutes.

```sh
scripts/cli-replies/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid -p irondivi-cli
scripts/cli-replies/run.sh target/release ~/divi-3.0.0/bin 54150 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid` and `irondivi-cli`; `<core-bin-dir>` holds `divid` and `divi-cli`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` on 127.0.0.1 (divid p2p and RPC, then irondivid's). The rows
  for a port nothing listens on use port 1.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

**Run time and clean-up.** A run takes about 15 seconds and is stopped after 10 minutes. However it ends, both nodes
are stopped and their directories deleted.

**Requirements.** bash and python3 (standard library only).

**Secrets.**

- The phrase is read from divid's `dumphdinfo` reply and handed to irondivid in its environment. It is never
  printed, written to a file or put on a command line.
- The RPC password is made at random for each run's two throwaway regtest nodes, and deleted with them. As in the
  other replies scripts it is in their `divi.conf`, and in client directories' `divi.conf` (0600). It is on a
  client's command line only in the rows that test `-rpcpassword=` given there. It is never printed.

## Nodes and steps

1. **Nodes:** divid listens and irondivid dials it (`connect=`). Both run with `staking=0` and `txindex=1`.
2. **Chain:** divid mines 25 blocks, and one send stays in both mempools.
3. **Client directories:** for the option rows, some hold a `divi.conf` with a setting left out or wrong (rpcport 1,
   a wrong user and password, no `regtest`).
4. **The rows below.** Then a repeat row, divi-cli's `getblockcount` against irondivid 50 times
   (`CLI_REPLIES_REPEATS` changes the count), because the interop script has seen that call fail now and then.
5. **Node down and `-rpcwait`.** Both nodes are stopped, and both clients are called against each with the node
   down. Then each node is started again with both clients already waiting (`-rpcwait`), and their outputs are
   compared.

## Rows

**Each against divid and against irondivid** (`... on divid`, `... on irondivid`):

- **Results of each kind, as printed:**
  - a number (`getblockcount`); a string (`getbestblockhash`, a hex block, a raw transaction);
  - objects (`getblock`, `validateaddress`, `getblockchaininfo`, `getmininginfo`, `getinfo`, `getnetworkinfo`);
  - arrays (`getrawmempool` with one transaction); a bool (`verifychain`);
  - null (`setaccount`, `gettxout` of an output that is not there);
  - reals (`getdifficulty`, `getbalance`);
  - non-ASCII and escaped text, as a string reply, in an array, and as object keys (`setaccount`, `getaccount`,
    `getaddressesbyaccount`, `listaccounts`).
- **Text divi-cli sets, read back:** a non-ASCII label set with divi-cli, read back by divi-cli and by irondivi-cli.
  These rows compare with the text set (`Zürich ✓`), not with a second client run.
- **Arguments:**
  - a number, a quoted number, a number for a bool;
  - JSON arrays and objects, with and without spaces, and bad JSON;
  - digits and spaces as a string.
- **Errors (code and message on stderr, exit code `abs(code)`):** a call that errors; no argument (the help text); an
  unknown call; `help`, `help <call>`, `help` of an unknown call.
- **Switches:** `-stdin` (empty, and with the argument on stdin), `-named`, an unknown switch, only switches.
- **Where the client finds the node** (`-name=value` forms as divi-cli reads them, Settings.cpp:99-151):
  - `-rpcport` and `-rpcconnect`, and `-rpcuser`/`-rpcpassword`, on the command line where `divi.conf` leaves them
    out, and over a `divi.conf` that holds wrong values;
  - `--rpcport=`; `-rpcport` twice; `-rpcport <port>` and `--rpcport <port>` with a space; `---rpcport` (ignored);
    `-rpcconnect=localhost`;
  - `--datadir=`; `-conf` of another file and relative to `-datadir`; `-rpcwait=0`, `-norpcwait`, `-regtest=1`;
  - an option after the call; a wrong password; a wrong user; no password set; a port nothing listens on;
  - the node down; `-rpcwait` started before the node.

**Once:** `-help`, `-?`, `-version`, no arguments. For each, one row compares the exit code, the stream and the
version line's shape, and one row compares the text. Also `-datadir` and `-conf` that do not exist, and `-regtest`
with `-testnet`.

**Then:** divi-cli's `getblockcount` against irondivid 50 times, all to give the height with exit 0.

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c).

## KNOWN differences (by design: irondivi-cli is another program with more options)

- `-help: text`, `-?: text`, `no arguments: text`: the version line names the client. irondivi-cli prints
  "IronDivi RPC client version v<irondivi version>" where divi-cli prints "Divi Core RPC client version v3.0.0"
  (`divi-cli.cpp:52-65`). Exit code (1), stream (stdout) and the line's shape are the same, in the row before.
- `-version: text`: the same line, and the license text and option list are irondivi-cli's own (`divi-cli.cpp:53-62`,
  `HelpMessageCli`).
- `-stdin, the argument on stdin`: irondivi-cli reads more arguments from stdin, as Bitcoin Core's `bitcoin-cli
  -stdin` does. divi-cli has no `-stdin`: it skips it as a switch (`divi-cli.cpp:140-144`) and calls without the
  argument. With nothing on stdin both print the same.
- `-named`: irondivi-cli sends `name=value` arguments as named parameters (an object). divi-cli has no `-named` and
  sends `"height=1"` as a string. Neither node takes named parameters (divid: -32600 "Params must be an array",
  `rpcserver.cpp:903`), so irondivi-cli's `-named` is of use only with other servers.
- `--rpcport <port> with a space`: irondivi-cli also takes the `--name value` form (its `-help`: "Options may also be
  written --name value"). divi-cli reads only `-name=value` (`Settings.cpp:130-151`), so the port becomes its call and
  the conf's rpcport stays. The single-dash `-rpcport <port>` form is read alike by both.

## Proving a difference is caught

- `CLI_REPLIES_INJECT=<row name>` adds a line to irondivi-cli's stdout in that row before it is compared. For example,
  `CLI_REPLIES_INJECT='getblockcount (a number) on irondivid'` makes that row print `FAIL` and the run exit 1.
- `CLI_REPLIES_DUMP=<dir>` writes both outputs of every row that differs to `<dir>`.
