# submitblock, getblocktemplate and reservebalance next to Divi Core

`run.sh` starts a fresh Divi Core 3.0.0 `divid` and a fresh irondivid on regtest, not connected to each other.
- It calls `submitblock`, `getblocktemplate` and `reservebalance` on both with the same arguments and compares the
  replies.
- Around those calls it compares `getblockcount`, `getchaintips` and `getstakingstatus`, also after a restart.

Each row prints one line:
- `PASS`: same as divid;
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not, a `KNOWN` row that differs in another way, or a `KNOWN` row that now matches
  divid (the list below is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 15
minutes).

```sh
scripts/submit-reserve/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/submit-reserve/run.sh target/release ~/divi-3.0.0/bin 53700 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` on 127.0.0.2 (divid p2p and RPC, then irondivid's).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 3 minutes. However it ends, both nodes are stopped and their directories deleted. Needs bash and
python3 (standard library only). RPC passwords are made at random per run and kept in each node's 0600 `divi.conf`.

## What divid has

Divi Core 3.0.0 has none of the three calls. They are not in its command table (`rpcserver.cpp:329-460`), so each
answers `-32601 "Method not found"` with any arguments, and `help <call>` says `help: unknown command: <call>`.
- No `-reservebalance` option exists either (`LicenseAndInfo.cpp`).
- The staker keeps nothing back.
- `getstakingstatus` sets `enoughcoins` to `staking_balance > 0`; only its help text still speaks of a reserve
  balance (`rpcmisc.cpp:1036-1066`).

## Rows

| rows | what is sent |
|---|---|
| `help submitblock`; `submitblock` with the tip block from `getblock <hash> false`, and with its nonce (byte 76), merkle root (byte 36), first coinbase output value or parent hash (byte 4) changed; a 2.1 MB block of zeros; `zz`; one byte; no argument; the tip block and a second argument | then `getblockcount` and `getchaintips` against the state before |
| `help getblocktemplate`; `getblocktemplate` with no argument and with mode `template`, `proposal` (the tip block) and `nonsense` | |
| `getstakingstatus` (walletunlocked, staking_balance, enoughcoins); `help reservebalance`; `reservebalance` with nothing, `true 100`, `true`, `false`, `false 100`, `true -1`, `true abc`, `true` above the balance, then shown; `getstakingstatus` again; after a restart `reservebalance` and `getstakingstatus` | |

Each node mines 25 blocks of its own first, so its wallet has a staking balance.

## KNOWN differences

None.

## Proving a difference is caught

`SUBMIT_RESERVE_INJECT=<row name>` replaces irondivid's value in that row, which must then FAIL. Or run a build
that still has `reservebalance`, such as dc7aa8e: its 12 reservebalance rows FAIL.
