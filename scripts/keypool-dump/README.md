# The key pool and the wallet dump calls next to Divi Core

`run.sh` starts a fresh Divi Core 3.0.0 `divid` and a fresh irondivid wallet for each key pool setting and makes
the same calls on both. Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 30
minutes).

```sh
scripts/keypool-dump/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/keypool-dump/run.sh target/release ~/divi-3.0.0/bin 53950 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` on 127.0.0.1 (p2p and RPC of divid, then irondivid's). The
  nodes do not connect to each other or to anyone else.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end, with every
  node stopped, however the run ends. A run takes a few minutes.

Needs bash and python3 (standard library only). RPC passwords and the wallet passphrase are made at random for
each run. The passphrase lives only in memory and in RPC requests: it is never printed, logged, written to a file
or put on a command line. No key is printed. Each wallet has its own keys, so an address is compared by its form
(the base58check version byte and payload length), never shown. The files the dump rows name are deleted at the
end.

## Steps
Each step uses a fresh pair of wallets started with its option.

| step | calls (getwalletinfo `keypoolsize` compared after each) |
|---|---|
| `-keypool` unset (divid's default, 1000 per chain: `wallet.cpp:2059`) | a fresh wallet; `getnewaddress`; `getrawchangeaddress`; `keypoolrefill` with no size, 5 (below the pool), 0, 1200; refused: -1, `"x"`, 1.5, two arguments |
| dump calls (same wallets) | `dumpwallet` of a new file, of an existing file, of a file in a missing directory, with no argument; `importwallet` of a file that is no dump and of a missing file; whether a file or directory was made or the existing file changed |
| `-keypool=0` (a target of at least 1 per chain, `wallet.cpp:2079-2080`) | fresh; `getnewaddress` ×2; `getrawchangeaddress` ×2; `keypoolrefill` |
| `-keypool=1` | fresh; `getnewaddress` ×3; `getrawchangeaddress` ×2; `keypoolrefill 4` |
| `-keypool=3`, encrypted | fresh; `getnewaddress`; `encryptwallet`. Locked: `getnewaddress` ×5 and `getrawchangeaddress` ×5 (the pool runs out: -12, `rpcwallet.cpp:305-307`, `:574-576`); `keypoolrefill` with and without a size (-13); `dumpwallet`. Unlocked for staking only: `getnewaddress` ×2, `getrawchangeaddress`, `keypoolrefill` (-13: still locked to these calls, `crypter.h:139-157`, while the pool tops up, `wallet.cpp:2129-2130`). Unlocked: `getnewaddress`; `keypoolrefill`; `keypoolrefill 6`. Locked again: the pool size; `getnewaddress`. |
| `-keypool=2000` | fresh; `getnewaddress`; `getrawchangeaddress`; `keypoolrefill 100` (below the target) |

How a row compares: the same outcome (a result, or an error with the same code and message, a help text by its
first line) and the same value. An address is compared by its form.

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c):
- `getnewaddress` `rpcwallet.cpp:281-313`, `getrawchangeaddress` `:558-583`, `keypoolrefill` `:2544-2571`,
  `getwalletinfo` `:2873-2908`;
- TopUpKeyPool `wallet.cpp:2057-2120`, ReserveKeyFromKeyPool `:2122-2156`, GetKeyFromPool `:2179-2195`,
  GetKeyPoolSize `:2197-2201`, CReserveKey `reservekey.cpp:16-33`;
- divid has no `dumpwallet` or `importwallet`: neither is in its table (`rpcserver.cpp:420-464`) nor in
  `rpcdump.cpp`; both answer -32601 `Method not found`;
- a wallet is always HD: a new one gets an HD chain and a loaded non-HD wallet is refused (`wallet.cpp:1974-1988`),
  so there is no non-HD pool to compare.

## KNOWN differences

- `getwalletinfo keypoololdest (every step)`: irondivid adds `keypoololdest` to `getwalletinfo`, divid has no such
  member (`rpcwallet.cpp:2894-2906`). Kept on purpose: `docs/divid-differences.md` R4 (also KNOWN in
  `scripts/wallet-replies`).

## Proving a difference is caught

`KEYPOOL_DUMP_INJECT=<row name>` changes irondivid's reply of that row before it is compared, e.g.
`KEYPOOL_DUMP_INJECT='-keypool=3 locked: getnewaddress #4'`: that row prints `FAIL` and the run exits 1.
