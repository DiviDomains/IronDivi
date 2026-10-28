# An encrypted wallet next to Divi Core, from encryptwallet to unlock

`run.sh` starts a fresh Divi Core 3.0.0 `divid` and a fresh irondivid on regtest, not connected, each mining its own
chain, and takes both through the same wallet steps. It covers what `scripts/unlock-send` and
`scripts/locked-wallet-rpcs` do not:

- numbers written in the request as json_spirit reads them (`+60`, `060`, `-0`, `60.`, `.5`, beyond int64/uint64);
- the argument shapes of `encryptwallet`, `walletpassphrase`, `walletpassphrasechange` and `walletlock` (missing,
  extra, empty, wrong type, a 5000-character passphrase, a passphrase with a NUL);
- the unlock timer's edges: timeout 0 and below, a timer replaced by a longer or shorter one or by 0, `walletlock`
  before a timer ends, staking-only with a timer, a full unlock over staking-only and back;
- `walletpassphrasechange` while unlocked, while staking only, and with a wrong old passphrase;
- what each state (locked, staking only, unlocked) allows: sends, signing, dumps, BIP38, imports, keypool refill, new
  addresses and mining;
- `getwalletinfo`'s and `getinfo`'s encryption members, before and after `encryptwallet`;
- the wallet after a restart;
- whether a private key or the phrase is in any file of the data directory once the node has stopped;
- `backupwallet` of the encrypted wallet started on a new node of the same kind (the two wallet formats differ, so a
  backup is never started on the other implementation).

```sh
scripts/wallet-encryption/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/wallet-encryption/run.sh target/release ~/divi-3.0.0/bin 46500 /var/tmp
```

- `<port-base>`: ports `<port-base>` to `<port-base>+7` on 127.0.0.2.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end, with every
  node stopped.
- `WALLET_ENCRYPTION_TIMEOUT`: seconds before the run is stopped (900).

A run takes a few minutes. It needs bash and python3 (standard library only). Passphrases, imported keys and RPC
passwords are made fresh for each run; they are sent only in RPC request bodies or written to 0600 `divi.conf` files,
and never printed or put on a command line.

## Rows

Each row is one call on both nodes. Compared: the outcome (a result's shape, or the error code and the first line of
its text) and the wallet after it: `encryption_status`, `unlocked_until` (0, absent, at or before the call, a few
seconds after it, or a longer time to 10 s) and `keypoolsize`. A row that differs is a `FAIL` unless it is listed
below as `KNOWN`; a `KNOWN` row that matches divid is a `FAIL` too, so the list stays true. The run ends with
`FAILS <n>`, the exit code.

## KNOWN differences

See `KNOWN` in `check.py` for the row names. Paths are under `divi/src/` of Divi Core 3.0.0.

- `bip38encrypt` exists on irondivid only; divid has `bip38paperwallet` (rpcserver.cpp:424-425).
- divid copies a passphrase with `c_str()` (rpcwallet.cpp:2603, :2645-2650, :2711), so it ends at the first NUL
  character; irondivid uses the passphrase as given.
- `dumphdinfo`: irondivid adds an `hdaccountpath` member (the path its keys derive from).
- `walletpassphrase` with a timeout of 2^62: divid's timer overflows (`posix_time::seconds`, rpcserver.cpp:852) and
  the wallet locks at once; irondivid keeps it unlocked until `walletlock`.
- A timeout written `1e400`: json_spirit reads a real beyond a double as infinity, so divid unlocks and then refuses
  the timeout's type; serde_json has no infinite number, so irondivid refuses the request (-32700) and unlocks nothing.
- `bip38decrypt` with a wrong passphrase: divid adds whatever key comes out of the decryption, a key nobody holds
  coins on (rpcdump.cpp:316-339); irondivid answers -4 `Failed To Decrypt`.
