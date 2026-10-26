# Wallet writes that fail, next to Divi Core

`run.sh` starts a Divi Core 3.0.0 `divid` and an irondivid, each alone on regtest with its own chain, and makes their
wallet writes fail while they run, without filling any disk. Each node starts with SIGXFSZ ignored, as in
`scripts/disk-errors`. At the step under test the soft file size limit of the running process is lowered to one byte
with `prlimit` (a write past it fails with EFBIG), and raised again afterwards. No block is made while the limit is
down, so only the wallet's writes fail; a chain write that fails is `scripts/disk-errors`' subject.

For each case the script compares the RPC replies (code and message), whether a log line names the failed write,
whether the node stays up, and what a restart finds: balance, the transactions sent, the keys handed out, the
wallet's encryption. Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not, a `KNOWN` row that differs in another way, or a `KNOWN` row that now matches
  divid (the list below is out of date).

Replies that hold a txid or an address are compared as `["ok", "txid"]` or `["ok", "address"]`. The run ends with
`# rows: ...` and `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 20
minutes).

```sh
scripts/wallet-write-failures/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example
cargo build -p irondivid
scripts/wallet-write-failures/run.sh target/debug ~/divi-3.0.0/bin 53700 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` on 127.0.0.2 (divid's p2p and RPC, then irondivid's).
  Nothing may listen on `<port-base>+4`: both nodes are told to connect only there, so they have no peers.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end (kept with
  `KEEP=1`, with each node's output).

A run takes about a minute. Needs bash, python3 (standard library only) and util-linux's `prlimit`; no root. RPC
passwords are made at random for each run and kept in each node's 0600 `divi.conf`. Each node's output goes
through a pipe to a file the script writes, so the limit never applies to the log.

## Cases

Core paths are under `divi/src/` of the Divi Core source at v3.0.0. In each case both nodes mine 110 blocks, fill
their keypool and hand out one address before the limit goes down.

| case | what divid does |
|---|---|
| `send` | With the keypool full, `getnewaddress` hands out a pool key: its key was written when the pool was topped up, and KeepKey does not read ErasePool's result (`wallet.cpp:2158-2163`). After `keypoolrefill` once writes work, `sendtoaddress` with the limit down answers its txid: the change key comes from the pool, AddToWallet logs `addToWallet - Unable to write tx (…) to disk` and goes on (`wallet.cpp:1271-1274`), and the send is relayed. `getnewaddress` then needs a new key, whose write fails, and the derivation throws: `-1 loadHDChain: WriteHDChain failed` (`wallet.cpp:2346-2347`, answered with the exception's text, `rpcserver.cpp:1107-1108`). `setaccount` answers null: its result is not read (`rpcwallet.cpp:616`). The node stays up; once writes work its next send goes through, and a block mined then writes the earlier send too. After a restart: the balance after both sends, both sends listed, and the pool key handed out is the wallet's |
| `encryptwallet with a full keypool` | The writes inside its encryption transaction go through; the rewrite of the file fails (`CDB::Rewrite : Failed to rewrite database file`, `wallet.cpp:1025-1028`): `-16 Error: Failed to encrypt the wallet.` (`rpcwallet.cpp:2729-2730`). After a restart the wallet is unencrypted, with its balance |
| `encryptwallet with a keypool one short` | The keypool top-up after the encryption (`wallet.cpp:1011-1015`) derives a key whose write fails, and the derivation throws: `-1 loadCryptedHDChain: WriteCryptedHDChain failed` (`wallet.cpp:2359-2360`), with no log line. After a restart the wallet is unencrypted |

## KNOWN differences

- `the wallet's state while it runs on` (both encryptwallet cases): divid encrypts its keys in memory first and does
  not undo that when a later write fails (`wallet.cpp:960-1030`). So the wallet it runs on shows `locked` (full
  keypool) or `unlocked` (one short) while the file is unencrypted, as the restart rows show. irondivid leaves the
  wallet as it was: `unencrypted`.
- `encryptwallet with a keypool one short: encryptwallet` and `…: a log line names the failed write`: in divid, the
  writes inside its encryption transaction go through and only the top-up after it fails, which throws past the
  RPC's own error. irondivid fails at its first write and answers `-16 Error: Failed to encrypt the wallet.`, as
  divid does when its keypool is full, and logs the cause. Copying divid would mean copying when Berkeley DB writes
  its log.

## Not compared

- **A keypool entry that cannot be read** (`wallet.cpp:2143-2151`, ReserveKeyFromKeyPool: `read failed`, `unknown
  key in key pool`, `keypool entry misclassified`). irondivid has no keypool record: its keypool is the HD keys
  stored past the next index, with the two indices (`crates/divi-wallet/src/keystore.rs` `top_up_keypool`). There
  is no record to damage the same way in both files. In divid a pool record is read at load and again at
  ReserveKeyFromKeyPool, so `read failed` needs the record to vanish while the wallet runs, which Berkeley DB, holding
  the file, does not allow from outside.
- **walletdb.cpp:290-298** (`multisig` records), **:543-549** (rewriting 0.4.0 and 0.5.0rc encrypted wallets) and
  **:471-473** (`minversion` newer than the client): irondivid has none of these records. Its wallet is RocksDB,
  with no Berkeley DB versions and no minimum-version record.
- **A received transaction whose write fails:** a received transaction comes in a block, and the block write fails
  first; divid then aborts (`scripts/disk-errors`).
- **A send made while writes fail, never confirmed, after a restart:** both keep it in memory only. divid holds it in
  mapWallet and writes it at its next change (`wallet.cpp:1271-1274`), and irondivid logs `Failed to store
  unconfirmed wallet tx` and records it when a block confirms it. So both lose it at a restart before a block. The
  `send` case mines a block before its restart, so the rows show both keeping it.
