# Low disk and failed writes, next to Divi Core

`run.sh` starts a Divi Core 3.0.0 `divid` miner on regtest and two followers of it, a `divid` and an irondivid, and
makes the followers' writes fail without filling any disk: each follower runs under a file size limit
(`ulimit -f`, with SIGXFSZ ignored), so a write past that size fails with EFBIG. For each case it compares whether
the node stops, whether what it prints names the failed write, the RPC replies on the way, and what a start without
the limit finds on disk: whether it starts, its height and best block, its wallet balance and transactions. Each row
prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not, a `KNOWN` row that differs in another way, or a `KNOWN` row that now matches
  divid (the list below is out of date).

Lines starting with `#` show what each node printed and the other facts that are not compared (exit codes, heights,
the files that reached the limit). The height after the restart is shown, not compared: after `-reindex` divid comes
back at whatever its block files hold, sometimes above the last height it answered and sometimes below it (it had
answered blocks it never wrote). What is compared is that the node's best block is the miner's block at its height. The run ends with `# rows: ...` and `FAILS <n>`; the exit code is the number of
FAILs (255: usage error, interrupted, or over 30 minutes).

```sh
scripts/disk-errors/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/disk-errors/run.sh target/release ~/divi-3.0.0/bin 54250 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+5` on 127.0.0.2 (the miner's p2p and RPC, then divid's, then
  irondivid's). `<port-base>+49` must have nothing listening: a follower started alone is pointed at it.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end (kept with
  `KEEP=1`, with each node's output).
- `DISK_ERRORS_MARGIN_KB` (32): how far past its largest file a follower may write; `DISK_ERRORS_MAX_BLOCKS` (4000):
  the most blocks mined while waiting for a write to fail.

A run takes 4 to 6 minutes and is stopped after 30. However it ends, every node is stopped. Needs bash and python3
(standard library only). RPC passwords are made at random for each run and kept in each node's 0600 `divi.conf`.
Each node's output goes through a pipe to a file the script writes, so the limit never applies to the log.

## Nodes and the limit

1. The miner mines 110 blocks. Each follower starts with no limit, follows the miner, makes an address and is sent
   100 DIVI, follows two more blocks and stops cleanly. That data directory is the template every case starts from.
2. The limit is worked out per node from its own files: the bytes in use of its largest file (up to its last
   non-zero byte, since divid preallocates its block files with zeros, `util.cpp:197-224`), plus the margin. The two
   nodes keep different files (divid: `blocks/blk*.dat`, `rev*.dat`, LevelDB and `wallet.dat`; irondivid: RocksDB),
   so the file that fails first differs; the run prints which files reached the limit.

## Rows

Core paths are under `divi/src/` of the Divi Core source at v3.0.0.

| case | what divid does |
|---|---|
| blocks until the limit | the miner mines 20 blocks at a time until the follower stops, or stops taking blocks. A write fails and divid aborts: `*** System error: CAutoFile::write : write failed` or `*** System error while flushing: Database I/O error` and `Error: A fatal internal error occured, see debug.log for details` (AbortNode, `ValidationState.cpp:17-27`; `ChainExtensionService.cpp:513-518`, `FlushChainState.cpp:37-58`), and shuts down. So `getblockcount` and a `sendtoaddress` at the limit find no node |
| ... and a start without the limit | divid's own state is left damaged (KNOWN below); with `-reindex` it comes back at the best block it had written, the miner's block at that height, with its coin and wallet |
| start with the limit reached | the limit is half the largest file's bytes in use. The node starts alone (it comes up), is then told to connect to the miner (`addnode … onetry`, the miner is far ahead by now) and the miner mines 5 more: the first block write past the limit stops divid within seconds; the start without the limit finds the same as above |

## Not covered here

- The 50 MB free-space check (`CheckDiskSpace`, `BlockDiskAccessor.cpp:13-25`): it needs a small filesystem, which
  this script does not make. irondivid's check is tested in `crates/divi-storage` with the free space set for the
  test (`chain::tests::disk_space`).
- A wallet write that fails while the chain can still be written: divid writes its wallet through BerkeleyDB and does
  not abort when a wallet write fails (`walletdb.cpp`), so there is nothing to compare beyond what the rows show.

## KNOWN differences

- `restart without the limit` (both cases): after the failed write divid exits through std::terminate, since its
  shutdown flush throws `leveldb_error` (`leveldbwrapper.cpp:15-23`) and nothing catches it. Its block files, block
  index and coins are left at different points. Started again it crashes (SIGSEGV) after "Checking all blk files are
  present", or refuses with "Block database corruption detected!" (`BlockIndexLoading.cpp:275`), and comes up only
  with `-reindex`. irondivid starts on the chain it had. divid is wrong here by accident.
