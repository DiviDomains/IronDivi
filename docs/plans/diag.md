# Plan: `irondivi diag` and the node's own flight recorder

Status: plan, Revision 16 (the A1–A4 implementation's findings recorded
against the plan; Revision 15 folded the fourteenth review round —
consensus, crashes, platforms, privacy, adversarial — into the body; Revision 14 folded
in the thirteenth round, Revision 13 the twelfth, Revision 12 the eleventh, Revision 11 the tenth, Revision 10 the ninth,
Revision 9 the eighth,
Revision 8 the seventh, Revision 7 the /proc facts measured on hp3 on
2026-10-30). Not implemented, except D5's `PR_SET_DUMPABLE` call
(bae9c769), its hardening in b2dbea56 (`disable_core_dumps()` now always
runs the `prctl`, even when `setrlimit` fails, and returns the first
error), D5's credential-call lint (97c4bceb,
`bin/irondivid/tests/credential_calls_lint.rs`) and D5's per-tick
dumpable re-check (f5f3bce5, moved onto its own `dumpable-check` thread in
856f7376), the A11 item 8 sync-complete change (1fd59a5c), its
catch-up gate (8e4bfaca, `CAUGHT_UP_LAG`), the main-task panic exit
(70cb5785), the removal of the per-transaction wallet mempool lines
(f67b0984, bf6452fc), the "Header sync complete" gate and the single
way into Synced (73440b48), and the removal of the per-transaction
relay and submit lines (09cb18e4, 6de594fb), and, in Revision 16, A1
(ff299088), A2 (d34c0bac, 426dba00, 3309b5ad), A3 (4aea6299), A4
(deb9295f), the R3 usage-message fix (bcf713c8), and Part B's B1, B2, B6.4, §6 and
§8.1–§8.3 (d3502999 … 29c7bbf8), as built, with the
differences listed under "Revision 16 changes".
Date: 2026-10-30; Revision 16 2026-10-31. Revision 1 is kept outside the repo for comparison.
Line numbers are as of 6de594fb. Six files changed since f67b0984
(`git diff --stat f67b0984..6de594fb`): `bin/irondivid/src/main.rs`
(one line removed at `:2345`), `crates/divi-network/src/relay.rs`,
`crates/divi-network/src/sync.rs`, `crates/divi-node/src/node.rs`,
`crates/divi-rpc/src/wallet.rs` and `crates/divi-wallet/src/wallet_db.rs`;
the citations into them are re-based, and a line those commits removed
keeps its f67b0984 number and is marked removed where it is named. Only
`sync.rs` and `main.rs` changed between 1fd59a5c and f67b0984
(`git diff --stat 1fd59a5c..f67b0984`), so the citations of every other
file are as r13 checked them. 8e4bfaca shifts `sync.rs`
by +11 from line 71, +12 to +13 around the connect loop and +32 after
`check_timeouts`; 70cb5785 shifts `main.rs` by +14 after line 3191. Both
are re-based throughout, the older change lists included, so every
number in the plan, in any revision's list, points into 6de594fb,
except the removed lines named as such. They
drift, so each one also names the code it points at.

### Revision 16 changes

The first §10 item 2 parts are implemented: A1 `runs.log` (ff299088), A2
the marker (d34c0bac, 426dba00, rustfmt 3309b5ad), A3 signals (4aea6299)
and A4 panics and tasks (deb9295f), after the R3 usage-message fix
(bcf713c8). This entry records where the code differs from the plan,
found while building them. The tests named are the ones that hold each
point; `main.rs` line numbers in older revisions predate these commits
and are not re-based.

- R3, code 2 never echoes a value (bcf713c8): every usage reason
  (`-onlynet`, `-whitelist`, `-whitebind`, `-externalip`,
  `-minrelaytxfee`, `-maxtxfee`, `-rpcbind`, `-rpcallowip`, the argument
  parser's number parse, `-loglevel`, `-expire`, the Electrum and web UI
  addresses, and the RPC access checks) names the option and why, never
  the value given, as the `divi.conf` reasons already did; a repeated
  option names its place ("value i of n"). `exit_codes.rs` passes a
  sentinel value to each and checks it is absent from stderr and from
  every log under the data directory.
- R3, `divi.conf` values: a bad value read from `divi.conf` exits 2
  (usage), not 3: code 3 is a file that cannot be read or that divid's
  parser refuses (`ConfigFileError`), and a value that parses but is
  refused when the settings are applied exits 2. Several divid-style options still accept a bad value
  and fall back to the default instead of refusing it; they are not yet
  checked.
- R3, code 7: a P2P listener that fails to start, and an RPC bind that
  fails with `AddrInUse`, `AddrNotAvailable` or `PermissionDenied`, exit
  7. An RPC address the access settings refuse (an `InvalidInput` error)
  exits 2.
- R3, code 9 is recognised by the error's text ("No space left on
  device", "Read-only file system"), since RocksDB's errors reach the node
  as text, as well as by `ENOSPC`/`EROFS` on the node's own writes.
- R3, code 10 is also the generic code: a start-up error that maps to no
  other code exits 10, not only a critical task. The third stop signal
  (10) counts TERM, INT and QUIT alike (A3).
- R3, code 101: the main thread's `catch_unwind` is the only one in
  `irondivid` and the ten node crates (`tasks_lint`
  `main_has_the_only_catch_unwind`), which holds Crashes R15-1 in place of
  the line numbers `:3194`/`:3203`. A panic on the main thread before that
  `catch_unwind` is entered also exits 101, from the hook.
- A2, the marker after a panic: `die` and the main thread's catch write
  the `exit` record and then remove the marker, so a panic that ends the
  node (10 or 101) leaves no marker and the next start writes no
  `unclean-previous`. Only an exit from the signal handler (the third stop
  signal, and the default-action signals that exit 128+N) leaves the
  marker, read next start as `verdict=exit-recorded`. The crash.log
  verdict rows describe A5's records, not A4's (`runs_log`
  `a_task_panic_is_recorded_and_a_main_panic_exits_101`,
  `a_critical_panic_ends_the_run_with_code_10`).
- A3 as built: no A11 or A17 parts yet (no counters in the third
  signal's record); no argv allowlist, the sender's command line is
  masked by its own rule; HUP reopens `debug.log` only; QUIT counts as a
  stop and records `dump=not-implemented`; USR1 records "not
  implemented"; the sender is not read on macOS; a stop signal that
  arrives before the record sink is set is held and recorded when it is;
  a one-shot command (not the node) keeps the default action; the
  default-action group writes `exit code=128+N` and re-raises. The TSTP
  stop branch has no test. The SIGPIPE and EPIPE counts go in the exit
  record.
- A3, the 5 s window (817b7013): a stop signal (TERM, INT or QUIT)
  within 5 s of the last *counted* one is recorded as `ignored count=<n>
  within=5s` and does not count. The window is measured from the last
  counted signal and re-armed by each, so `_exit(10)` takes three
  signals each more than 5 s after the one counted before it; the plan
  speaks only of "a second one within 5 s", the third's timing is this
  reading. A counted second signal is still recorded and ignored as
  before (`ignored count=2`). Debug builds read
  `IRONDIVI_TEST_STOP_WINDOW_MS`, so `a_third_stop_signal_ends_the_run_with_code_10`
  can send all three at once with the window at 0;
  `stop_signals_within_five_seconds_count_once` sends three at once with
  the default window and expects exit 0 and two ignored records. The
  count and the time of the last counted signal share one atomic word
  (count in the top 8 bits, monotonic ms below), and a signal counts
  only when its compare-and-swap moves that word; a handler that loses
  re-reads the winner's count and time and decides again (60e039d8). So
  two handlers running at once on different threads cannot both count
  inside one window, and the test no longer depends on their order. The
  window is kept in whole milliseconds.
- A4 as built: the hook ends the node itself (`die(10, "Error: <name>
  panicked")` for a critical task or thread), with no supervisor between;
  the `panic` record in `runs.log` holds thread, task, location and
  `ends_node` only, and the message and a forced backtrace go to
  `diag/crash.log` (mode 0600), followed by the A8 ring. The default hook
  still prints the message to stderr, as A4 says ("Then the default hook
  runs"); stderr is the console, or `/dev/null` under `-daemon`, so it is
  kept out of `runs.log` only. A supervised panic is also a `task-failed`
  record in `events.log` (name and place, no message), an incident, and
  one more in health's `panics` count (194c97e6); a panic that ends the
  node writes the crash and `runs.log` records only. A critical task that
  returns an error ends the node through `die(10, "Error: <name>:
  <error>")` (the plan's reason has no `Error: ` prefix; every `die`
  reason has it, as the console line it also is); a supervised task's
  error is a `task-failed cause=error` record with its name, the error
  text going to `debug.log`. No A11 counters or wrapping yet. irondivid
  starts every task and thread through `tasks.rs` (`tasks_lint`
  `irondivid_starts_tasks_only_through_tasks_rs`); the node crates are
  not converted, and a ratchet keeps their spawn count from growing
  (`the_node_crates_start_no_new_tasks`). `spawn_blocking` goes through
  `tasks::spawn_blocking(name, ...)` in irondivid (aa7bacb2), which runs
  the work under its name, so its panic records `task=<name>`, critical
  when the caller is; the lint refuses a bare `spawn_blocking` there. The
  RPC server, web UI and Electrum crates still call it unnamed (counted by
  the ratchet), and a panic in one records `task="-"`. A4 converts
  `tokio::spawn` and `std::thread::spawn` and does not name
  `spawn_blocking`, and those crates cannot reach irondivid's `tasks.rs`,
  so they stay unnamed and the ratchet stays as it is. The test seam
  `IRONDIVI_TEST_PANIC` (regtest only) delays its critical panics 2 s so
  the test sees RPC answer first.
- A8 as built (c7c4985b): the ring is not redacted (A11 is not built);
  it reaches only `crash.log` (0600, local), not yet `getdiaginfo` (A10).
  It holds the node's own categories at debug and libraries at info (the
  plan's "every category" read as ours); a ring line is cut at 320
  bytes and carries no span fields. The delivery queue is bounded at
  65536 lines (the plan gives no number); its drop path has no test.
  Counted lines are filtered per layer; nothing disables them globally.
  The `tracing-appender` dependency is left in `Cargo.toml`, unused.
- A5 as built (2086651b): no `pthread_create` interposition, so a thread
  the node does not start (RocksDB pools, blocking-pool threads not seen
  by `on_thread_start`) has no alternate stack and no stack range; its
  record says `thread=<comm> foreign=yes` and has no frame walk. No
  filtered 16 KB raw stack dump (item 3) and no 32-bit `crash-stack.bin`;
  no seccomp `si_syscall`/`si_arch`; on macOS no dyld image list or
  registers (`pc=- sp=- fp=-` off Linux x86_64 and aarch64). No A11
  counters. The sender is named by `si_pid`, `si_uid` and
  `/proc/<pid>/comm` only, no command line or parent chain. No
  `pthread_key` destructor: the guard that enters a thread
  (`tasks::thread`, tokio's `on_thread_stop`) frees its alternate stack.
  The 64 KB alternate stack's headroom is not measured. The `maps` copy
  is refreshed at start and on each `dumpable-check` tick. The test seam
  is `IRONDIVI_TEST_CRASH=segv|abort|overflow` (regtest and debug
  builds) instead of a `crashtest` build feature. The aarch64 and macOS
  branches are not compiled on hp3. A crash's verdict is `crash
  signal=<S>` or `sent-by comm=<c> signal=<S>`; `crash_log=record|none`
  replaces `not-read`; `kernel_log` is still `not-read`.
- A6 as built (194c97e6, which also closed the A4 `events.log` and
  health-count gaps): written as `n/a` for now are `rpc_calls`,
  `lock_waits`, `stakes_30d`, `stake_ratio`, `masternode`, `mnsync`,
  `allocator`, `rocksdb`, `future_headers_rejected` and every macOS-only
  field; the staking group is `n/a` when the node runs without a staker.
  Incidents carry no `getdiaginfo` output yet, and only the stall (over
  600 s) and supervised-panic triggers are built. One stall incident per
  stall, re-armed when the tip moves (consensus N-k); the stall uses the
  boot clock, so time suspended counts as stall time (platforms R15-1),
  and the stall record carries `clock_synced`. No integration test drives
  a real stall; the latch is unit-tested. Start and stop stay in
  `runs.log` only. Health reads chain state through the node's locks and
  calls `get_status` on every tick. The dumpable check runs at the
  health tick's rate (10 s for the first 10 minutes, then 60 s) on its
  own `dumpable-check` thread; its value is in `health.log`, and a reset
  is the `events.log` record `dumpable-reset was=<n> result=ok|error`
  (the plan's text `dumpable restored (was <n>)` stays the `debug.log`
  line).
- A7 as built (2b8d663e, 56f98396): `diag/startup/<run>.txt`, mode 0600,
  the last 20 kept, capped at 64 KB with `truncated=yes`. No pseudonyms:
  a value is written as it is only for keys whose values are numbers,
  switches or words, and every other value (secrets, addresses, paths,
  commands, the `electrum*` bind addresses) is `<set>`; `HOME` is
  `<set>`; `IRONDIVI_*` variables show a value only for the three the
  node reads, others by name. The start directory is a class (`/`,
  `datadir`, `inside-datadir`, `<other>`), not a path. `git=` is `-`
  unless the build had a checkout or `IRONDIVID_GIT_SHA`; `features=`
  names only `fault-injection`. The Linux-only fields (`/proc/self/status`,
  `fs_type`, mount options) are `n/a` on macOS, which has not run it.
- Crashes R15-2: the RocksDB close in an early panic's unwind is "bounded
  on a responsive disk", not bounded; A4 now says so.
- `flush_log` cannot deadlock `die` when a critical panic is raised from
  inside logging: it takes a lock only it uses, drops the log writer's
  guard, and the stdout and stderr locks it then takes are reentrant.
- A11 types and flag (f0ccd6b0): the wrappers live in
  `divi_primitives::redact`, the one crate every node crate already
  depends on, so no crate gains a dependency. The HMAC-SHA256 is built
  there from `sha2` (no `hmac` crate; `rand` is a dev dependency only);
  the key is 32 bytes from `/dev/urandom`, or, where that cannot be
  read, a SHA-256 of a `RandomState` hash, the pid and the time. A
  pseudonym is 8 hex digits (`wtx-3f2a91c0`), not the plan's 4: one run
  can log tens of thousands of wallet values, and 4 digits collide
  within a few hundred. Two types beyond the plan's list:
  `WalletScripthash` (`wsh-`, the Electrum scripthashes the plan routes
  "through the same wrapper") and `WalletValue` (`wal-`, any other
  wallet value a line must name). `SwapId` exists but no swap line is
  converted: `divi-swap` does not depend on `divi-primitives` and
  `irondivid` does not link `divi-swap`, so its lines never reach a
  node log. The `-logwalletdetail` start warning and the
  `setlogconfig-refused` record (`option=logwalletdetail`) are as the
  plan says; `logwalletdetail` is listed in the A7 record so diag can
  read it there.

Part B as built so far: B1 discovery, the B2 collectors (B2.0–B2.19),
`contrib/diag.sh` (B1.4), `--import` (B6.4), the §6.2 redaction and §6.3
scanner, and §8.1–§8.3 with the §8.4 offline stop, in the crate
`crates/divi-diag` behind `irondivi-cli diag` (d3502999, c83a9dd4,
da960024, 27e50955 … 96554be4, 3016d799, 2bf873f4, 27d59aab, c23a0e76,
ad0562c7) and the shared option parser `crates/divi-settings` (29c7bbf8).
Tested on hp1, hp2 and hp3 as a user and as root; on macOS only
`contrib/diag.sh` ran, since the Rust code is only cross-checked
(`cargo check --target aarch64-apple-darwin` on hp3). Corrections:

- B2.2, no nodename or user name anywhere: `diag.sh` printed `uname -a`
  and `id`; it now prints `uname -srvm` and numeric ids only. On macOS it
  uses `otool -L` where `ldd` is missing, `sw_vers` where
  `/etc/os-release` is missing, and `log show` where `dmesg` is denied.
- B1.4 / B6.4: `diag.sh` tells the user to run `irondivi-cli diag
  --import <folder>`; that command now exists (27d59aab). It takes a
  folder or a tar on stdin (`--import -`), redacts and scans as a direct
  run does, writes a new package folder, and deletes the unredacted
  input unless `--keep-raw`. `diag.sh --emit-shar` writes a shell
  archive, which the user unpacks and imports as a folder; diag does not
  read the shar itself. Bad input leaves no output folder.
- B1.3, "parsed with the node's parser": the parser was compiled into
  divi-diag from `bin/irondivid/src/settings.rs` by path, which tied it
  to a file of the node's binary. It is now its own crate,
  `crates/divi-settings`, used by both; `irondivid`'s `settings.rs` is a
  one-line re-export.
- B1, a data dir the user cannot look into (`/root/.irondivi` from a user
  run, `EACCES` on the parent): the plan is silent. Diag reports "cannot
  check, sudo can" and the `sudo` command, not an unreadable data dir.
- B1 / B2.19 search places: the plan gives no list. Diag searches a fixed
  set of system directories plus every home under `/home`, `/Users` and
  `/root`, and each chain subdirectory (`testnet`, `regtest`,
  `privatedivi`) of a base data dir. `diag.sh` skips the config file and
  lists processes by name only.
- Run table (B2.5): a run that ends on a "Daemon error" exit with no A1
  `exit` record shows as "no clean shutdown line"; the A1/A9 exit records
  settle it on a node that writes them.
- §6.2 step 3, names that are ours: a folder or image the user named
  `irondivi-<x>` or `divi-<x>` is user data and gets a placeholder. Only
  the fixed names in "Paths" below stay readable; the earlier broad
  `irondivi-`, `irondivid-` and `divi-` prefixes are gone (2bf873f4).
  Locally built Docker image names are pseudonymised unless they are
  `irondivi` or `irondivid`.
- §6.2 step 3, kernel lines that quote a command line (`ptrace attach of
  "python3 -I /x secret"[123]`, audit and OOM lines): the plan named no
  rule. Each quoted command line followed by `[pid]` keeps only the
  program's base name, as `"python3 <args>"[123]`; the rule is now in
  §6.2 step 3.
- §6.2 over-redaction left: mount points, Docker overlay hashes and
  `/dev/mapper` names still become placeholders, which costs the
  developer some disk context; they are kept hidden until a rule says
  which are safe.
- §6.3, canaries not yet testable: `--rpc`, the attach path (B6.2), A10
  `known_values`, A11 counters, `crash.log` and the incident files come
  from parts not built or not runnable on the test hosts; the scanner
  runs over them when they exist, but no canary test covers them yet.
- §8.1 `--report-file`: a plain text file; a line `## N` starts answer N
  and text before the first heading is answer 1. It is capped at 1 MB and
  passes the "Old-log lines" filter and §6.2 like the answers typed at
  the terminal. With no terminal and no file the report says the
  questions were skipped.
- §8.2 is not asked in this version: the summary says which questions
  were not asked, and that no developer key is compiled in.
- §8.3 exclusions are non-destructive: an excluded file stays in the
  folder and the exclusions are kept in `preview.ok` (mode 0600, never
  sent), with a digest of every file; `--send` reads it, says which files
  changed since the last review and keeps the exclusions. The packed
  manifest names every excluded file and every file the scan left out at
  send, as comment lines. A file added with `i` is listed with collector
  `user-added`. `00-SUMMARY.txt` can be excluded like any other file;
  `02-manifest.txt` is not listed and is always sent, rewritten at send.
- §8.3 step 4, a file the send-time scan still matches is left out and
  listed with the reason, not sent and not a refusal of the whole send.
- §8.3 step 5 with R2: `--send <folder>` always runs the whole review
  again (list, menu, final question), and with no terminal it refuses
  (exit 1) rather than send unreviewed. It builds a fresh redactor from
  the machine as it is now; the folder's own salt is not re-checked.
- §8.4: built on the offline path. After `yes` the files and their
  manifest are packed as a tar (mtime 0, each file's SHA-256 checked),
  compressed with zstd (level 12) and encrypted with `age` (binary
  format, X25519) to the developer key in `DEV_KEY`, the one place it
  lives. The fingerprint printed at send is the first 16 hex characters
  of the SHA-256 of the `age1…` recipient string (`9274ffc0368679fe`); the
  private half is in the developer's 1Password only. The result is written
  beside the folder as `<folder>.age` (mode 0600) with its SHA-256, for
  the user to send by hand; nothing unencrypted is ever written beside the
  folder. Crates pinned: `age =0.11.1`, `zstd =0.13.3`. No receiver
  address is compiled in (§9 hosting is open). A build with `DEV_KEY`
  empty still stops after `yes` and writes nothing.
- Exit codes after the review: a collection run exits on its own result
  (0 when complete) whatever the review ends in, including `yes` on a
  build with no key, because the folder it made is the run's product;
  `--send` exits 0 only when a package was sealed and 1 otherwise (`q`,
  no terminal, no key, a failed check), since sending is its only job.
- §6.2 "Paths", over-redaction (decided; the plan named only "well-known
  system directories"): the fixed names the OS, systemd, Docker, snapd
  and LXD give mount points stay readable (`/boot`, `/boot/efi`,
  `/run/lock`, `/run/rpc_pipefs`, `/run/credentials`, `/sys/kernel/debug`,
  Docker's `overlay2/<id>/merged`, `containers/<id>/mounts/secrets`,
  `plugins/<id>/propagated-mount`, `netns/ingress_sbox`, snapd and LXD
  `ns`/`mntns`/`shmounts`). Generated IDs stay pseudonymised (Docker layer
  and container hashes, netns IDs): they are not names but they are
  unique to the host. `/dev/mapper/<vg-lv>` stays pseudonymised as a
  mount source (step 1); the `/dev/mapper/` prefix shows it is a
  device-mapper volume. User-chosen mount points (`/mnt/<name>`) stay
  pseudonymised. Tightened at the same time: a component directly under
  `/home` or `/Users` is masked even when it is a word kept elsewhere
  (`/home/user`, `/home/debug`), except `/Users/Shared`.
- Built bug found in testing: storage.txt read `statvfs` as (total, free)
  and printed more free than total, and the fsync-test skip rule sized
  itself on free space; fixed (bcc8d835).
- B4: built as one collector, `platform` (`host/platform.txt`), for
  what the B2 collectors did not already do: libc kind (glibc, musl or
  static, from each binary's ELF interpreter), Alpine, BusyBox applets
  (B4.1); Rosetta and TCC (B4.2; the rest of B4.2 was already in B2,
  and `log show` matches amfid, sandbox and code-signing lines through
  the node's name rather than by process); the ARM board checks (B4.3);
  WSL (B4.4); Docker Desktop (B4.5). Decisions: the WSL distro name is
  shown only when it is a stock Store name (`Ubuntu-22.04`), otherwise
  as "(a custom name)", because a renamed distro may carry the user's
  name; the SD card's CID serial is never read; WSL is detected from
  `/proc/sys/kernel/osrelease` as well as `/proc/version`. Tested: run
  for real on hp1 and hp2 (glibc, no BusyBox, not WSL, not ARM, Docker
  Engine correctly not taken for Docker Desktop); Pi, WSL, Docker
  Desktop, Alpine and macOS only through fixture tests of each parser,
  as no such host was available (a musl build needs a musl C compiler
  hp3 lacks, and the glibc build does not run under Alpine's gcompat).
  The macOS branch is compiled and linted on Linux (no `cfg` gate) but
  has not run on a Mac.
- Smaller: `irondivi-cli --version` exits 1 with the usage text; the
  first divi-diag commit (d3502999) lacks its `Cargo.lock` entry, so
  `--locked` builds need c83a9dd4 or later; `diag --run` (B3) and the
  `irondivid --diag` alias are not built.

### Revision 15 changes

Each item names the round-14 finding (r15 brief, reviews r14-*) and the
sections that now carry the fix, with its §10 test. Four code changes
landed with this round and are recorded where they apply: bf6452fc,
73440b48, 09cb18e4 and 6de594fb.

- Privacy R14-1 (blocking; the tx relay lines in the debug ring told a
  transaction this node sent from a peer's: a peer's wrote "Received
  tx" and then "Relaying tx", an own one "Relaying tx" alone, or its
  echo's "Received tx" after it, and a restart opened the ring with one
  "Relaying tx" per unconfirmed wallet transaction): done in commits
  09cb18e4 and 6de594fb, which remove every per-transaction line on the
  relay and submit paths. Removed, with their f67b0984 numbers:
  `relay.rs:288` "Received tx {} from peer {}", `:331` "Sent tx {} to
  peer {} (version={}, vin={}, vout={})", `:391` "Relaying tx {} to {}
  peers", `:429` "Retrying tx {} from peer {}" and `:199` "Queuing {}
  new transactions to request from peer {}" (6de594fb); `node.rs:1349`
  (then; it is now the `TransactionAccepted` send) and `:1990` "Added relayed tx {} to mempool", `:1786` "Accepted
  transaction {} to mempool" and `:2062` "accepted orphan tx {}";
  `main.rs:2345` "Transaction {} submitted to mempool and announced to
  peers"; `divi-rpc wallet.rs:2476` "Broadcasted transaction {}" and
  `:3746` "Sent {} outputs (txid: {})". A11 gains "Own transactions log
  like peer transactions": the general rule (no line, copy, count or
  ordering may differ between a transaction this node created or
  resubmitted and a peer's, whether by a line on one side only, a pair
  of lines in another order or a per-peer count), the scan roots with
  file and line, and a class for every remaining line on those paths:
  written alike for both (with the reason), failure-only per day with
  the txid masked, or counted. `mempool.rs:441` "Added tx {} to
  mempool" is counted, not kept in place (the restart burst and the RPC
  lines beside an own send, below). The new failure line
  `main.rs:1719` "Unconfirmed wallet tx {} cannot be resubmitted ({});
  forgetting it" replaces `main.rs:2345` as rule (b)'s crate-root edit
  site, and the four own-only info lines left in `divi-rpc wallet.rs`
  (`divi-rpc wallet.rs:1929`, `divi-rpc wallet.rs:3174`, `divi-rpc wallet.rs:3566`, `divi-rpc wallet.rs:4170`) are counted. The §10 item 6 scan
  starts from the new roots; the §10 item 5 canary becomes the R14-1
  canary: `sendtoaddress`, `sendrawtransaction`, `sendmany`, a receive
  and a restart that resubmits, on regtest with at least 3 peers, at the
  default level, `-debug` and `-debug=net`, through a capture layer,
  asserting that no format, count or order of lines differs between the
  own transactions and a peer's.
- Privacy R14 NB3: "Resubmitted {} unconfirmed wallet transaction(s) to
  the mempool" (`main.rs:1727`) and "Restored {} unconfirmed wallet
  transaction(s)" (`wallet_db.rs:555`) stay in place as count-only lines,
  written once per start; with the relay lines gone they have nothing to
  pair with (A11 "Own transactions log like peer transactions").
- Privacy R14 NB1, consensus N-j and platforms R14-2 (the wallet line
  `wallet_db.rs:3098` was still "a code change still to make"): done in
  commit bf6452fc, which removes "Mempool wallet tx {} {} {} sats ({})";
  the comment now at `:3098` says why. Every "code change still to make"
  for it (the Revision 14 list, A11 "Wallet lines on the mempool
  listeners", the §10 item 5 canary) records the removal, the failure
  lines are cited at 6de594fb (`:3119`, `:3142`, `:3163`, `:3166`,
  `:3182`), and the §10 item 6 scan treats the site as removed, not as
  counted.
- Adversarial r14 notes 1 and 2 (the info "Header sync complete" was
  written about once per peer block near the tip; a node that reached
  the tip through `handle_headers` or `start()` kept the catch-up flag
  and wrote one stray "Block sync complete" later): done in commit
  73440b48. `enter_synced()` (`sync.rs:1596`) is now the only way into
  Synced and clears `fell_behind` (`:1603`); it is called at `:563`,
  `:714`, `:985` and `:1363`. "Header sync complete" is info (`:986`)
  only after a real catch-up and debug (`:988`) otherwise; the unit test
  `short_lag_does_not_rearm_sync_complete` (`:2544`) also checks that an
  empty headers reply after a far lag enters Synced and clears the flag.
  A11 item 6: the info line is a fifth sync-state line kept in place,
  the debug line replaces the old `:984` on the counted list, the site
  count is 88; item 8 and the §10 item 5 gate name all five.
- Adversarial r14 note 3 (the unit test checks state, not logging): the
  §10 item 5 sync-state gate reads the lines through a tracing capture
  layer as well as from `debug.log`, and the A11 unit test is extended
  with a capture layer that asserts no sync-state line is written on the
  short-lag paths.
- Adversarial r14 note 4 and privacy R14 NB2 (`sync.rs:546` "restarting
  sync" is not under the lag gate): it stays in place with the handshake
  lines, is named as the one exception to the §10 item 5 sync-state
  gate, and stays classified in the §10 item 6 scan (A11 item 6).
- Adversarial r14 note 5 (`sync.rs:1822` "Block download state but no
  work" can follow a near-tip flap): it is in the daily failure-only
  bucket, which A11 item 6 now says next to it.
- Consensus N-i (the A12 stall record and the stall incident did not say
  what a stall is): both are measured on the sync stall counter or the
  tip age at any lag, never on the `far_behind` gate, with the lag in the
  record (A12, A11 item 7); §10 adds a peer that claims a tip 3 blocks
  ahead and never serves the blocks.
- Platforms R14-1 (a VM or WSL2 guest is paused while its host sleeps, so
  its boot clock stops): an hour whose wall span is over about 1 h 5 min
  is flagged `stretched` and still filed by its end time; containers
  without a time namespace share the host's boot ID and boot clock, which
  is expected (A11 "Count clock", §10 S1).
- Crashes R14-1 (the unwind still drops `async_main`'s state): A4 names
  the case, an early panic whose unwind runs the RocksDB close, slow but
  bounded, and states the choice not to `_exit` from the hook; §10 S1
  times that exit.

### Revision 14 changes

Each item names the round-13 finding (r14 brief, reviews r13-*) and the
sections that now carry the fix, with its §10 test. Three code changes
landed with this round and are recorded where they apply.

- Adversarial AC1 (the sync-state lines could be re-armed by a short
  lag and so mark peer blocks): done in commit 8e4bfaca. `sync.rs` gains
  `CAUGHT_UP_LAG` (6, `:78`) and a `fell_behind` flag (`:392`); "Block
  sync complete" (`:1364`) is written only on entering Synced after
  being more than 6 blocks behind, "Exiting IBD mode" (`:1368`) once per
  process, "Sync progress" (`:1628`) and the warn "Sync stalled"
  (`:1645`) only while more than 6 behind; within the lag "Sync stalled"
  is debug (`:1650`). Unit test `short_lag_does_not_rearm_sync_complete`
  (`:2544`). A11 item 6 "Kept in place" and item 8 now state the gate,
  the short-lag cases (`handle_inv`, a short headers reply, a new peer's
  start height) and the test, and say these lines are not counted
  because they fire only on a real catch-up, a public event; the new
  debug "Sync stalled" goes on the counted list (item 6 is now 87 sites);
  §10 item 5 makes "no sync-state line within the lag window" a release
  gate at the default level, `-debug` and `-debug=net`; the §10 item 6
  scan treats a new log site on these paths as unlisted until classified.
- Consensus N-g (a re-arm would go unseen): the package carries a weekly
  tally of the four sync-state lines next to the lines themselves (A11
  item 6), so a re-arm shows as a count near the number of blocks.
- Privacy R13-1 (the mempool added listener wrote "Wallet sees
  unconfirmed tx {txid}" next to the relay lines): done in commit
  f67b0984, which removes that line (`main.rs:1926`-`:1930`); the
  start-up line "Wallet picked up {} unconfirmed tx(s) already in the
  mempool" (`main.rs:1952`) stays. §6.2 rule (b)'s edit-site list now
  includes every log site inside a mempool, block or wallet listener
  closure, and A11 lists what the mempool listeners reach; the §10 item
  6 scan adds the added listener (`main.rs:1926`, `zmq.rs:428`), the
  removed listener (`main.rs:1933`) and the ZMQ block listener
  (`zmq.rs:434`) as roots. Walking the added listener finds
  `wallet_db.rs:3098` "Mempool wallet tx {} {} {} sats ({})" at info
  (as of f67b0984), still written per wallet transaction with its txid;
  r14 put it on the A11 counted list, and commit bf6452fc has since
  removed it (Revision 15). §10 item 5 adds a txid
  linkage canary over a regtest wallet send and receive.
- Crashes R13-1 (a main-task panic waited on the runtime's drop): done in
  commit 70cb5785. `main()` runs `block_on` inside `catch_unwind`
  (`main.rs:3194`-`:3196`); on a panic it forgets the runtime, writes
  "Error: the node's main task panicked", calls `flush_log()` and
  `_exit(101)` (`:3203`). "The main thread", the exit-code table and A4
  say so; std's clean-up no longer runs on that path.
- Crashes R13-2 (counter copies could be counted twice): A11 "Counts
  since the last hourly line" now says the package uses, per run, only
  the latest copy taken after that run's last hourly line, which
  replaces that run's pending counts and is dropped when a later hourly
  line exists; it names the double-count cases. §10 S1 test adds an A17
  incident followed by a normal hour, and a critical-task panic.
- Crashes R13-3: A8 drops counted lines from the ring with a per-layer
  filter only (`Layer::with_filter`), never a global `Interest::never()`;
  §10 item 6 asserts a tagged site still reaches `debug.log` and not the
  ring.
- Consensus N-f (the `counted` field in `debug.log`): the `debug.log`
  formatter strips the field, so lines read as today; the §10 item 6
  fixtures assert no `counted=` token in `debug.log`.
- Platforms R13-1: A11 "Count clock" drives the hourly timer from the
  boot clock (a `timerfd` on `CLOCK_BOOTTIME`, or a 60 s tick that reads
  it; `mach_continuous_time` on macOS), never a tokio `interval`, which
  stops during suspend; §10 S1 adds a suspend across an hour boundary.
- Platforms R13-2: count lines written before clock sync with no synced
  line after them in the same boot go to an `unplaced` bucket; each
  count line carries the boot ID.
- Platforms R13-3: A11 "Count clock" names the clock-synced flag sources
  in containers (read-only `adjtimex`, `unknown` when refused) and on
  macOS (`unknown` until shown to work).
- Adversarial AC2: A12's reorg records in the package get the same
  hour-truncated time as the tip record while (e) is on.
- Adversarial AC3, privacy N3: §8.3's summary tells the user that a
  `debug.log` or `crash.log` sent by hand, outside the package, is not
  filtered.
- Privacy N1: covered by the AC1 release gate.
- Citations: all re-based to f67b0984 (header). One found stale in the
  full pass and fixed: the D-table log-rotation row cited the exit-error
  lines of `exit_after_stop` as "log config"; it now cites the
  `debug.log` writer in `init_logging` (`main.rs:1290`-`:1295`).

Decisions where the brief left a choice:

- N-f: the formatter strips the field (the matcher is not widened), so
  `debug.log` stays byte-compatible with older nodes' logs and the
  §6.2 matchers need no change.
- The four sync-state lines stay in place and are not counted; the N-g
  weekly tally is in addition, not in place of them.
- A12's reorg record time is truncated to the hour rather than argued
  public: an own stake orphaned by a reorg has its depth and old tip in
  the record, and its time to the second would date the stake.
- The `wallet_db.rs:3098` line was classified on the counted list in the
  plan; commit bf6452fc has since removed it (Revision 15).

### Revision 13 changes

Each item names the round-12 finding (r13 brief, reviews r12-*) and the
sections that now carry the fix, with its §10 test.

- Consensus C1, B4, adversarial AB1 (log copies escaped rules (b) and
  (e) on a current node): §6.2 "Old-log lines" now runs one filter over
  every run's inputs and lists them all, the debug-ring sections of
  `crash.log`, the incidents and `getdiaginfo`, the incident `debug.log`
  tails and the A14 mirrors included; a new copy joins the list or is
  not packaged; A11 item 7, A11 "Logs written before A11" and the
  `-logwalletdetail` paragraph say the same; A8 keeps counted lines out
  of the ring with a static `counted` field; §6.3 treats a hit in any
  copy as a filter miss and a release-test failure; §10 item 5 O1
  differential check (5) takes an incident, a `getdiaginfo` and a crash
  record inside the ring window and runs checks (1) to (4) on them.
- Privacy R12-1, consensus P1 ("Block sync complete" per peer block at
  the default level, and its family): A11 facts record the old line;
  A11 item 6 now classifies all 86 log sites of `sync.rs` (re-grepped at
  1fd59a5c) into counted, failure-only, public-record and kept groups,
  following `handle_block` into `try_connect_blocks` and
  `request_headers`; new A11 item 8 records the transition-only fix,
  done in commit 1fd59a5c, and what is to measure in §10; §6.2 (e)
  removes the line from logs of older nodes; the O1 differential also
  runs at the default level.
- Platforms R12-1, consensus T1 (timing gate measured without network
  delay): A11 item 7 now says where the gap is measured (a mainnet node,
  a staking testnet node with off-LAN peers, or hp1–hp3 with `tc
  netem`), refuses loopback and LAN-only runs, states that the gate will
  probably fail and that rule (e) then stays as the shipped design, and
  lists what still diagnoses a node; §6.2 (e) and §10 item 5 (new T1
  test; regtest samples never count) match.
- Consensus N-d (lists read as complete): A11 item 6 and the §10 item 6
  scan say the lists are not proof of completeness; the scan is the gate
  and the O1 differential a backstop.
- Consensus N-e: §8.3's summary line points to `chain-events.log`.
- Adversarial AB2: B6.5 and §6.2 "Public records" say rule (e)
  collapses the Connected line by default.
- Adversarial AB3: A12's tip-per-100 record keeps height and hash with
  its time truncated to the hour, in the package, while (e) is on.
- Crashes R12-1 (counts lost on `die()`, panic, third TERM): A9, A4 and
  the A3 third-TERM record copy the counters; A11 S1 now reads "lost
  only on SIGKILL and power loss"; §10 S1 test covers each path.
- Crashes R12-2: "Main thread exits" adds a panic in `async_main` (exit
  101).
- Crashes R12-3: AA3 reason code is `difficulty:<variant>`.
- Platforms R12-2: A11 "Count clock" times the hour on `CLOCK_BOOTTIME`
  (`mach_continuous_time` on macOS), and each count line carries its
  start and end wall times and a clock-synced flag; §10 S1 test steps the
  clock.
- Platforms R12-3: a week without a clean-exit record is `partial`;
  counters are `AtomicU32`, lock-free on every target.
- Privacy R12-2 (`run_notify` writes the command and txid): new A11
  "Notify commands" paragraph masks the line to its kind and counts it;
  the §10 item 6 scan walks every stored listener registration and fails
  on a new kind; §10 item 5 adds a notify canary test.
- Hourly count lines no longer say "such as the variant name"; the
  error kind is the AA3 reason code.
- `crates/divi-rpc/src/wallet.rs:796` is failure-only: it stays in
  place, masked by (b), and (e) no longer removes it.

Deviations, with reasons:
- The `counted` tag at the source is added in addition to the package
  filter, not instead of it: the tag keeps lines out of copies the user
  sends by hand, the filter catches a site that misses the tag.
- AB3 is fixed by truncating the time to the hour in the package, not
  by dropping the record, since the tip record is part of what still
  diagnoses a node under (e).
- `run_notify` keeps a kind-only line in `debug.log` rather than
  becoming a node-counted site without a line, since a failing notify
  command must stay visible to the user.
- "Block sync complete", "Exiting IBD mode", "Sync progress" and "Sync
  stalled" stay in place pending the §10 measurement of whether a peer
  block can re-arm them; if it can, they move to the counted list.
  (Answered in r14: 8e4bfaca gates them on a lag of more than
  `CAUGHT_UP_LAG`; see the Revision 14 list.)
- Citations are re-based on 1fd59a5c (`sync.rs` at or after 1343 moved
  by 10), in the older change lists too.

### Revision 12 changes

Each item names the round-11 finding (r12 brief, reviews r11-*) and the
sections that now carry the fix, with its §10 test. Line numbers are the
line a log macro starts on, as of the 2026-10-30 tree; r11 mixed this
(`sync.rs:1235` for a macro that starts at `:1234`), and r12 uses the
start line throughout.

- Consensus B3 (per-block-event lines missing from the counted list):
  A11 "Own blocks log like peer blocks" item 6 now lists every per-block
  site in `sync.rs`, `node.rs` (getdata serving, getblocks response, the
  per-message line), `peer_manager.rs`, `relay.rs:312`, `codec.rs` and
  `connection.rs` (per command), `chain.rs` and `block_import.rs`, with
  the sites checked and found not per block (`zmq.rs`, `divi-electrum`);
  §6.2 "Old-log lines" (e) removes every format on that list; §10 item 5
  O1 differential compares counts per format with at least 3 peers; the
  §10 item 6 log source scan covers every per-block-event site, with or
  without a hash. `block_import.rs:213` calls the shared Connected
  function (A11 item 1).
- Adversarial AA1 and privacy R11-1 (wallet lines written while a block
  is connected): new A11 paragraph "Wallet lines on the connect path"
  traces `main.rs:1893` and `:2153` through `sync_wallet_to_tip` to
  `scan_block` and lists its sites (`wallet_db.rs:2835` "Received" among
  them) and the mempool sites `mempool.rs:581`, `:627`, `:736`; they are
  counted, the node writes hourly counts, and the package carries weekly
  buckets for logs with and without the change; §6.2 rule (b) no longer
  keeps them in place, even masked; the §10 item 6 scan follows the call
  graph from `scan_block` and the callbacks, with no module exempt; §10
  item 5 O1 check (4) runs wallet payment and spend blocks at `-debug`.
- Privacy R11-1, timing fallback: A11 item 7 and §6.2 (e) state that rule
  (e) applies to every log by default until the timing measurement
  passes, the threshold, and who decides.
- Consensus N-a, N-b: failure-only staker and sync lines get daily
  buckets; "Received block" is also bucketed weekly per peer pseudonym
  (§6.2 (e)).
- Consensus N-c: the item-7 timing measurement is a release gate (A11
  item 7, §10 item 5).
- Adversarial AA3 (free-text staking errors): A11 "Staking error kinds"
  makes `StakeResult::Error` a closed reason code, counted per code, with
  `events.log` transitions under the A12 "not staking because" rule;
  §10 item 5 test.
- Crashes S1 (counts lost at stop or crash): A11 staker paragraph,
  A5 item 5, A17 incident; §10 item 5 test.
- Crashes, early returns from `main()`: A5 "The main thread" says the
  node installs its stack over std's and does not unmap std's region.
- Crashes, musl: A5 musl bullet states the allocation-failure and
  real-call-error rules for the `--wrap` path.
- Platforms R11-1 (macOS thread exits between range read and suspend):
  A17 checks the SP against the range after `thread_suspend` and records
  a failed suspend `no stack: thread exited`; §10 item 5 test.
- Platforms R11-2 (`libdl.so.2` on glibc 2.31 builds): §10 item 6
  compares NEEDED against a baseline taken without the interposer.
- Platforms R11-3 (clock jumps on a Pi): §10 item 5 records clock sync
  state and drops samples before the first sync.
- Pointer fix: the Revision 11 item for adversarial N1 now points to §10
  item 1, where B5's budget measurement is.

Deviations from the brief:

- `wallet_db.rs:1364` "Wallet incremental save complete" is added to the
  counted list. No review named it: `save_incremental` (`:1254`) writes it
  only when the wallet is dirty, and the callbacks call it after every
  block (`main.rs:1906`, `:2024`, `:2166`, `:2808`), so it marks blocks
  that touched the wallet.
- `peer_manager.rs:1068` and `:1085` "Failed to send block inv to peer"
  move from "stay" (r11 item 5) to the counted list: the own broadcast
  always runs and the relay only sometimes, so their rate marks own
  blocks.
- Per-message lines (`node.rs:898`, `codec.rs`, `connection.rs`) are
  counted per command rather than per format, so block traffic is one
  bucket and the rest another.

### Revision 11 changes

Each item names the round-10 finding (r11 brief, reviews r10-*) and the
sections that now carry the fix, with its §6.3 canary or §10 test. Where
the fix differs from the brief's wording, the item says so under
"Deviation".

- O1 (consensus B2, privacy P1, adversarial Z1/Z2) (the node logs its own
  staked block differently from a peer's block, so the log names it): r10
  rested on `node.rs:1551` "Accepted block", which is never written in
  production (`Node::accept_block`, `node.rs:1515`, is called only from
  `crates/divi-node/tests/mempool_reorg.rs:248`). A11 "Own blocks log like
  peer blocks" — one shared "Connected block {} at height {}" function on
  every accept path, own included, with an explicit `divi_network::sync`
  target; one shared failure line; `staker.rs:797`, `:812`, `:828` and
  `main.rs:2167`, `:2173` go; the per-block broadcast and relay lines
  (`peer_manager.rs:1071`, `:1091`) are dropped; the peer-only lines go on
  a counted list. A11 "Staker default-deny" — every `staker.rs` log site
  listed, each on an allowlist or counted, the own-UTXO lines
  (`staker.rs:1475`, `:1488`, `:1509`, `:1520`) added to the A11 edit
  sites. §6.2 "Public records" no longer cites `node.rs:1551`; §6.2
  "Old-log lines" (e) collapses per-block lines of older logs; §8.3 item
  1 says so; §6.3 scanner; B6.5; Revision 10 canaries (first one
  replaced); §10 item 5 O1 differential tests; §10 item 6 log source
  scan (privacy P2). Deviations: (1) the package carries the counts as
  weekly buckets (0, 1–3, 4–20, >20), not hourly: an hourly count of a
  peer-only line ("Received block … from peer") beside the clear
  per-block Connected lines would show, hour by hour, one connected block
  no peer sent. The node itself writes hourly count lines, zeros
  included. (2) The broadcast lines are dropped rather than unified:
  even in one format the relay's peer count is one lower and the relay
  is conditional (`sync.rs:1269-1279`), so the own broadcast would still
  stand out. (3) The peer-only lines stay per block in the node's own
  `debug.log` and are kept out of the package; the format-set test is
  therefore defined over the package, since a line such as `sync.rs:1240`
  cannot be written for a block no peer sent. (4) Brief line numbers
  corrected after grepping: 1501 is `staker.rs:1509`, "797/802" is `:797`,
  "828/829" is `:828`; sites the brief did not list are added (`:847`,
  `:856`, `:1114`, `:1122`, `:1372`, `:1857`, `:1910`, `:2171`), and so
  are `main.rs:2167`/`:2173` (own-only callback lines) and the `sync.rs`
  accept at `:1486`, which writes no Connected line today. (5) A timing
  check is added (A11 "Timing"): the gap between a block's header time and
  its Connected line may separate own blocks from peer blocks; it is to
  measure in §10.
- R10-1 (platforms) (macOS sends no signal, so alternate stacks do not
  limit its stacks): A17 — "only threads with an alternate stack are
  signalled" is the Linux signal path's rule; on macOS the walk covers
  every `task_threads` thread but the watchdog and the helper, with stack
  bounds from `pthread_from_mach_thread_np` and
  `pthread_get_stackaddr_np`/`pthread_get_stacksize_np`, falling back to
  `mach_vm_region` around SP, else `no stack: no stack range`. A5 drops
  "Expected on macOS: every C++ thread"; there the alternate stack matters
  only for the A5 overflow record. §10 item 5 requires a stack for every
  `rocksdb:*` thread on macOS; the foreign-thread overflow test still
  expects no A5 record on macOS.
- Crashes N1 (the main thread keeps std's small alternate stack, and
  start-up runs on it): A5 "The main thread" — `main()` (`main.rs:3020`)
  runs start-up through `runtime.block_on(async_main(...))` at
  `main.rs:3195`; the first statement of `main()` installs the node's own
  64 KB stack on every Linux family; not applicable on macOS. It is never
  freed, since `exit_after_stop` (`main.rs:3216`) ends in `libc::_exit`
  (`main.rs:3234`). §10 item 5 headroom and K4 spin tests extended to the
  main thread. Deviation: std's main-thread stack size (about 8 KB on
  x86_64, 16 KB on aarch64) is the reviewers' reading of std, not checked
  here (rust-src is not installed), so it is marked to verify in §10.
- R10-2 (platforms), crashes N2 (interposer robustness): A5 gnu bullet —
  the real `pthread_create` is resolved lazily and thread-safely on first
  use (the `main()` call stays as a warm-up); null or our own symbol from
  `dlsym` aborts with a fixed `write(2)` message and no allocation; a
  failed stack allocation still creates the thread, recorded `no stack:
  alloc failed`; a failed real call frees the stack and argument block and
  returns its error. §10 item 5 checks the symbol version on i686 and in
  ubuntu:20.04 (libpthread, glibc 2.31).
- R10-3 (platforms) (`--export-dynamic-symbol` needs binutils 2.35):
  A5 names `--dynamic-list` (a file holding `{ pthread_create; };`) for
  every gnu target; the builds run in ubuntu:20.04
  (`.github/scripts/build-linux-gnu.sh:2`), binutils 2.34 by the
  reviewers' count; §10 item 6 records `ld --version` to confirm.
- Crashes N3 (how the interposer and std interact): A5 gnu bullet — std's
  per-thread handler finds the installed stack and installs none (the
  reviewers' reading of std, to verify); the §10 headroom test names a
  std thread, so a std change is caught.
- Consensus N4 (an undecided block's coinstake txid got a wallet
  pseudonym): B6.5 "Own staked blocks" — the coinstake txid of a block
  reduced as undecided is pseudonymised under the public-record salt;
  only a block decided own uses the own-txid pseudonym; Revision 11
  canaries.
- Consensus N5 (the Y2 budget is an estimate): kept as written; B6.5 and
  §10 item 5 Y2 already mark it to measure.
- Privacy P3 (P2PK stake scripts left undecided): B6.5 — P2PK is decoded
  by HASH160 of the pubkey, as `crates/divi-rpc/src/wallet.rs:265-272`
  does (`divi_crypto::hash160` at 268); Revision 11 canaries.
- Privacy P4 (the prevout fetch depends on `-txindex` and the wallet):
  §10 item 5 Y1 runs it with and without `-txindex` and with the
  transaction in and out of the wallet.
- Adversarial N1 (no prefix-tag fallback, so B5 must come first): §10
  item 1 — B5's budget measurement, taken before A10 (a) is built (a miss
  blocks A10 (a)), though Part A otherwise precedes Part B.

### Revision 10 changes

Each item names the round-9 finding (r10 brief, reviews r9-*) and the
sections that now carry the fix, with its §6.3 canary or §10 test. Where
the fix differs from the brief's wording, the item says so under
"Deviation".

- B1 (consensus), Y3 (adversarial) (an own staked hash masked in chain log
  lines marks it): B6.5 "Own staked blocks" — outside wallet-context lines
  an own staked hash is a public block hash and printed in clear; §6.2
  "Public records" adds the block hashes of the non-wallet chain, sync,
  node and net log lines (`node.rs:1551`, `sync.rs:1322`, `:1446`,
  `:2393`), where step 1's own-hash replacement does not run; §6.2
  "Old-log lines" (b) removes the staker lines that announce an own stake
  from their place and puts weekly bucketed counts in the package instead;
  §6.3 scanner; Revision 10 canaries; §10 item 5. `previousblockhash` and
  `nextblockhash` stay dropped from every block answer. Deviation: the
  brief did not move the staker lines. A masked staker line keeps its
  timestamp and its place in the file, and beside the clear "Accepted
  block" line either one pairs the two and names the own block, so these
  lines are removed rather than masked. The real format strings are
  `staker.rs:722-724` "Staked block {} at height {} (reward: {})" and
  `staker.rs:812-814` "Self-accepted staked block {} at height {}".
- N1 (privacy) (r9's tag was invertible): A10 — the tag is now
  SipHash-2-4, keyed with k2 = `HMAC(k, "tag")`, over the 8 bytes of an
  internal 61-bit rolling hash R_b of the whole value, truncated to 16
  bits; R_b is never sent or written. r9 sent R_b's own bits, which are
  linear in the value with a base the caller knows. The prefix-tag
  fallback is removed: missing B5's bound is a blocker for A10 (a), to be
  revisited in its own revision. The limits that went only with that
  fallback (the leak stated in the consent text, `known_values` answered
  at most once per diag run and once a minute) go with it. §10 items 1
  and 5 (R2, N1).
- R9-1 (platforms) (`--wrap` never reached RocksDB's threads): A5
  "Alternate stacks" rewritten per target family. On the 7 gnu targets
  the executable interposes `pthread_create` (exported with
  `--export-dynamic-symbol`, or `--dynamic-list`), forwards through
  `dlsym(RTLD_NEXT)` resolved in `main()`, and installs a stack only when
  none is present. musl keeps `--wrap`. On macOS no C++ thread has one.
  The stack is freed on return and, through a `pthread_key_create`
  destructor, on `pthread_exit` (crashes note 2). The 64 KB headroom is
  stated and measured with a guard pattern (crashes note 3). A17 updated;
  §10 item 5 (F3/P5 test, R9-1, `pthread_exit` and headroom tests); §10
  item 6 (`nm -D`, `readelf -d`). Deviation: on musl, `--wrap` stays,
  because a static binary has no `dlsym(RTLD_NEXT)`; which of the two
  export flags each gnu target uses is to confirm in §10 item 6.
- R9-2 (platforms) (threads still without a stack): A5 "Threads with no
  alternate stack" and A17 — such a thread is recorded by `comm` as `no
  stack: no alternate stack`, marked expected (gnu: glibc's internal
  helper threads and raw `clone` threads; macOS: `rocksdb:*`) or
  unexpected, as a hint only, since a helper inherits its starter's name.
- Y1 (adversarial), N2 (consensus) (coinstake ownership read from any
  payee): B6.5 "Own staked blocks" — ownership is decided from the staked
  input only, the script of the output the coinstake's first input
  spends, fetched with one `getrawtransaction <prevout txid> 1`;
  masternode, treasury and lottery payees are ignored; P2PKH, P2SH and
  vault scripts are decoded, and either vault hash in the own set means
  own. A10 `known_values` and §6.2 step 1 gain both hashes of every vault
  script the wallet owns or manages. §10 item 5 (Y1). Deviation: the code
  names the two vault hashes owner and vault (`wallet.rs:294-297`), not
  owner and manager; that `getrawtransaction` answers for a spent output
  is an assumption, tested in §10 item 5.
- Y2 (adversarial) (undecided ownership let through): B6.5 "Undecided is
  reduced" — a stopped, failed or timed-out fetch, a partial or unknown
  set, or a failed decode reduces the block; a stop-rule cut reduces every
  lookup; the lookups have their own budget (10 s each, 60 s a run, to
  measure in §10 item 5) under the 512 MB rule; a no-wallet node reduces
  nothing; the screen note; §6.2 step 1 warning. §10 item 5 (Y2).
  Deviation: the budget values are estimates, to measure.
- Y4 (adversarial) (a clear neighbour gives the height): B6.5
  "Consecutive heights" — one reduced lookup in a run of consecutive
  heights reduces the whole run; "The call itself" covers undecided blocks
  and reduced runs. §10 item 5 (Y4). Deviation: the whole run gets the
  full reduction (version, size class and nTx), because a clear hash names
  its height through any explorer; always dropping the height argument
  alone was not taken.
- Y5 (adversarial): B6.5 "When every lookup is reduced" — the summary
  points to `getmasternodewinners`, the A13 and A11 lines and B6.3 `diag
  --tx <txid>`. §10 item 5 (Y5).
- Y6 (adversarial) (`dump*` uncapped): A15 — `dump*` joins `import*` and
  `*passphrase*` in the 100-an-hour cap and the total cap, and leaves the
  uncapped list; A14 updated; the reserved file evicts per method without
  a rewrite on every append. §10 item 5 W3 (10,000 `dumpprivkey` calls).
- N2 (privacy) (`gettxoutsetinfo` has eight keys): B6.6 shapes, the
  shape match, the public-answer rule and the C1 canary now name all
  eight (`blockchain.rs:825-845`).
- N3 (privacy): §7.1 "Fork, wrong chain, reorgs" says how a fork is
  traced with the neighbour hashes dropped, and what a pre-A10 or pre-A13
  node lacks.
- N4 (privacy): B6.6 key-name rule — the `stake` token over-protects, and
  that is accepted; it buckets numbers only.
- D5 update (856f7376): D5 row, A5 "Non-dumpable process", A6 — the
  re-check now runs on its own `dumpable-check` std thread, started in
  `main()` after the daemon forks and before the tokio runtime (so before
  the wallet), every 60 s, with its `warn!`, `error!` and console lines.
  Its unit test was updated in 856f7376; only the f5f3bce5 version is
  reported passing on hp3. Still open: A6 sets its interval and its line
  goes to `events.log`. Deviation: the check stays on the `dumpable-check`
  thread when A6 drives it, so a stalled runtime cannot stop it.

### Revision 9 changes

Each item names the round-8 finding (r9 brief) and the sections that now
carry the fix. Every fix has its §6.3 canary or §10 test, named in the
item. Where the fix differs from the brief's wording, the item says so
under "Deviation".

- E1 (a send undone by a reorg reads as unconfirmed): B6.5 timing
  classes — the confirmation buckets gain a fifth class, `-1` (not in the
  chain or the mempool, `depth()` in `wallet_history.rs:198-221`), never
  folded into 0; §6.3 canary (a `-1` entry); §10 item 5.
- E2 (transactions inside an attached public block lose their times):
  B6.6 "No label lowers protection" now states it as a decision: each
  transaction entry of an attached `getblock` at verbosity 2 is
  wallet-shaped, the block-level header fields survive; §10 item 5.
- F1 (a spinning start-up ends in SIGKILL with no stack): B3.2 "A stack
  before any signal" (snapshot request and a 5 s wait before SIGTERM to a
  node not yet `running`, and again before SIGKILL; SIGQUIT when the
  request cannot be written); A1 spin bound becomes min(15 min,
  `-startuptimeout`), still only a record; §10 item 5 K4 and the new F1
  test.
- F2 (a late handler can write into a reused buffer): A17 per-thread
  slots (WAITING, WRITING, DONE, ABANDONED) from a small ring, claimed by
  compare-and-swap on the sweep number, `no stack: torn`; §10 item 5 K1.
- F3, P5 (signal flags and number, EINTR, C-created threads, a hung
  macOS walk): A17 "The stack signal" (`SIGRTMIN()+k` read at run time,
  `SA_SIGINFO | SA_ONSTACK | SA_RESTART`, `tgkill` to own tids only, the
  EINTR calls listed); A5 "Alternate stacks" (`-Wl,--wrap=pthread_create`
  for statically linked C/C++ threads); A17 macOS helper thread; §10
  item 1 soak, §10 item 5 tests. Deviation (P5): a thread the wrap does
  not reach is not signalled (`no stack: no alternate stack`), and the
  handler also checks it is on its alternate stack.
- P1 (which `/` mount line; a plain chroot): B2 "Node in a container"
  signal (4) takes the last `/` line, and no `/` line counts as `root
  differs`; §10 item 5 N2.
- P2 (B2.16 skipped when only the root differs): B2 "Node in a
  container"; §10 item 5 N2.
- P3 (escaped scope names, libvirt-LXC, a uid with no name): B2 "Node in
  a container" hints; §10 item 5 N5.
- P4 (`docker events` times dropped): B6.6 known formats; §10 item 5.
- S1, X2 (a mislabelled or unknown-shape wallet answer with no `txid`
  goes out exact): B6.6 "A label must match the shape"; the key-name rule
  runs in every attached file and matches amount keys by token;
  `txcount` bucketed; stake weights as a ratio; §6.3 canaries (both
  reviews' examples); §10 item 5.
- S2, X1 (own staked blocks unmasked on pre-A10 and LAN-only nodes):
  B6.5 "Own staked blocks" decides ownership from the block's coinstake,
  or reduces every block lookup when the own addresses are unknown; §6.2
  step 1 warning names it; §6.3 canary; §10 item 5.
- S3 (the 8-byte prefix tag lets a caller test guesses): A10 (a) tag over
  the whole value (a rolling hash), the false "add nothing" sentence
  corrected; §10 item 1 measures it. Deviation: none in substance; the
  brief's rolling tag is the plan, and its fallback (the prefix tag with
  the leak stated and `known_values` rate-limited) is written down for
  the case where §10 item 1 fails B5's bound.
- S4 (unpadded base64; neighbour block hashes): A10 decoded views take
  base64 and base64url runs at any length and padding; B6.5 drops
  `previousblockhash` and `nextblockhash` from every block answer; §6.3
  canaries. Deviation: the brief asks to mask an own hash in those two
  fields; they are dropped from every block instead, because dropping them
  only where they point at an own block would itself mark the neighbour.
- X3 (a flood of capped calls rolls `stop` out): A15 total cap (200
  capped lines an hour in all) and the reserved file
  `rpc-methods-reserved.log`; A14 arithmetic redone and budget now about
  75 MB; §10 item 5 X3. Deviation: the reserved file is 1 MB, and when it
  is full it drops the oldest line of the method with the most lines, so
  a `backupwallet` loop cannot push out `stop` either.
- D5 (coordinator's note, not a review finding): the credential-call lint
  is done in 97c4bceb; the §0 D5 row, A5 "Non-dumpable process" and §10
  items 5 and 6 now describe it as it is. The per-tick
  `PR_GET_DUMPABLE` re-check is done in f5f3bce5 as a 60 s tick of its
  own (`private_files::restore_non_dumpable`, unit test
  `node10_reset_dumpable_flag_is_restored`); it writes a tracing `warn!`
  until A6 exists, then moves into the A6 tick and `events.log`.

### Revision 8 changes

Each item names the round-7 finding (r8 brief) and the sections that now
carry the fix. Where the fix differs from the brief's wording, the item
says so under "Deviation".

- D1, R3, K5, W1 (merged: an attached wallet answer that no shape or a
  wrong label lets through in clear): B6.6 "Attached RPC answers" (new
  shapes for `listunspent`, `listtransactions`, `listsinceblock`,
  `gettransaction`, `getwalletinfo`; "No label lowers protection", the
  per-object wallet rule; the key-name rule inside unknown JSON), B6.5
  `listunspent` refusal and §7.2 L10 (the full `--attach-method` command
  line), §6.3 canaries, §10 item 5. Deviation (W1): inside unknown JSON,
  `height`, `blockheight`, `time`, `blocktime` and `timereceived` are
  dropped, not bucketed. B6.5 already drops wallet heights and times and
  has no bucket for them; one rule for both keeps the two paths the same.
- R1 (own staked block still locatable): B6.5 "Own staked blocks" (only
  `version`, a size class and `nTx` kept; every other field, the
  `getblockhash` answer and the block's other txids dropped or
  pseudonymised), B6.5 "The call itself", B6.6, §6.3 (a canary per
  field), §8.2, §10 item 5. This replaces r7's wallet-side pseudonym for
  the hash: the hash is now dropped.
- R2, W6 (secret matching misses glued and encoded secrets): A10 (a)
  (every byte offset with a 16-bit tag pre-filter, then HMAC-SHA256;
  base64, percent, JSON and shell-unescaped views; the limit restated as
  silent), §6.3 (match restated, one canary per form), §8.2, §10 items 1
  and 5. Deviation: the brief asked for every offset only inside runs of
  letters and digits longer than the secret; r8 checks every byte
  offset, which is a superset, and keeps the cost down with the tag
  (cost to measure in §10). The hash stays HMAC-SHA256 under the per-call
  key, which is keyed and not reversible as the brief asks.
- N1 (blocking; signal 5 is not container evidence): B2 "Container"
  (signal 5 recorded as a fact only; both hints printed), §10 item 5.
- N2, W4 (overlay-root hosts): B2 signal (4) (root mount line compared
  with diag's own by `major:minor` and root, never fs type or mount
  IDs), §10 item 5.
- N3 (`wchan` 0 wording): A1, A5, A17, B2 (abandoned collector), B2.16,
  B3, §7.1, §10 items 1 and 5 — a `wchan` of `0` is written by the
  `stat` state letter (`running` for `R`, `hidden` otherwise); the
  sleeping-thread case is still to measure.
- N4 (root without `CAP_SYS_PTRACE` keeps the fd count): A5, B2.16 (both
  sentences), §10 item 5 M4 test.
- N5 (`machine.slice` alone is libvirt too): B2 signal (3), the
  `machinectl shell` hint, §10 item 5.
- K1 (blocking; unbounded stack sweep): A17 (status pre-check, 200 ms per
  thread, 2 s per sweep, sweep number, exit 10 not held by the sweep;
  macOS bound), A1, §7.1, §10 item 5.
- K2 (A1 incident has the stacks): A1, §7.1, §10 item 5.
- K3 (A6 I/O from `getrusage` only): A6.
- K4 (spinning start-up thread never reported): A1 "spin bound", A17
  budget class, §7.1, §10 items 1 and 5.
- W2 (blocking; LAN-only node refuses diag `known_values`): A10 (b)
  (loopback whenever the node listens there), §6.2 step 1 (fallback and
  the degraded-masking statement), B2.16, §6.3, §10 item 5.
- W3 (`import*` and `*passphrase*` can push out `stop`): A15, §10 item 5.
- W5 (`/wallet/<name>` route and the shared helpers): A10 (b), §10 item 5.

### Revision 7 changes

Each round-6 finding and the section that resolves it. The r6 list below
is history: where it says the hash160 backstop applies to "B6.5 answers
only", r7 widens that to B6.5 answers and attached RPC answers (V3); and
where it names the `listunspent` "address-filter exception", r7 removes
that exception (V1).

- C1 (attached `gettxoutsetinfo` stays in clear): B6.6 "Attached RPC
  answers"; §6.3 canary; §10 item 5 attached RPC answers.
- C2 (attached RPC-shaped files get the B6.5 rules and the "treated as RPC
  output" label): B6.6 "Attached RPC answers" (shape match and
  `--attach-method`); §8.2 "Attached files"; §6.3 canaries; §10 item 5.
- X1 (start-up stuck after `network`): A1 start-up bound (from `network`
  on, only phase and progress records and the start-up thread's own CPU
  count); §7.1 start-up row; §10 item 5 X1 test (`staking` blocked while
  syncing).
- X2 (credential-change test and lint lists): A5 "Non-dumpable process"
  (ten credential calls, workspace scope, per-tick re-check for
  third-party crates); D5 row; §10 item 5 (`prctl(PR_SET_DUMPABLE, 1)`
  test, ten-call lint); §10 item 6 release check.
- X3 (per-class incident budgets, request deleted on the helper): A17
  budgets and snapshot request (persistent helper, one operation
  outstanding, each request answered once); §10 item 5 X3 tests.
- P1 (script fields dropped even under `--rpc-clear`): B6.5 "Scripts and
  raw transactions" and the `--rpc-clear` text; §8.2 "One RPC answer in
  clear"; §7.2 L10; §6.3 canary; §10 item 5.
- P2 (own staked block lookups): B6.5 "Own staked blocks"; §8.2; §6.3
  canary; §10 item 5.
- P3 (secret environment values as HMAC plus length): A10 "Who may read"
  (a), with the corrected "nothing is lost" sentence and the stated limit;
  §6.3 scanner re-run and canaries (value alone in a command line, a URL
  and a component log; short value); §8.2 "Secret environment values";
  §10 item 5.
- L1 (container leftovers): B2 "Node in a container" (`--import -` from
  stdin, 0700 folders, `umask 077`, cleanup checked with `test -e`); §10
  item 5 L1 test.
- L2 (`mirror-same-fs=yes`): A17 snapshot request (both copies through the
  helper); §10 item 5 L2 test.
- L3 (binary replaced on disk): B1.2 and the A14 path record (SHA-256 of
  the running image, compared with the file now on disk); §10 item 5 L3
  test.
- L4 (one tracer only): B3.3 (no live attach while `strace` is attached;
  snapshot instead); §10 item 5 L4 test.
- M1 (`/proc/<pid>` keeps the task's euid): A5 readability check (no
  ownership test; `PR_GET_DUMPABLE` in the node); B2.16; D5 row; §10
  item 1 measured matrix.
- M2 (self-reads a non-root D5 node is refused): A5 "Non-dumpable process"
  self-read list; A1 I/O from `getrusage`; A17 incident (`getrusage`,
  `getauxval`, "refused by kernel" line); §10 item 1.
- M3 (`wchan` 0 and the reduced `stat`): A1 samples, A5, A17, B2.16 and
  B3.2 write `hidden`, never `running`, and never use the zeroed `stat`
  fields; §10 item 1; §10 item 5.
- M4 (`CapEff` and the visibility matrix): B2.16 matrix; B3.2 (abandoned
  node and collector record `hidden`); B3.3 (`CapEff`, `ptrace_scope`, root without `CAP_SYS_PTRACE` treated as
  non-root); §10 item 5 M4 test.
- V1 (`listunspent` refused above 10,000 transactions whatever its
  arguments): B6.5 argument caps, with the `wallet.rs:1209`/`1255` reason;
  §7.2 L10; §10 item 1 (the under-2 s timing, to measure); §10 item 5.
- V2 (explicit caller for `known_values`): A10 "Who may read" (b)
  (`Caller` with transport, peer and proxy flag, passed from the
  middleware through `handle_rpc`, `handle_http_body_for` and
  `dispatch`; Web UI and Electrum pass their own transport); §10 item 5
  V2 tests (Web UI, proxy headers, remote `rpcauth`).
- V3 (how an attached file is recognised; backstop on attached answers):
  B6.6 "Attached RPC answers"; B6.5 backstop scope; §8.2; §6.3 canary;
  §10 item 5.
- V4 (pid namespace is not a container): B2 "Node in a container"
  (positive evidence only); §10 item 5 `PrivatePIDs=yes` and `unshare
  --pid --fork` tests.
- V5 (local state-changing calls capped): A15 (rare methods always kept,
  `send*`/`*broadcast*`/`sign*` 100 an hour per method); §10 item 5 V5
  test.
- V6 (a failed first read counts as unreadable): A5 readability check;
  B2.16; §10 item 5.
- V7 (mirror copy of the snapshot request first): B2.16; §10 item 5 V7
  test.

### Revision 6 changes

Each round-5 review item, and where it is now handled. Every new test is
in §10 item 5; the facts not yet measured are in §10 item 1. Where a fix
differs from the reviewer's, the reason is given in the section named.

- Chain 1 (relative `-datadir` of a running node not findable under D5): A14 "Path record of the running process", B1.1 "A running node's paths" (record, then `/proc/<pid>/cwd`, else a plain statement, never the default dir), §10. Instead of a path field in `runs.log`, the record is a separate per-process file, so a stale one can be told from a live one by pid and start time.
- Crashes 1 (start-up bound never runs out because Part A's own CPU and I/O count): A1 start-up bound (non-Part-A threads only, read bytes only), §7.1 start-up row, §10.
- Crashes 2 (non-dumpable state can be reset): D5 status (b2dbea56 recorded), A5 "Non-dumpable process" (per-tick `PR_GET_DUMPABLE` re-check, credential-call lint), A6, §10.
- Crashes 3 (`eu-stack`/`gdb` refused under D5): B3.3, §7.2 L5, §10.
- Crashes 4 (stopped/frozen vs starved mislabelled): A17 classifier (`CONT` record, `frozen` only while set, cgroup-scoped deltas, "cause uncertain" with system-wide PSI), §7.1 hang row, §10.
- Crashes 5 (stop during start-up checked only at phase boundaries): A1 stop during start-up (progress records and rescan batches), §10.
- Crashes 6 (fd probe unbounded): A5 "Non-dumpable process" (bounded by `FDSize`, bound recorded), A6, §10 items 1 and 5.
- Platforms 1 (`docker cp` into `/dev/shm` or a read-only rootfs): B2 "Node in a container" (script on stdin, CLI in the data volume, `tar` stream out, shell-archive fallback), §10.
- Platforms 2 (partial hang invisible to a non-root diag): A17 (either stall, in-flight call over 60 s, snapshot request), B2.16, §7.1 hang row, §10.
- Platforms 3 (live attach needs `CAP_SYS_PTRACE`): B3.3, §7.2 L5, §10.
- Platforms 4 (root without `CAP_SYS_PTRACE` in a container): A5 (CapEff/CapBnd rule), B1.1 sudo hint, B2.16, §10.
- Platforms 5 (`cwd`/`exe` refused under D5): A14 path record, B1.1, B1.2, §10.
- Platforms 6 ("only `execve` resets it"): A5 "Non-dumpable process" (credential changes reset it too), D5 status.
- Privacy N1 (raw stack dump is process memory): A5 item 3 (filter in the handler; 32-bit words only with consent), §7.2 L6, §8.2 "Raw stack words (32-bit build)", §6.3 canary, §10.
- Privacy N2 (script hex, `asm`, `addresses`): B6.5 "Scripts and raw transactions", §6.3 canaries, §10. The hash160/push patterns apply to B6.5 answers only, not to §6.2 step 2 in general (they would mask build-ids and SHA-256s).
- Privacy N3 (`gettransaction` `hex`): B6.5 (dropped always, even under `--rpc-clear`; `listsinceblock` builds its entries with `details()`, `wallet.rs:1409`, and carries no `hex`), §8.2, §10.
- Privacy N4 (timing fields by class): B6.5 "Timing fields, by class", §6.3 height canary, §10.
- Privacy N5 (address-scoped answers; call arguments): B6.5 "The call itself" and "Address-scoped answers", §10.
- Privacy N6 (incident must not hold environment values): A17, §6.3, §10.
- Adversarial 1 (`wchan` reads `0` under D5): A5 readability check, B1.1, B2.16, §10 items 1 and 5.
- Adversarial 2 (RPC-only hang leaves no evidence): same design as Platforms 2. The request file is named `diag/snapshot-request`, and the watchdog reads the mirror copy itself and the data-dir copy through a helper thread, so a hung disk cannot block it.
- Adversarial 3 (raw transaction and script hex): same design as Privacy N2/N3; the ≥40-hex backstop is scoped to B6.5 answers, as the reviewer said.
- Adversarial 4 (remote broadcasts one line per call): A15 (remote Electrum/Web UI state changes capped), §7.1 "I ran a command" row, §10.
- Adversarial 5 (unbounded allowlisted calls): B6.5 — `gettxoutsetinfo`, `getaddressbalance`, `getaddressutxos` removed (a size gate was rejected: it needs the number the call computes); `listunspent` 10,000-transaction rule with the address-filter exception; §7.2 L10 "run it yourself and `--attach`"; the old `getaddressutxos` cap and its test removed; §10. Correction to the review: `getaddressutxos` loads every unspent output **of the address**, not the whole chain.
- Adversarial 6 (D5 follow-ups): A5 refused-file list (`cwd`, `root`, `mem`, `fdinfo/`; `maps` to measure), A7 start-up cwd, B2.12, B2 container detection by `NSpid` first, A6 fd bound, §10 item 1.
- Adversarial 7 (`known_values` to any RPC caller): A10 "Who may read the pages" (secret-named values omitted; loopback JSON-RPC only via the peer address the RPC middleware already has), §10.

### Revision 5 changes

Each round-4 review item, and where it is now handled. Every new test is
in §10 item 5 (release gates in item 6). Where a reviewer named something
IronDivi does not have, the real equivalent is used and noted.

- Platforms r4-1 (no real-time signals on macOS; per-thread stacks): A17, §7.1 hang row, §10.
- Platforms r4-2 (`docker cp` with nothing to copy; read-only rootfs, distroless): B1.4, B2 intro (container-outside), §10.
- Platforms r4-3 (macOS jetsam verdict): A2 table, §7.1 macOS row, §10 (a real jetsam kill via `memorystatus_control`, or stated untested).
- Platforms r4-4 (`systemd-run --scope` as root, mechanism recorded): B2 "Memory cap", §10.
- Platforms r4-5 (`max`/`PAGE_COUNTER_MAX`, minimum over ancestors): B2.8, §10.
- Platforms r4-6 (A1 wchan has no macOS note): A1 start-up bound.
- Adversarial r4-1 (RPCs that do not exist; unpaged calls): §6.2 step 1, A10. `listaddressgroupings` and `listlabels` do not exist in `divi-rpc`; step 1 uses the real `listaccounts`, `getaddressesbyaccount`, `listreceivedbyaddress`, `listunspent`, `listlockunspent`, `getmasternodestatus` (server.rs:609-619), with the B6.5 stop rule; `listtransactions` is never paged (its paging is quadratic, wallet.rs:1345-1373).
- Adversarial r4-2 (A15 per-caller/per-error growth; retention contradiction): A15 bounds, A14 arithmetic (cap about 74 MB), §7.1 Electrum row, §10 (public-server load test).
- Adversarial r4-3 (`--rpc` argument bounds): B6.5 argument caps and stop rule, §8.2, §7.2 L10, §10.
- Adversarial r4-4 (`--rpc getdiaginfo` with user `diag_key`/`known_values`): A10, B6.5, §8.2, §10.
- Adversarial r4-5 (environment values destroying the logs): §6.2 step 1 exclusions, §6.3 realistic-environment canary, §10.
- Chain r4-1 (allowlist too narrow for "wrong answer"): B6.5 extended allowlist with caps, §7.1 RPC row, §7.2 L10, §10.
- Chain r4-2 (mild staking shortfall invisible): B6.5 `getmintinginfo` (staking.rs:236-241, weights as one ratio bucket), §7.1 staking row, §7.2 L12.
- Crashes r4-1 (start-up bound kills a slow healthy start): A1 (I/O and CPU count as progress; no kill by default), A18 `-startuptimeout`, B3.2, R3 code 10, §7.1 start-up row, §10.
- Crashes r4-2 (die(10) blocks on a hung data-dir disk): A1/A17 mirror-first then bounded data-dir writes, A14, §7.1 start-up row (D-state reap note), §10.
- Crashes r4-3 (starvation labelled "frozen"; hang clock reset): A17 "starved" label with deltas, clock subtracted, §7.1 hang row, §10.
- Crashes r4-4 (stop during start-up skips clean exit): A1, R3 row 0, §10.
- Crashes r4-5 (Part A threads before the `-daemon` fork): A3, A17, A1, §10.
- Crashes r4-6 (RLIMIT_DATA before Linux 4.7): B2 "Memory cap" `statm` poll, §10.
- Crashes r4-7 (one SIGSEGV after A5; `SI_USER` sender): A5, D5, B2.14, §10 (core-dump.sh).
- Crashes r4-8 (§7.1 seccomp row named A5): §7.1 seccomp row now "A2 marker".
- Privacy r4-1 (public lists show the own entry): §6.2 "Public records" (separate public-record salt), A10 winners, A12, A13, B6.5, §6.3, §10.
- Privacy r4-2 (stake counts reveal the balance): A6 count bucket, A12 weekly bucketed counts, §7.1 rewards row, §10.
- Privacy r4-3 (label/account/comment/to; HD ids): B6.5, §8.2, §10. `hdseedid` does not exist; the real fields are `hdmasterkeyid` (wallet.rs:1198) and `hdchainid` (validateaddress, wallet.rs:1058).
- Privacy r4-4 (timing fields in wallet answers): B6.5, §10.
- Privacy r4-5 (`getdiaginfo` params; `--rpc-clear` scale): A10, B6.5, §8.2 (counts, 100-item cap), §7.2 L10, §10.
- Privacy r4-6 (diag.log and 00-SUMMARY.txt): §6.2 "Diag's own files", §6.3, §10.
- Privacy r4-7 (receiver contacted before consent): B2.15, §8.4, §9 (hosting provider logs), §10.
- Privacy r4-8 (age key in diag.sh): B1.4, §8.4, §10.
- Privacy r4-9 (apport `Stacktrace` locals): B2.12, §10.
- Privacy r4-10 (bare host names, Windows fields, `C:\Users`, `\\wsl$`, `docker info`): §6.2 step 1 and the paths rule, B6.4, B6.6, §6.3, §10.
- Privacy r4-11 (rule (b) module list): §6.2 rule (b) derived from the edit sites (adds `divi_node::mempool`, mempool.rs:736, and the main.rs:2345 line, as of f67b0984, removed in 09cb18e4), A11, §10.
- Privacy r4-12 (where the sent-from-here set lives): A15 `diag/sent-txids` (0600), A10, §6.1, §6.2 step 1, §6.3, §10.
- Privacy r4-13 (exit reasons echo a secret): R3, A14 `_unresolved/`, §6.3, §10.
- Privacy r4-14 (logwalletdetail mirrors; start-only): A11, A14, §10.
- Privacy r4-15 (wallet `OPTIONS-*`): B2.7 (wallet/ as total size and count only), §6.1, §10.
- Privacy r4-16 (optional: per-call key instead of the salt): adopted — A10 per-call `k`, §6.3, §10.
- Privacy r4-17 (rule (b) hides ports and error codes): §6.2 rule (b), §10.
- Privacy r4-18 (irondivi-cli positional arguments): A3, §6.2 step 3.
- Coordinator D5 finding (hp1 VM: systemd-coredump stores a core at RLIMIT_CORE 0): D5 row (evidence, `PR_SET_DUMPABLE` 0), A5 "Non-dumpable process" (own `/proc/self` fallbacks; diag gets the node's `/proc` data through `getdiaginfo`, not root), A6, A10, §6.2 step 1, B2.11, B2.12 (no `coredumpctl` entry for a D5 node; field list for older entries), B2.16, §7.1 crash row (crash evidence from A5, A9/A1, A2, B2.5), §7.2 L6, §10 items 1, 5 and 6 (gate: `core-dump-vm/vm.sh` D5-A/D5-B, `core-dump.sh` for apport). The coordinator's corrected point 4 (no journal entry at all for a non-dumpable crash) replaces the first report.

### Revision 4 changes

Each review item, and where it is now handled. Every new test is in §10.

- Platforms 1 (diag.sh on glibc-only arches; import elsewhere): B1.4, B6.4, §6.3, §7.1.
- Platforms 2 (memory cap that works with glibc and on macOS): B2 intro, B2.8, §10.
- Platforms 3 (free memory inside a cgroup; macOS): B2.8, §10.
- Platforms 4 (macOS paths for I/O, threads, pressure, live sample): A6, A17, B2.16, §10.
- Platforms 5 (WSL verdict order): A2 table, §10.
- Platforms 6 (container-outside: collect what can be collected): B2 intro, §10.
- Platforms 7 (`docker exec` for images without the CLI): B2 intro, §10.
- Platforms 8 (Docker Desktop pulls an image): B4.5, B6.2, §10.
- Adversarial 1 (RPC log retention under load): A14, A15, §7.1, §10.
- Adversarial 2 + Privacy 2 (`--rpc` allowlist, refused methods, amounts bucketed): B6.5, §8.2, §7.2 L10, §10.
- Adversarial 3 (known-value fetch on a big wallet): §6.2 step 1, A10, §10.
- Adversarial 4 (environment secrets in attached host output): §6.2 steps 1–3, B6.6, §10.
- Adversarial 5 (diag filling the node's disk): R1 (a), B2 intro, B6.1, §10.
- Privacy 1 (expected stake rate): A6, §7.1.
- Privacy 3 (every locally submitted tx is "own"): A15, A13, §8.2, §10.
- Privacy 4 (old-log arguments always masked; real module names): §6.2 step 2, A11.
- Privacy 5 (`-logwalletdetail=1` runs): A11, §6.2 step 2.
- Privacy 6 (journal, docker logs, observed-start output): §6.2 step 2, B2.5, B3.2.
- Privacy 7 (swap logs): B2.17.
- Privacy 8 (stored RPC error text): A15.
- Privacy 9 (attached host files' names): B6.6, §6.2 steps 1 and 3, §10.
- Privacy 10 (diag.sh contents; machine-id hash): B1.4, B6.4, §6.3 canary (e), §7.1, §10.
- Privacy 11 (temporary `-conf` copy holds `rpcpassword`): R1 (d), B3.2.
- Privacy 12 (other senders' command lines): A3, §6.2 step 3.
- Privacy 13 (`diag_key`): A10, §6.3, §10.
- Privacy 14 (wallet RocksDB `LOG`): B2.7, §6.1, §10.
- Privacy 15 (`--tx` consent text): B6.3, §8.2, §10.
- Crashes 1 (stdin and `-sign-snapshot`): §3 intro "stdin", §10.
- Crashes 2 (seccomp kill actions run no handler): A5, A17, B2.18, §7.1, §10.
- Crashes 3 (start-up hang has no bound): A1, A3, A17, B3.2, §7.1, §10.
- Crashes 4 (collector spawn, rlimits, cap kills): B2 intro, B3.2, §10.
- Crashes 5 (stopped/frozen vs hang): A3 CONT row, A17, §7.1, §10.
- Crashes 6 (allocation failure code): R3, §3 "Who writes", A5, §7.1, §10.
- Crashes 7a (Rust stack overflow is 134): A5, §7.1, §7.2 L5, §10.
- Crashes 7b (code 11 line refs; log-file open failure): R3.
- Crashes 7c (daemon record pids): A1.
- Crashes 7d (job-control signals with no terminal): A3, §10.

The goal, in the developer's words: a diagnostic package so complete that no
problem report ever needs a follow-up question, safe enough that it never
gives away the user's private information, shown to the user before it is
sent, and sent only if they agree.

"Complete" is defined precisely in §7: every failure the reviewers could name
is either answered by a named file in the package (§7.1), or is one of the
stated limits in §7.2, each of which comes with a recording step the user can
run (`diag --capture`, `diag --host`, `diag --tx`, the printed host command)
that does answer it. Nothing in this plan ends with "ask the user"; questions
the user can answer are asked once, inside diag, in `01-user-report.txt`.

---

## 0. Defects found while reviewing (fixed first, independent of diag)

Bugs in 0.2.9 as shipped, found by the reviewers while checking the plan.
They ship in the first release of this work whether or not diag is done.

| # | Defect | Where | Fix |
|---|---|---|---|
| D1 | The signal task writes the console line (`eprintln!`) **before** `shutdown_tx.send`. After an SSH drop the terminal is gone, the write fails, `eprintln!` panics, the task dies, and SIGTERM never stops the node. | `main.rs` signal task, about line 3317 (already reordered in the working tree; the test is still owed) | Send the shutdown first. Every console write goes through one `console_line()` that ignores write errors and records "stderr lost at <time>" once in `debug.log` and `events.log`. |
| D2 | A closed stdout/stderr gives EPIPE (Rust ignores SIGPIPE), and `println!`/`eprintln!` panic on it. | all console writes | Same `console_line()`; SIGPIPE/EPIPE count kept (A3). |
| D3 | `process::exit(1)` after a `run_daemon` error, the runtime builder's `?`, and the early exits do not flush the non-blocking log writer, so the error line can be lost — the friend's symptom. | `main.rs` about 3358; runtime builder; early exits about 3049–3105 | One `die(code, reason)` (A9). |
| D4 | `-help` and `-version` exit 1 (divid compatibility), so 1 cannot mean "configuration error". | about `main.rs:3052` | Kept; the exit-code table (R3) gives 1 no other meaning. |
| D5 | `disable_core_dumps()` set only `RLIMIT_CORE` to 0 (`private_files.rs:31`). A **piped** `core_pattern` handler is run whatever that limit says, and whether it stores a core is up to the handler. A core holds wallet keys. | `private_files.rs:31`, called at `main.rs:3039` | `disable_core_dumps()` also calls `prctl(PR_SET_DUMPABLE, 0)` on Linux, right after the `RLIMIT_CORE` call, at the start of `main()` (after the fd 0–2 reopen and the umask, before argument parsing, any thread or the wallet). The kernel does not hand a non-dumpable process to any core handler, piped or not. **Status:** done in bae9c769 (`private_files.rs:43-50`, with a `PR_GET_DUMPABLE` assertion in its unit test), together with `scripts/tests/core-dump-vm/`; hardened in b2dbea56: the `prctl` call now always runs, even when the `RLIMIT_CORE` call fails, and the first error is returned (`private_files.rs:31-56`). **Credential-call lint: done** in 97c4bceb (`bin/irondivid/tests/credential_calls_lint.rs`): it walks `bin/`, `crates/` and `tools/` and fails on any of the ten credential calls (`setuid`, `setgid`, `setresuid`, `setresgid`, `setreuid`, `setregid`, `setfsuid`, `setfsgid`, `capset`, `setgroups`, in their bare, `libc::` and `nix::unistd::` spellings) or `caps::set`, `caps::raise`, `caps::drop`, `caps::clear` that is not followed by `PR_SET_DUMPABLE` in the same function (the kernel resets the flag on a credential change); the file also holds a self-test of the matcher, and both tests pass on hp3 (as reported with the commit). **Per-tick re-check: done** in f5f3bce5 (`private_files::restore_non_dumpable`, which clears a non-zero `PR_GET_DUMPABLE` and logs `dumpable restored (was <n>)`; unit test `node10_reset_dumpable_flag_is_restored` passes on hp3 for that commit), and moved in 856f7376 off the tokio runtime onto a plain `std::thread` named `dumpable-check`, started in `main()` after the daemon forks and before the tokio runtime is built, so it runs before the wallet opens. It sleeps 60 s in a loop; `restore_non_dumpable()` returns `Option<(i32, io::Result<()>)>`; a reset logs `warn!` "dumpable restored (was <n>)", a failed reset logs `error!` "dumpable is <n> and could not be reset: <err>", and a thread that cannot start prints "Warning: could not start the core dump check: <err>" on the console. The unit test was updated in 856f7376; that the updated test passes is not yet reported. **A6: done** in 194c97e6: the check runs at the health tick's rate (10 s for the first 10 minutes, then 60 s), still on the `dumpable-check` thread so a stalled runtime cannot stop it; `health.log` carries its value and a reset is the `events.log` record `dumpable-reset was=<n> result=ok|error` (Revision 16). **Evidence 2026-10-30:** (1) hp3, apport pipe: `scripts/tests/core-dump.sh` passes; apport honours the zero limit. (2) hp1, Ubuntu 22.04 VM, systemd 249, as root: the systemd-coredump pattern is `\|/lib/systemd/systemd-coredump %P %u %g %s %t 9223372036854775808 %h %d`; its literal limit replaces ours, so a SIGSEGV'd irondivid at `RLIMIT_CORE` 0 **left a 1.2 MB core in `/var/lib/systemd/coredump`** — the old "limit 0 is enough" claim was false. A Python probe at `fs.suid_dumpable` 2 and 0: limit 0 alone stored 715 KB; limit 0 plus `coredump_filter` 0 still stored 3.9 KB (the filter is not enough); limit 0 plus `PR_SET_DUMPABLE` 0 stored **nothing**. (3) The plain `core` file pattern honours limit 0: no core (pass). (4) Runs as a non-root user (`probe`) stored no core in any case; the cause is **not confirmed** and nothing relies on it. (5) VM rerun with `PR_SET_DUMPABLE` 0 built in: the kernel never runs systemd-coredump for a non-dumpable process, so an irondivid crash leaves **no** `coredumpctl`/journal coredump entry at all, not only no file (an earlier "journal: present" was the previous run's entry); the control process was recorded and stored as usual. systemd-coredump (D5-A) and plain `core` (D5-B) **pass**; apport on hp3 still passes. **Consequence:** diag cannot see an irondivid crash through `coredumpctl`; crash evidence comes from the node's own records — A5 `crash.log`, the A9/A1 exit record in `runs.log`, the A2 marker verdict — and from the exit code or signal its parent or service manager saw (B2.5 `ExecMainCode`/`ExecMainStatus`, the unit's journal "Main process exited, code=killed, status=11/SEGV" line, Docker `ExitCode`). **Cost:** the files inside a non-dumpable process's `/proc/<pid>` are root-owned (the directory itself keeps the task's euid, measured on hp3, §10 item 1), and same-user ptrace and the ptrace-checked `/proc` reads are refused; how Part A and diag live with that is in A5 "Non-dumpable process". The release gate (§10 item 6) is `scripts/tests/core-dump-vm/vm.sh` (a throwaway Ubuntu 22.04 VM on a libvirt host, running `run.sh` under systemd-coredump and plain `core` patterns), plus `scripts/tests/core-dump.sh` for apport: a control process must leave a core and irondivid must leave none. Diag reports any irondivid core found (B2.12), by name, size and time only, and tells the user it may hold keys and how to delete it. |
| D6 | Default `debug.log` rotation (1 MB × 5) keeps minutes of history during sync. | `config.rs:846-849`, `main.rs:1290`-`:1295` (the size-rotated `debug.log` writer in `init_logging`, `:1250`) | Unchanged for `debug.log`; history moves to the Part A logs, which have their own budget (A14). |

---

## 1. The friend's case, and what it taught

**Reported.** The 0.2.8 musl build, run as root in a Debian LXC container
(6 cores, 4 GB), printed "Logging to", "Log rotation" and the wallet warning;
then the shell prompt came straight back. `debug.log` was empty.

**What can be concluded.** Not reproduced. The wallet warning is printed
while loading the wallet (`warn_if_unencrypted`, called from `run_daemon`
at about lines 1553/1657), after the data dir lock (`lock_data_dir`, called
at about 1771), so the process got that far. `debug.log` stayed empty, so
the process ended before the non-blocking writer wrote anything — an exit that
skips the flush. That is either an error path through `process::exit(1)` (D3,
status 1, error line lost) or a signal (SIGKILL from the kernel OOM killer, the
container's memory limit, `pct stop`, a supervisor or a person; or a crash
signal). The exit status was not recorded, so **the cause is not known**, and
this plan does not pretend otherwise.

**What it taught.** The node did not record how it ended, and the user had
no way to send what the machine knew. Part A makes the node record its own
life in files that survive any death short of power loss; Part B collects
those files and everything around them into one package the user reviews
before sending. For this exact case the package would show: the exit status
or signal and its sender (A1, A3), the last phase reached (A1), memory and
cgroup counters at death (A2), the kernel's OOM line if any (B2.11), the
container's limits from inside (B2.3) and the host command to run outside
(§7.2 L3).

---

## 2. Requirements and the rules that hold throughout

1. **Complete.** Every row in §7.1 is answered from the package alone; every
   limit in §7.2 has a recording step that answers it.
2. **Safe.** Nothing in §6.1 ever leaves the machine. Redaction is done at the
   source (A11), again on collection (§6.2), and a scanner refuses to package
   anything that still matches (§6.3).
3. **Seen before sent.** The user reads the package before anything is sent
   (§8). No tty, or end of input, always means "no".
4. **Only the developer can read it.** Encrypted to the developer's `age` key
   before upload (§8.4).
5. **Works when the node does not.** No collector needs the node running,
   the RPC port, or the binary that crashed. A static-musl `irondivi-cli` and
   a POSIX `sh` fallback cover a binary that cannot run at all (B1.4).
6. **Never makes things worse.** Diag is read-only except the writes in R1. It
   never starts the node without consent, never changes configuration, never
   deletes anything outside its own output, never blocks forever (B5), and
   never runs a heavy or intrusive tool without asking.

### R1. What diag writes

- (a) Its output folder (default `./irondivi-diag-<ticket>/`; falls back to
  `$TMPDIR`, then `/tmp`, if the working directory is not writable or fails
  the free-space rule below), with its own `diag.log` inside.
  `00-SUMMARY.txt` is written **first** and rewritten as collectors finish,
  so a diag killed halfway still leaves a readable summary.
  **Free-space rule** (the one rule; B2 and B6.1 refer here): when the
  output folder is on the same filesystem as a data dir (same `st_dev`),
  diag keeps at least max(1 GB, 5 %) of that filesystem free; on any other
  filesystem, at least 50 MB. It checks before each collector and before
  each B6.1 sample. When a check fails on the data dir's filesystem, diag
  moves the output folder to `$TMPDIR` (or `/tmp`) if that is on another
  filesystem with room, and otherwise stops collecting, keeps what it has,
  and says why in the summary. Diag never takes the node's last free space.
- (b) The **fsync test file** (B2.6): created with `O_EXCL` in the data dir's
  filesystem, only when free space is at least max(1 GB, 5 %), only when no
  node runs on that data dir, at most 10 MB, removed on every exit path
  including SIGINT, SIGTERM and SIGHUP. Its name is written to `diag.log`
  before it is created, and the next diag run removes any leftover named
  `.irondivi-diag-fsync-*`.
- (c) The **observed start** (B3), which runs the node and so lets the node
  write what it normally writes — only with consent and only if B3.1 passes.
- (d) The **temporary `-conf` copy** for the observed start (B3.2), which
  holds the user's `rpcpassword` and other config secrets. It is written
  mode 0600 inside a fresh mode-0700 directory under `$TMPDIR` (never in the
  data dir or the output folder), its path is written to `diag.log` before
  it is created, it is removed on every exit path including SIGINT, SIGTERM
  and SIGHUP, and the next diag run removes any leftover
  `irondivi-diag-conf-*` directory. §6.3 refuses to package any path under it.

The mirrors of `runs.log`, `crash.log` and `events.log` outside the data dir
(A14) are written by the **node**, not by diag.

### R2. Consent flags

| Flag | Means | With no tty / EOF |
|---|---|---|
| (none) | Collect, show the preview, ask before an observed start, ask "send? [yes/no]". | Collect and save; no observed start; never send. |
| `--run` | Consent to the observed start (B3) **if** B3.1 passes. | Same. |
| `--no-run` | Never start the node. | — |
| `--submit` | Consent to send **after** the preview; diag still shows it and still waits for `yes`. | Saved, not sent. |
| `--no-submit` | Never send. | — |
| `--yes` | Removed (it was ambiguous). Prints which flags above to use and exits 64. | — |

There is no way to send a package the user has not seen. With no tty diag
never sends, whatever the flags. `--send <folder>` sends only a folder that
was previewed: the preview writes `preview.ok` holding the SHA-256 of the
sorted file list and every file's hash, `--send` recomputes both, re-runs the
§6.3 scanner, shows the §8.3 summary again and still waits for `yes` on a
tty. A folder without `preview.ok`, or whose hashes differ, is refused.

Other flags, none of which grants consent: `--offline` (no network at all: skips the B2.15 probe and the upload, writes the encrypted file only), `--send <folder>` (§8.3 step 4 on a saved folder), `--report-file <path>` (§8.1), `--capture`, `--host`, `--tx`, `--import` (B6), `--datadir`/`--conf` (B1, added to what discovery finds).

Whatever the flags, diag **never** starts the node when: (i) a masternode is
configured (`masternode=1` or any `masternode.conf` entry); (ii) a migration,
reindex or wallet upgrade would run (detected read-only, B2.8); (iii) a
supervisor is restarting the node or it is running already (B3.1); (iv) the
data dir is owned by a user diag cannot run as. The summary says which rule
stopped it and the exact command to run instead.

### R3. Exit codes of `irondivid` (A9)

| Code | Meaning |
|---|---|
| 0 | Clean stop (RPC `stop`, SIGTERM, SIGINT; SIGHUP never stops the node, A3). A clean stop after SIGTERM is 0; `runs.log` records the signal and its sender. The two `-daemon` parents also exit 0, through `_exit(0)`, writing nothing; the grandchild writes the A1 `daemon` record (today `process::exit(0)` at about `main.rs:3117` and `:3133`). A stop request during start-up is also 0: the node closes what it has opened, removes the pid file and the A2 marker, and calls `die(0, "stopped during start-up in <phase>")` (A1). |
| 1 | `-help` / `-version` only (D4), through `die(1)` (about `main.rs:3052`). |
| 2 | Usage: unknown or malformed command-line argument, and (as built, Revision 16) a value from `divi.conf` that parses but is refused. The reason names the argument's key and why it was refused, never its value or the argument as typed (a malformed `-rpcpassword=…` must not be echoed). |
| 3 | Configuration file error: as built (Revision 16), a file that cannot be read or that divid's parser refuses; a refused value is 2. The reason names the file, the line number, the key (when one parses) and why, never the value or the line's text. The same holds for every copy of these reasons: `runs.log`, `debug.log`, stderr, and the A14 `_unresolved/` record. |
| 4 | Data dir error (create, lock held by another node, permissions). Also the `-daemon` child failing to open its log file (about `main.rs:3150`) for any reason other than the two in code 9. |
| 5 | Database error (open, corruption, migration refused or failed). |
| 6 | Wallet error (load, decrypt, version). |
| 7 | Bind error (P2P, RPC, Electrum, Web UI port in use or not permitted). |
| 8 | Not used. (Revision 3 gave it to allocation failure, but Rust's `handle_alloc_error` aborts, so that ends as 134 SIGABRT; A5 links the abort to the allocator's own record. The number stays reserved so old notes are not misread.) |
| 9 | Disk full or read-only filesystem on a required write, including the `-daemon` log-file open (about `main.rs:3150`) failing with `ENOSPC` or `EROFS`. |
| 10 | A task the node cannot live without returned an error or panicked (A4), a third stop signal (TERM, INT or QUIT) forced the stop (A3), any start-up error that maps to no other code, or the A1 start-up bound ran out on a run started with an explicit `-startuptimeout=<s>` (A18; B3.2's observed start passes it). Without that flag the bound never stops the node. |
| 11 | `-daemon` could not fork or `setsid` (about `main.rs:3112`/`3115` first fork, `3122-3124` setsid, `3128`/`3131` second fork). |
| 101 | Panic on the main thread: the node's own `_exit(101)` after `catch_unwind` (70cb5785; held by `tasks_lint`), or from the panic hook before that `catch_unwind` is entered, the same number as Rust's, kept. |
| 128+N | Killed by signal N (the shell's convention). `docs/exit-codes.md` lists every N per architecture: 134 abort (including allocation failure and a stack overflow on a Rust thread, A5), 137 SIGKILL, 139 SIGSEGV (including a stack overflow on a RocksDB thread), 143 SIGTERM before handlers are installed, 152 SIGXCPU, 153 SIGXFSZ, 159 SIGSYS on x86_64/aarch64 (a seccomp `KILL_PROCESS`, A5), and SIGPWR, whose number differs by arch. |

Codes 0 (stop during start-up only) and 1–11 go through `die(code, reason)`
except the two that must not block: the third signal (10), which writes a
pre-formatted record to the pre-opened fd and calls `_exit`; and the
`-startuptimeout` bound (10), which writes its record to the A14 mirror
first, runs the data-dir writes on a helper thread for at most 2 s, then
calls `_exit(10)` whether or not they finished (A1). The two `-daemon` parents' 0 is a bare
`_exit(0)` with no record (A1 `daemon`). `die`: write the reason synchronously
to `runs.log`, `debug.log` and stderr (write errors ignored), flush, then
`_exit(code)`. No code in `bin/irondivid` calls `process::exit` directly; a
test greps for it. A wrapper (systemd, Docker) that reports a status is
compared with the node's own record in the run table (B2.14).

---

## 3. Part A — the node records its own life

All Part A files live in `<datadir>/diag/` (budget in A14), are plain text,
one record per line, `key=value` fields after an RFC 3339 UTC timestamp with
microseconds and the monotonic clock in seconds. `runs.log`, `crash.log` and
`events.log` are durable (`write` + `fdatasync`); `health.log` is `write`
only. They survive any death except power loss, and the last `fdatasync`ed
record survives that too. The `diag/` directory is `fsync`ed once when it is
created, so the files themselves survive a power loss.

**Who writes.** Only `die()`, the A3/A5 signal handlers and the allocator
wrapper (A5, which writes its record and then returns null, so Rust's
`handle_alloc_error` aborts) write directly, from pre-opened fds and fixed
buffers. Everything
else goes through one dedicated writer thread with a bounded queue (4096
records); a full queue drops the record and counts it, and the count is in
the next `runs.log` `dropped` line. A write that blocks (a hung disk) holds
only that thread; health records "diag writer blocked N s" from the
monotonic clock, and the A17 watchdog writes its incident to the A14
mirror **first**, then to the data dir, so a hung data-dir disk cannot stop
the mirror copy.

**Before the data dir is known** (argument and config errors, the early
`-daemon` fork), records go to the fixed mirror location's `_unresolved/`
folder (A14). B1.1 always collects it. These records carry the R3 code 2/3
reason only — key name, line number, why — never a value or the text of a
config line, since nothing has been parsed into types yet that could hide
it.

**No Part A thread before the `-daemon` forks.** `fork()` keeps only the
calling thread (`main.rs:3112` and `:3128`): a writer thread started earlier
would not exist in the grandchild, its queued records would be lost, and a
queue mutex it held at the fork would stay locked there, so the first record
would deadlock the node — a hang at start with an empty log. So until the
forks are done (or, without `-daemon`, until the point where they would
be), Part A writes synchronously from the main thread to `_unresolved/` or
the mirror, and the writer, A17 watchdog, A6 health and A1 hash threads are
started only in the grandchild (or in the single process without
`-daemon`). Nothing spawns a thread before the fork today; a test keeps it
so (§10).

**stdin.** The start of `main()` already reopens any of fds 0–2 that is
closed onto `/dev/null` (about `main.rs:3021-3034`). On the `-daemon` path
only, the existing
`libc::close(libc::STDIN_FILENO)` (about `main.rs:3157`, after the
stdout/stderr `dup2` at about 3155–3156) is replaced with `dup2` of
`/dev/null` onto fd 0. Closing fd 0 leaves it free, so the next file the
node opens (a log, a RocksDB file) would become fd 0 and could be read or
written by mistake; `/dev/null` keeps it taken. Without `-daemon`, fd 0 is
left alone: `-sign-snapshot` reads its key from stdin (`snapshot_command`,
about `main.rs:2881-2883`), and that must keep working. `-daemon` together
with `-sign-snapshot` is not a supported combination and is refused at
argument parsing (exit 2). A7 decides "started from a tty" from fd 2.

### A1. `runs.log` — one line per life event

- **start**: run number, pid, ppid and parent comm, uid/euid/gid, binary path
  and SHA-256 (hashed once at start in a background thread; the line is
  rewritten as `start-hash` when done), version, git sha, build target,
  frame pointers yes/no, kernel release, boot id
  (`/proc/sys/kernel/random/boot_id`; macOS `kern.bootsessionuuid`),
  container type and PID 1 start time (A2), cgroup path, config file SHA-256
  and mtime, the masked argv (§6.2), network, data dir pseudonym, how it was
  started (tty, systemd unit name from `INVOCATION_ID`/cgroup, Docker,
  OpenRC, launchd, `nohup`, `setsid`) and whether `-daemon` forked.
- **phase**: each start-up phase as it is entered — `args`, `config`,
  `datadir`, `lock`, `db-open`, `migration:<n>`, `chain-load`, `wallet-load`,
  `wallet-rescan`, `network`, `rpc`, `staking`, `masternode`, `running` — and
  how long the previous phase took. The last `phase` before an exit is where
  it died.
  **Start-up bound.** Start-up (everything before `running`) gets 5 minutes,
  extended by 5 minutes each time there is progress: a new `phase` record, a
  progress record inside `db-open`, `migration:<n>`, `chain-load` or
  `wallet-rescan`, or a rise since the last check in the work done by the
  node's **own start-up threads**. From the `network` phase on (X1), only
  `phase` and progress records and the CPU of the **start-up thread
  itself** count: by then the P2P, RPC, sync and staking threads are
  running, and their CPU and reads would keep extending a start-up that is
  stuck in `staking` or `masternode` for ever (a node that syncs from peers
  while `staking` blocks is the case). The start-up thread records its tid
  in each `phase` record, so the check reads that one
  `/proc/self/task/<tid>/stat` (macOS: that thread's `thread_info`), and
  read I/O no longer counts. **The spin bound** (K4): since CPU on the
  start-up thread counts as progress, a start-up thread spinning in a
  loop would never be reported. So from `network` on, a phase that has
  run 15 minutes (or `<s>` seconds when `-startuptimeout=<s>` is set and
  shorter, F1, so the record comes before the start-up bound and before
  diag's B3.2 escalation) with no new `phase` record writes an A17
  incident (in
  the "health-tick and runtime stalls" class, A17, where the first one of
  a run is always written) and an `events.log` line `start-up phase
  <name> running <m> min` (the bound that applied), whatever its CPU. It
  never ends the run, even
  with `-startuptimeout`, and fires once per phase per run; a long rescan
  that is making progress also writes it once, which is a record, not a
  verdict. The 15 minutes is a first value, to measure in §10 against the
  longest real `wallet-rescan` and `staking` phases on the reference Pi.
  Before `network` the rule below applies. Part A's threads (the A17 watchdog, the
  A6 health thread, the A8 writer thread, the A1 hash thread) run during a
  stall and would keep any process-wide figure rising, so they are left
  out. CPU is the sum of `utime`+`stime` (fields 14 and 15) of
  `/proc/self/task/<tid>/stat` over every tid that is not in the Part A
  set (each Part A thread records its tid when it starts); those files stay
  readable to the node when it is non-dumpable (D5). On macOS it is
  `thread_info(THREAD_BASIC_INFO)` user+system time over the threads of
  `task_threads` that are not Part A's. I/O counts **read** bytes only
  (`getrusage(RUSAGE_SELF)` `ru_inblock`, the count of block reads that hit
  the disk; macOS `proc_pid_rusage` `ri_diskio_bytesread`): Part A
  reads no block data, while WAL replay and chain load do; Part A's own
  writes would otherwise count as progress. `/proc/self/io` is not used:
  measured on hp3 (§10 item 1), a non-dumpable node is refused its own
  `io`. RocksDB's
  `DB::open` (WAL replay, many SST files on an SD card) is one call with no
  progress hook, so these counts are what keep a slow but working open
  from being taken for a stall. Only a stretch with no record, no read I/O
  and no CPU on the non-Part-A threads for the whole bound counts. When it runs out, the
  A17 watchdog writes a full A17 incident (K2): the current phase; five
  samples of each thread's state from `/proc/self/task/<tid>/stat` and its
  `wchan`, the kernel function it is waiting in, from
  `/proc/self/task/<tid>/wchan`, where a `wchan` of `0` is written by the
  `stat` state letter as A17 says — `running` for `R`, `hidden` for `S`,
  `D` or any other state (M3, N3); whether a non-root node reading a
  sleeping sibling thread gets a real name is to measure in §10 item 1;
  on macOS the thread states from `task_threads`/`thread_info` with
  `wchan` "n/a (macOS)", as A17; every thread's stack, collected under
  A17's bounds (200 ms a thread, 2 s for the sweep, threads in `D` or
  with the signal blocked named and not signalled, K1); and the task
  dump. It also writes an `events.log` line, and **the node keeps running**: a
  stall that later resolves only leaves the record. Under systemd
  `Restart=on-failure` a self-kill would replay the same WAL and be killed
  again forever, which is worse than the stall.
  Only when the run was started with an explicit `-startuptimeout=<s>` (A18;
  B3.2's observed start passes it, nothing else does) does the bound end the
  run, and then in an order a hung data-dir disk cannot block: (1) the
  incident and a pre-formatted `exit code=10 reason="start-up stalled in
  <phase>"` record go to the A14 mirror, which is on another filesystem when
  there is one (A14); (2) the data-dir writes (`runs.log`, the incident,
  `debug.log` flush) run on a helper thread with a 2 s bound, as A8's flush;
  (3) `_exit(10)` whether or not they finished. A thread stuck in `D` state
  can delay the kernel's final reap, but the mirror record is already there.
  **Stop during start-up.** A stop request (A3) during start-up is honoured
  at the next phase boundary, at each progress record inside `db-open`,
  `migration:<n>`, `chain-load` and `wallet-rescan`, and at each rescan
  batch boundary, instead of waiting for `running` (a rescan or chain load
  can take hours, and a stop then would otherwise run into the service
  manager's stop timeout and a SIGKILL) (today
  `shutdown_rx` is first read only after `running`, about `main.rs:2240`).
  The node takes the normal stop path for what it has set up so far: it
  closes the databases opened so far, flushes the `debug.log` writer,
  removes the pid file (`remove_pid_file`, about `main.rs:3014`), removes
  the A2 marker, and calls `die(0, "stopped during start-up in <phase>")`
  (R3 row 0), so the next start writes no `unclean-previous`.
- **daemon**: written by the final (grandchild) process after the second
  fork: its own pid, the first parent's pid and the intermediate process's
  pid. The two parents exit at once through `_exit(0)` and write nothing
  (they share the pre-opened fd, and a write from them would race the
  child's). This tells a `-daemon` start that "returns to the prompt" apart
  from a death.
- **stop-requested**: by what (RPC `stop` with the caller's transport,
  signal with sender from A3, `-stopafterblockimport`, internal error).
- **exit**: code from R3 and reason, or `signal=<n>` when the node is about to
  re-raise one, uptime, peak RSS.
- **unclean-previous**: written at start when the A2 marker was left behind:
  the previous run's last health record, last phase, its marker counters, and
  the verdict rules in A2.
- **dropped**: log lines dropped by A8, with the count.

### A2. `irondivid.running` — the marker that proves an unclean end

Created at `lock`, removed as the very last act of a clean exit (after
`runs.log` `exit`). Each rewrite goes to a temporary file, is `fdatasync`ed
and renamed over the marker, so a marker is either the old one or the new
one; one that does not parse is read as "unclean, counters lost". Rewritten
every health tick (A6) with: pid, start time,
boot id, the container's PID 1 start time (`/proc/1/stat` field 22 in the
node's namespace), last health record, last phase, the stop-requested record
if any, and memory counters:

- cgroup v2: `memory.events` (`low`, `high`, `max`, `oom`, `oom_kill`,
  `oom_group_kill`), `memory.current`, `memory.peak`, `memory.max`,
  `memory.swap.events`, `pids.events`, `pids.max`, `cgroup.events`
  (`frozen`), `cpu.stat` throttling;
- cgroup v1: `memory.oom_control` (`oom_kill`, `under_oom`), `memory.failcnt`,
  `memory.max_usage_in_bytes`, `memory.limit_in_bytes`,
  `memsw.*`, `freezer.state`, `pids.*`;
- OpenVZ: `/proc/user_beancounters` failcnt columns;
- none: `/proc/meminfo` `MemAvailable`, `Committed_AS`, `CommitLimit`, and
  `vm.overcommit_memory`;
- macOS: `proc_pid_rusage` (footprint, lifetime max) and the
  `kern.memorystatus_level` jetsam level; the A1/A2 PID 1 check does not
  apply there.

At the next start, a marker present means the previous run did not exit
cleanly, and `unclean-previous` records which of these held:

| Evidence | Verdict written |
|---|---|
| WSL detected (`/proc/sys/kernel/osrelease` contains `microsoft`) and boot id differs | WSL VM stopped (`wsl --shutdown`, idle timeout or Windows restart), not a power loss; L3 has the Windows event-log step |
| Boot id differs (not WSL) | machine or VM rebooted (or power loss) while running |
| Same boot id, PID 1 start time differs | container restarted around it |
| `oom_kill` (or v1 `oom_kill`/`failcnt`) rose between the marker and now in the same cgroup | memory limit kill, **probable** (another process in the cgroup may have been the one killed; the kernel log line in B2.11 settles it) |
| A3 recorded a stop request and no `exit` followed within the stop timeout | killed after a stop request (container/systemd stop timeout) |
| `crash.log` has a record from that pid with `si_code` `SI_USER`/`SI_TKILL` | fatal signal **sent by `<comm>`** (A5 sender chain), not a crash |
| `crash.log` has a record from that pid (any other `si_code`) | crash, see crash.log |
| The B2.11 audit log or kernel log has a seccomp line (`type=1326`) for that pid | killed by a seccomp filter (`KILL_PROCESS`), status 159 on x86_64/aarch64; see A5 |
| macOS: a memorystatus/jetsam line names the previous pid (below) | killed by jetsam (macOS memory pressure), with the reason the line gives |
| None of the above | killed by SIGKILL or power loss with no other trace; the next sources are the B2.11 kernel log and the host step L3 on Linux, and B4.2 (the unified log) on macOS |

**Kernel lines about the dead pid.** At the same start, the node reads
`/dev/kmsg` (or, when that is not readable, `journalctl -k` for the last
boot and the previous one) and copies into `unclean-previous` every OOM-kill,
segfault, `hung_task` and `Killed process` line that names the previous
run's pid, before the ring buffer can wrap. If neither is readable it
records `kernel-log=unreadable (<errno>)`, and L3 is the step that gets it.
On macOS there is no kernel ring: the node runs, on a background thread so
start-up does not wait for it, `log show --style syslog
--start <marker's last health time − 60 s> --end <now> --predicate
'(subsystem == "com.apple.kernel" OR process == "kernel") AND (eventMessage
CONTAINS "memorystatus" OR eventMessage CONTAINS "jetsam")'` with a 10 s
timeout, and copies the lines naming the previous pid (jetsam lines print
it as `pid <n>` or `[<n>]`). A timeout or an empty result is recorded as
such, and the verdict then falls to "none of the above" with B4.2.

A counter that went **down** means the cgroup was recreated; the verdict
says so and does not treat a counter reset as proof of anything. A kill
by a parent cgroup's limit does not show in the node's own cgroup; the marker
also records the counters of each ancestor cgroup it can read, and states
"ancestors not readable" when it cannot.

### A3. Signals: who sent what

The non-fatal signals below are installed with `SA_SIGINFO` through
`signal-hook-registry` (already in the lockfile), before anything else in
`main()`. The fatal set (A5) is **not**: registry 1.4.8 sets no
`SA_ONSTACK`, refuses SEGV/ILL/FPE, passes no `ucontext` and chains its own
handlers first, so A5 installs those with raw `sigaction(SA_SIGINFO |
SA_ONSTACK)`.

| Signal | Action |
|---|---|
| TERM, INT | Record, then request a clean stop (D1 order). A second one within 5 s is recorded and ignored. A third writes a pre-formatted record straight to the pre-opened `runs.log` fd, with the A11 node counters since the last hourly count line appended by plain atomic loads and the signal-safe integer formatting A5 uses (crashes R12-1), and calls `_exit(10)` — no `die()`, no flush, nothing that can block. |
| HUP | Record, reopen `debug.log` and every diag file, keep running — today's behaviour (about `main.rs:3283-3296`), which logrotate `postrotate` scripts rely on. HUP never stops the node. |
| QUIT | Record, write a task and thread dump (A17) to an incident, then clean stop. |
| USR1 | Record, write a health record and an incident now; keep running. |
| USR2 | Record, reopen all log files (for logrotate copytruncate users); keep running. |
| TSTP, TTIN, TTOU | Record. With a controlling terminal and a parent other than PID 1, then raise SIGSTOP, so shell job control (Ctrl+Z, `fg`) still works. With no controlling terminal (`-daemon`, systemd, Docker) or `getppid() == 1`, record and ignore: nobody could send the CONT, so stopping would hang the node for good. |
| CONT | Record the resume and how long the node was stopped (monotonic clock against the TSTP record, or against the last health tick when the stop came as an uncatchable SIGSTOP). This row covers `kill -CONT` only: a cgroup thaw (`docker unpause`, `cgroup.freeze` 0, `freezer.state`) sends no signal, so a freeze is caught by the A17 watchdog's lateness check instead. |
| PIPE | Ignored, counted, the count is in health. |
| XCPU, XFSZ, PWR, ALRM, VTALRM, PROF, STKFLT, IO | Record only, then restore the default action and re-raise, so the exit status is the true 128+N. |
| SEGV, BUS, ILL, FPE, ABRT, TRAP, SYS | A5. |
| KILL, STOP | Cannot be caught; A2 and B2 show them. |

**PID 1.** When `getpid() == 1` (a container started without `--init`), the
kernel ignores a re-raised signal that has no handler, so the node would keep
running after a SEGV. In that case A3 and A5 call `_exit(128 + signo)`
instead of re-raising, after the record is written. `runs.log` `start`
records `pid1=yes`, and B2.3 reports "node is PID 1, no --init".

Each record has `si_signo`, `si_code` decoded (`SI_USER` kill, `SI_TKILL`
tgkill, `SI_QUEUE`, `SI_KERNEL`, and the fault codes), `si_pid`, `si_uid`,
and — read **inside the handler** with `open`/`read`/`close` into fixed
buffers, which are async-signal-safe — the sender's `comm`, the first 256
bytes of `cmdline`, and its parent chain up to four levels. The handler
stores the raw bytes in memory only; the writer thread masks them before
anything reaches a file, by the §6.2 step 3 argv rule: for an `irondivid`
sender the argv allowlist; for an `irondivi-cli` sender the allowlisted
options and the method name only, with every later positional argument
replaced by `<arg>` (`irondivi-cli walletpassphrase <arg> <arg>`); for any
other sender only the basename of
`argv[0]` with every further argument replaced by `<arg>` (a sender is often
`kill`, a shell or a script whose arguments can hold anything, such as
`irondivi-cli walletpassphrase <passphrase>` run by a cron job). On macOS the sender's path
is read with `proc_pidpath` and its parent with `proc_pidinfo`, both outside
the handler on the writer thread, with `sender=gone` when it has exited. A sender that has already
exited is recorded as `sender=gone`; one whose `/proc` entry cannot be read
as `sender=hidden`. `SI_USER` with `si_pid=0` is recorded as
`sender=outside-pid-namespace` — the container's host (`pct stop`,
`docker stop`, `lxc-stop`, the host's OOM handling is not a signal) — which
is the commonest container case and is never written as "kernel".

### A4. Panics and background tasks

- A panic hook writes, synchronously, to `crash.log` and `runs.log`: thread
  name, location, message (wallet values already wrapped by A11), a
  backtrace captured with `Backtrace::force_capture`, the debug ring
  (A8), and the A11 node counters since the last hourly count line
  (crashes R12-1). Then the default hook runs.
- Main-thread panic exits 101: `main()` runs `block_on` inside
  `catch_unwind` (commit 70cb5785; the only `catch_unwind` in the node,
  held by `tasks_lint`); after the hook
  has written its record, the caught panic forgets the runtime without
  dropping it, writes "Error: the node's main task panicked", calls
  `flush_log()` and `libc::_exit(101)`, so neither the runtime's
  drop nor the C++ destructors can hang the exit. `catch_unwind` skips
  the runtime's drop but not the unwind of `async_main` (`:3237`) itself,
  which drops what that future owns before `catch_unwind` returns
  (crashes R14-1). Every `Arc` a spawned task also holds survives, and no
  `Drop` in the tree waits, except in one case: a panic early in
  `async_main`, after the databases are open and before any task holds a
  clone, drops the block store, and the RocksDB close waits for its
  running background jobs. That wait is bounded on a responsive disk, so the exit is slow, not
  hung, and the A4 record is already on disk. The choice: the hook does
  not flush and `_exit` on the main thread, because it cannot tell a
  panic that a `catch_unwind` on that thread will catch and handle
  (the RPC and test seams) from one that ends the node; the slow close is
  accepted, and the §10 S1 test times it. A panic on any other
  thread unwinds that thread only.
- Every `tokio::spawn` in the node is replaced by one of:
  `spawn_critical(name, fut)` — the node cannot run without it (sync, chain,
  RPC, P2P listener, staker when staking is on); its error or panic goes to
  `die(10, "<name>: <error>")`; or `spawn_supervised(name, fut)` — its error
  or panic is written to `events.log` with the name and counted in health.
  A lint test fails on a bare `tokio::spawn`/`std::thread::spawn` in node
  crates. (As built, deb9295f: irondivid only; the node crates are held
  by a ratchet, see Revision 16 changes.)

### A5. `crash.log` — fatal signals

Handler for SEGV, BUS, ILL, FPE, ABRT, TRAP, SYS:

1. Writes fixed fields first, with `write(2)` to a pre-opened fd, from
   pre-formatted buffers: signal, `si_code`, `si_addr`, thread id and name
   (from a per-thread table filled at thread start; foreign threads read
   `/proc/self/task/<tid>/comm`), PC, SP, FP from `ucontext`. When
   `si_code` is `SI_USER` or `SI_TKILL` (a `kill -SEGV`, `kill -ABRT` from
   another process), the signal was sent, not raised by a fault: the record
   says `sent=yes` and adds the A3 sender fields (`si_pid`, `si_uid`, the
   sender's `comm`, `cmdline` and parent chain, read the same way into fixed
   buffers and masked later by the writer), and the A2 and B2.14 verdict is
   "sent by `<comm>`", not "crash". A signal the process sent itself (`raise`,
   `abort`) has `si_pid` equal to its own and stays a crash.
2. A frame-pointer walk, each frame checked for alignment and for lying
   inside the thread's stack range (recorded at thread start for Rust and
   tokio threads; for foreign threads, the range from the `/proc/self/maps`
   copy taken at start and refreshed every health tick into a static
   buffer), at most 128 frames.
3. A **filtered** dump of up to 16 KB of stack from SP, bounded by the same
   range, so the stack can be unwound offline against the unstripped binary
   (A16) even where frame pointers are missing. The raw stack is process
   memory: a thread that crashes while signing, decrypting the wallet or
   deriving a key can hold secret scalars, nonces, passphrase or seed bytes
   in its top 16 KB, which look like random words that no §6.2 pattern can
   catch. So the handler filters each word **before** it is written: a word
   is kept only when its value points into an executable mapping of the
   saved maps copy (item 4; a possible return address, recorded with its
   mapping index) or into this thread's own stack range (a saved frame
   pointer or stack address); every other word is written as the fixed
   marker `--------`. Offline unwinding needs only those two kinds of word.
   On a 64-bit target a random secret word falls into the kept ranges with
   a chance of about the kept size over 2^47, far under 2^-20 per word. On
   the 32-bit targets (armv7, i686) that chance is not negligible (a few MB
   out of 4 GB), so there the filtered words go not into `crash.log` but
   into a separate `diag/crash-stack.bin` (mode 0600, kept on the machine,
   replaced by the next crash), which diag packages only when the user
   says yes to the §8.2 item "raw stack words (32-bit build)", off by
   default and no on a run without a tty; `crash.log` holds the frame
   walk (item 2) either way. A §6.3
   canary test crashes a thread inside a signing path that holds a canary
   key and passphrase and checks the package for them in every encoding
   (§10).
4. The saved `/proc/self/maps` copy (so addresses can be resolved).
5. The debug ring (A8), read without locks from its fixed buffer, and
   the A11 counted-list counters since the last hourly count line, read
   with atomic loads (crashes S1).
6. Chains to the previously installed handler (so Rust's stack-overflow
   message still prints), then restores the default action and re-raises for
   the true exit status (`_exit(128 + signo)` when PID 1, A3).

**Order and re-entry.** The record is written **before** the saved handler is
called, because Rust's handler aborts. A static atomic holds the crashing
thread id: a second fatal signal on the same thread (the handler itself
faulted) goes straight to `SIG_DFL` and re-raise; a fatal signal on another
thread waits at most 2 s for the first to finish, then does the same.

**Seccomp.** A seccomp filter (a kernel list of system calls a process may
make, set by Docker, systemd `SystemCallFilter=` or a sandbox) acts on a
forbidden call in one of four ways, and only one of them reaches this
handler:

- `RET_TRAP`: the kernel sends SIGSYS; this handler runs and the record adds
  `si_syscall` and `si_arch`, which are filled only for this action.
- `KILL_PROCESS` (Docker's and systemd's default): the whole process dies at
  once with status 159 (SIGSYS) on x86_64/aarch64 and no handler runs. The
  evidence is the A2 marker left behind, the status in the parent's or the
  supervisor's record (B2.5), and the kernel's audit line `type=1326` with
  `syscall=` for the pid, which B2.11 collects from the audit log or the
  kernel log. That line is written only when `kill_process` is in
  `/proc/sys/kernel/seccomp/actions_logged` (the default); B2.18 records
  that file.
- `KILL_THREAD`: only the calling thread dies, silently. The A17
  vanished-thread record and the same audit line are the evidence.
- `ERRNO`: the call fails with an error code; it shows as an ordinary error
  in the debug ring (A8) and the `runs.log` reason.

A `crashtest` case runs the node under a filter for each of `KILL_PROCESS`
and `KILL_THREAD` and asserts what each leaves (§10).

**Allocation failure.** The global allocator is wrapped: a null return
writes a pre-formatted record `alloc-null size=<n>` to `crash.log` and
`runs.log` from fixed buffers, then returns null. Rust's
`handle_alloc_error` then prints "memory allocation of N bytes failed" and
aborts, so the process ends as SIGABRT (134) through this handler, and the
crash record names the `alloc-null` record just before it. A C++
`std::bad_alloc` inside RocksDB is not seen by that wrapper; it also ends in
`abort()` and is recorded here as SIGABRT (134), with the RocksDB frames in
the stack and no `alloc-null` record.

**macOS.** `/proc` does not exist, so the macOS build records: thread names
with `pthread_getname_np` at thread start into the same table; the dyld
image list (`_dyld_image_count`/`_dyld_get_image_header`/slide) copied at
start in place of `/proc/self/maps`; PC/SP/FP from the Darwin `ucontext`
(`__ss.__pc`/`__rip`). A macOS `crashtest` assertion checks the record
resolves against the dSYM (A16).

**Alternate stacks.** Every thread the node creates itself (std threads
through a wrapper, tokio through `on_thread_start`) gets a 64 KB
`sigaltstack`, so a stack overflow on those threads is recorded. Threads
that C and C++ code creates are reached differently on each target family
(R9-1). r9's `-Wl,--wrap=pthread_create` never reached RocksDB's threads
on the gnu targets: `--wrap` rewrites only the references in the objects
being linked, and RocksDB starts its threads through `std::thread`
(`using Thread = std::thread;`, `port/port_posix.h:166`, started at
`util/threadpool_imp.cc:382`, librocksdb-sys 0.16.0+8.10.0), whose
`pthread_create` call is inside libstdc++, a shared library there
(librocksdb-sys `build.rs:358` prints `cargo:rustc-link-lib=dylib=stdc++`,
and `.github/scripts/build-linux-gnu.sh` passes no static-libstdc++ flag).

- **gnu targets** (x86_64, aarch64, armv7hf, i686, ppc64le, s390x,
  riscv64): the executable **interposes** `pthread_create`. It defines the
  symbol and exports it to the dynamic symbol table with
  `-Wl,--dynamic-list=<file>`, whose file holds `{ pthread_create; };`, on
  every gnu target (R10-3). `-Wl,--export-dynamic-symbol` is not used: it
  needs binutils 2.35, and the gnu builds run in ubuntu:20.04
  (`.github/scripts/build-linux-gnu.sh:2`), whose binutils the reviewers
  give as 2.34 (§10 item 6 records the version). The dynamic linker then
  binds libstdc++'s call, and every other shared library's, to ours. Ours
  forwards to the real one through `dlsym(RTLD_NEXT, "pthread_create")`,
  resolved **lazily on first use** and thread-safely (R10-2, crashes N2):
  the first call through the interposer, which can come from a shared
  library's constructor before `main()` runs, resolves it under
  `pthread_once` (or publishes it through an atomic pointer with
  release/acquire ordering). A call in `main()` before the first thread
  starts stays only as a warm-up. If `dlsym` returns null, or returns our
  own `pthread_create`, the interposer writes one fixed message to stderr
  with `write(2)`, allocating nothing, and calls `abort()`: forwarding to
  null or to itself would crash or loop. In ubuntu:20.04 (glibc 2.31) the
  real symbol is in `libpthread.so.0` (from glibc 2.34 it is in
  `libc.so.6`), and on i686 the default version is `GLIBC_2.1`, beside an
  older `GLIBC_2.0`; that `dlsym` picks the right one on each is checked
  in §10 item 5. Its start
  routine (the trampoline) first calls `sigaltstack(NULL, &old)` and
  installs the 64 KB stack only if the thread has none, then calls the
  real start routine. On gnu it is the single installer for every thread
  that goes through `pthread_create`, std and tokio threads included, so
  no thread gets two. Rust std's own per-thread handler, which runs when
  a std thread starts, finds the alternate stack already installed and
  installs none of its own (crashes N3). That is the reviewers' reading of
  std's `stack_overflow.rs`, not checked here because rust-src is not
  installed; the §10 item 5 headroom test runs on a std thread, so a std
  change that installs a second, smaller stack is caught. **Failures**
  (R10-2, crashes N2): the interposer allocates the 64 KB stack and the
  trampoline's argument block before the real call (the trampoline frees
  the stack unused if the thread already has one). If the stack
  allocation fails, the thread is still created, with no alternate stack,
  and its A5 table entry says so; A17 records it `no stack: alloc
  failed`. If the real `pthread_create` returns an error, the interposer
  frees the stack and the argument block and returns that error
  unchanged. This needs no packaging change; linking libstdc++
  statically would change the binary's dependencies and needs a release
  decision, so it is not taken.
- **musl targets**: the binary is static, so there is no `dlsym(RTLD_NEXT)`
  to forward to; `-Wl,--wrap=pthread_create` stays, and there libstdc++
  is linked into the same image, so the wrap reaches RocksDB's threads.
  Its start routine makes the same "install only if none" check, and
  the `--wrap` path follows the same two rules as the gnu interposer: if
  the stack allocation fails, the thread is still created and A17 records
  it `no stack: alloc failed`; if the real call (`__real_pthread_create`)
  returns an error, the wrapper frees the stack and the argument block
  and returns that error unchanged.
- **macOS**: dyld's two-level namespace binds each dylib's
  `pthread_create` to libSystem by name, so a definition in the
  executable does not catch calls from dylibs, and there is no `--wrap`.
  Only std threads (through the wrapper) and tokio threads (through
  `on_thread_start`) have an alternate stack; no C++ thread has one. On
  macOS that matters only for the A5 overflow record: an overflow on a
  C++ thread gives no A5 record there (§10 item 5). It does not limit
  A17, which on macOS sends no signal and walks every thread (R10-1).

**The main thread** (crashes N1). Start-up runs on the main thread:
`main()` (`bin/irondivid/src/main.rs:3020`) calls
`runtime.block_on(async_main(...))` at `main.rs:3195`, so the start-up
phases A1 watches are polled there. Rust std gives the main thread an
alternate stack of its own, which the reviewers read as small (about 8 KB
on x86_64 and 16 KB on aarch64; not checked here, to verify in §10 item
5), too small for the A5 walk and the A17 handler. So on every Linux
family, gnu and musl, the first statement of `main()`, before any thread
starts, installs the node's own 64 KB alternate stack on the main thread
and enters it in the A5 table like any other thread's. It is never
freed: the node ends through `exit_after_stop` (`main.rs:3216`), which
forgets the runtime and calls `libc::_exit` (`main.rs:3234`). `main()`
can also end before that: `std::process::exit` at `main.rs:3048` to
`:3150` (start-up and daemonise errors), the `?` on the runtime build
at `:3189`, and a panic in `async_main` while `block_on` (`:3195`) polls
it on the main thread (crashes R12-2). Since 70cb5785 that panic is
caught by `catch_unwind` (`:3194`-`:3196`) after the A4 hook has run;
the runtime is forgotten, "Error: the node's main task panicked" is
written, then `flush_log()` and `libc::_exit(101)` (`:3203`), so std's
clean-up does not run on that path and the node's stack stays as
installed (crashes R13-1). The first two run std's own clean-up,
which, by the reviewers' reading (std's source is not in this tree; to verify in §10 item 5), disables
the main thread's alternate stack and unmaps the region std mapped for
it. That is harmless: the node installs its stack over std's with
`sigaltstack` and never unmaps std's region, so std unmaps only its own
mapping and nothing is freed twice. It is not
installed on macOS, where A17 does not signal (R10-1) and the main
thread keeps std's stack for the A5 overflow record.

**Freeing the stack** (crashes note 2). The trampoline frees its stack
when the real start routine returns. A thread can also end through
`pthread_exit` and never return, so when the stack is installed a
`pthread_key_create` key is set to it, and the key's destructor frees it.
Whichever runs first disables the stack (`SS_DISABLE`), unmaps it and
clears the key, so the other finds nothing to free. A stack installed in
`on_thread_start` is disabled and unmapped in `on_thread_stop`, which
frees only a stack `on_thread_start` installed. Thread churn does not
leak stacks (§10 item 5).

**Headroom** (crashes note 3). The 64 KB must hold the kernel's signal
frame (larger on a CPU with wide vector registers), the A5 handler with
its 128-frame walk, the A17 stack-signal handler, and a nested fatal
handler if a fault hits inside one of them. §10 item 5 measures it with
a guard pattern: the stack is filled with a known pattern, each handler
runs at its deepest, and at least half of the 64 KB must be left
untouched (to measure). If it is not, the stack grows; the walk is not
shortened.

**Threads with no alternate stack** (R9-2). On Linux A17 does not signal
such a thread; it records it by its `comm` as `no stack: no alternate stack`
and marks it **expected** or **unexpected**. Expected on gnu: threads
that glibc starts through its internal alias of `pthread_create`, which
interposition does not see (`SIGEV_THREAD` timer threads, `getaddrinfo_a`
helpers), and threads made with a raw `clone`; on gnu a thread named
`rocksdb:*` or with one of the node's own thread names is unexpected.
A thread whose stack allocation failed is recorded `no stack: alloc
failed` instead (R10-2). macOS has no such record: A17 sends no signal
there and walks every thread (R10-1). The mark comes from
`comm`, which is approximate: a helper thread keeps the name of the
thread that started it until it renames itself, so the mark is a hint
for the reader, never a verdict.

Our record is written first; then Rust's own handler prints "thread
'<name>' has overflowed its stack" and aborts, so a Rust-thread overflow
ends with status **134**, not 139. An overflow on a thread with no
alternate stack (macOS C++ threads such as RocksDB's, and the gnu threads
above) cannot run the handler. That case still leaves the A2 marker,
exit status 139 and the kernel's segfault line (B2.11), which together
name the thread's `comm` (`rocksdb:low`, …); the debug ring and maps are
lost. A `crashtest` build feature (never in release builds) provides
hidden test paths for SEGV, abort, Rust-thread overflow and
foreign-thread overflow, and the test suite asserts what each leaves
behind.

To make RocksDB overflows rarer on musl, whose default thread stack is
128 KB, the musl targets link with `-Wl,-z,stack-size=8388608`, which
raises musl's default thread stack for RocksDB's threads to 8 MB. When an
overflow still happens on a thread with no alternate stack, L5's second
step resolves the kernel segfault line's `ip`/`sp` against the A16
unstripped binary.

**Frame pointers.** All 12 release targets build with
`-C force-frame-pointers=yes` (target rustflags in `.cargo/config.toml`), and
RocksDB with `CXXFLAGS=-fno-omit-frame-pointer` (librocksdb-sys builds it
from source with `cc::Build`, which honours `CXXFLAGS`). The prebuilt Rust
standard library is not rebuilt (that needs nightly `-Zbuild-std`), so walks
through std frames can stop early; the filtered stack dump (A5 item 3)
covers that. A release
check disassembles a known function in each target's binary and fails if the
frame-pointer prologue is missing.

**Non-dumpable process (D5).** From the start of `main()` the node is
non-dumpable on Linux (`PR_SET_DUMPABLE` 0, D5), so the A5 re-raise
leaves no core under any `core_pattern`, and a shell no longer reports
"core dumped"; the A2 verdict is taken from the signal, never from
`WCOREDUMP`. Since b2dbea56 `disable_core_dumps()` always runs the
`prctl`, even when `setrlimit(RLIMIT_CORE)` fails (a seccomp `ERRNO` on
`prlimit64` no longer skips it), and returns the first error. The flag
survives the `-daemon` forks (a `fork` is not an `execve`). It is **not**
permanent: the kernel resets it to `fs.suid_dumpable` on `execve` and on
any credential change (`commit_creds`, when the effective or filesystem
uid or gid or the capabilities change). irondivid changes no credentials
today (none of the ten credential calls below is in the tree), so two
guards keep it that way: A6 reads `PR_GET_DUMPABLE` every health tick
and, if it is ever non-zero, sets it to 0 again and writes an
`events.log` line `dumpable restored (was <n>)` (the check is **done** in
f5f3bce5 as `private_files::restore_non_dumpable`, and since 856f7376 runs
every 60 s on its own `dumpable-check` std thread, started before the
tokio runtime and the wallet; it logs a `warn!` on a reset and an
`error!` if the reset fails until A6 and `events.log` exist; then A6 sets
its interval and its line goes to `events.log`, but it stays on that
thread, so a stalled runtime cannot stop it); and a
lint test, **done** in 97c4bceb as
`bin/irondivid/tests/credential_calls_lint.rs` (beside the
`process::exit` grep), walks `bin/`, `crates/` and `tools/` and fails on
any of the ten **credential calls** `setuid`, `setgid`, `setresuid`,
`setresgid`, `setreuid`, `setregid`, `setfsuid`, `setfsgid`, `capset` and
`setgroups`, in their bare, `libc::` and `nix::unistd::` spellings, and
on `caps::set`, `caps::raise`, `caps::drop` and `caps::clear`, unless
`PR_SET_DUMPABLE` follows it later in the same function (X2). The same
file holds a self-test of the matcher (`the_lint_catches_what_it_should`)
beside the lint itself (`no_credential_call_without_pr_set_dumpable`);
both pass on hp3. The same names are used in §10 item 5 and in the item
6 release check. The lint covers the workspace's own source only; a third-party crate that changes
credentials is caught by the per-tick re-check, which is why that check
exists, and the §10 test proves it does. The
A2/A7 start record states the flag (`dumpable=0`, or the `prctl` error,
which is also a warning on the console). Two consequences are designed
for:

- **The node's reads of its own `/proc/self`.** Measured on hp3 (§10
  item 1: kernel 5.15.0-198, `ptrace_scope` 1, 2026-10-30; M2). The
  `/proc/<pid>` directory keeps the node's own uid; some files inside
  become root-owned. A non-root, non-dumpable node **can** read its own
  `stat`, `status`, `cmdline`, `limits`, `cgroup`, `mountinfo`, `maps`,
  `smaps_rollup`, `fd/`, `fdinfo/`, the `cwd`, `exe` and `root` links,
  `ns/*`, `timerslack_ns` and `task/*/{stat,status,comm}`. It is
  **refused** (EACCES) its own `io`, `environ`, `stack`, `syscall`, `mem`,
  `auxv` and `personality`, and its `wchan` reads `0` (see M3 below). Part
  A therefore uses none of the refused files: I/O figures (A1, A6, A17)
  come from `getrusage(RUSAGE_SELF)` `ru_inblock`/`ru_oublock`; the
  hardware capability words come from `getauxval(AT_HWCAP)` and
  `getauxval(AT_HWCAP2)`, not `/proc/self/auxv`; A7 reads the environment
  from the process itself (`std::env::vars_os`), not from `environ`; and
  kernel stacks and the current syscall of each thread are not available
  to a non-root node at all, so A17 records them as `refused by kernel`
  rather than leaving them out. A6 counts fds by listing `/proc/self/fd/`,
  which the measurement shows works; the `fcntl(F_GETFD)` probe from 0 up
  to `FDSize` (from `/proc/self/status`; it is the size of the fd table,
  so no open fd lies above it) is kept only as the fallback when `fd/` is
  refused, which may happen on kernels or LSM setups not yet measured, and
  the record names the source it used. What a non-root node sees on macOS,
  on other kernel versions, inside LXC and under other `ptrace_scope`
  settings is still to measure in §10 (item 1).
- **Diag's reads of the node's `/proc/<pid>`.** A non-root diag (the
  normal case, same user as the node) is another process, so the ptrace
  check applies to it. Measured on hp3 (§10 item 1), it is refused the
  node's `exe`, `cwd` and `root` links, `ns/*`, `environ`, `io`, `mem`,
  `auxv`, `personality`, `stack`, `syscall`, `maps`, `smaps_rollup`,
  `fd/`, `fdinfo/` and `timerslack_ns`. `stat`, `status`, `limits`,
  `cmdline`, `cgroup`, `mountinfo` and `task/*/{stat,status,comm}` stay
  readable. **Some refused reads do not fail.** `wchan` (and
  `task/*/wchan`) prints `0` and returns success, and `stat` as seen by
  another reader is shorter (190 bytes against 325 on hp3) because the
  kernel zeroes its `kstkesp`, `kstkeip` and `wchan` fields and the
  start/end code and data addresses. Those zeroed `stat` fields are never
  evidence of anything, for any reader (M3). Root **without**
  `CAP_SYS_PTRACE` can list `fd/` and read `timerslack_ns`, but is refused
  everything else in the refused list above (EPERM for `stack`), and its
  `wchan` also reads `0`; it is treated as the non-root reader except
  for the fd count (N4): a same-uid non-root reader is refused `fd/`
  itself, while root without the capability can list `fd/` (so it has the
  number of open fds) and is refused only `fdinfo/` and the `fd/*` links
  (so it has no fd types).
  Only root with `CAP_SYS_PTRACE` reads the full set (`mem` gives EIO at
  offset 0, which is expected and not used). So diag decides **before**
  any ptrace-checked read whether it can read the node at all
  ("readability check", M1, V6): it opens `/proc/<pid>/io` and reads its
  first bytes, and does the same for `/proc/<pid>/environ`; if **either**
  the open **or** the first `read` fails with EACCES or EPERM, the node is
  unreadable. The ownership of `/proc/<pid>` is not used: the hp3
  measurement showed the directory keeps the node's uid under D5, so an
  ownership test never fires. (The node itself uses `PR_GET_DUMPABLE`,
  never a `/proc` test.) When the node is unreadable, diag reads none of
  the ptrace-checked files, records `unreadable: node is non-dumpable
  (D5)` once, and never writes a `/proc`-sourced `wchan` or `stat` stack
  field; a `wchan` of `0` is written by the thread's `stat` state letter,
  `running` for `R` and `hidden` otherwise (M3, N3). A `wchan` value is
  evidence only when the readability check passed and the value is not
  `0`. **Root is not always enough.** Root passes the check only with
  `CAP_SYS_PTRACE` in its effective set. Default Docker and most
  Kubernetes pods drop it, so diag running as root inside such a
  container is refused too. Diag reads its own `CapEff` from
  `/proc/self/status` and records it: as root without bit 19
  (`CAP_SYS_PTRACE`) it records `unreadable: node is non-dumpable (D5), no
  CAP_SYS_PTRACE` and prints **no** `sudo` hint. **Decision:
  diag gets that data through the node, not through root.** The node
  reads it from itself and hands it over: `getdiaginfo` (A10) carries the
  health figures (fds, I/O, thread states and `wchan`), the binary path
  and hash (A1), and the environment values for the §6.2 known-value set
  in its `known_values` pages; when RPC does not answer, the A17 hang
  incident and the A1/A7 records written by the node itself carry the
  same; when RPC does not answer but the health tick does not stall
  either (a partial hang), diag asks the node for a fresh incident through
  the A17 `diag/snapshot-request` file; kernel stacks, the current
  syscall, I/O counters, `maps` and the fd table of a D5 node come only
  from that route for any reader without `CAP_SYS_PTRACE`. Diag uses the direct read only
  when the readability check passes (root with `CAP_SYS_PTRACE`, or an
  older node that is still dumpable). When it fails, the `sudo` hint B1
  prints is offered only when diag is not root and `sudo` would give it
  `CAP_SYS_PTRACE` (outside a container, or in one that has the
  capability in its bounding set, `CapBnd`); root is offered, never
  required. The node's own path record (A14) gives B1 the data dir, conf,
  cwd and binary that the refused `cwd` and `exe` links would have given.
  The B2 memory cap (diag's own collectors) and B3 are unaffected: those
  processes are diag's, not the node's.

### A6. `health.log` — how the node was doing

One line every 10 s for the first 10 minutes of a run, then every 60 s:

- process: RSS, `VmPeak`, `VmSize` (and, on 32-bit targets, `VmSize`
  against the 3 GB address space), threads, fds, sockets by state, CPU time,
  major faults, I/O as block counts from `getrusage(RUSAGE_SELF)`
  `ru_inblock` and `ru_oublock` (blocks read and written that reached the
  disk; named as block counts, not bytes; on macOS `proc_pid_rusage`
  `ri_diskio_bytesread` and `ri_diskio_byteswritten`, which are bytes and
  named so), always: `/proc/self/io` is never read, since a non-dumpable
  node is refused it (A5, K3, M2); allocator stats;
- system: cgroup counters (A2), PSI `some`/`full` for memory, I/O and CPU
  (`n/a` on kernels without PSI; PSI, "pressure stall information", is the
  share of time tasks waited for that resource), load, free memory, swap,
  data dir free space and inodes;
- on macOS, where `/proc` and PSI do not exist: footprint, lifetime peak and
  I/O bytes from `proc_pid_rusage`; thread count and states from
  `task_threads`/`thread_info`; the system memory pressure level from
  `kern.memorystatus_level` and the `memory_pressure` state in place of
  PSI; anything with no macOS source is written as `n/a (macOS)`, never
  left out silently;
- time: wall clock, `CLOCK_MONOTONIC`, `CLOCK_BOOTTIME`; the difference
  `BOOTTIME − MONOTONIC` rising means the machine was suspended; a wall
  clock jump against monotonic is recorded; the network-adjusted time offset
  and the count of headers rejected as too far in the future;
- chain: height, header height, best hash (public), sync state, peers in and
  out, blocks in flight, mempool size and bytes, RocksDB memtable and block
  cache bytes, last block received age;
- staking: enabled, the **reason** it is not staking now (wallet locked,
  not synced, no mature coins, no peers, stale tip, disabled by flag),
  wallet lock state, age of the last stake found as a bucket only (< 1 day,
  1–7 days, 7–30 days, > 30 days, never), never a time or height; stakes
  found in the last 30 days as a bucket only (0, 1–3, 4–20, > 20 — an
  exact count with the public network weight would give the wallet's stake
  weight, and so its balance), and the ratio of stakes found to
  stakes expected over those 30 days as a bucket only (< 0.5, 0.5–2, > 2,
  or "too few expected to judge" when fewer than 3 were expected). The
  node computes the expected count from own and network stake weight in
  memory and never writes it: the expected rate would give the wallet's
  share of the network weight, and so its balance. This keeps "staking but
  never finding a stake" visible; a mild shortfall inside 0.5–2× is not
  visible here by design (L12), and its second step is B6.5 `--rpc
  getmintinginfo`;
- masternode: own status (read from the own entry; the record holds the
  status word only, never the entry), `mnsync` phase;
- counters since start: panics in supervised tasks, dropped log lines,
  SIGPIPE count, lock waits over 1 s (A17), RPC calls;
- `dumpable` from `PR_GET_DUMPABLE` on every tick (Linux); a non-zero
  value is set back to 0 at once and written to `events.log` (A5
  "Non-dumpable process"); the check runs on the `dumpable-check` thread
  (856f7376) at A6's interval, so a stalled runtime cannot stop it, and A6
  reports its last result;
- the fd count's source (`fd/`, or the `F_GETFD` probe with the `FDSize`
  bound it used).

### A7. `startup/<run>.txt` — the start-up environment

One file per run, the last 20 kept, at most 64 KB each: masked argv; every
configuration key in force with its source (default, file, argument) and a
redacted value (§6.2: secrets as `<set>`/`<unset>`, addresses and paths as
pseudonyms); unknown keys by **name only**; environment variable **names**
for all, values only for an allowlist (`RUST_LOG`, `RUST_BACKTRACE`,
`MALLOC_*`, `LD_PRELOAD`/`LD_LIBRARY_PATH` as basenames, `TZ`, `LANG`,
`HOME` as a pseudonym, `IRONDIVI_*` non-secret); rlimits; seccomp mode,
`NoNewPrivs`, capabilities (from `/proc/self/status`); CPU model and
features; page size; filesystem type and mount options of the data dir;
build info (target, rustc, git sha, features, frame pointers); time zone;
the start-up working directory (absolute, from `getcwd` before the
`-daemon` chdir; packaged as a pseudonym, §6.2 paths rule), which B2.12
uses to look for core files and which goes into the A14 path record.

### A8. Log delivery and the debug ring

- Until the `running` phase, `debug.log` writes are synchronous on the
  calling thread, so nothing logged during start-up can be lost.
- After it, the non-blocking writer runs with `lossy(false)` behind a
  wrapper with a 2 s bound: if the channel stays full for 2 s the line is
  dropped and counted; the count is written to `debug.log` and `runs.log`
  (`dropped`) when the channel drains.
- `die()`, the panic hook and the stop path flush with a 2 s bound.
- **Debug ring**: an in-memory ring of the last 4096 log lines at **debug
  level for every category**, whatever the configured level, already
  redacted (A11), in a fixed buffer readable without locks. It goes into
  `crash.log`, every incident, and `getdiaginfo`. So the detail for a failure
  exists even though the user never turned on `-debug`.
- **Counted lines stay out of the ring** (consensus B4, adversarial AB1).
  Every log site on the A11 counted list that writes a line carries a
  static `counted` field in its macro (`debug!(counted = true, …)`), and
  the ring's layer drops any event whose callsite metadata has that field,
  a check made once per callsite. The drop is a per-layer filter on the
  ring's layer only (`Layer::with_filter`), never a global
  `Interest::never()` from a layer's `register_callsite`, which would
  turn the callsite off for every layer and so remove the line from
  `debug.log` as well (crashes R13-3). The `debug.log` formatter skips
  the `counted` field, so a tagged line reads there as it does today and
  the §6.2 matchers need no change (consensus N-f). The A11 hourly count lines are not
  counted sites and do reach the ring. This is chosen in addition to the
  package filter (§6.2 "Old-log lines"), not in place of it: a site that
  misses the tag still reaches the ring, so the filter runs over every
  ring copy anyway, and the tag keeps the per-event lines out of a copy
  the filter never sees, such as a `crash.log` the user mails by hand. The
  shared Connected line is not counted and stays in the ring; rule (e)
  collapses it in the package. The §10 item 6 log source scan checks that
  every counted site carries the tag.

### A9. One way out

`die(code, reason)` and the table in R3. The early exits in `main()`, the
runtime builder's `?`, and the `run_daemon` error path all call it. Errors
from argument parsing that happen before the data dir is known write to
stderr and to the A14 mirror location (which needs no data dir).
`die()` writes, with its record, the A11 node counters since the last
hourly count line (crashes R12-1), so a `die(10, …)` from a failed
critical task, the staker's included, loses no counts.

### A10. `getdiaginfo` RPC

Read-only, authenticated like every RPC; its only parameters are the
optional `diag_key` and `known_values` page described below. Returns everything in
health plus: `SyncState`, `pending_headers`, `blocks_in_flight` per peer,
`stall_counter`; `getchaintips`; orphan block and transaction pool sizes;
peers with version, services, ping, bytes, ban score and the last 50
misbehaviour records per peer (message type, height, score added); the ban
list with reasons; address-book counts by network and bucket; snapshot and
prune state; chain mode as recorded in config, database and wallet; schema
version and migrations applied; `mnsync` per asset, MN list counts by state,
winners for the next 10 blocks (every payee pseudonymised the same way,
own or not — §6.2 "Public records"), own collateral confirmations only as
"≥ required" or "< required" (a count would date the collateral block;
outpoint pseudonymised); next lottery and treasury heights; staking kernel counters
(attempts, hashes, rejects by reason) and errors; per-method counters and
error counts for RPC, Electrum, Web UI and ZMQ; Electrum client versions;
a per-thread state and `wchan` sample taken by the A17 sampler once per
call (from the node's own `/proc/self/task`, so it works on a
non-dumpable node, A5); the running binary's path, size and SHA-256 as A1
recorded them;
ZMQ dropped messages; lock-wait statistics (A17); the last 20 redacted
error messages per method (A15); the debug ring; the wallet section B2.9
describes (counts, buckets and shares only); and the node's own A11
pseudonym map for this run, **as pseudonyms only**: diag passes a fresh
random 32-byte key `k` for this one call (`getdiaginfo {"diag_key": k}`)
— **not** its run salt, which never leaves diag — and the node returns,
for each wallet pseudonym it printed this run, `HMAC(k, value)`. Diag
computes `HMAC(k, v)` for each of its own known values in memory, matches
the two, and writes the pairs (node pseudonym → diag pseudonym) to the
package; `k` and the HMACs are then discarded. Neither side's real value
nor diag's salt crosses the RPC. This lets node logs and diag files be
read together. All wallet values pass through A11.

**The `diag_key` is still secret.** With `k` and the reply, anyone could
test guesses against the node's pseudonyms. The node treats the parameter
like a passphrase: the RPC layer never logs, echoes or stores it — not in
A15 lines or stored error text, incidents, the debug ring, `events.log` or
an error reply (a malformed call is answered "invalid diag_key" with no
value) — and the node zeroes it in memory after the call. The §6.3 scan
checks for both the run salt and every `k` diag generated, in every
encoding, and fails the package on a hit. `diag --rpc getdiaginfo` (B6.5)
refuses the `diag_key` and `known_values` parameters by name, and
`--rpc-clear` is never allowed for `getdiaginfo`.

**Known values in pages.** `getdiaginfo {"diag_key": …, "known_values":
<page>}` returns the wallet's addresses, txids, labels, outpoints, own
staked block hashes, both hashes (owner and vault) of every vault script
the wallet owns or manages, the masternode collateral, the A15 sent-from-here
txids and the values of the node's own environment (read in the process,
with the same exclusions as step 1; diag cannot read
`/proc/<pid>/environ` of a non-dumpable node, A5) that §6.2 step 1 needs, 1000 at a time, read from the wallet's
in-memory index and the `diag/sent-txids` file with no rescan. On a node
with A10, diag makes no other wallet call (§6.2 step 1); the values stay in
diag's memory and are never written.

**Who may read the pages.** The pages hold the node's environment and the
wallet's values, which RPC credentials never exposed before. So:
(a) the environment page never carries the **value** of a secret-named
variable — any name matching the §6.2 step 2 `k=v` name list
(`*PASSWORD*`, `*PASS`, `*SECRET*`, `*TOKEN*`, `*KEY*`, `*_URL` with
credentials, `DATABASE_URL`, `AWS_SECRET_ACCESS_KEY`, …). Instead it
carries `HMAC(k, value)` (HMAC-SHA256), the value's length in bytes
and a 16-bit **tag**, under the same per-call `diag_key` `k` (P3, R2).
The tag is built in two steps (N1). First, an internal rolling hash
R_b over the **whole** value: a polynomial hash modulo 2^61-1 whose base
b is derived from the subkey k2 = `HMAC(k, "tag")`; R_b is never
truncated, sent or written. Second, the tag is SipHash-2-4 keyed with k2
over the 8 bytes of R_b(value), truncated to 16 bits. The rolling hash
lets diag move its window by one byte in O(1); the SipHash output is
what is sent. It lets diag skip almost every window without computing an
HMAC. r9 sent 16 bits of R_b itself, and that was invertible: R_b is
linear in the value's bytes, the caller chooses `k` and so knows b, and
each call gave 16 bits of a linear equation in the value, so enough calls
solve for it. r8's tag over the first 8 bytes let a caller test guesses
of those bytes on their own. The r10 tag is a keyed PRF of the whole
value: a caller learns from it only whether a guess of the **whole**
value matches, which the HMAC already tells it. There is no fallback to
a prefix tag. Its cost is to measure in §10 item 1 on the reference Pi;
if it fails B5's bound, that is a blocker for (a), to be revisited in
its own revision, not a reason to send a weaker tag. Step 2 masks such a value only where it is
printed beside its name; the same token pasted alone into a command line,
a component log or a shell history would otherwise go out, so the r6
claim that nothing is lost by omitting the value was wrong. With the
HMAC, the length and the tag, diag finds the value without ever holding
it. Over all collected text it takes **every byte offset** as the start
of a window of that length (R2, W6). At each offset it rolls R_b over the
window (O(1) a byte) and computes one SipHash-2-4 over those 8 bytes, and
only where the tag matches (about one offset in
65,536 by chance) does it compute `HMAC(k, w)` for the window `w`. It
does the same over four **decoded views** of the text, because a secret
is often pasted encoded: (1) base64 — the credential after
`Authorization: Basic` or `Bearer`, and any run of base64 or base64url
(`-`, `_`) characters at least ceil(4L/3) long for a value of L bytes,
padded or not, decoded at each of the 4 start offsets (S4),
with a decoded `user:secret` also split at its first `:`; (2)
percent-decoding, with `+` read as a space, of URL and form text; (3)
JSON string unescaping (`\"`, `\\`, `\uXXXX`); (4) backslash and shell
unescaping (`\x`, `'…'`, `"…"`). A match in a decoded view replaces the
whole encoded span it came from. A match is replaced by
`<secret-env:NAME>` and counted in §8.2. This finds a secret glued to a
flag (`-p<secret>`), one inside a longer word, and one whose first or
last character touches a letter, all of which r7's token-boundary
windows missed. The cost per secret is one rolling-hash step and one 8-byte
SipHash-2-4 per byte of collected text (per decoded view too), plus a
rare HMAC; that it fits B5's bound on the reference Pi is to
measure in §10 (items 1 and 5). Values
shorter than 8 bytes are not sent as an HMAC at all (a short value is
easy to guess from its HMAC and matches by chance in normal text); for
those the step 2 name-beside rule is the only cover, and §8.2 lists the
variable's name with "short secret, masked only beside its name". **The
limit**, stated in §8.2 too: a secret in any other form is not found —
hex or UTF-16 encoded, compressed, encoded twice (base64 inside
percent-encoding), split across lines, or changed (cut short,
upper-cased, hashed). This gap is **silent**: §6.3 runs the same match,
so it cannot catch what this one misses, and r7's claim that the gap was
"a known one, not a silent one" was wrong. Diag keeps `k` and these HMACs in memory only (never on
disk) until the package is sent or abandoned, because the §6.3 scanner
runs the same window match again at preview and at submit, after any
user edit, and fails packaging on any remaining hit; then it discards
them.
(b) The node serves `known_values` (every page, wallet values included)
only to a caller on the JSON-RPC transport whose peer address is loopback
and whose request carries no proxy header (V2). The r6 text said the
`getdiaginfo` handler could test `addr.ip().is_loopback()` because the
access middleware has `ConnectInfo<SocketAddr>` (server.rs, about line
1810). Checked against the code, it cannot: the middleware only calls
`access.peer_allowed(addr.ip())` and does not pass the address on;
`handle_rpc` (about line 1397) goes through `handle_http_body_for(grant,
body)` to `dispatch(&self, method, params)` (line 500) with no caller
argument, and `handle_request(&self, request)` (line 489), which the Web
UI's `call()` (divi-webui `lib.rs:547-556`, through `spawn_blocking`) and
the Electrum backend use, has none either. So r7 adds one:
`struct Caller { transport: Transport, peer: Option<IpAddr>, proxied:
bool }` with `Transport` one of `JsonRpc`, `WebUi`, `Electrum`,
`Internal`. The access middleware, which already holds the
`ConnectInfo`, inserts a `Caller { transport: JsonRpc, peer:
Some(addr.ip()), proxied }` into the request's extensions, where
`proxied` is true when any `Forwarded`, `X-Forwarded-For` or `X-Real-IP`
header is present. Two handlers serve JSON-RPC, and both take it as
`Extension<Caller>` the way they already take `Extension<MethodGrant>`
(W5): `handle_rpc` (server.rs about line 1397, the `/` route at about
line 1721) and `handle_wallet_rpc` (about line 1484, the
`/wallet/:wallet_name` route at about line 1723, whose prefix the
middleware strips at about line 1792). Both go through the same helpers,
and the `Caller` is passed through each one: `rpc_reply` (about line
1411), `handle_body` (about line 1439, which runs the call under
`spawn_blocking`, so the `Caller` is moved into that closure),
`handle_http_body_for` (about line 1536) and `dispatch` (line 500). A
request that reaches either handler with no `Caller` extension (a route
added later without the middleware) is refused `known_values is local
only`, never served. `handle_request` gains a `caller`
argument: the Web UI `call()` passes `Transport::WebUi` with
`peer: None`, the Electrum backend `Transport::Electrum`, and tests
`Internal`. The `getdiaginfo` handler serves `known_values` only when
`transport == JsonRpc`, `peer` is `Some` loopback address and `proxied`
is false; anything else, including `peer: None`, a missing or unknown
`Caller`, gets the
error `known_values is local only` and the rest of `getdiaginfo` as
usual. **What this does not catch:** a reverse proxy on the same host
that forwards remote callers to the loopback port and strips those three
headers looks exactly like a local caller. That set-up already hands
remote callers the full RPC; the plan says so in the `getdiaginfo` help
text rather than claiming to detect it. Diag runs on the node's host or
inside its container, so it reaches the node over loopback **when the
node listens there** (W2): it connects to `127.0.0.1` or `::1` whenever
the node's `rpcbind` setting or its listening sockets (B2.16) include a
loopback address, whatever `rpcconnect` says. A node bound only to a LAN
address (`rpcbind=192.168.1.10`) cannot be reached over loopback, and
answers diag on that address with `known_values is local only`. Diag
then falls back to the pre-A10 wallet calls (§6.2 step 1); the
environment values are then not available unless diag is root and can
read the node's `environ`; and `00-SUMMARY.txt` and the preview name the
masking that is degraded (§6.2 step 1).

### A11. Redaction at the source

Wallet-linked values are typed, not just strings: `WalletTxid`,
`WalletAddress`, `WalletAmount`, `WalletLabel`, `OwnOutpoint`,
`OwnBlockHash` (a block this wallet staked), `SwapId`. These types are
for **wallet context** only — a line that says what the wallet did ("stake
found", "sent", "received"). Where a value appears as an entry of a public
record or list (a tip or reorg hash in A12, a header in an A13 bundle, a
payee in the A10 winners list, a txid in a block or the mempool), the
public type is used whatever the owner (`BlockHash`, printed in clear with
the `blk:` prefix; a public txid or address, which §6.2 pseudonymises for
every entry alike), so ownership never changes how a public entry is
printed (§6.2 "Public records"). Their `Display` and
`Debug` print a per-run pseudonym (`wtx-3f2a`, `wad-91c0`, `amt-<magnitude
bucket>`), an HMAC under a random key that exists only in the node's memory,
so the same value reads the same within one run and cannot be linked across
runs or reversed. `-logwalletdetail=1` (off by default, warned at start)
prints the real values for the user's own debugging. Diag detects it from
the A7 record of each run and treats **every** Part A file and incident
written during such a run (the debug ring copies in `crash.log`,
incidents and `getdiaginfo`, `debug.log` itself) exactly like a pre-A11
log: the §6.2 step 2 "Old-log lines" rule applies to them in full, not only
the known-value replacement, because known values miss anything not in the
wallet file. This includes the **A14 mirror copies** of `runs.log`,
`crash.log` and `events.log` lines written during such a run: diag matches
them to the run by run id and applies the same rule. Since r13 the rule
also runs over the log copies of every other run (the ring sections of
`crash.log`, the incidents and `getdiaginfo`, the incident `debug.log`
tails and the mirrors; §6.2 "Old-log lines" lists every input,
consensus B4); what a `-logwalletdetail=1` run adds is that its other
Part A records are treated the same way. **The flag is
start-only.** It is read from the command line and config at start;
`setlogconfig` refuses it ("logwalletdetail can be set only at start"),
and the refusal is recorded in `events.log`, so a run's A7 record is the
whole truth about it. Electrum scripthashes are logged through the same wrapper.

Edit sites named by the reviewers (all to be converted; the A11 test below
finds any missed): `staker.rs:722`, `staker.rs:812`; the staker's own-UTXO
lines `staker.rs:1475` "Hashproof SUCCESS for UTXO {}:{} value={},
timestamp={}", `:1488` "Sample UTXO {}:{} value={} age={}s ({:.1}h)
block_time={}", `:1509` "Skipping UTXO {}:{} - hashproof timestamp {} <=
MTP {} (diff: {}s)" and `:1520` "Found valid stake for UTXO {}:{} at
timestamp {} (MTP={}, current_time={})" (O1; they are also on the staker
counted list below); `divi-rpc wallet.rs:1929` "Sent {} DIVI to {}
(txid: {})", `divi-rpc wallet.rs:3174` "Funded vault {} with {} DIVI (txid: {})", `divi-rpc wallet.rs:3566`
"Allocated {} DIVI for masternode collateral (txid: {})" and `divi-rpc wallet.rs:4170`
"Sent {} DIVI from account '{}' to {} (txid: {})" (also counted, A11
"Own transactions log like peer transactions"); `main.rs:1719`
"Unconfirmed wallet tx {} cannot be resubmitted ({}); forgetting it";
the former sites `divi-rpc wallet.rs:2476`, `wallet.rs:3746` and
`main.rs:2345` ("Transaction {} submitted", as of f67b0984) were removed
in 09cb18e4 and stay edit sites only for the §6.2 "Old-log lines" rules
over older logs; `mempool.rs:736`; `wallet_db.rs:543`,
`1749`, `2159`, `2702`, `2835`, `2928`, `3237`; the `masternode.conf`
collateral parse in `core_files.rs:141`. Invalid-value warnings for config
keys (about `main.rs:446`) print the key name and the reason, never the value.

**Own blocks log like peer blocks** (O1: consensus B2, privacy P1,
adversarial Z1/Z2). r10 assumed an own staked block gets the same chain
lines as every other block. In the code it does not:

- `Node::accept_block` (`crates/divi-node/src/node.rs:1515`), which writes
  "Accepted block {} at height {}" (`node.rs:1551`) and "Block {}
  reorganised the chain at height {}" (`node.rs:1538`), is called only
  from `crates/divi-node/tests/mempool_reorg.rs:248`; neither line is
  written in production.
- A peer's block is written "Received block {} from peer {}"
  (`crates/divi-network/src/sync.rs:1240`), then "Connected block {} at
  height {}" (`sync.rs:1322` in `try_connect_blocks`, `:1446` in
  `try_connect_blocks_by_prev`) or "Connected orphan block {} at height
  {}" (`:2393`). On a synced node `try_connect_blocks` (`sync.rs:1293`,
  called from `handle_block` at `:1264` for every peer block) wrote
  "Block sync complete at height {}" at info, the default level, after
  every peer block it connected (`:1348` before 1fd59a5c); an own block
  never passes there, so in a default log the heights skipped each own
  stake (privacy R12-1). Since 1fd59a5c it is written only on the
  transition into Synced, and since 8e4bfaca only after a lag of more
  than `CAUGHT_UP_LAG` blocks (item 8). The second accept in `try_connect_blocks_by_prev`
  (`:1486`) writes no Connected line, only "Chain reorganized! Height
  changed from {} to {} after accepting block {}" (`:1499`) when the
  height grew. A failure is "Failed to connect block {}: {}" at error
  (`:1330`, `:1455`).
- The own block goes through `Staker::accept_own_block`
  (`crates/divi-node/src/staker.rs:788`), which writes no Connected line,
  so at `-debug` its height is the one gap among the Connected heights.
  It writes "Reorg detected during self-accept of staked block {} (fork
  height {})" (`:797`, warn), "Self-accepted staked block {} at height
  {}" (`:812`) or "Failed to self-accept staked block {}: {} (not
  broadcasting)" (`:828`, warn), and then `broadcast_block_inv` (`:823`)
  writes "Broadcast block inv {} to {} peers"
  (`crates/divi-network/src/peer_manager.rs:1071`), whose only non-test
  caller is that line. A relayed peer block is written "Relayed block inv
  {} to {} peers (excluding {})" (`peer_manager.rs:1091`, called from
  `sync.rs:1278`).
- The block-connected callback writes "Self-accepted block {} at height
  {} processed (wallet + mempool + fees)" (`bin/irondivid/src/main.rs:2173`)
  and "Failed to save wallet after self-accepted block {}: {}"
  (`main.rs:2167`) for the own block (callback set at `main.rs:2148`),
  against "Block {} at height {} processed (fees: {}, mempool cleaned,
  wallet scanned)" (`main.rs:1910`) and "Failed to save wallet after
  block {}: {}" (`main.rs:1907`) for a peer's (callbacks set at
  `main.rs:1835` and `:1884`).

The change, made with A11:

1. **One Connected line.** One function in `divi_network::sync` writes
   "Connected block {} at height {}" at debug with an explicit `target:
   "divi_network::sync"`, so the `net` and `sync` debug categories select
   it whichever module calls it (`bin/irondivid/src/log_filter.rs:17-24`
   maps `net` to `divi_network` and `sync` to `divi_network::sync`). Every
   accept path calls it: `sync.rs:1322` and `:1446`; the `:1486` accept,
   which gains the line and loses `:1499`; the orphan path (`:2393`),
   which writes the same line (how many blocks came from the orphan pool
   goes into the counted list below); `Staker::accept_own_block`, in
   place of `staker.rs:812`; and `Node::accept_block`, in place of
   `node.rs:1551` and `:1538`, so a production caller added later logs
   like every other path; and the bootstrap import's accept
   (`crates/divi-node/src/block_import.rs:213`, `chain.accept_block`),
   which today writes no Connected line.
2. **One failure line.** A second shared function writes "Failed to
   connect block {}: {}" at error, for `sync.rs:1330`, `:1455` and the
   staker's `:839`. Its error kind stays in the line.
3. **No own-only reorg line.** `staker.rs:797` is removed. The chain
   lines that `accept_block` writes on a reorganisation (`chain.rs:2090`,
   `:2150`, `:2273`) are written for both paths alike.
4. **One callback line.** The staker-path callback writes its outcome
   through the same function and format as the sync-path callbacks:
   `main.rs:2173` and `:2167` go, and the `:1910` and `:1907` formats serve
   both.
5. **No per-block announce line.** The per-block lines
   `peer_manager.rs:1071` "Broadcast block inv" and `:1091` "Relayed block
   inv" are dropped. One format would not be enough: the relay counts one
   peer fewer and names the excluded peer, and it runs only when the
   height grew and the node is fewer than 10 blocks behind
   (`sync.rs:1269-1279`), while the own broadcast always runs. The
   per-peer "Failed to send block inv to peer {}: {}" lines
   (`peer_manager.rs:1068`, `:1085`) name no block, but for the same
   reason their rate is higher around own blocks; r11 kept them, and they
   now go on the counted list (item 6).
6. **The counted list.** Some lines are written once per block event —
   a block a peer sent, a block served, a header or inv batch, a request,
   a timeout — and whether they appear around a block, or how often,
   tells an own block from a peer's (consensus B3). They are on the
   **counted list**, in two tiers. The network and chain lines below stay
   per event in the node's own `debug.log`, where they help a local
   reader, and diag counts them when it packages a log: never per event,
   only as bucketed counts per format (§6.2 "Old-log lines" (e)). The
   wallet, mempool and staker sites named at the end of this list write
   no line of their own; the node keeps a counter per site and writes
   hourly count lines, which diag sums into the same buckets. Sites are
   cited by the line their macro starts on. These lists are what greps of
   the tree found; they are not proof that nothing is missing (consensus
   N-d). The §10 item 6 log source scan is the gate, and the O1
   differential (§10 item 5) is a backstop only: a per-block line written
   on both sides of its comparison window would pass it.
   - `crates/divi-network/src/sync.rs`, every log site outside its tests,
     re-grepped at 6de594fb (88 sites: the 86 of 1fd59a5c, the debug
     "Sync stalled" of 8e4bfaca, and the split of "Header sync complete"
     into info `:986` and debug `:988` by 73440b48; privacy R12-1,
     consensus N-d, adversarial AC1, adversarial r14 note 1).
     `handle_block` (`:1230`) calls `try_connect_blocks` (`:1264`), which
     can call `request_headers` (`:1379`), which reaches
     `select_sync_peer` (`:778`) and `build_block_locator` (`:922`), so
     lines in all of them run per peer block. Four groups:
     - Counted, weekly (51): "Received block {} from peer {}" (`:1240`)
       and "Ignoring block {} from peer {} while importing" (`:1234`);
       the getblocks and header-request lines `:601`, `:742`, `:756`,
       `:768`, and peer selection and the locator `:794`, `:925`, `:961`;
       the headers lines `:974` (empty headers), `:988` "Header sync
       complete" (debug: entering Synced without a real catch-up,
       about once per peer block near the tip; 73440b48), `:994` "Received {} headers from peer {} (first:
       {})", `:1064`, `:1068`; the request lines `:1105`, `:1119` (trace,
       "Every peer has {} blocks in flight") and `:1188` "Requested {}
       blocks from peer {}"; the connect-loop lines `:1374` "All queues
       empty, requesting more blocks (at height {}, target {})", `:1387`
       "Sync work pending: …", `:1416` "try_connect_blocks_by_prev:
       tip={}, …", `:1499` "Chain reorganized! …" (removed by item 1) and
       `:1517` "Block {} not accepted yet: {}"; the timeout and orphan
       lines `:1583`, `:1696`, `:1750`, `:1795`, `:1809`, `:1815`,
       `:1817`; the inv lines `:1832` and `:1862` (trace), `:1880`
       "Received inv with {} block hashes from peer {}", `:1914` "First
       inv block: hash=…", `:1920` "Block index exists…", `:1943` "Reorg
       triggered by block {} from inv", `:2013` "After reorg, chain height
       is now {}" (info), `:2017`, `:2024`, `:2040`, `:2065`, `:2081`; and
       `:2189`, `:2247` (notfound), `:2292`, `:2304`, `:2422`, `:2425`,
       `:2448`, `:2472`, `:2477`; and `:1650`, the debug "Sync stalled at
       height {} for {} cycles, rotating sync peer" that 8e4bfaca writes
       when the node is stalled within `CAUGHT_UP_LAG` of its best peer,
       which on a synced node means waiting on a peer's block, so at
       `-debug` it marks peer blocks.
     - Failure-only, counted per day (19): `:607`, `:733`, `:764`,
       `:828`, `:836`, `:1020` and `:1034` (a header that does not connect
       or fails validation), `:1048`, `:1185` (failed request), `:1330`
       and `:1455` "Failed to connect block {}: {}" (item 2), `:1515`
       "Dropped invalid block {}: {}" (warn), `:1711` (request timed out),
       `:1763`, `:1822`, `:1962`, `:2046`, `:2412` and `:2414` (orphan
       failures). `:1822` "Block download state but no work - requesting
       more blocks" (warn, in `check_timeouts`, not under the lag gate)
       can follow a near-tip flap out of Synced; it stays in this daily
       bucket, which saturates, and is never kept in place (adversarial
       r14 note 5).
     - Public records (3): the Connected lines `:1322`, `:1446`, `:2393`
       (below); rule (e) collapses them by default (item 7).
     - Kept in place (15): the peer handshake and removal lines `:527`,
       `:537`, `:546`, `:559` (from the version handshake,
       `crates/divi-node/src/node.rs:870`), and in `sync.rs` `:627`,
       `:659`; start-up `:693`, `:704`, `:713`, `:718`; and the five
       sync-state lines (adversarial AC1; 1fd59a5c, 8e4bfaca and
       73440b48): `sync.rs:1364` "Block sync complete at height {}",
       `:986` "Header sync complete" (info), `:1368`
       "Exiting IBD mode — full validation enabled for new blocks",
       `:1628` "Sync progress: height {}/{}, state {:?}, in_flight={},
       queued={}" and `:1645` "Sync stalled at height {} for {} cycles,
       rotating sync peer" (warn). None of them can be written by a short
       lag. "Block sync complete" and the info "Header sync complete" need
       the `fell_behind` flag (`:392`),
       which `note_lag` (`:1606`) sets only when the best peer height is
       more than `CAUGHT_UP_LAG` (6, `:78`) blocks above the node's own,
       and which `enter_synced` (`:1596`) clears (`fell_behind.swap`,
       `:1603`) on every way into Synced: it is the only code that sets
       the state to Synced, called at `:563` (the IBD exit in
       `update_peer_height`), `:714` (`start`, after "Chain is up to
       date"), `:985` (`handle_headers`) and `:1363`
       (`try_connect_blocks`), and returns true, which lets the caller
       write its info line, only when the state was not already Synced
       and the flag was set. Before 73440b48 a node that reached the tip
       through `handle_headers` or `start` kept the flag and wrote one
       stray "Block sync complete" on a later peer block (adversarial r14
       note 2), and "Header sync complete" was info on every empty
       headers reply (note 1); off a real catch-up it is now debug
       (`:988`, counted above). "Exiting IBD mode" is
       written once per process, while `is_ibd()` is true (`:1367`), and
       `set_ibd_mode(false)` follows; no production call sets IBD mode
       back on (`crates/divi-storage/src/chain.rs:733`). "Sync progress"
       and the warn "Sync stalled" are written from the `check_timeouts`
       timer (`sync.rs:1615`) only while `note_lag` reports more than
       `CAUGHT_UP_LAG` behind (`far_behind`, `:1626`). So the ways a
       synced node trails its peers by a block or two, `best_peer_height`
       raised from an inv in `handle_inv` (`:1855`, `:2069`), a short
       headers reply (`handle_headers`, `:972`) and a new peer's start
       height in `update_peer_height` (`:533`-`:537`), can move the state
       out of Synced (item 8) but write none of the five. The unit test
       `short_lag_does_not_rearm_sync_complete` (`:2544`) checks it: one
       block behind with the queues empty leaves Synced without setting
       the flag, `check_timeouts` sets none, the catch-up returns to
       Synced with the flag still clear, so the line is not written, and
       only a lag of `CAUGHT_UP_LAG + 1` arms it again; after that far
       lag, an empty headers reply (`handle_headers`) enters Synced and
       clears the flag, so no stray line follows on a later peer block
       (73440b48). The test checks the state and the flag; it gains a
       tracing capture layer that asserts no sync-state line is written
       on the short-lag steps (adversarial r14 note 3), and the §10 item
       5 gate checks the log at run time. These lines fire
       only on a real catch-up, which the chain's public heights and the
       peers already show, so they are not counted: they stay in place in
       `debug.log` and in the package. The package also carries a weekly
       tally of each of the five next to them (consensus N-g), so a
       re-arm, should one ever happen, shows as a weekly count near the
       number of blocks. The handshake warn "Peer {} has height {} but
       we're at {} - restarting sync (was best_peer_height={})" (`:546`,
       format `:547`) is not under the lag gate: it is written when a
       peer whose start height is above the node's own connects while
       the node is Synced, once per connection, from the peer's version
       message (its one runtime caller, `node.rs:870`), never from a block of the node's own, so it stays in
       place with the handshake lines above, stays classified in the §10
       item 6 scan, and is the one named exception to the gate below
       (privacy R14 NB2, adversarial r14 note 4). §10 item 5 makes "no
       sync-state line within the lag window" a release gate, and the §10 item 6 scan treats a new
       log site on these paths (`try_connect_blocks`, `check_timeouts`,
       `note_lag`) as unlisted until it is classified.
   - `crates/divi-node/src/node.rs`: "Received P2P message from peer {}:
     {}" (`:898`), "Block message received from peer {}: {} with {} txs"
     (`:912`); the getdata serving lines `:1020` "Failed to send block {}
     to peer {}: {}", `:1027` "Served block {} to peer {} (getdata)",
     `:1052` "Block {} not found for getdata from peer {}", `:1062` (failed
     to send notfound) and `:1071` "Error looking up block {} for peer {}:
     {}" (the serves go through `peer_manager.send_block_to_peer`, called
     at `node.rs:1018`, `:1045`, `:1060`); and the getblocks inv response
     `:1104`, `:1106`.
   - `crates/divi-network/src/peer_manager.rs`: in `send_block_to_peer`
     (`:1100`), `:1111` "Failed to send block to peer {}: {}" and `:1115`
     "Timeout sending block to peer {}"; `:1068` and `:1085` "Failed to
     send block inv to peer {}: {}" (item 5); `:1040` and `:1130` "Failed
     to broadcast to peer {}: {}".
   - `crates/divi-network/src/relay.rs:312` "getdata item type {:?} (not
     tx), skipping hash {}".
   - Per message, counted per command (`block`, `inv`, `getdata`,
     `headers`, and so on), not per format: `node.rs:898` above,
     `crates/divi-network/src/codec.rs:115` "Decoded header: cmd={},
     payload_size={}" and `:148` "Decoded message: {} ({} bytes)", and the
     received and sent lines `crates/divi-network/src/connection.rs:648`,
     `:737`, `:771`, `:789` (all trace).
   - "Activating stored block {} at height {}…" and "try_activate_block:
     Successfully activated block {}"
     (`crates/divi-storage/src/chain.rs:5167`, `:5175`, reached only from
     the inv path at `sync.rs:1941`).
   - The bootstrap import's per-block lines,
     `crates/divi-node/src/block_import.rs:185`, `:204` (every 1000th
     height), `:216`, `:225`.
   - Counted in the node, with no line of their own: the wallet and
     mempool lines written while a block is connected ("Wallet lines on
     the connect path", below) and the staker counted list ("Staker
     default-deny", below).

   The Connected lines (`sync.rs:1322`, `:1446`, `:2393`) are not on the
   list: after item 1 they are written for every block alike and are
   public records (§6.2). Checked and not per block:
   `crates/divi-node/src/zmq.rs:385-409` (start-up only);
   `crates/divi-electrum/src` (`backend.rs`, `lib.rs`, `session.rs`) has
   no per-block line, and `session.rs:403` "electrum: notification check
   failed: {}" is written per 1 s tick, only on failure. r13 re-grepped
   the info, warn and error sites of `node.rs`, `peer_manager.rs`,
   `relay.rs` and `block_import.rs` for block, inv, getdata, height and
   tip lines at the default level and found none per block beyond those
   listed; `crates/divi-rpc/src/wallet.rs:796` "Failed to save wallet
   after chain sync" is written only from `sync_with_chain` (`:790`),
   after `invalidateblock` and `reconsiderblock`, so it is a failure-only
   line that stays in place (masked by §6.2 rule (b)) and rule (e) does
   not remove it.
7. **Timing.** An own block is connected moments after it is made; a
   peer's arrives after network delay. Whether the gap between a block's
   header time and its Connected line tells own blocks from peer blocks
   is to measure in §10, with the clock state at each sample (R11-3).
   The measurement is a release gate (consensus N-c). **Until it passes,
   and by default,** diag applies §6.2 "Old-log lines" (e) to every text
   copy of node log output from every run, current node or not: the
   `debug.log` files and every other input §6.2 "Old-log lines" lists,
   the debug-ring copies in `crash.log`, the incidents and `getdiaginfo`,
   the incident tails and the mirrors among them (consensus B4). The
   fallback switches off only when, on at least 200 own and 200 peer
   blocks, the best threshold on the gap alone sorts own from peer blocks
   no better than 55% right on a balanced sample; that bound is this
   plan's choice, and the developer decides from the recorded runs, at
   release, whether it is met.
   **Where the gap is measured** (platforms R12-1). A run with no network
   delay cannot pass the gate: on loopback or one LAN a peer block
   connects about as fast as an own block, so the gap would sort nothing
   and the gate would pass by construction while mainnet leaks. The
   peer-block gap is measured passively on a mainnet node (or a testnet
   node) with its normal peers; the own-block gap on a staking testnet
   node whose peers are all off its LAN. The only lab stand-in is hp1–hp3
   with `tc netem` delays drawn from the measured mainnet distribution.
   The 4-node regtest O1 run records the gap too but never counts toward
   the gate.
   **Expected outcome.** The gate will probably fail: an own block meets
   no network delay before its own node connects it, and nothing in this
   plan hides that. Then rule (e) stays on for good, and that is the
   shipped design, a decision rather than a gap. What still diagnoses a
   node whose per-block lines are collapsed: `chain-events.log` (a tip
   record every 100 blocks, reorgs, invalid blocks, bans, stalls, header
   conflicts; A12), the A13 replay bundles, the tips and peers in
   `getdiaginfo`, the daily failure-only counts, the weekly per-peer
   "Received block" counts, and the "Sync progress" and "Sync stalled"
   lines, which stay in place (item 6). Within the lag a stall writes
   only the debug "Sync stalled" (`sync.rs:1650`, counted), so the A12
   stall record and the stall incident are measured on the sync stall
   counter or the tip age at any lag, never on the `far_behind` gate
   (consensus N-i, A12). Decoupling the own block's
   Connected timing in the node (for example delaying or batching its
   Connected line) is a possible follow-up only and is not in this plan.
8. **Sync-state lines** (privacy R12-1, adversarial AC1; done in
   1fd59a5c and 8e4bfaca). "Block sync complete at height {}"
   (`sync.rs:1364`) is written only on the transition into Synced,
   which `enter_synced` (`:1596`) makes under the state lock, and only
   when the node was more than `CAUGHT_UP_LAG` blocks behind since the
   flag was last cleared (`:1603`), not after every peer block; the info
   "Header sync complete" (`:986`) follows the same rule, and every way
   into Synced (`:563`, `:714`, `:985`, `:1363`) clears the flag
   (73440b48). "Exiting IBD mode — full
   validation enabled for new blocks" (`:1368`) is written once per
   process. The state is set out of Synced at `:550`, `:707`, `:722`,
   `:979`, `:1072`, `:1378`, `:1823` and `:2484`, and a peer block can do
   that (`:1378`, one block behind with the queues empty), but leaving
   Synced no longer re-arms the line: item 6 "Kept in place" gives the
   gate, the short-lag cases and the unit test. The five sync-state
   lines are not counted; the package carries a weekly tally of them
   (consensus N-g), and the §10 item 5 release gate checks that none is
   written within the lag window around an own stake or a peer block. In
   a log from a node without 1fd59a5c, or whose version is unknown, rule
   (e) removes "Block sync complete" (§6.2); in one from a node with
   1fd59a5c and without 8e4bfaca it does the same, and removes "Sync
   progress" and "Sync stalled" too, since there a lag of one block could
   write them.

**Wallet lines on the connect path** (adversarial AA1, privacy R11-1).
Every block-connected callback scans the block into the wallet: the peer
callback (set at `main.rs:1884`, scan at `:1893`), the staker callback
(set at `:2148`, scan at `:2153`), and the calls at `:2002` and `:2807`,
all through `sync_wallet_to_tip` (`main.rs:2854`; its error line at
`:2857` reports blocks missing after pruning), then
`divi_rpc::wallet::sync_wallet_with_chain`
(`crates/divi-rpc/src/wallet.rs:769`), `WalletDb::sync_to_tip`
(`crates/divi-wallet/src/wallet_db.rs:3389`), `scan_active_block`
(`:3438`), `scan_block` (`:2775`) and `scan_transaction` (`:2788`). Lines
on that path are written only for blocks that touch the wallet, and an
own stake always does, so next to the clear Connected line they name the
own block. The sites, all in `wallet_db.rs`: `:2835` trace "Received {}
to {} in tx {}"; `:2849` trace (an output spent); `:1749` "Adding UTXO
{}:{} ({})" in `add_utxo` (`:1747`); `:1767` "Spent UTXO {}:{}" and
`:1776` "Failed to persist spent_utxo_data: {}" in `spend_utxo_at_height`
(`:1760`); `:2159` "Adding transaction {} to history" in
`add_transaction` (`:2158`); `:2928` "Wallet tx {} {} {} sats"; `:3237`
"Dropped mempool wallet tx {} (conflicts with {})" in
`drop_confirmed_from_mempool` (`:3210`); `:3182` "Failed to forget
unconfirmed wallet tx {}: {}"; `:2224` (keys not stored) in
`mark_address_used` (`:2192`); `:3402` "Wallet scanned blocks above {}
that left the active chain; rolling back" and the `rollback_heights`
(`:3280`) lines `:3337`, `:3345`, `:3355`; and whatever `tx_changed`
(`:2990`) reaches. One more is easy to miss: the callbacks call
`save_incremental` (`:1254`) after every block (`main.rs:1906`, `:2024`,
`:2166`, `:2808`), and it writes "Wallet incremental save complete"
(`wallet_db.rs:1364`) only when the wallet is dirty, that is after a block that
touched it. The mempool side, `mempool_block_connected` (`main.rs:2824`),
writes `crates/divi-node/src/mempool.rs:581` "Removed tx {} from
mempool", `:627` "Removed {} non-final transaction(s) from mempool" and
`:736` "Removed tx {} from mempool: conflicts with a block" (in
`remove_conflicts`, `:713`); `fee_estimator.add_block`
(`crates/divi-node/src/fee_estimator.rs:44`) writes no line. Checked with
no per-block line: `persistence.rs`, `manager.rs` and `backup.rs` in
`divi-wallet`.

**Wallet lines on the mempool listeners** (privacy R13-1). The mempool
added listener (`main.rs:1926`) calls `WalletDb::add_mempool_tx`
(`wallet_db.rs:2970`) for every transaction that enters the mempool, so
a line it writes would pick out the wallet's own transactions by its
time and txid next to the relay lines (`relay.rs:288` "Received tx {}
from peer {}" and `:391` "Relaying tx {} to {} peers", as of f67b0984;
both removed in 09cb18e4, "Own transactions log like peer transactions"
below). Commit f67b0984 removed the closure's own
line, "Wallet sees unconfirmed tx {}" (the comment at `main.rs:1927`
says why); the start-up line "Wallet picked up {} unconfirmed tx(s)
already in the mempool" (`main.rs:1952`) stays, since it carries a count
only and is written once. The removed listener (`set_removed_listener`,
`main.rs:1933`) calls `remove_mempool_tx` (`wallet_db.rs:3192`) and
writes no line of its own. What the added listener still reaches, in
`track_mempool_tx` (`wallet_db.rs:2999`): no success line, since
commit bf6452fc removed "Mempool wallet tx {} {} {} sats ({})" (info,
written for every wallet transaction with its txid; r14 had put it on
the counted list) and the comment now at `:3098` says why; the §10 item
6 scan treats that site as removed, not counted (platforms R14-2); and
the failure lines `:3119` "Failed to store
unconfirmed wallet tx {}: {}", `:3142`, `:3163`, `:3166` and `:3182`,
counted per day as failure-only. `add_mempool_tx` then calls `tx_changed`
(`:2990`), which runs `-walletnotify` ("Notify commands" below). The ZMQ
added listener (`zmq.rs:428`) and block listener (`zmq.rs:434`) reach
`mempool_added` (`:502`) and `chain_event` (`:509`), which write no
line.

All of these are on the counted list and are counted like the staker's
counted sites below: the site writes no line of its own, the node writes
one hourly count line per format, zeros included, and the package
carries weekly buckets, for logs with the change and without it (§6.2
"Old-log lines" (b), (e)). `-logwalletdetail=1` does not restore them.
The list is found by following the call graph from the callbacks and
`scan_block`, not by module (§10 item 6).

**Own transactions log like peer transactions** (privacy R14-1). The
rule: no log line, no copy of one, no count and no ordering of lines may
differ between a transaction this node created or resubmitted and a
peer's. A difference can be a line written on one side only, the same
lines in another order (a peer's echo of an own transaction arrives
after the node has announced it, since the submit path marks nothing
seen), or a count split by origin or per peer. A line on these paths is
written alike for both, or counted in the A11 way, or, written only on a
failure, counted per day with its txid masked; nothing else stays in
place, and the §10 item 6 scan fails a new site until it is classified.

Removed in the code (numbers as of f67b0984; commits 09cb18e4 and
6de594fb, the comment at `relay.rs:282` says why): `relay.rs:288`
"Received tx {} from peer {}", `:331` "Sent tx {} to peer {}
(version={}, vin={}, vout={})", `:391` "Relaying tx {} to {} peers",
`:429` "Retrying tx {} from peer {}", `:199` "Queuing {} new
transactions to request from peer {}"; `node.rs:1349` (then; it is now the `TransactionAccepted` send) and `:1990`
"Added relayed tx {} to mempool", `:1786` "Accepted transaction {} to
mempool", `:2062` "accepted orphan tx {}"; `main.rs:2345` "Transaction
{} submitted to mempool and announced to peers"; `divi-rpc
wallet.rs:2476` "Broadcasted transaction {}" and `:3746` "Sent {}
outputs (txid: {})". In older logs §6.2 "Old-log lines" (e) removes
them and counts them as one "tx relay events" site, never split by
origin.

The paths, at 6de594fb. An own transaction: a send RPC (`server.rs:608`,
`:622`, `:623`, `:636`, `:645`, `:727`, `:728`, `:729`) reaches
`sign_and_submit` (`crates/divi-rpc/src/wallet.rs:1826`), from
`send_to_address` (`:1889`), `fund_vault` (`:3101`),
`debit_vault_by_name` (`:3190`), `reclaim_vault_funds` (`:3277`),
`allocate_funds` (`:3501`), `send_many` (`:3626`) and `send_from`
(`:4092`), or `send_raw_transaction` (`:2386`, submitting at `:2474`),
which the Electrum "blockchain.transaction.broadcast"
(`crates/divi-electrum/src/session.rs:214`) also reaches; all call
`submit_transaction` (`divi-rpc wallet.rs:932`), which runs the submit callback
(`set_tx_submit`, `bin/irondivid/src/main.rs:2329`): `mempool.add`
(`crates/divi-node/src/mempool.rs:358`), then `announce_tx`
(`crates/divi-network/src/relay.rs:334`, spawned at `main.rs:2342`),
which calls `relay_tx(txid, None)` (`relay.rs:350`). A restart:
`resubmit_wallet_txs` (`main.rs:1702`) calls `resubmit_tx` (`:1679`) and
`announce_tx` for each unconfirmed wallet transaction. A peer's
transaction: `handle_inv` (`relay.rs:149`), `request_tx` (`:244`),
`handle_tx` (`:265`), which relays with `relay_tx(txid, Some(peer))`
(`:277` for a whitelisted peer's repeat, `:300`) and sends the event to
the node's relay handler (`crates/divi-node/src/node.rs:1327`), which
calls `add_relayed` (`mempool.rs:364`); a transaction already in the
mempool, an own one echoed back included, returns there without a line
(`mempool.rs:377`). Serving: `handle_getdata` (`relay.rs:304`).
`Node::accept_transaction` (`node.rs:1760`) has no runtime caller. The
node event `TransactionAccepted` is sent only for a peer's transaction
(`node.rs:1349`, `:1356`; the third send, `:1776`, is in
`accept_transaction`) and nothing consumes it; a consumer would be a
new root. These are the §10 item 6 scan roots.

What the paths still write:

- Written alike for both, kept in place: "Expired {} old transactions
  from mempool" (`mempool.rs:835`) and "Mempool cleared" (`:920`), one
  rule for every transaction, counts only; "Reorg: returned {} of {}
  transaction(s) of disconnected blocks…" (`node.rs:2136`), counts
  only, once per reorg, and reorgs are public in `chain-events.log`;
  the relay handler's debug "mapOrphan overflow, removed {} tx"
  (`node.rs:1365`), "Rejected relayed tx {}: {}" (`:1369`), and the
  orphan lines "invalid orphan tx {}" (`:2074`) and "removed orphan tx
  {}" (`:2076`): written only for a peer transaction that is refused or
  orphaned, never for one that enters the mempool, own or peer, and an
  own transaction's echo is a silent duplicate (`mempool.rs:377`), so
  they say nothing about which accepted transactions are the node's;
  and the start-up count lines "Restored {} unconfirmed wallet
  transaction(s)" (`crates/divi-wallet/src/wallet_db.rs:555`),
  "Resubmitted {} unconfirmed wallet transaction(s) to the mempool"
  (`main.rs:1727`) and "Wallet picked up {} unconfirmed tx(s) already
  in the mempool" (`main.rs:1952`): once per start, a count only, and
  with the relay lines gone nothing is left to pair them with (privacy
  R14 NB3). They stay count-only: a change that adds a txid or a
  per-transaction line to them fails the canary.
- Counted (the A11 way: hourly count lines with zeros, weekly buckets,
  the A8 `counted` tag so they never reach the ring): `mempool.rs:441`
  "Added tx {} to mempool (fee: {}, size: {})" (debug). It is written
  for both, but not alike in time: after a restart it comes as a burst,
  one per unconfirmed wallet transaction, before any peer connects, and
  an own send's line sits between the RPC server's debug lines
  "RPC {method}: …" (`crates/divi-rpc/src/server.rs:1578`) and "RPC
  request: …" (`:1424`), so it is not kept in place. Also counted:
  `mempool.rs:581`, `:627` and `:736` (already counted on the connect
  path); `:662` "Removed tx {} from mempool: inputs no longer spendable"
  (`remove_unspendable`, `:639`, reached only from the reorg path at
  `node.rs:2133`) and `node.rs:2125` "Transaction {} of a disconnected
  block not returned to the mempool: {}", which carry a txid per
  transaction of a reorg; the relay debug lines `relay.rs:312` (already
  on the item 6 list) and `:325` "getdata: tx {} not found in mempool
  for peer {}"; the trace lines `:159`, `:253`, `:275` and `:384`,
  which never reach the ring (it holds debug, not trace) and which (e)
  removes from a log written with `-loglevel=net:trace`, `setlogconfig`
  or `RUST_LOG` (`-debug=net` gives debug only); and the four own-only
  info lines in `divi-rpc wallet.rs`, `divi-rpc wallet.rs:1929` "Sent {} DIVI to {} (txid:
  {})", `divi-rpc wallet.rs:3174` "Funded vault {} with {} DIVI (txid: {})", `divi-rpc wallet.rs:3566`
  "Allocated {} DIVI for masternode collateral (txid: {})" and `divi-rpc wallet.rs:4170`
  "Sent {} DIVI from account '{}' to {} (txid: {})", which a peer's
  transaction never writes and which are therefore never kept in place,
  masked or not. "RPC {method}: …" itself is a `divi_rpc` line, so rule
  (b) masks the method name; it is written for every RPC call.
- Failure-only, counted per day, txid masked (rule (b) for the
  `irondivid` root and `divi_wallet`; the relay warns are edit sites
  for the same masking): `relay.rs:249` "Failed to request tx {} from
  peer {}: {}" and `:403` "Tx {} request timed out from peer {}" (a
  peer's transaction only), `:322` "Failed to send tx {} to peer {}: {}"
  (serving a getdata, which an own transaction meets more often), and
  `main.rs:1719` "Unconfirmed wallet tx {} cannot be resubmitted ({});
  forgetting it", an edit site that replaces `main.rs:2345` in rule (b).
  The daily bucket is not split by origin.

**Notify commands** (privacy R12-2). `run_notify` (`main.rs:2663`)
writes "runCommand error: {} ({})" at warn (`:2671`, `:2673`) with the
user's command, `%s` already replaced by the txid or block hash.
`-walletnotify` runs it from the wallet transaction listener
(`w.set_tx_listener`, `main.rs:1872`), so a failing command writes, at
the default level, one line per wallet transaction, an own coinstake
included, with the command and the txid in clear; `-blocknotify` runs it
from a tip listener (`spawn_block_notify`, `main.rs:2680`, which calls
`chain.add_tip_listener` at `:2681`). The change: `run_notify` takes the
kind and writes "runCommand error: walletnotify ({})" or "runCommand
error: blocknotify ({})" with the exit status or the error kind only,
never the command or the value. Both formats are on the counted list in
its first tier: they stay in the user's `debug.log`, where a failing
command must be visible, and the package carries them as weekly
buckets. In older logs §6.2 "Old-log lines" (e) removes the old format
and counts it the same way.

**Staker default-deny** (O1). Every log site in
`crates/divi-node/src/staker.rs` (by the line its macro starts on, as of
the 2026-10-30 tree) is on one of two lists, and the §10 item 6 log source
scan fails a new site that is on neither.

- **Allowlist**, written as today, because each is written the same
  whether or not a stake succeeds: the lifecycle lines `:645` (already
  running), `:649` (starting), `:662` (stopping), `:671` (loop started),
  `:683` "Staking loop iteration {}" (every 60th iteration, whatever
  happened), `:690` (no peers, before any attempt) and `:774` (loop
  stopped); the wallet-lock lines `:1155` and `:1163`; and the skips
  before an attempt, `:1190` (initial block download), `:1198` (snapshot
  base heights) and `:1217` (stale tip, height and age).
- **Counted list**, everything else: `:722` "Staked block {} at height {}
  (reward: {})"; `:738`, `:740` (no stakeable UTXOs); `:744` (no valid
  proof); `:758`, `:760` (rate limited); `:766` "Staking error: {}"; `:797`,
  `:812` and `:828`, replaced as above but still counted with the kind of
  outcome; `:847` (phantom UTXO evicted); `:856` (wallet save failed);
  `:1106`, `:1114`, `:1122` (rate limiting); `:1255` (next difficulty
  failed); `:1317`, `:1322` (reserve balance); `:1341` (vault UTXOs);
  `:1372` and `:1389` (every 60th attempt, the latter "MODIFIER
  MISMATCH"); the own-UTXO lines `:1475`, `:1488`, `:1509`, `:1520`;
  `:1541` (create failed); `:1550`, the attempt summary, which today is
  written only when nothing was staked and so marks a success by its
  absence; `:1611` (no block index); `:1668`, `:1684` (lottery) and
  `:1710`, `:1731` (treasury), written only on success; the signing
  lines `:1857`, `:1871`, `:1873`, `:1877` and `:1910`, `:1921`; and the
  coinstake lines `:1995`, `:2130` and `:2171` "Block {} rewards…".

A counted site writes no line of its own. The staker keeps a counter per
site and outcome kind (for an error, its AA3 reason code from the closed
set below, never its text), and every hour writes one line per counted site, **zeros
included**, in one fixed format at info, so the presence and the timing
of the count lines say nothing; repeatedly orphaned or failed stakes stay
diagnosable from the kinds. The hourly lines stay on the user's disk;
the package carries weekly buckets (§6.2 "Old-log lines" (b), (e)).

**Count clock** (platforms R12-2, R12-3, R13-1 to R13-3). The hour is
timed on `CLOCK_BOOTTIME` (on macOS `mach_continuous_time`), which counts
through suspend and is not stepped by the wall clock, so a clock step
neither drops nor doubles an hour. The hourly timer is driven by that
clock too: a `timerfd` on `CLOCK_BOOTTIME` on Linux, or, where that is
not available, a 60 s tick that reads the boot clock and writes the
count lines when an hour of it has passed; on macOS the 60 s tick reads
`mach_continuous_time`. A tokio `interval`, as the daily backup timer
uses (`main.rs:2039`-`:2040`), is not used: it runs on a monotonic clock
that stops during suspend, so a laptop or Pi that sleeps would stretch
the hour (platforms R13-1). Each count line carries the wall-clock times
at the start and end of its hour, the boot ID
(`/proc/sys/kernel/random/boot_id`; `kern.bootsessionuuid` on macOS, as
A1 records it) and a flag saying whether the clock was synchronised:
`yes`, `no` or `unknown`. On Linux the flag comes from a read-only
`adjtimex` call (`modes` = 0, which needs no capability) and its status
without `STA_UNSYNC`, or from `timedatectl` "System clock synchronized"
where that runs; in a container where `adjtimex` is refused (a seccomp
profile) the flag is `unknown`. On macOS `ntp_adjtime` is read the same
way, and the flag is `unknown` until §10 shows that it reports the sync
state (platforms R13-3). `unknown` is placed as unsynchronised. The
package files each count into the week of its end time; a line from an
unsynchronised hour is placed by the next synchronised line of the same
boot ID, less the boot-clock interval between them. A line with no
synchronised line after it in the same boot (the machine was powered off
or rebooted before its clock synced) goes to an `unplaced` bucket, shown
apart from the weekly buckets, never filed by its own wall time
(platforms R13-2). A VM or WSL2 guest is paused, not suspended, while
its host sleeps, so its boot clock stops and its wall clock is stepped on
resume: an hour whose wall span is over about 1 h 5 min is flagged
`stretched` and still filed by its end time, so a low count there is not
read as a quiet hour (platforms R14-1). A container without a time
namespace shares the host's boot ID and boot clock, which is expected and
keeps the placement rule working across container restarts on one boot.
The counters are
`AtomicU32`: an hour of any site stays far below 2^32, and 32-bit atomics
are lock-free on every target the plan builds, so the signal-handler
loads stay safe. A week in which a run ended without a clean-exit record
in `runs.log` (SIGKILL, power loss) lost up to an hour of counts; its
buckets are marked `partial`, so a zero there is not read as "no
failures".

Counts since the last hourly line are lost only on SIGKILL and power
loss (crashes S1, R12-1). `exit_after_stop` (`main.rs:3216`) writes the pending count lines
before its `flush_log()` (`main.rs:3231`; `flush_log` at `:1349`); the A5
crash record (item 5), the A17 incident, the `die()` record (A9), the
A4 panic hook's record and the A3 third-TERM record copy the counters
since the last hourly line with plain atomic loads, which are safe in a
signal handler; and the package folds those copies into the last weekly bucket.
Per run, the package uses only the latest copy taken after that run's
last hourly line, which **replaces** the run's pending counts and is
never added to another copy; a copy is dropped when a later hourly line
of the same run exists, since that line already holds its counts
(crashes R13-2). Without this rule a count would be taken twice where a
run writes a copy and goes on: an A17 incident or a supervised-task
panic (the A4 hook copies, the node keeps running and writes the next
hourly line), and a critical-task panic, which writes the A4 hook's copy
and then the `die()` copy. On a main-thread panic the A4 hook's copy is
the only one, since `exit_after_stop` never runs (70cb5785).
This holds for every site counted in the node: the staker's and the
wallet and mempool connect-path sites. The network lines that stay in
`debug.log` have no counter and lose nothing.

**Staking error kinds** (adversarial AA3). `StakeResult::Error(String)`
(`staker.rs:290`) carries free text, built as "No chain tip" (`:1183`)
and "Difficulty computation failed: {}" (`:1256`), and matched at `:765`
and `:1051`. A count keyed by that text would carry whatever the text
holds. It becomes a closed reason code: `no-tip`, `difficulty:<variant>`,
`create:<step>`, `sign:<step>` and `self-accept:<variant>`, where
`<step>` is a fixed name for a step in the code and `<variant>` the chain
error's variant name (for `difficulty`, the inner error's; crashes
R12-3), never a value. The staker counts per code. In
`events.log` the change into and out of "stake attempts failing: <code>"
is recorded with the day only, under the A12 rule for the "not staking
because" reason.

**Test.** A regtest wallet is filled with canary values (an address, a label
`CANARY-LABEL-7f3e`, a txid, an amount of exactly 1.23456789 DIVI =
123456789 sats, a masternode collateral); the node runs a scripted session
(send, receive, stake, rescan, lock, unlock, an RPC error, a panic in a
supervised task, a crash test); every Part A file and a full diag package are
scanned for each canary in every encoding in §6.3. Any hit fails the build.

**Logs written before A11** (0.2.9 and earlier, and every run with
`-logwalletdetail=1`) cannot rely on types. Known-value replacement alone
would miss a wallet txid that is not in the wallet file (for example one the
user pasted into a `gettransaction` call that failed), labels and addresses
when the known-value set is incomplete or could not be read, and amounts
written without a unit. So §6.2 step 2 "Old-log lines" applies to them
**always**, whether or not the known values were read: every 64-hex string
that is not a block hash in the block index is pseudonymised, and in every
line from the wallet-bearing modules every argument, number, quoted string
and address-shaped token is masked, except the fixed non-wallet positions
§6.2 rule (b) keeps (`port N`, `code -N`, the port after a class address).
**The module list is derived from the edit sites above, not chosen by
hand:** every tracing target that contains an A11 edit site is on it —
`divi_wallet`, `divi_node::staker`, `divi_node::mempool` (`mempool.rs:736`),
`divi_rpc`, `divi_electrum`, `divi_swap`, `irondivid::core_files` — and for
the `irondivid` crate root, whose target also carries most of the node's
ordinary start-up lines, only lines whose fixed text matches the format
string of an edit site there are masked (today the one at `main.rs:1719`,
"Unconfirmed wallet tx … cannot be resubmitted …; forgetting it", and,
for logs from before 09cb18e4, the removed `main.rs:2345` "Transaction …
submitted to mempool and announced to peers", as of f67b0984). Every log
site inside a mempool, block or wallet listener closure, and every site
such a closure reaches, is an edit site too (privacy R13-1): the closures
registered at `main.rs:1835`, `:1872`, `:1884`, `:1926`, `:1933`,
`:1962`, `:2071`, `:2148`, `:2357` and `:2681`, and at
`crates/divi-node/src/zmq.rs:428`, `:434` and `:440` (§10 item 6 lists
them). Today that adds no target: the added listener's own line was
removed in f67b0984, and what it reaches is in `divi_wallet` (A11
"Wallet lines on the mempool listeners"). The A11
test fails if an edit site's target is missing from this list. The same rule covers every other
copy of node output that diag collects: the journal and `docker logs`
(B2.5), the observed start's stdout/stderr (B3.2), component logs (B2.17)
and A15's stored error text, and, from every run, current node or not,
the debug-ring sections of `crash.log`, the incidents and `getdiaginfo`,
the incident `debug.log` tails and the A14 mirror copies (§6.2
"Old-log lines" lists every input; consensus B4).

### A12. `events.log` and `chain-events.log` — months of history

Synchronous, append-only, about 4 MB × 2 each, which at the expected rate is
months. `events.log` records state **transitions**, never steady state: start
and stop; sync state changes; staking on/off and every change of the
"not staking because" reason; stake found (the day only, with no block
hash, height or time — any of them would identify the block on the public
chain; **in the package** these records are replaced by weekly counts,
each a bucket 0, 1–3, 4–20, >20 as in A6, because a daily stake count
plus the public network weight gives the stake weight and so the balance);
wallet lock/unlock (no passphrase, no duration); masternode
status and `mnsync` phase changes; spork changes; time-offset warnings; data
dir free space crossing 1 GB / 100 MB; memory pressure crossings (PSI over
10 %, cgroup `high` events); stderr lost; `setlogconfig` changes; supervised
task failures; dropped-line bursts; RPC methods that change state (`stop`,
`setlogconfig`, `walletpassphrase`, `walletlock`, `reservebalance`,
`setstaking`…) by **name only**; config file hash change detected at start.
`chain-events.log`: tip changes once per 100 blocks (in the package,
while §6.2 "Old-log lines" (e) is on, this record keeps its height and
hash but its time is truncated to the hour and its monotonic field
dropped, so the gap from the block's header time is gone when that block
is an own stake; adversarial AB3) and on every reorg (depth,
old and new tip hashes — public, printed with the public `blk:` type even
when this wallet staked the block, A11; in the package, while (e) is on,
its time is truncated to the hour and its monotonic field dropped like
the tip record's, since a reorg that orphans an own stake would
otherwise date it to the second; adversarial AC2), invalid blocks (hash, height, reason, peer
pseudonym), rejected non-wallet transactions (txid — public — and reason),
bans (peer pseudonym, reason), stalls over 2 minutes (measured on the
sync stall counter or the tip age, at any lag, never on the
`far_behind` gate; the record carries the lag; consensus N-i),
header-chain conflicts.

**Incidents.** On a panic, a supervised-task failure, an invalid block, a
stall over 10 minutes (measured the same way, at any lag), a ban storm (over 10 bans in 10 minutes), a watchdog
trigger (A17), SIGQUIT or SIGUSR1, the node writes `diag/incidents/<n>/` with
the debug ring, the last 256 KB of `debug.log`, the current health record and
`getdiaginfo` output. The last 10 incidents are kept.

### A13. Replay bundles for invalid blocks and rejected transactions

When the node rejects a block, it writes `diag/invalid/<hash>/`: the raw
block, the headers back to the fork point with the active chain, the spent
outputs, the stake modifier and difficulty inputs used, the spork state and
the lottery/treasury state at that height, the rejection reason and the code
path. The same for a rejected **non-wallet** transaction (raw tx, prevouts,
reason) in `diag/rejected-tx/`. Caps: 20 MB and 5 MB, oldest removed.
A transaction that came from a local caller (A15 "sent from here") is the
user's own even when it was rejected: it never goes to `rejected-tx/` or
`chain-events.log` under its real txid, but to `diag/own-invalid/` like an
own block, under the same §8.2 question.
Every P2P message that added misbehaviour score or failed to parse is written
to `diag/bad-messages/`: the first 4 KB of the message, its command, the
parse error or the score added, and the peer as a pseudonym; cap 5 MB,
oldest removed. Blocks
and non-wallet transactions are public chain data. The headers, blocks and
spent outputs in a bundle are printed as public records with no marking by
ownership (A11, §6.2 "Public records"): a header this wallet staked reads
exactly like any other. A block **this wallet
staked** that was rejected is written to `diag/own-invalid/` and is included
in a package only if the user says yes to the specific question in §8.2
(it links the stake to this node). A developer tool `irondivi-replay
<bundle>` (built in the workspace, not shipped) re-runs validation on a
bundle.

### A14. Storage budget and mirrors

`<datadir>/diag/` is capped at about 75 MB, the sum of these parts: `runs.log` 1 MB × 2, `events.log`
4 MB × 2, `chain-events.log` 4 MB × 2, `health.log` 1 MB × 5, `crash.log`
1 MB × 2, `rpc-methods.log` 1 MB × 2, `startup/` 20 × 64 KB, `incidents/`
10 × 1 MB, `invalid/` 20 MB, `rejected-tx/` 5 MB, `bad-messages/` 5 MB,
`rpc-aggregate.log` 1 MB × 2 (per minute) plus `rpc-aggregate-hourly.log`
1 MB × 2, plus the private `sent-txids` file (A15) 1 MB and
`rpc-methods-reserved.log` (A15, X3) 1 MB, so about 75 MB in all. **Retention arithmetic for the RPC logs**, at a worst case of
50 methods active every minute and lines of about 120 bytes (one line per
method and transport, with a distinct-caller count, never the callers):
per-minute aggregate = 50 × 1440 × 120 B ≈ 8.6 MB a day, so 2 MB holds
about 5 hours at that worst case and 48 hours at 5 active methods;
the node keeps the per-minute tier for **48 hours or 2 MB, whichever ends first**.
Per-hour aggregate = 50 × 24 × 120 B ≈ 144 KB a day, so 2 MB holds about
**14 days at the worst case and 30 days at 20 active methods**; the
per-hour tier is kept for 30 days or 2 MB, whichever ends first. The number
of remote callers does not enter this arithmetic: they are counted, not
listed. `rpc-methods.log` holds only the per-call lines A15 lists
(state-changing calls; the first call per method and **local or
authenticated** caller per hour; errors capped at 5 per (method, error
code, transport) and 50 in all per hour), at about 150 B a line. Worst case
without state-changing calls: 50 first-call lines + 50 error lines an hour
= 100 × 24 × 150 B ≈ 360 KB a day, so 2 MB holds about 5.5 days; at the
§10 test load (20 local first-call lines, 5,000 remote addresses, 100
errors a second from one method) it is about 25 lines an hour ≈ 90 KB a
day, about 22 days. State-changing calls are added on top, and they are
not always few: a script can loop `signrawtransaction` or
`importaddress` (X3). So capped lines have a total cap of 200 an hour
across all capped methods (A15): 200 × 24 × 150 B ≈ 720 KB a day, which
with the lines above rolls the 2 MB log in about 2.5 days at the worst
case; the rare uncapped lines (`stop`, `setlogconfig`,
`backup*`; `dump*` is capped since r10, Y6) and the first call of each
capped method each hour are also written to `rpc-methods-reserved.log`, which no flood of capped calls
reaches, so they are kept far longer than the 2 MB log. When the data dir has less
than 100 MB free the Part A writers stop (except `runs.log`, `crash.log`) and
record "diag logs paused"; they never compete with the database for space.

**Mirrors.** `runs.log`, the last 256 KB of `crash.log` and the last 1 MB
of `events.log` are also kept in `$XDG_STATE_HOME/irondivi/<datadir id>/`
(default `~/.local/state/…`), or `/var/log/irondivi/<datadir id>/` when
running as root, or `~/Library/Logs/IronDivi/<datadir id>/` on macOS
(records from before the data dir is known go to `_unresolved/` under the
same root, §3 intro "Before the data dir is known"), so a
deleted data dir, a wiped volume, or an argument error before the data dir is
known still leaves a record. If neither location is writable the node records
"mirror unavailable" in `runs.log`. **Another filesystem when there is
one.** The mirror's job includes surviving a hung or failed data-dir disk
(the A1 bound, A17), so of the writable candidates — the location above,
then `$XDG_STATE_HOME` when running as root, then `/var/tmp/irondivi-<uid>/`
— the node uses the first whose filesystem (`st_dev`) differs from the data
dir's. When all of them share it (a one-disk machine, a container with one
volume) it uses the first writable one and the `start` record says
`mirror-same-fs=yes`, so a reader knows a hung disk could have held both.

**Path record of the running process.** A node started with a relative
`-datadir` or `-conf` keeps that path as given (`compute_data_dir`,
bin/irondivid/src/main.rs about line 1067, returns `args.datadir.clone()`
unchanged), so its command line names a path relative to a working
directory that a non-root diag cannot read under D5 (`/proc/<pid>/cwd` is
ptrace-checked). So the node writes a per-process record
`<mirror>/<datadir id>/running/<pid>` (mode 0600, directory 0700) as soon
as the data dir is known, holding: the absolute, canonical data dir; the
absolute conf path; the start-up working directory (A7); the executable
path (read from its own `/proc/self/exe`, which the process may read
about itself; macOS `proc_pidpath`); the binary SHA-256 (added when the
A1 hash thread finishes; it hashes `/proc/self/exe`, the running image,
not the path, so B1.2 can tell a replaced file from the running one, L3); the pid; the start time (field 22 of
`/proc/self/stat`, in clock ticks since boot; macOS `p_starttime` from
`proc_pidinfo`); and the uid. Under `-daemon` the final grandchild writes
it with its own pid. It is removed on every `die()` path and replaced at
the next start; a record whose pid no longer exists, or whose start time
differs from the live process's `stat` field 22 (still readable under
D5), is stale and ignored. It is a local file only: §6.2 replaces each
path in it by its pseudonym before anything from it is packaged, and the
record file itself is never copied. Diag finds it without knowing the
data dir by listing `running/` under every mirror root of A14 (the
XDG/`~/.local/state`, `/var/log/irondivi`, `~/Library/Logs/IronDivi` and
`/var/tmp/irondivi-<uid>` roots). A diag running as a **different** user
from the node (the node under a service account, diag as the login user)
cannot read a 0600 record of another user; B1 then says so and prints the
`sudo -u <node user>` hint.

### A15. `rpc-methods.log` — what was run

Every request, on every transport (JSON-RPC, Electrum, Web UI, ZMQ), is
counted in two aggregate tiers: `rpc-aggregate.log`, one line per minute
per method (count, errors by code, p50 and p99 duration), and
`rpc-aggregate-hourly.log`, the same per hour; each aggregate line also has
the number of distinct callers in that interval (a count only). A per-call
line in `rpc-methods.log` — time, method, transport, caller (loopback, or an
IP pseudonym), result (ok or error code), duration — is written only for:

- every call to a **rare state-changing method** — `stop`,
  `setlogconfig`, `backup*` and the rest of the list A12 names
  that is not below or in the next item — from any caller, with no cap;
  these are the lines the log exists to keep (V5);
- calls to `import*`, `dump*` and `*passphrase*`, from any caller,
  capped at 100 an hour per method (`dump*` joined in r10, Y6: a script
  looping `dumpprivkey` rolls the log as an import loop does), with one
  line `<method>: <n> more calls not listed` for each hour that went over (W3). r7 left them uncapped on the ground
  that a local script cannot call them fast enough to roll the log; that
  was wrong (a script calling `importaddress` in a loop, or retrying
  `walletpassphrase`, can), and an uncapped flood would push out the
  `stop` and `setlogconfig` lines above;
- calls to the **high-rate state-changing methods** `send*`,
  `*broadcast*` and `sign*` from a **local or authenticated JSON-RPC
  caller or the local Web UI**, at most 100 lines an hour **per method**;
  the rest of that hour's calls are in the aggregates and the hour's
  `rpc-methods.log` gets one line `<method>: <n> more calls not listed`
  (V5). Without this cap a local wallet script looping `sendtoaddress` or
  `signrawtransaction` rolls the 2 MB log and pushes out the `stop` and
  `setlogconfig` lines, which r6 left uncapped for local callers;
- state-changing calls from remote Electrum or remote Web UI callers (for example
  `blockchain.transaction.broadcast` on a public server, which a client
  can send 100 times a second, cheaply rejected) get the error-style cap
  instead: the first 5 per (method, result, transport) in each hour and at
  most 50 such lines an hour, the rest in the aggregates; otherwise a
  broadcast flood would roll the 2 MB log and push out the local `stop`,
  `setlogconfig` and `send*` lines this log exists to keep;
- the first call of each (method, caller) pair in each hour, **for local
  or authenticated JSON-RPC callers only**, so a client that polls
  `getinfo` ten times a second costs one line an hour. Remote Electrum and
  Web UI callers get no first-call lines (a public server sees thousands of
  addresses an hour); they are in the aggregates and the distinct-caller
  count;
- a call that returned an error, for the first 5 per (method, error code,
  transport) in each hour and at most 50 in all per hour; later ones are in
  the aggregates' error counts.

This bounded split is what makes the retention in A14 hold: a busy client, a
public Electrum server, a remote broadcast flood or an error flood can no
longer roll the log through in minutes.

**Total cap and reserved lines** (X3). The caps above are per method,
and about ten methods are capped, so a script looping several of them
could still write about 3.6 MB a day and roll the 2 MB log within a day.
So all capped lines together (`import*`, `dump*`, `*passphrase*`, `send*`,
`*broadcast*`, `sign*`, the remote state-changing calls) stop at **200 an
hour in all**; the rest of that hour's calls are in the aggregates, with
one line `<n> more calls suppressed (total cap)`. And every uncapped
line — `stop`, `setlogconfig`, `backup*` and the rest of the
rare list — plus the first call of each capped method in each hour is
written a second time to its own file, `rpc-methods-reserved.log` (1 MB,
mode 0600 like the rest), which capped lines never enter. When that file
is full, the oldest line of the method that has the most lines in it is
dropped, so a `backupwallet` loop rolls only its own lines and an earlier
`stop` stays. So that a drop never rewrites the file on every append, the
file is kept as per-method segments, or with a per-method offset index
(Y6). Diag collects both files and shows them merged by time.
**In-flight calls.** Each transport's request handler (the JSON-RPC
middleware that already takes `ConnectInfo<SocketAddr>`, server.rs about
line 1810; the Electrum session loop; the Web UI handler) records the call
in a fixed in-flight table when it starts — method, transport, caller
kind, the monotonic start time ("in call since"), the handling thread or
task — and clears the slot when it returns. The A17 watchdog reads the
table without locks; `getdiaginfo` lists the calls in flight. No
parameters are recorded. The hourly aggregates keep 30 days, or about 14 at the worst
case of 50 methods active every minute (A14), so "Electrum stopped
answering last week" shows as the hour (and, for the last 48 hours, the
minute) the counts or latencies changed.
**Never parameters.** For errors, the error message is also kept, for the
last 20 errors per method (in `getdiaginfo` and the package), so a generic
-32603 or an Electrum error still says what went wrong. Error text often
echoes the call's own arguments ("Invalid address: <the address>",
"Invalid passphrase for <label>"), so before it is stored it passes A11
typing **and** the §6.2 step 2 "Old-log lines" masking: every argument,
quoted string, number and address-shaped token is replaced by its kind
(`<addr>`, `<str>`, `<num>`), and only the fixed message text is kept.
Every transaction a local caller submitted for broadcast
(`sendrawtransaction`, Electrum `blockchain.transaction.broadcast`, the Web
UI, a `divi-swapd` request), **whether the node accepted it or rejected
it**, is recorded as **sent from here**: its txid joins the A11 own set, so
it is pseudonymised in every later line, treated as the user's own by §6.2,
kept out of `rejected-tx/` and `chain-events.log` (A13), and covered by the
own-invalid question in §8.2. **Where the set lives:** not in
`rpc-methods.log`, which never holds a txid, but in a private
`<datadir>/diag/sent-txids` file — mode 0600, one raw txid and day per
line, capped at 1 MB with the oldest dropped. It is **never packaged**:
no collector reads it into the package, and §6.3 refuses a package that
contains it or any line of it. §6.2 step 1 takes the set from
`getdiaginfo`'s `known_values` on a running node, or reads the file
directly when the node is down. This answers "I ran something and then it broke" for
everything that reached the node. `irondivi-cli` also appends the method name
and result (no parameters) to the same mirror directory, so failed
connections that never reached the node are recorded too. The Web UI reports
its own JavaScript errors (message, file, line; no values) to a local
endpoint that logs them at the `webui` target, rate-limited.

### A16. Release builds keep their debug information

Each of the 12 release targets keeps its unstripped binary and the build-id.
The release script uploads them to the developer's private release storage
(not the public release) keyed by build-id. A release check fails if any
target's unstripped binary is missing or its build-id differs from the
shipped one. `runs.log` and `crash.log` record the build-id.

### A17. Hangs and lock waits

- The main locks (chain state, wallet, mempool, peer manager, masternode
  list) are wrapped in a timed lock that records any wait over 1 s with the
  lock name and the holder's task name; counts are in health, long waits in
  `events.log`.
- A watchdog thread (a plain OS thread, not tokio) wakes every 1 s and
  writes an incident when **any** of these holds: the health tick has not
  progressed for 60 s; the tokio runtime has not progressed for 60 s
  (either one alone is enough — a stuck health thread with a live runtime,
  or a stuck runtime with a live health thread, is a hang); a call in the
  A15 in-flight table (JSON-RPC, Electrum or Web UI) has been in progress
  for more than 60 s; a timed-lock wait (above) has lasted more than 60 s;
  or diag asked for one (**snapshot request**, below). One incident is
  written per stuck item (keyed by the method and handler thread, or the
  lock), at most one every 10 minutes for the same item. **Daily budgets
  are per class** (X3), so one flood cannot use up the budget another kind
  of hang needs: in-flight calls 10 a day; lock waits 10 a day; health-tick
  and runtime stalls 10 a day, and the **first** health or runtime stall
  of a run is always written, even when that budget is used up; snapshot
  requests at most one every 10 s and 20 a day. In r6 the 10-a-day budget
  was shared, so a client that kept ten slow calls running each morning,
  or a script that kept creating snapshot requests, left no incident for a
  real whole-node hang later that day. When a class's budget runs out the
  watchdog writes one `events.log` line `incident budget exhausted for
  <class>` (once per class per day) and writes no more incidents of that
  class until the day rolls; diag, finding a snapshot request unanswered
  and that line present, reports "snapshot refused: budget" rather than
  "node did not answer". The incident holds every thread's name, state
  and `wchan` (`/proc/self/task/*/stat`, `/wchan`; a `wchan` of `0` is
  written by the `stat` state letter: `running` for `R`, since a running
  thread has no wait channel and `0` is expected, and `hidden` for `S`,
  `D` or any other state, M3, N3; whether a non-root node reads its own
  sleeping threads' `wchan` as `0` is not yet measured, §10 item 1), the
  current lock
  holders, the tokio runtime metrics, the A11 counted-list counters since
the last hourly count line (atomic loads, crashes S1), I/O counters from
`getrusage`
  (never `/proc/self/io`, which a non-root D5 node is refused), the
  hardware capability words from `getauxval` (never `/proc/self/auxv`),
  a line `refused by kernel: <entries>` naming each `/proc/self` entry it
  tried and was refused (M2), and a frame-pointer stack of each thread. On Linux the
  stacks are collected by sending each thread a real-time signal whose
  handler records its stack into the incident buffer. **The stack
  signal** (F3, P5) is `SIGRTMIN()+k`, read at run time (glibc keeps the
  first two real-time signals for itself, so the number is never a
  constant). At start the node checks with a null `sigaction` that the
  signal has no handler, takes the next free one if it has, and records
  which in the A7 start record. It is installed with `SA_SIGINFO |
  SA_ONSTACK | SA_RESTART` and is sent only with `tgkill` to tids in the
  node's own thread table, never to another process. `SA_RESTART` does
  not cover every call: `poll`, `epoll_wait`, `select`, `nanosleep`,
  `clock_nanosleep`, timed waits such as `sem_timedwait`, and socket
  reads under `SO_RCVTIMEO` still return `EINTR` when the handler runs,
  so every such call in the node's code must retry on `EINTR`, and the
  §10 item 1 soak looks for one that does not. On Linux only threads that
  have an alternate stack are signalled (A5 "Alternate stacks": on gnu
  every thread started through the interposed `pthread_create`,
  RocksDB's included; on musl every thread through
  `--wrap=pthread_create`; on both, the main thread, A5 "The main
  thread"); any other thread is recorded `no stack: no alternate stack`
  and marked expected (glibc's internal helper threads and raw `clone`
  threads) or unexpected, from its `comm`, as a hint only (A5 "Threads
  with no alternate stack", R9-2), and a thread whose stack allocation
  failed is recorded `no stack: alloc failed`. This limit belongs to the
  Linux signal path only; the macOS walk below reaches every thread
  (R10-1). The handler first checks with
  `sigaltstack` that it is running on the alternate stack (`SS_ONSTACK`)
  and writes nothing if not. **The sweep is
  bounded** (K1), because a thread in state `D` (a hung disk) or one with
  the signal blocked never runs the handler, and an unbounded wait would
  mean no incident and, under `-startuptimeout`, no exit. Before
  signalling, the watchdog reads each thread's `State` and `SigBlk` from
  `/proc/self/task/<tid>/status` (readable to the node itself under D5,
  §10 item 1) and does not signal a thread in `D` or one whose `SigBlk`
  holds the stack signal; it records `no stack: state D` or `no stack:
  signal blocked` for it. It waits at most 200 ms for each signalled
  thread and 2 s for the whole sweep, then writes the incident with the
  stacks that arrived and names the rest: `no stack: no answer in 200 ms`,
  or `no stack: sweep time used up` for threads it did not reach. **Slots**
  (F2): each sweep has a number, stored before the signals go out, and
  takes fresh per-thread slots from a small ring; a slot's state is an
  atomic WAITING, WRITING, DONE or ABANDONED. The handler claims its slot
  by compare-and-swap from WAITING to WRITING, conditioned on the sweep
  number still being current, and sets DONE with release ordering when
  it has written. At the deadline the watchdog moves every slot still
  WAITING to ABANDONED, so a handler that arrives late fails its claim
  and writes nothing. A slot still WRITING at the deadline is recorded
  `no stack: torn` and is not reused until its handler sets DONE; if the
  ring has no free slot for a thread, that thread is recorded `no stack:
  no free slot`. The incident reads only DONE slots, with acquire
  ordering. (r8 checked the sweep number only on entry, so a handler that
  passed the check and then ran slowly could still write into a buffer
  reused by the next sweep.) The start-up bound's exit 10
  (A1, `-startuptimeout`) never waits for an incomplete sweep: the
  incident is written with what arrived and the exit follows. macOS has no
  real-time signals and no per-thread signal delivery a watchdog can rely
  on, so there the watchdog thread itself does it for each other thread:
  `thread_suspend`, `thread_get_state` (`ARM_THREAD_STATE64` /
  `x86_THREAD_STATE64` for PC, SP, FP), a frame-pointer walk over that
  thread's stack range, then `thread_resume` — never
  holding a lock or allocating while a thread is suspended. It walks
  **every** thread `task_threads` lists except the watchdog and the
  helper itself, alternate stack or not (R10-1). The stack range is read
  before `thread_suspend`, because it takes libpthread's thread-list
  lock, which a suspended thread might hold: `pthread_from_mach_thread_np`
  gives the thread's `pthread_t`, and `pthread_get_stackaddr_np` and
  `pthread_get_stacksize_np` its stack top and size. A thread with no
  `pthread_t` gets its range from `mach_vm_region` on the region that
  holds its SP, read after the suspend (a kernel call, no user-space
  lock); if neither gives a range, it is recorded `no stack: no stack
  range`. A thread can exit between the range read and the suspend, and
  its range can then be stale (platforms R11-1): after `thread_suspend`,
  the SP from `thread_get_state` must lie inside the range read earlier,
  and if it does not, the range comes from `mach_vm_region` as above. A
  `thread_suspend` that fails with `KERN_INVALID_ARGUMENT` or
  `MACH_SEND_INVALID_DEST` means the thread has exited; it is recorded
  `no stack: thread exited`, not as an error. A thread
  waiting in the kernel (`thread_basic_info` `run_state`
  `TH_STATE_WAITING` or `TH_STATE_UNINTERRUPTIBLE`) is recorded with `in
  kernel` beside its user-space stack, and the same 200 ms per thread and
  2 s per sweep bounds apply, with threads not reached named as on
  Linux (K1). The suspend, the `thread_get_state` and the walk run on a
  **helper thread** (P5), not on the watchdog: the watchdog waits for the
  helper at most 200 ms per thread, and if it has not returned, abandons
  it, records `no stack: helper did not return`, and itself calls
  `thread_resume` on the target if the helper had suspended it. After two
  abandoned helpers the sweep ends and the rest are named as not
  reached. On macOS the
  thread states come from `task_threads`/`thread_info` and there is no
  `wchan` (written as `n/a (macOS)`). It records, and does not kill —
  except at the start-up bound when the run was started with
  `-startuptimeout` (A1), where it writes the incident to the mirror first
  and the node then exits 10 in A1's order.
  The incident records the trigger (which tick stalled, or the in-flight
  call with its method, transport and age, or the lock) and **never** the
  node's environment values or any `known_values` page: the incident is
  packaged, and the environment values are exactly what §6.2 step 1 would
  need in order to mask them (on a down or hung D5 node diag has none).
- **Snapshot request.** Diag has no other way to get thread evidence from
  a D5 node whose RPC does not answer while its health tick still runs
  (a blocked RPC handler, an exhausted `spawn_blocking` pool, a call
  waiting on RocksDB or a lock that is not wrapped): `getdiaginfo` is an
  RPC, and the node's `wchan` and stacks are unreadable to a non-root
  diag. So diag creates an empty file `diag/snapshot-request` in two
  places: `<datadir>/diag/snapshot-request` and the A14 mirror copy
  `<mirror>/<datadir id>/diag/snapshot-request`. The watchdog checks for
  them on every 1 s wake: it checks the **mirror** copy itself (the mirror
  is on another filesystem when there is one, A14), and the data-dir copy
  through a helper thread whose `stat` it does not wait for, so a hung
  data-dir disk cannot block the watchdog. When A14 recorded
  `mirror-same-fs=yes` (no other filesystem was available, so the mirror
  sits on the data-dir disk), the watchdog checks **both** copies through
  the helper (L2): a hung disk then blocks the helper, never the watchdog.
  When a request exists and is owned by the node's uid or root, the
  watchdog writes a normal incident (trigger `snapshot-request`) to the
  mirror itself (or, under `mirror-same-fs=yes`, hands that write to the
  helper too); **every data-dir operation — the incident copy there and
  the `unlink` of both request files — runs on the helper thread** (X3).
  r6 had the watchdog delete the data-dir request file itself, which a
  hung data-dir disk would block. The helper is one persistent thread
  with at most one operation outstanding: when the previous operation has
  not returned, the watchdog skips the data-dir work for this request and
  records `data-dir helper busy since <t>` in the mirror incident, so a
  hung disk costs one stuck helper, not one more thread per request.
  Because the request file can only be removed by the helper, a request
  that is still there when the helper is stuck is not honoured again: the
  watchdog remembers the request's inode and mtime and answers each
  distinct request once. Requests are honoured at most once every 10 s
  and 20 times a day (the snapshot class budget above). No signal, no ptrace and no RPC is involved. Only a diag running
  as the node's user or as root can create the file (`diag/` is 0700),
  which is the same user who could read the node's files anyway; a diag
  of another user gets the B1 `sudo -u <node user>` hint. B2.16 uses it. The watchdog sleeps in steps of
  1 s and measures, on `CLOCK_MONOTONIC`, how late it woke. A wake-up 30 s
  or more late means the process was not scheduled for that long. That has
  different causes, which it tells apart in this order:
  1. An A3 `CONT` record (SIGCONT received) inside the late interval is
     conclusive: the process was **stopped** (SIGSTOP, a job-control stop),
     "process not scheduled N s (stopped, SIGCONT from <sender>)".
  2. `cgroup.events` `frozen` / v1 `freezer.state` is used only while it
     is **still** set (`1`/`FROZEN`) at the wake; after a thaw it has
     already gone back, so a post-hoc read proves nothing and is not used.
  3. **Starved** is said only from **cgroup-scoped** deltas since the last
     wake: the node's cgroup `cpu.stat` `nr_throttled`/`throttled_usec`,
     the cgroup's own `memory.pressure`/`cpu.pressure`/`io.pressure`
     `full` totals, and the process's own major faults. When those are
     clearly non-zero it writes "process starved N s: cpu throttled X s,
     memory stall Y s, major faults Z", with the deltas.
  4. When they are near zero, it writes "process not scheduled N s
     (stopped or frozen)" (`docker pause`, the host pausing the VM, a stop
     with no `CONT` record).
  5. When no cgroup-scoped pressure source exists (cgroup v1, no cgroup
     PSI files) and only the system-wide `/proc/pressure/*` shows a stall,
     that stall may be other processes'. It does not choose: "process not
     scheduled N s; host under pressure (system-wide PSI), cause
     uncertain", with the system-wide deltas. In both cases it **subtracts** the late interval from its 60 s
  hang clock instead of resetting it, so a freeze is not reported as a
  hang, but a thread that stays stuck through repeated starvation still
  reaches 60 s of scheduled time and is reported. On macOS, where neither
  cgroups nor PSI exist, the deltas are the process's own CPU time and
  faults from `proc_pid_rusage` and the `kern.memorystatus_level` change,
  and the record says which it used. (On Linux `CLOCK_MONOTONIC` does not
  advance during system suspend, so a suspend is not mistaken for a freeze;
  A6 sees suspend through `BOOTTIME − MONOTONIC`.)
- The watchdog also compares the per-thread table (A5) with
  `/proc/self/task` (macOS: `task_threads`) every tick: a thread that
  vanished without its `on_thread_stop` record (killed by seccomp
  `KILL_THREAD`, or exited from C++) is written to `crash.log` and
  `events.log` with its name and tid, as the "thread vanished" record A5
  and §7.1 refer to.

### A18. Flags added for diag

- `-walletbroadcast=0` (new; default 1): skips `resubmit_wallet_txs`
  (about `main.rs:1702`, called at about `:2029`) and every wallet relay.
  Today the key is unknown and ignored (the "Unknown option" warning at
  about `main.rs:876`). Test: a regtest node with an
  unconfirmed wallet transaction, started with `-walletbroadcast=0` and one
  peer, never sends that transaction to the peer and does not put it in its
  own mempool.
- `-createwalletbackups=0` (existing key, today accepted but ignored,
  about `main.rs:352`): gate `backup_at_start` (about `main.rs:1521`,
  `backup.rs:166-176`)
  on it, so a start with `=0` neither writes a backup nor prunes
  `backups/` or `monthlyBackups/`. Test: both folders byte-identical after
  such a start.
- `-logwalletdetail=1` (new; default 0): A11.
- `-startuptimeout=<s>` (new; default unset): with it, the A1 start-up
  bound ends the run with exit 10 after `<s>` seconds without progress (R3);
  without it, the bound only records. Only B3.2's observed start passes it.
  Test: a start-up stall with the flag exits 10 with the mirror record; the
  same stall without it records the incident and keeps running.
- Existing flags used by diag, checked to exist in `main.rs`: `-staking`,
  `-daemon`, `-printtoconsole`, `-disablewallet`. `-masternode` is **not**
  passed: irondivid refuses to start whenever the key is present, whatever
  its value (about `main.rs:855-861`).
- Diag reads the binary's version first and knows which of these the binary
  supports. An observed start (B3) of a binary that has a wallet but lacks
  `-walletbroadcast` or a working `-createwalletbackups=0` (0.2.9 and
  earlier) runs with `-disablewallet`; `-debug=1` is added only on a binary
  with A11, otherwise the run logs at the default level.

---

## 4. Part B — `irondivi-cli diag`

`irondivi-cli diag [--datadir D] [--conf F] [--run|--no-run]
[--submit|--no-submit] [--out DIR]`, plus the
recording modes in B6. Implemented in a new crate `crates/divi-diag`, linked
into `irondivi-cli` (so it does not depend on `irondivid` starting), with a
`--diag` alias on `irondivid` that `exec`s the sibling `irondivi-cli`.

### B1. Finding what to diagnose

**B1.1 Data dirs.** Every candidate, in order, de-duplicated by device and
inode: `--datadir`; `datadir=` in `--conf`; the `-datadir`/`-conf` of every
running `irondivid` (`/proc/*/cmdline`, macOS `sysctl kern.procargs2`);
systemd units, OpenRC scripts, launchd plists, Docker/Podman containers
whose command names `irondivid` (their `-datadir`, `User=`,
`WorkingDirectory=`, volumes); the default for the current user; `/root`,
every `/home/*` and `/Users/*` default (`.irondivi`,
`Library/Application Support/IronDivi`); `/etc/irondivi/`, `/var/lib/irondivi`.
A data dir is anything holding `irondivi.conf`, `blocks/`, `chainstate/`,
`wallet.dat` or `diag/runs.log`.

**A running node's paths.** A `-datadir=` on a node's command line can be
relative, and the node may have been started with no `-datadir` at all
from a working directory or `$HOME` diag cannot see. So for each running
`irondivid` pid diag uses, in order:
1. The A14 path record `<mirror>/<datadir id>/running/<pid>` whose pid
   **and** start time (stat field 22; macOS `p_starttime`) match the live
   process; a record whose pid is gone or whose start time differs is
   stale and ignored (and listed as stale). It gives the absolute data
   dir, conf, cwd and binary. Diag lists `running/` under every mirror
   root it can read (A14).
2. `/proc/<pid>/cwd` (macOS `proc_pidinfo(PROC_PIDVNODEPATHINFO)`), when
   readable, to resolve a relative `-datadir`/`-conf`.
3. Neither: the summary says so plainly — "running node <pid> uses a
   relative data dir (`<arg>`) and its working directory is unreadable
   (D5)" or "running node <pid> has no `-datadir` and no path record, so
   its data dir is unknown" — with the command that reads it (`sudo -u
   <node user> irondivi-cli diag`, under the CapEff rule in A5). Diag
   **never** substitutes the default data dir for that node. The default
   dir is still listed as its own candidate, but is never labelled as the
   running node's.

Before any `/proc/<pid>` read that needs ptrace access (`cwd`, `exe`,
`environ`, `io`, `fd/`, `wchan`, `ns/*`, `stack`), diag runs the A5
readability check. When the node is unreadable it records the refusal once
and skips those reads instead of collecting zeros or errors.

- One found: use it. Several: list each (owner, network, size, last
  `runs.log` start, running or not) and ask which; with no tty, collect all of
  them, each in its own subfolder, and say so in the summary — the
  "two nodes" case.
- A candidate diag cannot read (EACCES): the summary says so, names the owner,
  and prints the exact command (`sudo -u <owner> irondivi-cli diag --datadir
  <path>` or `sudo irondivi-cli diag …`). The `sudo` (root) form is printed
  only when root would get `CAP_SYS_PTRACE` (A5 "Non-dumpable process":
  checked from `CapBnd` before suggesting it); inside a container without
  it, only `sudo -u <owner>` is printed. Diag never re-runs itself with
  `sudo`.
- None found: diag still collects B2 system sections, the A14 mirrors (which
  survive a deleted data dir), and records "no data dir found" with every path
  it looked at — the "deleted datadir" and "container recreated" cases.

**B1.2 Binaries.** Every `irondivid` and `irondivi-cli` on `PATH`, in the
unit/container command, in the running process (`/proc/<pid>/exe`, including
`(deleted)`; when a D5 node refuses that link, the `exe` path and SHA-256 in
its A14 path record, marked "from path record"; L3: diag then hashes the
file now at that path and compares: on a match it records "binary on disk
matches the running one", on a mismatch or a missing file it records
**"running binary differs from the file on disk"** with both hashes, so an
upgrade that replaced the file under a running node is not reported as the
running build), and next to diag: path, SHA-256, size, mtime, ELF/Mach-O class
and machine, interpreter (`PT_INTERP`; musl static = none), build-id,
`--version` output (run with a 5 s timeout, `exec` errors recorded verbatim:
`Exec format error`, `No such file`, missing loader, `GLIBC_2.xx not found`),
the build-id matched against the release list compiled into diag, and the
file's quarantine/signature state on macOS (B4.2).

**B1.3 Config files.** Every `irondivi.conf` and `masternode.conf` found,
parsed with the node's own parser, rendered per §6.2.

**B1.4 When diag itself cannot run.** Of the 12 release archives, the
static-musl ones (`x86_64-linux-musl`, `aarch64-linux-musl`,
`armv7-linux-musl`) carry an `irondivi-cli` that runs on any Linux kernel of
that architecture whatever its libc; the summary of a failed `exec` names the
matching one. `i686`, `powerpc64le`, `riscv64` and `s390x` ship glibc builds
only (glibc 2.31 or newer). Decision: static-musl `irondivi-cli` builds for
`i686`, `powerpc64le` and `riscv64gc` are optional release work, not part of
this plan; `s390x` stays glibc-only. On those, or anywhere the CLI cannot
run, the release also ships `contrib/diag.sh`, a POSIX `sh` script (no
bashisms, tested under `dash` and busybox `ash`) that collects the subset
listed in §7.1 as "sh" — which includes `runs.log` and the other Part A
files and the filtered kernel log (B2.11) — and builds the same folder
layout without the scanner. Those logs are not redacted yet, so `diag.sh`
creates the folder with mode 0700 and says so. It **never packs, encrypts
or sends**, and it carries no developer key (§8.4): an encrypted file made
from an unredacted folder would look sendable, and the user could email
it. Only `irondivi-cli diag --import` turns the folder into a sendable
file. It prints the folder path and "run `irondivi-cli diag --import <folder>`
on any machine where irondivi-cli runs to review and send it" — the import
(B6.4) redacts and scans the folder before anything leaves.

### B2. Collectors

Every collector runs as its own process: `posix_spawn` of `irondivi-cli diag
--collector <name>` on every platform, results over a pipe. Diag never calls
`fork` once any thread exists (a forked child of a threaded process can
deadlock on a lock another thread held). Each collector has its own time
budget (B5) and memory cap (1 GB, or 512 MB on 32-bit; see "Memory cap"
below). A collector that times out is killed, its partial output kept and marked
`TRUNCATED: <collector> exceeded <n> s`; diag goes on. A collector that does
not die within 5 s of SIGKILL (uninterruptible sleep, typically a hung NFS
or SD card) is abandoned: diag polls `waitpid(WNOHANG)` for those 5 s, then
records its pid, its `stat` state, and its `wchan` and `/proc/<pid>/stack`
(only when readable; a `wchan` of `0` is written by the `stat` state
letter, `running` for `R` and `hidden` otherwise, M3, N3) as
`ABANDONED (uninterruptible)` — that record is itself evidence of the
storage hang — and goes on without waiting for it. Output is bytes:
non-UTF-8 is kept with `\xNN` escapes, never dropped.

**Memory cap.** Diag does not use `RLIMIT_AS` (a limit on address space,
not on memory used): a threaded Rust program reserves far more address space
than it touches — each glibc malloc arena reserves 64 MB — so that limit
fails collectors that are using little memory. Instead, on Linux each
collector runs in a transient cgroup whose `memory.max` is the cap when diag
can create one: as root, `systemd-run --scope` (the system manager; root
has no user manager to ask), as any other user `systemd-run --user
--scope`, or failing both a writable cgroup v2 subtree. Otherwise the
collector sets `RLIMIT_DATA` (heap and private mappings only) on itself as
its first action — but only on Linux 4.7 or later: before 4.7
`RLIMIT_DATA` counts only `brk`/data and not `mmap`, and glibc malloc and
Rust's large allocations use `mmap`, so on such a kernel with no usable
cgroup (RHEL/CentOS 7 at 3.10) the parent instead reads the collector's RSS
from `/proc/<pid>/statm` every 500 ms and kills it above the cap, as on
macOS. Collectors run with `MALLOC_ARENA_MAX=2` so glibc keeps few arenas.
macOS enforces neither limit, so there the parent reads the collector's
footprint with `proc_pid_rusage` every 500 ms and kills it above the cap.
`diag.log` records which mechanism applied to each collector (`cgroup
system scope`, `cgroup user scope`, `cgroup subtree`, `RLIMIT_DATA`,
`statm poll`, `rusage poll`). A collector
stopped by the cap is recorded as `MEMORY CAP: <collector> exceeded <n> MB`,
not as a crash, when any of these holds: it ended with 134 after printing
Rust's "memory allocation of N bytes failed", its cgroup's `memory.events`
`oom_kill` count rose, or the macOS parent killed it. Its partial output is
kept, as for a timeout.

**Node in a container, diag outside it.** A separate pid namespace is not
a container (V4): systemd's `PrivatePIDs=yes`, `unshare --pid --fork`
and some sandboxes give the node a nested pid namespace while it shares
the host's filesystem, data dir and network. r6 declared "container"
from the `NSpid:` field count alone and would then have skipped B3 and
B2.16 on such a node for no reason. So two questions are kept apart.
**Other pid namespace:** the `NSpid:` line of the node's
`/proc/<pid>/status` has more than one field (readable under D5 to any
reader), or, when readable, `/proc/<pid>/ns/pid` differs from diag's.
This alone is recorded (`node in another pid namespace`) and changes
nothing but how pids are printed. **Container:** declared only on
positive evidence, checked in this order, and the record names which one
decided: (1) `/.dockerenv` or `/run/.containerenv` seen through
`/proc/<pid>/root/` (ptrace-checked, so only when the readability check
passed); (2) `container=` in pid 1's `environ` of the node's pid
namespace (root with `CAP_SYS_PTRACE` only); (3) the node's
`/proc/<pid>/cgroup` path names a container runtime: `docker`,
`containerd`, `podman`, `libpod`, `lxc` or `kubepods`; `machine.slice`
counts only when the same path also holds `lxc`, `libpod` or `docker`
(N5; libvirt uses `machine.slice` for its virtual machines, so it alone is
not evidence); and a `machine-<name>.scope` under `machine.slice` whose
name does not start with `qemu` or `lxc` is a systemd-nspawn container
named `<name>`. Scope names are unescaped first, as `systemd-escape
--unescape` does (`\x2d` is `-`), before any match and before any name is
printed (P3); a `machine-lxc-<id>-<name>.scope` (written
`machine-lxc\x2d<id>\x2d<name>.scope`) is a libvirt-LXC container named
`<name>`, not nspawn; (4) the node's root is not diag's root (N2, W4):
diag takes the **last** mount line whose mount point (field 5) is `/`
(P1; a later mount over `/` hides the earlier ones) from the node's
`/proc/<pid>/mountinfo` (readable to every reader on hp3) and from its
own `/proc/self/mountinfo`, and the node is in another root when field 3
(the device `major:minor`) or field 4 (the root of the mount within its
filesystem) differs, or when the node's mountinfo has no `/` line at all
(a plain `chroot` into a directory that is not a mount point, P1). The filesystem type is never compared — a Raspberry
Pi with `overlayroot`, a live-USB system and Fedora CoreOS or Silverblue
run the host itself from an `overlay` root, so "the root is overlay" says
nothing — and the mount IDs (fields 1 and 2) are never compared, since
they are numbered per mount namespace. A host node under systemd
`RootDirectory=` or `RootImage=`, or in a `chroot`, also has another root
and is declared a container by this signal; that is right for what diag
can reach, and the record says `root differs (signal 4)`. When none of
(1)–(4) holds, the node is treated as a host process: B2.7–B2.10, B2.16
and B3 run normally, and only a step that actually fails is marked. (5)
Diag also records, as a fact only and never as container evidence (N1),
whether the node's data dir (from its command line or the A14 path
record) and its RPC port are both unreachable from diag: a host node
running as its own user with a 0700 data dir, held in start-up before its
RPC binds, gives the same result. When (5) is the only thing that looks
wrong, B3, B2.16 and B2.7–B2.10 run as for any host node (a step that
fails is marked with its own error), and the summary prints both `sudo -u
<node user> irondivi-cli diag --run` (the user named from the node's
`/proc/<pid>/status` `Uid`; `sudo -u '#<uid>'` when `getpwuid` finds no
name for it, P3) and the container hint below, in case the
node is in a container diag could not see. When one
holds, diag still collects what is true of
the host (B2.1–B2.3, B2.6 for the filesystems it can see, B2.11–B2.13,
B2.15, B2.18, B2.19), but refuses B3 and the collectors that need the
node's own namespace (B2.4's in-container view, B2.5's in-container
supervisors, B2.7–B2.10 when the data dir is not reachable from the host,
B2.16), each marked `SKIPPED: node in container <c>`. The summary prints
`docker exec <c> irondivi-cli diag --run` (or `podman exec`, `lxc-attach`,
`pct enter`; for a systemd-nspawn container `machinectl shell <name>
/usr/bin/irondivi-cli diag --run`, with the CLI's path inside the
container, N5; for a libvirt-LXC container `virsh -c lxc:///
lxc-enter-namespace <name> -- /usr/bin/irondivi-cli diag --run`, P3;
every name unescaped) and offers `diag --host <c>` (B6.2) for the host
half. **When only signal (4) decided** (P2) — no other signal holds —
and the node shares diag's network namespace (its `ns/net` link equals
diag's when readable, or its RPC answers on loopback), B2.16 still runs:
the node's RPC and its `/proc` entries are as reachable as for any host
node. B3 and B2.7–B2.10 stay `SKIPPED: root differs (signal 4)`.

The printed commands work on a container whose root filesystem is
read-only and whose `/tmp` and `/dev/shm` are `noexec`, and never use
`docker cp` (which cannot write into a read-only root filesystem, and
`docker cp` into a tmpfs such as `/dev/shm` writes under it into the
layer, not the tmpfs). Nothing is executed from `/dev/shm`; it is only
written to.
- **Image has no `irondivi-cli`, and `sh` exists:** the script is fed on
  stdin, so nothing is copied in to run: `docker exec -i <c> sh -s --
  --out /dev/shm/irondivi-diag < contrib/diag.sh`. When `/dev/shm` is
  absent or full, `--out` names a directory on the node's data volume.
- **The static CLI is wanted** (for `getdiaginfo` and B3): it is copied
  into the **data volume** from the host side (the volume's host path, from
  `docker inspect` Mounts, or `docker exec -i <c> sh -c 'cat >
  <volume>/irondivi-cli && chmod 700 <volume>/irondivi-cli' <
  irondivi-cli`) and run from there, since the volume is the one place in
  such a container that is both writable and, normally, executable. When
  the volume is mounted `noexec` too, diag says so and uses the script.
- **Bringing the result out:** `docker exec <c> tar -C
  /dev/shm/irondivi-diag -cf - . | irondivi-cli diag --import -`: the
  import reads the tar from stdin, so the **unredacted** collection never
  lands on the host's disk (L1). When the image has no `tar`, `diag.sh
  --emit-shar` writes the folder to stdout as a shell archive of `printf`
  lines, which the host side runs with `sh` inside a folder diag creates
  with mode 0700 under `umask 077`; `irondivi-cli diag --import <that
  folder>` (B6.4 redacts and scans it) then deletes the raw folder when
  the import finishes, and says so. Both the in-container script and the
  CLI run under `umask 077`, and the `--out` folder they write is created
  with mode 0700.
- **Cleaning up inside the container (L1):** after the result is out,
  the printed commands end with `docker exec <c> rm -rf
  /dev/shm/irondivi-diag` (or the `--out` folder on the data volume) and,
  when the CLI was copied in, `docker exec <c> rm -f
  <volume>/irondivi-cli`. The unredacted folder in `/dev/shm` otherwise
  stays there until the container stops, readable by anything that runs
  as the same user in the container, and the copied CLI stays in the
  user's data volume for ever. Diag's summary checks with `docker exec <c>
  test -e` that both are gone and prints the leftover path if not.
- **Image has no `sh`** (distroless): diag says so and points to §7.2 L3:
  only the host half (`diag --host <c>`) can be collected.

Diag also refuses, with the step that fixes it, when the data dir is on a
macOS path that returns `EPERM` under TCC (see B4.2).

Diag checks free space by the R1 (a) rule before each collector; when the
rule fails it moves the output or stops, keeping what it has and saying
so, as R1 (a) says.

| # | Collector | Contents |
|---|---|---|
| B2.0 | Locks | Runs first, budget 10 s, `TRUNCATED` on timeout like any other: `/proc/locks` (or `lsof` on macOS) and the holders (pid, comm) of the data dir `LOCK` and `.lock`, so a later collector that blocks on a lock is explained. |
| B2.1 | Identity | diag version, run time, timezone, uid/euid, tty yes/no, how invoked, locale. |
| B2.2 | Host | OS release, kernel, arch, `uname -a` without nodename, CPU model/flags/count, cgroup-visible CPUs (`cpu.max`, `cpuset.cpus.effective`), memory, swap and its devices, `vm.overcommit_*`, `vm.swappiness`, THP mode, page size, uptime, boot id, load, PSI, time sync state (`timedatectl`, chrony/ntpd tracking, macOS `sntp` query), clock offset from the B2.15 probe, entropy pool, `ulimit -a` of the node's user. |
| B2.3 | Container and virtualisation | `systemd-detect-virt`, `/proc/1/environ` `container=` (name only), `/run/.containerenv`, `/.dockerenv`, `/proc/self/cgroup`, `/proc/1/cgroup`, `/proc/self/mountinfo` (paths pseudonymised), the cgroup v1/v2 limits and event counters of the node's cgroup **and each ancestor** that is readable, `/proc/user_beancounters`, LXC `lxc.*` visible values via `/proc/self/status` (`CapBnd`, `Seccomp`, `NoNewPrivs`), AppArmor/SELinux label of the node, `/proc/sys/kernel/` limits visible inside, `nproc` vs host CPUs, the PID 1 start time and command; when the node itself is PID 1 in its namespace and no init (`tini`, `dumb-init`, `docker --init`) sits above it, it says "node is PID 1, no --init" (A3 then exits with `_exit(128+signo)`, and zombies are not reaped). States the container type it concluded and **why**, and prints the host-side command for §7.2 L3. Docker/Podman/Kubernetes: whether the data dir is a volume or the container's writable layer (a "recreate" loses it), restart count and policy if the socket is readable. |
| B2.4 | Processes | Every process (pid, ppid, user, start time, RSS, state, **comm and exe basename only** for non-irondivi processes — §6.2), with the full masked argv of irondivi processes; which supervisors exist (systemd, OpenRC, supervisord, runit, s6, pm2, Docker restart policy, cron and `@reboot` entries naming irondivi, `screen`/`tmux` sessions holding it — names only). Lists anything else that could kill or restart the node: `earlyoom`, `systemd-oomd` (and its `ManagedOOM*` settings for the unit), `oom_score_adj` of the node, watchdog scripts naming irondivi. |
| B2.5 | Service units | Full rendered systemd unit for any unit running irondivid (`systemctl cat`, `show` with `Environment*` dropped), its recent `journalctl -u` (200 lines), `NRestarts`, `Result`, `ExecMainStatus`, `ExecMainCode`, timestamps; OpenRC `rc-service status` and its log; launchd `launchctl print` of the job; Docker `inspect` subset (State, RestartCount, OOMKilled, ExitCode, HostConfig memory/pids/CPU, Mounts as pseudonyms) and `docker logs --tail 200` when the socket is readable. Every journal and docker log line goes through §6.2 including the step 2 "Old-log lines" rule. |
| B2.6 | Storage | For the data dir's filesystem: type, mount options, device, free space and inodes, read-only state, `df` of the output folder; the fsync test (R1 b): 10 MB written in 4 KB `write`+`fdatasync`, latency p50/p99/max, any error verbatim — explains "slow" and "corrupted after power loss" on SD cards and network filesystems. `dmesg`/journal I/O errors for that device (B2.11). SMART summary only if `smartctl` exists and runs without prompting (`-H -A`), skipped otherwise. |
| B2.7 | Data dir inventory | Every file and directory under the data dir: relative path (wallet file names pseudonymised), size, mtime, mode, owner (uid → pseudonym unless root or the node user), with RocksDB files summarised per column family directory; leftover temporaries; `OPTIONS-*` files in full **for the chain RocksDB instances only** (no secrets in them); `LOG` and `LOG.old.*` of each chain RocksDB instance, last 2 MB each (RocksDB's own record of compactions, stalls, corruption, background errors). `<datadir>/wallet/` — the wallet store, including its `OPTIONS-*`, `LOG*` and SST files — is **summarised as one total size and one file count**, with no file names, sizes or mtimes per file, and nothing in it is read (§6.1). Ownership mismatches (files not owned by the node's user — the "ran it once with sudo" case) are listed first. |
| B2.8 | Chain DB, read-only | Opened with `DB::open_as_secondary` into a temporary secondary path under `$TMPDIR` (never inside the output folder; removed after, and §6.3 refuses to package any path under it), so it works whether the node runs or not and never writes the primary. Gives: schema version, migrations applied and **pending** (R2 ii), tip height/hash, header tip, the chain mode recorded in the DB, failed-block index entries (public hashes), the block index set used to tell public block hashes from other 64-hex strings in §6.2, txindex/addressindex/spentindex state, snapshot/prune state, column family sizes, a `verify` of the last 288 blocks' index records (read-only). Opened with an 8 MB block cache and `max_open_files=64`, under the collector memory cap; skipped (and recorded as skipped, with the §6.2 fallback below) when free memory is under 512 MB, so diag never pushes a node that is short of memory into the OOM killer. Free memory is the smaller of `MemAvailable` and the room left in the node's cgroup (v2 `memory.max` − `memory.current`, v1 `memory.limit_in_bytes` − `memory.usage_in_bytes`), taken as the **minimum over the node's cgroup and every readable ancestor**, since a parent's limit binds as well; a v2 value of `max`, or a v1 value at or near `PAGE_COUNTER_MAX` (9223372036854771712 on 64-bit, and anything within a page of it), means "no limit" at that level and is skipped, never parsed as a number; on macOS it is `vm_stat` free + inactive pages. A collector stopped by the memory cap (B2, "Memory cap") gets the same fallback as a failed open. Diag never opens `<datadir>/wallet` (the wallet RocksDB, `core_files.rs:48`) as primary or secondary. If the secondary cannot open (a RocksDB too old to allow it, corruption, the LOCK in an unexpected state) the error is recorded verbatim and §6.2 switches to "pseudonymise every 64-hex string" for this package, and says so in the summary. Never opens with repair. |
| B2.9 | Wallet, structural, from the node only | Diag never opens the wallet store itself (§6.1; `<datadir>/wallet` is a RocksDB, `core_files.rs:48`, and a second opener could corrupt or lock it). Wallet facts come from two sources only: the config (`-disablewallet`, `-wallet=` names pseudonymised, `-walletbroadcast`, `-createwalletbackups`) and, when the node runs, `getdiaginfo`'s wallet section (A10), which the node computes and redacts at the source (A11). That section gives: wallet format version, encrypted yes/no, locked yes/no, HD yes/no, keypool size, count of keys, of transactions by category (send, receive, stake, MN reward, lottery, treasury, self), of unspent outputs by maturity bucket and by A11 magnitude bucket, of vaults; the spend-graph **shape** for "balance wrong" and "funds stuck" — counts only, no times, no depths, no ids: own transactions bucketed by number of own inputs (1, 2–5, 6–20, >20) and by number of own outputs (same buckets), unspent outputs whose funding transaction is unconfirmed, conflicted or abandoned (count each), and own outputs spent by a transaction the wallet does not know (count); balances as **shares** of the total by category (confirmed, immature, unconfirmed, locked, vaulted), never absolute amounts; wallet best block vs chain tip as a height difference; transactions marked conflicted or abandoned (count). A regtest test builds a wallet with known history and checks that the section cannot be matched back to any of its transactions (no bucket holds a single identifiable item that is not also in the public chain counts). With the node stopped, the summary says the wallet section is absent and why, and that B3 observed start (if consented) collects it. |
| B2.10 | Node logs | `debug.log` and its rotations: the last 16 MB in full; older parts reduced to start banners, version lines, `WARN`/`ERROR` lines and the hour-by-hour line count, so a long history fits. Every Part A file in full (A14 caps keep them small) and the A14 mirrors. Logs from before A11 (version < the first diag release, read from the banner) are marked and redacted under the pre-A11 rules in A11/§6.2. The summary states which history is present (from when) and that history from before the upgrade is partial. |
| B2.11 | Kernel and system log | `journalctl -k` / `dmesg` (both tried, `-T`, last 7 days or 2 MB) and `journalctl` system lines, `/var/log/kern.log`, `/var/log/messages`, `logread` (BusyBox/OpenWrt/Alpine), filtered to: lines naming the node's pids (any run in `runs.log`) or comm (`irondivid`, `tokio-runtime-w`, `rocksdb:*`); OOM killer and cgroup OOM lines (whole block, with the process table **reduced to the killed task and the node's tasks**); segfault/general protection/trap lines; `hung_task`; filesystem, block-device, MMC/SD and NVMe errors; ext4/xfs/btrfs/zfs errors; thermal and under-voltage lines; clocksource changes; suspend/resume; audit `SECCOMP`/`AVC`/`apparmor="DENIED"` lines for the node; `systemd-coredump` entries are not taken from this text log but through B2.12's field list (its message holds the command line and a stack trace with module paths). Journal lines are read with `-o short-iso`, which carries no boot or machine id. Netfilter, USB, Wi-Fi and everything else are dropped. Inside a container where the log is not readable, the summary records it and §7.2 L3 gives the host command. |
| B2.12 | Core dumps and crash stores | Lists, **never copies**: `coredumpctl list irondivid`, apport `/var/crash/*irondivid*`, abrt `/var/spool/abrt/*`, `core*` files in the data dir and the node's working directory (the
start-up cwd from A7 / the A14 path record; diag never guesses it), macOS `.ips` in `~/Library/Logs/DiagnosticReports` and `/Library/Logs/DiagnosticReports`. For each: time, signal, size, and from metadata only the faulting thread's frames as **frame address, function name and module** — `coredumpctl info` stack section reduced to those three columns, apport's `StacktraceTop` field (function names only), never apport's `Stacktrace` field (gdb `bt full` output, whose local variables and arguments can hold key material from the core), `.ips` JSON `threads[faulting].frames` (`imageOffset`, `symbol`, image) — **no memory, no locals, no arguments**. An irondivid with D5 leaves no `coredumpctl` entry at all (the kernel does not run the handler for a non-dumpable process), so B2.12 is evidence only for an older, dumpable irondivid or a crash before D5's call; an empty list proves nothing, and the crash verdict rests on A5, the A9/A1 exit record, A2 and the B2.5 exit status. From a systemd-coredump entry of an older, dumpable irondivid, diag reads only `COREDUMP_SIGNAL`, `COREDUMP_TIMESTAMP`, the stored size (or "none") and the stack frames reduced as above, and never `COREDUMP_CMDLINE` (it can hold `-rpcpassword`), `COREDUMP_EXE`, `COREDUMP_CGROUP`, `COREDUMP_UNIT`, `COREDUMP_ENVIRON`, `COREDUMP_PROC_*`, `COREDUMP_HOSTNAME`, `_HOSTNAME`, `_BOOT_ID` or `_MACHINE_ID`. `core_pattern` and `core_uses_pid`. Tells the user any core may hold keys and how to delete it (D5). |
| B2.13 | Network | Interfaces with addresses replaced by class (loopback, private, CGNAT, public, link-local) and prefix length; routes the same way; DNS resolver type; whether outbound P2P to the compiled-in seeds works (B2.15); listening sockets of the node's pids (port, bind class); firewall: `nft list ruleset`/`iptables -S` reduced to rules mentioning the node's ports; `HTTP(S)_PROXY`/`ALL_PROXY` set yes/no; IPv6 enabled. No public IP, no MAC, no hostnames. |
| B2.14 | Run table | Built from `runs.log` (and, for older versions, the `debug.log` start banners): one row per run — start time, version, binary hash, how started, phases reached and their durations, how it ended (exit code and reason, signal and sender, or the A2 verdict), uptime, peak RSS, the cgroup counter changes across the run, the matching wrapper status from systemd/Docker (B2.5) and journal line; differences from the previous run (version, binary, config hash, kernel, boot id, container) are marked. Unclean ends are paired with any stop request before them. This table is the first thing in `00-SUMMARY.txt`. |
| B2.15 | Network probe | Only to fixed destinations compiled into diag (the release's DNS seeds), never anything from config or logs: DNS resolution yes/no and time, TCP connect to two seeds on the P2P port, one `version` handshake (records their height and our clock offset from their timestamp); each with the error class on failure (DNS, refused, timeout, TLS, proxy). Results only — no addresses — in the package. Skipped with `--offline`. The receiver is **not** contacted during collection: its reachability is probed only at send time, after the user has said `yes` (§8.4), so nothing reaches the receiver or its hosting provider before consent. |
| B2.16 | Live node | First the A5 readability check (the open **or** the first `read` of the node's `/proc/<pid>/io` or `environ` fails with EACCES or EPERM; the ownership of `/proc/<pid>` is not used, M1, V6) and diag's own `CapEff` from `/proc/self/status`, which is recorded whatever diag's uid (M4); the result decides which reads below are tried. Root without `CAP_SYS_PTRACE` is treated as the non-root reader, except that it can list `fd/` and so keeps the open fd count (the number only: `fdinfo/` and the `fd/*` links, which give the types, stay refused); a same-uid non-root reader is refused `fd/` itself (N4). Diag also prints a **visibility matrix**: one row per `/proc/<pid>` entry it wanted (`stat` stack fields, `wchan`, `stack`, `syscall`, `io`, `maps`, `smaps_rollup`, `fd/`, `fdinfo/`, `environ`, `cwd`/`exe`/`root`, `ns/*`), each marked `read`, `hidden by kernel` (refused, or `wchan`/`stat` fields read as `0` for a reader without `CAP_SYS_PTRACE`), `absent` (the entry does not exist on this kernel) or `n/a (macOS)`, with the source used instead (`getdiaginfo`, A17 incident, A14 path record) or `none`, so a hidden row never reads as missing data (M4). Then the process state, before any RPC: `/proc/<pid>/stat` state `T`/`t` (stopped by a signal or a debugger, with `TracerPid`) and the cgroup's `cgroup.freeze`/`cgroup.events frozen=1` (or v1 `freezer.state`), on macOS `ps -o state`. A stopped or frozen node is reported as such ("node is stopped by SIGSTOP / traced by pid N / frozen by its cgroup"), RPC is not tried, and **no signal is sent**. Otherwise, only when a node is running and its RPC answers — over loopback whenever the node listens there, else on the address it is bound to (A10 (b), W2) — with the cookie or configured credentials readable by diag: `getdiaginfo` (A10), `getblockchaininfo`, `getnetworkinfo`, `getpeerinfo` (addresses → class + pseudonym), `getmempoolinfo`, `getstakingstatus`, `mnsync status`, `getmasternodestatus` (own outpoint pseudonymised), `getwalletinfo` (balances → shares), `getlogconfig`, the per-thread `/proc/<pid>/task/*/{stat,wchan}` sample taken 10 times one second apart (a hang shows as the same `wchan`), `/proc/<pid>/status`, `limits`, and, only when the readability check passed, `io`, `smaps_rollup` and open fd counts by type (otherwise from `getdiaginfo` or the A17 incident). If RPC does not answer within 10 s: that is recorded; diag writes the A17 **snapshot request** (when it runs as the node's user or root) in this order (V7): the **mirror** copy first, from diag's main thread; then the data-dir copy from a detached thread with a 1 s bound, which diag does not join if it has not returned (a hung data-dir disk then holds one diag thread, not diag); it then waits up to 5 s for the incident, reading the **mirror** copy first and the data-dir copy only through a second bounded detached read, and collects that incident and any earlier A17 incident. A `snapshot refused: budget` result (A17 `incident budget exhausted` line) is reported as such. The wchan sampling above runs only when the node is readable. Diag writes a `wchan` of `0` read from `/proc` by the thread's `stat` state letter (M3, N3): `running` for `R`, where `0` is expected, and `hidden` for `S`, `D` or any other state, since on hp3 every reader without root and `CAP_SYS_PTRACE` gets `0` and success; an unreadable node additionally gets `unreadable: node is non-dumpable (D5)`. On macOS, which has no `/proc`: the process state from `ps -o state`, thread stacks from one `sample <pid> 1` (reads stacks, sends no signal, changes nothing), fd counts from `lsof -p`; the `/proc`-only items (`status`, `limits`, `io`, `smaps_rollup`, wchan) are recorded as "n/a (macOS)". On Linux, the `/proc/<pid>` items a non-dumpable node (D5) refuses to a non-root diag (or to a root diag without `CAP_SYS_PTRACE`) — `wchan`, `io`, `maps`, `smaps_rollup`, fd counts (refused to the non-root reader; root without the capability keeps the count but not the types, N4), `stack`, `syscall`, `cwd`, `exe` — are taken from `getdiaginfo`, from the snapshot or A17 incident when RPC does not answer, and from the A14 path record, and the refused read is recorded as such (A5 "Non-dumpable process"). Diag never sends a signal to the node: not USR1, not QUIT, never a debugger unless B3.3. |
| B2.17 | Electrum, Web UI, ZMQ, swaps | Config (§6.2), listener state, counters from A10, TLS certificate subject/expiry/key type (no key), the last 1 MB of each component's log target (every line through §6.2 including the step 2 "Old-log lines" rule). Swaps run in the separate `divi-swapd`/`divi-swap` binaries, not in `irondivid`: if present, their version, process state and log errors, every swap log line under the "Old-log lines" rule. Swap state: counts by state and age, error strings, no swap ids, amounts, counterparty data or secrets (§6.1). |
| B2.18 | Seccomp and sandbox | `Seccomp`, `Seccomp_filters` of the node or of diag itself as a proxy; `/proc/sys/kernel/seccomp/actions_logged` (whether a seccomp kill leaves an audit line, A5); whether `irondivid --version` runs under the same sandbox; Docker `SecurityOpt` names; denied-syscall audit lines (B2.11). |
| B2.19 | Package and install | How irondivi was installed (release tarball path, package manager query, Homebrew, Docker image name and digest), every other copy on the system, and the files' ownership. |
| B2.20 | Diag's own record | `diag.log`: each collector's start, end, duration, exit, timeout, bytes, and every error; written synchronously, so a diag that hangs or is killed still says where — the "diag itself hung" case. |

### B3. Observed start

Only with consent (`--run` or "yes" at the prompt) and only if B3.1 passes.
It is the one way to see a failure that happens at start-up, with full
detail, when nothing earlier recorded it (a pre-Part-A version, or a fault
before the logs open).

**B3.1 Safety checks**, each recorded with the result: R2 rules i–iv; no
`irondivid` running on this data dir (lock free, no pid in `/proc` with it);
no supervisor will restart one: B3 refuses if **any** supervisor names
irondivi (a systemd unit that is active, `activating` or has `Restart=` set
with NRestarts rising over 10 s; an OpenRC `supervise-daemon`; runit, s6,
supervisord or pm2 entries; a launchd job with `KeepAlive`; a cron or
`@reboot` entry; a watchdog script from B2.4) and prints the command to stop
that supervisor first (Docker restart policy does not apply to a process
diag starts itself); free space ≥ 1 GB; the binary supports
`-walletbroadcast=0` and `-createwalletbackups=0` (A18), or the run uses
`-disablewallet` and the summary says that wallet-load failures were not
exercised and that upgrading and re-running diag covers them; no
`divi-swapd` is pointed at this node's RPC (it could act on a node it finds
running; diag lists any `divi-swapd` process and refuses while one runs); no
pending migration (B2.8).

**B3.2 How it runs.**
- As the data dir owner (or the unit's `User=`). Diag has threads, so it
  never changes ids or forks inside itself (B2). It starts
  `irondivi-cli diag --exec-as` with `posix_spawn`: a small helper that is
  single-threaded from its first instruction, sets the supplementary groups
  (`initgroups`), gid, uid, a new session (`setsid`) and, under a pty, that
  controlling terminal, applies the unit's rlimits, then `execve`s
  irondivid. If diag runs as root and the owner is another user, the helper
  switches to that user; if diag is that user already, the helper skips the
  id changes; otherwise B3 does not run and prints the command. Afterwards
  diag checks that no file in the data dir changed owner.
- In the same context as the real node where it can: on systemd, `systemd-run
  --scope --uid=… -p MemoryMax=… -p TasksMax=…` with the unit's resource
  properties; otherwise directly. Under a pty when the node normally has a
  tty, so console behaviour is the same. Context differences that remain
  (environment, cgroup, limits, cwd, tty) are recorded side by side.
- Arguments: the configured ones, plus `-daemon=0 -printtoconsole=0
  -staking=0 -createwalletbackups=0 -walletbroadcast=0 -debug=1` on a
  binary that supports them, or the A18 fallback otherwise (never
  `-masternode`, which irondivid refuses whatever its value). After the run
  diag checks that `backups/` and `monthlyBackups/` are byte-identical to
  before and that no wallet transaction reached a peer (the run's A15/A12
  records); any difference is reported at the top of the summary. Any of `-reindex`, `-rescan`, `-salvagewallet`,
  `-upgradewallet`, `-stopafterblockimport`, `-loadblock`, and
  `-checkblocks`/`-checklevel` above their defaults are **removed** (from
  argv and from the config, via the temporary `-conf` copy of R1 (d)) and
  each removal recorded with the value it had.
- Runs until the `running` phase, then 120 s more (or until it exits); then
  RPC `stop`, then SIGTERM after 60 s, SIGKILL after 120 s, each recorded.
  After SIGKILL diag polls `waitpid(WNOHANG)` for 5 s; a node still not
  reaped is abandoned with its pid, its `stat` state, and its `wchan` and
  `/proc/<pid>/stack` **only when the readability check passes** (root
  with `CAP_SYS_PTRACE`); otherwise those two are recorded as `hidden by
  kernel`, and a `wchan` of `0` is never written as a value: it is
  written `running` for a `stat` state `R` and `hidden` otherwise (M3,
  M4, N3).
  The record is `ABANDONED (uninterruptible)`, and the summary tells the user
  it is still there and that the data dir lock is still held.
  It never sends SIGTERM before `running` unless the user presses Ctrl+C
  or the start-up overruns. On a binary with A18's `-startuptimeout`,
  diag passes `-startuptimeout=<s>` (default 300) and lets the node end
  itself: the node writes its A17 incident and mirror record and exits
  10 (A1), which is better evidence than an outside kill; diag sends
  SIGTERM only if the node is still there 60 s after that timeout. A
  binary without the flag gets diag's own 5 minutes. Diag records which
  applied.
- **A stack before any signal** (F1). A start-up thread that spins after
  `network` counts as progress, so neither the node's start-up bound nor
  a phase boundary may come, and the run would end in SIGKILL with no
  incident. So before diag sends SIGTERM to an observed node that has not
  reached `running`, it writes the A17 snapshot request (mirror copy
  first, as in B2.16, V7) and waits up to 5 s for the incident; when the
  request cannot be written, it sends SIGQUIT instead, which A17 also
  answers with an incident. Before any SIGKILL of an observed node, it
  does the same again if no incident has appeared since the escalation
  began. Each request, wait and result is recorded beside the TERM and
  KILL records.
- Captures: exit status, stdout/stderr (bounded, §6.2 including the step 2
  "Old-log lines" rule), the run's Part A
  files, `debug.log` of the run, the cgroup counters before and after, and a
  `/proc/<pid>/task/*` sample every 5 s.

**B3.3 Deeper tracing, opt-in.** Only if asked separately: `strace -f -tt -T
-s 0 -e trace=%process,%signal,%file,%memory -o …` (no data bytes are
captured with `-s 0`; file paths are pseudonymised on collection), and, if the
node hangs, one `eu-stack -p` or `gdb -batch -ex 'set print frame-arguments
none' -ex 'thread apply all bt'` with a 30 s timeout. Both recorded as "on" in
the summary, since they change timing.

D5 changes which of these can work, and diag decides before trying:
- `strace -f` started by diag **as the node's parent** still works: it
  attaches before irondivid's first instruction, so before the
  `PR_SET_DUMPABLE 0` call, and an existing ptrace attachment survives that
  call.
- A **live attach** to a node already running (`eu-stack -p`, `gdb -p`)
  is refused by the kernel to any non-root caller once the node is
  non-dumpable. Root can attach only with `CAP_SYS_PTRACE` in its
  effective set (`CapEff` bit 19 in diag's `/proc/self/status`); a
  default Docker container drops that capability, so root inside it is
  refused too. Yama `ptrace_scope` 3 refuses everyone. Diag checks these
  first; when the attach cannot work it records `refused: node is
  non-dumpable (D5)` (with `no CAP_SYS_PTRACE` or `ptrace_scope 3` when
  that is the reason) and points to the A17 incident and snapshot
  stacks, which hold the same thread frames. It suggests `sudo` only when
  sudo would give `CAP_SYS_PTRACE` (A5).
- **While diag's own `strace -f` is attached, no live attach is tried**
  (L4). A thread can have only one tracer, so `eu-stack -p` or `gdb -p`
  on a node that `strace` already traces fails with EPERM even as root
  with `CAP_SYS_PTRACE`, and stopping `strace` to make room would lose
  the trace at the moment it matters. When a hang is seen during a run
  that has `strace` on, diag goes straight to the A17 **snapshot
  request** (B2.16), records `live attach skipped: strace attached`, and
  keeps the `strace` output.
- Diag records its own `CapEff` and `ptrace_scope` beside each B3.3
  decision, and the B2.16 visibility matrix is printed for the observed
  node too (M4): root without `CAP_SYS_PTRACE` gets the same rows as a
  non-root diag, and its kernel stacks and syscall state come from the
  A17 snapshot.

### B4. Platform backends

| Platform | Differences |
|---|---|
| B4.1 Linux, glibc and musl | The default above. Alpine/OpenRC: `rc-service`, `/var/log/messages`, `logread`. BusyBox tools are detected and their weaker output accepted. |
| B4.2 macOS (arm64, x86_64) | `sysctl` for host data and `kern.bootsessionuuid`; `vm_stat`, `memory_pressure`; `log show --last 7d --predicate` for the node's process, `jetsam`, `amfid`, `kernel` sandbox and code-signing lines; `.ips` crash reports (B2.12); `codesign -dv`, `spctl -a`, `xattr -p com.apple.quarantine` (Gatekeeper refusing the binary); `launchctl print`; `lsof -p` for fds; Rosetta translation yes/no for x86_64 binaries on arm64. TCC: any `EPERM` on a path under `~/Desktop`, `~/Documents`, `~/Downloads`, removable or network volumes, or `~/Library` subtrees is reported as "blocked by macOS privacy (TCC)", never as a missing file, with the step: System Settings → Privacy & Security → Full Disk Access → add the terminal app, then re-run. The same check runs on the node's own errors in runs.log (a node blocked by TCC). |
| B4.3 Raspberry Pi and other ARM boards | ELF class of the binary against `/sbin/init`'s (a 64-bit kernel with 32-bit userland, or the reverse); `vcgencmd get_throttled` decoded (under-voltage, throttling, now and since boot), falling back, when `vcgencmd` is missing or cannot open `/dev/vchiq`, to `/sys/devices/platform/soc/soc:firmware/get_throttled` and then hwmon `in0_lcrit_alarm`, with the source used recorded (or "no under-voltage source on this board"); `/sys/class/thermal/*`; MMC/SD errors (`mmc0`); SD card CID name and manufacturer date; on 32-bit, `VmPeak` and `VmSize` against the 3 GB limit; swap on SD warned. |
| B4.4 WSL 1 and 2 | Detected from `/proc/version` and `WSL_DISTRO_NAME` (name only); WSL 1 (no real cgroups, no `fdatasync` guarantees) vs 2; a data dir on `drvfs` (`/mnt/c/…`) flagged as slow and unsafe for RocksDB; Windows-side memory limit from `.wslconfig` is not readable from inside, so §7.2 L3 prints the PowerShell commands (`wsl --status`, `Get-Content $env:USERPROFILE\.wslconfig`, and `Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddDays(-7)} | Where-Object { $_.ProviderName -match 'Hyper-V|vmcompute|Lxss|Resource-Exhaustion' }` for the Windows side's memory and VM events). |
| B4.5 Containers | Docker, Podman, LXC/LXD/Proxmox, Kubernetes, OpenVZ: B2.3. Each states what cannot be seen from inside and the host command (§7.2 L3). `diag --host` (B6.2) run on the host does the host half. Docker Desktop (macOS, Windows) is detected from a `linuxkit` kernel release or `docker info` `Operating System: Docker Desktop`: its "host" is a hidden VM, so L3 there prints `docker run --rm --privileged --pid=host alpine dmesg > dd-dmesg.txt` plus `docker info > dd-info.txt`, and `diag --host docker-desktop` runs those and collects them — but first says that this pulls the `alpine` image from Docker Hub and asks; a "no", or `--offline`, prints the commands only. |

### B5. Time budgets

Total default budget 10 minutes without the observed start, plus up to
5 minutes for it. Per collector: 30 s, except B2.6 fsync 60 s, B2.8 120 s,
B2.0 10 s, B2.9 60 s, B2.10 60 s, B2.11 30 s, B2.15 30 s, B2.16 60 s. Every external
command runs with a timeout, a closed stdin and `LC_ALL=C`. A progress line
per collector is shown on the tty. Ctrl+C stops collection, cleans up (R1 b,
the secondary DB path) and still writes the summary and preview of what was
collected.

### B6. Recording modes — the second steps

Each limit in §7.2 names one of these.

- **B6.1 `diag --capture <minutes> [--until <event>]`.** For problems that
  come and go (slow at times, drops peers, crashes every few days). Runs
  alongside the node, at most 7 days: every 10 s, after the R1 (a)
  free-space check, the B2.16 live sample
  (without `getpeerinfo` detail) and B2.2 load/PSI/memory; on an event
  (`exit`, `stall`, `fork`, `ban`, `rss>N`, `peers<N`, or any incident
  written by A12) it takes a full B2 snapshot. Output capped at 200 MB
  (oldest samples thinned first). Then the normal preview and consent. It
  installs nothing; the user runs it in `screen`/`tmux` or as a transient
  `systemd-run` unit, whose command diag prints.
- **B6.2 `diag --host [<container>]`.** Run on the container host
  (Proxmox, LXD, Docker host, WSL's Windows side via the printed PowerShell
  command). Collects the host half: the container's configuration
  (`pct config`, `lxc config show`, `docker inspect`, cgroup files from the
  host side), host kernel log lines for that container's cgroup, host memory
  and OOM history, host storage under the container. Packaged and consented
  the same way, with a shared ticket so the two packages pair up. The
  container's hostname, IP and MAC addresses, bridge name, storage and pool
  names, and the container's name or id are added to §6.2's known values
  before anything is collected.
- **B6.3 `diag --tx <txid>`.** For "transaction stuck" and "balance wrong"
  on a specific transaction the user names. With the user's explicit
  consent, shown with the txid, includes that one transaction in clear: raw
  transaction, its inputs' prevouts, mempool state and rejection reason,
  wallet record and conflicts. This unavoidably also reveals the change
  output and its address (the output that returns to this wallet) and,
  through the inputs' prevouts, which earlier transactions funded it; the
  wallet's labels on any of these are pseudonymised. The consent text
  (§8.2) says exactly this. No other wallet transaction is included.
- **B6.4 `diag --import <folder>`.** B1.4: review and send a folder
  collected by `contrib/diag.sh`, on any machine where irondivi-cli runs.
  The folder holds `runs.log`, the other Part A files and kernel log lines,
  so the import treats every file as unredacted text: it runs the §6.2 step
  2 patterns, the "Old-log lines" rule on every line (wallet module or not),
  the step 3 structure rules, and then the §6.3 scanner. The wallet's known
  values (§6.2 step 1) are unavailable — the collecting machine's node is
  not asked — so the summary says "known values unavailable", and every
  remaining 64-hex string and address-shaped token is pseudonymised. The
  host-name, Windows and `docker info` fields listed in B6.6 are parsed
  into the known values first, as for an attached file. The §6.3 canary
  (e) tests this path.
- **B6.5 `diag --rpc <method> [args…]`.** For "an RPC gives a wrong
  answer" (L10) and "staking less than expected" (L12). Diag runs the
  method only if it is on this allowlist (every name checked against
  `crates/divi-rpc/src/server.rs`): `getblockchaininfo`, `getblockcount`,
  `getbestblockhash`, `getblockhash`, `getblockheader`, `getblock`,
  `getchaintips`, `getdifficulty`, `getrawmempool`, `getmempoolinfo`,
  `getnetworkinfo`, `getpeerinfo`, `getconnectioncount`, `getnettotals`,
  `getinfo`, `getstakingstatus`, `getmintinginfo`, `getmasternodecount`,
  `listmasternodes`, `getmasternodestatus`, `getmasternodewinners`,
  `getlotteryblockwinners`, `mnsync status`, `gettxout`, `getinvalid`,
  `getwalletinfo`, `getbalance`, `getcoinavailability`,
  `listtransactions`, `listsinceblock`, `listunspent`, `listlockunspent`,
  `gettransaction`, `getreceivedbyaddress`, `getdiaginfo`. Every other
  method is refused by name — in particular every `dump*`, `sign*`,
  `backup*`, `*privkey` and `*genkey` method and anything that changes
  state — whatever A15 says about it. Each refusal is one line on screen
  and in `diag.log` naming the method and the reason.

  **Removed in revision 6, and why.** Three calls on the revision 5 list
  cannot be bounded by any argument, so `--rpc` could make a struggling
  node worse (requirement 6), and the 2 s "stopped waiting" rule below
  cannot cancel a call the node has begun:
  - `gettxoutsetinfo` (`blockchain.rs:825` → `database.rs:645`
    `get_utxo_stats`) walks and SHA-256-hashes the whole UTXO set and takes
    no argument. A size gate was considered and rejected: diag would need
    the UTXO-set size first, which is what this call computes.
  - `getaddressbalance` (`blockchain.rs:1250`) reads every delta of the
    address, and `getaddressutxos` (`blockchain.rs:1267`) loads every
    unspent output of the address before paging (its page cap of 1000
    applies only after the load). The cost is per address, not a scan of
    the whole chain, but it has no limit for a busy address, and both
    return own-wallet data in full when called on an own address.
  For all three, L10 says "run it yourself and `--attach` the output":
  the user decides to spend that time, and the attached file goes through
  §6.2, the B6.5 key drops below and §6.3 like any other.

  **Argument caps.** Some allowlisted calls are expensive on a big wallet
  or chain, and `--rpc` must not become the way diag makes things worse
  (requirement 6). Diag checks the arguments before the call and clamps
  them, saying so on screen and in `diag.log` (`clamped: count 1000000 →
  1000`): `listtransactions` count ≤ 1000 (its paging is quadratic in the
  skip, `wallet.rs:1345-1373`, and `history()` clones the mempool,
  `wallet.rs:1314`); `listsinceblock` only with a block hash at most 1000
  blocks below the tip; `getblock` verbosity ≤ 1; `getrawmempool`
  non-verbose, or verbose only when `getmempoolinfo` reports fewer than
  5,000 entries; `getmasternodewinners` at most 100 blocks; `listunspent`
  is refused when `getwalletinfo` `txcount` (`wallet.rs:1194`) is above
  10,000 — the same limit as §6.2 step 1 — **whatever its arguments**
  (V1). r6 let it run when the third argument named at most 20
  addresses; checked against the code, that filter does not bound the
  work: `list_unspent` (`wallet.rs:1209`) first builds the whole
  spendable set with `get_spendable_utxos` (line 1255), sorts it,
  and only then filters by confirmations, lock state and address, so a
  one-address call costs the same as an unfiltered one. The refusal can
  be lifted only by a §10 measurement showing `listunspent` with an
  address filter finishes in under 2 s on a 10,000-transaction wallet on
  the reference Pi (to measure in §10; until then it stays refused, and
  L10 says "run it yourself and `--attach` the output" and prints the
  full command line, `irondivi-cli listunspent > unspent.json` and then
  `irondivi-cli diag --attach unspent.json --attach-method listunspent`,
  D1; B6.6 also recognises the answer by its shape). The §6.2 step 1 stop rule
  applies to every `--rpc` call as well: under 512 MB free memory, a call
  is refused; a call that runs past 2 s is answered "slow: stopped
  waiting" (diag stops reading; it cannot cancel a call the node has
  begun, which is why the caps come first); and all `--rpc` calls in one
  run share 60 s. A call that cannot be clamped to a safe form is
  refused with the reason.

  **`getdiaginfo` through `--rpc`** takes no parameters: `diag_key` and
  `known_values` are refused by name (A10), and `--rpc-clear` is never
  allowed for it.

  **The call itself.** The call shown on screen, kept in `diag.log` and
  sent in the package is pseudonymised like the answer: every argument
  that matches the address pattern or is a 64-hex string other than a
  public block hash is replaced by its pseudonym (an own txid and an own
  address get the same pseudonym they have in the answer). The hash
  argument of `getblock` or `getblockheader` and the height argument of
  `getblockhash`, when they point at an own staked block, an undecided
  block or a block in a reduced run ("Own staked blocks", Y2, Y4), are
  dropped from the call line altogether, not pseudonymised (R1).

  **Redaction.** The answer goes through A11 and §6.2 like everything
  else: addresses and txids pseudonymised; amounts, balances, values and
  fees bucketed by A11 magnitude; `getmintinginfo`'s `stakeweight` and
  `netstakeweight` (`crates/divi-rpc/src/staking.rs:236-241`) replaced by
  the ratio of this wallet's weight to the network's, bucketed (< 0.01 %,
  0.01–0.1 %, 0.1–1 %, > 1 %), never a number of coins, and its
  `expectedtime`, which is derived from the same ratio, bucketed (< 1 day,
  1–7 days, 7–30 days, > 30 days). **Dropped by JSON key in every case**,
  whatever the known-value set holds (it can be incomplete, §6.2 step 1):
  `label`, `account`, `comment`, `to`, and from `getwalletinfo`
  `hdmasterkeyid` (and `hdchainid` wherever it appears) — these are
  dropped **even under `--rpc-clear`**. (A reviewer named `hdseedid`; no
  such field exists in IronDivi's `getwalletinfo`, `wallet.rs:1198` has
  `hdmasterkeyid`, and `hdchainid` is in `validateaddress`, which is not
  allowlisted.)

  **Scripts and raw transactions.** A P2PKH script holds the address's
  40-hex hash160, a `scriptSig` holds the 33-byte public key, and a raw
  transaction hashes back to its txid and holds every script and amount;
  none of these is on a token boundary §6.2 step 2 matches, so they would
  undo the address and txid pseudonyms. So, in every B6.5 answer, these
  keys are **dropped**: `hex` (`gettransaction` returns the whole
  serialized transaction, `wallet_history.rs:848-851`; that is the only
  allowlisted method that does — `listsinceblock` and `listtransactions`
  carry no `hex`), `asm`, `redeemScript` (`listunspent`, `wallet.rs:1298`),
  `script` and `scriptSig` (vin, `wallet.rs:541`, `blockchain.rs:904`), and
  `scriptPubKey` when its value is a string (`listunspent`,
  `wallet.rs:1279`); a `scriptPubKey` object keeps only `type` and
  `reqSigs`. Each entry of an `addresses` array is pseudonymised like
  `address` (public lists under the public-record salt, below). **All of
  these script and raw-transaction keys — `hex`, `asm`, `redeemScript`,
  `script`, `scriptSig` and a string `scriptPubKey` (an object
  `scriptPubKey` keeps `type` and `reqSigs`) — are dropped even under
  `--rpc-clear`** (P1). r6 said this only of `hex`, so an `--rpc-clear`
  answer would have carried the scripts of every address in it: the
  consent the user gives for `--rpc-clear` names amounts, addresses and
  txids, not scripts and public keys, and nothing the clear answer is for
  (a wrong amount, a missing output) needs a script. B6.3 `--tx` is the
  way to send one transaction in clear, with its own consent. (A reviewer also named
  `txinwitness`; `divi-rpc` emits no such field, since Divi has no
  segwit, so it is not listed.) As a backstop **in B6.5 answers and in
  attached RPC answers** (B6.6; V3) — string values of the JSON reply,
  and the call's arguments — any run of
  40 or more hex characters that is not a public block hash becomes
  `<hex:N>` (length kept), and a 40-hex hash160 or a 20- or 33-byte push
  (`14`/`21` followed by 40/66 hex) is matched inside longer hex strings,
  not only on token boundaries. These are not general §6.2 step 2 rules:
  there they would mask the 40-hex ELF build-ids and the binary SHA-256s
  that A1, A16 and B1.2 record and the crash rows of §7.1 depend on.

  **Timing fields, by class.** In every answer from a wallet method or an
  address-scoped method (`getreceivedbyaddress`, and any `--attach`ed
  output of `getaddressbalance`/`getaddressutxos`), every field that is a
  **height, a time, a confirmation count or a block hash** places an own
  transaction on the public chain even with the txid pseudonymised, so:
  confirmation counts — `confirmations`, `bcconfirmations`
  (`wallet.rs:2662`, `wallet_history.rs:349`) and `gettxout`'s
  `confirmations` when the outpoint is an own one — are bucketed (-1,
  0, 1–5, 6–100, > 100; `-1` is what `depth()` in
  `wallet_history.rs:198-221` gives a transaction that is neither on the
  active chain nor in the mempool, such as a send undone by a reorg or a
  stake on an orphaned block, and it is never folded into 0, E1); heights (`height`, `blockheight`, `spentHeight`,
  `wallet.rs:636`, `:2555`), times (`time`, `timereceived`, `blocktime`)
  and block references (`blockhash`, `blockindex`) are dropped. The rule
  is by class, not by a list of names: a field diag does not recognise
  whose value is an integer between 0 and the tip height, a Unix time in
  the chain's range, or a block hash is dropped, and the drop is listed.

  **Own staked blocks** (P2, R1). A block the wallet staked is public,
  but anything that points at that one block identifies the staker as
  surely as an address does, and §6.2 step 1 already holds the own staked
  block hashes (A10 `known_values`). Without those pages — a node older
  than A10, or one bound only to a LAN address (W2) — the fallback calls
  return no staked-block hashes (S2, X1), so diag decides from the block
  itself: it fetches the block at verbosity 2 internally (never written)
  and finds its coinstake (`is_coinstake`,
  `crates/divi-primitives/src/transaction.rs:302`; the block's second
  transaction, `block.rs:193-194`). Ownership is decided from the
  **staked input only** (Y1, N2): the script of the output that the
  coinstake's first input spends. That output is spent, so `gettxout`
  cannot give it; diag fetches it with one `getrawtransaction <prevout
  txid> 1` and reads the output the input names (that this call answers
  for a spent output is an assumption, tested in §10 item 5). The stake
  returns pay that same script (`staker.rs:1953`,
  `builder.add_output_raw(*value, stake_utxo.script_pubkey.clone())`);
  the masternode, treasury and lottery payees in the same coinstake are
  ignored, so a block another wallet staked that pays this node's
  masternode is not own. Diag decodes P2PKH, P2SH, P2PK and vault scripts. A P2PK script's
  pubkey is hashed with HASH160 and the hash tested against the own set,
  as the wallet does when it gives a P2PK output an address
  (`crates/divi-rpc/src/wallet.rs:265-272`, `divi_crypto::hash160` at
  268; privacy P3); a
  vault script holds an owner hash and a vault hash
  (`crates/divi-rpc/src/wallet.rs:294-297`), and either hash in the own
  set makes the block own. A script diag cannot decode leaves the block
  **undecided**.

  **Undecided is reduced** (Y2). A block is undecided, and reduced as
  below, when either fetch was stopped, failed or timed out, when the own
  set is partial or unknown, or when a decode failed. The fallback calls
  (`list_received_by_address`, `wallet.rs:2612`;
  `get_addresses_by_account`, `:4714`; `list_accounts`, `:4727`) are not
  shown to list vault hashes, so on a node without the A10 pages the set
  is partial for vault scripts, and a vault stake is undecided and
  reduced. When step 1's stop rule cut its calls short, **every** block
  lookup is reduced. The block and prevout fetches have their own budget,
  10 s per lookup and 60 s per run (to measure in §10 item 5), and fall
  under step 1's 512 MB free-memory rule; a lookup over budget is
  undecided. A node with no wallet (`-disablewallet`, or the "Wallet not
  loaded" error, `wallet.rs:897`) has a known, empty own set: nothing is
  reduced for ownership and no warning is shown. The screen note for an
  undecided block is "this block could not be checked against your
  wallet; only its version, size class and transaction count are sent".
  §6.2 step 1's warning gives the count.

  **Consecutive heights** (Y4). If any lookup in a run of consecutive
  heights in the package is reduced, every lookup in that run is reduced
  the same way, because a clear neighbour gives the reduced block's
  height, and a height names the block through any explorer.

  **When every lookup is reduced** (Y5), the summary says so and points
  to the masternode-payment evidence that remains: `getmasternodewinners`,
  the A13 and A11 lines, and B6.3 `diag --tx <txid>`, which shows the
  coinstake in clear with its own consent.

  So when the block a call is about is an own staked block — a
  `getblock` or `getblockheader` hash argument in that set, or a
  `getblockhash` height whose answer is in that set — or a block left
  undecided or in a reduced run, diag
  keeps **only** three things from the answer: `version`, `size` rounded
  up to the next power of two in bytes (the size class), and `nTx`. Every
  other field is dropped, and each drop is listed: `hash`,
  `previousblockhash`, `nextblockhash`, `confirmations` (with the public
  tip it gives the height), `height`, `time`, `mediantime`, `merkleroot`,
  `nonce`, `bits`, `difficulty`, `chainwork`, `acc_checkpoint` and
  `moneysupply` (`blockchain.rs` `getblock` 549-577, `getblockheader`
  628-645); each of them, alone or with public data, names exactly one
  block. The `getblockhash` answer, which is the hash itself, is dropped
  whole. The `tx` array keeps its length and nothing that points at the
  block: the coinstake's txid gets its own-txid pseudonym when the
  block was decided own, and its pseudonym under the public-record salt
  when the block was reduced as undecided, so no wallet-side pseudonym is
  made for a value that may not be the wallet's (consensus N4); every
  other txid is replaced by its pseudonym under the
  public-record salt (a txid in clear names the block through any
  explorer), and at verbosity 2 each transaction entry is reduced to that
  pseudonym, so its `blockhash`, `confirmations`, `time`, `blocktime` and
  `height` go, and so do its inputs and outputs, whose amounts and
  addresses would also find the block. The hash or height argument is
  dropped from the call line ("The call itself"). This replaces r7, which
  kept the hash as a wallet-side pseudonym and left `confirmations`,
  `chainwork`, `moneysupply`, `merkleroot` and the rest in clear, each
  enough to find the block. The screen says "this block was staked by
  your wallet; only its version, size class and transaction count are
  sent". A block that is not own is a public record and stays in
  clear, except that `previousblockhash` and `nextblockhash` are dropped
  from **every** block answer, own or not (S4): in the block next to an
  own staked block they hold the own hash, and dropping them only there
  would mark that neighbour. Outside wallet-context lines an own staked hash is a
  public block hash and is printed in clear, for example in the shared
  "Connected block <hash> at height N" line that every accept path
  writes, own or a peer's, after the A11 "Own blocks log like peer
  blocks" change (B1, Y3, O1; §6.2 "Public records"; by default the
  package does not keep that line either: §6.2 "Old-log lines" (e)
  collapses it into weekly counts in every log until the A11 item 7
  timing gate passes, and for good if it fails, the expected outcome;
  adversarial AB2); masked there alone, among every other block's clear hash,
  it would mark itself. Wallet-module lines (§6.2 "Old-log lines" (b))
  and A11 typed wallet values keep the wallet treatment, and the staker
  lines that announce an own stake are not kept in place at all (§6.2
  "Old-log lines" (b)): beside the clear chain line, their time or their
  place in the file would pair with it and name the block.

  **Address-scoped answers** get the full wallet-answer rules:
  `getreceivedbyaddress` on an own address gives an exact amount, so its
  answer is bucketed by A11 magnitude, its address argument pseudonymised
  and its timing fields handled as above. **Public lists** (`listmasternodes`, `getrawmempool`,
  `getblock`, `getmasternodewinners`, `getlotteryblockwinners`): each field
  is either pseudonymised for every entry or printed in clear for every
  entry, never by ownership (§6.2 "Public records"); addresses, collateral
  outpoints and IPs in them are pseudonymised for every entry under a
  separate public-record salt, so a public pseudonym never equals the
  wallet-side pseudonym of the same value and the user's own entry cannot
  be picked out.

  The redacted answer is shown on screen with the exact call (after any
  clamping) and a list of the dropped fields before the consent question,
  so the user sees what would be sent; the summary says that B6.3 is the
  way to show one transaction in clear. When the wrong number is itself
  the evidence (`listunspent`, `getstakingstatus`, `getwalletinfo`
  showing a wrong amount), `--rpc-clear` — allowed only for methods on
  the same allowlist, and never for `getdiaginfo` — asks a second,
  separate consent (§8.2), worded like B6.3 and stating what the answer
  holds: "this answer will be sent in clear: amounts, <n> addresses,
  <m> txids". It is **refused when the answer holds more than 100
  addresses and txids together**; the user is told to name one
  transaction with `--tx` instead. With it, that one answer goes
  unredacted under `rpc/clear/` (except the always-dropped fields above:
  labels, accounts, comments, `to`, the HD ids, and every script and
  raw-transaction key, P1)
  and is shown in full on screen before the question; without it, the
  answer stays redacted. The §6.3 scanner skips only that file's wallet
  values, never secrets (keys, passwords, cookies still stop it).
- **B6.6 `diag --attach <file>`.** Adds a file the user saved from somewhere
  diag cannot reach (output of an L3 host command, a screenshot's text, a
  Windows event export) under `host/attached/`. It goes through §6.2 and the
  §6.3 scanner like every collected file and is listed in the preview with
  "attached by you". **Attached RPC answers** (C1, C2, V3). L10 tells the
  user to run `gettxoutsetinfo`, `getaddressbalance`, `getaddressutxos`
  or a refused `listunspent` themselves and `--attach` the output, so an
  attached file can be an RPC answer holding own addresses, scripts,
  amounts and heights, and r6 put it through §6.2 alone, which does not
  apply the B6.5 key drops, timing classes or hash160 backstop. So every
  attached file that parses as JSON (a bare result or a JSON-RPC
  `{"result": …}` envelope), and that the format recognition below
  (`pct config`, `lxc config show`, `lxc-info`, `docker inspect`) has not
  already claimed, is checked for an RPC answer; that recognition runs
  first, so a `docker inspect` file keeps its own rules. The method is
  taken from `--attach-method <method>` when the user gives it, or else
  from its shape: `getaddressbalance` is an object with `balance` and
  `received`; `getaddressutxos` is an array of objects with `address`,
  `txid`, `outputIndex`, `script`, `satoshis` and `height`, or, with
  `chainInfo`, an object whose `utxos` holds that array beside `hash` and
  `height` (`blockchain.rs` `get_address_utxos`);
  `gettxoutsetinfo` is an object with exactly eight keys, `height`,
  `bestblock`, `transactions`, `txouts`, `bogosize`, `bytes_serialized`,
  `hash_serialized` and `total_amount` (`blockchain.rs:825-845`, N2). The wallet answers have shapes
  too (D1, R3): `listunspent` is an array of objects with `txid`, `vout`,
  `address`, `scriptPubKey`, `amount`, `confirmations`, `spendable`,
  `solvable` and `ischange`, and on some entries `account` (the user's own
  address-book label, free text: dropped) and `redeemScript` (script hex:
  dropped, P1) (`wallet.rs:1275-1300`); `listtransactions` is an array of
  objects with `txid`, `category`, `amount` and `confirmations`, with
  `address`, `account`, `vout`, `fee`, `generated`, `bcconfirmations`,
  `blockhash`, `blockindex`, `blocktime`, `baretxid`, `walletconflicts`,
  `time` and `timereceived` as the entry has them
  (`wallet_history.rs` 346-370); `listsinceblock` is an object with
  `transactions` (that array) and `lastblock`; `gettransaction` is one
  such object with `details` and `hex` (`wallet_history.rs` 456-547);
  `getwalletinfo` is an object with `walletversion`, `balance`,
  `unconfirmed_balance`, `immature_balance`, `txcount` and `keypoolsize`
  (`wallet.rs:1185-1203`). `getbalance` answers a bare number, which has
  no shape, so it is recognised only by `--attach-method`, as is any other
  allowlisted B6.5 method.

  **A label must match the shape** (S1, X2). A wallet answer whose
  objects hold no `txid` (`getwalletinfo`, `getbalance`,
  `getmintinginfo`, `getstakingstatus`) is not caught by the per-object
  wallet rule below, so a label alone may never let it out in clear. A
  `--attach-method` naming a **public** method is honoured only when the
  file's shape strictly matches that method: every key the method always
  returns is present and no key it never returns is (for
  `getblockchaininfo`, `chain`, `blocks`, `headers`, `bestblockhash` and
  the rest of `blockchain.rs:678-685`; for `gettxoutsetinfo`, all eight keys
  listed above). Otherwise the label is ignored, the file is treated as
  unknown, and the preview says "label `<method>` does not match the
  file's shape; treated as JSON of unknown origin". A label naming a
  wallet method is always honoured, since it only adds rules.
  `getmintinginfo` is recognised by its shape (`blocks`,
  `currentblocksize`, `currentblocktx`, `difficulty`, `errors`,
  `generate`, `genproclimit`, `pooledtx`, `stakeweight`,
  `netstakeweight`, `expectedtime`, `searchinterval`) and gets B6.5's
  rules: `stakeweight` (an object `{minimum, maximum, combined}`) and
  `netstakeweight` (a number, `staking.rs:229-240`) become one ratio
  bucket when both are present and are dropped otherwise, and
  `expectedtime` is bucketed. `txcount` (`wallet.rs:1194`) is a wallet
  count and is bucketed by A11 magnitude in any file the wallet rules
  treat as wallet-shaped or recognise as a wallet answer.

  **No label lowers protection** (D1, R3, K5). A shape or a label decides
  which method's extra rules apply; neither decides whether the wallet
  rules apply. Every JSON object anywhere in an attached file — in a
  recognised answer, in a file of unknown origin, or in one the user
  labelled with a different `--attach-method` — is **wallet-shaped** when
  it has `txid` together with an amount key (`amount`, `value`, `fee`,
  `balance`, `satoshis`, `received`), a timing key (`confirmations`,
  `bcconfirmations`, `height`, `blockheight`, `time`, `blocktime`,
  `timereceived`) or an `address` key, or when any of its string values
  is one of the user's own addresses or txids from the §6.2 step 1 set. A
  wallet-shaped object gets every B6.5 wallet-answer rule, whatever the
  file was labelled: the key drops (including `account` and
  `redeemScript`), the timing classes, the A11 amount buckets, and
  pseudonyms for own addresses and txids. So an own `listunspent`
  attached with `--attach-method getblock`, and a `listtransactions` dump
  from Divi Core attached with no label, are covered as if labelled
  correctly. This includes each transaction entry inside an attached
  public `getblock` at verbosity 2 (E2): it has a `txid`, so it is
  wallet-shaped and loses `time`, `blocktime`, `confirmations` and
  `blockhash` where present; that is a decision, not a side effect, and
  the block-level header fields (`hash`, `height`, `time` and the rest)
  are kept as the public record they are, unless the block is own (B6.5). A file recognised as an RPC
  answer gets **every B6.5 answer rule**: the key drops (including
  `script`, and the script keys even if the user later asks for clear —
  attached files have no `--rpc-clear`), the ≥40-hex and hash160 backstop,
  the timing classes (`height` dropped on an address-scoped answer), A11
  magnitude buckets with `satoshis`, `balance` and `received` named as
  amount fields, and the address-scoped and own-staked-block rules.
  `gettxoutsetinfo`'s fields are chain-wide and public (all eight:
  `height`, `bestblock`, `transactions`, `txouts`, `bogosize`,
  `bytes_serialized`, `hash_serialized`, `total_amount`), so they stay in
  clear; the backstop does not touch
  `hash_serialized`, which is a public 64-hex hash, listed as such. A file
  that parses as JSON but matches no RPC shape, no other known format
  and has no `--attach-method` gets, on top of §6.2, the B6.5 key drops
  (script, raw-transaction, label, comment and HD-id keys), the ≥40-hex
  and hash160 backstop, the wallet rules on every wallet-shaped object
  (above), and a **key-name rule** on every other object (W1): a number
  under an amount key gets the A11 magnitude bucket; one under `confirmations` or
  `bcconfirmations` gets the B6.5 confirmation bucket; and one under
  `height`, `blockheight`, `time`, `blocktime` or `timereceived` is
  dropped, and the drop is listed. **Amount keys match by token** (S1):
  the key is split on `_` and compared without case, and it is an amount
  key when any token is `amount`, `value`, `balance`, `fee`, `satoshis`,
  `received`, `sent`, `credit`, `debit`, `reward`, `total` or `stake`, so
  `unconfirmed_balance`, `immature_balance` and `total_amount` are
  caught; `stakeweight` and `netstakeweight` get the ratio rule above, and
  `txcount` its bucket. The `stake` token is broad and over-protects (a
  count under a key such as `stake_count` is bucketed too); that is
  accepted, because the rule only buckets numbers and drops no key (N4). The key-name rule runs in **every** attached file,
  recognised or not, as well as on top of the rules above (S1; it only
  adds protection); the only fields it leaves alone are those a
  shape-confirmed **public** answer names (such as `gettxoutsetinfo`'s
  `total_amount` and `height`) and the `time` and `timeNano` of the
  `docker events` format below (P4). No other key is touched, so `pid`,
  `port`, `exit_code` and counts stay: the by-class timing rule is
  **not** applied, because it drops every unrecognised integer up to the
  tip height and would strip pids, exit codes, ports and counts from an
  ordinary JSON file (a journal export, a compose file), which is the
  evidence the attachment exists to carry. A `time` key in such a file is
  dropped by the key-name rule too; that is the cost of the rule, and the
  preview lists each drop. The preview says "JSON of
  unknown origin; script keys and hash backstop applied", lists the
  key-name drops and buckets, and suggests the full command line
  `irondivi-cli diag --attach <file> --attach-method <method>` if the
  file is an RPC answer. The preview lists each such file
  with "treated as RPC output: <method>" (or the unknown-origin line above). When an attached file is `pct config`, `lxc config
  show`, `lxc-info` or `docker inspect` output (recognised by its shape),
  diag first parses it and adds the host's hostname, the storage, pool and
  bridge names, container names and ids, IPs and MACs in it to §6.2's known
  values, and the §6.2 step 3 structure rules (argv, mount paths,
  environment values) apply to it as to collected files. `docker events`
  and `podman events` JSON lines (top-level `Type`, `Action` and `Actor`,
  or `status`, `id` and `from`) are a known format too (P4): the
  container names and ids in them join §6.2's known values, and `time` and
  `timeNano` are kept, since they say when a container stopped or was
  killed; the per-object wallet rule still applies on top. The same
  parsing runs on every attached or imported log (here and in B6.4):
  the host-name column of syslog, journal (`_HOSTNAME`) and `lxc-start
  --logfile`/`lxc --show-log` lines; `Computer` and `MachineName` in a
  Windows event export; the `Name:` line of `docker info`; and the user
  part of `C:\Users\<name>` paths in PowerShell and `.wslconfig` output.
  Each value found joins §6.2's known values before the file is redacted. L3's printed
  commands each end with `> <name>.txt`, and the summary prints the
  matching `--attach` line.

---

## 5. Where everything lands in the package

```
irondivi-diag-<ticket>/
  00-SUMMARY.txt          run table (B2.14), verdicts, what is missing and why, next steps (§7.2)
  01-user-report.txt      the user's own answers (§8.1)
  02-manifest.txt         every file, size, SHA-256, collector, redaction rules applied
  host/                   B2.1–B2.6, B2.13, B2.15, B2.18, B2.19, B4 extras
    attached/             B6.6 files the user added, each marked "attached by you"
    locks.txt             B2.0
  container/              B2.3, B2.5
  processes/              B2.4
  datadir-<n>/            B1.1 one per data dir:
    config/               B1.3
    inventory.txt         B2.7
    rocksdb/              B2.7 LOG files, OPTIONS
    chaindb.txt           B2.8
    wallet-structure.txt  B2.9
    logs/                 B2.10 debug.log extract, Part A files, mirrors
    live/                 B2.16
    observed-start/       B3
    services/             B2.17
    rpc/                  B6.5 one file per consented read-only call
      clear/              B6.5 `--rpc-clear` answers (separate consent)
    tx/                   B6.3 the consented transaction
  kernel/                 B2.11
  crashes/                B2.12
  binaries.txt            B1.2
  diag.log                B2.20
```

---

## 6. Safety

### 6.1 What never leaves the machine

Private keys, seeds, mnemonics, wallet passphrases, the wallet store or any
part of it (diag never opens `<datadir>/wallet`; wallet facts come only from
the config and the node's own redacted `getdiaginfo`, B2.9), the names, sizes
and mtimes of the files in `<datadir>/wallet/` and their contents,
including the wallet RocksDB's own `LOG*` and `OPTIONS-*` files (B2.7
gives only the directory's total size and file count), the private
`diag/sent-txids` file (A15), `wallet.dat` backups, core dumps and process memory, RPC
passwords and cookies, `rpcauth` hashes, TLS private keys, the masternode
private key and collateral outpoint, swap secrets and preimages, Electrum or
Web UI credentials, any API token, environment variable values outside the
A7 allowlist, the user's IP addresses and hostnames, MAC addresses, wallet
addresses, labels, own transaction ids, own amounts or balances, own staked
block hashes (which may appear only as ordinary, unmarked entries of a
public record or list — a tip, a header, a block in a bundle — printed
exactly as every other entry is, §6.2 "Public records"), stake counts
finer than the A6 buckets, user names, home directory names, file names chosen by the
user, peer IP addresses, and anything matching a §6.3 pattern. The only
exceptions are the §8.2 consent questions: B6.3, where the user explicitly
names one transaction, B6.5 `--rpc-clear`, and the A13 own-invalid
bundle.

### 6.2 Redaction on collection

Applied to every byte before it is written into the output folder, in this
order:

1. **Known values.** Diag builds, in memory only, the set of values to
   hide: every wallet address, label, own txid, own outpoint and own staked
   block hash (below); every value of a secret config key
   (`rpcpassword`, `rpcuser`, `rpcauth`, `masternodeprivkey`, `electrum*key`,
   `*password*`, `*token*`, `*secret*`, `*key*` except known public ones);
   the RPC cookie; the short hostname, the FQDN, every name in `/etc/hosts`
   and `/etc/hostname` and `scutil --get ComputerName/LocalHostName` on macOS,
   with their registrable domain (public suffix list compiled in) also
   hidden; every user name and home directory from `/etc/passwd` (and
   `dscl` on macOS) other than system accounts; the machine's own
   addresses (all interfaces, and the public one from B2.15's handshake);
   the machine id; wallet file names. Wallet values come from the running
   node over its local, authenticated RPC, held in diag's memory only and
   never written. **On a node with A10**, diag reads only the
   `getdiaginfo` `known_values` pages (A10, 1000 values a page), which hold
   every address, label, own txid, own outpoint, own staked block hash,
   both hashes of every vault script the wallet owns or manages (Y1), the
   masternode collateral and the A15 sent-from-here set; it makes no other
   wallet call. When the node answers `known_values is local only` — it
   listens on no loopback address, so diag had to reach it on a LAN
   address (A10 (b), W2) — diag treats it as a node older than A10 for
   the wallet values and uses the calls below. When neither the pages nor
   those calls can be read, `00-SUMMARY.txt` and the `01-user-report.txt`
   preview say plainly which masking is degraded: "wallet values were not
   available for masking (<reason>); addresses, txids and labels are
   caught only by the pattern rules"; when the own staked blocks came
   from the coinstake check rather than the pages, "own staked blocks
   were found from each block's staked input (<reason>)"; when the set is
   partial, "the own address set is partial (<reason>); blocks staked from
   addresses not in it, such as vault addresses on this node, are
   reduced"; when lookups were undecided, "<n> block lookups could not be
   checked against your wallet (<reason>) and were reduced" (Y2); and when
   the own
   addresses were not known either, "own staked blocks could not be told
   apart; every block lookup is reduced to version, size class and
   transaction count" (S2, X1); and, when that is so, "secret
   environment values were not available for matching". **On a node older than A10**, which has no such pages, it
   uses the calls IronDivi has (`crates/divi-rpc/src/server.rs`; there is
   no `listaddressgroupings` or `listlabels` in IronDivi):
   `listaccounts 0 true` for the label names, `getaddressesbyaccount
   <name>` for each name, `listreceivedbyaddress 0 true true`,
   `listunspent` — skipped when `getwalletinfo` reports more than about
   10,000 transactions — `listlockunspent`, and the collateral from
   `getmasternodestatus`. It does not page `listtransactions`: that call
   rebuilds the list from the newest record on every page and clones the
   mempool (`wallet.rs:1314`, `:1345-1373`), so paging a large wallet is
   quadratic; own txids on such a node come only from the calls above.
   Every call is under one **stop rule**: diag makes no further call when
   free memory (as defined in B2.8) is under 512 MB, when one call has
   taken over 2 s, or after 60 s in all. When the rule stops it, or a call
   answers "method not found", the set is incomplete and the summary says
   which calls were missing. (Diag holds the same RPC credentials the user does;
   this reads nothing the user could not.) When the node is not running,
   the wallet values are not available: A11-era logs need none of them
   (wallet values were never printed), and the "Old-log lines" rule in
   step 2 runs whether or not the set was read. The set also holds: the
   values of the node's environment (from the A10 `known_values` pages,
   or `/proc/<pid>/environ` when that is readable — root, or a node from
   before D5, since a non-dumpable node's `environ` is root-only (A5);
   read into memory only; not readable on macOS, so skipped there; when
   the node is hung or down, or refuses `known_values` (W2), and diag is
   not root, a non-dumpable node's environment values are not available
   at all — the set holds none of
   them, the step 2–3 pattern rules still run, and `00-SUMMARY.txt` and
   the `01-user-report.txt` preview say environment values were not
   available for matching),
   **except** values
   that would destroy the logs without hiding anything — those of the A7
   allowlist variables and of `PATH`, `SHELL`, `TERM`, `LANG`, `LC_*`,
   `PWD`, `OLDPWD`, `SHLVL`, `HOME` (handled as a path), `_`, `TZ`,
   `HOSTTYPE` and `container`, any value that is an existing system path,
   and any pure number (secret-named variables are still caught by the
   step 2 `k=v` rule wherever they are printed); every value of a
   host-naming config key (`addnode`, `connect`, `seednode`, `externalip`, `proxy`, `onion`,
   `bind`, `rpcbind`, `rpcallowip`, `whitelist`, `electrum*` listen
   addresses), from the config file and from argv; the source of every
   mount (B2.4) other than kernel pseudo-filesystems; the CN and every SAN
   of any TLS certificate the config names; the container and host names
   from B6.2 and from attached files (B6.6); the host names, Windows
   `Computer`/`MachineName` values, `docker info` `Name:` and
   `C:\Users\<name>` user names parsed from attached and imported logs
   (B6.4, B6.6); the hostname column of every syslog and journal line
   diag collects (`_HOSTNAME` in journal export), so a bare host name
   with no dot is caught; every txid A15 recorded as sent from here
   (from `getdiaginfo`'s `known_values`, or from the private
   `diag/sent-txids` file when the node is down — never from
   `rpc-methods.log`, which holds no txids). Each
   is replaced by a pseudonym
   `<kind>-<4 hex>` from an HMAC under a random 32-byte salt generated for
   this run and **never written anywhere**, so the same value reads the same
   throughout one package and cannot be reversed or linked to another
   package. Matching is on token boundaries (a value inside a longer word is
   not touched). Values shorter than 4 characters, and the common names
   `root`, `admin`, `user`, `ubuntu`, `debian`, `pi`, `irondivi`, `divi`,
   `localhost`, are not matched **free-standing in log text** (they would
   destroy the log without hiding anything). They **are** masked wherever
   their position says what they are: a path component under `/home`,
   `/Users` or a data-dir path, a `user=`/`User=`/`--user`/`-u` value, the
   owner column of B2.4/B2.5 listings, an argv value, and a hostname
   position (`@host`, `Host:`, the hostname fields of B2.1). This is the
   only exception to §6.1's "user names" and "hostnames", and it is stated
   in the package summary when such a name was seen.
2. **Patterns.** IPv4 and IPv6 addresses (→ class + pseudonym, loopback and
   RFC 1918 classes kept as classes), MAC addresses, e-mail addresses, URLs'
   user-info parts, `Authorization:`/`Cookie:` headers, base58 and bech32
   strings of address or key length, WIF keys, xprv/xpub/tprv, BIP39 word
   runs of 12 or more, PEM blocks, 64-hex strings that are not public block
   hashes (below), hex strings of 66 or 130 characters (public keys), long
   base64, and hostnames: any dotted name ending in a public suffix from the
   compiled-in list, other than the project's own seed and service names
   compiled into the binary; and the value after any key whose name
   contains `pass`, `secret`, `token`, `key` or `auth`, in the forms `k=v`,
   `k: v` and `"k": "v"` (replaced by `<set>`).
   **Public block hashes** are those in the B2.8 block index, plus, whatever
   B2.8 does, every hash a Part A file wrote through the A11 public
   `BlockHash` type (it is printed with a `blk:` prefix, which a wallet
   value can never carry) and the headers inside A13 bundles, so corruption
   and fork evidence keeps its hashes even when the database cannot open.
   **Public records.** Ownership never changes how a field of a public
   record or list is printed. The public records are: block and tip
   hashes (A12 tip and reorg lines, B2.8), headers and blocks (A13
   bundles, `getblock`, `getblockheader`), the txids of a block or of the
   mempool (`getrawmempool`, a block's `tx` list), the masternode list
   and the winners list (A10, `listmasternodes`, `getmasternodewinners`),
   and spent outputs inside a bundle, and the block hashes in non-wallet
   chain, sync, node and net log lines collected under "Old-log lines"
   below — the shared "Connected block {} at height {}" line that every
   accept path writes after the A11 "Own blocks log like peer blocks"
   change (today at `crates/divi-network/src/sync.rs:1322` and `:1446`,
   with "Connected orphan block {} at height {}" at `sync.rs:2393`), and
   the `divi_storage` chain lines written inside `accept_block` for every
   block alike (`crates/divi-storage/src/chain.rs:1812` "ACCEPTING BLOCK",
   `:4014` "VALIDATING BLOCK", `:4416` "BLOCK VALIDATED", `:2458`
   "Updating in-memory tip to block {} at height {}") — where an own
   staked hash is printed in clear like every other (B1, Y3, O1). Only a
   line written for every block alike, own or a peer's, is a public
   record here; on a node without the A11 change, or whose version is
   unknown, no per-block line is kept ("Old-log lines" (e)). By default,
   until the A11 item 7 timing gate passes, and for good if it fails,
   rule (e) collapses these lines too, in every log (adversarial AB2).
   `node.rs:1551` "Accepted block {} at height {}", which r10 named here,
   is not written in production (`Node::accept_block`, `node.rs:1515`, is
   called only from `crates/divi-node/tests/mempool_reorg.rs:248`). In each such field the rule is the
   same for every entry: either every entry is printed in clear (block
   hashes and headers, which the evidence needs) or every entry is
   pseudonymised under a **separate public-record salt**, also random per
   run and never written (payee addresses, masternode IPs and collateral
   outpoints, mempool and block txids in a `--rpc` answer). Step 1's
   own-hash, own-txid, own-address and own-outpoint replacement is **not**
   applied inside public-record fields, so the user's own masternode,
   staked tip or mempool transaction reads exactly like everyone else's,
   and a public pseudonym never equals the wallet-side pseudonym of the same
   value. Wallet-context lines (what the wallet did, A11) still get the
   wallet-side treatment. The step 2 patterns still run over public
   fields, except that a 64-hex public block hash is kept as above.
   **Old-log lines.** Always applied, by one filter function, whether or
   not the step 1 set could be read, and to **every** run, current node
   or not (consensus B4, adversarial AB1), over every text copy of node
   or component log output diag collects. The inputs, all of them:
   `debug.log` and its rotations; the journal and `docker logs` (B2.5);
   the observed start's stdout/stderr (B3.2); component and swap logs
   (B2.17); A15's stored error text; every file of an imported folder
   (B6.4); the debug-ring section of `crash.log` (A4, A5, A8); each
   incident's debug-ring section and its last 256 KB of `debug.log`
   (A12); the debug ring in `getdiaginfo` output (B2.16); the A14 mirror
   copies of `runs.log`, `crash.log` and `events.log`; and every Part A
   file of a pre-A11 or `-logwalletdetail=1` run (A11). A new copy of log
   output joins this list or is not packaged. The A8 ring also keeps
   counted lines out at the source; the filter runs anyway. The A11
   hourly count lines found in any input are folded into the weekly
   buckets (daily for failure-only sites) and never shipped as lines; a
   count line seen in two copies (the `debug.log` tail and the ring of
   one incident, say) is counted once, by its site and hour. (a) Every 64-hex string that is not a
   public block hash (below) is pseudonymised. (b) In every line whose
   module prefix (the logger's `target`, which is the Rust module path) is
   one of the wallet-bearing modules — derived from the A11 edit sites:
   `divi_wallet`, `divi_node::staker`, `divi_node::mempool`, `divi_rpc`,
   `divi_electrum`, `divi_swap`, `irondivid::core_files`, plus, for the
   `irondivid` crate root, only the lines matching an edit-site format
   string (`main.rs:1719`, "Unconfirmed wallet tx … cannot be
   resubmitted", and the removed `main.rs:2345`, "Transaction … submitted
   to mempool", in older logs) — the
   line keeps only its timestamp, level, module and the words of the
   code's own format string; every argument is masked by kind (`<num>`,
   `<str>`, `<addr>`, `<arg>` for anything else, including anything after
   `label`/`name`/`=`), **except** numbers in fixed, non-wallet positions,
   which are kept: the number after `port`, an RPC error `code -N`, and the
   port after an address that was already reduced to its class
   (`rfc1918-3a2f:51472`). This covers amounts with or without a unit
   (`wallet_db.rs:1749`, `:2928`, `amount.rs:118`) and the height in "at
   height N" (`staker.rs:722`, `:812`), and hides a label without knowing
   it. The staker lines that announce an own stake —
   `staker.rs:722-724` "Staked block {} at height {} (reward: {})",
   `staker.rs:812-814` "Self-accepted staked block {} at height {}", and
   any other A11 edit-site format string that reports an own stake — are
   not kept in their place even masked (B1): their timestamp, or their
   position next to the clear "Connected block <hash> at height N" line,
   would pair the two and name the block. They are removed from the file,
   and the package gets in their place one line per week with their count
   bucketed 0, 1–3, 4–20, >20, as for the `events.log` stake records
   (A11). The same holds for every staker line not on the A11 staker
   allowlist, in any log (O1), and the node's own hourly staker count
   lines are summed per week, per site and kind, into the same
   buckets. A line on the A11 counted list is not kept in place either,
   even masked, whatever its module: its timing next to the Connected
   line names the block. Rule (e) removes it. This covers the wallet and
   mempool lines written while a block is connected (A11 "Wallet lines on
   the connect path", `wallet_db.rs:2835` "Received {} to {} in tx {}"
   among them), in logs with and without the change. (c) In every other line, any number followed by `sats`, `sat` or
   `DIVI` is masked. (d) In `Invalid -k=v` warnings (about `main.rs:446`)
   everything after `=` is dropped. (e) **Per-block lines** (O1). In a log
   from a node older than the A11 "Own blocks log like peer blocks"
   change, or whose version is unknown (the same version test as for a
   pre-A11 log), the own block is logged differently from a peer's, so no
   per-block line is kept in place: every "Received block", "Ignoring
   block", "Block message received", "Connected block", "Connected orphan
   block", "Chain reorganized!", "Accepted block", "Block … reorganised
   the chain", "Broadcast block inv", "Relayed block inv", "Activating
   stored block", "try_activate_block: Successfully activated block",
   "Self-accepted block … processed", "Block … at height … processed" and
   "Failed to save wallet after" line is removed (except
   `crates/divi-rpc/src/wallet.rs:796` "Failed to save wallet after chain
   sync", a failure-only line, A11 item 6), "Block sync complete",
   "Sync progress" and "Sync stalled" when the node is older than
   8e4bfaca (A11 item 8), and every "runCommand
   error" line in its old format (A11 "Notify commands"), and so is every staker
   line not on the A11 allowlist, the success lines included, and every
   format on the A11 counted list (A11 "Own blocks log like peer blocks"
   item 6, with the wallet and mempool connect-path lines). In a log from
   a node with the change, the lines on the A11 counted list are removed
   the same way, and the shared Connected line stays (a public record,
   above). **By default every log — every input above, from every run —
   is treated as an older log**, the change or not, until the A11 item 7
   timing gate passes; it is measured with real network delay (A11 item
   7, §10 item 5), it will probably fail, and then this default is the
   shipped design. Each removed format is replaced
   by one line per week with its count bucketed 0, 1–3, 4–20, >20, as in
   (b); the node's hourly count lines are summed into the same weekly
   buckets. Per-message lines are bucketed per command. "Received block"
   is also bucketed per week per peer pseudonym, so which peer sends
   blocks stays visible. Lines written only on a failure — the staker's
   (`staker.rs:766`, `:856`, `:1255`, `:1541`) and the sync failures
   (the 19 sites of the A11 item 6 failure-only group, `sync.rs:1515`
   "Dropped invalid block" among them) — are bucketed per day instead, since they mark trouble rather than a
   block, and a day dates it well enough. Weekly, not
   hourly: an hourly count of a peer-only line beside the clear per-block
   Connected lines would show, hour by hour, one connected block that no
   peer sent. The §8.3 preview says this was done. The summary names the
   files the rule ran on.
3. **Structure.**
   - Config: secret keys show `<set>`/`<unset>`; `masternode.conf` lines show
     only the alias pseudonym and the count of fields; unknown keys show
     their **name only**; values of known non-secret keys are shown with
     paths and addresses pseudonymised.
   - Processes not named irondivi*: `comm` and exe basename only, no argv,
     no environment, no cwd.
   - `irondivid` processes: argv with every value masked except an allowlist
     of keys whose values are not private (`-testnet`, `-regtest`,
     `-daemon`, `-staking`, `-loglevel`, `-debug`, `-printtoconsole`,
     `-listen`, `-maxconnections`, `-dbcache`, `-par`, `-txindex`, and the
     other boolean or numeric tuning keys listed in the code). The same
     allowlist applies to every irondivi command line diag writes,
     including an irondivi A3 sender's and the parents' command lines,
     which are re-redacted on collection even though A3 already applied it.
   - `irondivi-cli` command lines (B2.4, an A3 sender, a cron line, a shell
     history line the user attaches): the allowlisted `-` options as
     above, then the RPC **method name only**; every later positional
     argument becomes `<arg>`, whatever the method, so a passphrase, an
     address or an amount passed positionally never survives
     (`irondivi-cli walletpassphrase <arg> <arg>`). The method name itself
     is kept only when it is a known RPC method; otherwise it is `<arg>`
     too.
   - A non-irondivi command line (an A3 sender that is not irondivi): the
     basename of argv[0], then `<arg>` for each further argument.
   - Kernel and syslog lines that quote a command line (`ptrace attach of
     "python3 -I /x secret"[123] was attempted by "cat …"[456]`, audit and
     OOM lines): each quoted string followed by `[pid]` that holds a space
     keeps only its program's base name, `"python3 <args>"[123]`.
   - Unit files, `docker inspect`, and attached `docker inspect`, `pct
     config`, `lxc config show` and `lxc-info` output (B6.6): `Environment*`,
     `Env`, `Labels` values and `ExecStart` values outside the allowlist
     are dropped; mount sources and paths are pseudonymised.
   - Paths: each component other than well-known system directories and
     irondivi's own fixed names is pseudonymised (`/home/u-3c1a/.irondivi`).
     The fixed names are the binaries and data-dir names, `irondivi-diag`,
     `irondivi-diag-*`, `.irondivi-diag-fsync-*`, `irondivi-replay` and
     `/var/tmp/irondivi-<uid>`; a name the user chose that merely starts
     with `irondivi-` or `divi-` (a folder, a Docker image) is user data
     and is pseudonymised.
     This includes Windows and WSL forms in attached files:
     `C:\Users\<name>\…` (the user name component always, any case,
     either slash) and `\\wsl$\<distro>\…` / `\\wsl.localhost\…`
     (the distro name and every component below it that is not a
     well-known directory).
   - Peers: class + pseudonym; user agent and version kept.
4. **Bytes.** Redaction works on bytes; invalid UTF-8 is matched as bytes
   and escaped afterwards, so a secret split by a bad byte is still found.

**Diag's own files.** `diag.log` and `00-SUMMARY.txt` hold error paths
(for example under `/home/<user>`), the temporary config directory, the
`--rpc` method and arguments, upload errors and the `sudo -u <owner> …
--datadir <path>` hint. The copies that go into the package pass through
§6.2 and §6.3 like every other file; only the terminal, which never leaves
the machine, may show them in clear.

### 6.3 The scanner — nothing is packaged that still matches

After §6.2, every file is scanned again for every known value from step 1
and every pattern from step 2, in each of these encodings: plain, upper and
lower case, hex (both cases), base64 (all three alignments), URL-encoded,
JSON-escaped, UTF-16LE, reversed byte order for hashes, and `user:pass`
pairs base64-encoded as they appear in HTTP basic auth. It also checks for
the run's salt, the public-record salt and every per-call A10 key `k` in
every encoding (none of them should ever be written, so a hit means a
leak), runs the A10 secret-environment match (every byte offset, tag then
HMAC, and the four decoded views, P3, R2) again over every file and stops packaging on any remaining hit, and
refuses any file whose content matches a line of the private
`diag/sent-txids` file (A15) or which is that file. Own-hash and own-txid
known values are not matched inside public-record fields (§6.2 "Public
records"), including the block hashes of the non-wallet chain, sync, node
and net log lines named there (B1, Y3), where they legitimately appear as
ordinary entries; a stake-announcing staker line (§6.2 "Old-log lines"
(b)) left anywhere in the package is a hit, and so is any line of a
format on the A11 counted list or any per-block line that §6.2
"Old-log lines" (e) removes, in any of its inputs, the debug-ring
sections of `crash.log`, the incidents and `getdiaginfo` and the A14
mirrors included (O1, consensus B4). Such a hit means the filter missed
a copy; the release tests treat it as a failure (§10 item 5), not as a
file to leave out quietly, since `crash.log` and the incidents are the
files a crash report needs; a public
pseudonym that equals a wallet-side pseudonym is itself a hit. Any hit stops packaging: the file and line
are named to the user (without the secret), and that file is left out with
the reason in the manifest. The scanner re-runs over the final folder at
preview **and again at submit**, after any edit the user made (§8.3), and
compares each file's SHA-256 with the manifest.

**Canary tests** (in the test suite, run before every release): the A11
canary wallet, plus a canary hostname, user name, home directory, RPC
password, cookie, masternode key, TLS key, peer IP, public IP, environment
value, config comment, `addnode` hostname, TLS certificate SAN, mount
source, a stake height, an amount written as `1.23456789 DIVI` and as a bare
`123456789` in a wallet-module line, an `Invalid -rpcpassword=<canary>`
warning, a canary in the node's environment, and `token=<canary>` and
`"auth": "<canary>"` lines in a component log; a realistic environment
(the canary beside real `PATH`, `LANG`, `TERM` and a Docker-style 12-hex
`HOSTNAME`), where the canary must go and `PATH` and `LANG` must survive;
a canary label on a **pre-A10** node in a component log and in the
`01-user-report` text, with no "method not found" from step 1; a
malformed `-rpcpassword=<canary>` argument and a malformed config line
holding a canary, which must appear in neither the R3 code 2/3 reason,
`runs.log`, nor `_unresolved/`; an apport report whose `Stacktrace` holds
a canary local (only `StacktraceTop` frames may survive); a bare canary
host name in a syslog and a journal hostname column, a Windows event
`Computer` field, `C:\Users\<canary>` in PowerShell output and `docker
info` `Name: <canary>`; a canary path and `--rpc` argument in
`diag.log` and `00-SUMMARY.txt`; a canary private key and passphrase held
by a thread that crashes inside the signing path (A5 item 3), searched in
every encoding including base58 and WIF, in either byte order; a canary
wallet address planted as a P2PKH `scriptPubKey` hex, as the hash160 in an
`asm` string, and a canary public key inside a `scriptSig` hex, in
`--rpc gettransaction`, `--rpc listunspent` and `--rpc-clear` answers; a
canary own-transaction `height`, `bcconfirmations` and `spentHeight` in
`--rpc` answers; a canary own address and a canary public key in the
`hex`, `asm`, `script` and `scriptSig` fields of an **`--rpc-clear`**
answer, where the script fields must be absent while the clear `address`
field is present and counted in the consent tally (P1); an own staked
block fetched with `--rpc getblock <hash>` (verbosity 1 and 2), `--rpc
getblockheader <hash>` and `--rpc getblockhash <height>`, with one canary
per field (R1): its `hash`, `previousblockhash`, `nextblockhash`,
`confirmations`, `height`, `time`, `mediantime`, `merkleroot`, `nonce`,
`bits`, `difficulty`, `chainwork`, `acc_checkpoint`, `moneysupply`,
exact `size`, every txid of the block in clear and, at verbosity 2, each
transaction's `blockhash`, `time`, `blocktime` and `height` must be
absent from the answer and from the call line, while `version`, the size
class and `nTx` are present (P2, R1); an attached
own-address `getaddressutxos` answer (bare, in a `{"result": …}`
envelope, and in the `chainInfo` form) and an attached
`getaddressbalance` answer, with and without `--attach-method`, whose
canary address, `script`, `satoshis`, `height`, `balance` and `received`
must be absent or bucketed and whose preview line says "treated as RPC
output: <method>" (C1, C2, V3); an attached `gettxoutsetinfo` answer whose
eight keys (`height`, `bestblock`, `transactions`, `txouts`, `bogosize`,
`bytes_serialized`, `hash_serialized`, `total_amount`) must all survive in
clear (V3, N2); and a canary value in a secret-named environment variable
(`IRONDIVI_TEST_TOKEN`), which the A10 environment page must carry only as
HMAC, length and tag (never the value) and which must be absent from any A17
incident, while the same value standing alone as a command-line argument
(`--token <canary>`), after `=` in `--token=<canary>`, inside a URL
`https://u:<canary>@h/` and in a component log line must be replaced with
`<secret-env:IRONDIVI_TEST_TOKEN>` (P3); a secret-named variable with a
value under 8 bytes, which must not be sent at all (P3); the same token
canary glued to a flag (`-p<canary>`), inside a longer word
(`ab<canary>cd`), with a first character `!` written straight after a
letter (`pw!…`), base64-encoded as `user:<canary>` after `Authorization:
Basic` in a component log, percent-encoded in a URL query, and
JSON-escaped (a canary holding `"` and `\`) in an attached file, each of
which must be replaced with `<secret-env:IRONDIVI_TEST_TOKEN>` (R2, W6);
an attached `listunspent` answer with no `--attach-method`, bare and in a
`{"result": …}` envelope, holding an entry with an `account` label and a
P2SH entry with a `redeemScript`, whose exact amounts, confirmations,
label, `redeemScript` and own addresses must be absent or bucketed (D1);
the same answer attached with `--attach-method getblock` (mislabelled)
and an unlabelled `listtransactions` answer from Divi Core, with the same
result (R3, K5); an unknown-shape JSON file whose objects hold `amount`,
`confirmations`, `height` and `time` canaries but no `txid`, which must be
bucketed or absent while its `pid` and `port` stay (W1); a canary wallet
label on a node bound only to a LAN address, which must still be masked
through the pre-A10 call fallback, with the summary naming the degraded
masking (W2); on (a) a running node, (b) a stopped node, (c) a
node whose RocksDB cannot be opened as secondary, (d) a pre-A11 `debug.log`
written with `-debug=1` and real wallet activity, (e) a `contrib/diag.sh`
folder imported with `--import` on a different machine, with canaries in
its `runs.log` and kernel log lines. The package must contain none of them in any
§6.3 encoding, and must contain the non-secret facts each collector is meant
to show (so redaction that destroys the evidence also fails the test).

**Revision 9 canaries** (each also in §10 item 5): an attached
`listtransactions` entry with `confirmations` `-1`, which must read the
`-1` class and never 0 (E1); a `getwalletinfo` answer attached with
`--attach-method gettxoutsetinfo`, the same labelled `getblockchaininfo`
(X2), an unlabelled `getmintinginfo`, and a `getwalletinfo` with one
extra and one missing field, none of which may leak an exact `balance`,
`unconfirmed_balance`, `immature_balance`, `stakeweight`,
`netstakeweight` or `txcount` (S1, X2); an own staked block fetched with
`--rpc getblock`, `getblockheader` and `getblockhash` on a **pre-A10**
node and on a node bound only to a LAN address, which must be reduced as
on an A10 node, with the warning naming own staked blocks (S2, X1); the
public block after an own staked block, whose `previousblockhash` must be
absent (S4); and a secret-environment canary written as unpadded base64
and as base64url, which must be replaced (S4).

**Revision 10 canaries** (the first replaced in Revision 11, O1). A
regtest `debug.log` from a node with the A11 "Own blocks log like peer
blocks" change, at `-debug`, with an own staked block among peer blocks,
whose "Connected block" hash must be in clear like every peer block's,
and in whose package no staker line off the A11 allowlist and no line on
the counted list may stand in place, only weekly counts; the same log
from a node without the change must keep no per-block line at all (§6.2
"Old-log lines" (e)) (B1, Y3, O1); a vault-staked
block looked up on a LAN-only node, which must be reduced (Y1, Y2); a run
of three consecutive heights with the middle one own, all three reduced
(Y4); an attached `gettxoutsetinfo` with all eight keys in clear (N2);
and a `known_values` environment page whose tag must not equal R_b's low
16 bits (N1).

**Revision 11 canaries.** A regtest block staked from a P2PK output,
which must be decided own and reduced (P3); a block reduced as
undecided, whose coinstake txid must equal its public-record pseudonym
and not its wallet-side one (N4); and an own staked block whose own-UTXO
txid and vout (`staker.rs:1475`, `:1488`, `:1509`, `:1520`) must appear
in no file of the package (O1).

---

## 7. Coverage

### 7.1 Every failure and the file that answers it

"sh" marks the rows `contrib/diag.sh` (B1.4) also answers.

| Failure as the user would report it | Answered by |
|---|---|
| Starts, then the prompt comes back, empty log (the friend's case) | A1 phases + exit, A3 sender, A2 verdict, B2.11 OOM line, B2.3 limits, B2.14 row; with `-daemon`, A1 `daemon` shows it forked and is running. sh: runs.log, kernel log. |
| Killed by memory limit (host, container, cgroup, systemd-oomd, earlyoom) | A2 counters and ancestors, B2.11 OOM block, B2.4 oomd/earlyoom, B2.5 unit `Result=oom-kill`, B2.3 limits; host-side: L3. |
| Killed by a person or a script | A3 sender comm/cmdline/parents, A1 stop-requested, A15 if via RPC. |
| Container stopped or restarted | A2 PID 1 start time verdict, A3 `outside-pid-namespace`, B2.5 Docker state; L3. |
| Machine rebooted, power loss | A2 boot id verdict, B2.2 uptime, B2.11 previous boot (journal `-b -1` filtered). |
| VM or laptop suspended | A6 `BOOTTIME − MONOTONIC`, A12 time jumps, B2.11 suspend lines. |
| Crash (SEGV, abort, illegal instruction) | A5 crash.log with stack + maps + debug ring, A16 symbols, the A9/A1 exit record and A2 verdict, B2.5 exit code/signal from the service manager, B2.11 segfault line; B2.12 core metadata (frame address, function, module only) only for a pre-D5 node — a non-dumpable node leaves no `coredumpctl` entry. A fatal signal sent by another process (`kill -SEGV`, `SI_USER`/`SI_TKILL`) is recorded with the A3 sender chain and shown as "sent by `<comm>`", not as a crash (A2, A5, B2.14). |
| Out of memory inside the process (an allocation fails) | A5 `alloc-null size=<n>` record, then exit 134 with the A5 abort record; A6 RSS before it. |
| Panic | A4 in crash.log and runs.log with backtrace, exit 101 or 10. |
| Stack overflow on a node thread / a RocksDB thread | A5 altstack record + exit 134 / A5 limit: marker + 139 + kernel line naming the thread. |
| Illegal instruction from a CPU without required features | A5 `SIGILL` + PC, A7 and B2.2 CPU flags, B1.2 build target. |
| Binary will not run (wrong arch, glibc too old, not executable, Gatekeeper) | B1.2 exec errors, ELF/Mach-O class, interpreter, B4.2 quarantine; sh. |
| `irondivi-cli` itself cannot run on this machine (no static-musl build for the arch) | B1.4 `contrib/diag.sh` folder, reviewed and sent with B6.4 `--import` on any machine. sh. |
| Config error, bad flag | R3 codes 2/3 with reason in runs.log and the A14 mirror, A7. |
| Data dir permission problems, "ran it once with sudo" | B2.7 ownership mismatches, A1 uid per run, B1.1 EACCES note. |
| Lock held / two nodes on one data dir / two nodes on one machine | R3 code 4, B2 `/proc/locks`, B1.1 every node listed. |
| Port in use | R3 code 7 with port, B2.13 listeners. |
| Disk full, read-only filesystem | R3 code 9, A6 free space, A12 crossings, B2.6, B2.11. |
| Database corruption, RocksDB background error | B2.7 RocksDB LOG, B2.8 open error and verify, B2.11 I/O errors, B2.6 fsync test, B4.3 SD errors. |
| Slow or failing SD card / network filesystem | B2.6 latency, B2.11, B4.3, B2.7 RocksDB stall lines. |
| Hang (no RPC answer, no log), whole or partial | A17 watchdog incident with threads, wchan, lock holders and per-thread stacks (Linux and macOS; the sweep bounded at 200 ms a thread and 2 s in all, with threads in `D`, with the signal blocked or not answering named, K1), written when **either** the health tick or the tokio runtime stalls for 60 s, or a JSON-RPC/Electrum/Web UI call has been in flight for over 60 s (that handler thread's stack named); when RPC does not answer, B2.16 writes the A17 snapshot request and collects the incident 5 s later; B2.16 wchan sampling only when the node is readable (never a D5 `0`); B3.3 opt-in stacks only where the attach can work (D5: root with `CAP_SYS_PTRACE`). A node that was stopped or frozen rather than hung shows as A17 "process not scheduled N s (stopped …)" (a `CONT` record makes it "stopped"; `frozen` only while still set); one starved of CPU or memory shows as "process starved N s" with the cgroup's own throttle and stall deltas, or as "cause uncertain" when only system-wide PSI is available, and the late interval is subtracted from the hang clock rather than resetting it, so a real hang under starvation is still reported. |
| Start-up never finishes (stuck in one phase) | A1 start-up bound (before `network`: no progress record, no read I/O and no CPU on the non-Part-A threads; from `network` on: no phase or progress record and no CPU on the start-up thread alone, X1 — for the bound): A17 incident with thread-state samples (a `wchan` of `0` written `running` for state `R` and `hidden` otherwise, N3) and every thread's stack under the K1 bounds (K2), and an events.log line; the node keeps running. From `network` on, a phase still running after 15 minutes with no new phase record writes an incident whatever its CPU (K4: a spinning start-up thread) and never ends the run. Only with an explicit `-startuptimeout=<s>` (A18; B3.2 passes it) does it then exit 10, even when the stack sweep did not finish (K1), writing the incident and exit record to the A14 mirror first, so a hung data-dir disk cannot block them; a thread stuck in `D` state can delay the final reap, but the mirror record is already there. B2.14 row. A stop request during start-up exits 0 with no `unclean-previous` next time (A1). |
| Slow node, high CPU, high memory | A6 per-tick RSS/CPU/IO/PSI, A10 counters, A17 lock waits, B2.16 smaps; past episodes from health.log; "slow yesterday": health.log covers days at 60 s (A14 5 MB). |
| Memory grows until killed (leak) | A6 RSS/allocator stats over the run, A2 counters at death, incidents. |
| Not syncing, stuck at a height | A6 chain fields, A10 sync internals, A12 stalls, A13 invalid block bundle, B2.15 seed reachability and clock offset. |
| Fork, wrong chain, reorgs | A12 chain-events reorgs and header conflicts, A10 `getchaintips`, A13 bundle, B2.15 seed heights. With `previousblockhash` and `nextblockhash` dropped from every block answer (B6.5, S4), a fork is traced through `getchaintips`, the A12 reorg lines and the A13 headers; on a node older than A10 or A13, the parent of an off-chain block is not in the package (N3). |
| Invalid block / consensus disagreement | A13 replay bundle (public data), `irondivi-replay`. |
| No peers, peers dropping, banned | A10 bans with reasons and score history, A12 bans, B2.13 firewall, B2.15 probe, proxy flags. |
| Clock wrong | A6 offset and future headers, B2.2 time sync, B2.15 seed timestamps. |
| Not staking | A6 reason now, A12 every change of reason with time, last stake age, A10 kernel counters, B2.9 maturity buckets. |
| Staking stopped last week | A12 events.log (months): the reason change at that time, plus restarts, locks, sync state around it. |
| Masternode not in list / dropped off | A10 own status, `mnsync` per asset, list counts, winners, collateral confirmations, A12 status changes with time, B2.15 reachability, B2.13 listener class. Collateral itself never leaves. |
| Rewards (stake, MN, lottery, treasury) missing | A12 stakes found (weekly bucketed counts in the package), A10 lottery/treasury heights and winners, B2.9 counts by category. |
| Balance wrong | B2.9 shares by category, spend graph, conflicted/abandoned counts, wallet best block vs tip; for a specific transaction: B6.3. |
| Transaction stuck / not confirming | A15 the send call, A10 mempool, A12 rejections of non-wallet tx; for the user's own tx: B6.3. |
| Wallet will not load / decrypt / wrong version | R3 code 6 with reason, B2.9 format version and encrypted flag. |
| Reindex or rescan started by itself | A1 phase `migration`/`wallet-rescan` with the trigger reason, A7 argument sources, A12, B2.14 diff from previous run. |
| Worked until an upgrade | B2.14 version diff row, A1 binary hash, A7 config diff, B2.8 migrations; history from before Part A from debug.log banners (stated as partial). |
| Crashes every few days | runs.log over months, A2 verdict per run, incidents; if still unexplained: B6.1 `--capture … --until exit`. |
| Restarted by Docker/systemd in a loop | B2.5 NRestarts/RestartCount, B2.14 runs a few seconds apart with their exits. |
| "I ran a command and then it broke" | A15 per-minute and hourly aggregates per method over every transport, with distinct-caller counts, plus a per-call line with time and result for every state-changing method, the first call of each (method, caller) in an hour for local or authenticated JSON-RPC callers, and errors (the first 5 per method, code and transport each hour, at most 50 an hour; the rest as counts); state-changing calls from remote Electrum and Web UI callers are capped at 5 per (method, result, transport) and 50 an hour, so a remote broadcast flood cannot push the local lines out; A12 state-changing methods; irondivi-cli's own log in the mirror. |
| An error the user saw on screen | `01-user-report.txt` paste (§8.1, redacted), A8 debug ring, A15 cli log. |
| Electrum/Web UI/ZMQ problems | B2.17, A10 counters, A15, Web UI JS errors (A15). |
| Swap problems | B2.17 swap daemon state and errors. |
| Deleted data dir, wiped or recreated container | A14 mirrors outside the data dir, B1.1 "none found" with paths searched, B2.3 volume vs writable layer. |
| Seccomp or AppArmor/SELinux blocking a call | B2.18 (filter mode, `actions_logged`), B2.11 audit lines (`type=1326` for seccomp), exit 159 (SIGSYS, `KILL_PROCESS`) in A2/A5 with the A2 marker. |
| Raspberry Pi under-voltage, thermal, 32-bit address space | B4.3. |
| WSL problems | B4.4. |
| macOS: killed by jetsam, blocked by Gatekeeper, crash report | A2 jetsam verdict (the unified-log memorystatus line naming the previous pid), B4.2, B2.12 `.ips` (frames only). |
| Diag itself hung or failed | B2.20 diag.log, per-collector timeouts (B5), summary written first (R1 a). |
| A diag collector stuck in uninterruptible sleep | B2 `ABANDONED (uninterruptible)` record with pid, `wchan`, kernel stack — itself evidence of a storage hang; B2.6, B2.11. |
| Electrum (or Web UI) stopped answering last week | A12 events.log listener errors and restarts with time, A15 per-minute (48 h) and hourly (30 days, or about 14 at the worst case of 50 methods active every minute) aggregates and errors over the period, B2.17 state now. |
| Staking less than expected | A6 found count and found/expected ratio over 30 days as buckets (count 0, 1–3, 4–20, >20; ratio <0.5, 0.5–2, >2, or "too few expected to judge"), A12 every reason change, A10 kernel counters, B2.9 maturity buckets; a mild shortfall inside 0.5–2× is L12, whose second step is `diag --rpc getmintinginfo` (B6.5). |
| Seccomp kills a thread or makes a call fail (`KILL_THREAD`, `ERRNO`) | `KILL_THREAD`: A17 vanished-thread record in crash.log and events.log, plus the B2.11 audit line when B2.18 `actions_logged` includes it (no handler runs, so there is no `si_syscall`); `ERRNO`: the failed call's error in the A8 debug ring and the runs.log reason; B2.18 filter mode. |
| Node stopped (SIGSTOP), traced, or cgroup frozen | B2.16 process state first (`T`/`t` with `TracerPid`, cgroup `frozen=1` / v1 `freezer.state`, macOS `ps`); afterwards, A17 "process not scheduled N s" (the wake-up lateness check) and A3 `CONT` for a `kill -CONT`. |
| Node blocked by macOS privacy (TCC) | B4.2 "blocked by macOS privacy (TCC)" from diag's own `EPERM` and from the node's errors in runs.log, with the Full Disk Access step. |
| Node is PID 1 in its container, zombies pile up, signals ignored | B2.3 "node is PID 1, no `--init`", zombie count from B2.4, A3 signal records. |
| Docker Desktop (macOS, Windows) | B4.5 detection, L3 commands for the hidden VM, `diag --host docker-desktop`. |
| SIGHUP received (logrotate, terminal closed) | A3 record; HUP reopens the logs and never stops the node (R3), so a stop near a HUP is explained by its own A1/A3 record. |
| An RPC gives a wrong answer | A15 the call, A10 internals, and L10's second step B6.5 (`--rpc` on the extended read-only allowlist with argument caps; wallet fields dropped or bucketed). |

### 7.2 Stated limits, and the second step for each

| # | What the package cannot show | Why | Second step that answers it |
|---|---|---|---|
| L1 | Anything before Part A existed: exit status, sender, phases of runs on 0.2.9 and earlier. | Not recorded at the time. | Upgrade, reproduce; the next failure is fully recorded. If it does not recur, B3 observed start, or B6.1 capture. |
| L2 | A failure that does not happen while diag looks and left no trace (intermittent slowness with no health record yet). | Nothing to collect yet. | B6.1 `diag --capture <min> --until <event>`. |
| L3 | The host's view of a container or VM: host memory limit, host OOM log, `pct stop` by the host, host disk. | Not visible from inside. | `diag --host <id>` on the host (B6.2), or the exact command printed in the summary, each ending in `> <name>.txt` with the matching `diag --attach <name>.txt` line (B6.6): `pct config <id>` + `journalctl -k --since …` (Proxmox), `lxc config show <name>` + `lxc info <name> --show-log` (LXD), `docker inspect <c>` + `journalctl -k` (Docker), the Docker Desktop commands (B4.5), the PowerShell commands for WSL. |
| L4 | A specific own transaction in clear. | Private (§6.1). | B6.3 `diag --tx <txid>` with explicit consent. |
| L5 | Stack of a foreign (RocksDB) thread that overflowed its stack. | No altstack on threads created in C++. | The marker, 139, and the kernel's thread name narrow it (a Rust thread's overflow is caught instead: A5 altstack record and 134); reproduce under B3 with B3.3 tracing (`strace -f` from the start works under D5; a live `eu-stack`/`gdb` attach needs root with `CAP_SYS_PTRACE`, otherwise it is recorded as refused and the A17 stacks stand in), or on the developer's side with the replay of A13 when a block triggers it. |
| L6 | Process memory contents (a core). | Holds keys (§6.1). | Never sent, and on Linux never written by the node at all (D5: non-dumpable). The developer reproduces with A16 symbols, the crash.log frame walk and **filtered** stack words (only code and stack addresses survive the A5 item 3 filter; on 32-bit builds only with the §8.2 "raw stack words" consent) and the A8 debug ring, which are designed to be enough. |
| L7 | Events at the kernel level when the kernel log is unreadable (container, no `CAP_SYSLOG`, `dmesg_restrict=1`) and diag is not root; on macOS, paths TCC blocks. | Permission. | Re-run as root (printed command) or L3 on the host; on macOS, the Full Disk Access step B4.2 prints, then re-run. |
| L8 | Power loss with no `fdatasync` reached: the last seconds. | Hardware. | A2 boot id verdict states it; the previous `health.log` record bounds the time. |
| L9 | What happened in the user's terminal outside irondivi. | Not the node's. | `01-user-report.txt` asks for it (§8.1). |
| L10 | The content of an RPC answer the user says is wrong. | Answers are not logged (they may hold wallet data). | B6.5 `diag --rpc <method> [args…]` with consent, for the read-only methods on the B6.5 extended allowlist only, with its argument caps (clamped calls and dropped fields shown on screen) and the stop rule; for `gettxoutsetinfo`, `getaddressbalance` and `getaddressutxos`, whose cost no argument bounds, and `listunspent` on a wallet above 10,000 transactions (V1), "run it yourself and `diag --attach` the output", printed as the full command with `--attach-method <method>` filled in, for example `irondivi-cli diag --attach unspent.json --attach-method listunspent` (B6.5, B6.6; D1, R3), where the attached answer gets the same B6.5 answer rules (C1, C2, V3); when the wrong amount itself is the evidence, `--rpc-clear` (same allowlist, never `getdiaginfo`, at most 100 addresses and txids, labels, comments, HD ids and every script and raw-transaction key still dropped) with its separate consent stating the counts (§8.2). |
| L11 | Wallet facts while the node is stopped, including "the node won't start because the wallet won't load". | Diag never opens the wallet store (§6.1). | B3 observed start on a binary with the A18 flags (on 0.2.9 and earlier, upgrade first: their `-disablewallet` fallback never loads the wallet). The wallet-load error then lands in `runs.log` and the A8 debug ring, and `getdiaginfo` gives the B2.9 section once the node runs. |
| L12 | A mild staking shortfall (found/expected inside 0.5–2×), and the exact stake count. | The A6 ratio and count are buckets: an exact count or expected rate with the public network weight would give the wallet's balance. | B6.5 `diag --rpc getmintinginfo` with consent: stake weight and network weight as a ratio bucket and `expectedtime` bucketed, which the developer compares with the A12 weekly counts; when the exact figures are the evidence, `--rpc-clear getmintinginfo` with its separate consent (§8.2). |

Nothing outside these rows and the §7.1 table is claimed. A new failure kind
found after release is added to §7.1 with its file, or to §7.2 with its
second step, in the same change that handles it.

---

## 8. Preview and consent

### 8.1 The user's own report

Before collecting, diag asks five questions on the terminal (each can be
left empty; with no tty they are skipped and the file says so):

1. What did you see? (Paste any error text; end with an empty line.)
2. When did it start, roughly? (Date and time, or "after I did X".)
3. What changed before it started? (Upgrade, new config, moved the data dir,
   new machine or container, power cut, anything.)
4. What commands did you run around then?
5. Anything else?

Answers go to `01-user-report.txt` and through §6.2 and §6.3 like every
other file, so a pasted address, path or hostname is pseudonymised. The
summary shows the time window from answer 2 next to the run table, so the
developer reads the right rows first. `--report-file <path>` takes the
answers from a file instead (for scripts and translators).

### 8.2 Specific consent questions

Asked only when the material exists, each one a separate yes/no with what
it reveals stated plainly; the default and the no-tty answer is no:

- **Own invalid stake or transaction** (A13 `own-invalid/`): "Include the
  block your wallet staked, or a transaction from this machine (sent by the
  wallet or submitted over RPC by a local caller), that was rejected? It
  shows the developer that this machine made it, and its inputs, outputs
  and amounts."
- **One transaction** (B6.3 `--tx`): "Include transaction `<txid>` in clear?
  It shows its amount, inputs and outputs, which of the outputs is your
  change and its address, and which earlier transactions paid for it. Your
  labels stay hidden."
- **Host package** (B6.2): "Include the host's view of container `<id>`?
  It shows the host's memory, storage and container configuration (names
  pseudonymised)."
- **One RPC answer** (B6.5 `--rpc`): "Include the answer to `<method
  args>` shown above? Addresses and transaction ids in it are
  pseudonymised, amounts, balances, values and fees are bucketed, stake
  weights are a ratio bucket, confirmation counts are bucketed, and
  labels, comments, HD ids, scripts, raw transaction hex, and the
  heights, times and block hashes of your transactions are dropped;
  everything else is as shown." The redacted answer is shown on screen before the question,
  with the exact call after any clamping of its arguments (B6.5 argument
  caps) and the list of dropped fields. Methods outside the B6.5
  allowlist, and `getdiaginfo` with any parameter, are refused before any
  question.
- **One RPC answer in clear** (B6.5 `--rpc-clear`): "Send the answer to
  `<method args>` in clear? It shows the amounts, <n> addresses and <m>
  transaction ids in it." Asked only after the redacted question, only
  with the flag, only for a method on the B6.5 allowlist and never for
  `getdiaginfo`. Refused before the question when the answer holds more
  than 100 addresses and txids together (the user is pointed to `--tx`).
  Labels, accounts, comments, `to`, the HD ids and every script and
  raw-transaction key (`hex`, `asm`, `redeemScript`, `script`,
  `scriptSig`, a string `scriptPubKey`) are dropped even in clear (B6.5,
  P1; `--tx` sends one transaction in clear). The question says so: "Scripts
  and raw transaction data are never sent in clear."
- **Own staked block** (B6.5, P2): no question; the screen says "this
  block was staked by your wallet; only its version, size class and
  transaction count are sent", and nothing else from the block, not even
  a pseudonym of its hash, is sent (R1).
- **Raw stack words (32-bit build)** (A5 item 3): asked only when
  `diag/crash-stack.bin` exists, on an armv7 or i686 node: "Include the
  filtered stack words from the crash at <time>? On a 32-bit build a
  fragment of a key held by the crashing thread could survive the filter.
  They help the developer unwind a crash the frame walk could not." Off by
  default.
- **Attached files** (B6.6 `--attach`): each file is listed with its size
  and the lines §6.2 changed, and the user confirms it. A file recognised
  as an RPC answer is listed as "treated as RPC output: <method>" (or
  "JSON of unknown origin; script keys and hash backstop applied", with
  the values the key-name rule dropped or bucketed, W1) with the fields the
  B6.5 rules dropped or bucketed (C1, C2, V3); a JSON file the user wants
  read as a particular method is re-run with `--attach-method <method>`.
- **Secret environment values** (A10, P3): no question, but the preview
  states what the redaction does and does not catch: "Secret values from
  the node's environment (<names>) were searched for in every file and
  replaced <n> times, including base64, percent-encoded and JSON- or
  shell-escaped copies. A secret written in any other form — hex,
  compressed, encoded twice, split across lines or altered — is not found,
  and nothing else checks for it." (R2)
  Each secret-named variable shorter than 8 bytes is listed by name with
  "short secret, masked only beside its name", so the user knows to look
  for it in the files before sending.
- **Observed start** (B3): asked before starting the node, with the B3.1
  checks it passed and what it will do (B3.2).

### 8.3 Review

1. Diag prints `00-SUMMARY.txt` first: verdict per run, what was found, what
   is missing and why, the stated limits that apply (§7.2) with their second
   step, the total size, and the folder path. When §6.2 "Old-log lines"
   (e) ran, it says so: "per-block log lines and staker lines were
   reduced to weekly counts, so the package does not show which blocks
   this node staked; the chain's own history is in `chain-events.log`,
   with a tip record every 100 blocks, reorgs, invalid blocks and
   stalls" (O1, consensus N-e). It also says, always: "a `debug.log` or
   `crash.log` you send by hand, outside this package, is not filtered:
   it can show which blocks and transactions are this wallet's"
   (adversarial AC3, privacy N3). On a current node that is the
   first-tier counted lines that stay in `debug.log` (the notify lines,
   the network lines of A11 item 6), and in `crash.log` any site that
   misses the A8 tag; on a node older than A11, every per-block and
   wallet line.
2. Then a menu: `[l]ist files`, `[v]iew <n>` (opens in `$PAGER`, default
   `less -R`, falling back to plain paging), `[x] <n>` exclude a file,
   `[i] <n>` include it again, `[e]dit` (opens the folder path so the user
   can edit or delete any file in their own editor), `[s]end`, `[q]uit
   (keep the folder, send nothing)`.
3. Every listed file shows its size, what collected it and why it is
   needed (one line from the manifest), so excluding one tells the user what
   the developer will not be able to see.
4. On `send`: the §6.3 scanner runs again over the folder as it now is; any
   file whose SHA-256 changed since the manifest is re-scanned and the
   manifest updated; any new file is refused unless added with `i`. Then
   diag shows the final list and total and asks `Send these N files (X MB) to
   the IronDivi developer? [yes/no]` — only the full word `yes` sends.
5. With `--no-submit`, no tty, or `q`, the folder stays and diag prints
   the command to send it later: `irondivi-cli diag --send <folder>`
   (which runs step 4 again).

### 8.4 Encryption and upload

- The folder is packed into `tar` + zstd, then encrypted with `age` to the
  developer's public key, which is compiled into `irondivi-cli` together
  with its fingerprint. `contrib/diag.sh` carries no key and never packs,
  encrypts or sends (B1.4): its folder is unredacted, so it becomes
  sendable only through `irondivi-cli diag --import` (B6.4), which redacts,
  scans and encrypts it. Only ciphertext ever
  leaves the machine; only the developer's private key, which never touches
  the receiver, can open it. The fingerprint is printed at send.
- The receiver is contacted for the first time **only now**, after the
  user typed `yes` (§8.3): its reachability is not probed during
  collection (B2.15 probes only the seed nodes), so neither the
  receiver nor its hosting provider learns the user's IP address or the
  time before consent.
- Upload is one HTTPS `PUT` to the receiver (§9). TLS is verified against
  the Mozilla roots compiled into diag (`webpki-roots`), so a machine with
  no or stale system roots (minimal containers, old Debian, busybox) still
  works; the system store is used in addition where it exists. The
  receiver's public-key pin is checked on top. Proxies: `HTTPS_PROXY` and
  `NO_PROXY` are honoured. Two receiver addresses are compiled in (a primary
  and a fallback on separate hosting); the second is tried when the first
  fails for a network reason.
- A failed upload names its cause, never just "error": `no route / DNS
  failed` (with the resolver result), `clock wrong` (the certificate is not
  yet or no longer valid at this machine's time, with the machine time
  and the server's `Date`), `TLS intercepted` (the chain verifies against a
  system-added root but the pin does not match — a company proxy or
  antivirus; the encrypted file is still safe to send another way), `proxy
  refused` (status from the proxy), `refused by receiver` (status and
  message, e.g. too large or rate-limited), `timed out` (bytes sent so far).
  Each is written to `diag.log` too.
- On success diag prints the ticket id and the SHA-256 of the ciphertext,
  and writes both to `diag.log`. The user quotes the ticket id in their
  report.
- If upload fails (offline, blocked, proxy), the encrypted file is left next
  to the folder and diag prints how to send it some other way (e-mail or
  chat attachment); it is safe to send through any channel because it is
  encrypted.
- `--offline` skips the upload and only writes the encrypted file.

---

## 9. Receiver

A small HTTPS service the developer runs. Hosting and domain: **open
decision** (the one question for the developer).

- **Accepts** `PUT /v1/upload` with an `age`-encrypted body up to 100 MB
  (B6.1 captures may need the 200 MB raw cap; zstd brings them under it, and
  diag splits into numbered parts if not). Anything that is not an `age`
  file (header check) is refused.
- **Returns** a ticket id: 8 characters from a 32-letter alphabet, random,
  not derived from anything about the sender.
- **Stores** only the ciphertext, its size, its SHA-256 and the arrival time,
  under the ticket id. No IP address, user agent or other request data is
  written to disk or to logs; access logs are off. That covers the
  service itself only: a hosting provider, load balancer or CDN in front
  of it keeps its own request logs, which "access logs off" does not
  reach. The hosting decision therefore prefers a host where the service
  terminates TLS itself with no provider request logging (a plain VM with
  no managed load balancer or CDN); if a provider with request logs is
  chosen, its retention is stated in diag's send prompt and in
  `docs/diag.md`.
- **Rate limits** by IP address **in memory only** (10 uploads an hour,
  1 GB a day), forgotten when the window passes or the service restarts.
- **Retention**: packages are deleted 90 days after arrival, or when the
  developer closes the ticket, whichever is first. Stated in diag's send
  prompt.
- **Developer side**: `irondivi-diag-open <ticket>` downloads, decrypts with
  the private key (from 1Password via `secret get`), checks the manifest
  hashes and runs `irondivi-replay` on any bundles.
- **No receiver available**: §8.4's fallback (send the encrypted file any
  other way) always works, so the receiver is a convenience, not a
  dependency.

---

## 10. Order of work

1. **D1–D6** with their tests (D5: the `PR_GET_DUMPABLE` unit assertion and
   the core-dump test of item 6). Released on their own as soon as done.
   **Measured on hp3, 2026-10-30** (Ubuntu, kernel 5.15.0-198-generic,
   `kernel.yama.ptrace_scope=1`, `fs.suid_dumpable=2`; a probe child set
   `PR_SET_DUMPABLE` 0, read its own `/proc/self`, and was read by a
   same-uid parent, by root with `CAP_SYS_PTRACE` and by root without it).
   These results replace r6's "expected" text and are what A5, A6, A17
   and B2.16 now rely on (M1–M4):

   | entry | node itself (non-root) | same-uid other | root + `CAP_SYS_PTRACE` | root without `CAP_SYS_PTRACE` |
   |---|---|---|---|---|
   | `stat`, `status`, `cmdline`, `limits`, `cgroup`, `mountinfo`, `task/*/{stat,status,comm}` | read | read (`stat` 190 B, not 325 B: `kstkeip`, `kstkesp`, `wchan`, code and data addresses zeroed) | read | read (`stat` reduced) |
   | `environ`, `io`, `auxv`, `personality` | refused | refused | read | refused |
   | `stack`, `syscall` (also per task) | refused | refused | read | refused (EPERM) |
   | `wchan` | `0` | `0` | real value | `0` |
   | `maps`, `smaps_rollup` | read | refused | read | refused |
   | `mem` | refused | refused | EIO at offset 0 | refused |
   | `fd/` (list) | read | refused | read | read |
   | `fdinfo/`, `cwd`/`exe`/`root`, `ns/*` | read | refused | read | refused |
   | `timerslack_ns` | read | refused (EPERM) | read | read |

   The directory `/proc/<pid>` stays owned by the task's euid (only the
   files inside become root-owned), so no check may use its owner (M1).
   **Still to measure** (each a test in item 5 when the host exists): the
   same matrix on macOS (where `/proc` does not exist and the A5 macOS
   path applies), on kernels other than 5.15, inside an LXC container
   with the friend's capability set, and with `ptrace_scope` 0 and 2; a
   **dumpable** node (pre-D5 build) read by a same-uid reader; whether a
   non-root node reading a **sleeping** sibling thread's
   `/proc/self/task/<tid>/wchan` gets `0` (the probe read only the
   reading thread itself, which was running, so its `0` is expected on
   any kernel and shows nothing about hiding; the probe gains a second
   thread parked in `nanosleep` (state `S`) and a third blocked on a pipe
   read, each read by the node itself as non-root and by root with
   `CAP_SYS_PTRACE`, N3); the longest real `wallet-rescan` and `staking`
   phases on the reference Pi, against the K4 15-minute spin bound; the
   cost of the A10 every-offset match with the r10 tag (one rolling R_b
   step and one 8-byte SipHash-2-4 per offset, S3, N1) over 50 MB of text
   and 20 secrets, with the four decoded views, on the reference Pi, which
   must fit B5's bound (R2; a miss is a blocker for A10 (a), with no
   prefix-tag fallback, N1); a stack-signal soak (F3, P5): an A17 sweep every 10 s for an
   hour under regtest sync and RPC load, and again through a
   `wallet-rescan`, plus one sweep during a RocksDB compaction and one
   while a thread is blocked in a socket read, with no `Interrupted`
   error in any log, no A4 exit, and the B2 consistency checks unchanged; that the in-process fallbacks (`getrusage`
   I/O, the `fd/` count, `std::env::vars_os`) give the same figures as a
   root `CAP_SYS_PTRACE` reading; the `FDSize` bound the A6 probe uses
   against the highest open fd; and the time `listunspent` with a
   one-address filter takes on a 10,000-transaction wallet on the
   reference Pi (B6.5, V1; the refusal stays until it is under 2 s).
2. **Part A** in this order: A9 `die` and R3 codes; A1 `runs.log`; A2 marker
   and verdicts; A3 signals; A4 panics and task supervision; A8 log delivery
   and the debug ring; A5 crash handler; A6 health; A7 start-up record; A11
   redaction at the source (before A12 and A15 write anything), with its
   O1 log changes (own blocks log like peer blocks, staker default-deny); A12 events
   and incidents; A15 RPC methods; A17 lock waits and watchdog; A13 replay
   bundles; A10 `getdiaginfo`, except that A10 (a), the environment-page
   tag, waits for B5's budget measurement, which is built and run first
   because there is no prefix-tag fallback (adversarial N1); A14 budget
   and mirrors; A16 release symbols;
   A18 flags.
3. **Part B**: B1 discovery and B1.4 `contrib/diag.sh`; B2 collectors; §6
   redaction and scanner with the canary tests; §8 preview and consent; B4
   platform backends; B3 observed start; B5 budgets; B6 recording modes.
4. **Receiver** (§9), once the hosting decision is made; until then §8.4's
   offline path works.
5. **Tests on hp1**, each producing a package and checked against its
   §7.1 row by a script (the row's named files must be present and must
   name the cause):
   - an LXC container with a 512 MB limit and the node syncing (cgroup OOM);
   - `kill -9` from another shell, from the host, and from a container stop;
   - the `crashtest` feature: SEGV on the main thread, on a tokio thread, a
     stack overflow on a Rust thread (exit 134) and on a RocksDB thread
     (exit 139), an abort, a panic in a critical task, an allocation
     failure (`alloc-null` record, then exit 134), a seccomp
     `KILL_PROCESS` (exit 159, marker, audit line when `actions_logged`
     allows it) and a seccomp `KILL_THREAD` (A17 vanished-thread record
     plus the audit line);
   - a forced hang (test feature holding the wallet lock 90 s);
   - a start-up stall (test feature blocking one phase past the A1 bound)
     **with** `-startuptimeout=60`: A17 incident with five thread-state
     samples (a `wchan` of `0` written `hidden` for a thread in `S` or
     `D` and `running` for `R`, N3) and the blocked thread's stack
     present — the test feature blocks it in state `S` (a lock or a
     sleep), so the signal reaches it (K2) — then exit 10;
     the same stall **without** the flag: the incident and an events.log
     line, and the node is still running afterwards;
   - X1: a test feature blocking the `staking` phase while the node syncs
     from a regtest peer (so block download, P2P threads and RocksDB
     writes keep CPU and I/O busy): the start-up bound still runs out and
     the incident names `staking`; the same with a blocked `network`
     phase;
   - K1: a start-up stall with `-startuptimeout=60` in which one thread is
     blocked reading a file on a device-mapper disk under `dmsetup
     suspend` (state `D`) and another has the stack signal blocked with
     `pthread_sigmask`: the incident is written within 2 s of the sweep
     starting, names the first `no stack: state D` and the second `no
     stack: signal blocked`, holds the other threads' stacks, and the node
     exits 10; a test seam that delays one handler past 200 ms gives `no
     stack: no answer in 200 ms`, and that handler's late output is
     discarded (its claim fails on the ABANDONED slot), not written into
     the next incident; the same seam firing after the slot is claimed
     gives `no stack: torn`, that slot is not reused until the handler
     finishes, and the next incident is intact (F2);
   - K4: a test feature that spins the start-up thread on CPU inside the
     `staking` phase for 16 minutes: one A17 incident and one
     `events.log` line `start-up phase staking running 15 min` at 15
     minutes, no second one for that phase, and the node still running,
     without `-startuptimeout` and with `-startuptimeout=1800`; with
     `-startuptimeout=300` the line reads `running 5 min` and comes at 5
     minutes (F1);
   - crashes N1: the same K4 spin in a start-up phase polled by
     `block_on` on the main thread (`main.rs:3195`) gives a stack for the
     main thread in the incident on every Linux family, and the A5 table
     shows a 64 KB alternate stack for it, installed at the top of
     `main()`; std's own main-thread stack size is read and recorded
     (to verify the reviewers' 8 KB / 16 KB reading);
   - F1: the same spin run as an observed start (`diag --run`) leaves an
     incident holding the spinning thread's stack, followed by the TERM
     (and, if needed, KILL) records with the snapshot request and its
     result beside each; with the request file made unwritable, the
     incident comes from SIGQUIT;
   - F3, P5: the stack signal's number is read at run time and recorded
     in the A7 start record, and a test that takes that signal first sees
     the node pick the next free one; on each gnu target a RocksDB thread,
     started inside libstdc++ and reached through the interposed
     `pthread_create`, has an alternate stack and gives a stack; on musl
     the same through `--wrap`; a thread with no alternate stack is
     recorded `no stack: no alternate stack`, marked expected or
     unexpected, and is not signalled (R9-1, R9-2, below); on macOS a test seam
     that hangs the helper thread gives `no stack: helper did not return`
     and the target thread is resumed;
   - a stop request during start-up: exit 0 at the next phase boundary,
     pid file and marker removed, and **no** `unclean-previous` at the
     next start;
   - a stop request during a long `wallet-rescan` (regtest wallet with
     200,000 transactions) and during a long `chain-load`: the node exits
     0 within one progress record or rescan batch, well inside systemd's
     default 90 s stop timeout, with no SIGKILL;
   - the A1 start-up bound with the Part A threads busy (a test feature
     making the writer and watchdog threads spin and write) while the
     start-up phase itself is blocked: the bound still runs out, because
     Part A's CPU and writes do not count as progress;
   - a slow `DB::open` on a throttled device (dm-delay, or cgroup `io.max`
     at a few hundred KB/s) taking longer than the bound: the I/O and CPU
     counts keep it from being a stall, and the node is not killed even
     with `-startuptimeout`;
   - a start-up stall on a data dir that hangs (`dmsetup suspend`, or a
     FUSE filesystem that never answers) with `-startuptimeout`: the
     incident and the exit record are in the A14 mirror, whether or not
     the process has been reaped;
   - `docker pause` of the node for 2 minutes, then `unpause`: A17 records
     "process not scheduled N s (stopped or frozen)" and writes no hang
     incident; `SIGSTOP` for 2 minutes, then `SIGCONT`: the A3 `CONT`
     record makes it "stopped, SIGCONT from <sender>"; a cgroup frozen
     and thawed between two wakes is never called "frozen" from a
     post-hoc read;
   - on a cgroup v1 host with no cgroup PSI, a memory hog **outside**
     the node's cgroup: the system-wide PSI stall gives "cause
     uncertain", never "starved";
   - the node under `cpu.max` at 5 % plus a memory hog in the same
     cgroup: A17 records "starved" with the throttle and stall deltas,
     never "frozen", and a forced hang during the starvation is still
     reported;
   - `-daemon`: the grandchild's `/proc/<pid>/task/*/comm` lists the
     Part A writer and watchdog threads, the parents have none before the
     fork, and the grandchild's start record reaches `runs.log`;
   - a forced hang on the Mac: the A17 incident holds a stack for each
     thread;
   - a partial hang: a test feature blocking one JSON-RPC handler (and,
     separately, filling the `spawn_blocking` pool) for 120 s while the
     runtime and the health tick keep running: after 60 s the in-flight
     trigger writes an incident holding the stuck call's method, transport
     and age and the handler thread's stack; the same item writes no
     second incident within 10 minutes; a stalled health tick with a live
     runtime, and a stalled runtime with a live health tick, each write
     an incident;
   - X3 per-class budgets: a client keeping 30 distinct slow calls
     running and a script creating a snapshot request every second for an
     hour use up the in-flight and snapshot budgets (`incident budget
     exhausted for in-flight` and `… for snapshot` each written once to
     `events.log`), and a whole-node hang caused afterwards (the wallet
     lock held 90 s, and separately the health tick stalled) still writes
     its incident; diag's next snapshot request reports "snapshot
     refused: budget";
   - the snapshot request: with the node D5 and RPC blocked, a non-root
     diag of the node's user creates `diag/snapshot-request` and gets an
     incident within 2 s, taken from the mirror while the data-dir disk
     is suspended (`dmsetup suspend`); a request file owned by another
     uid is ignored; ten requests in 5 s give one incident (the 10 s
     rule), and a 21st request in a day gives none and the `events.log`
     budget line; with the disk suspended, ten more requests leave one
     stuck helper (the node's thread count does not grow), the mirror
     incidents record `data-dir helper busy since <t>`, and each distinct
     request is answered once (X3);
   - L2: the same with `mirror-same-fs=yes` (one filesystem only): the
     watchdog keeps its 1 s wake and writes `events.log` lines while the
     disk is suspended, because both copies are checked through the
     helper;
   - V7: diag's snapshot request with the data-dir disk suspended: diag
     writes the mirror copy, finishes within its B5 limits, reads the
     incident from the mirror, and leaves at most one detached thread
     blocked; the node's thread count does not grow;
   - the incident of every trigger (hang, in-flight, snapshot request,
     start-up bound) holds no environment value and no `known_values`
     entry, with a secret-named and a canary environment variable set;
   - `scripts/tests/core-dump.sh` after A5: **one** `kill -SEGV` ends the
     node, `crash.log` has the record with `sent=yes` and the sender's
     comm, and the A2/B2.14 verdict reads "sent by `<comm>`";
   - the D5 flag re-check (X2): a test build that calls
     `prctl(PR_SET_DUMPABLE, 1)` has the flag back at 0 by the next health
     tick and an `events.log` line `dumpable restored (was 1)`. (r6 used a
     `setresuid` to the same uid, which does not change any id, so
     `commit_creds` leaves the flag alone and the test proved nothing.)
     The lint (`bin/irondivid/tests/credential_calls_lint.rs`, done in
     97c4bceb) fails on a new call site of any of the ten credential calls
     (`setuid`, `setgid`, `setresuid`, `setresgid`, `setreuid`,
     `setregid`, `setfsuid`, `setfsgid`, `capset`, `setgroups`, in their
     bare, `libc::` and `nix::unistd::` spellings) or of `caps::set`,
     `caps::raise`, `caps::drop` or `caps::clear` under `bin/`, `crates/`
     or `tools/` that is not followed by `PR_SET_DUMPABLE` in the same
     function, and its matcher self-test passes;
   - non-dumpable node (D5) with a non-root diag: the readability check
     fires before any ptrace-checked read, no `wchan` of `0` and no zeroed
     `stat` stack field appears anywhere in the package, the refused
     `/proc/<pid>` reads are recorded once as `unreadable: node is
     non-dumpable`, the same figures arrive through `getdiaginfo`, and a
     hung node's thread states come from the A17 incident; the B2.16
     visibility matrix marks `wchan`, `stack`, `syscall`, `io`, `maps`,
     `smaps_rollup`, `fd/`, `environ` and the links `hidden by kernel`
     and names the source used instead, and diag's `CapEff` is recorded
     (M4); the readability check fires when the open of `io` succeeds but
     the first `read` fails (a test seam returning EACCES on read, V6);
     the environment canary is masked using the `known_values` HMAC and
     length alone (P3); with the node
     hung (RPC not answering), the summary states that environment values
     were not available for matching;
   - a crash of a D5 node under systemd-coredump: `coredumpctl` has no
     entry, and diag's crash verdict still comes from `crash.log`, the
     `runs.log` exit record and the unit's `ExecMainStatus`;
   - a systemd-coredump journal entry for an older, dumpable irondivid whose
     `COREDUMP_CMDLINE` holds `-rpcpassword=<canary>` and whose host name,
     unit and cgroup are canaries: only signal, time, size and reduced
     frames reach the package, and no canary does;
   - a D5 node started with a relative `-datadir` and `-conf` from a
     directory the shell has since left: a non-root diag finds the data
     dir and conf from the A14 path record; with the record removed, from
     `/proc/<pid>/cwd` as root with `CAP_SYS_PTRACE`; with neither, diag
     says it cannot find the data dir and does **not** use the default
     one; a stale record (pid reused, start time different) is ignored;
   - root inside a default Docker container (no `CAP_SYS_PTRACE`): diag
     records `unreadable ... no CAP_SYS_PTRACE` and prints no `sudo`
     hint; a non-root diag on a host where `sudo` gives the capability
     gets the hint;
   - B3.3 live attach on a D5 node: `eu-stack`/`gdb -p` as a non-root
     user is refused and diag says so and does not offer it; as root
     with `CAP_SYS_PTRACE` it works; `strace -f` started by diag as the
     node's parent (B3.2) works on a D5 node;
   - the A6 fd count: the node's own `fd/` list (readable to it under D5,
     §10 item 1) equals the root `ls /proc/<pid>/fd` count; the `F_GETFD`
     probe, kept as a fallback for a kernel that refuses `fd/`, is tested
     through a test seam that makes `fd/` fail, and records its `FDSize`
     bound;
   - B2 pid namespace versus container (V4): a node under systemd
     `PrivatePIDs=yes`, and one started with `unshare --pid --fork`, both
     D5: recorded as `node in another pid namespace` and **not** declared
     a container; B2.7–B2.10, B2.16 and B3 run normally; a node in Docker
     and one in LXC are declared containers, and the record names the
     signal that decided;
   - N1: a host node running as another user with a 0700 data dir, held
     in start-up before its RPC binds (a test feature), and the same node
     under SIGSTOP: signal (5) is recorded as a fact, the node is **not**
     declared a container, B3, B2.16 and B2.7–B2.10 run (each failing
     step marked with its own error), and the summary prints both the
     `sudo -u <node user>` hint and the container hint;
   - N2, W4: a host node on a Raspberry Pi with `overlayroot`, on a
     live-USB system and on Fedora CoreOS (overlay roots all) is **not**
     declared a container, because its root mount line matches diag's
     by `major:minor` and root; a node under systemd `RootDirectory=` is
     declared one by signal 4; so is a node in a plain `chroot` into a
     directory that is not a mount point (no `/` line, P1), and a node
     with a second mount over `/` is judged by the last `/` line (P1);
     for such a node, sharing diag's network namespace, B2.16 runs while
     B3 and B2.7–B2.10 are `SKIPPED: root differs (signal 4)` (P2);
   - N5: a node in a systemd-nspawn container (`machine-<name>.scope`) is
     declared a container and the summary prints `machinectl shell
     <name>`; a node placed by a test in a cgroup directly under
     `machine.slice` (no `machine-*.scope`, no `lxc`, `libpod` or
     `docker`) is not declared one by signal 3; a libvirt-LXC container
     (`machine-lxc\x2d<id>\x2d<name>.scope`) is declared one, not as
     nspawn, and the summary prints the unescaped `<name>` in `virsh -c
     lxc:/// lxc-enter-namespace <name>`; a node whose uid has no
     passwd entry gets `sudo -u '#<uid>'` (P3);
   - L1: after the Docker run, `docker exec <c> test -e` finds neither
     `/dev/shm/irondivi-diag` nor the copied CLI; the `--import -` path
     leaves no unredacted file on the host; the shell-archive fallback's
     folder is mode 0700 and gone after the import;
   - L3: the binary replaced on disk while the node runs (a package
     upgrade without a restart): B1.2 reports "running binary differs
     from the file on disk" and the A14 record's SHA-256 is the running
     image's;
   - L4: a hang during a run with diag's `strace -f` attached: diag
     tries no `eu-stack`/`gdb -p`, records `live attach skipped: strace
     attached`, and the stacks come from the A17 snapshot;
   - M4: B3.3 and B2.16 as root without `CAP_SYS_PTRACE` (`capsh
     --drop=cap_sys_ptrace`): the matrix matches the non-root one except
     that `fd/` is `read` and the open fd count is present (N4), while
     `fdinfo/` and the `fd/*` links are `hidden by kernel`,
     `CapEff` is recorded, and kernel stacks and syscall state come from
     the A17 snapshot;
   - SIGTSTP sent to a `-daemon` node (no controlling tty): recorded and
     ignored, the node keeps running;
   - `-sign-snapshot` without `-daemon` reads its key from stdin;
     `-daemon` reopens stdin on /dev/null instead of closing it;
     `-daemon -sign-snapshot` is refused with exit 2;
   - the WSL boot-id case: a WSL 2 restart gives the WSL verdict, not
     "machine rebooted" (A2);
   - a full disk (small loop filesystem), a read-only remount;
   - diag writing to a nearly full loop filesystem that is also a data
     dir's: the R1 (a) rule moves the output or stops, and the node's
     filesystem never drops below the R1 (a) floor;
   - a data dir owned by another user; a held lock;
   - an invalid block on regtest (A13 bundle replays with `irondivi-replay`);
   - D1 (SSH drop, then SIGTERM) and D2 (closed stdout);
   - the canary tests of §6.3, all five variants, including the
     environment and `k=v` canaries and canary (e) in an imported
     `runs.log`;
   - the A10 `diag_key` is found in no file of the package, `diag.log`
     or any Part A file, in any §6.3 encoding;
   - a regtest wallet with 200,000 transactions, node under a 512 MB cgroup:
     §6.2 step 1 reads `known_values` pages, stops at its memory, latency
     or 60 s limit, the summary says the set is incomplete, and the node
     is not OOM-killed;
   - A15 under 10 requests a second for a simulated 30 days (fake clock):
     the cap holds and day 30's hourly aggregates are still present;
   - A15 under a public-server load for a simulated 30 days (fake clock):
     5,000 distinct remote Electrum callers an hour, 100 errors a second
     and 50 active methods: `rpc-methods.log` stays within its 2 MB,
     per-call lines from day 11 back are still present at this load, and
     the hourly aggregates reach back 14 days;
   - a collector pushed past its memory cap (test collector allocating in
     a loop) on Linux with and without a cgroup, as root through
     `systemd-run --scope`, on a pre-4.7 kernel with no usable cgroup
     (CentOS 7: the `statm` poll), and on macOS: recorded as `MEMORY CAP`,
     not as a crash, diag goes on, and `diag.log` names the mechanism;
   - B2.8 free memory inside a 1 GB cgroup on a host with plenty free:
     the figure is the cgroup's headroom (v2 and v1), not `MemAvailable`;
     a v2 `memory.max` of `max` and a v1 limit at `PAGE_COUNTER_MAX` read
     as "no limit"; a 1 GB limit on an ancestor cgroup with `max` on the
     node's own is found (the minimum over the ancestors);
   - a transaction submitted with `sendrawtransaction` by a local caller and
     rejected lands in `diag/own-invalid/`, not in `chain-events.log`;
   - a canary written into `<datadir>/wallet/LOG` and a file named after a
     canary in `<datadir>/wallet/`: B2.7 shows only the directory's total
     size and file count (no names, sizes or mtimes; chain RocksDB
     `OPTIONS-*` still in full), and neither canary is in the package;
   - `--tx` on a regtest send with change: the §8.2 text names the change
     output and the funding transactions, the package holds exactly those,
     and labels stay pseudonymised;
   - Docker Desktop on the Mac without the alpine image: diag asks before
     the pull, and "no" or `--offline` prints the commands only;
   - `contrib/diag.sh` under `busybox sh` and `dash`, then `--import`;
   - macOS on the Mac (a real jetsam kill forced with
     `memorystatus_control` on a test build, checking the A2 jetsam verdict
     from the unified-log line; if the call is not allowed without SIP
     changes, the jetsam verdict is stated as untested in the release
     notes and only the "none of the above" fallback after `kill -9` is
     tested; Gatekeeper by a
     quarantined copy; TCC by a data dir under `~/Documents` with the
     terminal lacking Full Disk Access), including the A6 macOS health
     fields, B2.16 via `sample` with the `/proc` items "n/a (macOS)", the
     B2.8 free-memory figure from `vm_stat`, and the memory-cap kill by the
     parent;
   - a collector stuck in `D` state (a FUSE filesystem that never answers):
     `ABANDONED` recorded, diag finishes;
   - the node under `SIGSTOP`, under a frozen cgroup, and under `strace`:
     B2.16 names each state and diag sends no signal;
   - B3.1 refusals: a systemd unit with `Restart=`, a supervise-daemon, a
     runit/s6 service, supervisord, pm2, a cron `@reboot` line, a watchdog
     script naming irondivi;
   - diag outside a Docker and an LXC container: collects host-side data,
     refuses only B3 and the node-namespace collectors, records which
     signal decided, and prints the exec command; then `contrib/diag.sh`
     fed on stdin to `docker exec -i` in a container with a read-only
     root filesystem (and `/dev/shm` mounted `noexec` or absent), its
     output streamed out with `tar` and imported with `--import`, and
     the shell-archive fallback when the image has no `tar`; the
     `irondivi-cli` copy placed in the data volume when the image has
     none; and a distroless image (no shell: diag reports it and prints
     the host-side steps);
   - the B2.9 unlinkability test (A10 section on a known regtest wallet);
   - `--rpc` (redacted answer shown before consent, state-changing method
     refused, `--rpc dumpprivkey` and `--rpc dumphdinfo` refused by name,
     every method outside the allowlist refused, amounts bucketed and
     wallet values pseudonymised, `--rpc-clear` refused outside the
     allowlist) and `--attach` (scanner hit on a canary in the attached
     file stops packaging; an attached `pct config` with a canary host,
     storage and bridge name has all three pseudonymised);
   - each §8.4 upload failure: unreachable host, clock a year off, a
     MITM proxy with its own root (pin mismatch reported as `TLS
     intercepted`), receiver refusing, fallback receiver used;
   - the receiver is not contacted before `yes`: a full run with a
     capture of outgoing connections shows only the seed probes until
     the user answers, and none at all after `no` or `--offline`;
   - `contrib/diag.sh` contains no key (a grep for the `age1` recipient
     and the fingerprint) and has no pack, encrypt or upload path;
   - `--rpc` argument caps: `--rpc listtransactions "*" 1000000` is
     clamped to 1000 and shown as clamped; `listsinceblock` too far below
     the tip, `getblock` verbosity 2, verbose `getrawmempool` above 5,000
     entries and `getmasternodewinners` above 100 are clamped or refused;
     a call past 2 s is reported "slow: stopped waiting";
   - each method removed from the B6.5 allowlist (`gettxoutsetinfo`,
     `getaddressbalance`, `getaddressutxos`) gives one refusal line naming
     the reason and the L10 "run it yourself and `--attach`" text;
     `listunspent` on a wallet above 10,000 transactions is refused with
     and without the third argument (the address array), and the refusal
     names the L10 "run it yourself and `--attach`" text with the full
     command line `irondivi-cli diag --attach <file> --attach-method
     listunspent` (V1, D1);
   - attached RPC answers (C1, C2, V3): the §6.3 attached-answer canaries
     pass; an attached `getaddressutxos` file is listed as "treated as RPC
     output: getaddressutxos" without `--attach-method`; a JSON file of
     no known shape gets "JSON of unknown origin; script keys and hash
     backstop applied", still loses its `script` and hash160 canaries,
     and keeps its plain integers (a pid, an exit code, a port); an
     attached `docker inspect` is handled by its own format rules, not as
     an RPC answer; an attached `docker events` and `podman events` file
     keeps `time` and `timeNano` while its container names are masked
     (P4); an attached public `getblock` at verbosity 2 keeps its
     block-level `hash`, `height` and `time`, while each transaction entry
     loses `time`, `blocktime`, `confirmations` and `blockhash` (E2); the
     Revision 9 canaries in §6.3 pass (E1, S1, X2, S2, X1, S4);
   - D1, R3, K5, W1: the §6.3 attached-wallet-answer canaries pass;
     attached `listunspent`, `listtransactions`, `listsinceblock`,
     `gettransaction` and `getwalletinfo` answers are each listed as
     "treated as RPC output: <method>" without `--attach-method`; a
     `getbalance` answer is treated as one only with it; a `listunspent`
     answer attached with `--attach-method getblock` still has its
     amounts and confirmations bucketed and its `account` and
     `redeemScript` dropped; an unknown-shape JSON file loses its
     `amount`, `confirmations`, `height` and `time` values by key name and
     keeps its `pid`, `port` and `exit_code`;
   - every method on the extended B6.5 allowlist runs on regtest and its
     redacted answer passes the scanner;
   - `--rpc getdiaginfo` with `diag_key` or `known_values` refused by
     name, and `--rpc-clear getdiaginfo` refused;
   - B6.5 field handling on a regtest wallet: `label`, `account`,
     `comment`, `to`, `hdmasterkeyid` and `hdchainid` dropped (also under
     `--rpc-clear`); `confirmations` bucketed; `blockhash`, `blockheight`,
     `blockindex`, `time`, `timereceived`, `blocktime` dropped;
     `getmintinginfo` weights shown as one ratio bucket and `expectedtime`
     bucketed;
   - `--rpc-clear` on an answer with 30 items states the counts in its
     question; on one with 101 it is refused and points to `--tx`;
   - public-list ownership (§6.2 "Public records"): with the user's own
     masternode in `listmasternodes` and the winners, an own-staked tip in
     the A12 reorg and tip lines and an A13 header, and an own transaction
     in `getrawmempool`, the own entry cannot be told from the others in
     any file, and no public pseudonym equals a wallet-side pseudonym;
   - A6 stake count as a bucket only, and A12 stake-found events reduced
     to weekly bucketed counts in the package (no hash, height or time);
   - a pre-A10 node (0.2.9): step 1 uses `listaccounts`,
     `getaddressesbyaccount`, `listreceivedbyaddress`, `listunspent`,
     `listlockunspent` and `getmasternodestatus`, never answers "method
     not found", and the canary label is masked in a component log and in
     `01-user-report.txt`;
   - the realistic environment canary (§6.3): the canary is gone and
     `PATH`, `LANG` and `TERM` values survive in the logs;
   - the R3 code 2/3 canary: a malformed `-rpcpassword=<canary>` and a
     malformed config line with a canary give reasons naming the key and
     line number only, and the canary is in neither `runs.log`, the
     mirror, nor `_unresolved/`;
   - an apport report with a canary local in `Stacktrace`: only
     `StacktraceTop` frames reach the package (and `coredumpctl info` and
     `.ips` reduced to address, function and module);
   - attached and imported logs with a bare canary host name in the
     syslog and journal hostname column, a Windows event `Computer` and
     `MachineName`, `C:\Users\<canary>` and a `\\wsl$\<canary>` path in
     PowerShell output, and `docker info` `Name: <canary>`: all masked;
   - rule (b): a pre-A11 `mempool.rs:736` line, a pre-09cb18e4
     `main.rs:2345` "submitted to mempool" line and a `main.rs:1719`
     "cannot be resubmitted" line have their txid, label and amount
     masked; an ordinary `irondivid` start-up line is untouched; a
     `divi_rpc` "port 51473" and an error `code -32603` keep their
     numbers; the A11 test fails when an edit site's target is removed
     from the list;
   - `diag/sent-txids`: created mode 0600, capped at 1 MB, never in the
     package, and a package with a copied line from it is refused by
     §6.3; step 1 reads it when the node is down;
   - `-logwalletdetail=1`: `setlogconfig` refuses to turn it on at run
     time and the refusal is in `events.log`; that run's `runs.log`,
     `crash.log` and `events.log` mirror copies get the old-log rule,
     matched by run id;
   - canary paths and `--rpc` arguments in `diag.log` and
     `00-SUMMARY.txt`: masked in the packaged copies, shown in clear on
     the terminal;
   - every per-call A10 key `k` and the public-record salt are in no
     file of the package, `diag.log` or any Part A file, in any §6.3
     encoding;
   - B6.5 scripts on a regtest wallet with P2PKH, P2SH and multisig
     outputs: `scriptPubKey` `hex` and `asm`, `redeemScript`, `scriptSig`
     `hex` and `asm`, `script` and `addresses` from `listunspent`,
     `getrawtransaction` verbose, `decoderawtransaction` and `getblock`
     verbosity 2 are dropped or masked, and the address canary and its
     hash160 canary are in no file; a build-id and a SHA-256 in `diag.log`
     are untouched (the hash160 backstop applies to B6.5 answers and
     attached RPC answers only, never to diag's own log or other files);
   - every script and raw-transaction key (`hex`, `asm`, `redeemScript`,
     `script`, `scriptSig`, a string `scriptPubKey`) is dropped from
     `gettransaction`, `getrawtransaction` verbose, `decoderawtransaction`
     and `listunspent` answers, also under `--rpc-clear`, where the clear
     `address` field is still present (P1);
   - own staked blocks (P2): `--rpc getblock`, `getblockheader` and
     `getblockhash` on a block the regtest wallet staked: every field but
     `version`, the size class and `nTx` absent (R1: each field the §6.3
     canary names, at verbosity 1 and 2), the block's other txids
     pseudonymised, the hash or height argument absent from the call line
     and `diag.log`, the screen note shown; the same calls on a block it did not stake are in clear;
   - B1, Y3: a regtest `debug.log` in which the wallet staked a block: in
     the package the "Connected block" line shows that hash in clear like
     every other block's, and the staker's "Staked block … (reward: …)"
     and "Self-accepted staked block" lines are absent from their place
     and appear only as weekly bucketed counts;
   - O1 differential: the test node and three other regtest nodes, so
     the own block goes out to at least 3 peers, the test node staking
     one block among blocks the others stake, with no bootstrap import in
     the run (`crates/divi-node/src/block_import.rs:213` gains the shared
     Connected line with A11 item 1; a separate run imports a bootstrap
     and checks it), once at the default level, once at `-debug=net` and
     once at `-debug` (privacy R12-1). (1) In
     the raw `debug.log` the "Connected block" heights run with no gap, and none of the formats the A11 change removes
     (`staker.rs:797`, `:812`, `:828`, `main.rs:2167`, `:2173`,
     `peer_manager.rs:1071`, `:1091`, `sync.rs:1499`) appears. (2) In the
     package no line names the own stake: its hash appears only in the
     shared Connected line and the chain lines, as every block's does.
     (3) The set of line formats (format strings, values ignored) between
     the previous and the next Connected line around the own block
     equals the set around a peer block, compared over the package, where
     the counted-list formats are already removed; the raw log is not the
     place to compare, since a peer-only line such as `sync.rs:1240` cannot
     be written for a block no peer sent. The count of each counted-list
     format (per command for per-message lines), read from the package's
     buckets (and, for the sites counted in the node, from its hourly
     count lines), is the same for the week of the own block as for a run
     with peer blocks only, up to the bucket. (4) Wallet blocks, at `-debug`: a peer block that pays
     the test wallet, a peer block that spends from it, and the own stake,
     each compared with an unrelated peer block. Between the previous and
     the next Connected line, the package shows the same number of lines
     and the same timestamps relative to the Connected line (to the
     millisecond, within the spread of the unrelated blocks); no
     `wallet_db.rs:2835` "Received", `:2849`, `:1749`, `:1767`, `:2159`,
     `:2928`, `:1364` "Wallet incremental save complete", `mempool.rs:581`,
     `:627` or `:736` line appears there, and the raw `debug.log` has none
     of them either, only their hourly count lines. The same four checks
     run with a test seam forcing a reorganisation during self-accept (the old
     `staker.rs:797` path) and one forcing the self-accept to fail (the
     old `:828` path). The time from each block's header time to its
     Connected line is recorded for own and peer blocks (to measure; A11
     "Own blocks log like peer blocks" item 7), with the clock state at
     each sample (`timedatectl` "System clock synchronized", or the
     `adjtimex` status without `STA_UNSYNC`); samples taken before the
     first sync are dropped, since a Pi has no real-time clock and jumps
     at its first sync (platforms R11-3). These regtest samples have no
     network delay and never count toward the A11 item 7 gate, which is
     measured with real delay (the T1 test below); until it passes, rule
     (e) applies to every log. (5) Log copies (consensus B4, adversarial
     AB1): within the debug-ring window of the own stake (4096 lines) the
     run takes a SIGUSR1 incident and a `getdiaginfo`, does the same
     around a peer block, and at the end forces a crash record through a
     test seam; the package keeps `crash.log` and every incident (the
     §6.3 scan leaves none out), and checks (1) to (4) pass over their
     ring sections, the incident `debug.log` tails, the `getdiaginfo`
     ring and the A14 mirror copies, with no counted-list line and no
     Connected line in place in any of them, and no `counted`-tagged line
     in the raw ring copies. The same run on a node
     without the change: the package keeps no per-block line, has no
     staker success line, and the §8.3 summary says so;
   - Sync-state release gate (adversarial AC1, privacy N1, consensus
     N-g): in the same O1 differential runs, at the default level,
     `-debug=net` and `-debug`, the raw `debug.log` of the synced test
     node holds none of `sync.rs:1364` "Block sync complete", `:986`
     "Header sync complete" (info), `:1368` "Exiting IBD mode", `:1628`
     "Sync progress" or `:1645` "Sync stalled" (warn) from the previous
     to the next Connected line around the own stake and around the peer
     block, read both from `debug.log` and through a tracing capture
     layer installed in the test node (adversarial r14 note 3), and the
     package's weekly tally of the five is 0 for those weeks; the one
     named exception is `:546` "restarting sync", written when a peer
     that is ahead connects (A11 item 6), which the gate reports but does
     not fail on; a run that holds the test
     node 7 blocks behind and lets it catch up writes "Block sync
     complete" once and a tally of 1. A sync-state line near an own stake
     fails the release. The debug "Sync stalled" (`:1650`) is counted and
     checked by (3) like other counted lines; a node reaching the tip
     through an empty headers reply after a far lag, and through
     `start()`, writes no "Block sync complete" on a later peer block
     (73440b48). Stall (consensus N-i): a regtest peer that claims a tip
     3 blocks ahead and never serves the blocks gives an A12 stall
     record after 2 minutes and an incident after 10, with the lag in
     both, although the node never leaves the lag window;
   - privacy R14-1 own-transaction canary (it keeps the R13-1 txid
     linkage checks): on regtest with the test node and at least 3 peers,
     at the default level, `-debug` and `-debug=net`, the test wallet
     sends with `sendtoaddress`, `sendrawtransaction` and `sendmany`,
     receives one transaction from another node, and is restarted with
     one unconfirmed wallet transaction so that `resubmit_wallet_txs`
     announces it; peers also send transactions of their own that the
     test node relays. Every line is read through a tracing capture layer
     installed in the test node as well as from `debug.log` and every
     package input (ring copies, incidents, `getdiaginfo`, `crash.log`).
     For each own transaction and each peer transaction, the test takes
     the sequence of log formats written from its submit or arrival to
     its relay (with the txid, the peer and every number blanked) and
     asserts the sequences, the count of each format and their order are
     the same for both, with no count split by origin or per peer in the
     hourly lines or the package; only the named start-up count lines
     (A11 "Own transactions log like peer transactions") and the
     own-only `divi-rpc wallet.rs` lines, which must be counted and never
     appear in place, are allowed to differ. As in R13-1, no txid
     pseudonym appears both in a wallet-transaction line and in any
     relay or mempool line, and no line written from a mempool listener
     closure appears in place, only its hourly count line
     (`wallet_db.rs:3098` "Mempool wallet tx" was removed in bf6452fc and
     must not reappear). No relay.rs tx-line format removed by 09cb18e4
     or 6de594fb appears in any package input, and no "RPC {method}"
     line (`divi-rpc server.rs:1578`, `:1424`) reaches a package input
     with the method name of a send RPC in clear (rule (b) masks it);
   - O1 staker lists: a staker run that stakes, fails a stake, is rate
     limited, meets a locked wallet and loses a self-accept to a
     reorganisation writes no staker line off the A11 allowlist in
     `debug.log`, and writes one count line per counted site every hour,
     zeros included;
   - T1 timing gate (platforms R12-1): a mainnet node with its normal
     peers records the time from header time to Connected line for at
     least 200 peer blocks, passively, and a staking testnet node whose
     peers are all off its LAN records at least 200 own and 200 peer
     blocks, each sample with the clock state as in the O1 differential;
     or, as the lab stand-in, hp1–hp3 with `tc netem` delays drawn from
     the mainnet distribution. A loopback or LAN-only run is refused as
     gate evidence. The A11 item 7 bound is computed from these samples;
     the expected result is a fail, which leaves rule (e) on for good;
   - privacy R12-2: `-walletnotify` and `-blocknotify` set to a failing
     command that holds a canary string; a payment, a peer block and an
     own stake are run; the canary and the txids appear in no file, the
     lines read "runCommand error: walletnotify (…)" and "runCommand
     error: blocknotify (…)", and the package carries them only as weekly
     buckets;
   - Y1: a regtest vault stake, once with the wallet holding the owner
     hash and once the vault hash, on an A10 node (reduced, from the
     pages) and on a LAN-only node (reduced, as undecided, since the
     fallback calls list no vault hashes); a block staked by another
     regtest wallet whose coinstake pays this wallet's masternode is in
     clear; and `getrawtransaction <prevout txid> 1` answers for the spent
     staked output (the B6.5 assumption), run four ways: with and without
     `-txindex`, and with the staked transaction in and not in the wallet;
     where it does not answer, the block is undecided and reduced
     (privacy P4);
   - Y2: with step 1's stop rule forced, a lookup of an own block is
     reduced; with the lookup budget exhausted through a test seam, the
     lookup is reduced and the summary gives the "<n> block lookups could
     not be checked" line; on a `-disablewallet` node no lookup is
     reduced and no warning is shown; the budget values (10 s a lookup,
     60 s a run) are measured here;
   - Y4: three consecutive heights looked up with the middle one own: all
     three are reduced, and none of their heights or hashes is in the
     call lines or `diag.log`;
   - Y5: when every lookup is reduced, the summary line points to
     `getmasternodewinners`, the A13 and A11 lines and `diag --tx`;
   - R9-1, R9-2: on each gnu target, a forced RocksDB write stall followed
     by an A17 sweep gives a stack for every `rocksdb:*` thread; a thread
     a test-only `.so` starts with a raw `clone` is not signalled and is
     recorded `no stack: no alternate stack`, marked unexpected (it keeps
     the name of the node thread that started it, which is why the mark
     is a hint); on musl the `rocksdb:*` threads have stacks through the
     wrap; on macOS, where A17 walks every thread and sends no signal,
     every `rocksdb:*` thread gives a stack, its range from
     `pthread_get_stackaddr_np`/`pthread_get_stacksize_np`, and a test
     thread whose range cannot be read is recorded `no stack: no stack
     range` (R10-1); the `crashtest` foreign-thread overflow on macOS
     still gives no A5 record (the thread has no alternate stack), and the
     test asserts exactly that;
   - R10-2, crashes N2: a test `.so` whose constructor starts a thread
     before `main()` runs: the thread is created through the lazily
     resolved real `pthread_create` and has an alternate stack; with a
     test seam making `dlsym` return null, and one making it return our
     own symbol, the process aborts with the fixed stderr message; with
     the stack allocation failing, the thread is still created and A17
     records it `no stack: alloc failed`; with the real call failing, its
     error is returned and the count of 64 KB mappings does not grow; on
     an i686 build `dlsym` resolves `pthread_create@GLIBC_2.1`, and in the
     ubuntu:20.04 image (glibc 2.31) it resolves the one in
     `libpthread.so.0`, each checked by starting a RocksDB thread and
     reading its stack;
   - crashes S1: a node with counted sites firing is stopped, killed with
     `SIGSEGV` from a test seam, hung into an A17 sweep, ended by a
     `die(10, …)` from a critical task failed through a test seam,
     panicked on the main thread (caught by `catch_unwind`, `_exit(101)`;
     the node exits rather than hangs, crashes R13-1), and sent three TERMs within
     5 s, each mid-hour (crashes R12-1); the pending counts appear in the
     stop-time count lines, the crash record, the incident, the `die()`
     and panic records and the third-TERM record, and the package's last
     weekly bucket includes each of them once; a SIGKILL mid-hour marks that week's
     buckets `partial` (platforms R12-3); a wall-clock step of an hour
     forward and one back during a counting hour neither drops nor
     doubles a count, and each count line carries its start and end wall
     times and the clock-synced flag (platforms R12-2); an A17 incident
     mid-hour followed by a normal hourly line, and a critical-task panic
     (A4 copy and `die()` copy), each give the package each count once
     (crashes R13-2); a suspend across an hour boundary (`rtcwake -m mem
     -s 600` on Linux, `pmset sleepnow` on macOS) writes the hour's line
     on the boot clock, and lines written before the first clock sync of
     a boot with no synced line after it land in `unplaced`, each with
     its boot ID (platforms R13-1, R13-2); in a container with `adjtimex`
     refused the flag reads `unknown` (platforms R13-3); a VM whose host
     sleeps across an hour boundary writes that hour flagged `stretched`,
     filed by its end time (platforms R14-1); a panic placed early in
     `async_main`, after the databases are open, writes the A4 record and
     exits with the RocksDB close bounded, the exit time recorded (to
     measure in §10; crashes R14-1);
   - AA3: a staker run that hits each `StakeResult::Error` path writes
     only reason codes from the closed set, counts per code, and one
     `events.log` transition (day only) into and out of "stake attempts
     failing: <code>"; no error text appears;
   - platforms R11-1: on macOS, a helper that starts and ends threads in a
     tight loop during 1,000 A17 sweeps; every thread is either walked
     inside its own range or recorded `no stack: thread exited`, and no
     sweep records an error;
   - crashes note 2: a thread that ends through `pthread_exit`, started
     and ended 10,000 times, leaves no growth in the count of 64 KB
     mappings;
   - crashes note 3: the alternate-stack headroom, measured with a guard
     pattern after each handler at its deepest (the A5 128-frame walk,
     the A17 handler, a nested fatal handler), leaves at least half of the
     64 KB untouched (to measure), on a tokio thread, a std thread (so a
     std change that installs its own, smaller stack in place of ours is
     caught, crashes N3), a RocksDB thread and the main thread (crashes
     N1);
   - B6.5 timing classes: the height canary (a wallet transaction at a
     known height) appears in no field (`height`, `spentHeight`,
     `bcconfirmations`, `confirmations` bucketed), and a block height on
     a public list stays;
   - B6.5 call arguments: an address passed to `--rpc` appears neither in
     the redacted answer nor in `diag.log` nor `00-SUMMARY.txt`;
   - N1: a crash with a canary on the stack (a 32-bit test build and a
     64-bit one): `crash.log` holds only frame addresses; the 32-bit
     `diag/crash-stack.bin` is mode 0600, is packaged only after the
     §8.2 "Raw stack words" consent, and with "no" it and the canary are
     absent; the §6.3 signing canary (a test key's bytes on the stack)
     is in no file without that consent;
   - A15 remote state changes: 100 remote `sendrawtransaction` broadcasts
     a second over Electrum for an hour: the remote cap holds, the lines
     are aggregated, and a local `stop` line from day 1 is still present;
   - V5: a **local** `sendtoaddress` flood (10 a second for a day from a
     loopback script): `send*` lines stop at 100 an hour with a "<n> more
     calls not listed" line, and a `stop` and a `walletpassphrase` call
     made during the flood are still listed;
   - W3: 20,000 local `importaddress` calls in an hour, then a `stop`:
     `importaddress` lines stop at 100 with an `importaddress: <n> more
     calls not listed` line, and the `stop` line and a `setlogconfig` call
     made during the flood are present; the same with `walletpassphrase`
     retried in a loop; and 10,000 `dumpprivkey` calls in an hour after a
     `stop`: `dumpprivkey` lines stop at 100, the `stop` line is still
     readable, and the first `dumpprivkey` call of the hour is in
     `rpc-methods-reserved.log` (Y6);
   - X3: a local `signrawtransaction` loop for 24 hours of simulated
     time, together with `importaddress`, `walletpassphrase` and
     `sendtoaddress` loops: capped lines stop at 200 an hour in all with a
     `<n> more calls suppressed (total cap)` line, and a `stop` made before
     the loops is still readable in `rpc-methods-reserved.log` at the end;
     a `backupwallet` loop does not push that `stop` out either;
   - A10 `known_values` (V2) is refused to a remote `rpcauth` caller,
     to a caller through the Web UI (even from loopback), to an Electrum
     caller, and to a loopback JSON-RPC call carrying `X-Forwarded-For`,
     `Forwarded` or `X-Real-IP`; it is served to a loopback JSON-RPC call
     with no proxy header; a secret-named environment variable
     (`*PASSWORD*`, `*TOKEN*`, `*KEY*`, `*SECRET*`) appears in the pages
     only as HMAC, length and tag (P3, R2), and its value is in no local
     page and no A17 incident;
   - W5: on the `/wallet/<name>` route, `getdiaginfo` with `known_values`
     is served to a loopback JSON-RPC call with no proxy header and
     refused to a remote caller and to one carrying `X-Forwarded-For`; a
     test build that mounts that route without the access middleware (no
     `Caller` extension) gets `known_values is local only`;
   - W2: a node with `rpcbind` set only to a LAN address: diag reaches it
     there, gets `known_values is local only`, falls back to the pre-A10
     calls, the §6.3 W2 label canary is masked, and `00-SUMMARY.txt` and
     the preview name the degraded masking (and, when diag is not root,
     that environment values were not available); with `rpcbind` adding
     `127.0.0.1`, diag uses loopback and reads the pages;
   - R2: the A10 match over 50 MB of collected text with 20 secrets on
     the reference Pi stays within B5's bound (to measure; the
     rolling R_b with one 8-byte SipHash-2-4 per offset is what is meant
     to keep it there; if it does not, that blocks A10 (a) until a later
     revision, and no prefix tag is sent, N1);
   - N1: the tag in a `known_values` environment page is the 16-bit
     SipHash-2-4 output over R_b's 8 bytes, never R_b's own bits (the test
     recomputes both under the test's `k` and checks the page against
     them).
6. **Release check** additions: every target built with frame pointers;
   unstripped binaries and build-ids stored (A16); the grep for
   `process::exit` in `bin/irondivid`; the D5 credential-call lint
   (`bin/irondivid/tests/credential_calls_lint.rs`, 97c4bceb: no call
   site of the ten credential calls — `setuid`, `setgid`, `setresuid`,
   `setresgid`, `setreuid`, `setregid`, `setfsuid`, `setfsgid`, `capset`,
   `setgroups`, in their bare, `libc::` and `nix::unistd::` spellings —
   or of `caps::set`, `caps::raise`, `caps::drop`, `caps::clear` under
   `bin/`, `crates/` or `tools/` without a `PR_SET_DUMPABLE` re-assert,
   A5, X2); on each gnu target, `nm -D` on the
   release binary shows `pthread_create` defined and exported, `readelf -d`
   lists the NEEDED libraries and they equal a baseline list taken from
   the same build without the interposer, except `libdl.so.2`, which is
   expected on a binary built against glibc 2.31 (R11-2), the link line used
   `--dynamic-list` (R9-1, R10-3), and `ld --version` in the ubuntu:20.04
   build image is recorded, to confirm it is older than 2.35; on i686 the
   symbol version the interposer resolves is recorded (R10-2); the **log
   source scan** (O1, privacy P2, consensus B3, privacy R11-1): every log
   macro under `bin/`, `crates/` and `tools/` outside tests whose
   arguments include a block hash (a value of the block hash type, or a
   call to `compute_block_hash`), and every log macro reachable from every
   stored block or wallet listener closure — the block-connected
   callbacks (`set_block_connected_callback` at `main.rs:1835`, `:1884`,
   and the staker's at `:2148`), the reorg callback (`set_reorg_callback`,
   `:1962`), the orphaned-transaction callback
   (`set_orphaned_tx_callback`, `:2071`), the tip listeners
   (`chain.add_tip_listener` at `main.rs:2681` for `-blocknotify`, and at
   `crates/divi-node/src/zmq.rs:440`), the mempool added listeners
   (`add_added_listener` at `main.rs:1926` and `zmq.rs:428`), the mempool
   removed listener (`set_removed_listener`, `main.rs:1933`), the ZMQ
   block listener (`chain.add_block_listener`, `zmq.rs:434`; privacy
   R13-1), the wallet transaction listener
   (`w.set_tx_listener`, `main.rs:1872`, for `-walletnotify`) and the
   staking status callback (`set_status_callback`, `:2357`), the
   transaction submit callback (`set_tx_submit`, `main.rs:2329`), and
   the transaction roots of A11 "Own transactions log like peer
   transactions" (privacy R14-1): `announce_tx` (`relay.rs:334`),
   `relay_tx` (`:350`), `handle_inv` (`:149`), `request_tx` (`:244`),
   `handle_tx` (`:265`), `handle_getdata` (`:304`), the node's relay
   handler (`node.rs:1327`), `resubmit_wallet_txs` (`main.rs:1702`) and
   `submit_transaction` (`crates/divi-rpc/src/wallet.rs:932`); a static walk
   does not follow a closure stored and called later, so the scan starts
   one walk at each registration, and a registration of a listener kind
   not on this list fails the scan until it is added (privacy R12-2) —
   and from the sync, inv and getdata handlers and `WalletDb::scan_block`,
   whether or not it names a block, with no module exempt, is either on the §6.2 "Public records"
   list of lines written for every block alike or on the A11 counted list
   (the reachable set comes from a call-graph walk, to build; the A11
   lists are its first result, made by hand, and not proof of
   completeness: this scan is the gate, and the O1 differential a
   backstop that passes a line written on both sides of its comparison
   window, consensus N-d), every counted-list site that writes a line
   carries the A8 `counted` field (and, in fixture runs, a tagged site
   still reaches `debug.log`, does not reach the ring, and its line in
   `debug.log` holds no `counted=` token; crashes R13-3, consensus N-f),
   a new log site in `try_connect_blocks`, `check_timeouts` or `note_lag`
   in `sync.rs` is unlisted until it is classified (adversarial AC1),
   `sync.rs:546` "restarting sync" stays classified as kept in place
   (adversarial r14 note 4), every log site reached from the transaction
   roots is in one of the three classes of A11 "Own transactions log
   like peer transactions", the removed `wallet_db.rs:3098` site is
   listed as removed, not counted, so a line written there again fails
   (platforms R14-2), and
   every log macro in
   `crates/divi-node/src/staker.rs` is on the A11 staker allowlist or
   counted list; a new line on neither fails the check; the canary tests
   pass. **Release
   gate (D5):** `scripts/tests/core-dump-vm/vm.sh` boots a throwaway
   Ubuntu 22.04 VM on a libvirt host (hp1 by default) and runs `run.sh`
   as root under the **systemd-coredump** pipe (D5-A) and a **plain `core`
   file** (D5-B); `scripts/tests/core-dump.sh` covers **apport** (hp3);
   an ordinary-user run is added to both. For each: a control process
   under `ulimit -c unlimited` must leave a core (proving the test can see
   one), and irondivid, sent SIGSEGV and, 2 s later if still alive, a
   second SIGSEGV (Rust's handler absorbs the first until A5 lands; after
   A5 the first ends it, and the A5 test asserts the `crash.log` record),
   must leave **none** in the data dir, the working directory,
   `/var/crash`, `/var/lib/apport/coredump` or
   `/var/lib/systemd/coredump`, and `coredumpctl list` gains **no**
   irondivid entry during the run while the control's is there. The VM is
   discarded afterwards; `core-dump.sh` changes no system setting.
7. **Docs**: `docs/diag.md` for users, `docs/exit-codes.md`, release notes.
