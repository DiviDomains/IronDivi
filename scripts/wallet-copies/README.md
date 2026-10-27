# Start-up wallet copies next to Divi Core

`run.sh` starts a fresh Divi Core 3.0.0 `divid` and a fresh irondivid on regtest, side by side, and takes both
through two sequences:

1. start, `encryptwallet`, restart;
2. start, restart, `encryptwallet`, restart.

After every start and step it compares, field by field, what each node does with the copies of its wallet that
Divi Core makes in `backups/` and `monthlyBackups/` at start-up (init.cpp:933-943, :1479). Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, a node that did
not start, or over 10 minutes).

```sh
scripts/wallet-copies/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/wallet-copies/run.sh target/release ~/divi-3.0.0/bin 53950 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+7` on 127.0.0.2 (each sequence: divid's p2p and RPC, then
  irondivid's).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 40 seconds and is stopped after 10 minutes. However it ends, the nodes are stopped and their
directories deleted. Needs bash and python3 (standard library only). The phrase is read from each node's own
`dumphdinfo` reply and the passphrase is made in memory; neither is printed, written to a file or put on a command
line. Both nodes run with `staking=0` and no peers. Copies are named by the minute, so a start waits until it is at
least 10 seconds before the next minute, and both nodes start in the same minute.

## Rows

For each sequence (`seq1`, `seq2`):

- `start <n>: console warnings`: the `Warning`/`Error` lines the node prints on its console at that start. divid
  warns at every start of an unencrypted wallet: "Make sure to encrypt your wallet and delete all non-encrypted
  backups after you verified that wallet works!" (init.cpp:1228-1232), and not once it is encrypted.
- `start <n>: backup log`: the backup lines of debug.log at that start, in order, paths named by their role:
  "backing up wallet" (init.cpp:939, WalletBackupFeatureContainer.cpp:41), "Wallet file not found at <wallet>.
  Skipping backup..." (WalletBackupFeatureContainer.cpp:29, a first start), "Creating backup of <wallet> ->
  backups/<copy>" (WalletBackupCreator.cpp:48), "Failed to create backup" (a copy of that minute already there,
  WalletBackupCreator.cpp:51).
- `start <n>: copies`: how many copies are in `backups/` and `monthlyBackups/` (`null`: no folder).
- `encryptwallet: reply`, `: node still running`, `: log` (the "Encrypting Wallet with an nDeriveIterations of <n>"
  line, its count left out), `: copies` (encryptwallet leaves the copies as they are).
- `end: copies holding the phrase in plain text`: per folder, how many copies still contain the recovery phrase
  as plain bytes. divid rewrites its wallet file when it encrypts it (wallet.cpp:1023-1026), so a copy made after
  `encryptwallet` holds no plain phrase; a copy made before it holds the phrase, on both nodes, and stays.
- `end: copy names`: the copy names with their time replaced.

## Known differences

- `end: copy names`: irondivid's wallet is a folder named `wallet`, so a copy is the folder `wallet.<time>`;
  divid's is the file `wallet.dat.<time>` (WalletBackupCreator.cpp:61-67).

## What this says about plain copies

Divi Core leaves the copies it made before `encryptwallet` in `backups/` and `monthlyBackups/` as they were: the
phrase stays readable in them, and its only notice is the start-up warning above while the wallet is not
encrypted. irondivid does the same, so with either node, delete the copies made before encrypting.

`WALLET_COPIES_INJECT=<row name>` changes irondivid's value of that row before it is compared, to show that a
difference is caught (the row then FAILs).
