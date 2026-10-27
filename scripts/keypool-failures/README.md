# The keypool when a wallet write fails, next to Divi Core

`run.sh` starts three regtest nodes on one chain:
- **S**, a Divi Core 3.0.0 `divid` that mines and pays;
- **C**, a `divid` wallet;
- **I**, an irondivid wallet.

C and I are new wallets of their own, both with `keypool=2`. They start with SIGXFSZ ignored, and their output goes
through a pipe to a file the script writes. For each case the soft file size limit of the running wallet is lowered
to one byte with `prlimit`, so a wallet write fails with EFBIG; the call is made, and the limit is raised again. No
block is mined meanwhile. The method is `scripts/wallet-write-failures`'.

Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, in the way listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid, or differs in another way.

The run ends with `# rows: …` and `FAILS <n>`; the exit code is the number of FAILs (255: usage error, a port in
use, interrupted, or over 15 minutes).

```sh
scripts/keypool-failures/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/keypool-failures/run.sh target/release ~/divi-3.0.0/bin 54150 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+5` on 127.0.0.150, the p2p and RPC port of S, C and I, checked
  to be free first.
- `[root]`: a fresh directory (mode 0700) is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end,
  or kept with `KEEP=1`.
- `KEYPOOL_FAILURES_INJECT=<row name>` makes that row differ, to show a difference is caught;
  `KEYPOOL_FAILURES_WIDE=1` prints each value whole.

A run takes about two minutes on hp1. Needs bash, `ss`, util-linux's `prlimit` and python3 (standard library only);
no root. Passphrases are random and go over RPC; no key or passphrase is printed.

## What divid does

Core paths are under `divi/src/` of the Divi Core source at v3.0.0. Every reservation of a key (getnewaddress, a
send's change key, a send without change, keypoolrefill) first runs TopUpKeyPool (wallet.cpp:2057-2118, :2129-2130).
encryptwallet tops up after encrypting (:1011-1015), and walletpassphrase after unlocking (rpcwallet.cpp:2617-2620).
TopUpKeyPool derives each missing key in GenerateNewKey. The derivation sets the HD chain's new counter in memory and
then writes it (deriveNewChildKey, :483-511; loadHDChain, :2339-2347; loadCryptedHDChain on an encrypted wallet,
:2352-2363). When that write fails it throws, before WritePool, before the key joins the pool set and before
`keypool added` is logged (:2104-2112).

So a call whose top-up cannot write a key:
- logs no keypool line: no `added`, no `reserve`, `keep` or `return`;
- leaves the pool set and its numbers as they were, so the next key is numbered one past the newest in the pool;
- answers -1 with the exception's text (rpcserver.cpp:1107-1108): `loadHDChain: WriteHDChain failed`, or
  `loadCryptedHDChain: WriteCryptedHDChain failed` on an encrypted wallet. walletpassphrase answers so after the
  wallet is unlocked, and its timer is never set (rpcwallet.cpp:2617-2623).

## Cases

Each case starts with the pool one receiving key short, as each getnewaddress leaves it, so the call's top-up must
write a key.

| case | rows |
|---|---|
| `getnewaddress`, `keypoolrefill 3`, `sendtoaddress <payee> 1` with change, `sendtoaddress <payee> 1 "sweep_funds"` without change, `encryptwallet`, `walletpassphrase <passphrase> 60` (on a wallet encrypted while writes worked), `getnewaddress` on the unlocked encrypted wallet | while writes fail: the reply, the keypool lines, whether the node stays up, `keypoolsize`; after walletpassphrase, getwalletinfo's `encryption_status` and `unlocked_until` |
| after each case but the encryption | once writes work, the keypool lines of the next `getnewaddress` (the new key's number and the reserved key's) and `keypoolsize` |
| the addresses handed out | the HD child index of each (validateaddress's `hdkeypath`), and of the next ones after a restart |

## KNOWN

| rows | why |
|---|---|
| `the HD child index of each address handed out`, `a restart: the HD child index of the next addresses` | divid's deriveNewChildKey moves its HD chain's counter on in memory before the write that fails (wallet.cpp:483-511, :2339-2347), so the child it could not write is never handed out, and after a restart its counter is the one its last written key left. irondivid's keypool is the children from its next index on, and it derives that child again once writes work. The keypool numbers, sizes and lines are the same |
| `encryptwallet while writes fail: reply` | divid's writes inside its encryption transaction go through, and the keypool top-up after it (wallet.cpp:1011-1015) throws from the derivation (:2359-2360): `-1 loadCryptedHDChain: WriteCryptedHDChain failed`. irondivid fails at its first write and answers `-16 Error: Failed to encrypt the wallet.`, as `scripts/wallet-write-failures` lists |

## Results on hp1 (divid 3.0.0)

Each run is 50 rows.

| irondivid | PASS | KNOWN | FAIL |
|---|---|---|---|
| before the fixes (base-d265abc) | 28 | 3 | 19 |
| with them, run 1 | 47 | 3 | 0 |
| with them, run 2 | 47 | 3 | 0 |

The two runs with the fixes printed the same rows, values included. Before the fixes:
- every call whose top-up could not write logged `keypool added` for the key, and the reservation's `reserve`/`keep`
  (or the change key's `reserve`) that divid never reaches;
- the pool numbers of the keys rolled back stayed behind, and the taken key's number was lost, so every later
  `getnewaddress` numbered its new key higher than divid's and, after a send, reserved a different key;
- encryptwallet and walletpassphrase kept the key they could not write in memory: `keypoolsize` 4 where divid's is 3;
- walletpassphrase answered null and set its timer (`unlocked_until`), where divid answers -1 and sets none;
- getnewaddress on the encrypted wallet answered `loadHDChain: WriteHDChain failed`.
