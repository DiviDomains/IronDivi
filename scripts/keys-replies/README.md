# Key import/export and wallet-upkeep RPC replies next to Divi Core

`run.sh` starts a fresh Divi Core 3.0.0 `divid` and an irondivid restored from divid's phrase on one regtest chain. It
makes the same key import/export and wallet-upkeep calls on both, first on unlocked wallets and then after
`encryptwallet` on locked ones, and compares the replies. Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 10 minutes).

```sh
scripts/keys-replies/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/keys-replies/run.sh target/release ~/divi-3.0.0/bin 53950 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` on 127.0.0.1 (divid p2p and RPC, then irondivid's).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about a minute and is stopped after 10 minutes. However it ends, both nodes are stopped and their
directories deleted, with every file the calls wrote there (backups, a dump file if one were written). It needs bash
and python3 (standard library only).

Secrets:
- The phrase is read from divid's `dumphdinfo` and handed to irondivid in its environment (`WALLET_MNEMONIC`).
- The private keys are new regtest keys made by the run (random bytes, WIF prefix 239). The BIP38 and wallet
  passphrases are made by the run too.
- None of them is printed, written to a file or put on a command line. A row names them by placeholder (`<key1>`,
  `<passphrase>`), and a reply that holds a secret (`dumpprivkey`, `bip38encrypt`, `bip38decrypt`) is shown only as
  `(hidden)`.

## Nodes and steps

divid listens; irondivid dials it (`connect=`), so both see one chain, and both wallets own the same keys. Both run
with `staking=0`.

1. divid mines 25 blocks. One address both wallets own (divid's first new address) and one nobody holds a key for
   (random bytes) are used below.
2. The rows on unlocked wallets.
3. `encryptwallet` on both with a passphrase made by the run, then the rows on locked wallets.
4. `walletpassphrase` for 60 s, two calls on the unlocked wallets, `walletlock`, one more call.

## Rows

| call | forms |
|---|---|
| `importprivkey` | `<key1> imported1 false`; `<key1>` again (Core clears the label first, rpcdump.cpp:79-84); `<key2> imported2`; `<key3> "" true`; none; four arguments; key not a string; label not a string; rescan not a bool; a key with one character changed |
| `getaddressesbyaccount` | `imported1` after each import of `<key1>`, `watch` |
| `importaddress` | the watched address with a label and `false`, then again; an address the wallet holds the key for; `notanaddress`; a P2PKH script in hex; `zz`; none; not a string; rescan not a bool |
| `dumpprivkey` | the own address; the imported address (and that it is `<key1>` on each node); the watched address; `notanaddress`; none; not a string |
| `dumpwallet`, `importwallet` | a file in the run directory: in neither program, and no file is written |
| `backupwallet` | a new path, the same path again, a path in a folder that does not exist; none; not a string |
| `keypoolrefill` | none; `0`; `5`; `1200`; `-1`; `"5"`; two arguments; `getwalletinfo` keypoolsize afterwards |
| `walletverify`, `settxfee` | in neither program |
| `bip38paperwallet` | `<passphrase>` (its two fields); none |
| `bip38decrypt` | divid's paper key with the passphrase; again (already held); a wrong passphrase; `notakey`; one argument; not a string; irondivid's paper key on both; a second key of divid's |
| `bip38encrypt`, `setstakesplitthreshold`, `getstakesplitthreshold`, `reservebalance` | irondivid only: show, set, unset and bad arguments |
| `encryptwallet` | `<passphrase>` |
| locked | `getwalletinfo` unlocked_until, `importprivkey`, `importaddress`, `dumpprivkey` (an address, `notanaddress`), `backupwallet`, `keypoolrefill` (none, `-1`), `bip38paperwallet`, `bip38decrypt`, `bip38encrypt`, `setstakesplitthreshold`, `reservebalance` |
| unlocked again | `walletpassphrase <passphrase> 60`, `dumpprivkey`, `importprivkey`, `walletlock`, `dumpprivkey` |

Not here, because `crates/divi-rpc/tests/core_replies.rs` `key_errors` already compares them:
- `dumpprivkey` of an address nobody holds and of a script address;
- `importprivkey notakey`.

## How replies are compared

- An error: the same code and text. A wrong argument count is answered with the call's help as a -1 error, and each
  program words its help itself (divid's `bip38paperwallet` help even starts with `bip38encrypt`), so two help texts
  agree as help texts.
- A result: the same value. For `getwalletinfo` only the field named in the row is compared.
- A secret result: compared, shown as `(hidden)`.

## KNOWN

| row | divid | irondivid | why |
|---|---|---|---|
| `bip38decrypt <encrypted key> <wrong passphrase>` | Adds whatever key the wrong passphrase gives, and answers its address: Core's BIP38_Decrypt does not check the address hash (bip38.cpp:131-178, rpcdump.cpp:313-343) | -4 "Failed To Decrypt" | A wrong passphrase must not put an unrelated key into the wallet |
| `bip38encrypt` (every form) | Method not found (rpcserver.cpp:424-425 has bip38paperwallet and bip38decrypt only) | Encrypts a key the wallet holds | Kept: it exports a held key in BIP38 form |
| `setstakesplitthreshold`, `getstakesplitthreshold` (every form) | Method not found; the threshold is the start-up option `-stakesplitthreshold` | Read and change the threshold of the running node | Kept: no restart needed to change it |
| `reservebalance` (every form) | Method not found in 3.0.0 | Shows or sets an amount the staker keeps back | Kept from earlier Divi releases |

An irondivid-only row is `KNOWN` while divid answers "Method not found" and irondivid answers; otherwise it is a `FAIL`.
