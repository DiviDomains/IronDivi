# Message signing and the wallet passphrase next to Divi Core

`run.sh` starts a fresh Divi Core 3.0.0 `divid` and an irondivid restored from divid's phrase, on regtest. It makes
the same `signmessage`, `verifymessage`, `walletpassphrasechange`, `walletpassphrase` and `walletlock` calls on both
and compares the replies, the error codes and texts, and `getwalletinfo`'s `encryption_status` and `unlocked_until`
after each step. Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

A reply object whose members come in another order than divid's is a FAIL too (`scripts/lib/member_order.py`). The
run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 10 minutes).

```sh
scripts/sign-passphrase/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/sign-passphrase/run.sh target/release ~/divi-3.0.0/bin 54300 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` (divid p2p and RPC, then irondivid's), bound to 127.0.0.2
  (`SIGN_PASSPHRASE_HOST` to change it). The nodes listen to nobody and dial only `<port-base>+49` on that host,
  where nothing listens.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about a minute and is stopped after 10 minutes. However it ends, both nodes are stopped and their
directories deleted. It needs bash and python3 (standard library only).

`SIGN_PASSPHRASE_INJECT=<row name>` changes irondivid's reply of that row before it is compared, to show that a
difference is caught.

Secrets:
- The phrase is read from divid's `dumphdinfo` and handed to irondivid in its environment (`WALLET_MNEMONIC`).
- The four wallet passphrases are random, made by the run into a 0600 file in its directory. They go only into RPC
  request bodies: never onto a command line, into the output or into a row's name. A row checks that neither node's
  `debug.log` holds one.

## Steps

Both wallets come from one phrase and so hold the same keys; a signature is deterministic (RFC 6979), so the two
nodes' signatures of one message are equal.

1. **Unencrypted:** the signing rows; `walletpassphrasechange`, `walletpassphrase` and `walletlock` (-15).
2. `encryptwallet` on both with the first passphrase. **Locked:** the signing rows (each signmessage -13).
3. **Unlocked for staking only** (`walletpassphrase … 600 true`): signmessage, staking only again (-17), walletlock.
4. **Unlocked:** the signing rows; walletpassphrase with a wrong passphrase, and for staking only.
5. **walletpassphrasechange** while locked (wrong old passphrase, empty new or old one, one argument, a number, a
   change), unlocked (a change, a wrong one) and unlocked for staking only (a change, a wrong one), and during a
   3-second unlock. After each, the unlock state, and that the old passphrase is refused and the new one taken.
6. **walletpassphrase's timeout:** `0`, `1000000000`, `2^31`, `-5`, `1.5`, `"60"`, `true`, `null`, each followed by
   the unlock state and `walletlock`; a 2-second unlock 4 seconds on; a wrong passphrase; wrong argument counts and
   types; `walletlock` with an argument.
7. **A restart** of both: the unlock state, the passphrase before the last change (refused), the last one, a
   signmessage.
8. **The logs:** no passphrase in either `debug.log`, and as many lines naming a passphrase change on each.

`unlocked_until` is compared in steps of 10 seconds from now, since the two nodes are read a moment apart.

The signing rows, for each state:

| call | forms |
|---|---|
| `signmessage` | a short, an empty and a 20000-character message; a non-ASCII message `\u`-escaped and as UTF-8; hex and b64 input; an unknown input format; hex output; the multisig address; a vault `owner:manager`; an address not in the wallet; a bad address; one and five arguments; a number as the message |
| `verifymessage` | each signature above with its message; another message; the wrong address; the multisig address; an address not in the wallet; a bad address; a signature that is not base64; base64 that is no signature; an empty signature; the signature without its padding; the hex signature; two arguments |

## What divid does (Divi Core 3.0.0)

- `signmessage` (rpcwallet.cpp:1364-1430) checks that the wallet is fully unlocked (-13) before it reads an
  argument; then a bad address is -3 "Invalid address", a P2SH or vault address -3 "Address does not refer to key",
  a key the wallet lacks -4 "Private key not available". `verifymessage` (rpcmisc.cpp:485-525): -5 "Malformed base64
  encoding", else `true` or `false`.
- `walletpassphrase` (rpcwallet.cpp:2573-2625) reads the passphrase and the staking-only flag, refuses staking only
  on a wallet already unlocked for staking (-17), unlocks, and only then reads the timeout with `get_int64`. A timeout
  that is no integer is -1 with the wallet left unlocked. The timer (rpcserver.cpp:1195-1220): `unlocked_until`
  becomes now plus the timeout, and only a timeout above 0 sets one.
- On a wallet unlocked for everything, the unlock takes any passphrase and only sets the staking-only flag
  (CWallet::Unlock, wallet.cpp:778-803).
- `walletpassphrasechange` (rpcwallet.cpp:2628-2664, CWallet::ChangeWalletPassphrase wallet.cpp:808-848) locks the
  wallet before it checks the old passphrase. A wrong one is -14 with the wallet left locked and the timer and
  `unlocked_until` as they were; a right one leaves the wallet as it was before the call.

## KNOWN differences

| rows | divid | irondivid | why |
|---|---|---|---|
| `unencrypted:` and `unlocked:` `signmessage, a non-ASCII message, \u-escaped` and `verifymessage, …` | signs, and verifies its own signature | signs the text that was sent; divid's signature does not verify | json_spirit keeps only the low byte of each `\uXXXX` escape (unicode_str_to_char, json/json_spirit_reader_template.h:71-82, :111-116), so divid signs another message than the one sent. The same text sent as UTF-8 matches (the `as UTF-8` rows) |
