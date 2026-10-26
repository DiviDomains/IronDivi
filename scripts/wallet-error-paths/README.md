# Wallet error replies next to Divi Core

`run.sh` starts a Divi Core 3.0.0 `divid` and an irondivid on regtest. irondivid is restored from divid's phrase and
follows its chain, so both wallets hold the same keys and coins. The script then makes the same wallet calls on both
whose replies are errors, or which fail part of the way through:

- `keypoolrefill` with sizes json_spirit folds into another int;
- `bip38paperwallet`'s argument and lock checks;
- sends that fail after the wallet has started to build them.

After each, it compares whether the wallet changed: `getwalletinfo` `keypoolsize` and the default account's addresses.
Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, in the way listed below;
- `FAIL`: differs and should not.

The run ends with `# rows: ...` and `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted,
or over 20 minutes). A run takes about three minutes.

```sh
scripts/wallet-error-paths/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]
```

- Ports `<port-base>` to `<port-base>+3` on 127.0.0.2.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.
- `WALLET_ERROR_PATHS_INJECT=<row name>` changes irondivid's reply of that row, which then FAILs.
- RPC passwords are made at random. The wallet phrase and the passphrase live only in memory, in RPC requests and
  replies, and in irondivid's environment; they are never printed or put on a command line.
- No key is printed: an address or a BIP38 key shows as its form only (version byte and length).

## Rows

Divi Core paths are under `divi/src/` at v3.0.0 (9e2f76c).

| calls | divid |
|---|---|
| `keypoolrefill` 2147483648, 3000000000, 6442450944 | `-8 "Invalid parameter, expected valid size."`: get_int keeps the low 32 bits as a C++ int, which is negative here (rpcwallet.cpp:2556-2561) |
| `keypoolrefill` 4294967296, 4294967297, -4294967295 | null: they fold to 0 (the `-keypool` default), 1 and 1 (rpcwallet.cpp:2556-2568) |
| `bip38paperwallet` with no argument, with two | `-1` and its help text (rpcdump.cpp:251-260) |
| `bip38paperwallet 5` | `-1 "value is type int, expected str"` |
| `bip38paperwallet <passphrase>`, `""` | `{"Address", "Encrypted Key"}` of a fresh key not kept in the wallet; the wallet does not change (rpcdump.cpp:262-292) |
| `sendmany` of 3000 outputs | `-4 "Transaction too large"`, after divid reserved the change key; the key goes back, and the key pool ends full (wallet.cpp:1805-1816, reservekey.cpp:44-51) |
| `sendtoaddress` of more than the balance | `-6 "Insufficient funds: …"`, before any transaction is built (rpcwallet.cpp:750-760) |
| `getnewaddress`, then `sendtoaddress <payee> 0.00006 receiver_pays` | `-4 "Cannot subtract needed fees from outputs."`: the fee would leave the payment as dust. The change key was reserved first, which tops the key pool up (wallet.cpp:1786-1793, :2129-2130) |
| while the wallet's writes fail (3b), the pool full (`keypoolrefill` first): `sendmany` of 3000 outputs, `sendtoaddress 0.00006 receiver_pays` | as with writes working, `-4 "Transaction too large"` and `-4 "Cannot subtract needed fees from outputs."`: the change key comes from the pool, nothing is derived, and it goes back in memory (reservekey.cpp:44-51), so `keypoolsize` stays 2000. Then `getrawchangeaddress` once writes work: the same key on both, since both wallets come from one phrase |
| writes failing, the pool one short (after that `getrawchangeaddress`): the same two sends | `-1 "loadHDChain: WriteHDChain failed"`: the change key's reservation tops the pool up (wallet.cpp:2129-2130), and the derivation throws when it cannot write the HD chain (wallet.cpp:2339-2347), before any key leaves or joins the pool: `keypoolsize` stays 1999 |
| writes failing, the pool one short: `keypoolrefill` | the same `-1`: the key is derived, and its HD chain written, inside the `WritePool` call (wallet.cpp:2104), so `-1 "TopUpKeyPool: writing generated key failed"` (wallet.cpp:2104-2105) is not reached |
| once writes work again, and after a restart (irondivid without the phrase, which would move its wallet aside, init.cpp:864-888): `keypoolsize`, the address count, `getrawchangeaddress` | the next change key is the one it would have been without the failed calls |
| locked and unlocked for staking only: `bip38paperwallet`, `sendtoaddress`, `sendmany`, `keypoolrefill` | `-13 "Error: Please enter the wallet passphrase with walletpassphrase first."` |
| unlocked again: `bip38paperwallet`, `keypoolrefill 4294967296` | as unlocked before |

Section 3b lowers each node's soft file size limit to one byte with util-linux's `prlimit` while it runs, as
`scripts/wallet-write-failures` does; the nodes start with SIGXFSZ ignored, so a write past it fails with EFBIG. No
block is made meanwhile, so only wallet writes fail.

Not reached by any call, on either daemon, and so covered by Rust tests on irondivid's side instead:

- **bip38paperwallet's `-4 "Invalid key"`** (rpcdump.cpp:269-275): for a fresh key whose public key is not valid,
  which `CKey::MakeNewKey` never gives. irondivid's fresh key cannot be invalid either; its encryption error,
  `-4 "BIP38 encryption failed: …"`, likewise has no input that reaches it.
- **keypoolrefill's `-4 "Error refreshing keypool."`** (rpcwallet.cpp:2564-2566): for a pool still under the size
  after `TopUpKeyPool`, which fills it to the size once the wallet is unlocked. irondivid has the same check
  (crates/divi-rpc/src/wallet.rs, keypool_refill).
- **The send `-4 "Signing transaction failed"`** (wallet.cpp:1805-1809, rpcwallet.cpp:796-800): a healthy wallet
  picks only coins it can sign. crates/divi-rpc/tests/wallet_sends.rs gives the wallet a coin it holds the wrong
  key for, and checks the reply and that the change key goes back.

## KNOWN

None.
