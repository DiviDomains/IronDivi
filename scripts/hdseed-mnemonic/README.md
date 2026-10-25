# Wallet start options and replies next to Divi Core

`run.sh` starts fresh single regtest nodes, a Divi Core 3.0.0 `divid` and an irondivid with the same `divi.conf`
lines. They have no peers and no blocks beyond genesis. Each case below runs on both, and its outcome is compared.
Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, in the way listed below with the reason (none at present);
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid.

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 15 minutes).

```sh
scripts/hdseed-mnemonic/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/hdseed-mnemonic/run.sh target/release ~/divi-3.0.0/bin 53950 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` on 127.0.0.2, the p2p and RPC port of the two nodes.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 3 minutes (measured on hp1) and is stopped after 15. However it ends, every node is stopped and its
directory deleted. Needs bash and python3 (standard library only). `HDSEED_MNEMONIC_INJECT=<row name>` makes that row
differ, to show a difference is caught.

**Secrets.** Every secret is made in the run: the words come from a throwaway divid wallet, and the hex seed, the BIP39
passphrase and the wallet passphrase are random. They go only into each node's 0600 `divi.conf`, or over RPC. None is
printed or put on a command line: rows say `the seed`, `the words`, `the passphrase`, `empty` or `other`.

## Rows (Divi Core 3.0.0, `divi/src/`)

| case | divid |
|---|---|
| `hdseed=<hex>` with `mnemonic=<words>`, with `mnemonicpassphrase=<p>`, and with both | PruneHDSeedParameterInteraction drops both and logs `PruneHDSeedParameterInteraction: parameter interaction: can't use -hdseed and -mnemonic/-mnemonicpassphrase together, will prefer -seed` (init.cpp:945-951, called at :1493). The wallet is made from the seed (wallet.cpp:2288-2294). Compared: the start; `dumphdinfo`'s hdseed (the seed), mnemonic and mnemonicpassphrase (empty); whether the first `getnewaddress` is the other node's; both log lines. |
| `hdseed=nothex` with `mnemonic=<words>` | Logs `CWallet::GenerateNewHDChain -- Incorrect seed, generating random one instead`, then the wallet is made from the words (wallet.cpp:2295-2313); the prefer-seed line is not logged, as the seed is not hex. |
| `hdseed=nothex` alone | The same log line, then a new random wallet. |
| encrypted and locked, `-keypool=1`: `walletpassphrase <p>` (one argument) and `walletpassphrase <p> 60 false x` (four) | -1 with the help text: the count is checked only on an encrypted wallet (rpcwallet.cpp:2575). The help texts are compared with sample addresses and hashes written `diviaddress` and `hash`, as `scripts/help-replies` compares them. |
| encrypted: `walletlock x` | -1 with the help text (rpcwallet.cpp:2669) |
| locked: `sendmany "*" {<own address>: 1}` | -11 `Invalid account name`; the account is read before the lock is checked (rpcwallet.cpp:276-277, :1718, :1727) |
| locked: `getnewaddress` four times, then `getaccountaddress "fresh"` | The pool is not topped up while locked; once it is empty, -12 `Error: Keypool ran out, please call keypoolrefill first`, for getaccountaddress too (rpcwallet.cpp:306-307, :347-348) |
| `-disablewallet` | Starts, and logs `Wallet disabled!` (init.cpp:1546-1547) |
