# The next wallet cases no other script compares

`run.sh` starts three regtest nodes on one chain:
- **S**, a Divi Core 3.0.0 `divid` that mines and pays;
- **C**, a `divid` wallet with `vault=1` and `maxtxfee=0.001`;
- **I**, an irondivid with the same options, restored from C's phrase, so C and I own the same coins.

Each case below runs on both twins, and its outcome is compared (never its timing). Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, in the way listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid, or differs in another way (the list below
  is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, a port in use, interrupted, or
over 15 minutes).

```sh
scripts/wallet-gaps-2/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/wallet-gaps-2/run.sh target/release ~/divi-3.0.0/bin 54150 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+5` on 127.0.0.150, the p2p and RPC port of S, C and I, checked
  to be free first. S listens; C and I dial it.
- `[root]`: a fresh directory (mode 0700) is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.
- `WALLET_GAPS_2_INJECT=<row name>` makes that row differ, to show a difference is caught;
  `WALLET_GAPS_2_WIDE=1` prints each value whole (otherwise cut at 260 characters).

A run takes about a minute and a half on hp1 and is stopped after 15. However it ends, every node is stopped and its
directory deleted. Needs bash, `ss` and python3 (standard library only).

Secrets stay off command lines and out of the output:
- C's phrase is read from its `dumphdinfo` reply and handed to irondivid in its environment (`WALLET_MNEMONIC`).
- The wallet passphrase and the bip38 passphrase are random (`secrets.token_hex`) and go over RPC only.
- The imported key is the twins' own, read with `dumpprivkey` and sent back over RPC; the out-of-range keys are 0
  and the curve order, which are no keys.
- S's seed and C's words for the restore cases are written only into the `divi.conf` of copied datadirs under the
  run's directory.

None of these is printed.

## Set-up

S mines 110 blocks and pays the twins eight coins of 100 DIVI, 800 coins of 0.25 DIVI (two sets of 400, one for each
twin's sweeps, on ten addresses each) and one coin of 0.00006 DIVI.

## Cases

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c).

| group | rows | divid |
|---|---|---|
| imports | `importprivkey` of the twins' own HD key with a label, then its account | relabelled, then null as the key is held (rpcdump.cpp:83-89) |
| | `importprivkey` of a well-formed WIF of 0 and of the curve order | -5 "Private key outside allowed range" (rpcdump.cpp:76-77) |
| | `importaddress <hex P2PKH script of S's address> hexlabel false`, then `validateaddress` and `getaddressesbyaccount hexlabel` | watched, but no label: only a parsed address is labelled (rpcdump.cpp:126-128, :150-151) |
| | `setaccount` on that watched address | labelled (rpcwallet.cpp:600-615) |
| | `importaddress <hex of the twins' own P2PKH script>`, then `validateaddress`, then `importaddress <the address>` | KNOWN, below |
| | `bip38decrypt` of a key S made with `bip38paperwallet` and paid 5 DIVI before, then the balance change | a full rescan finds the coin (rpcdump.cpp:336-345) |
| | `getcoinavailability "yes"`, `1`, `null` | -1 "value is type …, expected bool": get_bool whenever given (rpcwallet.cpp:828) |
| vaults | `addvault` with a mined transaction that is not the twins', and with one of theirs that does not fund the vault; then both vaults funded by S | the script is stored first; -32600 "AddingVaultScript: Unable to sync TX!" unless the transaction is the wallet's; both vaults are managed afterwards (rpcwallet.cpp:1295-1301, wallet.cpp:695-704) |
| | a start with `-whitelisted_vault` for a vault the twins manage, one they own, a P2PKH script and `nothex`; the vaults after it, after a funding of each, and after a start without the option | the managed one is added, without its earlier funding, and kept; the others are left out (init.cpp:1182-1201, wallet.cpp:1992-2003, wallet_ismine.cpp:80-91) |
| | `reclaimvaultfunds <payee> 1 "metadata" "a note" "a shop"`: the fee, the inputs, and the transaction's `comment` and `to` | the notes are kept (rpcwallet.cpp:1170-1176) |
| locked | `sendtoaddress notanaddress 1`, `<payee> -1`, `<payee> "abc"`, `<payee> 1 "bogus"` on a locked wallet | the address, amount and mode are read before the lock is checked (rpcwallet.cpp:1324-1358) |
| sweeps | `sendtoaddress <payee> 1 "sweep_funds"` with only the 0.00006 coin unlocked, with nothing unlocked, and with all 800 small coins | -4 "Cannot sweep inputs." (wallet.cpp:1683-1691, :1794-1798); "Insufficient funds to meet coin selection algorithm requirements."; "Transaction too large" (wallet.cpp:1595-1597, :1812-1816) |
| | with only the twin's own 400 coins: `sendtoaddress <payee> 90`, then the sweep | the plain send is refused under `-maxtxfee=0.001` (MinimumFeeCoinSelectionAlgorithm.cpp:97); the sweep pays 0.0075646, over it, as its coin selection returns at :77, before that check (wallet.cpp:1736-1748) |
| restores | copies of each twin with no wallet and `hdseed=<S's seed>` with `mnemonic=<the twins' words>`; `hdseed=nothex`; `hdseed=nothex` with the words: whose addresses are the wallet's, and the log lines | a hex seed wins and logs "can't use -hdseed and -mnemonic/-mnemonicpassphrase together, will prefer -seed" (init.cpp:945-951); one that is not hex logs "Incorrect seed, generating random one instead" and the words, if any, are used (wallet.cpp:2286-2300) |

A wallet already there with `-hdseed` or `-mnemonic` is moved aside by divid first (init.cpp:864-888). That is
`fix/wallet-gaps` (`scripts/wallet-gaps`), so the restores here start from copies with the wallet deleted.

## KNOWN

| rows | why |
|---|---|
| `importaddress <hex script of an own address> '' false`, `then: validateaddress of the own address`, `importaddress <own address> '' false` | divid takes the hex of the wallet's own P2PKH script as watch-only, as a script names no address for its spendable check (rpcdump.cpp:138-147), and then counts the address as watch-only, not its own (`ismine` false), so the import of the address passes too. irondivid refuses both with -4 "The wallet already contains the private key for this address or script" (`import_address` in crates/divi-rpc/src/wallet.rs) [on purpose: it would turn an address of the wallet's own into a watch-only one; docs/divid-differences.md R18] |

## Results on hp1 (divid 3.0.0)

| irondivid | PASS | KNOWN | FAIL | time |
|---|---|---|---|---|
| `fix/wallet-gaps-2` (af8020b), run 1 | 47 | 3 | 0 | 1 m 5 s |
| `fix/wallet-gaps-2` (af8020b), run 2 | 47 | 3 | 0 | 1 m 16 s |
| its base, integration f11d336 | 35 | 3 | 12 | 1 m 8 s |

On f11d336 the 12 FAILs are: the hex script's label (2 rows), `getcoinavailability null` (1), `addvault` with a
transaction of the wallet's that does not fund the vault (1), the vaults afterwards and after the `-whitelisted_vault`
starts (4), `reclaimvaultfunds`' notes (1), and the `-hdseed` log lines (3).
