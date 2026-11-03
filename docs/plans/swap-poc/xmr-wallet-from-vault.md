# XMR wallets open from the vault seed through the Mac (plan row B5)

Status: design + tooling landed, migration not yet run. Tool: `tools/swap-poc/xmr-wallet-from-vault.sh`;
test: `tools/swap-poc/test-xmr-wallet-from-vault.sh`. Claims about Monero behaviour are in
`xmr-wallet-from-vault.FACTS.md`.

## Problem

Row B5: no XMR wallet key file may sit on an hp host in a form that opens without a secret. Today the
stagenet swap wallet on hp2 (`mining-wallet`) is a `.keys` file with an empty password, opened by a
long-running `monero-wallet-rpc` (127.0.0.1:38088) that the Mac reaches by `ssh -L 38088`
(`tools/swap-poc/xmr-soak.sh:8,36`, `c1-punish-step.sh:14`). hp hosts may never hold a 1Password secret,
so a wallet password cannot live there either. Nothing on an hp host can therefore open a wallet.

## Truth table (code, file:line)

| Question | Answer |
|---|---|
| Who calls wallet-rpc | `swap_chain_xmr::monero_chain::lock` (`crates/swap-chain-xmr/src/monero_chain.rs:107-137`): one `transfer`, Digest auth to `{wallet_rpc}/json_rpc`. Called from the taker's `lock` in `crates/divi-swap-xmr/src/live.rs:360-374`. |
| Which methods the swap code uses | `transfer` only (monero_chain.rs:130). `get_balance` appears in an ignored live test (monero_chain.rs:584). The daemon side (`get_fee_estimate`, monero_chain.rs:296) goes to monerod, not wallet-rpc. |
| Who needs a wallet | Taker only. `live.rs:161-167` documents `wallet_rpc_*` as taker-only; `deploy/divi-swapd/divi-swapd.toml.example:167-171` says a maker omits them and sweeps with the recovered key. The hp-hosted maker needs no wallet. |
| Wallet path | Never in the swap code. It is whatever the wallet-rpc process was started on: hp2 `mining-wallet` (`status/xmr.md:19`), RPC `127.0.0.1:38088`. The brief's "38111" does not appear in the repo; the live port is 38088. |
| Daemon address | A wallet-rpc flag, not swap config: `node.monerodevs.org:38089` (`status/xmr.md:348`). The swap config has a separate `--xmr-monerod-url` (`xmr-soak.sh:35`, `c1-punish-step.sh:14`). |
| RPC login | Vault items `IronDivi Swap POC - taker-xmr-wallet-rpc/{username,password}` via `secret get` (`xmr-soak.sh:67-79`, `c1-punish-step.sh:9-15`). |
| Seed source already in the vault | `divi_xmr_swap_<network>/seed_phrase` (`tools/swap-poc/xmr-verify-wallet.sh:36-46`, which restores it with `monero-wallet-cli` on stdin). |
| Disk behaviour of wallet-rpc | `restore_deterministic_wallet`, `generate_from_keys`, `open_wallet` all require `--wallet-dir`; create/restore write `<name>.keys` (keys, encrypted by the password) and `<name>` (cache) there, and `close_wallet` stores by default. A log file is also written. See FACTS rows 1-4: could not verify against vendor docs in this lane (no network), so the design makes **every** file wallet-rpc writes land on the RAM disk (`--wallet-dir`, `--log-file`, `--config-file`) rather than relying on any claim that it writes nothing. |

## Recommended shape

wallet-rpc runs **on the Mac**, against a remote daemon, with its wallet dir on a Mac RAM disk.

1. `xmr-wallet-from-vault.sh --network stagenet --restore-height N` creates a hdiutil RAM disk
   (HFS+, `nobrowse`), starts `monero-wallet-rpc --wallet-dir <ramdisk>/w --daemon-address <daemon>
   --rpc-bind-ip 127.0.0.1 --rpc-bind-port 38088` with login and log file on the RAM disk.
2. It resolves the RPC login and then the seed with `secret get` (one call each, once per process),
   and sends `restore_deterministic_wallet` as one POST body on localhost. The seed lives in a shell
   variable and in that body only (builtin `printf` into curl's stdin: no argv, no file).
3. The wallet file password is random per run and discarded, so even a RAM-disk remnant would not open.
4. It prints `address` and `height`, then stays up. The taker and `xmr-soak.sh` use
   `--xmr-wallet-rpc-url http://127.0.0.1:38088` exactly as today, minus the `ssh -L` tunnel.
5. On exit, success, failure, SIGINT or SIGTERM, the trap calls `close_wallet`, stops wallet-rpc,
   removes the files and detaches the RAM disk.

The port stays 38088 and the login stays the vault's taker-xmr-wallet-rpc pair, so no swap code or
taker invocation changes.

### How the maker on the hp host reaches the wallet

It does not. The maker never sends XMR; it sweeps with the key it recovers (`live.rs:161`,
`divi-swapd.toml.example:167`). The taker runs on the Mac (as `xmr-soak.sh` already does). An
hp-hosted taker is **not supported** by this design: it would need the wallet-rpc password on the host.
If ever needed, `ssh -R 38088:127.0.0.1:38088 <host>` exposes the Mac wallet to it, but its login would
still have to reach the host; that is a new decision, not a default.

### Restore height

`--restore-height` is required. Record the wallet's creation height as a `restore_height` field in the
same vault item as `seed_phrase` (a human step, no secret) and pass it. For the existing stagenet
wallet use a height at or before its first receive; too high silently hides funds, too low only costs
scan time. A restore from height 0 on mainnet is slow, so mainnet wallets must record the height at creation.

### One-time migration of the stagenet wallet (human-started, never the builder)

Prerequisite: the vault item `divi_xmr_swap_stagenet` really holds the seed of the hp2 `mining-wallet`
(`tools/swap-poc/xmr-verify-wallet.sh --network stagenet` must print MATCH).

1. On the Mac: `xmr-wallet-from-vault.sh --network stagenet --restore-height <N> --once` and confirm the
   printed address equals `5AbHxitM2WMiq1b957FpA6ZMHPPSex3XNH3UU9ox2tGpMHj9mNwCXCEXWMUVnfhnrQLyeh8vNDy6Mitu5d4L9Zjm9p8LaiS`.
2. Stop hp2's wallet-rpc (`ssh hp2`, stop the `monero-wallet-rpc` process on 38088).
3. Shred the stagenet `.keys`, the wallet cache and `.address.txt` in its wallet directory
   (`shred -u` on each file; `rm` after).
4. Prove with `ls` and `find <wallet dir> -name 'mining-wallet*'` that they are gone, and report
   "deleted N files". Only then tick B5.

## Alternatives

| Alternative | Trade-off |
|---|---|
| **A. Mac wallet-rpc + RAM disk (recommended)** | No key at rest anywhere; no secret on hp. Cost: the Mac runs a wallet (CPU for scans) and must be awake; a seed restore re-scans from the restore height each time. macOS may page RAM to swap; FileVault encrypts it. |
| B. Wallet-rpc on hp with `--wallet-dir` on tmpfs, seed pushed over an SSH tunnel from the Mac | Same RAM-only property, but the seed crosses the host's wallet-rpc process and the host's memory/swap; a host compromise sees a live open wallet. Violates the spirit of "never on an hp host". Rejected. |
| C. Password-protected `.keys` on hp | The password needs a secret on hp, forbidden. Rejected. |
| D. Mac wallet persisted on an encrypted Mac volume | Faster restarts, but a key file at rest on the Mac and a password to manage. Acceptable for mainnet-scale amounts only if the RAM-disk rescan is too slow; revisit then. |

## Not done / verified only on hp1

The self-test runs on hp1 (Linux, `/dev/shm`) against mocks. The Darwin branch (hdiutil RAM disk,
`newfs_hfs`, `mount -t hfs`) and a real `monero-wallet-rpc` are **untested**; the first Mac run is a
human step (`--dry-run`, then stagenet `--once`).
