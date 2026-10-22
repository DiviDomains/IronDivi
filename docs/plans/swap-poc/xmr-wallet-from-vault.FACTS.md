# FACTS — xmr-wallet-from-vault.md

Tier rule: each third-party claim has a verdict and a vendor URL. This lane had no network access
(only `git fetch`) and hp1 has neither `monero-wallet-rpc` nor the Monero source, so nothing below was
checked against the vendor text. The design does not depend on any of these: it puts every file the
process writes on the RAM disk and the self-test uses a mock.

| # | Claim | Verdict | Source | What the page says |
|---|---|---|---|---|
| 1 | `monero-wallet-rpc --wallet-dir` is needed for `create_wallet`/`open_wallet`/`restore_deterministic_wallet`, and files are created inside it | could not verify | https://docs.getmonero.org/rpc-library/wallet-rpc/ | Design keeps `--wallet-dir` on the RAM disk; no claim relied on. |
| 2 | `restore_deterministic_wallet` takes name, password, seed, restore_height, language and writes `<name>.keys` + cache | could not verify | https://docs.getmonero.org/rpc-library/wallet-rpc/#restore_deterministic_wallet | Page states the method and params as used; the file layout is stated as "expected". |
| 3 | `close_wallet` stores the wallet by default | could not verify | https://docs.getmonero.org/rpc-library/wallet-rpc/#close_wallet | Not relied on: the RAM disk is wiped regardless. |
| 4 | `--wallet-dir` on a RAM disk avoids any persistent write | could not verify (also the log file and config file are separate flags) | https://docs.getmonero.org/rpc-library/wallet-rpc/ | Page says: all known wallet-rpc files are redirected to the RAM disk by flags; a write elsewhere (for example a default log in the binary's directory) is not ruled out, so `--log-file` is set explicitly. |
| 5 | `--config-file` accepts `rpc-login=user:pass` | could not verify | https://docs.getmonero.org/interacting/monero-wallet-rpc-reference/ | Used so the login never reaches argv; if a version rejects it, wallet-rpc fails to start and the tool exits 10 (it fails closed). |
| 6 | wallet-rpc requires HTTP Digest auth | verified in-repo, live | `crates/swap-chain-xmr/src/monero_chain.rs:113` | Repo comment: confirmed live, plain and Basic are refused. |
