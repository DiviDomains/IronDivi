# Where irondivid knowingly differs from divid

irondivid follows Divi Core 3.0.0's `divid` (tag v3.0.0, commit 9e2f76c). The rows below are the places where it
differs on purpose. Each row names what divid does, what irondivid does, why the difference is kept, and the test
that pins it: a change that removes or alters a difference fails that test, and should update this page too.

Core paths are under `divi/src/` of the Divi Core source. IronDivi paths are from the repository root.

## Start-up

| # | divid | irondivid | Why | Pinned by |
|---|---|---|---|---|
| S1 | Keeps an option it does not know and says nothing (Settings.cpp:130-150) | Starts as well, and logs `Unknown option -<name>; ignored`, naming a `-no<name>` as written (bin/irondivid/src/main.rs:638-644, bin/irondivid/src/settings.rs) | A typo in `divi.conf` would otherwise go unnoticed; the node still starts as divid does | `bin/irondivid/tests/divid_differences.rs` `unknown_and_unsupported_options_start_with_a_log_line`, `negated_unknown_option_is_named_as_written` |
| S2 | Uses options such as `-dbcache`, `-checklevel`, `-createwalletbackups` | Accepts them, logs `Option -<name> is not supported by irondivid; ignored` (bin/irondivid/src/main.rs:266, :635) | They tune parts irondivid does not have (Berkeley DB, LevelDB cache, level-3 check) or keeps fixed at Core's default | same test |
| S3 | `-masternode=<alias>` runs the node as that masternode of `masternode.conf` (MasternodeModule.cpp:163-190) | Refuses to start: `irondivid does not run as a masternode; remove the masternode= line to start it` (bin/irondivid/src/main.rs:626-633) | irondivid does not run a masternode; starting as a plain node would leave the owner believing the masternode runs | `bin/irondivid/tests/divid_differences.rs` `masternode_option_is_refused` |
| S4 | Wallet seed only from `-mnemonic`, `-mnemonicpassphrase`, `-hdseed` (wallet.cpp:2286-2304) | The same options, and when an option is absent the environment variables `WALLET_MNEMONIC`, `WALLET_MNEMONIC_PASSPHRASE`, `WALLET_HDSEED` (bin/irondivid/src/main.rs:1005-1011) | Keeps a phrase off the command line and out of `divi.conf`; the options win, so divid's way works unchanged | `bin/irondivid/tests/move_from_core.rs` (starts with `WALLET_MNEMONIC`), `bin/irondivid/src/main.rs` `wallet_move_tests::hex_seed_restores_cores_first_address` |
| S5 | Opens a `wallet.dat` (Berkeley DB) in the data folder | Does not read a Core `wallet.dat`: a `-wallet` pointing at one, or a Core data folder, is refused with a plain message; a `wallet.dat` beside its own wallet is named in the log (bin/irondivid/src/core_files.rs:32-112) | irondivid's wallet is a RocksDB folder; it never opens or writes a Core file, and says what to do instead (phrase or `dumpprivkey` / `importprivkey`) | `bin/irondivid/tests/move_from_core.rs` `wallet_option_at_a_core_wallet_file_gives_a_plain_message`, `wallet_dat_in_the_datadir_is_named_in_the_log`, `core_datadir_is_refused_and_left_alone` |
| S6 | Shrinks `debug.log` at start when it is large (Logging.cpp:94, :191, :206) | Rotates `debug.log` by size while running: `debug.log.1` ... up to `-maxlogfiles` (bin/irondivid/src/main.rs:726, :755) | A long-running node never grows one file without bound | `bin/irondivid/src/main.rs` `log_rotation_tests::log_rotation_writes_new_debug_log_within_limits`, `log_rotation_rotates_oversized_log_at_startup` |

## Peers

| # | divid | irondivid | Why | Pinned by |
|---|---|---|---|---|
| P1 | Retries `-addnode` / `addnode add` peers every 120 s (net.cpp, ThreadOpenAddedConnections: `MilliSleep(120000)`) | Retries them on its maintenance pass every 30 s while outbound slots are free (crates/divi-network/src/peer_manager.rs:1026-1027) | Same rule (one connection per address, skipped while that IP has a peer); only the timing differs, so a node reconnects sooner | `crates/divi-node/tests/peer_dial.rs` `added_node_is_not_dialled_while_a_peer_from_its_ip_is_connected` (expects the dial within 35 s) |
| P2 | No built-in static peers; peers come from DNS seeds, `-addnode`, `-connect` and `peers.dat` | Has built-in static peers per network (crates/divi-node/src/config.rs:234-262, crates/divi-network/src/peer_manager.rs:1076-1095), dialled under the `-addnode` one-per-IP rule, not divid's one-per-/16 outbound rule | irondivid keeps no `peers.dat`; the built-in list lets a node find the network when DNS seeds fail | `crates/divi-node/src/config.rs` `peer_sources_default_uses_builtin_peers_seeds_and_listens`, `crates/divi-node/tests/peer_dial.rs` `addnode_entries_on_one_ip_are_dialled_once` |

## RPC

| # | divid | irondivid | Why | Pinned by |
|---|---|---|---|---|
| R1 | No `estimatefee` / `estimatesmartfee` (absent from rpcserver.cpp's table, :324-467) | Both answer, never below the relay floor (crates/divi-rpc/src/server.rs:651-652, crates/divi-rpc/src/lite_wallet.rs:271, :285) | BasicSwap calls them to price its transactions | `crates/divi-rpc/tests/divid_differences.rs` `fee_estimates_exist`; `crates/divi-rpc/src/lite_wallet.rs` `test_estimate_smart_fee` |
| R2 | `loadwallet` loads another wallet at run time (rpcserver.cpp:439) | Refused with a message naming `--wallet` and the wallet in use (crates/divi-rpc/src/wallet.rs:2824, server.rs:623) | irondivid opens one wallet at start and keeps it until it stops | `crates/divi-rpc/tests/divid_differences.rs` `loadwallet_is_refused`; `crates/divi-rpc/src/wallet.rs` `loadwallet_refusal_names_the_real_option_and_current_wallet` |
| R3 | `getblockchaininfo`: chain, blocks, headers, bestblockhash, difficulty, chainwork (rpcblockchain.cpp:445-452) | The same, plus mediantime, pruned, pruneheight, winnersstripheight, fullhistorypeers, lastblockfetch, snapshotbase, warnings (crates/divi-rpc/src/blockchain.rs:583-630) | They report pruning, block expiry and snapshot state, which divid does not have; readers that ignore unknown members are unaffected | `crates/divi-rpc/tests/divid_differences.rs` `getblockchaininfo_has_fields_divid_lacks` |
| R4 | `getwalletinfo` without walletname, keypoololdest, paytxfee, hdmasterkeyid (rpcwallet.cpp:2873-2907) | Adds those four (crates/divi-rpc/src/wallet.rs:776-830) | Tools written for other Bitcoin-family wallets read them | `crates/divi-rpc/tests/divid_differences.rs` `getwalletinfo_has_fields_divid_lacks` |
| R5 | `getinfo` and `getnetworkinfo` report version 3.0.0.0 and divid's protocol version (rpcmisc.cpp:138-139, rpcnet.cpp:369-372) | `getinfo` reports 3.0.0.0; `getnetworkinfo` reports irondivid's own version (`<crate version>.0`); both report protocol version 70920 (crates/divi-rpc/src/server.rs:439, crates/divi-rpc/src/network.rs:62-64, crates/divi-network/src/constants.rs:46) | `getinfo` keeps what scripts compare against; `getnetworkinfo` names the software actually running; 70920 is the peer protocol irondivid speaks | `crates/divi-rpc/tests/divid_differences.rs` `versions_name_irondivid` |
| R6 | Members of a result in the order divid inserts them (json_spirit Object) | In name order (serde_json without `preserve_order`, Cargo.toml) | JSON readers do not depend on member order; switching the whole workspace's JSON maps is a larger change than the difference | `crates/divi-rpc/tests/divid_differences.rs` `result_members_are_in_name_order` |
| R8 | `gettxoutsetinfo` bytes_serialized / hash_serialized over Core's per-transaction coin serialization (txdb.cpp:105) | transactions, txouts and total_amount as divid; bytes_serialized and hash_serialized over irondivid's own UTXO records (crates/divi-storage/src/database.rs:585) | irondivid stores one record per output; the counts and total are what compare across implementations | `crates/divi-storage/tests/divid_differences.rs` `utxo_stats_are_over_irondivis_own_records` |
| R9 | `setgenerate` on regtest stakes from the current time and answers -25 "failed to generate a valid block" until the clock passes the median time of the last blocks (rpcmining.cpp:110) | Starts the block-time search past the median time, so blocks made back to back succeed (crates/divi-node/src/staker.rs:831-833, :881-883) | BasicSwap's regtest tests mine many blocks in a row; only regtest, no chain or wallet rule changes | `bin/irondivid/tests/setgenerate.rs` `setgenerate_mines_pow_then_pos` (five proof-of-stake blocks back to back) |
| R10 | `addvault` of a funding output that is already spent is added (with `-vault=1`) | Refused -4 "...the vault output of transaction X is already spent" (crates/divi-rpc/src/wallet.rs:2300) | That coin can never stake; adding it would show a balance that is not there | `crates/divi-rpc/tests/vault_rpc.rs` `addvault_refuses_spent_funding_output`, `addvault_refuses_funding_output_spent_in_mempool` |
| R11 | Vault RPCs need `-vault=1`; without it `addvault` answers -32600 "AddingVaultScript: Unable to sync TX!" (wallet.cpp:152, :693-706) | No `-vault` switch: the vault RPCs always work | irondivid's wallet always tracks vaults; a switch would only add a way to fail | `crates/divi-rpc/tests/vault_rpc.rs` (every vault test runs without a switch) |
| R12 | `dumphdinfo`: hdseed, mnemonic, mnemonicpassphrase (rpcdump.cpp:221-233) | The same, plus `hdaccountpath` (`m/44'/<coin type>'/0'`) (crates/divi-rpc/src/wallet.rs:3623-3672) | Shows the coin type, so a restore elsewhere uses the same path (older testnet wallets keep 301 where divid uses 1) | `crates/divi-rpc/tests/wallet_move.rs` `dumphdinfo_names_the_account_path` |
| R13 | `getblock` verbose: true or false only; another type is -1 "value is type int, expected bool" (rpcblockchain.cpp:216) | Also takes 0, 1 and 2, verbosity 2 giving the transactions decoded (crates/divi-rpc/src/blockchain.rs, `get_block`) | Tools written for Bitcoin Core ask for verbosity 2; true and false answer as divid does | `crates/divi-rpc/tests/divid_differences.rs` `getblock_takes_a_verbosity_number`; `crates/divi-rpc/tests/getblock_verbosity.rs` |

## Wallet files

| # | divid | irondivid | Why | Pinned by |
|---|---|---|---|---|
| W1 | `backupwallet` writes a copy of `wallet.dat`; to a folder, as `<folder>/wallet.dat` (walletdb.cpp:601-624) | Writes a consistent copy of the wallet folder (a RocksDB checkpoint, then copied); to a folder, as `<folder>/wallet` (crates/divi-wallet/src/wallet_db.rs:1168) | The wallet is a folder, not a file; the copy is taken so writes running meanwhile are all in it or not at all | `crates/divi-rpc/tests/wallet_move.rs` `backup_into_folder_and_again`, `backup_taken_while_wallet_writes_opens` |
| W2 | Start-up and monthly backups are files `backups/wallet.dat.<time>` and `monthlyBackups/wallet.dat.<time>` (WalletBackupCreator.cpp:56-75) | The same places, counts and times, each backup a folder `wallet.<time>` (crates/divi-wallet/src/backup.rs:153) | Same reason as W1 | `crates/divi-wallet/src/backup.rs` `start_up_backups_are_pruned_to_the_count`; `bin/irondivid/src/main.rs` `wallet_move_tests::start_makes_wallet_backups` |

## Not listed here

Differences that are not choices (work not done yet, or replies that are only shorter or longer texts) are kept with
the work that found them, not here: for example `getrawmempool` priorities reported as 0, `gettxout` `version`
always 1, `listtransactions` order among transactions of one block, help texts for wrong argument counts, the
masternode messages (`mnb`, `mnp`, `mnw`) and a full send queue going unscored (irondivid does not check masternode
signatures or collateral, and its send queue counts messages, not divid's bytes), and the `-txindex` change message
naming a `-reindex` irondivid does not have.
