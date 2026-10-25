# Vaults staking for their owner, next to Divi Core

`run.sh` starts four regtest nodes on one chain:
- Divi Core 3.0.0's `divid` as a vault owner (it mines) and as a vault manager (`vault=1`);
- an irondivid owner and an irondivid manager, restored from the two divid phrases, so each irondivid wallet holds
  the same keys as its divid twin and sees the same vault coins.

The managers stake the owner's vault coins in turn with `setgenerate`, and the run compares the coinstakes, the
rewards, the owner's and the manager's views and `getstakingstatus`, with every block checked on all four nodes.
Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 10 minutes).

```sh
scripts/vault-staking/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/vault-staking/run.sh target/release ~/divi-3.0.0/bin 53950 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+7` on 127.0.0.2, the p2p and RPC port of the divid owner, the
  divid manager, the irondivid owner and the irondivid manager. The divid owner listens; the others dial it.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 5 minutes and is stopped after 10 minutes. However it ends, all four nodes are stopped and their
directories deleted. Needs bash and python3 (standard library only). The two phrases are read from the divid nodes'
`dumphdinfo` replies and handed to irondivid in its environment (`WALLET_MNEMONIC`); the wallet passphrase of the
locked rows is random and lives only in memory. None of them is printed, written to a file or put on a command line.

## Why one chain with twin wallets

A mixed network, one chain: the divid manager's blocks are validated by both irondivid nodes and the irondivid
manager's by both divid nodes, so a block one side refuses shows at once (every `accepted by all four nodes` row).
The twins hold the same keys, so the owner's and the manager's views are compared value for value, as in
`scripts/wallet-replies` and `scripts/vault-replies`. Two separate networks would give two chains whose stakes
fall at random and could not be compared block by block.

## Steps

1. divid's owner mines 101 blocks; an owner address per vault, the manager address and a destination are taken
   from divid and given to the irondivid twins (`setaccount`).
2. **Before any vault:** `getstakingstatus` on each pair; `addvault` with an unknown funding transaction;
   `removevault` of a vault never added.
3. **Round 1:** vault 1 gets three coins of 1000 DIVI from divid's owner, each in its own transaction (the first
   one confirmed and given to `addvault` on both managers, then `addvault` again); 25 blocks; divid's manager
   stakes one block. Views and status before and after.
4. **Round 2:** both managers `removevault` vault 1 (and again); vault 2 gets three coins the same way, from
   irondivid's owner; irondivid's manager stakes one block. Its coinstake is compared with round 1's.
5. **The owner withdraws** from vault 2 (two more coins of 500 first, so each side's call has a confirmed coin):
   `debitvaultbyname` part while vault 2 is managed, `reclaimvaultfunds` part; then `removevault` vault 2 and
   `debitvaultbyname ... sweep_funds`.
6. **Vault 3** funded; both managers restart, then restart with `-reindex`; after each, `removevault` of vaults 1
   and 2 again (see KNOWN), views and status.
7. **Locked:** both managers `encryptwallet` (divid stops and is started again); `getstakingstatus`;
   `setgenerate 1`; `walletpassphrase <pw> 600 true` (staking only); `getstakingstatus`; divid's manager stakes
   vault 3; `removevault` vault 3; vault 4 funded the same way; irondivid's manager stakes it; the two compared.

A stake is never made at a lottery or treasury height (every 10th from 101, every 50th from 102: the block is
mined by the owner instead), so each coinstake holds only the vault's payout.

## Rows

| row | what is compared |
|---|---|
| the stakes (rounds 1/2, staking only 3/4) | the coins it spends (the round's three coins, combined into one input set as divid's CombineUtxos does, PoSTransactionCreator.cpp:172-210), the output roles (an empty output, then the round's vault script), whether the vault output is the inputs plus divid's stake reward for the height (stake and masternode parts of the block value less the lottery part, LegacyBlockSubsidies.cpp:15-90, regtest halving every 100 blocks), `staking status` right after the call, and whether every node accepted the block |
| the two stakes' amounts | for rounds 1 and 2 (one subsidy period): every input and output value |
| `block <h> ... accepted by all four nodes` | the four tips equal after the stake |
| `the stake after removevault spends no coin of vault 1` | the round-2 coinstake's inputs |
| `getstakingstatus` (each pair, at every step) | every member and value except `mnsync` (own row) and `staking status` (it says whether the node tried to stake in the last minutes, so it is compared right after each manager's own `setgenerate`); the members' order as sent; `staking status text` as irondivid's extra member |
| `getbalance`, `listunspent`, `listtransactions * 100 0 true`, `listsinceblock <block before the step> 1 true`, `getcoinavailability` (each pair) | every field and value, list items sorted by txid/vout |
| `addvault`, `removevault` | the replies, good and bad (unknown funding, added twice, removed twice, a vault never added) |
| `debitvaultbyname`, `reclaimvaultfunds` | the replies (txids masked) |
| `locked manager: setgenerate` | the outcome |

## KNOWN differences

- `getstakingstatus` member order: irondivid's members are in name order (docs/divid-differences.md R6).
- `getstakingstatus`: irondivid adds `staking status text`, the string it gave before the member became a bool
  (docs/rpc-parity-audit.md: getstakingstatus).
- `getstakingstatus mnsync (divid's masternode sync not finished)`: open: irondivid has no masternode sync and
  counts it finished once the chain is synced; divid gives false on a regtest node until its masternode sync times
  out (rpcmisc.cpp:1068; the same gap as `mnsync status` in scripts/net-replies). The row is a PASS once both say
  true.
- `getcoinavailability`: irondivid adds `total_vaults` and `vaults` (also KNOWN in scripts/vault-replies).
- `manager listtransactions * 100 0 true (a removed vault's records)`: open: after `removevault`, divid still lists
  the records of the removed vault's coins until it restarts (removevault drops the script from memory only,
  wallet.cpp:707-716); irondivid drops them at once.
- `removevault vault 1/2 again (divid manages it again)`: open: after a restart or `-reindex` divid reads the
  removed vault back from its wallet file and manages it again (the same wallet.cpp:707-716). The run removes it
  again on both, so the rows after compare like with like.
- `locked manager: setgenerate`: divid's locked wallet throws from key derivation (`CWallet::GetKey`,
  wallet.cpp:544) and the RPC layer returns that text as -1 "GetKey: DecryptHDChainSeed failed"; irondivid answers
  -25 "failed to generate a valid block", as divid does when it finds no stake.

No other row differs from divid.

## Proving a difference is caught

`VAULT_STAKING_INJECT=<row name>` changes irondivid's reply of that row before it is compared, e.g.
`VAULT_STAKING_INJECT='vault 1: addvault'`: that row prints `FAIL` and the run exits 1.
`VAULT_STAKING_DUMP=<dir>` writes both replies of every row that differs to `<dir>`.
