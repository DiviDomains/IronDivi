# Coin selection, fee and change next to Divi Core

`run.sh` builds one regtest chain with Divi Core 3.0.0 `divid`, an irondivid restored from divid's phrase, and a
second divid with a wallet of its own (the miner).

- **Setup:** the miner pays the twins a set of coins with known values, accounts and depths, and the nodes stop.
- **Each scenario:** a send is made on a fresh, unconnected copy of each twin's datadir.
- **Compared:** what each twin built — the coins it spent, the payees, the change and the fee.

Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 10 minutes).

```sh
scripts/coin-select/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/coin-select/run.sh target/release ~/divi-3.0.0/bin 54150 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+5` on 127.0.0.2. The setup's three nodes use them all; the
  copies use the first four. `<port-base>+9` is used as a peer that does not exist.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about a minute and is stopped after 10 minutes. However it ends, every node is stopped and every
directory deleted. Needs bash and python3 (standard library only).

**The phrase:** read from divid's `dumphdinfo` reply and handed to irondivid in its environment
(`WALLET_MNEMONIC`) at its first start only. It is never printed, written to a file or put on a command line.

**Switches:**

- `COIN_SELECT_INJECT=<row name>` changes irondivid's reply of that row before it is compared, so the row FAILs.
- `COIN_SELECT_DUMP=<dir>` writes both replies of every row that is not PASS into `<dir>`.

## How divid selects coins

Every send RPC of divid 3.0.0 goes through `createCoinSelectionAlgorithm` (`rpcwallet.cpp:705-719`). This covers
`sendtoaddress`, `sendmany`, `sendfrom`, `fundvault`, `reclaimvaultfunds` and `debitvaultbyname`. The selector is
`AccountCoinSelector`, or `VaultCoinSelector` for vault sends, both wrapping `MinimumFeeCoinSelectionAlgorithm`
(`MinimumFeeCoinSelectionAlgorithm.cpp:40-147`).

`StochasticSubsetSelectionAlgorithm` (`SelectCoinsMinConf` and its 1/6, 1/1, 0/1 confirmation tiers) and
`CoinControlSelectionAlgorithm` are built but used nowhere outside Core's unit tests (`test/wallet_tests.cpp`); the
source has no Qt wallet. No RPC reaches them, so there is no stochastic path to compare.

**The minimum-fee selection** is deterministic:

- **The coins:** `AvailableCoins` gives the confirmed, mature, unlocked coins, in the wallet map's order (by txid,
  then output). With `-spendzeroconfchange` it adds the unconfirmed coins whose inputs are all the wallet's
  (`AvailableUtxoCollector.cpp:26-35`). Vault coins are only for vault sends.
- **The order:** `std::sort` with Core's priority.
  - For vault change, the least confirmed coin comes first.
  - Of two coins that each cover the need alone, the smaller scriptSig comes first.
  - Otherwise the larger value net of its own input fee comes first.
  - Coins ranked alike come where libstdc++'s introsort leaves them, which is fixed for a given input order.
- **Taking coins:** in that order until they cover the payments, a non-dust change (5460 sat) and the fee.
- **The fee:** the minimum relay fee (10000 sat/kB) of an estimate, never of the signed transaction. The estimate is
  the payee outputs with no inputs, plus 34 bytes of change (59 for vault change), plus 148 bytes per P2PKH input.
- **Dust change** (under 5460 sat for P2PKH) goes to the fee.
- **`receiver_pays` and `sweep_funds`** take the fee from the payees (`wallet.cpp:1647-1697`).

**The rows compare:**

- the outcome (txid, or the error code and message);
- the coins spent, by the names the setup gave them, and their depths;
- the payees (type, amount, who);
- the change (type, amount, address);
- the fee (inputs less outputs);
- `gettransaction`'s `fee`;
- whether the fee covers 10 sat per byte of the signed transaction.

**Not compared, because divid makes them at random:**

- where the change output goes (`AttachChangeOutput`, `wallet.cpp:1626-1632`, a random index);
- the order of the inputs, which comes from a `std::set` ordered by the address of each coin's wallet transaction
  in memory (`Output.h:23-27`).

For the same reason the signed sizes differ by a byte or two between the twins, as each signature is 71-73 bytes. The
fee does not depend on them. Each scenario prints its fee, size and rate on both nodes in a `#` line.

## Setup

1. The miner makes 100 work blocks and 5 stake blocks, and hands out the payee addresses DEST, Z and M0..M11.
2. The twins hand out the same addresses, one per coin, with the accounts below.
3. **One miner transaction pays:**
   - the default account: 1000, 50, 30, 20, 10, 10 and 7;
   - `small`: ten coins of 0.1;
   - `dust`: 7;
   - `exact`: 3;
   - `chg`: 100.
4. The miner funds two vaults the twins own (owner key of the twins, manager key of the miner): 200, then 6 blocks
   later 100.
5. **Later coins:**
   - one more default 10, in a transaction of its own, a block later;
   - `young`: 1, 2, 3, 4 and 5, one block apart, so they end at depths 5 to 1.
6. **Unconfirmed coins:**
   - divid sends 1 from `chg`, which leaves its change unconfirmed (irondivid takes the change key out of its pool,
     as divid's send did);
   - the miner pays `unconf` 50 without a block.
7. The twins' `listunspent 0` must match (a setup row).

## Scenarios

| call | forms |
|---|---|
| `sendtoaddress DEST` | 5 (many coins each cover it alone: a tie); 900 (one coin covers it); 1080 (none does); 1150 (needs the young coins); 1300 (more than the confirmed coins); 1180 (only with the unconfirmed change), without and with `-spendzeroconfchange`; 5 with `-spendzeroconfchange`; 0.00005 (dust); 5 and 900 `receiver_pays`; 1 `sweep_funds` |
| `sendmany ""` | `{DEST: 2, Z: 3}`; 12 payees of 1; 12 payees of 90 |
| `sendfrom` | `small` 0.55 (ten equal coins); `dust` 6.999926 (the change would be 5140 sat, dust) and 6.99992 (5740 sat, kept); `exact` 3 (the coin equals the amount, so there is no room for the fee); `young` 4.5 and 9; `unconf` 1 (only an unconfirmed coin); `""` 5 |
| vaults | `fundvault <vault> 20`; `reclaimvaultfunds DEST 50`, `50 receiver_pays`, `150` (more than the younger vault coin), `1 sweep_funds`; `debitvaultbyname <vault> DEST 50` |

## KNOWN differences

- **`sendmany "" ...: payee order`** (three rows):
  - divid writes the payees in the order of the request's JSON object (json_spirit keeps it, `rpcwallet.cpp:1724`).
  - irondivid parses the request with serde_json, which keeps an object's members in name order
    (`docs/divid-differences.md` R6), so the payees come in address order.
  - Each request lists its payees in descending address order, so the rows differ every run. The payees themselves
    (amounts, addresses) are compared as a set and are the same.

No other row differs from divid.

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c).
