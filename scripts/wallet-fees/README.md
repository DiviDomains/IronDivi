# Wallet fee settings, next to Divi Core

`run.sh` builds one regtest chain with Divi Core 3.0.0 `divid`, an irondivid restored from divid's phrase, and a
second divid with a wallet of its own (the miner), as `scripts/coin-select` does. For each fee setting it starts fresh,
unconnected copies of both twins with that setting, makes the same sends on both, and compares what each built.
Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 30
minutes).

```sh
scripts/wallet-fees/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/wallet-fees/run.sh target/release ~/divi-3.0.0/bin 54250 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+5` on 127.0.0.2. The setup's three nodes use them all; the
  copies use the first four. `<port-base>+9` is used as a peer that does not exist.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 10 minutes (each send starts its own pair of copies) and is stopped after 30. However it ends, every
node is stopped and every directory deleted. Needs bash and python3 (standard library only).

**The phrase:** read from divid's `dumphdinfo` reply and handed to irondivid in its environment (`WALLET_MNEMONIC`) at
its first start only. It is never printed, written to a file or put on a command line.

**Switches:** `WALLET_FEES_INJECT=<row name>` changes irondivid's reply of that row before it is compared, so the row
FAILs; `WALLET_FEES_DUMP=<dir>` writes both replies of every row that is not PASS into `<dir>`.

## How divid picks the fee

Core paths are under `divi/src/` of the Divi Core source at v3.0.0.

- A wallet send pays the relay fee rate, `-minrelaytxfee` (default 10,000 sat/kB, `defaultValues.h:38`), on an
  estimated size. The estimate is the outputs, plus 34 bytes of change and each input's signing bytes plus 40 (148
  for a P2PKH input), each part's fee rounded down on its own (`MinimumFeeCoinSelectionAlgorithm.cpp:47-96`,
  `FeeRate.cpp:35-43`, `SignatureSizeEstimator.cpp:23-60`). There is no fee estimate and no free transaction.
- Change that would be dust goes to the fee (`wallet.cpp:1700-1717`). A payment under the dust threshold at the
  current rate gives -4 `Transaction output(s) amount too small` (`wallet.cpp:1852-1854`).
- `-maxtxfee` (default 100 DIVI) caps the fee. A send whose fee would be over it finds no coins: -4 `Insufficient funds
  to meet coin selection algorithm requirements.` (`MinimumFeeCoinSelectionAlgorithm.cpp:97-99`). There is no message
  of its own. The same text is given for coins that cover the amount but not the fee and the room for non-dust change
  (`:75-77`, `wallet.cpp:1777-1779`).
- `-spendzeroconfchange` lets a send spend the wallet's unconfirmed change (`wallet.cpp:1848`).
- Options divid lists in its help but never reads: `-txconfirmtarget`, `-sendfreetransactions`
  (`LicenseAndInfo.cpp:135`, `:143`). Options it does not have at all: `-paytxfee`, `-mintxfee`. No call
  `settxfee` or `fundrawtransaction` (its command table, `rpcserver.cpp:425-464`).
- Spork 14 replaces the rate and the cap when a spork message arrives (`spork.cpp:253-257`, `:286-302`); a spork loaded
  from disk at start is not applied (`:192-211`). Spork 14 is compared by `scripts/spork-consensus`.

## Settings and rows

Settings, each a start option on both copies:
- no fee option;
- `-minrelaytxfee` 0.001 and 0.00001;
- `-maxtxfee` 0.0001 (the least divid takes: the relay fee for a kB, `init.cpp:840-842`), 0.00012, and 20 (over 10
  DIVI: a warning, `init.cpp:836-837`);
- `-paytxfee=0.001`, `-mintxfee=0.001`, `-txconfirmtarget=6`, `-sendfreetransactions=1`;
- `-spendzeroconfchange=1`.

For each setting:

| row | what is compared |
|---|---|
| `getinfo relayfee` | the rate the node uses |
| small: `sendtoaddress DEST 5`; large: `sendtoaddress DEST 900`; many payees: `sendmany` to 12 payees of 1; many inputs: `sendfrom "small" DEST 0.95` (ten coins of 0.1) | the outcome; for a send, the coins spent, the payees, the change, the fee from the transaction and from `gettransaction`. The size is printed, not compared: a signature is 71 to 73 bytes, and the change's position is random (`wallet.cpp:1626-1632`), which changes what is signed. The fee comes from the estimate, which is compared |
| a dust payment: `sendtoaddress DEST 0.0001` | taken at 10,000 sat/kB; refused at 0.001 DIVI/kB, where its dust threshold is higher |
| covers the amount, not the fee: `sendfrom "exact" DEST 3` | the account's one coin is 3 DIVI: -4 |
| `debug.log` | for `-maxtxfee=20`, divid's warning `-maxtxfee is set very high`; for the options divid does not read, whether the log names them |

Then, once: `settxfee` with 0, 0.001, 0.000001, 1000, -1 and `"abc"`: -32601 `Method not found` on both.

Not covered here: the sends of `scripts/coin-select` (coin choice, `receiver_pays`, `sweep_funds`, vaults),
`sendrawtransaction`'s fee cap (`scripts/fee-estimate`), and bad values of the options at start
(`scripts/start-errors`).

## KNOWN

| row | divid | irondivid | reason |
|---|---|---|---|
| `-paytxfee=0.001: debug.log names the option`, `-mintxfee=0.001: debug.log names the option` | False | True | divid keeps an option it does not know and says nothing (`Settings.cpp:130-150`); irondivid starts as well and logs `Unknown option -<name>; ignored` (`docs/divid-differences.md` S1). divid 3.0.0 has neither option: only help texts name paytxfee (`rpcmisc.cpp:123`, `LicenseAndInfo.cpp:143`) |
