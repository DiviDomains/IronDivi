# Transaction refusals next to Divi Core

`run.sh` starts a fresh Divi Core 3.0.0 `divid` and an irondivid restored from divid's phrase on one regtest chain,
makes a set of raw transactions on divid, sends each to both nodes, and compares how each node refuses it (or takes
it): through `sendrawtransaction`, through the wallet, and as a `tx` from a raw p2p peer. Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 10 minutes).

```sh
scripts/reject-replies/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/reject-replies/run.sh target/release ~/divi-3.0.0/bin 53950 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` on 127.0.0.1 (divid p2p and RPC, then irondivid's).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes 20 to 30 seconds and is stopped after 10 minutes. However it ends, both nodes are stopped and their
directories deleted. Needs bash and python3 (standard library only). The phrase is read from divid's `dumphdinfo`
reply and handed to irondivid in its environment (`WALLET_MNEMONIC`). A private key (for the wrong-key case) and the
wallet passphrase live only in memory and RPC messages. None of them is ever printed, written to a file or put on a
command line.

## Nodes and steps

Both run with `staking=0` and Core's default policy (no `acceptnonstandard`).

1. divid listens and irondivid dials it (`connect=`). divid mines the 100 work blocks of regtest
   (`chainparams.cpp:405`), sends 10 DIVI to each of 18 addresses of its wallet and 200 DIVI to one more, and mines
   a stake block. Then one coin is spent in a second stake block.
2. irondivid is stopped and started again alone: `listen=1` for the raw peer, and `connect=` to an address nothing
   listens on. From here a transaction one node takes is not relayed to the other, so each is sent to each node on
   its own.
3. The `sendrawtransaction` rows, the p2p rows, then the wallet rows. `encryptwallet` runs on both before the
   locked-wallet rows.

The raw transactions are serialized by `check.py`. divid's `signrawtransaction` signs those that need a signature.
Each case a node could take spends a coin of its own, so a transaction one case gets into the mempool does not
change another case.

## Rows

How a `sendrawtransaction` row compares: the same reply (the txid, or an error with the same code and message), and
the same answer to "is the transaction in this node's mempool now".

| case | the transaction |
|---|---|
| unsigned | a spend with an empty scriptSig |
| bad signature | a signed spend with 1 satoshi more out after signing |
| wrong key | the coin's spend with the signature and public key of another key |
| missing inputs | an input of an unknown transaction |
| input spent in the chain | a second spend of a coin a block spent |
| valid | a signed spend with a fee of 0.001 DIVI (taken by both) |
| double spend of a mempool input | another spend of the coin `valid` spends |
| already in the mempool | `valid` again |
| already in the chain | the spend confirmed in step 1 |
| no fee, fee of 100 satoshis | below the relay fee (10000 satoshis per kB) |
| absurd fee | 150 DIVI of fee (the maximum is 100): no flag, `allowhighfees` false, `allowhighfees` true |
| dust output | an output of 5000 satoshis (the dust threshold is 5460) |
| non-standard output script | `OP_TRUE` |
| OP_META of 604 / 603 bytes | one byte over the size divid relays, and at it (`defaultValues.h:40`) |
| two OP_META outputs | |
| oversize | 3000 outputs, over 100000 bytes |
| negative output, output over the money supply, outputs past the int64 range | -1 satoshi; 2^62 satoshis; two of 2^62 |
| duplicate inputs, no inputs, no outputs | |
| non-final locktime | a lock time 100 blocks ahead, sequence 0 |
| immature coinbase spend, immature coinstake spend | the coinbase of block 100 and the coinstake of the tip, both under the 20 blocks of maturity |
| not hex, odd length, truncated, trailing bytes, empty | the hex of a signed spend, cut or with a byte added (divid reads the transaction and leaves the extra byte: taken by both) |

p2p rows: a raw peer connects to each node, does the handshake and sends the transaction as `tx`. The row compares
the `reject` the node sends back within 5 seconds (command, code, reason, txid) or that none comes, and that the
transaction is not in the mempool. The cases are `dust output`, `non-final locktime` (both 64, no misbehaviour score)
and `unsigned` (no reject: the refusal leaves no reject state). They run in that order, so no peer is banned before
the last.

Wallet rows: `sendtoaddress` with a dust amount, an amount over the balance, zero, a negative amount and a bad
address; then, with the wallet encrypted and locked, `sendtoaddress`, `sendmany` and `sendrawtransaction` (which needs
no key); `getbalance * 0` after all of it.

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c). The refusals come from
`sendrawtransaction` (`rpcrawtransaction.cpp:828-893`), `MempoolConsensus::AcceptToMemoryPool` and `IsStandardTx`
(`MempoolConsensus.cpp`), `CheckTransaction` (`BlockCheckingHelpers.cpp:98-140`) and the `reject` sent for a `tx`
(`main.cpp:803-809`).

## KNOWN differences

None. Every row matches divid.

## Proving a difference is caught

`REJECT_REPLIES_INJECT=<row name>` changes irondivid's reply of that row before it is compared (an error gets text
added to its message), e.g. `REJECT_REPLIES_INJECT='sendrawtransaction dust output'`: that row prints `FAIL` and the
run exits 1. `REJECT_REPLIES_DUMP=<dir>` writes both replies of every compared result row to `<dir>`, for looking
into a FAIL.
