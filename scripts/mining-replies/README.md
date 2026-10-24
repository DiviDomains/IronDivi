# Mining and mempool RPC replies, irondivid beside divid

This script makes the same mining and mempool RPC calls on Divi Core 3.0.0's `divid` and on `irondivid`, and compares the replies. Both nodes run on regtest and share one chain and one mempool. It compares result shape, member names and types, the values that should agree, and error code and text.

```
scripts/mining-replies/run.sh <irondivid-bin-dir> <divid-bin-dir> <port-base> [<datadir-root>]
```

- `<irondivid-bin-dir>`: the directory holding `irondivid`, for example `target/release`.
- `<divid-bin-dir>`: the directory holding Divi Core 3.0.0's `divid` (tag v3.0.0, commit 9e2f76c).
- `<port-base>`: the first of 4 consecutive free ports: divid rpc `base`, p2p `base+1`; irondivid rpc `base+2`, p2p `base+3`.
- `<datadir-root>`: where the temporary datadirs go (default `$TMPDIR` or `/tmp`).

## Output and exit code

Each call prints one row:
- `SAME`: the replies agree.
- `DIFFERS`: the row is followed by what differs and both replies. A difference kept on purpose names its row of `docs/divid-differences.md`.
- `ABSENT`: divid answers and irondivid does not have the method.

The run ends with the counts. The exit code is the number of rows that are neither `SAME` nor a kept difference. 255 means a usage error, or that the run went over 15 minutes. A trap stops both nodes and deletes the datadirs on every exit, including Ctrl-C. A run takes about two minutes.

It needs bash and python3 (standard library only).

## What is compared

- **What may differ between the nodes.** Values each node has its own of are left out of the comparison:
  - the `time` a transaction entered the pool;
  - block hashes, since each node mines its own block;
  - the order of the txid list in `getrawmempool`, since divid's map order means nothing.
- **Member order.** irondivid writes members in name order (difference R6), so it is not compared.
- **Help text.** A wrong argument count is answered with the method's help in both. The two help texts are worded differently, so such replies count as `SAME` when the code and the first (usage) line agree.

## What runs

1. **Start-up.** divid starts and mines 30 blocks with `setgenerate`. irondivid starts with `-connect` to divid and syncs.
2. **One mempool on both.** divid's wallet sends six transactions:
   - spends of coins from heights 1, 2, 7, 8 and 9, with fees from 3,000 satoshis to 0.01 DIVI;
   - a child of one of them paying 0.5 DIVI.

   irondivid gets them by relay.
3. **The calls, each on both nodes.**
   - Reading the pool: `getmininginfo`, `getmempoolinfo`, `getrawmempool` (no argument, `false`, `true`, and the wrong types and counts).
   - `prioritisetransaction`: a pool transaction and an unknown one, a short or non-hex txid, a fee as a string or a real, the wrong counts.
   - Methods divid does not have, which both nodes should refuse as unknown: `getblocktemplate`, `getnetworkhashps`, `generate`, `getblocksubsidy`, `getblockpayments`, `submitblock`, `getgenerate`, `gethashespersec`.
   - Mining, each node in turn on the shared tip: `setgenerate` with each argument form, and `generateblock` with each option (`extratx`, `coinstake`, `ignoreMempool`, `blockBitsShift`) and bad option types.
4. **Past block 100, proof of stake.** The same `setgenerate` and `generateblock` calls again. irondivid stakes with the coins it mined in step 3.

divid stops answering after `generateblock` with a custom coinstake (difference R14). The run then starts divid again on the same data directory, or makes that call last.
