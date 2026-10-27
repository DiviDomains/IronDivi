# wallet-finality

What the wallet does with transactions that are not final yet, Divi Core 3.0.0
divid next to irondivid on one regtest network.

    scripts/wallet-finality/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

Ports `<port-base>` .. `<port-base>+5` on 127.0.0.2. divid A listens, mines and
pays; divid B and irondivid I dial A, both with `-spendzeroconfchange`. Each RPC
password is a fresh `secrets.token_hex` written only to that node's 0600
`divi.conf`. The work directory is removed and every node stopped however the
run ends.

B and I get the same coins and do the same things, so their wallet replies are
compared value for value, each transaction named by its role:

1. transactions locked above the next block (height tip+1, tip+5, time now+1h):
   `sendrawtransaction`, `gettransaction`, the mempool, the wallet replies;
2. a payment from A, one to A and one to itself, locked at the tip height
   (final for the next block, not at the tip): the replies in the mempool and
   after the block;
3. a payment from A and one to itself time-locked a minute ago, with the
   node's clock set ten minutes before the lock (`setmocktime`): in the mempool
   and mined;
4. a payment from A and one to itself locked at height L and mined at L+1;
   A stops, B and I `invalidateblock` block L, so both are back in the mempool
   and cannot go in the next block: the replies, a `sendtoaddress` that needs
   the coin of the one to itself, then each node's next two blocks.

The replies: `getbalance` (no argument, `"*"`, `""`, an account, minconf 0 and 1),
`getunconfirmedbalance`, `getwalletinfo` balances, `listunspent 0` and `1`,
`getreceivedbyaddress`, `getreceivedbyaccount`, `listreceivedbyaddress 0` and
`1`, `gettransaction` and `listtransactions` of each transaction, the mempool.

PASS: the same as divid. KNOWN: a difference kept on purpose, listed below.
FAIL: anything else. The exit code is the number of FAILs.

## KNOWN

- `3 time lock behind the clock, mined: listunspent 0` and `listunspent 1`:
  divid's AvailableCoins checks finality for confirmed coins too
  (AvailableUtxoCalculator.cpp:84), so while its clock reads before a mined
  transaction's time lock it hides that coin from listunspent, sends and the
  staker. The coin is in a block, so a transaction spending it can be mined;
  irondivid keeps it listed and spendable.
