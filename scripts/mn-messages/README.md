# Masternode messages on the wire next to Divi Core

`run.sh` starts a fresh Divi Core 3.0.0 `divid` and a fresh irondivid on regtest, not connected to each other. It
sends the same masternode broadcasts (`mnb`), pings (`mnp`) and payment votes (`mnw`) to both from raw P2P peers
and compares, for each message:
- what the node took (`listmasternodes`, `getmasternodewinners`);
- the misbehaviour score of the sender (`getpeerinfo` banscore), and whether the sender was dropped;
- what a second raw peer was sent (the masternode invs and messages), and what the sender got back (invs, and
  `dseg` asking for a masternode).

Each row prints one line:
- `PASS`: same as divid;
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not, a `KNOWN` row that differs in another way, or a `KNOWN` row that now matches
  divid (the list below is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 45
minutes).

```sh
scripts/mn-messages/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a build of this tree
cargo build -p irondivid
scripts/mn-messages/run.sh target/debug ~/divi-3.0.0/bin 53700 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` on 127.0.0.2 (divid p2p and RPC, then irondivid's). The raw
  peers connect from 127.0.0.10 (the second peer) and 127.0.0.12 upwards, one address per row, so a ban in one row
  does not touch the next.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 30 minutes, most of it waiting until the test masternode is 25 minutes old so that it may vote
(masternode-payments.cpp:557-558). However it ends, both nodes are stopped and their directories deleted. Needs bash
and python3 (standard library only; signing, RIPEMD-160 and secp256k1 are done in the script).

Secrets:
- RPC credentials are made at random per node, kept in the 0600 `divi.conf`.
- **Keys:** the collateral key, the masternode key and a stranger's key are throwaway regtest keys made at random by
  the script. They live only in its memory: they are never printed, written to a file or put on a command line. The
  nodes see only the collateral key's address (`sendtoaddress`) and the signed messages.
- The collaterals are regtest coins each node mines itself.

## Setup

Each node mines 31 blocks and pays four copper collaterals (100 DIVI on regtest) to the collateral key:
- `mn1`, the test masternode;
- `spare`, the target of the refused broadcasts;
- `spent`, spent again by a transaction the script signs;
- `young`, with 3 confirmations.

Each node then mines to height 126. Blocks mined in a burst carry times ahead of the clock, so broadcasts are signed
no earlier than the 15th-confirmation block (masternodeman.cpp:221-227).

## Rows (Core paths under `divi/src/`)

| rows | what divid does |
|---|---|
| a broadcast with a bad signature before any block is mined | nothing: no masternode message is read until the tip is at most ten minutes old, which then holds (MasternodeModule.cpp:371-382, MasternodeHelpers.cpp:27-66) |
| a good broadcast; the same again; getdata for it; getdata for unknown items | taken and announced by inv 14 to every peer, the sender too; the same hash again is ignored; getdata gets the broadcast, an unknown item `notfound` (masternodeman.cpp:420-502, main.cpp:165-212, :322-345) |
| a newer broadcast within five minutes; an older one | not taken: the entry keeps its ping; an older one is refused (masternodeman.cpp:51-55, :267-307) |
| broadcasts signed two hours ahead, of tier 7, of protocol 70914, with a scriptSig, with a bad signature | refused; scores 1, 20, 0, 0 and 100 (dropped) (masternodeman.cpp:232-265) |
| a broadcast whose collateral pays another key; of a collateral with 3 confirmations; of a spent one; signed before the 15th confirmation | refused; 33, then 0 (masternodeman.cpp:57-74, :196-230) |
| a broadcast whose ping has a bad signature, is signed two hours ahead, names an unknown block or one 30 deep | refused; 33, 1, 0, 0 (masternodeman.cpp:309-375, :456-466) |
| a good ping; the same again; getdata for it | taken and announced by inv 15 (masternodeman.cpp:504-517) |
| pings a minute after the last, with a bad signature, two hours ahead or ago, naming an unknown block or one 30 deep, of a masternode not in the list | not taken; 0, 33, 1, 1, 0, 0, 0; a bad signature and an unknown masternode also get the sender a `dseg` for it (masternodeman.cpp:519-534, masternode-sync.cpp:456-462) |
| votes of a masternode younger than 25 minutes, of one not in the list (a `dseg` back), for a height 30 ahead | not taken (masternode-payments.cpp:203-248, :548-620) |
| after the wait: a good vote; the same again; getdata for it; a second payee from the same masternode; a bad signature (a `dseg` back); a payee not in the queue | taken and announced by inv 7, then as listed (masternode-payments.cpp:203-331) |
| a newer broadcast after five minutes; getdata for it | updates the entry, announced with its ping; not kept as seen, so `notfound` (masternodeman.cpp:288-307) |
| a restart of both, on the same data directories | the winners at the voted heights are the same as before the stop: the votes are written to mnpayments.dat at the stop and read back at the start (init.cpp:376, MasternodeModule.cpp:269-297) |

Not in Divi Core 3.0.0, so not checked: a rule on the masternode's port, and a 10000-block rule.
`CMasternode::IsValidNetAddr` is never called (masternode.cpp:229-235).

## KNOWN differences

None. With only raw peers neither node's masternode sync gets past its first stage (SPORKS, 1;
masternode-sync.cpp:437-440), so both take a vote's payee without the queue check and charge nothing for a bad vote
signature (masternode-payments.cpp:241-245, :320-328).

## Proving a difference is caught

`MN_MESSAGES_INJECT=<row name>` replaces irondivid's value in that row, which must then FAIL. Or run the base
build of 532e853, which fails 43 rows.
