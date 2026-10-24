# help and usage errors next to Divi Core

`run.sh` starts a fresh Divi Core 3.0.0 `divid` and irondivid on one regtest chain, and compares what both answer to:

- `help`, the list;
- `help <call>` for every call of divid's command table;
- `help` of an unknown call;
- every call given no arguments, and given one argument more than divid takes.

Then it does the same on a second pair of nodes started with `-disablewallet`. Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with `FAILS <n>`. The exit code is the number of FAILs. It is 255 for a usage error, an interrupted
run, or a run over 10 minutes.

```sh
scripts/help-replies/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/help-replies/run.sh target/release ~/divi-3.0.0/bin 54150 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` on 127.0.0.1 (divid p2p and RPC, then irondivid's).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

**Run time and clean-up.** A run takes about 15 seconds and is stopped after 10 minutes. However it ends, the nodes
are stopped and their directories deleted.

**Requirements.** bash and python3 (standard library only).

**Secrets.** No reply of a call that runs is printed or written, since `dumphdinfo`'s would hold the wallet's phrase.
Only help texts and errors are printed and dumped.

## Nodes and steps

1. **Wallet pass.** divid and irondivid each with their own new, unencrypted wallet; irondivid dials divid
   (`connect=`), and divid mines 5 blocks.
2. **The rows below,** with `stop` last (it stops both nodes).
3. **Second pass.** A second pair started with `disablewallet=1`, and the rows again (`disablewallet:` rows) for
   `help`, `getinfo` and the wallet calls.

## Rows

**How a row compares.**

- **Help texts and errors:** exactly, code and text.
- **Where divid runs the call** (no arguments where it takes none): only that irondivid runs it too, not the reply.
- **Sample addresses and hashes:** divid's help examples name them, and irondivid's texts write them `diviaddress`
  and `hash`. No address or hash of anyone's wallet is written in the tree. So both replies are compared, printed and
  dumped with each base58 word of 26-35 characters (with a digit and a letter) written `diviaddress`, and each run of
  40 or more hex digits written `hash`. That is the only change made to a text before it is compared.

**The rows.**

- **`help`, the list:** divid's list against irondivid's list up to its own sections, exactly. Then the calls divid
  lists that irondivid does not, and irondivid's own sections (KNOWN).
- **`help nosuchcall`, and `help` with two arguments.**
- **`help <call>`** for every call of the table, the hidden ones included.
- **`<call>` with no arguments, and `<call>` with one argument more than divid takes,** for every call that has a most.
  The arguments are `x`, a path in a directory that does not exist (`backupwallet`), or an empty passphrase
  (`encryptwallet`), so a call that took them could do nothing.
- **`<call> help`** for the calls that read a word first: `mnsync`, `spork`, `getinvalid`, and `addnode x help`.
- **`help <call>` for every call only irondivid has** (KNOWN): divid has no text for them.

## divid's command table (rpcserver.cpp:324-467)

| call | arguments | Core line |
|---|---|---|
| `getinfo` | 0 | `rpcmisc.cpp:103` |
| `help` | 0-1 | `rpcserver.cpp:291` |
| `stop` | 0-1 | `rpcserver.cpp:311` |
| `getnetworkinfo` | 0 | `rpcnet.cpp:334` |
| `addnode` | 2, the second add/remove/onetry | `rpcnet.cpp:157-161` |
| `getaddednodeinfo` | 1-2 | `rpcnet.cpp:190` |
| `getconnectioncount` | 0 | `rpcnet.cpp:39` |
| `getnettotals` | 0 | `rpcnet.cpp:291` |
| `getpeerinfo` | 0 | `rpcnet.cpp:69` |
| `ping` | 0 | `rpcnet.cpp:53` |
| `getblockchaininfo` | 0 | `rpcblockchain.cpp:427` |
| `getbestblockhash` | 0 | `rpcblockchain.cpp:51` |
| `getblockcount` | 0 | `rpcblockchain.cpp:36` |
| `getlotteryblockwinners` | 0-1 | `rpclottery.cpp:18` |
| `getblock` | 1-2 | `rpcblockchain.cpp:178` |
| `getblockhash` | 1 | `rpcblockchain.cpp:155` |
| `getblockheader` | 1-2 | `rpcblockchain.cpp:242` |
| `getchaintips` | 0 | `rpcblockchain.cpp:471` |
| `getdifficulty` | 0 | `rpcblockchain.cpp:66` |
| `getmempoolinfo` | 0 | `rpcblockchain.cpp:557` |
| `getrawmempool` | 0-1 | `rpcblockchain.cpp:82` |
| `gettxout` | 2-3 | `rpcblockchain.cpp:332` |
| `gettxoutsetinfo` | 0 | `rpcblockchain.cpp:295` |
| `verifychain` | 0-2 | `rpcblockchain.cpp:406` |
| `reverseblocktransactions` | 1 | `rpcblockchain.cpp:579` |
| `invalidateblock` | 1 (also listed as hidden) | `rpcblockchain.cpp:614` |
| `reconsiderblock` | 1 (also listed as hidden) | `rpcblockchain.cpp:651` |
| `getinvalid` | 0-1 | `rpcblockchain.cpp:689` |
| `getspentinfo` | 1, an object | `rpcmisc.cpp:881` |
| `getmininginfo` | 0 | `rpcmining.cpp:220` |
| `prioritisetransaction` | 3 | `rpcmining.cpp:253` |
| `setgenerate` | 1 | `rpcmining.cpp:54` |
| `generateblock` | 0-1 | `rpcmining.cpp:122` |
| `createrawtransaction` | 2 | `rpcrawtransaction.cpp:363` |
| `decoderawtransaction` | 1 | `rpcrawtransaction.cpp:466` |
| `decodescript` | 1 | `rpcrawtransaction.cpp:529` |
| `getrawtransaction` | 1-2 | `rpcrawtransaction.cpp:141` |
| `sendrawtransaction` | 1-2 | `rpcrawtransaction.cpp:830` |
| `signtransactionwithaddresskey` | no count | `rpcrawtransaction.cpp:568` |
| `signrawtransaction` | 1-4 | `rpcrawtransaction.cpp:604` |
| `createmultisig` | 2 | `rpcmisc.cpp:447` |
| `validateaddress` | 1 | `rpcmisc.cpp:320` |
| `verifymessage` | 3 | `rpcmisc.cpp:487` |
| `setmocktime` | 1 (hidden) | `rpcmisc.cpp:528` |
| `listmasternodes` | 0-1 | `rpcmasternode.cpp:269` |
| `getmasternodecount` | 0 | `rpcmasternode.cpp:329` |
| `setupmasternode` | 5-6 | `rpcmasternode.cpp:185` |
| `signmnbroadcast` | 1 | `rpcmasternode.cpp:163` |
| `verifymasternodesetup` | 4 | `rpcmasternode.cpp:124` |
| `broadcaststartmasternode` | 1-2 | `rpcmasternode.cpp:363` |
| `startmasternode` | 1-2 | `rpcmasternode.cpp:395` |
| `getmasternodestatus` | 0 | `rpcmasternode.cpp:429` |
| `getmasternodewinners` | 0-3 | `rpcmasternode.cpp:491` |
| `importmnbroadcast` | 1 | `rpcmasternode.cpp:597` |
| `listmnbroadcasts` | 0 | `rpcmasternode.cpp:617` |
| `allocatefunds` | 3 | `rpcmasternode.cpp:65` |
| `mnsync` | 1, status or reset | `rpcmisc.cpp:166` |
| `spork` | show, active, or a name and a value | `rpcmisc.cpp:277-312` |
| `ban` | 1 | `rpcmisc.cpp:67` |
| `clearbanned` | 0-1 | `rpcmisc.cpp:1014` |
| `listbanned` | 0-1 (its help text starts "clearbanned") | `rpcmisc.cpp:1025` |
| `getaddressbalance` | 1-2 | `rpcmisc.cpp:819` |
| `getaddressdeltas` | 1-2 | `rpcmisc.cpp:695` |
| `getaddresstxids` | 1-2 | `rpcmisc.cpp:611` |
| `getaddressutxos` | 1-2 | `rpcmisc.cpp:930` |
| `addmultisigaddress` | 2-3 | `rpcwallet.cpp:1738` |
| `backupwallet` | 1 | `rpcwallet.cpp:2527` |
| `dumpprivkey` | 1 | `rpcdump.cpp:172` |
| `dumphdinfo` | 0 | `rpcdump.cpp:201` |
| `bip38paperwallet` | 1 (its help text starts "bip38encrypt") | `rpcdump.cpp:251` |
| `bip38decrypt` | 2 | `rpcdump.cpp:297` |
| `encryptwallet` | 1, counted on an unencrypted wallet only | `rpcwallet.cpp:2694` |
| `getaccountaddress` | 1 | `rpcwallet.cpp:540` |
| `getaccount` | 1 | `rpcwallet.cpp:626` |
| `getaddressesbyaccount` | 1 | `rpcwallet.cpp:652` |
| `getbalance` | 0-3 | `rpcwallet.cpp:1556` |
| `getnewaddress` | 0-1 | `rpcwallet.cpp:283` |
| `getrawchangeaddress` | 0-1 | `rpcwallet.cpp:560` |
| `getreceivedbyaccount` | 1-2 | `rpcwallet.cpp:1501` |
| `getreceivedbyaddress` | 1-2 | `rpcwallet.cpp:1434` |
| `getstakingstatus` | 0 | `rpcmisc.cpp:1039` |
| `gettransaction` | 1-2 | `rpcwallet.cpp:2454` |
| `getunconfirmedbalance` | 0 | `rpcwallet.cpp:1599` |
| `getwalletinfo` | 0 | `rpcwallet.cpp:2875` |
| `loadwallet` | 1 | `rpcwallet.cpp:526` |
| `importprivkey` | 1-3 | `rpcdump.cpp:43` |
| `importaddress` | 1-3 | `rpcdump.cpp:107` |
| `keypoolrefill` | 0-1 | `rpcwallet.cpp:2546` |
| `listaccounts` | 0-2 | `rpcwallet.cpp:2322` |
| `listlockunspent` | 0 | `rpcwallet.cpp:2818` |
| `listreceivedbyaccount` | 0-3 | `rpcwallet.cpp:1946` |
| `listreceivedbyaddress` | 0-3 | `rpcwallet.cpp:1916` |
| `listsinceblock` | no count | `rpcwallet.cpp:2366` |
| `listtransactions` | 0-4 | `rpcwallet.cpp:2217` |
| `listunspent` | 0-3 | `rpcrawtransaction.cpp:253` |
| `lockunspent` | 1-2 | `rpcwallet.cpp:2744` |
| `sendfrom` | 3-5 | `rpcwallet.cpp:1608` |
| `sendmany` | 2-4 | `rpcwallet.cpp:1696` |
| `sendtoaddress` | 2-5 | `rpcwallet.cpp:1308` |
| `fundvault` | 1-2, one only if an object | `rpcwallet.cpp:1039` |
| `reclaimvaultfunds` | 2-5 | `rpcwallet.cpp:1141` |
| `debitvaultbyname` | 3-4 | `rpcwallet.cpp:1082` |
| `removevault` | 1 | `rpcwallet.cpp:1194` |
| `addvault` | 2 | `rpcwallet.cpp:1233` |
| `getcoinavailability` | 0-1 (its help text is empty) | `rpcwallet.cpp:820` |
| `setaccount` | 1-2 | `rpcwallet.cpp:588` |
| `signmessage` | 2-4 | `rpcwallet.cpp:1366` |
| `walletlock` | 0, counted on an encrypted wallet only | `rpcwallet.cpp:2669` |
| `walletpassphrasechange` | 2, counted on an encrypted wallet only | `rpcwallet.cpp:2630` |
| `walletpassphrase` | 2-3, counted on an encrypted wallet only | `rpcwallet.cpp:2575` |

## Not called

divid 3.0.0 stops (the process ends) on these forms, so they are not called:

- `getlotteryblockwinners` with no arguments, on this short chain;
- `signtransactionwithaddresskey` with no arguments;
- `verifymasternodesetup` with no arguments, and with 5.

Its help texts are still compared. If divid stops on any other form, the run ends with one FAIL line naming it.

## KNOWN differences (by design)

- `help: irondivid's own sections`: irondivid has more calls than divid. It lists them after divid's sections, under
  `<category> (irondivid)` sections. divid's sections are compared exactly in the row before.
- `help <call> (a call only irondivid has)`: divid answers `help: unknown command: <call>`
  (`rpcserver.cpp:283-285`). irondivid answers with the call's help.
- `removevault with 2 arguments (one too many)`: irondivid still takes the second argument older IronDivi callers
  send, as `scripts/vault-replies` lists it. divid takes exactly one (`rpcwallet.cpp:1194`).

## Proving a difference is caught

- `HELP_REPLIES_INJECT=<row name>` changes irondivid's reply of that row before it is compared. For example,
  `HELP_REPLIES_INJECT='help getblockcount'` makes that row print `FAIL` and the run exit 1.
- `HELP_REPLIES_DUMP=<dir>` writes both replies of every row that differs to `<dir>` (help texts and errors only,
  with the sample addresses and hashes written as above).
