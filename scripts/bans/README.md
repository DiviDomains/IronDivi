# Peer bans, mock time and the leftover raw calls next to Divi Core

`run.sh` starts a Divi Core 3.0.0 `divid` and an irondivid on regtest, both with wallets made from the same phrase,
and compares, case by case:

- `ban` (an address or `outdated`), `listbanned` and `clearbanned`, against raw peers that connect to each node;
- automatic bans from misbehaviour at `-banscore` 100 (the default), 1 and 1000, and `-bantime` 1 and 60;
- bans and the ban list across a restart;
- `setmocktime`, and the times it moves;
- `getinvalid`, before and after `invalidateblock` and `reconsiderblock`;
- `signtransactionwithaddresskey`, and `sendrawtransaction` with its signature.

All six calls are in Divi Core's command table (`divi/src/rpcserver.cpp:360`, `:378`, `:389`, `:407-409`).

Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not, a `KNOWN` row that differs in another way, or a `KNOWN` row that now matches
  divid (the list below is out of date).

The run ends with `# rows: ...` and `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted,
or over 10 minutes).

```sh
scripts/bans/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/bans/run.sh target/release ~/divi-3.0.0/bin 54100 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+7` on 127.0.0.2: divid p2p and RPC, irondivid's, then the same
  for a testnet pair started for one row.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about two minutes and is stopped after 10. However it ends, every node is stopped and its directory
deleted. Needs bash and python3 (standard library only). RPC passwords and the wallet passphrase are made at random
for each run. They are kept in the 0600 `divi.conf` or passed in an RPC body, never printed or put on a command line.
The wallet phrase is read from divid's `dumphdinfo` and given to irondivid in its environment (`WALLET_MNEMONIC`).

## Nodes and peers

At first irondivid follows divid's chain: divid mines 26 blocks and pays a coin to an address both wallets hold. That
is all the signing rows need. Then irondivid is restarted with no peer. From there each node sees only the raw peers
made here.

A raw peer connects from its own loopback address (127.0.0.11 and up, one per case), does the version/verack
handshake with a sub-version of its choosing, answers pings, and sends what the case needs.

Both nodes listen on 127.0.0.2, so every peer is a loopback address. divid never bans a local peer for misbehaviour;
it drops it (`divi/src/main.cpp:1117-1125`, `CNetAddr::IsLocal`). So an automatic ban, and its `-bantime`, cannot be
seen on divid here. irondivid does the same. The rows check that both drop the peer at the threshold and let it
back in.

## Rows

| step | rows (each on both nodes) |
|---|---|
| signtransactionwithaddresskey | a spend of the address's coin; a transaction not spending it; input 1 of a transaction with one output (SIGHASH_SINGLE signs the value 1); a fourth argument (ignored). The signatures are the same on both (one key, RFC 6979). Refused: an address not in the wallet, a malformed one (-4 `Unable to sign for unknown address`); a number for the address (-1); hex `zz`, odd hex (-8 `Transaction hex data must be hexadecimal string (not '<text>')`); hex that is no transaction (-22 `TX decode failed`); a text input index; a number for the hex. Then `sendrawtransaction` with that signature and the pubkey: -26 `16: mandatory-script-verify-flag-failed (...)`, since it signs `<pubkey> OP_CHECKSIG`, not the P2PKH script |
| ban, the arguments | none and two (-1 with the help text), a number (-1 `value is type int, expected str`) |
| ban, one peer | the peer's address (see KNOWN); the address with its port, an address with no peer, `not-an-address`, `999.1.1.1`, `::1`, `[::1]`, `""`: `{"Banned": "Could not find matching node to ban"}`. After each: the peer's connection, `getconnectioncount`, `getpeerinfo` addresses, `listbanned`, and whether the address gets in again |
| ban outdated | no peer; a `Divi Core: 3.0.0.0` peer: `{"Banned": []}`, the peer stays; a `Divi Core: 2.4.0.0` peer: `{"Banned": ["127.0.0.13:<port>"]}`, the peer is dropped, its address is listed and refused, even with a current sub-version, until `clearbanned`. Odd sub-versions: `/IronDivi:0.2.6/` and `/bans:1.2.3.4/` (see KNOWN); `x2.0.0.0`, read from its second character as `2.0.0.0`, is banned |
| listbanned, clearbanned | one argument is taken, two give the help error. divid's `listbanned` error shows `clearbanned`'s help (`divi/src/rpcmisc.cpp:1023-1028`) |
| misbehaviour | 4 `addr` messages of 1001 addresses (20 each, `divi/src/main.cpp:528-531`): connected, `banscore` 80; 5: dropped, not listed, gets in again. `-banscore=1`: a second `version` message (1, `:358-362`) drops the peer. `-banscore=1000`: 5 stay connected at 100. `-bantime=1` and `=60`: dropped at 100, not listed, back at once. `setmocktime` 120 s ahead with `-bantime=60`: a peer gets in |
| restart | `ban outdated` of a 2.4.0.0 peer, then a restart: the list is empty on both, no ban file is written, and the address gets in (divid keeps bans in memory only: `divi/src/PeerBanningService.cpp:7`) |
| getinvalid | with no argument, `all`, a number (-1), two arguments (-1, help); after `invalidateblock` of the tip and after `reconsiderblock`: always the one summary of zeros (`divi/src/rpcblockchain.cpp:687-725` fills nothing) |
| setmocktime | no argument, two (-1, help); text and 1.5 (-3 `Expected type int, got str` / `got real`); -5 and 0 taken (`null`). With the clock a day ahead and a minute ahead: a new peer's `conntime`, `lastsend`, `lastrecv` and the time of a block mined then all equal the mocked time; `getinfo` `timeoffset` stays 0. On testnet: -1 `setmocktime for regression testing (-regtest mode) only`. `getblockchaininfo` has no field read from the clock (`divi/src/rpcblockchain.cpp:446-451`) |
| locked wallet | after `encryptwallet` (divid stops and is started again): signing with the address's key, -1 `GetKey: DecryptHDChainSeed failed` (`divi/src/wallet.cpp:543-544`); an address not in the wallet, -4 |

Not called, because each makes divid read past its arguments or inputs:
- `signtransactionwithaddresskey` with fewer than 3 arguments (divid exits, docs/rpc-parity-audit.md), an empty
  transaction, or an input index past the inputs or negative (`divi/src/rpcrawtransaction.cpp:566-599`);
- `ban outdated` with a peer whose sub-version has fewer than four numbers (`net.cpp:372` indexes past them).

## KNOWN

| row | divid | irondivid | reason |
|---|---|---|---|
| `listbanned` (every one) | `{"banned:": "[\n<ip>,\n]"}` | `[{"address", "ban_created", "banned_until", "ban_reason"}]` | divid's text list has no ban times (`divi/src/rpcmisc.cpp:1023-1030`, `divi/src/PeerBanningService.cpp:23-34`); irondivid keeps its array (docs/rpc-parity-audit.md: listbanned; also KNOWN in `scripts/net-replies`). The row checks that both name the same addresses |
| `ban` of a connected peer's address, and its after-rows | `Could not find matching node to ban`; the peer stays | `{"Banned": "<ip>"}`; the peer is dropped and refused | divid compares the address with each peer's `ip:port` text, so it never finds one (`divi/src/net.cpp:395-407`); irondivid bans the peer (also KNOWN in `scripts/net-replies`). irondivid's ban is then cleared so the later rows start alike |
| `ban outdated` with a `/IronDivi:0.2.6/` or `/bans:1.2.3.4/` peer | -1 `stoi` | `{"Banned": []}` | divid reads each sub-version as four numbers with `std::stoi`, which throws on `IronDivi:0` and `bans:1` (`divi/src/net.cpp:359-376`), so the whole call fails while such a peer is connected; irondivid leaves that peer alone and bans the outdated ones |
| `getinvalid key order` | `addresses_with_invalid, total_unspent, total_minted, total_valid_used` | `addresses_with_invalid, total_minted, total_unspent, total_valid_used` | irondivid writes every JSON object's keys in name order (serde_json without `preserve_order`, `Cargo.toml:67`); JSON objects are unordered (RFC 8259 section 4) |
