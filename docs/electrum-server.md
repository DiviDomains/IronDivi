# Electrum server

`irondivid -electrum=<bind:port>` serves the Electrum protocol (1.4) so light
clients, BasicSwap in `--light` mode first, can use a Divi node without running
one. It is off by default.

## Decisions

### Header size: pad every header to 112 bytes

A Divi header is 80 bytes when `version <= 3` and 112 bytes when
`version > 3`. The extra 32 bytes are the zerocoin accumulator checkpoint after
the nonce. The two kinds also hash differently: a header with `version < 4`
hashes with Quark over its 80 bytes, and a newer one with sha256d over all
112. IronDivi builds every new block as version 4, but mainnet's early blocks,
and the genesis block of every network, are legacy headers.

Electrum clients assume one fixed header size: they slice
`blockchain.block.headers` replies by it and index their header files by
`height * size`. The server therefore sends every header as 112 bytes and
appends 32 zero bytes to a legacy header. A client sets its header size to 112
for Divi and reads the version from the first 4 bytes, little-endian, to tell
the kinds apart.

This rules out the other options. A variable-size stream cannot be sliced. An
80-byte truncation loses the accumulator, which the v4 hash needs.

BasicSwap does not implement Quark. It hashes v4 headers and checks that each
links to the one before; for a legacy header it has no hash, so it skips the
link checks that need one and trusts the server, as it does for stake. A
legacy genesis is accepted when its prev-hash is zero, and height 1 must link
to the network's known genesis hash. Checkpoints are what pin the legacy part
of mainnet; see below.

### Proof of stake: the client trusts the server

Divi blocks are proof of stake. A light client cannot check stake without the
UTXO set, so it checks only that each header's prev-hash links to the one
before, plus any checkpoints it carries. It does not check proof of work. PoS
validity is therefore trusted to the server, so run your own server or one you
trust.

### Scripthash index

Electrum looks up history by `sha256(scriptPubKey)` reversed. IronDivi's
address index is keyed by (type, hash160). A new column family,
`scripthash`, maps the 32-byte script hash to the 21-byte (type, hash160)
key. It is written together with the address index when a block connects.
Nothing is deleted when a block disconnects, because the mapping does not
depend on the chain.

When the column family is empty but the address index is not, as on a node
upgraded from a version without it, the server fills it once at startup. It
walks the distinct (type, hash) keys of the address index and rebuilds the
P2PKH or P2SH script for each. Vault scripts cannot be rebuilt from a hash, so
they are taken from the scripts stored in the unspent index. Spent vault
outputs whose script no longer appears there are not backfilled. A reindex
fills those too.

The server refuses to start without `-addressindex=1` and `-txindex=1`.

### Mempool

Unconfirmed transactions appear in `get_history`, `get_balance` and
`listunspent` the way ElectrumX shows them: at height 0, or -1 when they spend
an unconfirmed output. The server keeps one index of the mempool, shared by
every session: each pool output by script hash, and each pool input by the
outpoint it spends. Each request and status check lists the pool (txid, fee,
and whether it spends an unconfirmed output, in the pool's order) and uses
the index when the listing is the one indexed; otherwise it builds a new
index, reading only the transactions the old one did not hold. One pool state
is read once however many scripts are queried; listing the pool still costs
time proportional to its size on every call. Confirmed outputs come from the
address index on every call, so the mempool index never holds chain data.

### Notifications

Each connection checks the tip and the mempool about once a second. Its
fingerprint covers the tip and, for each pool transaction, the txid, the fee,
and whether it spends an unconfirmed output, so a parent confirming while its
child stays in the pool (the child going from height -1 to 0) starts a status
pass. When the tip changes it pushes `blockchain.headers.subscribe`. When the status hash of a
subscribed scripthash changes it pushes `blockchain.scripthash.subscribe`. The
status hash is the Electrum one: sha256 over `txid:height:` for each history
entry, in order.

## Methods

`server.version`, `server.ping`, `server.banner`, `server.features`,
`server.donation_address`, `server.peers.subscribe` (always `[]`),
`blockchain.headers.subscribe`, `blockchain.block.header`,
`blockchain.block.headers`, `blockchain.scripthash.get_balance`,
`blockchain.scripthash.get_history`, `blockchain.scripthash.get_mempool`,
`blockchain.scripthash.listunspent`, `blockchain.scripthash.subscribe`,
`blockchain.scripthash.unsubscribe`, `blockchain.transaction.get` (raw or
verbose), `blockchain.transaction.broadcast`,
`blockchain.transaction.get_merkle`, `blockchain.estimatefee`,
`blockchain.relayfee`, `mempool.get_fee_histogram` (always `[]`).

`blockchain.block.header` and `blockchain.block.headers` do not support the
`cp_height` checkpoint proof. Requests with a nonzero `cp_height` get an error.

## Running it

### Flags

| Flag | Meaning |
|---|---|
| `-electrum=<ip:port>` | Serve plain TCP on this address. |
| `-electrumtls=<ip:port>` | Serve TLS on this address. |
| `-electrumcert=<file.pem>` | TLS certificate chain, PEM. Needed with `-electrumtls` or `-electrumwss`. |
| `-electrumkey=<file.pem>` | TLS private key, PEM. Needed with `-electrumtls` or `-electrumwss`. |
| `-electrumws=<ip:port>` | Serve Electrum over plain WebSocket on this address. Conventional port 50003 (testnet 51003). Meant for `127.0.0.1` behind a TLS front such as nginx, `tailscale serve` or a Cloudflare Tunnel. |
| `-electrumwss=<ip:port>` | Serve Electrum over WebSocket with TLS on this address, using `-electrumcert` and `-electrumkey`. Conventional port 50004 (testnet 51004). |

The WebSocket listeners are for wallets that run in a browser engine (a web
page, a Telegram webview, an extension service worker) and cannot open a raw
socket. The methods, subscriptions and push notifications are the same as over
TCP. Only the framing differs: each JSON-RPC message (or batch) is one
WebSocket text frame, with no trailing newline. Any `Origin` is accepted,
because everything served is public chain data. All four listeners share the
1000-connection cap. A client must open the socket with a WebSocket handshake;
plain TCP or HTTP sent to these ports is dropped.

```
irondivid -txindex=1 -addressindex=1 -electrumws=127.0.0.1:50003
```

Relative cert and key paths are taken from the data directory. Either
listener, or both, can be on. The node also needs `-txindex=1`,
`-addressindex=1` and its RPC server (the default `-server=1`; the Electrum
server calls it for broadcast and fee estimates). A port that is taken fails
startup. Turning `-addressindex` on for an existing node needs a reindex; the
scripthash index then fills itself.

The conventional ports are 50001 (TCP) and 50002 (TLS). For a private server
on the same machine or a LAN:

```
irondivid -txindex=1 -addressindex=1 -electrum=127.0.0.1:50001
```

### A public server

1. **Use TLS.** Plain TCP lets anyone on the path change what the wallet sees.
   Get a certificate for the server's DNS name, for example from Let's Encrypt
   (`certbot certonly --standalone -d electrum.example.org`). Point
   `-electrumcert` at `fullchain.pem` and `-electrumkey` at `privkey.pem`. The
   key must be readable by the user running irondivid, and the daemon has to
   be restarted after a renewal to pick up the new certificate.
2. **Bind TLS publicly and TCP locally**, for example
   `-electrumtls=0.0.0.0:50002 -electrum=127.0.0.1:50001`, and open only 50002
   in the firewall (`ufw allow 50002/tcp`). Keep the RPC port closed.
3. **Limits.** See [Limits](#limits). They bound what one client can cost,
   but they do not replace a firewall or a connection-rate limit in front if
   you expect a determined flood.
4. **Trust.** Clients cannot check proof of stake or hash legacy headers, so
   a client trusts its server about which chain is best. It can still check
   that a confirmed transaction is in a v4 block's merkle root. Tell users
   this. A swap client should use a server its operator runs or trusts.
5. **Checkpoints.** BasicSwap syncs headers from genesis unless it has a
   checkpoint file for the coin
   (`basicswap/interface/divi/checkpoints/<network>.json`).
   For mainnet a recent checkpoint saves the full sync and pins the legacy
   blocks; add one with each BasicSwap release.

### Limits

Where a value comes from ElectrumX (spesmilo/electrumx master, `env.py` and
`session.py`) it is the same; the others are IronDivi's own. All are constants
in `crates/divi-electrum/src/limits.rs` and `lib.rs`.

| Limit | Value | Source |
|---|---|---|
| Connections, all listeners | 1000, the last 100 only for peers holding fewer than 4 | ElectrumX `MAX_SESSIONS`; the reserve is IronDivi's |
| Connections per peer | 32 (loopback exempt; IPv6 counted per /64) | IronDivi (ElectrumX has none) |
| Request size | 1,000,000 bytes (line or WebSocket message) | ElectrumX `MAX_RECV` |
| Reply size | 8,100,000 bytes; larger becomes an error | ElectrumX `MAX_SEND` |
| History / unspent per script | 81,817 entries, `(MAX_SEND-100)/99` | ElectrumX |
| Requests per batch | 1000; a larger batch is refused whole | IronDivi (ElectrumX has none) |
| Subscriptions | 20,000 per connection, 250,000 per server | IronDivi |
| Request time | 30 s, then an error reply | ElectrumX `REQUEST_TIMEOUT` |
| Idle | 600 s without a complete message | ElectrumX `SESSION_TIMEOUT` |
| Write to a client | 30 s, then the connection ends | IronDivi |
| Calls into chain/mempool at once | 7 request slots and 1 notification slot, shared by all sessions | IronDivi |

Each connection has a cost budget as in ElectrumX: it starts at 5, each request
adds its cost (header methods 0.5, a blank keepalive line 0.1, others as in
`limits::method_cost`), and the bytes sent and received add 1 per 5000. The
budget decays by 10000 / (10000 + 5 x subscriptions) per second. Above 1000 a
request is delayed, up to 2.5 s as the cost nears 10000; at 10000 the
connection is sent an error and closed. Header requests are not charged for
bytes, so a header sync from genesis is not slowed. A status pass starts
when the fingerprint changes, at least one second plus 2 ms per subscription
after the previous pass finishes. After 120 seconds without a pass, the server
rechecks statuses even if the fingerprint is unchanged. This corrects statuses
observed during a temporary tip or mempool change. Each one-second tick allows up to 64 chunks
of four scripts (256 scripts); a pass over 20,000 scripts needs at least 79
ticks. A changed header is sent before the first chunk, and changed statuses
are sent after each chunk. When requests and notification work are both
ready, the session alternates between one message and one notification turn.
Eligible sessions queue in arrival order for the notification slot. Each session
keeps one waiter across requests and ticks. A grant covers at most one header
check and one chunk, including their writes, before another session can run. A failed status check
closes the connection rather than leaving the wallet with a stale status.

Each Electrum address-index scan visits at most 81,817 rows plus one lookahead.
Rows count before transaction deduplication, vault script filtering, or
mempool spends, so even a small final result can get a limit error. The
non-Electrum address-index reads remain unrestricted. The reply limit counts
encoded JSON bytes, including escaped text, IDs, and batch punctuation.
A stopped batch reserves room for an error. An oversize single reply retains
its ID if the error fits; otherwise the error uses a null ID.

The RPC server (`-rpcport`) has its own policy: a peer not in `-rpcallowip`
gets its 403 without taking a slot; a peer may hold at most `max(2, threads/2)`
connections (loopback exempt); request headers must arrive within 30 s, an idle
keep-alive connection is closed after 30 s, and a request body or reply that
makes no progress for 30 s ends the connection. Divi Core has no such timeouts
(it keeps `-rpcthreads=4` connections for as long as they last); these are a
deliberate IronDivi difference. The wallet RPC uses HTTP. Keep it on loopback or use an encrypted
tunnel for remote access. The address allowlist and RPC credentials control
access but do not encrypt wallet passphrases in transit.

Not covered: a reconnecting client starts with a new budget (ElectrumX groups
cost by subnet; IronDivi does not), there is no connection-rate or TLS
handshake limit, a client sending a byte every few seconds is held until the
idle limit, many source addresses still add up to the total, and each
session's fingerprint and each script query still list the whole pool,
though they share one index of it. RPC-backed verbose results are materialized
before the bounded JSON encoder. Put a firewall or rate limit in front of a
public server.

Tests (no node needed except the last):

```
cargo test -p divi-electrum limits
cargo test -p divi-electrum --lib session::tests
cargo test -p divi-storage --lib search_index::tests
cargo test -p divi-rpc conn_policy
cargo test -p divi-rpc server::tests
cargo test -p irondivid --test electrum   # existing end-to-end suite
```

### Connecting BasicSwap

```
basicswap-prepare --withcoins=divi --light --divi-mode=electrum \
    --divi-electrum-server=electrum.example.org:50002:s
```

The suffix `s` means TLS; leave it off, or use `t`, for plain TCP. There is
no default public Divi server, so `--divi-electrum-server` is required.
