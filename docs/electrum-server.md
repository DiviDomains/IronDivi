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
an unconfirmed output. There is no address index for the mempool, so each
request scans it, which costs time proportional to the mempool size. Divi's
mempool is small, so this is fine for now.

### Notifications

Each connection checks the tip and the mempool about once a second. When the
tip changes it pushes `blockchain.headers.subscribe`. When the status hash of a
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
| `-electrumcert=<file.pem>` | TLS certificate chain, PEM. Needed with `-electrumtls`. |
| `-electrumkey=<file.pem>` | TLS private key, PEM. Needed with `-electrumtls`. |

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
3. **Limits.** The server takes up to 1000 connections at once and refuses
   more. Each connection polls the tip and mempool once a second, and mempool
   lookups scan the whole mempool. Put a reverse proxy or connection-rate
   limits in front if you expect abuse.
4. **Trust.** Clients cannot check proof of stake or hash legacy headers, so
   a client trusts its server about which chain is best. It can still check
   that a confirmed transaction is in a v4 block's merkle root. Tell users
   this. A swap client should use a server its operator runs or trusts.
5. **Checkpoints.** BasicSwap syncs headers from genesis unless it has a
   checkpoint file for the coin
   (`basicswap/interface/divi/checkpoints/<network>.json`).
   For mainnet a recent checkpoint saves the full sync and pins the legacy
   blocks; add one with each BasicSwap release.

### Connecting BasicSwap

```
basicswap-prepare --withcoins=divi --light --divi-mode=electrum \
    --divi-electrum-server=electrum.example.org:50002:s
```

The suffix `s` means TLS; leave it off, or use `t`, for plain TCP. There is
no default public Divi server, so `--divi-electrum-server` is required.
