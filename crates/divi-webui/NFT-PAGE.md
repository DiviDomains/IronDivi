# NFT page (`static/nft.js`)

`nft.js` defines `window.irondiviNft(ctx)`, which renders the NFTs page for
DiviTokens (DT/1) assets held by the node's wallet. It is loaded with `defer`
before `app.js`, uses only the `ctx` helpers and plain DOM, and puts all chain
data into text nodes. Its names live inside an IIFE so they cannot clash with
`app.js`.

The spec is divi-nft `docs/DIVI-ASSET-STANDARD.md`.

## Tabs

- **Gallery**: lists the wallet's colored outputs.
  - **What it reads.** It reads `listlockunspent` plus `listunspent 0`, because
    `listunspent` hides locked coins and §10 says to lock colored coins.
    Unlocked coins above 0.01 DIVI are skipped, which keeps a staking wallet
    from fetching thousands of coinstakes. At most 200 transactions are read
    per scan. The page shows the skipped and truncated counts and a Rescan
    button.
  - **How it decodes.** Each creating transaction is decoded strictly to DT/1
    (§1, §3): exactly one OP_META output, minimal push, `DIVA` v1, minimal
    varints, no trailing bytes, at most 599 bytes. It then assigns colors from
    ISSUE `out_vout`/`coll_vout`, TRANSFER groups and CERTIFY `out_vout`.
  - **Assets that arrived by TRANSFER.** The page fetches the ISSUE for these
    to get the supply, metadata CID (shown as `ipfs://bafk…`, §6), content
    sha256, collection and royalty (§3.2, §7.4).
  - **Badges.** Every item is badged *unverified*: input color (§5) needs an
    indexer. Unconfirmed items are badged as such (§9).
  - **Locking.** It offers **Lock this coin** (`lockunspent false`, §10) and
    warns that the Wallet page's Pay form burns unlocked colored coins.
- **Mint** (§3.2): a one-of-one ISSUE, testnet only, with these fields.
  - kind (item or collection)
  - media file
  - name and description
  - collection (from the collection tokens held; its holder address mints)
  - royalty bps, with a warning above 10 %, and royalty address (both or
    neither)
  - the wallet passphrase, when the wallet is locked or unlocked for staking
- **List** (§7.1, §7.3, §7.4, §7.6): pick an asset and enter a price. The page
  shows live what the seller receives, the creator royalty
  (`royaltyFor = max(floor(price*bps/10000), dust)`), the organization royalty
  (items only; 100 bps to the network's org address, mainnet from block
  4 250 000), the carrier and the address that is paid (the one holding the
  coin). Testnet only. The "Open listings" card says the page posts listings
  but does not show the book yet.
- **Send** (§3.1, §5): pick an asset, enter a recipient (checked live with
  `validateaddress`) and an amount. The submit stays off (see below).

## RPC calls

- `listunspent`, `listlockunspent`
- `getrawtransaction <txid> 1`; if that fails, `gettransaction` plus
  `decoderawtransaction` for wallet transactions
- `decodescript` to turn a royalty pkh into an address
- `validateaddress`
- `lockunspent false` (only when the wallet is encrypted; the server refuses
  this call for an unencrypted wallet)
- Mint and List: `listunspent 1`, `signmessage`, `signrawtransaction`,
  `walletpassphrase`, `walletlock`

## Mint and List: divi-nft `packages/nft-kit`

Mint and List run the NFT lane's wallet kit (divi-nft
`docs/WALLET-INTEGRATION.md`), in the `// --- the NFT lane's wallet kit ---`
section.

- **The bundle.** `static/nftkit.js` is the kit built by `nftkit/build.sh`
  from a pinned divi-nft commit (`git archive`, never a working tree; the
  header names the commit). `nft.js` loads it the first time it is needed.
- **The service.** The kit talks to the NFT service through the node's
  `/api/nft/*` proxy (`lib.rs`), which is signed-in only, testnet only (it
  answers 404 on any other network) and goes only to
  `nft-testnet.irondivi.com/nft/api`. Writes carry the CSRF header.
- **Signing.** The node wallet signs: `signmessage` for the service's
  sign-in (the token stays in memory, per address), `signrawtransaction` with
  the kit's sighash type for each transaction. The kit checks each signed
  transaction against the one it built (`checkPasted`) before it broadcasts.
- **Locked wallets.** A locked or staking-only wallet is unlocked for 600 s
  with the passphrase field, then put back (staking only, or locked).
- **Mint** pins the media and the metadata JSON to IPFS, then builds the
  ISSUE from the address with the most confirmed uncolored coin (or the
  collection's holder).
- **List** checks that the service has the asset at the address that holds
  the coin, then posts the `SINGLE|ANYONECANPAY` listing to the service's
  order book.

**Send stays off.** `sendTransfer` keeps its `waits` line: the kit has a
TRANSFER builder, but a transfer built wrong burns the asset (§5), so it stays
disabled until it is proven on testnet.

Gallery validation is also provisional. When the NFT index API exists, it
should replace the "unverified" badge.

## CSS to add

None. The page uses only existing app.css classes: `card`, `grid`, `field`,
`row`, `row wrap`, `tabs`/`on`, `kv`, `note ok/err`, `muted`, `small`, `badge`,
`badge live`, `badge warn`. `.kv dd` already wraps long ids.
