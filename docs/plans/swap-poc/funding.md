# Testnet funding addresses (multi-coin, 2026-10-11)

Decision: the testnet runs reuse the existing secp256k1 swap keys for every secp256k1 chain,
so no new 1Password items are needed. LTC P2WPKH and ZEC transparent P2PKH use the same
hash160 as the BTC address; EVM uses the same public key. Pass the BTC refs as the
LTC/ZEC/EVM key refs:

- taker: `op://global_secret_store/IronDivi Swap POC - taker-btc/password`
- maker: `op://global_secret_store/IronDivi Swap POC - maker-btc/password`

Derived from public keys only (pubkeys read from on-chain BTC witnesses; the `tb1…`
re-encoding is asserted to match before printing). Script: `tools/swap-poc/derive-addrs.py`.

| role | BTC testnet3 | LTC testnet | ZEC testnet (TAZ) | Sepolia (ETH gas + USDC) |
|---|---|---|---|---|
| taker | tb1qa826ffe73xnqsm64x6fvln7sl0zp3rgfdq3hpg | tltc1qa826ffe73xnqsm64x6fvln7sl0zp3rgf5gnf3p | tmX2ki4DXm6ucGvdZY8CxSmPKdzkL8dnVdk | 0x4bb95b0cD0AC55556D96D7E850a5090Cc450D60C |
| maker | tb1quqkt7c06svzt68f2y9uwf2jzgpd48k6ku45zrt | tltc1quqkt7c06svzt68f2y9uwf2jzgpd48k6k9akunz | tmW9gJFxB1138x4xyMpk3qZ84VZNs7hypzn | 0x995669a244d511542ca314e4068c754E3F555bd2 |

Keep every testnet coin; never sweep back to a faucet.
XMR (ed25519, stagenet) gets its own wallet when its lane reaches live readiness.

## ZEC testnet: faucet on the wrong fork (2026-10-11)

NU7 activated on Zcash testnet at height 4,465,026 (Oct 4) and cut blocks to 25 s.
`testnet.zec.rocks`, the server `swap-chain-zec` uses, follows the NU7 chain (tip ~4,489,850
on Oct 11). fauzec.com still runs a pre-NU7 node: its claim to our funding wallet (txid
`9cf8c2203229ef9577857439452c22b63ba0981b3419ba02dce98a05d7049814`, 1 TAZ) was mined at
4,474,361 on a chain whose tip was ~4,474,400 (75 s blocks). zexplorer.app shows the same
stale chain. A wallet synced against zec.rocks from height 4,474,000 never sees it, so those
coins do not exist on the chain we swap on.

Funding wallet (shielded, for splitting TAZ to the two t-addrs above): hp2
`~/zec-faucet-wallet/wallet2` (zcash-devtool, birthday 4,474,000, age identity alongside).
Its unified address:
`utest1shuxck4zpa4rn9aa3ydyxnhgdc9aq66kr4x9dy95tegfm25ujh9uu5xvlnrhey42cd364kry7wgs4fkmwre69jaqw0jxzjelfxa4ltkzcpj2tevtq3gu924gczq4g26hf4dsxu9gwg499fmxlh80ypf23ty45vdjcphrz507gk9n07cz62pjcamnqt87v3jh79f53a3y8dxag0kjq4l`.
TAZ sent straight to the taker/maker t-addrs works just as well. Needs a source on the
NU7 chain.

## Sepolia / Base Sepolia ETH faucet research (2026-10-12)

The taker (`0x4bb95b0cD0AC55556D96D7E850a5090Cc450D60C`) has 20 USDC on Sepolia but no ETH
on either network, and no mainnet balance on this address (it is a fresh testnet-only key) —
so any faucet gated on mainnet ETH holdings is a dead end here. Every row below was checked
with a real HTTP request (`curl`/fetch against the faucet's own page or docs) on 2026-10-12;
none were signed up for and no CAPTCHA was solved — where a candidate's actual claim flow
needed either, that step was left undone and is noted as such. "Confirmed working" means the
faucet/its documentation page was reachable and the requirements below were read directly off
it, not that a claim was completed.

| faucet | URL | network | amount/day | requirement | confirmed working |
|---|---|---|---|---|---|
| **QuickNode Multi-Chain Faucet** | https://faucet.quicknode.com/ethereum/sepolia (and `/base/sepolia`) | Sepolia, Base Sepolia | base amount shown only after entering an address; one drip/network per 12 h, up to 4x with optional bonuses | **none for the base drip** — page states explicitly "no Quicknode account, no post on X and no minimum mainnet balance, so a brand new wallet can claim"; a "complete the verification" bot-check gates the actual claim (type unconfirmed — no `captcha`/`turnstile`/`recaptcha` string in the page's static HTML, may be an invisible check) | **Yes** — page reachable, requirements read directly off its own copy; the bot-check step itself was not attempted (no signup needed to reach it, but completing it was out of scope here) |
| **pk910 Sepolia PoW Faucet** | https://sepolia-faucet.pk910.de/ | Sepolia only | self-directed: mine in-browser until balance reaches the ~0.05 ETH minimum, then claim; no fixed daily cap found | **none** — no account, no mainnet balance, no CAPTCHA; cost is browser CPU time (proof-of-work), not a web form | **Yes** — page reachable (title "Sepolia PoW Faucet"); mining itself was not run (open-ended compute time, and the task's own "do not sign up or solve CAPTCHAs" scope was read as "don't go claim funds," not just avoid CAPTCHAs specifically) |
| Chainlink Faucets | https://faucets.chain.link/sepolia | Sepolia, Base Sepolia, 6 others | drips 0.5 ETH per network | connect a wallet (MetaMask/WalletConnect in its UI); no mainnet-balance or CAPTCHA string found in the page's static HTML, but the real claim flow is a client-rendered app that wasn't exercised | Page reachable, "Drips 0.5 ETH" read directly off it; claim flow not attempted (needs an actual wallet signature, not just an HTTP request) |
| Alchemy Faucet | https://www.alchemy.com/faucets/ethereum-sepolia (and `/base-sepolia`) | Sepolia, Base Sepolia | 0.1 ETH / 24 h | **fails our case**: page states "No account required" but requires "at least 0.001 ETH on Ethereum Mainnet" plus "sufficient" mainnet transaction history — exactly the mainnet-balance gate we don't have | Page reachable, requirement read directly off it; not usable for this address as-is |
| Google Cloud Web3 Faucet | https://cloud.google.com/application/web3/faucet/ethereum/sepolia (and `/base-sepolia`) | Sepolia, Base Sepolia | not published on the page | Google **sign-in** required (page's own nav links to `accounts.google.com/ServiceLogin`) **and** Google reCAPTCHA Enterprise is loaded on the page (`recaptcha/enterprise.js` in the page source) — both a login and a CAPTCHA | Page reachable; both gating requirements confirmed directly from the page's own markup, so excluded as a no-signup/no-CAPTCHA option |
| Coinbase CDP Faucet | https://portal.cdp.coinbase.com/products/faucet (UI), https://docs.cdp.coinbase.com/faucets/introduction/quickstart (API) | Base Sepolia, Ethereum Sepolia, + ERC-20s | API: 0.0001 ETH/claim, up to 1000 claims/24 h (portal UI amount not published) | requires "Created and signed in to an existing CDP account"; the API additionally needs a CDP API key + wallet secret | Both pages reachable; account requirement read directly from Coinbase's own quickstart doc |
| thirdweb Faucet | https://thirdweb.com/sepolia | Sepolia | not published before login | the page's own "Faucet" button is a `/login?next=/sepolia` link — thirdweb account/wallet connect required before any amount is shown | Page reachable; login-gate confirmed from the page's own link target |
| Circle Faucet | https://faucet.circle.com | Base Sepolia (and others), USDC/EURC | n/a | reCAPTCHA present (`captcha`/`Captcha` strings in the page); this is a **USDC/EURC faucet, not an ETH one** — listed only because it was named in the request | Page reachable; not a meaningful ETH source for this address |
| Infura Faucet | https://www.infura.io/faucet | — | — | — | **No** — the URL now just serves Infura's marketing homepage; no faucet UI remains on it |
| fauceth.komputing.org | http://fauceth.komputing.org | — | — | — | **No** — the domain is parked (returns a bare cPanel "default web page" redirect, not a faucet) |
| LearnWeb3 Faucet | https://learnweb3.io/faucets/sepolia | — | — | — | **No** — the URL returned HTTP 503 on a direct request |

**Best two, in order:** QuickNode's multi-chain faucet first — it explicitly disclaims every
gate we'd fail (no account, no mainnet balance, no social post) and covers both Sepolia and
Base Sepolia from the same page, so whichever network's maker/taker funding lands first, this
is the one to try. pk910's Sepolia-only PoW faucet second — strictly zero account/CAPTCHA/
mainnet-balance requirement of any kind, at the cost of needing sustained browser mining
instead of an instant claim, and it doesn't cover Base Sepolia at all.
