# Swap quote intent validation (taker side)

The maker is the untrusted party in an atomic swap, and so is everything it serves: an offer
page or `GET /offers` can change between the moment the user read it and the moment the
taker asks for a quote. Before the taker generates a preimage, persists a swap or calls
`POST /swaps` (or `POST /xmr/swaps`), it holds the maker's quote to a `QuoteIntent`
(`crates/divi-swap/src/intent.rs`). Every intent pins **all** of:

- the offer id and the counter-chain amount (`btc_sats`);
- the counter chain (`btc`, `ltc`, `zec`, `usdc`, `xmr`);
- the direction (`taker_pays_btc`: buy DIVI; `taker_pays_divi`: sell DIVI);
- an exact DIVI amount bound: the least DIVI received when buying, the most paid when
  selling.

There is no "any chain", "any direction" or "any price". An intent comes from one of two
places only:

| Source | Used by | Bound |
| --- | --- | --- |
| `QuoteIntent::for_offer(&offer, btc_sats)`: the offer terms the user was shown and selected | extension `beginSelected` (the immutable selection an `offers()` listing issued), library `flow::begin` / `run_swap` / `run_swap_gated` (the caller passes the selected `Offer`) | `offer.checked_divi_for(btc_sats)`, exactly what an honest maker quotes (floor-rounded); `btc_sats` must be inside the offer's range |
| `QuoteIntent::with_limit(id, btc_sats, chain, direction, limit_price)`: explicit limits from the user | CLI `accept` / `run` (hashlock and XMR), extension `beginWithIntent` | `floor(btc_sats × limit_price / 1e8)`; refused if it overflows or rounds to 0 |

`stricter_price(limit)` only ever tightens a bound. A re-fetched offer is never used as the
source of terms: the extension's `beginSelected` refuses a selection it did not issue, and
the CLI has no trusted offer list, so it requires explicit limits.

## What is checked

The checks are pure (no chain or network access) and shared by the CLI, the library and the
extension.

| Check | Refused when |
| --- | --- |
| Intent itself | empty, over-long (>128) or non-`[A-Za-z0-9_-]` offer id; zero amount; `divi` as counter chain; zero bound; `min_remaining_secs` ≥ 3600; `max_taker_timeout_secs` 0 |
| Quote id | empty, over-long or non-`[A-Za-z0-9_-]` |
| Offer, chain, direction, amount | any differs from the intent |
| DIVI amount | 0; buying, below the bound; selling, above it |
| Terms (any flow) | `maker_timeout_secs` 0; `taker_timeout_secs` ≤ `maker_timeout_secs`; either confirmation count 0 |
| Quote expiry | already expired; less than `min_remaining_secs` (default 15 s) left; more than 3600 s ahead |

The quote expiry is checked again at commitment, right before `POST /swaps` (after
`prepare`, and in the extension after the host persisted the swap), so slow local work
cannot carry an almost-expired quote into an accept.

### HTLC timing (hashlock flows under a profile floor)

Quote expiry only bounds *when the taker may commit*. Whether a committed swap can complete
is a separate question about the HTLC timelocks, checked against the taker's local profile
(`--profile`, or the extension's `profile` config) by `QuoteIntent::check_htlc_terms`
before `prepare`:

| Check | Refused when |
| --- | --- |
| Profile floor | `check_terms_against_profile`: timeouts or confirmation counts below the profile (testnet 6 h / 3 h, BTC 1, DIVI 3; mainnet 24 h / 12 h, BTC 2, DIVI 17) |
| Ceiling | `taker_timeout_secs` above `max_taker_timeout_secs` (default 2 × the profile's taker timeout: testnet 12 h, mainnet 48 h), the longest the taker's coins may be stranded |
| Taker leg | `taker_timeout < maker_timeout + claim_margin + confirmations(taker chain) × block_secs + 1800` (the locktime MTP tolerance): the maker refuses to lock unless `maker_timeout + its claim margin` of the taker leg is left once that lock confirms, and the locktime may start up to the tolerance behind |
| Maker leg | `maker_timeout < confirmations(maker chain) × block_secs + claim deadline margin(maker chain)`: the taker could never claim before its own claim deadline |

Example: testnet, buying DIVI with BTC on 6 h / 3 h terms allows up to 12 BTC confirmations
(10800 + 1800 + 12 × 600 + 1800 = 21600); 13 are refused. Block times are expectations, not
guarantees; the checks refuse terms that cannot work even on schedule. The maker's own claim
margin is not quoted, so the taker's profile margin stands in for it.

Before funding, `Taker::lock` (under a profile floor) re-checks the real window with
`check_funding_window`: the accepted taker-leg locktime minus the taker chain's current MTP
must be at least `maker_timeout + claim_margin + confirmations × block_secs`. Both ends are
MTP readings on the same chain, so MTP lag cancels. This is not the confirmation count
elapsed: it is what the maker's `taker_window_too_short` will demand once the lock is
confirmed. A taker that sat on an accepted swap (e.g. `accept`, then `lock` hours later)
therefore does not fund into a window the maker would refuse to match. Without a floor
(library callers that pass none) the core engine keeps its old behaviour.

The XMR adaptor flow's timelocks are checked by `XmrTaker::prepare` against its own floor;
`check_htlc_terms` is hashlock-only.

## CLI (`divi-swap accept` / `divi-swap run`)

`accept` and `run` commit funds, so both now **require** explicit limits, for every counter
chain including `xmr`:

- `--direction taker-pays-btc|taker-pays-divi`
- `--limit-price <DIVI sats per counter coin>`: the worst price accepted.
- optional `--min-quote-secs <N>` (default 15).
- For hashlock swaps, `--max-taker-timeout-secs <N>` defaults to twice the profile's taker
  timeout. XMR adaptor swaps use different timelocks and reject this option.

Without `--direction` and `--limit-price` they fail before any request ("a maker's offer page
is not a trusted source of terms"). `divi-swap quote` needs neither: printing a quote commits
nothing. `--counter-chain xmr` accepts `--direction taker-pays-btc` (the taker pays XMR) and
holds the XMR quote to the same intent before `POST /xmr/swaps`.

The test harnesses (`tools/swap-poc/{e2e,ltc-live,zec-live,xmr-soak}.sh`, the chaos driver)
drive the operator's own maker and pass its listed direction and price as the limits;
`TAKER_LIMIT_PRICE` overrides the price in the shell scripts.

Library: `flow::begin`, `run_swap` and `run_swap_gated` take the selected `&Offer`;
`begin_with_intent` / `run_swap_intent` take any `QuoteIntent`; `xmr_flow::begin` / `run`
take a `&QuoteIntent`.

## Extension (`swap-wasm`)

`Config.profile` (`"testnet"` by default, or `"mainnet"`) is the profile floor the engine's
taker is built with; the HTLC checks above apply to both entry points.

`offers()` resolves to the offers for chains the taker has keys on, each with an `exact`
object holding `divi_sats_per_btc`, `min_btc_sats` and `max_btc_sats` as decimal strings
(the plain JSON numbers round in JS past 2^53 − 1), and a `selection` token.

Each `offers()` call is a new listing. Refreshing identical terms cannot renew an old
token. A token is a keyed digest of the listing number and one offer's full terms
(id, direction, counter chain, price, range), so it can never name different terms: another
extension view or a refresh adds tokens and never changes what an earlier one selects. An
id the maker lists more than once, on any chain, gets `selection: null` and
`ambiguous: true`, and any earlier token for that id is refused while the latest listing
still repeats it (the maker's quote endpoint is keyed by id alone).

`beginSelected(selectionJson)` holds the quote to the selected terms
(`QuoteIntent::for_offer`). The caller repeats every term it displayed, u64 values as
canonical decimal strings (no sign, exponent, fraction or leading zero); each must match the
selection exactly, and unknown keys are refused:

```json
{
  "selection": "<64 hex from offers()>",
  "offer_id": "divi-btc-testnet",
  "direction": "taker_pays_btc",
  "counter_chain": "btc",
  "divi_sats_per_btc": "10000000000000",
  "min_btc_sats": "1000",
  "max_btc_sats": "1000000",
  "btc_sats": "10000"
}
```

Optional `min_remaining_secs` and `max_taker_timeout_secs` are as for `beginWithIntent`.
Refused before any request: a token this engine never issued or no longer remembers
(selections live in memory only, so a service-worker restart or a wallet lock forgets them),
one listed more than 15 minutes ago, one for an ambiguous id, and any displayed term that
differs. The UI must then list offers again and let the user select again; it must never
substitute a refreshed offer itself. Swaps already begun are unaffected: `lock`, `tick` and
`refund` work by swap id from the sealed store across restarts.

The former `begin(offerId, btcSats)` (terms looked up by id in the most recent listing) is
removed: a later listing could replace the terms the user saw, and a duplicate id resolved
to whichever listing came last.

`beginWithIntent(intentJson)` takes explicit limits; every term is required and unknown keys
are refused. u64 values may be decimal strings, or JSON integers up to 2^53 − 1; fractions,
exponents, negatives and larger numbers are refused:

```json
{
  "offer_id": "divi-btc-testnet",
  "btc_sats": "10000",
  "counter_chain": "btc",
  "direction": "taker_pays_btc",
  "limit_divi_sats_per_btc": "10000000000000",
  "min_remaining_secs": 15,
  "max_taker_timeout_secs": 43200
}
```

Errors reject the promise with the engine's message, e.g. `transaction rejected: maker's
quote: …` or `invalid parameters: offer selection missing: …`.
