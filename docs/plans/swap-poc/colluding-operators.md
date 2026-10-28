# Colluding ZEC/DIVI operators: a threat model (T32-14)

Date: 2026-10-28. Base `2eda574` (EV's gated tip). Design note only: no code, config default,
timeout, margin or confirmation count changes here, and no build or test was run. Line numbers are
at `2eda574` unless a commit is named.

This note goes one step past `colluding-endpoints.md` (EP, T32-4, at `118bc27`), which covers every
chain. It takes the open limit ET left (T32-5): with `[zec].crosscheck_url` set, a ZEC lock read
must agree between the primary lightwalletd and a second operator, and DIVI reads agree between
`rpc_url` and `fallback_rpc_url`. A **colluding** pair is not covered: both operators lie the same
way, or one party runs both. The note looks closely at ZEC and DIVI, the two chains whose reads go
through a remote operator with no local proof of any kind, and says what changes once ET, EW and EX
land (§7). No new fact about a third-party product is stated. Operator facts (who runs `zec.rocks`
or `services.divi.domains`) are taken from `colluding-endpoints.FACTS.md`, where both are rows marked
"could not verify". This lane made no network request.

**What is on this base and what is not.** On `2eda574`: EH's ZEC tip cross-check
(`crates/swap-chain-zec/src/crosscheck.rs:85`, `:152`, `:190`), EM/EU/EV's bounded holds
(`crates/divi-swap/src/hold.rs`), DIVI's two-source agreement (`crates/swap-chain-divi/src/second_source.rs`),
and LTC's lock, spend and claim cross-checks (EL, EN, EI). **Not** on this base: ET (the ZEC lock's
script and value read from both operators), EW (txid binding, pin `971a695`) and EX (a deadline on a
failing second operator, `lane/zec-second-operator-deadline` at `ab2dcfd`, in progress). So at
`2eda574` **one** ZEC operator is still enough to fake a lock. The second operator compares tips
only (`crosscheck.rs:85-150`) and is never asked about the lock (`crates/swap-chain-zec/src/lib.rs:765-791`).

## 0. Summary

1. Every multi-source check in the tree is an agreement check. It does not check who runs the
   sources, and nothing checks a proof-of-work header or a Merkle path locally. Two colluding
   operators are as strong as one, and on ZEC at this base one operator is already enough for the
   lock (ET not merged).
2. **Funds can be lost** at four acting points, and in each the liar is, or works with, the
   **counterparty**. (a) The maker funds against a fabricated taker lock. (b) The taker reveals the
   preimage against a fabricated maker lock. (c) The maker misses the taker's claim of the maker
   leg (a hidden spend). (d) A claim is swallowed or judged on a falsely low MTP until the other
   side can refund. Each costs one whole leg. The timelocks do not bound (a), (b) or (c). (d) is
   bounded only by how long the liar can keep the real network from seeing the claim.
3. Everything else is a **stall until refund**. That covers a fake spend, a high MTP, a wrong branch
   id or coin list on ZEC, a swallowed refund while the preimage is still secret, and a second
   operator that is down. The checks that turn these into stalls all hold against a colluding pair:
   the HTLC script built locally, the preimage hash, signatures that commit to amounts, and consensus
   locktimes (§3).
4. The worst row in a real deployment is the default direction (taker pays the counter coin, maker
   pays DIVI). The taker CLI reads the maker's DIVI lock through a primary it cannot change: the
   project's proxy (`bin/divi-swap/src/main.rs:676-678`). The reference maker is the project's own
   daemon. Nothing on the taker's side requires a source the maker does not control.
5. Recommendation (§6): yes, a code slice. First a taker-side DIVI source flag
   (`--divi-rpc-url`), with a mainnet refusal or warning when the taker has no DIVI source outside
   the default proxy's domain. Then mainnet value caps. Header or proof-of-work checks for ZEC are
   real work and should wait until own nodes have been costed. For DIVI (proof of stake) the only
   full answer is an own node.

## 1. Scope: which chains read through a remote operator, and who runs it

"Maker" is `divi-swapd`, "taker" is the `divi-swap` CLI. Default direction: the taker locks the
counter coin (taker leg) and the maker locks DIVI (maker leg). Reverse (`TakerPaysDivi`): the taker
locks DIVI and the maker locks the counter coin (`crates/divi-swap/src/api.rs:76-89`).

| Chain | Sources in the code | Who runs them in a real deployment | Two-source rule today |
|---|---|---|---|
| ZEC | primary: lightwalletd list, defaults `zec.rocks`, `na.zec.rocks`, `eu.zec.rocks` (`crates/swap-chain-zec/src/lib.rs:71-75`; the comment at `:69-70` says all three are one operator's); failover endpoints from config or `SWAP_ZEC_LIGHTWALLETD_EXTRA` (`:62`); optional `[zec].crosscheck_url` / `--zec-crosscheck-url` (`lib.rs:222-234`, `bin/divi-swap/src/main.rs:648-652`) | third party (one company behind the defaults). A second operator: another third party, or the maker's own zebrad+lightwalletd. No second testnet operator is known (EH, ET rounds) | tips only, at start (`crosscheck.rs:152`) and before every claim/refund build (`lib.rs:250-261`, `crosscheck.rs:190-222`). Lock, confirmations, spend, MTP, branch id, coins and broadcast are read from the primary alone (`lib.rs:576-629`, `:745-830`). Same-domain second operator refused (`crosscheck.rs:241-284`; daemon `bin/divi-swapd/src/config.rs:1014-1018`); a mainnet daemon needs a second operator unless waived (`config.rs:1020-1028`). **Taker CLI: no mainnet requirement** (`main.rs:637-653` checks only `--allow-mainnet` and the domain) |
| DIVI | `[divi].rpc_url`, default `services.divi.domains` (`crates/swap-chain-divi/src/lib.rs:50-57`); `[divi].fallback_rpc_url` (`config.rs:56-62`), example an own node `http://127.0.0.1:51473` (`deploy/divi-swapd/divi-swapd.toml.example:21`) | primary: the project's proxy (from the hostname; FACTS "could not verify"). Maker: the reference maker is the project's daemon (`deploy/divi-swapd/README.md:1`), so primary and maker belong to one organisation. Taker: **primary fixed to the default** (`main.rs:676-678`, `:1003`), optional `--divi-fallback-rpc-url` (`main.rs:589-607`) | every swap read on both and agreed (`lib.rs:742-782`, `second_source.rs`); broadcast to both, success if either takes it (`lib.rs:661-686`). Independence check: string inequality only (`config.rs:141-150`; CLI against the default, `main.rs:604`). Mainnet daemon needs the fallback unless waived (`config.rs:1066-1072`); taker CLI not |
| LTC | Esplora `litecoinspace.org` (`crates/swap-chain-ltc/src/lib.rs:60-64`) plus `[ltc].crosscheck` (Blockbook/BlockCypher) | two third-party products (EP FACTS) | lock terms, spend and the claim-time tip are agreed (`ltc/src/lib.rs:256`, `:1144-1160`). Covered in EP; not repeated here |
| BTC | Esplora mempool.space / blockstream.info, `[btc].quorum_reads` (`config.rs:166-214`) | two third parties | quorum reads off by default; EP |
| USDC | one EVM RPC (publicnode / `mainnet.base.org`, `crates/swap-chain-evm/src/network.rs:50-53`), optional fallback | third party | `htlc_output`, `find_spend`, `confirmations` agreed when set (`swap-chain-evm/src/backend.rs:823-850`); EP |

Common to every row: TLS uses the bundled web roots with no pinning (`Cargo.toml:99` `rustls-tls`;
`crates/swap-chain-zec/Cargo.toml:37` `tls-webpki-roots`). Whoever controls the swap host's resolver
or network path, and can get a certificate for the names, answers as **both** operators.

Who can make both sources agree on a lie:

| Actor | ZEC | DIVI |
|---|---|---|
| one company under two names | the defaults are one operator (`lib.rs:69-70`); a "second" under another domain bought from the same company passes `check_second_operator` | the proxy and any fallback the project also runs |
| the counterparty | a taker paying or running both ZEC operators the maker uses | **the project's maker vs a taker on defaults**: the maker's organisation runs the taker's only DIVI source (`main.rs:676-678`) |
| one upstream behind two front ends | two lightwalletds on one zebrad/zcashd | two RPC proxies on one divid |
| the swap host's network (DNS, BGP, captive network) plus a certificate | both hostnames | both hostnames; with a plain `http://` fallback off the host, the network path alone |

## 2. What collusion can do, per acting point

"MC" is the maker-leg chain and "TC" the taker-leg chain. Each row names the backend that reads
and on whose host it runs. **LOSE** means a permanent loss of funds. **STALL** means funds are held
until a refund locktime, or a human acts, with nothing lost. The bound is what limits the damage in
practice.

### 2a. Lose funds

| # | Acting point (code) | The lie | What the victim does | Worst outcome | Bound today |
|---|---|---|---|---|---|
| L1 | **Maker before funding.** Reads the taker lock on TC (`crates/divi-swap/src/maker.rs:651`, `:674`, `:704`), then selects coins and funds (`maker.rs:715-728`). ZEC TC: primary alone at this base (`lib.rs:765-791`). DIVI TC (reverse): both sources agreed (`swap-chain-divi/src/lib.rs:760-770`) | a taker lock with the agreed script, at least the agreed value, and enough confirmations. Confirmations are the operator's tip − the operator's height + 1 (ZEC `lib.rs:783-788`) or the node's `confirmations` field (DIVI `lib.rs:940`), so the depth is faked along with the lock | locks the real maker leg | **liar allied with the taker: the maker loses the whole maker leg.** The taker holds the preimage and the claim key, and claims it. Liar acting alone (the taker never locked): STALL, the maker leg refunds at its locktime | none. `taker_window_too_short` (`maker.rs:636-640`) reads the TC MTP from the same liars. The script and amount checks hold (§3), but a fake lock passes them by design |
| L2 | **Taker before revealing.** Checks the hash and keys locally (`crates/divi-swap/src/taker.rs:571-581`), reads the maker lock on MC (`taker.rs:584`), checks the claim deadline on MC MTP (`taker.rs:593-595`), then claims, which reveals the preimage. DIVI MC (default): primary fixed to the project's proxy (`main.rs:676-678`). ZEC MC (reverse): the taker CLI's lightwalletd defaults, cross-check optional and not required on mainnet (`main.rs:642-652`) | a maker lock that does not exist, or a real one with fake depth | builds and sends the claim through the same operators. The preimage is now in the liar's hands | **taker loses the whole taker leg.** The maker claims the taker leg with the preimage and never had to lock. A fake depth on a real lock is a loss only if the lock is then reorged out | none locally. For DIVI in the default direction against the project's maker, this needs **no** collusion beyond the project running its own proxy |
| L3 | **Maker learns the preimage** from a spend of the maker leg (`revealed_preimage`, `maker.rs:1137-1161` via `hold::find_spend`, `hold.rs:276`). DIVI MC: block scan on both sources (`swap-chain-divi/src/lib.rs:944-977`). ZEC MC: compact-block scan on the primary (`swap-chain-zec/src/lib.rs:794-830`, `spend_in_block` `:549-563`) | the taker's claim is hidden (no spend reported) | waits, then tries to refund a leg that is already spent. The refund fails on the real chain | **liar allied with the taker: the maker loses the maker leg.** The taker claimed it and refunds its own taker leg at the taker locktime | none. The taker-leg locktime turns the hidden spend into a loss rather than bounding it |
| L4 | **Claim timing and broadcast.** Taker's first claim, judged on MC MTP (`taker.rs:593-595`, `ClaimDeadline::check` `crates/divi-swap/src/config.rs:148`). The maker's claim of the taker leg after the reveal (`maker.rs:958`). ZEC broadcasts to the primary only, and to the second operator only after a `Disagree` (`swap-chain-zec/src/lib.rs:720-724`, `:264-271`, `:305-325`). DIVI to both (`swap-chain-divi/src/lib.rs:661-686`) | MTP reported low, so the claim goes out after the real margin has passed. Or a claim reported as sent, and even as confirmed (`confirmations` from the same operator, `lib.rs:745-763`), while it is swallowed | the claimer believes it is safe or done | **the claimer loses its leg** once the counterparty's refund locktime passes: the counterparty refunds, and already has, or can take, the other leg. Needs a liar allied with the counterparty | the counterparty's refund locktime minus the claim margin (ZEC and DIVI 1800 s, `config.rs:120`, `:124`). This holds **only if** the real network sees the claim in time: a pair that swallows the claim and reports it confirmed defeats it |

### 2b. Stall until refund (no loss)

| # | Acting point | The lie | Outcome | Why it is only a stall |
|---|---|---|---|---|
| S1 | fake spend of either lock | a spend carrying a wrong "preimage" | ignored | `SpendInfo::extract_preimage` keeps only a value whose SHA-256 is the hash (`crates/divi-swap/src/types.rs:254-262`). The maker's own refund txid is excluded (`maker.rs:1153-1158`) |
| S2 | refund (taker `taker.rs:533`, maker `maker_leg_timed_out` `maker.rs:1112-1118`; ZEC build behind `spend_hold`, `swap-chain-zec/src/lib.rs:692-718`, then `hold::build_refund` `hold.rs:244`) | MTP high (refund sent early) or the refund swallowed | with the preimage still secret, funds stay locked until the refund lands through an honest path | consensus enforces CLTV, so an early refund is rejected and retried, and nobody else can take a leg whose preimage is secret. **Exception**: once the preimage is public, a swallowed refund is a race the counterparty can win (that is L4) |
| S3 | ZEC funding reads: coins (`GetAddressUtxos`, `lib.rs:424`), branch id (`lib.rs:458`) | invented coins, wrong values, wrong branch id | the funding or spend is invalid on the real chain and is retried | ZIP 244 commits to the spent amounts and the branch id (test at `crates/swap-chain-zec/src/tx.rs:1679`). The fee rate is local (`lib.rs:143`) |
| S4 | DIVI funding reads | a coin reported lower than its value | **small LOSE**: the wallet signs a transaction whose real fee includes the difference | DIVI's legacy signature hash takes no input amount (`crates/divi-wallet/src/signer.rs:33-39`). The loss is bounded by the coin's value and goes to the block producer, so the liar gains only if it also produces the block (EP row 7) |
| S5 | maker's own locktime `MTP + maker_timeout` (`maker.rs:716-725`) | MC MTP low | the maker leg becomes refundable early. This shortens the taker's window, not the maker's | the taker checks the window on its own view (`check_maker_leg_locktime`, `config.rs:849`, exact form `:893`, called at `taker.rs:604-636`) |
| S6 | high MTP or tip on TC, read by the maker | "the window is too short" | the maker aborts before funding (`maker.rs:636-640`) | nothing has been locked by the maker |
| S7 | a second operator down, or not agreeing, while the primary is honest | — | claims and refunds wait under EM/EU/EV's bounded hold. The taker's secret-preimage claim is never built on one source (`claim_fee.rs:138`, H1). A public-preimage claim keeps holding and is flagged "needs a human" (`hold.rs:50`, `:149`) | not collusion. Listed because a colluding pair can also mimic it. EX bounds the same thing for lock reads (§7) |

**Confirmation counting** is not a separate row. Faking depth on a real lock buys nothing unless the
lock is also reorged out, and the depth on a fake lock is part of L1 and L2. Longer confirmation
counts do not help against a pair that fabricates the lock (§5, F9).

## 3. What a colluding pair cannot do

These hold whatever every remote source says, because they are computed or enforced locally, or by
the real chain's consensus:

- **The lock script is ours.** The redeem script is built locally from the hash, the two keys and
  the locktime (`crates/divi-swap/src/htlc.rs:144-150`, validated `:100`). A reported output counts
  only if its scriptPubKey equals the one derived locally: ZEC `swap-chain-zec/src/lib.rs:778-782`,
  DIVI `swap-chain-divi/src/lib.rs:931`. The taker also checks the maker's stated hash, claim key and
  refund key against its own (`taker.rs:571-581`). A liar cannot get a lock with another hash or key
  accepted. It can only invent a lock with the right script.
- **The amounts are compared locally**: maker `maker.rs:652`, `:676`, `:706`; taker `taker.rs:586`.
- **No wrong preimage is accepted.** A preimage is used only if its SHA-256 matches the hash
  (`types.rs:254-262`). The preimage is generated locally and reaches the network only in the
  taker's own claim (`claim_fee.rs:138`).
- **Our signatures commit to what we spend.** ZEC claims, refunds and funding commit to the input
  amount and the branch id under ZIP 244 (`swap-chain-zec/src/tx.rs:1679`, condition b of EM).
  LTC/BTC P2WSH under BIP 143 likewise (EU round). So a lie about an amount makes our transaction
  invalid. It cannot redirect value. DIVI funding is the exception (S4).
- **Our outputs are ours.** Claims and refunds pay to our own key, built locally (`tx::build_spend_tx`
  in `swap-chain-zec/src/lib.rs:672-686`, `:701-716`). No answer from an operator changes the destination.
- **Consensus enforces the locktimes.** A refund before its locktime is rejected by the real network,
  so no lie lets the counterparty take a leg back early. The locktime arithmetic is local:
  `maker.rs:716-725`, `ClaimDeadline::check` `config.rs:148`, `check_maker_leg_locktime` `config.rs:849`, `:893`.
  Its **input**, though, is the MTP the operators report, so the arithmetic is only as honest as that
  number (L4, S5).
- **A secret preimage is never revealed on one source's word while the second is silent** (EM H1,
  `claim_fee.rs:138`). A colluding pair does not need this path because it agrees, but the check
  keeps a down or stalled operator from becoming a cheap version of L2.

What is **not** among them: whether the reported transaction exists, is in a block, and that block is
on the most-work chain. No code checks a header, a proof of work, or a Merkle path. The ZEC crate
decodes only the height, hash, time and transactions of a compact block (`swap-chain-zec/src/grpc.rs:178-188`),
and DIVI reads verbose JSON (`swap-chain-divi/src/lib.rs:838-851`).

## 4. Detection and limits that exist today

| What | Where | Catches |
|---|---|---|
| ZEC startup tip cross-check: `Disagree` refuses the start, `Unavailable` warns | `crosscheck.rs:152`; `ZecBackend::crosscheck` `lib.rs:239-244` | a primary on a different chain from the second operator. Not a colluding pair |
| ZEC tip cross-check before every claim/refund build: `Held`, both endpoints and both hashes in the message | `crosscheck.rs:190-222`, `:60-70`; `lib.rs:250-261` | the same, at each spend |
| DIVI agreement on every read: one-sided or different answers are `Transient` / `Held` naming both endpoints | `second_source.rs` (`pair`, `agree_*`; tolerances `:27`, `:32`, `:39`); `swap-chain-divi/src/lib.rs:742-782` | one lying source |
| same-operator refusal at config load (ZEC: registrable domain; DIVI/USDC: identical string) | `crosscheck.rs:241-284`, `config.rs:1014-1018`; `config.rs:141-150`; CLI `main.rs:604`, `:650` | an accidental same-host pair. Not two domains owned by one operator |
| mainnet start rule (second source required unless `allow_single_source`, warned every start) | `config.rs:1081-1092`, ZEC `:1020-1028`, DIVI `:1066-1072` | a daemon on one source by mistake. **Not applied to the taker CLI** |
| maker abort reasons stored in the record (`taker lock underfunded`, `does not match the HTLC`, `vanished`, `window ran out`) | `maker.rs:651-668`, `:674-697`, `:704-713` | a lie that is internally inconsistent. A consistent lie passes |
| taker `claim_declined` (persisted) and `last_error` on both records | `taker.rs:595-600`; `crates/divi-swap/src/store.rs:90`, `:171`, `:201` | deadline or floor refusals. A post-mortem has the swap's outpoints and txids to check against an independent node by hand |
| hold logs at error level, one "needs a human" report per held public-preimage claim | `hold.rs:82-136`, `:149-177` | stalls, not lies |

Limits: nothing records **which** endpoint answered a lock or spend read, nothing counts
disagreements over time, and nothing alerts when a swap ends in a state where the counterparty
gained (for example a maker leg spent while the taker leg is refunded). A colluding pair that
agrees from the first request leaves nothing in the logs except the normal swap trail.

## 5. Possible fixes, ranked by money-risk removed per unit of work

"Decision" names who decides. A protocol, config default or mainnet start rule is an operator/Bert
decision; this note does not make it.

| Rank | Fix | Closes | Cost | Changes / decision |
|---|---|---|---|---|
| F1 | **Taker-side DIVI source.** `--divi-rpc-url` so a taker can replace the project's proxy as primary, plus a mainnet refusal (or warning) when the taker's DIVI sources are all on the default's registrable domain. Reuse EH's `check_second_operator` (`crosscheck.rs:272`) as a shared helper | L2 in the default direction against the project's maker, the worst row. Also L4's MTP lie on the taker's DIVI reads | small: CLI flag, helper move, a few tests (EP §5 M2 names them) | **mainnet start rule for the taker CLI** (refuse vs warn): Bert |
| F2 | **Mainnet value caps**, per swap and in flight per chain, until own nodes run | bounds L1-L4 and S4 to the cap; removes nothing | small code (quote/accept checks) | **money decision** (the numbers) and a mainnet start rule: Bert |
| F3 | **Own nodes on the maker's host as the second source**: divid as `[divi].fallback_rpc_url` (already the example, `divi-swapd.toml.example:21`), zebrad+lightwalletd as `[zec].crosscheck_url` | L1 and L3 for the maker on both chains, against any third-party collusion. With loopback URLs, the network attacker too | ops: two hosts' worth of disk and upkeep. No code beyond F4's loopback rule | **mainnet start rule** ("second source must be loopback/own" vs "any independent"): operator/Bert. Hosting cost: operator |
| F4 | **Operator diversity rules, generalised.** One shared check for all chains and the taker CLI: Public Suffix List registrable domain (EH's heuristic misreads private suffixes, `crosscheck.rs:233-266`), distinct resolved IPs at load, and on mainnet no plain `http://` second source off loopback. Also bring the ZEC mainnet second-operator rule to the taker CLI (`main.rs:642-652` has none) | the accidental same-operator pair and lazy configurations, not a deliberate colluder with two domains. ASN diversity would add "same hosting provider" but needs an IP-to-ASN dataset shipped and kept current | small (helper + config tests). ASN: medium plus data upkeep | **config default / mainnet start rule** (how strict; ASN or not): Bert |
| F5 | **ZEC: broadcast every claim and refund to the second operator too**, not only after a `Disagree` (`lib.rs:264-271`) | L4's swallowed claim when the second operator is honest. Nothing against a pair | small | none (no default or protocol change) |
| F6 | **Answer audit trail.** Store which endpoint(s) answered each acting read (lock, spend, MTP, with height and block hash) in the swap record, and offer a post-hoc "recheck against source X" command | detection only: makes L1-L4 provable after the fact and lets an operator spot one upstream behind two names | small to medium (schema field) | **schema change**: operator/Bert |
| F7 | **Third operator, 2-of-3** on top of the pair helpers | a colluding pair when the third is honest | small code. Needs a third independent ZEC lightwalletd and DIVI RPC that may not exist on testnet (EH) | config default: Bert |
| F8 | **ZEC header chain and proof-of-work check** of the block the lock (or spend) is in: a local header store from a checkpoint, Equihash and difficulty checks, a Merkle path from the tx to the header. The crate decodes no header today (`grpc.rs:178-188`); whether lightwalletd serves full headers was not verified here | L1, L2 and fake depth on ZEC against any collusion short of mining real blocks. L3 (a hidden spend) still needs a full scan of the window against local headers | **medium-large**: per-chain consensus code, checkpoint upkeep, a new third-party dependency to check. **Not possible for DIVI**: proof of stake, so a header check needs stake validation, which is close to a full node (F3) | protocol-adjacent (a new trust anchor, the checkpoint): Bert |
| F9 | **Longer confirmation counts on remote-only reads** | reorg risk only. Nothing against a fabricated lock or fabricated depth, since the liar fakes the depth too | trivial | **protocol/quote change** (confirmations are in the quote): Bert. Not recommended for this threat |

The order follows money at risk per unit of work. F1 removes the largest default-direction loss for
the least code. F2 bounds everything for little code but is a money call. F3 is the real fix for the
maker and costs operations, not code. F4 and F5 are cheap hygiene. F6 adds evidence, not prevention.
F7 needs operators that may not exist. F8 is the only fix that removes ZEC collusion without an own
node, and it is the most expensive. F9 does not address this threat.

## 6. Recommendation

A code slice should follow, and the first one is **F1 with F4's taker-CLI part**. F1 adds
`--divi-rpc-url` to the taker CLI. F4's part moves EH's operator check into a shared helper that
also covers DIVI, and gives the CLI the same ZEC mainnet second-operator rule as the daemon. The
mainnet behaviour ships as a warning that names the project's proxy and the risk, and turns into a
refusal only when Bert rules on the taker start rule. This closes L2 for the default direction, which
is the one row where a real deployment needs no extra conspirator: the project runs both the maker
and the taker's only DIVI source. It is a few dozen lines with mock-only tests, and changes no
protocol. Next is F2 (caps, once the numbers are decided) and F3 (own divid and zebrad+lightwalletd
on the maker host before mainnet value beyond the cap). F5 can ride with any ZEC slice. F8 should
not start until F3 has been costed, because an own node removes the same risk on both chains, and
F8 cannot help DIVI.

## 7. What changes once ET, EW and EX land

ET is the base of EW (`git merge-base --is-ancestor 1319222 971a695`), so EW's pin carries both.

- **ET** (`crosscheck::lock_view` / `agree_lock`, `971a695:crates/swap-chain-zec/src/crosscheck.rs:249`,
  `:290`; `htlc_output` `971a695:crates/swap-chain-zec/src/lib.rs:847-858`). The ZEC lock read in L1
  and L2 goes from "one operator suffices" to "both must lie". The ZEC cells of L1/L2 in §2a and the
  "primary alone" cells in §1 change. The colluding-pair verdict does not: two agreeing operators
  pass `agree_lock`. `confirmations`, `find_spend`, MTP, branch id, coins and broadcast stay
  primary-only, so L3 and L4 on ZEC still need only **one** operator, even after ET.
- **EW** (`not_requested`, `971a695:crates/swap-chain-zec/src/lib.rs:553-563`, used by the lock read
  `:307`, `lock_view` `crosscheck.rs:260`, `confirmations` `:820` and `find_spend` `:860`). An
  operator can no longer answer with **another** real transaction whose output happens to match, and
  a spend must actually spend the watched outpoint. That narrows L1/L2 against an operator acting
  alone. Against a counterparty-allied pair it does not: the colluding taker (or maker) can sign a
  transaction with the right script and value, never broadcast it, and have both operators serve
  exactly those bytes at a made-up height. EW binds the bytes to the txid, not the txid to a block.
  §3's last paragraph stands until F8 or F3.
- **EX** (`Maker::taker_lock_unread`, `ab2dcfd:crates/divi-swap/src/maker.rs:648`;
  `Taker::maker_lock_unread`, `ab2dcfd:crates/divi-swap/src/taker.rs:627`; `LOCK_READ_BUDGET`
  `ab2dcfd:crates/swap-chain-zec/src/crosscheck.rs:44`). A second operator that is down or hangs ends
  in an abort at the maker's funding deadline instead of retrying forever, and it never relaxes to
  primary-only. That changes S7's "lock reads fail closed with no deadline" to "bounded". For
  collusion it changes nothing: a colluding pair agrees, so it never triggers the EX path. EX's own
  open limit (the abort is judged on the primary's TC MTP, so a liar can make the maker abort early)
  is a stall, consistent with S6.

## 8. Open limits of this note

- Line numbers are at `2eda574`. ET/EW/EX lines are at the named pins, and EX is still in progress,
  so its lines may move before it lands.
- No third-party fact was checked: no network was used. Operator identities rely on
  `colluding-endpoints.FACTS.md` rows marked "could not verify". Whether lightwalletd serves full
  block headers (F8) is not verified.
- No test was run or written. EP §5 lists fail-first test names for F1, F2, F4 and F6/F8 that still apply.
- XMR (no second source, mainnet not enabled) is out of scope.
