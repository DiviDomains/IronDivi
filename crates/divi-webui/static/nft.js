// SPDX-License-Identifier: AGPL-3.0-only
// IronDivi web interface: DiviTokens (DT/1) assets in the node's wallet.
// The standard is divi-nft docs/DIVI-ASSET-STANDARD.md; § numbers below are
// its sections. Everything read from the chain is untrusted: it reaches the
// page as text nodes only.
"use strict";

(function () {

// --- DT/1 constants ----------------------------------------------------------

const MAGIC = "DIVA"; // §3: the testnet wire label, kept on the wire
const VERSION = 1;
const OPS = { 1: "issue", 2: "transfer", 3: "certify", 4: "burn", 5: "revoke" };
const MAX_PAYLOAD = 599; // §1
const DUST = 5460n; // §1, sat
const CARRIER = 10000n; // §2, sat
const SAT = 100000000n;
/// Outputs above this are not read for color: a staking wallet holds
/// thousands of large coins, and a carrier SHOULD be 10 000 sat (§2)
const CARRIER_MAX = 1000000n;
/// At most this many transactions are fetched per scan
const SCAN_MAX = 200;
/// §7.6: the organization royalty, a protocol constant per network
const ORG_ROYALTY = {
  testnet: { bps: 100, address: "y564xiFpwW3J8gN5wRYhy7aFDNykYiY9Jd" },
  mainnet: { bps: 100, address: "D9Mq3WZsqpTyqafFxahK3oooasPhwS53vB", from: 4250000 },
};
const PROVIDERS = { 0: "fake (tests only)", 1: "serpapi-lens", 2: "tineye", 3: "local-dhash" };

let nftTab = "gallery";
/// The last gallery scan: { items, skipped, truncated, at }
let scan = null;

// --- bytes, numbers ------------------------------------------------------------

function hexBytes(hex) {
  if (typeof hex !== "string" || hex.length % 2 || /[^0-9a-f]/i.test(hex)) return null;
  const b = new Uint8Array(hex.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.substr(i * 2, 2), 16);
  return b;
}

function bytesHex(b) {
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}

/// A hash written in internal order, shown like a txid (§3)
function hashText(b) {
  return bytesHex([...b].reverse());
}

/// Satoshis as DIVI, without float rounding
function divi(sat) {
  const s = BigInt(sat);
  const frac = (s % SAT).toString().padStart(8, "0").replace(/0+$/, "");
  return (s / SAT).toString() + (frac ? "." + frac : "") + " DIVI";
}

/// "12.5" DIVI as satoshis, or an error
function parseDivi(text) {
  const m = /^(\d{1,10})(?:\.(\d{1,8}))?$/.exec(String(text).trim());
  if (!m) throw new Error("enter an amount in DIVI, up to 8 decimals");
  return BigInt(m[1]) * SAT + BigInt((m[2] || "").padEnd(8, "0"));
}

/// A wallet amount (a JSON number in DIVI) as satoshis
function satOf(amount) {
  return BigInt(Math.round(Number(amount) * 1e8));
}

/// §7.4 royaltyFor: the marketplace minimum for one royalty output
function royaltyFor(price, bps) {
  const due = (price * BigInt(bps)) / 10000n;
  return due === 0n ? 0n : (due < DUST ? DUST : due);
}

function percent(bps) {
  return (bps / 100).toString() + " % (" + bps + " bps)";
}

function short(id) {
  return id.slice(0, 8) + "…" + id.slice(-4);
}

/// A binary CID as text: CIDv1 in base32 ("bafkrei…", §6), else hex
function cidText(b) {
  if (!b.length || b[0] !== 0x01) return "hex:" + bytesHex(b);
  const abc = "abcdefghijklmnopqrstuvwxyz234567";
  let out = "b", bits = 0, acc = 0;
  for (const x of b) {
    acc = (acc << 8) | x;
    bits += 8;
    while (bits >= 5) { out += abc[(acc >>> (bits - 5)) & 31]; bits -= 5; }
    acc &= 0xff;
  }
  if (bits) out += abc[(acc << (5 - bits)) & 31];
  return out;
}

// --- DT/1 decoder (§3) ------------------------------------------------------------

/// Reads a payload front to back; any slip throws, and a throw means "no op"
function reader(b) {
  let at = 0;
  const need = (n) => { if (at + n > b.length) throw new Error("truncated"); };
  const r = {
    u8() { need(1); return b[at++]; },
    u16() { need(2); const v = b[at] | (b[at + 1] << 8); at += 2; return v; },
    u32() { need(4); const v = (b[at] | (b[at + 1] << 8) | (b[at + 2] << 16)) + b[at + 3] * 0x1000000; at += 4; return v; },
    /// CompactSize, minimal only
    varint() {
      const first = r.u8();
      if (first < 0xfd) return BigInt(first);
      const n = first === 0xfd ? 2 : first === 0xfe ? 4 : 8;
      need(n);
      let v = 0n;
      for (let i = n - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[at + i]);
      at += n;
      const min = first === 0xfd ? 0xfdn : first === 0xfe ? 0x10000n : 0x100000000n;
      if (v < min) throw new Error("non-minimal varint");
      return v;
    },
    /// A varint used as an index or count
    count() {
      const v = r.varint();
      if (v > 10000n) throw new Error("count out of range");
      return Number(v);
    },
    raw(n) { need(n); const s = b.slice(at, at + n); at += n; return s; },
    hash() { return hashText(r.raw(32)); },
    bytes() { return r.raw(r.count()); },
    end() { if (at !== b.length) throw new Error("trailing bytes"); },
  };
  return r;
}

/// The payload of an OP_META script `6a <push>`, or null
function payloadOf(scriptHex) {
  const s = hexBytes(scriptHex);
  if (!s || s.length < 2 || s[0] !== 0x6a) return null;
  let len, at;
  if (s[1] >= 1 && s[1] <= 75) { len = s[1]; at = 2; }
  else if (s[1] === 0x4c && s.length > 2) { len = s[2]; at = 3; if (len <= 75) return null; }
  else if (s[1] === 0x4d && s.length > 3) { len = s[2] | (s[3] << 8); at = 4; if (len <= 255) return null; }
  else return null; // not a minimal push
  if (at + len !== s.length || len > MAX_PAYLOAD) return null;
  return s.slice(at);
}

/// One DT/1 op from a payload, or null when it is not valid DT/1
function decodeDt(p) {
  try {
    const r = reader(p);
    if (String.fromCharCode(...r.raw(4)) !== MAGIC) return null;
    if (r.u8() !== VERSION) return null;
    const code = r.u8();
    const op = { op: OPS[code] };
    if (!op.op) return null;
    if (code === 1) {
      op.kind = r.u8();
      const flags = r.u8();
      if (op.kind > 1 || flags & ~3) return null;
      op.supply = r.varint();
      if (op.supply < 1n) return null;
      op.outVout = r.count();
      op.content = bytesHex(r.raw(32));
      op.metaCid = r.bytes();
      if (op.metaCid.length < 1 || op.metaCid.length > 64) return null;
      if (flags & 1) { op.collection = r.hash(); op.collVout = r.count(); }
      if (flags & 2) {
        op.royaltyBps = r.u16();
        if (op.royaltyBps < 1) return null;
        op.royaltyPkh = bytesHex(r.raw(20));
      }
    } else if (code === 2) {
      op.groups = [];
      const n = r.count();
      for (let g = 0; g < n; g++) {
        const asset = r.hash();
        const outs = [];
        const k = r.count();
        for (let i = 0; i < k; i++) outs.push({ vout: r.count(), amount: r.varint() });
        op.groups.push({ asset, outs });
      }
    } else if (code === 3) {
      op.content = bytesHex(r.raw(32));
      op.certCid = r.bytes();
      op.provider = r.u8();
      op.checkedAt = r.u32();
      op.outVout = r.count();
    } else if (code === 4) {
      op.asset = r.hash();
      op.amount = r.varint();
    } else {
      op.cert = r.hash();
      op.reason = r.u8();
    }
    r.end();
    return op;
  } catch (_) {
    return null;
  }
}

/// The DT/1 op of a decoded transaction: exactly one OP_META output (§1, §3)
function opOf(tx) {
  const metas = (tx.vout || []).filter((o) => o.scriptPubKey && o.scriptPubKey.type === "nulldata");
  if (metas.length !== 1) return null;
  const p = payloadOf(metas[0].scriptPubKey.hex);
  const op = p && decodeDt(p);
  if (op) op.metaVout = metas[0].n;
  return op;
}

/// The color the op puts on output `vout` of transaction `txid`, as the
/// payload claims it. Whether the inputs carried that color is not checked
/// here: only an indexer replaying §5 knows, so every result is unverified.
function colorsAt(op, txid, vout) {
  if (!op || vout === op.metaVout) return [];
  const out = [];
  if (op.op === "issue") {
    if (op.outVout === vout) out.push({ asset: txid, amount: op.supply, kind: op.kind ? "collection" : "item", issue: op });
    if (op.collection && op.collVout === vout) out.push({ asset: op.collection, amount: 1n, kind: "collection" });
  } else if (op.op === "transfer") {
    for (const g of op.groups) {
      for (const o of g.outs) if (o.vout === vout) out.push({ asset: g.asset, amount: o.amount });
    }
  } else if (op.op === "certify" && op.outVout === vout) {
    out.push({ asset: txid, amount: 1n, kind: "certificate", cert: op });
  }
  return out;
}

// --- reading the wallet -------------------------------------------------------------

/// A decoded transaction: by the chain (needs -txindex for old ones), else
/// through the wallet's own copy
async function txOf(rpc, txid) {
  try {
    return await rpc("getrawtransaction", txid, 1);
  } catch (_) {
    const w = await rpc("gettransaction", txid);
    const d = await rpc("decoderawtransaction", w.hex);
    d.confirmations = w.confirmations;
    return d;
  }
}

/// `work` over `list`, a few at a time
async function batched(list, work) {
  const out = [];
  for (let i = 0; i < list.length; i += 6) {
    out.push(...await Promise.all(list.slice(i, i + 6).map(work)));
  }
  return out;
}

/// The wallet's colored outputs, as their transactions claim them. Locked
/// coins are read too: §10 tells holders to lock every colored outpoint, and
/// listunspent leaves locked coins out.
async function scanWallet(rpc) {
  const [unspent, locked] = await Promise.all([rpc("listunspent", 0), rpc("listlockunspent")]);
  const coins = new Map();
  for (const l of locked) coins.set(l.txid + ":" + l.vout, { txid: l.txid, vout: l.vout, locked: true });
  let skipped = 0;
  for (const u of unspent) {
    if (satOf(u.amount) > CARRIER_MAX) { skipped++; continue; }
    coins.set(u.txid + ":" + u.vout, { txid: u.txid, vout: u.vout, locked: false,
      value: satOf(u.amount), address: u.address, confirmations: u.confirmations });
  }
  const txids = [...new Set([...coins.values()].map((c) => c.txid))];
  const truncated = Math.max(0, txids.length - SCAN_MAX);
  const txs = new Map();
  await batched(txids.slice(0, SCAN_MAX), async (id) => {
    txs.set(id, await txOf(rpc, id).catch(() => null));
  });

  const items = [];
  for (const c of coins.values()) {
    const tx = txs.get(c.txid);
    if (!tx) continue;
    const out = (tx.vout || [])[c.vout];
    for (const col of colorsAt(opOf(tx), c.txid, c.vout)) {
      items.push(Object.assign({}, col, c, {
        value: c.value !== undefined ? c.value : (out ? BigInt(out.valueSat ?? satOf(out.value)) : null),
        address: c.address || (out && out.scriptPubKey.addresses ? out.scriptPubKey.addresses[0] : null),
        confirmations: c.confirmations !== undefined ? c.confirmations : tx.confirmations || 0,
      }));
    }
  }

  // An asset that arrived by TRANSFER: its terms are in its ISSUE (§3.2)
  const issues = new Map();
  await batched([...new Set(items.filter((i) => !i.issue && !i.cert).map((i) => i.asset))], async (id) => {
    const tx = await txOf(rpc, id).catch(() => null);
    const op = tx && opOf(tx);
    issues.set(id, op && op.op === "issue" ? op : op && op.op === "certify" ? { cert: op } : null);
  });
  for (const i of items) {
    if (i.issue || i.cert) continue;
    const found = issues.get(i.asset);
    if (found && found.cert) { i.cert = found.cert; i.kind = "certificate"; }
    else if (found) { i.issue = found; i.kind = found.kind ? "collection" : "item"; }
    else i.noIssue = true;
  }

  // Royalty addresses, from the key hashes in the payloads
  const pkhs = [...new Set(items.filter((i) => i.issue && i.issue.royaltyPkh).map((i) => i.issue.royaltyPkh))];
  const addrs = new Map();
  await batched(pkhs, async (pkh) => {
    const d = await rpc("decodescript", "76a914" + pkh + "88ac").catch(() => null);
    addrs.set(pkh, d && d.addresses ? d.addresses[0] : null);
  });
  for (const i of items) {
    if (i.issue && i.issue.royaltyPkh) i.royaltyAddress = addrs.get(i.issue.royaltyPkh) || "key hash " + i.issue.royaltyPkh;
  }

  items.sort((a, b) => (a.kind || "").localeCompare(b.kind || "") || a.asset.localeCompare(b.asset));
  return { items, skipped, truncated, at: new Date() };
}

// --- the NFT lane's wallet kit (divi-nft packages/nft-kit), testnet only -------------
// The kit pins to IPFS, builds each transaction and posts listings, talking to
// the NFT service through the node's /api/nft proxy (testnet only, see lib.rs).
// The node wallet signs: signmessage for the service's sign-in,
// signrawtransaction for the transactions, and the kit checks every signed
// transaction against the one it built before it broadcasts.

/// Divi Core's signrawtransaction names for the kit's sighash types
const SIGHASH_LABELS = { 0x01: "ALL", 0x83: "SINGLE|ANYONECANPAY", 0x81: "ALL|ANYONECANPAY" };

let kitLoad = null;
/// Coins the kit spent and the service has not yet seen spent
let spent = null;
/// The NFT service's sign-in per address: { token, expiresAt }. In memory only
const tokens = new Map();

/// The bundled kit (static/nftkit.js), fetched the first time it is needed
function loadKit() {
  kitLoad = kitLoad || new Promise((ok, fail) => {
    const s = document.createElement("script");
    s.src = "/nftkit.js";
    s.addEventListener("load", () => window.IronDiviNftKit ? ok(window.IronDiviNftKit) : fail(new Error("the NFT kit did not load")));
    s.addEventListener("error", () => { kitLoad = null; s.remove(); fail(new Error("could not load the NFT kit")); });
    document.head.append(s);
  });
  return kitLoad;
}

/// A kit acting as `address`, signed by the node wallet and signed in to the
/// NFT service. The wallet must be able to sign (see `unlocked`)
async function kitFor(ctx, address) {
  const K = await loadKit();
  // the bundle's fetch adds this to its writes to /api/nft
  window.__irondiviCsrf = () => ctx.state.csrf;
  spent = spent || new K.SpentTracker();
  const token = () => {
    const t = tokens.get(address);
    return t && Date.parse(t.expiresAt) > Date.now() + 60000 ? t.token : null;
  };
  const api = K.createNftApi("/api/nft/", { getToken: token });
  const signer = {
    address: () => address,
    isSignedIn: () => !!token(),
    spent,
    async signTx(req) {
      const label = SIGHASH_LABELS[req.hashType];
      if (!label) throw new Error("unsupported signature type 0x" + req.hashType.toString(16));
      // Divi Core's prevtxs take no amount
      const prevouts = req.built.prevouts.map((p) => ({ txid: p.txid, vout: p.vout, scriptPubKey: p.scriptPubKey }));
      const r = await ctx.rpc("signrawtransaction", K.txHex(req.built.tx), prevouts, null, label);
      return K.checkPasted(req.built.tx, req.built.prevouts, r.hex, req.indexes, req.hashType);
    },
  };
  if (!token()) tokens.set(address, await K.signIn(api, address, (m) => ctx.rpc("signmessage", address, m)));
  return new K.NftKit({ net: K.TESTNET, api, signer });
}

/// Run `work` with the wallet able to sign, then put it back the way it was:
/// staking only, or locked. `work` returns the message for the form
async function unlocked(ctx, f, work) {
  const before = ctx.state.wallet;
  const p = f.elements.p ? f.elements.p.value : "";
  const locked = before === "locked" || before === "unlocked-for-staking";
  // With the passphrase left blank, an enrolled node wallet passkey (WebAuthn
  // PRF) unseals it on the node instead
  const slots = nodeSlots(ctx);
  let pk = null;
  if (locked && !p) {
    if (!slots.length || !ctx.passkey) throw new Error("enter the wallet passphrase");
    pk = await ctx.passkey.evalPrfPasskey(slots);
    await ctx.post("/api/node-wallet/unlock-passkey", {
      slot_id: pk.slot_id, prf_output: pk.prf_output, staking_only: false, timeout: 600,
    });
  } else if (locked) {
    await ctx.rpc("walletpassphrase", p, 600, false);
  }
  let done;
  let restore = null;
  try {
    done = await work();
  } finally {
    const back = before === "unlocked-for-staking"
      ? (pk
        ? ctx.post("/api/node-wallet/unlock-passkey", { slot_id: pk.slot_id, prf_output: pk.prf_output, staking_only: true, timeout: 0 })
        : ctx.rpc("walletpassphrase", p, 0, true))
      : before === "locked" ? ctx.rpc("walletlock") : null;
    if (pk) pk.prf_output = "";
    if (back) restore = await back.then(() => null, (e) => e.message);
  }
  return done + (restore ? " The wallet could not go back to " + before + ": " + restore : "");
}

/// Node wallet passkey slots enrolled for this host
function nodeSlots(ctx) {
  return ((ctx.state && ctx.state.node_passkeys) || []).filter((s) => s.rp_id === window.location.hostname);
}

/// A "… with Passkey" button for a signing form: it submits the form with the
/// passphrase blank, so `unlocked` unseals the wallet with the passkey
function passkeyButton(ctx, f, label, testid) {
  const w = ctx.state.wallet;
  if (!(w === "locked" || w === "unlocked-for-staking") || !nodeSlots(ctx).length || !ctx.passkey) return null;
  return ctx.h("button", {
    type: "button", class: "secondary", "data-testid": testid,
    onclick: () => {
      if (f.elements.p) f.elements.p.value = "";
      f.requestSubmit();
    },
  }, label);
}

/// The wallet address with the most confirmed uncolored coin: the kit pays the
/// fee and the carrier from one address
async function fundingAddress(ctx) {
  const colored = new Set(scan.items.map((i) => i.txid + ":" + i.vout));
  const by = new Map();
  for (const c of await ctx.rpc("listunspent", 1)) {
    if (!c.address || c.spendable === false || colored.has(c.txid + ":" + c.vout)) continue;
    by.set(c.address, (by.get(c.address) || 0) + c.amount);
  }
  const best = [...by].sort((a, b) => b[1] - a[1])[0];
  if (!best) throw new Error("the wallet has no confirmed coins to pay the fee and the carrier");
  return best[0];
}

/// §3.2 ISSUE: the kit pins the media and the metadata JSON (§6) to IPFS, then
/// builds the ISSUE, which commits to the metadata's CID
async function mintIssue(ctx, f, progress) {
  const { val } = ctx;
  const file = f.elements.file.files[0] || null;
  const kind = val(f, "kind") === "1" ? "collection" : "item";
  const bps = val(f, "bps").trim();
  const royaltyTo = val(f, "royalty").trim();
  if (!bps !== !royaltyTo) throw new Error("a royalty needs both the bps and the address");
  const colId = val(f, "collection");
  const name = val(f, "name").trim();
  if (!name) throw new Error("enter a name");
  if (!confirm("Mint " + kind + " \"" + name + "\" on testnet? It pins the files and pays the fee and a carrier.")) return "Not minted.";
  return unlocked(ctx, f, async () => {
    // Items of a collection are minted by whoever holds its token
    const holder = colId ? scan.items.find((i) => i.asset === colId) : null;
    const address = holder ? holder.address : await fundingAddress(ctx);
    progress("Signing in to the NFT service as " + address + "…");
    const kit = await kitFor(ctx, address);
    const collection = colId ? await kit.show(colId) : null;
    const r = await kit.mint({
      kind, file, name, description: val(f, "description"), attributes: [], externalUrl: "",
      royalty: bps ? { bps: Number(bps), address: royaltyTo } : null, collection,
    }, progress);
    return "Minted: asset " + r.txid + ", metadata ipfs://" + r.metaCid + ". Rescan the gallery once it confirms, and lock the coin.";
  });
}

/// §7.1: the coin signed SINGLE|ANYONECANPAY to pay the price to the address
/// that holds it, posted to the NFT service's order book
async function postListing(ctx, f, i) {
  const price = parseDivi(ctx.val(f, "price"));
  if (price <= 0n) throw new Error("enter a price");
  if (!confirm("List " + short(i.asset) + " for " + divi(price) + "? Anyone who pays that takes the asset, until the coin moves.")) return "Not listed.";
  return unlocked(ctx, f, async () => {
    const kit = await kitFor(ctx, i.address);
    const asset = await kit.show(i.asset);
    if (asset.owner !== i.address) {
      throw new Error("the NFT service has this asset at " + asset.owner + ", not at " + i.address + "; wait until it has indexed the coin");
    }
    const l = await kit.list(asset, price);
    return "Listed for " + divi(price) + " (listing " + l.id + "). To cancel for certain, move the coin to yourself (§7.3).";
  });
}

/// §5, §10: a TRANSFER spends the colored coin, funds the fee from uncolored
/// coins only and must carry the OP_META payload, or the asset burns. The kit
/// has the builder; it stays off here until it is proven on testnet
async function sendTransfer() { throw new Error(sendTransfer.waits); }
sendTransfer.waits = "Sending stays off until the NFT kit's TRANSFER builder is proven on testnet: " +
  "a transfer built wrong burns the asset.";

/// Switch off a form's submit while its work is a stub, and say why
function stubbed(h, f, waits) {
  if (!waits) return f;
  f.querySelector("button[type=submit]").disabled = true;
  f.append(h("p", { class: "muted small" }, waits));
  return f;
}

// --- the page ------------------------------------------------------------------------

window.irondiviNft = async function (ctx) {
  const { h, show, rpc, form, field, val, note, state } = ctx;
  const w = state.wallet;
  if (w === null || w === undefined) {
    return show(h("section", {}, h("h2", {}, "NFTs"), h("p", { class: "muted" }, "The daemon has no wallet loaded.")));
  }
  const canWrite = w !== "unencrypted";
  const net = /main/.test(state.network || "") ? "mainnet" : /test/.test(state.network || "") ? "testnet" : null;
  const org = net ? ORG_ROYALTY[net] : null;
  /// Minting and listing go through the NFT service, which runs on testnet only
  const offNet = net === "testnet" ? null
    : "Minting and listing run on testnet only for now: the NFT service this page uses is the testnet one.";
  /// The passphrase field for forms that sign, when the wallet cannot sign as it is
  const passField = () => w === "locked" || w === "unlocked-for-staking"
    ? field(nodeSlots(ctx).length ? "Wallet passphrase (or leave blank and use your passkey)" : "Wallet passphrase",
      "p", "password", { autocomplete: "current-password" }) : null;
  /// Put a "… with Passkey" button beside a signing form's submit button
  const withPasskey = (f, label, testid) => {
    const b = passkeyButton(ctx, f, label, testid);
    if (b) {
      b.disabled = !!offNet;
      f.querySelector("button[type=submit]").after(b);
    }
    return f;
  };

  if (!scan) {
    show(h("p", { class: "muted" }, "Reading the wallet for DT/1 assets…"));
    scan = await scanWallet(rpc);
  }

  /// Held assets as select options
  function assetOptions(filter) {
    const held = scan.items.filter(filter || (() => true));
    if (!held.length) return [h("option", { value: "" }, "no assets found in this wallet")];
    return held.map((i) => h("option", { value: String(scan.items.indexOf(i)) },
      (i.kind || "asset") + " " + short(i.asset) + (i.amount !== 1n ? " × " + i.amount : "") + " at " + short(i.txid) + ":" + i.vout));
  }

  function picked(f) {
    if (val(f, "asset") === "") throw new Error("no asset to pick");
    const i = scan.items[Number(val(f, "asset"))];
    if (!i) throw new Error("pick an asset");
    return i;
  }

  // --- gallery ---

  function card(i) {
    const msg = h("p", { class: "note" });
    const badges = [h("span", { class: "badge warn", title: "Only the NFT index can confirm the color of the inputs (§5)" }, "unverified")];
    if (!i.confirmations) badges.push(h("span", { class: "badge" }, "unconfirmed"));
    if (i.locked) badges.push(h("span", { class: "badge live" }, "locked"));
    const rows = [
      ["Asset id", i.asset],
      ["Amount", i.amount.toString()],
      ["Held in", i.txid + ":" + i.vout],
      ["Address", i.address],
      ["Carrier", i.value === null ? null : divi(i.value)],
      ["Confirmations", i.confirmations],
    ];
    if (i.issue) {
      rows.push(["Supply", i.issue.supply.toString()], ["Metadata", "ipfs://" + cidText(i.issue.metaCid)],
        ["Content sha256", i.issue.content]);
      if (i.issue.collection) rows.push(["Collection", i.issue.collection]);
      rows.push(["Royalty", i.issue.royaltyBps ? percent(i.issue.royaltyBps) + " to " + i.royaltyAddress
        : i.issue.collection ? "the collection's, if it has one" : "none"]);
    }
    if (i.cert) {
      rows.push(["Certified sha256", i.cert.content], ["Certificate", "ipfs://" + cidText(i.cert.certCid)],
        ["Checked by", PROVIDERS[i.cert.provider] || "provider " + i.cert.provider],
        ["Checked at", new Date(i.cert.checkedAt * 1000).toISOString()]);
    }
    if (i.noIssue) rows.push(["Issue", "not readable here (the node needs -txindex), or not a DT/1 issue"]);
    const lock = !i.locked && canWrite ? h("button", { type: "button", onclick: async (e) => {
      e.target.disabled = true;
      note(msg, "Locking…", true);
      try {
        await rpc("lockunspent", false, [{ txid: i.txid, vout: i.vout }]);
        i.locked = true;
        render();
      } catch (err) {
        note(msg, err.message, false);
        e.target.disabled = false;
      }
    } }, "Lock this coin") : null;
    return h("div", { class: "card" },
      h("h3", {}, (i.kind || "asset").replace(/^./, (c) => c.toUpperCase()) + " " + short(i.asset)),
      h("div", { class: "row wrap" }, badges),
      kvList(rows),
      lock ? h("div", { class: "row" }, lock) : null,
      !i.locked && !canWrite ? h("p", { class: "muted small" }, "Encrypt the wallet to lock this coin.") : null,
      msg);
  }

  function kvList(rows) {
    return h("dl", { class: "kv" }, rows.flatMap(([k, v]) =>
      [h("dt", {}, k), h("dd", {}, v === undefined || v === null ? "—" : String(v))]));
  }

  async function rescan() {
    scan = null;
    try {
      await window.irondiviNft(ctx);
    } catch (err) {
      show(h("section", {}, h("h2", {}, "NFTs"), h("p", { class: "note err" }, err.message)));
    }
  }

  function gallery() {
    const unlocked = scan.items.filter((i) => !i.locked).length;
    return [
      h("p", { class: "muted" }, "DT/1 assets on this wallet's coins, read from the transactions that made them. ",
        "Spending a colored coin any other way than a DT/1 transfer burns the asset (§5): lock each one so the wallet never uses it to pay."),
      unlocked ? h("p", { class: "note err" }, unlocked + " colored coin(s) are not locked. The Wallet page's Pay form may spend them, which burns the asset.") : null,
      h("div", { class: "row wrap" },
        h("button", { type: "button", onclick: rescan }, "Rescan"),
        h("span", { class: "muted small" }, "Read " + scan.at.toLocaleTimeString() + ". " +
          (scan.skipped ? scan.skipped + " coin(s) above " + divi(CARRIER_MAX) + " not read. " : "") +
          (scan.truncated ? scan.truncated + " transaction(s) over the limit of " + SCAN_MAX + " not read." : ""))),
      scan.items.length ? h("div", { class: "grid" }, scan.items.map(card))
        : h("div", { class: "card" }, h("p", { class: "muted" }, "No DT/1 assets found on this wallet's coins.")),
    ];
  }

  // --- mint ---

  function mint() {
    const hash = h("p", { class: "muted small" });
    const warn = h("p", { class: "note" });
    const progress = h("p", { class: "muted small" });
    const f = form("Mint", [
      h("label", { class: "field" }, h("span", {}, "Kind"),
        h("select", { name: "kind" }, h("option", { value: "0" }, "Item"), h("option", { value: "1" }, "Collection"))),
      h("label", { class: "field" }, h("span", {}, "Media file"), h("input", { name: "file", type: "file" })),
      hash,
      field("Name", "name"),
      field("Description (optional)", "description"),
      h("label", { class: "field" }, h("span", {}, "Collection (optional; needs its collection token, §3.2)"),
        h("select", { name: "collection" }, h("option", { value: "" }, "none"),
          scan.items.filter((i) => i.kind === "collection").map((i) => h("option", { value: i.asset }, short(i.asset))))),
      field("Royalty in bps (optional; 500 = 5 %)", "bps", "number", { min: 1, max: 65535, step: 1 }),
      field("Royalty address (optional)", "royalty", "text", { spellcheck: "false" }),
      warn,
      passField(),
      progress,
    ], "Mint", async (f) => {
      try { return await mintIssue(ctx, f, (s) => { progress.textContent = s; }); }
      finally { progress.textContent = ""; }
    }, h("p", { class: "muted" },
      "Creates a DT/1 asset (§3.2), one of one: the media's sha256 and the metadata's IPFS address go on the chain; ",
      "the asset id is the id of the minting transaction. The media and the metadata are pinned by the NFT service."));
    f.elements.file.addEventListener("change", async () => {
      const file = f.elements.file.files[0];
      hash.textContent = "";
      if (!file) return;
      if (!crypto.subtle) { hash.textContent = "The sha256 needs HTTPS or localhost; the NFT lane's API computes it otherwise."; return; }
      const d = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
      hash.textContent = "sha256 " + bytesHex(new Uint8Array(d)) + " · " + file.size + " bytes";
    });
    f.elements.bps.addEventListener("input", () => {
      const bps = Number(val(f, "bps"));
      if (bps > 1000) note(warn, "Above 10 %: every resale owes the creator " + percent(bps) + " of the price (§7.4).", false);
      else warn.textContent = "";
    });
    return stubbed(h, withPasskey(f, "Mint with Passkey", "nft-mint-passkey"), offNet);
  }

  // --- list ---

  function list() {
    const terms = h("div", {});
    const f = form("List for sale", [
      h("label", { class: "field" }, h("span", {}, "Asset"), h("select", { name: "asset" }, assetOptions((i) => i.kind !== "certificate"))),
      field("Price in DIVI (paid to you)", "price", "text", { inputmode: "decimal" }),
      terms,
      passField(),
    ], "Sign listing", (f) => postListing(ctx, f, picked(f)), h("p", { class: "muted" },
      "A listing is the coin signed SINGLE|ANYONECANPAY to pay you the price (§7.1). Any buyer can complete it ",
      "through any marketplace; they add the royalties. To cancel for certain, move the coin to yourself (§7.3)."));

    function update() {
      let i, price;
      try { i = picked(f); price = parseDivi(val(f, "price")); } catch (_) { terms.replaceChildren(); return; }
      const rows = [["You receive", divi(price)], ["Paid to", i.address + ", the address holding the asset"]];
      const bps = i.issue && i.issue.royaltyBps;
      rows.push(["Creator royalty", bps ? divi(royaltyFor(price, bps)) + " (" + percent(bps) + ")" : "none"]);
      if (i.kind === "item" && org) rows.push(["Organization royalty", divi(royaltyFor(price, org.bps)) + " (" + percent(org.bps) + ", §7.6" + (org.from ? ", from block " + org.from : "") + ")"]);
      rows.push(["Buyer also pays", divi(CARRIER) + " carrier and the fee"]);
      terms.replaceChildren(kvList(rows));
    }
    f.elements.asset.addEventListener("change", update);
    f.elements.price.addEventListener("input", update);

    return [stubbed(h, withPasskey(f, "List with Passkey", "nft-list-passkey"), offNet),
      h("div", { class: "card" }, h("h3", {}, "Open listings"),
        h("p", { class: "muted" }, "Signed listings go to the NFT service's order book, not to the Divi chain. ",
          "This page posts them; it does not show the book yet."))];
  }

  // --- send ---

  function send() {
    const check = h("p", { class: "note" });
    const f = form("Send", [
      h("label", { class: "field" }, h("span", {}, "Asset"), h("select", { name: "asset" }, assetOptions())),
      field("To address", "to", "text", { spellcheck: "false", placeholder: net === "mainnet" ? "D…" : "y…" }),
      check,
      field("Amount (all of it if empty)", "amount", "number", { min: 1, step: 1 }),
    ], "Send", (f) => sendTransfer(ctx, f), h("p", { class: "muted" },
      "Moves the asset with a DT/1 transfer (§3.1). Never send a colored coin with the Wallet page's Pay form: ",
      "a wallet that does not write the transfer burns the asset (§5)."));
    f.elements.to.addEventListener("change", async () => {
      const a = val(f, "to").trim();
      if (!a) { check.textContent = ""; return; }
      try {
        const v = await rpc("validateaddress", a);
        if (v.isvalid) note(check, "A valid address" + (v.ismine ? " of this wallet." : "."), true);
        else note(check, "Not a valid address on " + (state.network || "this network") + ".", false);
      } catch (err) {
        note(check, err.message, false);
      }
    });
    return stubbed(h, f, sendTransfer.waits);
  }

  // --- tabs ---

  const tabs = { gallery: ["Gallery", gallery], mint: ["Mint", mint], list: ["List", list], send: ["Send", send] };

  function render() {
    if (!tabs[nftTab]) nftTab = "gallery";
    show(h("section", {},
      h("h2", {}, "NFTs"),
      canWrite ? null : h("p", { class: "note err" }, "Encrypt the wallet on the Security page before locking, listing or sending."),
      h("div", { class: "tabs" }, Object.entries(tabs).map(([key, [label]]) =>
        h("button", { type: "button", class: key === nftTab ? "on" : "", onclick: () => { nftTab = key; render(); } }, label))),
      tabs[nftTab][1]()));
  }

  render();
};

})();
