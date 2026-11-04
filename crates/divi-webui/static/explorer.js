// SPDX-License-Identifier: AGPL-3.0-only
// IronDivi web interface: the built-in block explorer. It reads the node's own
// chain through the signed-in JSON-RPC proxy (and /api/explorer/address/:addr
// for arbitrary addresses), so nothing leaves the node.
"use strict";

window.irondiviExplorer = async function (ui, rest) {
  const { h, show, rpc, getJson, kv } = ui;
  const PAGE = 15;
  const [sub, arg] = rest || [];

  const txLink = (txid, label) => h("a", { href: "#/explorer/tx/" + txid, class: "mono", "data-txid": txid }, label || txid);
  const addrLink = (a) => h("a", { href: "#/explorer/address/" + encodeURIComponent(a), class: "mono" }, a);
  const blockLink = (hashOrHeight, label) => h("a", { href: "#/explorer/block/" + hashOrHeight, class: "mono" }, label === undefined ? String(hashOrHeight) : String(label));
  const when = (t) => (t ? new Date(t * 1000).toLocaleString() : "—");
  const divi = (n) => (n === undefined || n === null ? "—" : Number(n).toFixed(8).replace(/\.?0+$/, "") + " DIVI");
  const short = (s) => (s && s.length > 20 ? s.slice(0, 10) + "…" + s.slice(-8) : s);
  const table = (testid, head, rows) => h("table", { class: "table", "data-testid": testid },
    h("thead", {}, h("tr", {}, head.map((c) => h("th", {}, c)))),
    h("tbody", {}, rows));
  const td = (...kids) => h("td", {}, ...kids);
  const notFound = (what) => /not found|no such|invalid|unknown/i.test(what);

  function isCoinstake(tx) {
    if (!tx || !tx.vin || !tx.vin.length || tx.vin[0].coinbase) return false;
    const first = tx.vout && tx.vout[0];
    return !!first && Number(first.value) === 0 && !(first.scriptPubKey && first.scriptPubKey.hex);
  }

  function blockType(b) {
    if (b.height === 0) return "Genesis";
    const txs = Array.isArray(b.tx) ? b.tx : [];
    if (txs.length > 1 && typeof txs[1] === "object" && isCoinstake(txs[1])) return "PoS (coinstake)";
    return "PoW";
  }

  function searchForm(initial) {
    const msg = h("p", { class: "note" });
    const input = h("input", {
      name: "q", type: "search", autocomplete: "off", spellcheck: "false",
      placeholder: "Block height, block hash, txid or address", "data-testid": "explorer-search-input",
    });
    input.value = initial || "";
    const f = h("form", {
      class: "card explorer-search", "data-testid": "explorer-search-form",
      onsubmit: async (e) => {
        e.preventDefault();
        const q = input.value.trim();
        if (!q) return;
        msg.textContent = "";
        try {
          location.hash = await resolve(q);
        } catch (err) {
          ui.note(msg, err.message, false);
        }
      },
    }, h("div", { class: "row" }, input, h("button", { type: "submit" }, "Search")), msg);
    return f;
  }

  /// Where a search goes: a height, a block hash, a txid or an address
  async function resolve(q) {
    if (/^\d+$/.test(q)) {
      const hash = await rpc("getblockhash", Number(q));
      return "#/explorer/block/" + hash;
    }
    if (/^[0-9a-fA-F]{64}$/.test(q)) {
      const lower = q.toLowerCase();
      const block = await rpc("getblock", lower, true).catch(() => null);
      if (block) return "#/explorer/block/" + lower;
      const tx = await rpc("getrawtransaction", lower, 1).catch(() => null)
        || await rpc("gettransaction", lower).catch(() => null);
      if (tx) return "#/explorer/tx/" + lower;
      throw new Error("No block or transaction " + short(lower) + " on this node.");
    }
    if (/^[1-9A-HJ-NP-Za-km-z]{25,40}$/.test(q)) return "#/explorer/address/" + encodeURIComponent(q);
    throw new Error("Enter a block height, a 64-character hash or txid, or a Divi address.");
  }

  function page(title, ...kids) {
    show(h("section", { class: "explorer" },
      h("h2", {}, h("a", { href: "#/explorer" }, "Explorer"), title ? " · " + title : ""),
      searchForm(), ...kids));
  }

  // --- overview ----------------------------------------------------------------

  async function overview(fromHeight) {
    show(h("p", { class: "muted" }, "Reading the chain…"));
    const [chain, info, mem, tips, pool] = await Promise.all([
      rpc("getblockchaininfo").catch((e) => ({ error: e.message })),
      rpc("getinfo").catch(() => ({})),
      rpc("getmempoolinfo").catch(() => ({})),
      rpc("getchaintips").catch(() => []),
      rpc("getrawmempool", true).catch(() => ({})),
    ]);
    const tip = Number(chain.blocks ?? info.blocks ?? 0);
    const top = fromHeight === undefined ? tip : Math.min(tip, Math.max(0, fromHeight));
    const heights = [];
    for (let i = top; i >= 0 && heights.length < PAGE; i--) heights.push(i);
    const blocks = await Promise.all(heights.map(async (ht) => {
      try {
        const hash = await rpc("getblockhash", ht);
        return await rpc("getblock", hash, 2);
      } catch (err) {
        return { height: ht, error: err.message };
      }
    }));

    const summary = h("div", { class: "grid" },
      h("div", { class: "card", "data-testid": "explorer-chain-summary" }, h("h3", {}, "Chain"), kv([
        ["Network", chain.chain], ["Blocks", blockLink(tip)], ["Headers", chain.headers],
        ["Best block", chain.bestblockhash ? blockLink(chain.bestblockhash, short(chain.bestblockhash)) : undefined],
        ["Difficulty", chain.difficulty], ["Money supply", info.moneysupply !== undefined ? divi(info.moneysupply) : undefined],
        ["Connections", info.connections], ["Chain tips", Array.isArray(tips) ? tips.length : undefined],
      ])),
      h("div", { class: "card" }, h("h3", {}, "Mempool"), kv([
        ["Transactions", mem.size], ["Bytes", mem.bytes], ["Usage", mem.usage],
      ])));

    const poolRows = Object.entries(pool || {}).sort((a, b) => (b[1].time || 0) - (a[1].time || 0))
      .map(([txid, e]) => h("tr", {}, td(txLink(txid, short(txid))), td(String(e.size ?? "—")),
        td(divi(e.fee)), td(when(e.time))));
    const mempool = h("div", { class: "card", "data-testid": "explorer-mempool" }, h("h3", {}, "Live mempool"),
      poolRows.length ? table("explorer-mempool-table", ["Transaction", "Size", "Fee", "Seen"], poolRows)
        : h("p", { class: "muted" }, "No unconfirmed transactions."));

    const rows = blocks.map((b) => b.error
      ? h("tr", {}, td(String(b.height)), h("td", { colspan: "5", class: "muted" }, b.error))
      : h("tr", {}, td(blockLink(b.height)), td(blockLink(b.hash, short(b.hash))), td(when(b.time)),
        td(String(b.nTx ?? (b.tx || []).length)), td(blockType(b)), td(String(b.size))));
    const older = top - PAGE;
    const newer = top + PAGE;
    const nav = h("div", { class: "row wrap" },
      top < tip ? h("a", { href: "#/explorer/blocks/" + Math.min(tip, newer), "data-testid": "explorer-newer" }, "← Newer") : null,
      older >= 0 ? h("a", { href: "#/explorer/blocks/" + older, "data-testid": "explorer-older" }, "Older →") : null);
    const recent = h("div", { class: "card", "data-testid": "explorer-recent-blocks" },
      h("h3", {}, top === tip ? "Recent blocks" : "Blocks from " + top),
      table("explorer-blocks-table", ["Height", "Hash", "Time", "Txs", "Type", "Size"], rows), nav);

    page(null, chain.error ? h("p", { class: "note err" }, chain.error) : null, summary, recent, mempool);
  }

  // --- block -------------------------------------------------------------------

  async function block(id) {
    show(h("p", { class: "muted" }, "Reading the block…"));
    let hash = id;
    if (/^\d+$/.test(id)) hash = await rpc("getblockhash", Number(id));
    const b = await rpc("getblock", hash, 2);
    const txs = (b.tx || []).map((t) => (typeof t === "string" ? { txid: t } : t));
    const txRows = txs.map((t, i) => {
      const out = (t.vout || []).reduce((a, v) => a + Number(v.value || 0), 0);
      const kind = t.vin && t.vin[0] && t.vin[0].coinbase ? "coinbase" : isCoinstake(t) ? "coinstake" : "";
      return h("tr", {}, td(String(i)), td(txLink(t.txid)), td(kind ? h("span", { class: "badge" }, kind) : ""), td(divi(out)));
    });
    page("Block " + b.height,
      h("div", { class: "card", "data-testid": "explorer-block-detail" }, h("h3", {}, "Block " + b.height), kv([
        ["Height", b.height], ["Hash", h("span", { class: "mono", "data-testid": "explorer-block-hash" }, b.hash)],
        ["Confirmations", b.confirmations],
        ["Time", when(b.time)], ["Type", blockType(b)], ["Size", b.size + " bytes"], ["Version", b.version],
        ["Merkle root", h("span", { class: "mono" }, b.merkleroot)], ["Bits", b.bits], ["Difficulty", b.difficulty],
        ["Nonce", b.nonce], ["Money supply", b.moneysupply !== undefined ? divi(b.moneysupply) : undefined],
        ["Previous block", b.previousblockhash ? blockLink(b.previousblockhash, short(b.previousblockhash)) : "none (genesis)"],
        ["Next block", b.nextblockhash ? blockLink(b.nextblockhash, short(b.nextblockhash)) : "none yet (tip)"],
      ]),
      h("div", { class: "row wrap" },
        b.previousblockhash ? h("a", { href: "#/explorer/block/" + b.previousblockhash, "data-testid": "explorer-prev-block" }, "← Previous block") : null,
        b.nextblockhash ? h("a", { href: "#/explorer/block/" + b.nextblockhash, "data-testid": "explorer-next-block" }, "Next block →") : null)),
      h("div", { class: "card" }, h("h3", {}, txs.length + " transaction(s)"),
        table("explorer-block-txs", ["#", "Transaction", "Kind", "Output total"], txRows)));
  }

  // --- transaction -------------------------------------------------------------

  async function lookupTx(txid) {
    try {
      return { tx: await rpc("getrawtransaction", txid, 1), source: "chain" };
    } catch (first) {
      const wtx = await rpc("gettransaction", txid).catch(() => null);
      if (!wtx || !wtx.hex) {
        throw new Error(notFound(first.message)
          ? "Transaction " + short(txid) + " is not on this node. Turn on txindex=1 in Settings to look up any transaction."
          : first.message);
      }
      const tx = await rpc("decoderawtransaction", wtx.hex);
      Object.assign(tx, { confirmations: wtx.confirmations, blockhash: wtx.blockhash, time: wtx.time, blocktime: wtx.blocktime });
      return { tx, source: "wallet" };
    }
  }

  function opReturn(spk) {
    const asm = (spk && spk.asm) || "";
    const m = asm.match(/^OP_RETURN\s*([0-9a-fA-F]*)/);
    if (!m) return null;
    const hex = m[1] || "";
    let text = "";
    try {
      const bytes = new Uint8Array((hex.match(/../g) || []).map((x) => parseInt(x, 16)));
      text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch (_) { text = ""; }
    return h("span", {}, h("code", {}, hex || "(empty)"),
      text && /^[\x20-\x7e\s]+$/.test(text) ? h("span", { class: "muted" }, " “" + text + "”") : null);
  }

  async function tx(txid) {
    show(h("p", { class: "muted" }, "Reading the transaction…"));
    const { tx: t, source } = await lookupTx(txid);
    const coinbase = t.vin && t.vin[0] && t.vin[0].coinbase;
    const coinstake = isCoinstake(t);
    let height = t.height;
    if (height === undefined && t.blockhash) {
      height = await rpc("getblock", t.blockhash, true).then((b) => b.height, () => undefined);
    }
    const spent = await Promise.all((t.vout || []).map((v) =>
      rpc("gettxout", t.txid, v.n, true).then((r) => (r ? "unspent" : "spent"), () => "unknown")));
    const vinRows = (t.vin || []).map((v, i) => h("tr", {}, td(String(i)),
      v.coinbase ? td(h("span", { class: "badge" }, "coinbase"), " ", h("code", {}, short(v.coinbase)))
        : td(txLink(v.txid, short(v.txid)), ":" + v.vout), td(String(v.sequence ?? "—"))));
    const voutRows = (t.vout || []).map((v, i) => {
      const spk = v.scriptPubKey || {};
      const addrs = spk.addresses || (spk.address ? [spk.address] : []);
      const ret = opReturn(spk);
      return h("tr", {}, td("#" + v.n), td(divi(v.value)), td(spk.type || "—"),
        td(ret || (addrs.length ? addrs.map((a) => h("div", {}, addrLink(a))) : h("span", { class: "muted" }, "—"))),
        td(h("span", { class: "badge" + (spent[i] === "unspent" ? " ok" : "") }, spent[i])));
    });
    page("Transaction",
      h("div", { class: "card", "data-testid": "explorer-tx-detail" },
        h("h3", {}, "Transaction ", coinbase ? h("span", { class: "badge" }, "coinbase") : null,
          coinstake ? h("span", { class: "badge" }, "coinstake") : null,
          source === "wallet" ? h("span", { class: "badge warn" }, "from this node's wallet") : null),
        kv([
          ["Txid", h("span", { class: "mono", "data-testid": "explorer-txid" }, t.txid)],
          ["Confirmations", t.confirmations ?? 0],
          ["Block", t.blockhash ? blockLink(t.blockhash, height !== undefined ? height + " · " + short(t.blockhash) : short(t.blockhash)) : "in the mempool"],
          ["Time", when(t.blocktime || t.time)], ["Size", t.size !== undefined ? t.size + " bytes" : undefined],
          ["Version", t.version], ["Lock time", t.locktime],
        ])),
      h("div", { class: "card" }, h("h3", {}, "Inputs"), table("explorer-tx-vin", ["#", "Spends", "Sequence"], vinRows)),
      h("div", { class: "card" }, h("h3", {}, "Outputs"), table("explorer-tx-vout", ["#", "Value", "Script", "To", "State"], voutRows)));
  }

  // --- address -----------------------------------------------------------------

  async function address(addr) {
    show(h("p", { class: "muted" }, "Reading the address…"));
    const a = await getJson("/api/explorer/address/" + encodeURIComponent(addr));
    if (!a.indexed) {
      return page("Address",
        h("div", { class: "card", "data-testid": "explorer-address-detail" }, h("h3", {}, "Address"),
          kv([["Address", h("span", { class: "mono" }, a.address)], ["Type", a.address_type]]),
          h("p", { class: "note err" }, a.hint || "This node does not index addresses."),
          h("p", {}, h("a", { href: "#/settings" }, "Open Settings"))));
    }
    const utxos = (a.utxos || []).map((u) => h("tr", {}, td(txLink(u.txid, short(u.txid)), ":" + (u.vout ?? u.outputIndex ?? "")),
      td(divi((u.satoshis ?? u.value ?? 0) / 1e8)), td(String(u.height ?? "—"))));
    const history = (a.history || []).map((x) => {
      const txid = typeof x === "string" ? x : x.txid;
      return h("tr", {}, td(txLink(txid, short(txid))),
        td(typeof x === "object" && x.height != null ? (x.height > 0 ? String(x.height) : "pending") : "—"),
        td(typeof x === "object" && x.satoshis != null ? divi(x.satoshis / 1e8) : "—"));
    });
    page("Address",
      h("div", { class: "card", "data-testid": "explorer-address-detail" }, h("h3", {}, "Address"), kv([
        ["Address", h("span", { class: "mono" }, a.address)], ["Type", a.address_type],
        ["Confirmed", divi((a.confirmed_sat || 0) / 1e8)], ["Pending", divi((a.pending_sat || 0) / 1e8)],
        ["Unspent coins", (a.utxos || []).length], ["Transactions", (a.history || []).length],
      ])),
      h("div", { class: "card" }, h("h3", {}, "Unspent coins"), utxos.length
        ? table("explorer-address-utxos", ["Coin", "Value", "Height"], utxos) : h("p", { class: "muted" }, "None.")),
      h("div", { class: "card" }, h("h3", {}, "History"), history.length
        ? table("explorer-address-history", ["Transaction", "Height", "Change"], history) : h("p", { class: "muted" }, "None.")));
  }

  try {
    if (sub === "block" && arg) return await block(decodeURIComponent(arg));
    if (sub === "tx" && arg) return await tx(decodeURIComponent(arg).toLowerCase());
    if (sub === "address" && arg) return await address(decodeURIComponent(arg));
    if (sub === "blocks" && arg && /^\d+$/.test(arg)) return await overview(Number(arg));
    return await overview();
  } catch (err) {
    page("Not found", h("p", { class: "note err", "data-testid": "explorer-error" }, err.message));
  }
};
