// SPDX-License-Identifier: AGPL-3.0-only
// IronDivi web interface: the interface's own wallets, as many as one likes.
// Each keeps its recovery words sealed under its own passphrase on the node;
// balances and history come from the node's Electrum backend, mempool included.
"use strict";

window.irondiviWallets = async function (ui) {
  const { h, show, post, getJson, form, field, val, note } = ui;
  const SAT = 100000000;
  const divi = (sat) => (Number(sat || 0) / SAT).toFixed(8).replace(/\.?0+$/, "") + " DIVI";
  const go = () => window.irondiviWallets(ui);

  let data;
  try {
    data = await getJson("/api/wallets");
  } catch (err) {
    return show(h("section", {}, h("h2", {}, "Wallets"), h("p", { class: "note err" }, err.message)));
  }

  /// The recovery words, shown once, with what to do with them
  function wordsCard(title, words) {
    const list = h("ol", { class: "words" }, words.split(" ").map((w) => h("li", {}, w)));
    return h("div", { class: "card warn" }, h("h3", {}, title),
      h("p", {}, "Write these words down, in order, and keep them offline. With them anyone can spend this wallet; without them and the passphrase, nobody can restore it."),
      list,
      h("div", { class: "row" }, h("button", { type: "button", onclick: go }, "I have written them down")));
  }

  const create = form("New wallet", [
    field("Name", "name", "text", { maxlength: 64, required: true }),
    field("Passphrase (8 characters or more)", "p", "password", { autocomplete: "new-password", required: true }),
    field("Passphrase again", "p2", "password", { autocomplete: "new-password", required: true }),
    field("Extra BIP39 word (optional; you need it to restore)", "bip39", "password", { autocomplete: "off" }),
  ], "Create", async (f) => {
    if (val(f, "p") !== val(f, "p2")) throw new Error("the passphrases differ");
    const r = await post("/api/wallets/create", { name: val(f, "name"), passphrase: val(f, "p"), bip39_passphrase: val(f, "bip39") || null });
    show(h("section", {}, h("h2", {}, "Wallets"), wordsCard("Recovery words for " + r.wallet.name, r.words)));
    return "Created.";
  }, h("p", { class: "muted" }, "A new HD wallet with fresh recovery words. The words are shown once, then kept only sealed under the passphrase."));

  const restore = form("Restore from words", [
    field("Name", "name", "text", { maxlength: 64, required: true }),
    h("label", { class: "field" }, h("span", {}, "Recovery words"),
      h("textarea", { name: "words", rows: 3, spellcheck: "false", autocomplete: "off", required: true })),
    field("Extra BIP39 word, if the wallet had one", "bip39", "password"),
    field("New passphrase (8 characters or more)", "p", "password", { autocomplete: "new-password", required: true }),
  ], "Restore", async (f) => {
    const r = await post("/api/wallets/create", {
      name: val(f, "name"), passphrase: val(f, "p"), words: val(f, "words"), bip39_passphrase: val(f, "bip39") || null,
    });
    f.elements.words.value = "";
    setTimeout(go, 800);
    return "Restored " + r.wallet.name + ".";
  });

  const fileInput = h("input", { type: "file", name: "file", accept: "application/json,.json" });
  const importForm = form("Import a backup file", [
    h("label", { class: "field" }, h("span", {}, "Backup file"), fileInput),
    field("The wallet's passphrase", "p", "password", { autocomplete: "current-password", required: true }),
  ], "Import", async (f) => {
    const file = fileInput.files[0];
    if (!file) throw new Error("choose the backup file");
    const r = await post("/api/wallets/import", { backup: await file.text(), passphrase: val(f, "p") });
    setTimeout(go, 800);
    return "Imported " + r.wallet.name + ".";
  });

  /// One wallet's page: balance, receive, send, history, and its management
  async function detail(id) {
    const box = h("div", { class: "card" }, h("p", { class: "muted" }, "Reading the node's Electrum backend…"));
    show(h("section", {}, h("h2", {}, "Wallets"), h("p", {}, h("a", { href: "#/wallets", onclick: (e) => { e.preventDefault(); go(); } }, "← All wallets")), box));
    let d;
    try {
      d = await getJson("/api/wallets/" + id);
    } catch (err) {
      return box.replaceChildren(h("p", { class: "note err" }, err.message));
    }
    const w = d.wallet;
    const addrBox = h("div");
    const showAddress = (a) => addrBox.replaceChildren(h("p", {}, h("code", { class: "uri" }, a)));
    const receive = form("Receive", [field("Passphrase (only once the first 20 addresses are used)", "p", "password", { autocomplete: "current-password" })], "New address", async (f) => {
      const r = await post("/api/wallets/" + id + "/address", { passphrase: f.elements.p ? val(f, "p") || null : null });
      showAddress(r.address);
      return "A fresh address of " + w.name + ".";
    }, h("div", {}, w.receive.length ? h("p", { class: "muted" }, "Last handed out:") : null,
      w.receive.length ? h("p", {}, h("code", { class: "uri" }, w.receive[w.receive.length - 1])) : null));
    receive.append(addrBox);

    const send = form("Send", [
      field("Pay to", "to", "text", { spellcheck: "false", required: true }),
      field("Amount in DIVI", "amount", "text", { inputmode: "decimal", required: true }),
      h("label", { class: "field check" }, h("input", { type: "checkbox", name: "sub" }), h("span", {}, "Take the fee from the amount")),
      field("Wallet passphrase", "p", "password", { autocomplete: "current-password", required: true }),
    ], "Send", async (f) => {
      const to = val(f, "to").trim(), amount = val(f, "amount").trim();
      if (!confirm("Send " + amount + " DIVI from " + w.name + " to " + to + "?")) return "Not sent.";
      const r = await post("/api/wallets/" + id + "/send", { to, amount, fee_from_amount: f.elements.sub.checked, passphrase: val(f, "p") });
      f.elements.to.value = f.elements.amount.value = "";
      setTimeout(() => detail(id), 1500);
      return "Sent. Transaction " + r.txid + ", fee " + divi(r.fee) + ".";
    });

    const rename = form("Rename", [field("Name", "name", "text", { value: w.name, maxlength: 64 })], "Rename", async (f) => {
      await post("/api/wallets/" + id + "/rename", { name: val(f, "name") });
      setTimeout(() => detail(id), 500);
      return "Renamed.";
    });
    const wordsBox = h("div");
    const backup = form("Back up", [field("Passphrase (to show the words)", "p", "password", { autocomplete: "current-password" })],
      "Show recovery words", async (f) => {
        const r = await post("/api/wallets/" + id + "/words", { passphrase: val(f, "p") });
        wordsBox.replaceChildren(h("ol", { class: "words" }, r.words.split(" ").map((x) => h("li", {}, x))),
          h("button", { type: "button", onclick: () => wordsBox.replaceChildren() }, "Hide"));
        return "Keep them offline.";
      }, h("p", {}, h("a", { href: "/api/wallets/" + id + "/backup", download: "" }, "Download the backup file"),
        h("span", { class: "muted" }, " — the words stay sealed in it; importing it needs the passphrase.")));
    backup.append(wordsBox);
    const remove = form("Delete", [field("Passphrase", "p", "password", { autocomplete: "current-password" })], "Delete wallet", async (f) => {
      if (!confirm("Delete " + w.name + " from this node? Only its words or backup file bring it back.")) return "Kept.";
      await post("/api/wallets/" + id + "/delete", { passphrase: val(f, "p") });
      setTimeout(go, 500);
      return "Deleted.";
    });

    const history = d.history.length
      ? h("table", { class: "table" }, h("tr", {}, h("th", {}, "Height"), h("th", {}, "Change"), h("th", {}, "Transaction")),
        d.history.map((t) => h("tr", {}, h("td", {}, t.height > 0 ? t.height : "pending"), h("td", { class: t.satoshis < 0 ? "neg" : "pos" }, divi(t.satoshis)),
          h("td", {}, h("code", {}, t.txid)))))
      : h("p", { class: "muted" }, "No transactions yet.");

    box.replaceWith(h("div", {},
      h("div", { class: "card" }, h("h3", {}, w.name + (w.active ? " (in use)" : "")),
        ui.kv([["Balance", divi(d.balance.confirmed + d.balance.pending)],
          ["Confirmed", divi(d.balance.confirmed)], ["Pending, in the mempool", divi(d.balance.pending)],
          ["Coins", d.coins], ["Addresses watched", w.derived]]),
        w.active ? null : h("div", { class: "row" }, h("button", { type: "button", onclick: async () => {
          await post("/api/wallets/" + id + "/switch", {});
          detail(id);
        } }, "Use this wallet"))),
      h("div", { class: "grid" }, receive, send),
      h("div", { class: "card" }, h("h3", {}, "History"), history),
      h("div", { class: "grid" }, backup, rename, remove)));
  }

  const rows = data.wallets.length
    ? h("div", { class: "grid" }, data.wallets.map((w) => h("div", { class: "card" },
      h("h3", {}, w.name, w.active ? h("span", { class: "muted" }, " · in use") : null),
      h("p", { class: "muted" }, "Made " + new Date(w.created * 1000).toLocaleString()),
      h("div", { class: "row" }, h("button", { type: "button", onclick: () => detail(w.id) }, "Open")))))
    : h("p", { class: "muted" }, "No wallets yet. Make one, restore one from its words, or import a backup file.");

  if (ui.open) return detail(ui.open);
  show(h("section", {}, h("h2", {}, "Wallets"),
    h("p", { class: "muted" }, "Wallets this interface keeps, besides the node's own wallet, on the " + data.network + " network. Each has its own passphrase."),
    rows, h("div", { class: "grid" }, create, restore, importForm)));
};
