// SPDX-License-Identifier: AGPL-3.0-only
// IronDivi web interface: the interface's own wallets, as many as one likes.
// Each keeps its recovery words sealed on the node under a mandatory Argon2id
// passphrase slot and optional WebAuthn PRF passkey slots; balances and history
// come from the node's Electrum backend, mempool included.
"use strict";

window.irondiviWallets = async function (ui) {
  const { h, show, post, del, getJson, form, field, val, note, passkey } = ui;
  const SAT = 100000000;
  const divi = (sat) => (Number(sat || 0) / SAT).toFixed(8).replace(/\.?0+$/, "") + " DIVI";
  const go = () => window.irondiviWallets(ui);
  const short = (s) => (s && s.length > 20 ? s.slice(0, 10) + "…" + s.slice(-8) : s);
  // Explorer deep links (app.js), with plain fallbacks
  const txLink = (txid, label) => (ui.links ? ui.links.txLink(txid, label) : h("code", {}, label || txid));
  const addrLink = (a) => (ui.links ? ui.links.addrLink(a) : h("code", {}, a));
  const sentNote = (r) => h("span", {}, "Sent. Transaction ", txLink(r.txid), ", fee " + divi(r.fee) + ".");

  function localhostHint() {
    if (passkey && passkey.localhostPasskeyHint) return passkey.localhostPasskeyHint();
    const host = window.location.hostname;
    if (host !== "127.0.0.1" && host !== "::1" && host !== "[::1]") return null;
    const port = window.location.port ? ":" + window.location.port : "";
    const href = "http://localhost" + port + "/" + window.location.hash;
    return h("div", { class: "card warn", "data-testid": "localhost-passkey-hint" },
      h("strong", {}, "Passkeys need localhost: "),
      "Browsers block WebAuthn Passkeys on IP addresses (" + host + "). Open ",
      h("a", { href }, href),
      " to use Passkeys.");
  }

  let data;
  try {
    data = await getJson("/api/wallets");
  } catch (err) {
    return show(h("section", {}, localhostHint(), h("h2", {}, "Wallets"), h("p", { class: "note err" }, err.message)));
  }

  /// The recovery words, shown once, with what to do with them
  function wordsCard(title, words, nextAction) {
    const list = h("ol", { class: "words", "data-testid": "wallet-recovery-words" }, words.split(" ").map((w) => h("li", {}, w)));
    return h("div", { class: "card warn" }, h("h3", {}, title),
      h("p", {}, "Write these words down, in order, and keep them offline. With them anyone can spend this wallet; without them and the passphrase, nobody can restore it."),
      list,
      h("div", { class: "row" }, h("button", { type: "button", onclick: nextAction || go }, "I have written them down")));
  }

  const create = form("New wallet", [
    field("Name", "name", "text", { maxlength: 64, required: true }),
    field("Passphrase (8 characters or more)", "p", "password", { autocomplete: "new-password", required: true }),
    field("Passphrase again", "p2", "password", { autocomplete: "new-password", required: true }),
    field("Extra BIP39 word (optional; you need it to restore)", "bip39", "password", { autocomplete: "off" }),
  ], "Create", async (f) => {
    if (val(f, "p") !== val(f, "p2")) throw new Error("the passphrases differ");
    const r = await post("/api/wallets/create", { name: val(f, "name"), passphrase: val(f, "p"), bip39_passphrase: val(f, "bip39") || null });
    show(h("section", {}, localhostHint(), h("h2", {}, "Wallets"),
      wordsCard("Recovery words for " + r.wallet.name, r.words, () => detail(r.wallet.id, r.wallet))));
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

  /// One wallet's page: balance (when Electrum indices are on), receive, send,
  /// passkeys, backup/words, and management. Falls back gracefully if Electrum
  /// indices are off so passkey enrollment, words, and backups always work!
  async function detail(id, fallbackWallet) {
    const box = h("div", { class: "card" }, h("p", { class: "muted" }, "Reading wallet…"));
    show(h("section", {}, localhostHint(), h("h2", {}, "Wallets"),
      h("p", {}, h("a", { href: "#/wallets", onclick: (e) => { e.preventDefault(); go(); } }, "← All wallets")), box));
    let d = null;
    let chainErr = null;
    try {
      d = await getJson("/api/wallets/" + id);
    } catch (err) {
      chainErr = err.message;
      const listRes = await getJson("/api/wallets").catch(() => null);
      const found = (listRes && listRes.wallets && listRes.wallets.find((x) => x.id === id)) || fallbackWallet;
      if (!found) {
        return box.replaceChildren(h("p", { class: "note err" }, err.message));
      }
      d = { wallet: found, balance: null, coins: 0, history: [] };
    }
    const w = d.wallet;
    const hostSlots = (w.passkeys || []).filter((s) => s.rp_id === window.location.hostname);

    const addrBox = h("div");
    const showAddress = (a) => addrBox.replaceChildren(h("p", {}, addrLink(a)));
    const receive = form("Receive", [field("Passphrase (only once the first 20 addresses are used)", "p", "password", { autocomplete: "current-password" })], "New address", async (f) => {
      const r = await post("/api/wallets/" + id + "/address", { passphrase: f.elements.p ? val(f, "p") || null : null });
      showAddress(r.address);
      return "A fresh address of " + w.name + ".";
    }, h("div", {}, w.receive.length ? h("p", { class: "muted" }, "Last handed out:") : null,
      w.receive.length ? h("p", {}, addrLink(w.receive[w.receive.length - 1])) : null));
    receive.append(addrBox);

    let sendPasskeyBtn = null;
    const send = form("Send", [
      field("Pay to", "to", "text", { spellcheck: "false", required: true }),
      field("Amount in DIVI", "amount", "text", { inputmode: "decimal", required: true }),
      h("label", { class: "field check" }, h("input", { type: "checkbox", name: "sub" }), h("span", {}, "Take the fee from the amount")),
      field("Wallet passphrase", "p", "password", { autocomplete: "current-password" }),
    ], "Send", async (f) => {
      const to = val(f, "to").trim(), amount = val(f, "amount").trim(), p = val(f, "p");
      if (!p) throw new Error("enter the wallet passphrase");
      if (!confirm("Send " + amount + " DIVI from " + w.name + " to " + to + "?")) return "Not sent.";
      const r = await post("/api/wallets/" + id + "/send", { to, amount, fee_from_amount: f.elements.sub.checked, passphrase: p });
      f.elements.to.value = f.elements.amount.value = "";
      setTimeout(() => detail(id), 1500);
      return sentNote(r);
    }, null, hostSlots.length ? [
      (sendPasskeyBtn = h("button", {
        type: "button",
        class: "secondary",
        "data-testid": "wallet-send-passkey",
        onclick: async () => {
          sendPasskeyBtn.disabled = true;
          note(send._note, "Waiting for passkey…", true);
          try {
            const to = val(send, "to").trim(), amount = val(send, "amount").trim();
            if (!to || !amount) throw new Error("enter the recipient address and amount");
            if (!confirm("Send " + amount + " DIVI from " + w.name + " to " + to + " with Passkey?")) {
              note(send._note, "Not sent.", true);
              return;
            }
            const unlocked = await passkey.evalPrfPasskey(hostSlots);
            const r = await post("/api/wallets/" + id + "/send", {
              to,
              amount,
              fee_from_amount: send.elements.sub.checked,
              passkey: unlocked,
            });
            unlocked.prf_output = "";
            send.elements.to.value = send.elements.amount.value = "";
            note(send._note, sentNote(r), true);
            setTimeout(() => detail(id), 1500);
          } catch (err) {
            note(send._note, err.message, false);
          } finally {
            sendPasskeyBtn.disabled = false;
          }
        },
      }, "Send with Passkey")),
    ] : []);

    // Passkeys card for this Electrum wallet
    const pkMsg = h("p", { class: "note" });
    const pkPassInput = field("Wallet passphrase (required to add or remove a passkey)", "passphrase", "password", {
      autocomplete: "current-password",
    });
    const pkLabelInput = field("Passkey label (optional)", "label", "text", {
      maxlength: 64,
      placeholder: "Touch ID / Security Key",
    });
    const enrolledList = (w.passkeys && w.passkeys.length)
      ? h("ul", { class: "pk-list" }, w.passkeys.map((s) =>
        h("li", { class: "pk-item" },
          h("span", {}, h("strong", {}, s.label), " ", h("span", { class: "muted small" }, "(" + s.rp_id + ")")),
          h("button", {
            type: "button",
            class: "link",
            onclick: async () => {
              const p = pkPassInput.querySelector("input").value;
              if (!confirm("Remove passkey \"" + s.label + "\" from " + w.name + "?")) return;
              try {
                if (p) {
                  await del("/api/wallets/" + id + "/passkeys/" + s.id, { passphrase: p });
                } else if (s.rp_id === window.location.hostname) {
                  const unlocked = await passkey.evalPrfPasskey([s], s.id);
                  await del("/api/wallets/" + id + "/passkeys/" + s.id, { passkey: unlocked });
                  unlocked.prf_output = "";
                } else {
                  throw new Error("enter the wallet passphrase to remove this passkey");
                }
                detail(id);
              } catch (err) {
                note(pkMsg, err.message, false);
              }
            },
          }, "Remove"))))
      : h("p", { class: "muted" }, "No passkeys enrolled for this wallet yet.");

    const addPkBtn = h("button", {
      type: "submit",
      "data-testid": "wallet-add-passkey",
    }, "Add Passkey");

    const passkeysCard = h("form", {
      class: "card",
      onsubmit: async (e) => {
        e.preventDefault();
        addPkBtn.disabled = true;
        note(pkMsg, "Waiting for passkey…", true);
        try {
          const p = val(passkeysCard, "passphrase");
          if (!p) throw new Error("enter the wallet passphrase to enroll a passkey");
          const label = val(passkeysCard, "label").trim() || "Passkey";
          const enrolled = await passkey.enrollPrfPasskey("wallet-" + w.id, w.name + " (" + label + ")");
          await post("/api/wallets/" + id + "/passkeys", {
            passphrase: p,
            label,
            credential_id: enrolled.credential_id,
            prf_salt: enrolled.prf_salt,
            rp_id: enrolled.rp_id,
            prf_output: enrolled.prf_output,
          });
          enrolled.prf_output = "";
          detail(id);
        } catch (err) {
          note(pkMsg, err.message, false);
        } finally {
          addPkBtn.disabled = false;
        }
      },
    },
      h("h3", {}, "Passkeys"),
      h("p", { class: "muted" }, "Unlock sends and recovery words with a WebAuthn PRF passkey. Passkeys do not replace writing down your 12/24-word recovery phrase — always keep your recovery words and passphrase offline, and your downloaded backup file remains recoverable on any computer with your passphrase."),
      enrolledList,
      pkLabelInput,
      pkPassInput,
      h("div", { class: "row" }, addPkBtn),
      pkMsg);

    const rename = form("Rename", [field("Name", "name", "text", { value: w.name, maxlength: 64 })], "Rename", async (f) => {
      await post("/api/wallets/" + id + "/rename", { name: val(f, "name") });
      setTimeout(() => detail(id), 500);
      return "Renamed.";
    });

    const wordsBox = h("div");
    function renderWords(wordsText) {
      wordsBox.replaceChildren(
        h("ol", { class: "words", "data-testid": "wallet-words-list" }, wordsText.split(" ").map((x) => h("li", {}, x))),
        h("button", { type: "button", onclick: () => wordsBox.replaceChildren() }, "Hide"));
    }

    let wordsPasskeyBtn = null;
    const backup = form("Back up", [field("Passphrase (to show the words)", "p", "password", { autocomplete: "current-password" })],
      "Show recovery words", async (f) => {
        const r = await post("/api/wallets/" + id + "/words", { passphrase: val(f, "p") });
        renderWords(r.words);
        return "Keep them offline.";
      }, h("p", {}, h("a", { href: "/api/wallets/" + id + "/backup", download: "" }, "Download the backup file"),
        h("span", { class: "muted" }, " — the words stay sealed in it; importing it on any computer needs only the passphrase.")),
      hostSlots.length ? [
        (wordsPasskeyBtn = h("button", {
          type: "button",
          class: "secondary",
          "data-testid": "wallet-words-passkey",
          onclick: async () => {
            wordsPasskeyBtn.disabled = true;
            note(backup._note, "Waiting for passkey…", true);
            try {
              const unlocked = await passkey.evalPrfPasskey(hostSlots);
              const r = await post("/api/wallets/" + id + "/words", { passkey: unlocked });
              unlocked.prf_output = "";
              renderWords(r.words);
              note(backup._note, "Keep them offline.", true);
            } catch (err) {
              note(backup._note, err.message, false);
            } finally {
              wordsPasskeyBtn.disabled = false;
            }
          },
        }, "Show Words with Passkey")),
      ] : []);
    backup.append(wordsBox);

    let deletePkBtn = null;
    const remove = form("Delete", [field("Passphrase", "p", "password", { autocomplete: "current-password" })], "Delete wallet", async (f) => {
      if (!confirm("Delete " + w.name + " from this node? Only its words or backup file bring it back.")) return "Kept.";
      await post("/api/wallets/" + id + "/delete", { passphrase: val(f, "p") });
      setTimeout(go, 500);
      return "Deleted.";
    }, null, hostSlots.length ? [
      (deletePkBtn = h("button", {
        type: "button",
        class: "secondary",
        "data-testid": "wallet-delete-passkey",
        onclick: async () => {
          deletePkBtn.disabled = true;
          try {
            if (!confirm("Delete " + w.name + " from this node with Passkey? Only its words or backup file bring it back.")) {
              note(remove._note, "Kept.", true);
              return;
            }
            note(remove._note, "Waiting for passkey…", true);
            const unlocked = await passkey.evalPrfPasskey(hostSlots);
            await post("/api/wallets/" + id + "/delete", { passkey: unlocked });
            unlocked.prf_output = "";
            note(remove._note, "Deleted.", true);
            setTimeout(go, 500);
          } catch (err) {
            note(remove._note, err.message, false);
          } finally {
            deletePkBtn.disabled = false;
          }
        },
      }, "Delete with Passkey")),
    ] : []);

    // Sign & verify a message with one of this wallet's addresses
    const allAddrs = (d.addresses ? [...(d.addresses.receive || []), ...(d.addresses.change || [])] : (w.receive || []));
    const sigOut = h("textarea", { class: "sig", rows: 3, readonly: true, "data-testid": "wallet-signature-output" });
    const listId = "wallet-sign-addrs-" + id;
    const signBody = (f) => {
      const address = val(f, "address").trim();
      if (!address) throw new Error("enter an address of this wallet");
      return { address, message: f.elements.message.value };
    };
    let signPkBtn = null;
    const sign = form("Sign a message", [
      h("label", { class: "field" }, h("span", {}, "Address"),
        h("input", { name: "address", list: listId, spellcheck: "false", autocomplete: "off", value: allAddrs[0] || "" }),
        h("datalist", { id: listId }, allAddrs.map((a) => h("option", { value: a })))),
      h("label", { class: "field" }, h("span", {}, "Message"), h("textarea", { name: "message", rows: 3 })),
      field(hostSlots.length ? "Passphrase (or use your passkey)" : "Passphrase", "p", "password", { autocomplete: "current-password" }),
    ], "Sign", async (f) => {
      if (!val(f, "p")) throw new Error("enter the wallet passphrase");
      const r = await post("/api/wallets/" + id + "/signmessage", Object.assign(signBody(f), { passphrase: val(f, "p") }));
      sigOut.value = r.signature;
      return "Signed by " + r.address + ".";
    }, h("p", { class: "muted" }, "A Divi signed message: the node's verifymessage (and Divi Core's) checks it."),
    hostSlots.length ? [
      (signPkBtn = h("button", {
        type: "button",
        class: "secondary",
        "data-testid": "wallet-sign-passkey",
        onclick: async () => {
          signPkBtn.disabled = true;
          note(sign._note, "Waiting for passkey…", true);
          try {
            const body = signBody(sign);
            const unlocked = await passkey.evalPrfPasskey(hostSlots);
            const r = await post("/api/wallets/" + id + "/signmessage", Object.assign(body, { passkey: unlocked }));
            unlocked.prf_output = "";
            sigOut.value = r.signature;
            note(sign._note, "Signed by " + r.address + " with Passkey.", true);
          } catch (err) {
            note(sign._note, err.message, false);
          } finally {
            signPkBtn.disabled = false;
          }
        },
      }, "Sign with Passkey")),
    ] : []);
    sign.setAttribute("data-testid", "wallet-sign-message-card");
    sign.append(h("label", { class: "field" }, h("span", {}, "Signature"), sigOut));

    const verify = ui.rpc ? form("Verify a message", [
      field("Address", "address", "text", { spellcheck: "false" }),
      field("Signature", "signature", "text", { spellcheck: "false" }),
      h("label", { class: "field" }, h("span", {}, "Message"), h("textarea", { name: "message", rows: 3 })),
    ], "Verify", async (f) => {
      const ok = await ui.rpc("verifymessage", val(f, "address").trim(), val(f, "signature").trim(), f.elements.message.value);
      if (!ok) throw new Error("The signature does not match that address and message.");
      return "Valid: the address signed this message.";
    }) : null;
    if (verify) verify.setAttribute("data-testid", "wallet-verify-message-card");

    const history = d.history.length
      ? h("table", { class: "table", "data-testid": "wallet-history" },
        h("thead", {}, h("tr", {}, h("th", {}, "Height"), h("th", {}, "Change"), h("th", {}, "Transaction"))),
        h("tbody", {}, d.history.map((t) => h("tr", {}, h("td", {}, t.height > 0 ? t.height : "pending"), h("td", { class: t.satoshis < 0 ? "neg" : "pos" }, divi(t.satoshis)),
          h("td", {}, txLink(t.txid))))))
      : h("p", { class: "muted" }, chainErr || "No transactions yet.");

    const coinsList = Array.isArray(d.coins) ? d.coins : [];
    const coins = h("details", { class: "card drawer", "data-testid": "wallet-coins" },
      h("summary", {}, "Unspent coins (" + coinsList.length + ")"),
      h("div", { class: "drawer-body" }, coinsList.length
        ? h("table", { class: "table" },
          h("thead", {}, h("tr", {}, h("th", {}, "Coin"), h("th", {}, "Address"), h("th", {}, "Value"), h("th", {}, "Height"))),
          h("tbody", {}, coinsList.map((c) => h("tr", {}, h("td", {}, txLink(c.txid, short(c.txid)), ":" + c.vout),
            h("td", {}, addrLink(c.address)), h("td", {}, divi(c.satoshis)), h("td", {}, c.height > 0 ? c.height : "pending")))))
        : h("p", { class: "muted" }, chainErr || "No unspent coins.")));

    const addrRows = (list, kind) => (list || []).map((a, i) => h("tr", {}, h("td", {}, kind + " " + i), h("td", {}, addrLink(a))));
    const watched = h("details", { class: "card drawer", "data-testid": "wallet-addresses" },
      h("summary", {}, "Watched addresses (" + allAddrs.length + ")"),
      h("div", { class: "drawer-body" }, allAddrs.length
        ? h("table", { class: "table" }, h("tbody", {},
          d.addresses ? [...addrRows(d.addresses.receive, "receive"), ...addrRows(d.addresses.change, "change")] : addrRows(w.receive, "receive")))
        : h("p", { class: "muted" }, "No addresses yet.")));

    const summaryRows = d.balance
      ? [
        ["Balance", divi(d.balance.confirmed + d.balance.pending)],
        ["Confirmed", divi(d.balance.confirmed)],
        ["Pending, in the mempool", divi(d.balance.pending)],
        ["Coins", d.coins_count ?? coinsList.length],
        ["Addresses watched", w.derived],
        ["Passkeys", (w.passkeys || []).length],
      ]
      : [
        ["Addresses watched", w.derived],
        ["Passkeys", (w.passkeys || []).length],
      ];

    box.replaceWith(h("div", {},
      chainErr ? h("p", { class: "note err" }, chainErr) : null,
      h("div", { class: "card" }, h("h3", {}, w.name + (w.active ? " (in use)" : "")),
        ui.kv(summaryRows),
        w.active ? null : h("div", { class: "row" }, h("button", { type: "button", onclick: async () => {
          await post("/api/wallets/" + id + "/switch", {});
          detail(id);
        } }, "Use this wallet"))),
      h("div", { class: "grid" }, receive, send),
      passkeysCard,
      h("div", { class: "card" }, h("h3", {}, "History"), history),
      coins, watched,
      h("div", { class: "grid" }, sign, verify),
      h("div", { class: "grid" }, backup, rename, remove)));
  }

  const rows = data.wallets.length
    ? h("div", { class: "grid" }, data.wallets.map((w) => h("div", { class: "card" },
      h("h3", {}, w.name, w.active ? h("span", { class: "muted" }, " · in use") : null),
      h("p", { class: "muted" }, "Made " + new Date(w.created * 1000).toLocaleString() +
        ((w.passkeys && w.passkeys.length) ? " · " + w.passkeys.length + " passkey(s)" : "")),
      h("div", { class: "row" }, h("button", { type: "button", onclick: () => detail(w.id, w) }, "Open")))))
    : h("p", { class: "muted" }, "No wallets yet. Make one, restore one from its words, or import a backup file.");

  if (ui.open) return detail(ui.open);
  show(h("section", {}, localhostHint(), h("h2", {}, "Wallets"),
    h("p", { class: "muted" }, "Wallets this interface keeps, besides the node's own wallet, on the " + data.network + " network. Each has its own passphrase and optional passkeys."),
    rows, h("div", { class: "grid" }, create, restore, importForm)));
};
