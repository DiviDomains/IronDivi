// SPDX-License-Identifier: AGPL-3.0-only
// IronDivi web interface. No framework, no outside scripts: the page's
// policy allows only what this server sends.
"use strict";

let state = {};
/// A message for the next render of the page, after an action re-draws it
let flash = null;

// --- helpers ---------------------------------------------------------------

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "class") el.className = v;
    else if (v === true) el.setAttribute(k, "");
    else el.setAttribute(k, v);
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

function show(...nodes) {
  const main = document.getElementById("main");
  main.replaceChildren(...nodes);
}

async function post(path, body) {
  const res = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": state.csrf || "" },
    body: JSON.stringify(body || {}),
  });
  let data = {};
  try { data = await res.json(); } catch (_) { data = { error: await res.text().catch(() => res.statusText) }; }
  if (res.status === 401) { await refresh(); throw new Error(data.error || "sign in first"); }
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

async function getJson(path) {
  const res = await fetch(path, { credentials: "same-origin" });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401) { await refresh(); throw new Error("sign in first"); }
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

/// One daemon call; throws with the daemon's message
async function rpc(method, ...params) {
  const r = await post("/api/rpc", { method, params });
  if (r.error) throw new Error(r.error.message);
  return r.result;
}

function note(el, text, ok) {
  el.textContent = text;
  el.className = ok ? "note ok" : "note err";
}

/// A form whose submit runs `work` and reports into its own note line
function form(title, fields, label, work, extra) {
  const msg = h("p", { class: "note" });
  const button = h("button", { type: "submit" }, label);
  const f = h("form", {
    class: "card",
    onsubmit: async (e) => {
      e.preventDefault();
      button.disabled = true;
      note(msg, "Working…", true);
      try {
        const done = await work(f);
        note(msg, done || "Done.", true);
        f.querySelectorAll("input[type=password]").forEach((i) => (i.value = ""));
      } catch (err) {
        note(msg, err.message, false);
      } finally {
        button.disabled = false;
      }
    },
  }, h("h3", {}, title), extra || null, fields, h("div", { class: "row" }, button), msg);
  return f;
}

function field(label, name, type, attrs) {
  return h("label", { class: "field" }, h("span", {}, label),
    h("input", Object.assign({ name, type: type || "text", autocomplete: "off" }, attrs || {})));
}

function val(f, name) { return f.elements[name].value; }

function walletLabel(w) {
  return {
    "unencrypted": "Not encrypted",
    "locked": "Locked",
    "unlocked-for-staking": "Unlocked for staking only",
    "unlocked": "Unlocked for spending",
  }[w] || (w === null || w === undefined ? "No wallet" : w);
}

function banner() {
  const b = document.getElementById("banner");
  if (state.signed_in && state.wallet === "unencrypted") {
    b.replaceChildren("The wallet is not encrypted. Until it is, this interface only reads: ",
      h("a", { href: "#/security" }, "encrypt it now"), ".");
    b.hidden = false;
  } else {
    b.hidden = true;
  }
}

// --- state and routing -------------------------------------------------------

async function refresh() {
  state = await getJson("/api/state").catch(() => ({}));
  document.getElementById("net").textContent =
    [state.chain_mode === "privatedivi" ? "PrivateDivi" : "Divi", state.network].filter(Boolean).join(" · ");
  document.getElementById("nav").hidden = !state.signed_in;
  document.getElementById("logout").hidden = !state.signed_in;
  banner();
}

const routes = {
  "": dashboard,
  "security": security,
  "settings": settings,
  "console": consoleView,
  "wallet": () => later("Wallet", "Send and receive."),
  "staking": () => later("Staking", "Staking status, rewards and the split threshold."),
  "vaults": () => later("Vaults", "Vaults that stake for you but cannot spend."),
  "swaps": () => later("Swaps", "Atomic swaps with other chains."),
};

async function route() {
  const name = location.hash.replace(/^#\/?/, "");
  if (state.setup_required) return setupView();
  if (!state.signed_in) return loginView();
  const view = routes[name] || dashboard;
  document.querySelectorAll("#nav a").forEach((a) =>
    a.classList.toggle("on", a.getAttribute("href") === "#/" + name));
  try {
    await view();
  } catch (err) {
    show(h("p", { class: "note err" }, err.message));
  }
}

// --- views -------------------------------------------------------------------

function setupView() {
  show(h("section", { class: "narrow" },
    h("h2", {}, "Set the web interface password"),
    h("p", {}, "The daemon wrote a one-time setup token to the file ",
      h("code", {}, "webui-setup-token"), " in its data directory. Paste it here and choose the ",
      "password this interface will ask for. It is not the wallet passphrase."),
    form("First sign-in", [
      field("Setup token", "token", "text"),
      field("Password (" + state.min_password + " characters or more)", "password", "password", { autocomplete: "new-password" }),
      field("The password again", "again", "password", { autocomplete: "new-password" }),
    ], "Set password", async (f) => {
      if (val(f, "password") !== val(f, "again")) throw new Error("the passwords differ");
      const r = await post("/api/setup", { token: val(f, "token"), password: val(f, "password") });
      state.csrf = r.csrf;
      await refresh();
      location.hash = "#/security";
      route();
    })));
}

function loginView() {
  show(h("section", { class: "narrow" },
    form("Sign in", [field("Password", "password", "password", { autocomplete: "current-password", autofocus: true })],
      "Sign in", async (f) => {
        const r = await post("/api/login", { password: val(f, "password") });
        state.csrf = r.csrf;
        await refresh();
        route();
      })));
}

function later(title, what) {
  show(h("section", {}, h("h2", {}, title),
    h("p", { class: "muted" }, what + " This app is coming; it will use the same settings and the same sign-in.")));
}

function kv(rows) {
  return h("dl", { class: "kv" }, rows.flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v === undefined || v === null ? "—" : String(v))]));
}

async function dashboard() {
  show(h("p", { class: "muted" }, "Loading…"));
  const [info, chain, staking] = await Promise.all([
    rpc("getinfo").catch((e) => ({ error: e.message })),
    rpc("getblockchaininfo").catch((e) => ({ error: e.message })),
    rpc("getstakingstatus").catch((e) => ({ error: e.message })),
  ]);
  show(h("section", {},
    h("h2", {}, "Dashboard"),
    h("div", { class: "grid" },
      h("div", { class: "card" }, h("h3", {}, "Node"), kv([
        ["Version", info.version], ["Blocks", chain.blocks ?? info.blocks], ["Headers", chain.headers],
        ["Connections", info.connections], ["Network", state.network],
      ])),
      h("div", { class: "card" }, h("h3", {}, "Wallet"), kv([
        ["Encryption", walletLabel(state.wallet)], ["Balance", info.balance],
      ]), h("p", {}, h("a", { href: "#/security" }, "Security settings"))),
      h("div", { class: "card" }, h("h3", {}, "Staking"), staking.error ? h("p", { class: "muted" }, staking.error) :
        kv(Object.entries(staking).map(([k, v]) => [k, typeof v === "object" ? JSON.stringify(v) : v]))),
    )));
}

async function security() {
  await refresh();
  const w = state.wallet;
  const parts = [h("h2", {}, "Security"), h("p", {}, "Wallet: ", h("strong", {}, walletLabel(w)))];
  if (flash) {
    parts.push(h("p", { class: "note ok" }, flash));
    flash = null;
  }
  if (w === "unencrypted") {
    parts.push(form("Encrypt the wallet", [
      field("New wallet passphrase", "p1", "password", { autocomplete: "new-password" }),
      field("The passphrase again", "p2", "password", { autocomplete: "new-password" }),
    ], "Encrypt", async (f) => {
      if (val(f, "p1").length < 8) throw new Error("use 8 characters or more");
      if (val(f, "p1") !== val(f, "p2")) throw new Error("the passphrases differ");
      await rpc("encryptwallet", val(f, "p1"));
      flash = "The wallet is encrypted and locked. Unlock it for staking below.";
      security();
    }, h("p", { class: "muted" }, "Keep the passphrase somewhere safe: without it the coins cannot be spent.")));
  }
  if (w && w !== "unencrypted") {
    parts.push(form("Unlock for staking only", [field("Wallet passphrase", "p", "password", { autocomplete: "current-password" })],
      "Unlock for staking", async (f) => {
        await rpc("walletpassphrase", val(f, "p"), 0, true);
        flash = "Unlocked for staking. Spending still needs the passphrase.";
        security();
      }, h("p", { class: "muted" }, "The wallet stakes, but cannot send, until it is locked again.")));
    parts.push(form("Lock the wallet", [], "Lock", async () => {
      await rpc("walletlock");
      flash = "Locked.";
      security();
    }));
    parts.push(form("Change the wallet passphrase", [
      field("Current passphrase", "old", "password", { autocomplete: "current-password" }),
      field("New passphrase", "p1", "password", { autocomplete: "new-password" }),
      field("The new passphrase again", "p2", "password", { autocomplete: "new-password" }),
    ], "Change passphrase", async (f) => {
      if (val(f, "p1") !== val(f, "p2")) throw new Error("the passphrases differ");
      await rpc("walletpassphrasechange", val(f, "old"), val(f, "p1"));
      return "The wallet passphrase is changed.";
    }));
  }
  parts.push(form("Change the web interface password", [
    field("Current password", "current", "password", { autocomplete: "current-password" }),
    field("New password", "p1", "password", { autocomplete: "new-password" }),
    field("The new password again", "p2", "password", { autocomplete: "new-password" }),
  ], "Change password", async (f) => {
    if (val(f, "p1") !== val(f, "p2")) throw new Error("the passwords differ");
    await post("/api/password", { current: val(f, "current"), new: val(f, "p1") });
    return "Changed. Other browsers are signed out.";
  }));
  show(h("section", {}, parts));
}

// --- settings ----------------------------------------------------------------

let settingsTab = null;

async function settings() {
  const s = await getJson("/api/settings");
  const opts = s.schema.options;
  const cats = s.schema.categories.filter((c) => opts.some((o) => o.category === c));
  settingsTab = settingsTab && cats.includes(settingsTab) ? settingsTab : cats[0];
  const edits = new Map(); // key -> values array (empty = remove)
  const msg = h("p", { class: "note" });
  const save = h("button", { disabled: true }, "Save");
  const count = h("span", { class: "muted" });
  const locked = s.wallet === "unencrypted";

  function changed(key, values) {
    edits.set(key, values);
    count.textContent = edits.size + " unsaved";
    save.disabled = locked;
  }

  function control(o) {
    const fileVals = s.file.values[o.key];
    const isSet = fileVals !== undefined || s.file.secrets.includes(o.key);
    const cur = fileVals || [];
    const ro = !o.writable || locked;
    if (o.secret) {
      const inp = h("input", { type: "password", autocomplete: "new-password", disabled: ro,
        placeholder: isSet ? "set — type to replace" : "not set" });
      inp.addEventListener("input", () => changed(o.key, o.multi ? inp.value.split(",").map((x) => x.trim()).filter(Boolean) : [inp.value]));
      const kids = [inp];
      if (isSet && !ro) {
        kids.push(h("button", { type: "button", class: "link", onclick: () => { inp.value = ""; inp.placeholder = "will be removed"; changed(o.key, []); } }, "Remove"));
      }
      return h("div", { class: "ctl" }, kids);
    }
    if (o.multi) {
      const ta = h("textarea", { rows: Math.max(2, cur.length + 1), disabled: ro, placeholder: "one per line" });
      ta.value = cur.join("\n");
      ta.addEventListener("input", () => changed(o.key, ta.value.split("\n").map((x) => x.trim()).filter(Boolean)));
      return ta;
    }
    if (o.kind === "bool") {
      const sel = h("select", { disabled: ro },
        h("option", { value: "" }, "default" + (o.default !== "" ? " (" + (o.default === "1" ? "on" : "off") + ")" : "")),
        h("option", { value: "1" }, "on"), h("option", { value: "0" }, "off"));
      sel.value = cur.length ? (cur[cur.length - 1] === "0" ? "0" : "1") : "";
      sel.addEventListener("change", () => changed(o.key, sel.value === "" ? [] : [sel.value]));
      return sel;
    }
    if (o.kind === "choice") {
      const sel = h("select", { disabled: ro }, h("option", { value: "" }, "default" + (o.default ? " (" + o.default + ")" : "")),
        o.range.map((c) => h("option", { value: c }, c)));
      sel.value = cur.length ? cur[cur.length - 1] : "";
      sel.addEventListener("change", () => changed(o.key, sel.value === "" ? [] : [sel.value]));
      return sel;
    }
    const attrs = { disabled: ro, placeholder: o.default ? "default " + o.default : "not set" };
    if (o.kind === "int") Object.assign(attrs, { type: "number", min: o.range.min, max: o.range.max, step: 1 });
    if (o.kind === "amount") Object.assign(attrs, { inputmode: "decimal" });
    const inp = h("input", attrs);
    inp.value = cur.length ? cur[cur.length - 1] : "";
    inp.addEventListener("input", () => changed(o.key, inp.value.trim() === "" ? [] : [inp.value.trim()]));
    return inp;
  }

  function row(o) {
    const badges = [];
    if (o.live) badges.push(h("span", { class: "badge live" }, "applies now"));
    else badges.push(h("span", { class: "badge" }, "after restart"));
    if (!o.writable) badges.push(h("span", { class: "badge" }, "read-only here"));
    const cli = s.cli.values[o.key] || (s.cli.secrets.includes(o.key) ? ["(secret)"] : null);
    if (cli) badges.push(h("span", { class: "badge warn", title: "The command line wins over the file" }, "command line: " + cli.join(", ")));
    return h("div", { class: "opt" },
      h("div", { class: "opt-head" }, h("code", {}, o.key), badges),
      h("p", { class: "muted" }, o.help),
      control(o));
  }

  const tabs = h("div", { class: "tabs" }, cats.map((c) =>
    h("button", { type: "button", class: c === settingsTab ? "on" : "", onclick: () => {
      if (edits.size && !confirm("Leave " + edits.size + " unsaved change(s)?")) return;
      settingsTab = c; settings();
    } }, c)));

  save.addEventListener("click", async () => {
    save.disabled = true;
    note(msg, "Saving…", true);
    try {
      const changes = [...edits].map(([key, values]) => ({ key, values }));
      const r = await post("/api/settings", { changes });
      const parts = ["Saved to " + s.conf + "."];
      for (const l of r.live) parts.push(l.key + (l.ok ? " applied now." : " not applied now: " + l.error));
      if (r.restart.length) parts.push("Restart the daemon for: " + r.restart.join(", ") + ".");
      if (r.overridden.length) parts.push("The command line still overrides: " + r.overridden.join(", ") + ".");
      edits.clear();
      await settings();
      const fresh = document.querySelector("#settings-msg");
      if (fresh) note(fresh, parts.join(" "), true);
    } catch (err) {
      note(msg, err.message, false);
      save.disabled = false;
    }
  });
  msg.id = "settings-msg";

  const other = s.file.other.length ? h("p", { class: "muted" },
    "Also in the file, not edited here: " + s.file.other.join(", ")) : null;
  show(h("section", {},
    h("h2", {}, "Settings"),
    h("p", { class: "muted" }, "File: ", h("code", {}, s.conf), " (" + s.format + "). A backup of the old file is kept beside it as ",
      h("code", {}, ".bak"), "."),
    locked ? h("p", { class: "note err" }, "Encrypt the wallet on the Security page before changing settings.") : null,
    tabs,
    h("div", { class: "opts" }, opts.filter((o) => o.category === settingsTab).map(row)),
    other,
    h("div", { class: "savebar" }, save, count, msg)));
}

// --- console -----------------------------------------------------------------

function consoleView() {
  const out = h("pre", { class: "out" });
  show(h("section", {}, h("h2", {}, "Console"),
    h("p", { class: "muted" }, "Any daemon call, as with divi-cli. Key exports are refused; spending unlocks last " +
      state.max_full_unlock + " seconds at most."),
    form("Call", [
      field("Method", "method", "text", { placeholder: "getblockcount", autofocus: true }),
      field("Parameters (a JSON array)", "params", "text", { placeholder: "[]" }),
    ], "Run", async (f) => {
      let params = [];
      const text = val(f, "params").trim();
      if (text) {
        params = JSON.parse(text);
        if (!Array.isArray(params)) throw new Error("parameters are a JSON array");
      }
      const r = await post("/api/rpc", { method: val(f, "method").trim(), params });
      out.textContent = JSON.stringify(r.error ? r : r.result, null, 2);
      return r.error ? "The daemon refused it." : "OK";
    }),
    out));
}

// --- start ---------------------------------------------------------------------

document.getElementById("logout").addEventListener("click", async () => {
  await post("/api/logout").catch(() => {});
  await refresh();
  route();
});
window.addEventListener("hashchange", route);
refresh().then(route);
