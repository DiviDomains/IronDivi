// SPDX-License-Identifier: AGPL-3.0-only
// IronDivi web interface. No framework, no outside scripts: the page's
// policy allows only what this server sends.
"use strict";

let state = {};
/// A message for the next render of the page, after an action re-draws it
let flash = null;
/// The log view's polling timer, stopped whenever the page changes
let logTimer = null;

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

async function sendJson(method, path, body) {
  const res = await fetch(path, {
    method,
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

function post(path, body) {
  return sendJson("POST", path, body);
}

function del(path, body) {
  return sendJson("DELETE", path, body);
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
  // text, or a node (a message with explorer links)
  el.replaceChildren(text instanceof Node ? text : String(text));
  el.className = ok ? "note ok" : "note err";
}

/// A form whose submit runs `work` and reports into its own note line
function form(title, fields, label, work, extra, extraButtons) {
  const msg = h("p", { class: "note" });
  const button = h("button", { type: "submit" }, label);
  const rowKids = [button, ...(extraButtons || [])];
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
  }, h("h3", {}, title), extra || null, fields, h("div", { class: "row wrap" }, rowKids), msg);
  f._note = msg;
  return f;
}

function field(label, name, type, attrs) {
  return h("label", { class: "field" }, h("span", {}, label),
    h("input", Object.assign({ name, type: type || "text", autocomplete: "off" }, attrs || {})));
}

function val(f, name) { return f.elements[name].value; }

// --- WebAuthn & PRF helpers ------------------------------------------------

function bytesToB64url(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function b64urlToBytes(str) {
  const norm = String(str).replace(/-/g, "+").replace(/_/g, "/");
  const pad = norm + "=".repeat((4 - (norm.length % 4)) % 4);
  const bin = atob(pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function isLoopbackIpHost() {
  const host = window.location.hostname;
  return host === "127.0.0.1" || host === "::1" || host === "[::1]";
}

function localhostHref() {
  const port = window.location.port ? ":" + window.location.port : "";
  return "http://localhost" + port + "/" + window.location.hash;
}

function localhostPasskeyHint() {
  if (!isLoopbackIpHost()) return null;
  const href = localhostHref();
  return h("div", { class: "card warn", "data-testid": "localhost-passkey-hint" },
    h("strong", {}, "Passkeys need localhost: "),
    "Browsers block WebAuthn Passkeys on raw IP addresses (" + window.location.hostname + "). Open ",
    h("a", { href }, href),
    " to sign in or unlock wallets with a Passkey.");
}

function ensurePasskeyOrigin() {
  if (isLoopbackIpHost()) {
    throw new Error("Browsers reject Passkeys on " + window.location.hostname + "; open " + localhostHref() + " instead.");
  }
  if (!window.PublicKeyCredential || !navigator.credentials) {
    throw new Error("This browser does not support WebAuthn Passkeys in this context.");
  }
}

function extractPrfOutputB64(extResults) {
  const raw = extResults && extResults.prf && extResults.prf.results && extResults.prf.results.first;
  if (!raw) return null;
  const view = raw instanceof ArrayBuffer
    ? new Uint8Array(raw)
    : ArrayBuffer.isView(raw)
      ? new Uint8Array(raw.buffer, raw.byteOffset, raw.byteLength)
      : null;
  if (!view || view.length !== 32) return null;
  const copy = new Uint8Array(view);
  const encoded = bytesToB64url(copy);
  copy.fill(0);
  view.fill(0);
  return encoded;
}

/// Create a new WebAuthn credential with `prf` enabled, then immediately run
/// `get` with a fresh 32-byte `prfSalt` to verify and obtain its 32-byte PRF output.
async function enrollPrfPasskey(accountName, displayLabel) {
  ensurePasskeyOrigin();
  const rpId = window.location.hostname;
  const prfSalt = crypto.getRandomValues(new Uint8Array(32));
  const regChallenge = crypto.getRandomValues(new Uint8Array(32));
  const userId = crypto.getRandomValues(new Uint8Array(16));

  const created = await navigator.credentials.create({
    publicKey: {
      challenge: regChallenge,
      rp: { id: rpId, name: "IronDivi WebUI" },
      user: {
        id: userId,
        name: accountName,
        displayName: displayLabel || accountName,
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "required",
      },
      attestation: "none",
      extensions: { prf: {} },
      timeout: 60000,
    },
  });
  if (!created) throw new Error("Passkey creation was cancelled.");
  const createExt = created.getClientExtensionResults ? created.getClientExtensionResults() : {};
  if (createExt.prf && createExt.prf.enabled === false) {
    throw new Error("This passkey authenticator does not support the WebAuthn PRF extension.");
  }

  const getChallenge = crypto.getRandomValues(new Uint8Array(32));
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: getChallenge,
      rpId,
      allowCredentials: [{ type: "public-key", id: new Uint8Array(created.rawId) }],
      userVerification: "required",
      extensions: { prf: { eval: { first: prfSalt } } },
      timeout: 60000,
    },
  });
  if (!assertion) throw new Error("Passkey verification was cancelled.");
  const getExt = assertion.getClientExtensionResults ? assertion.getClientExtensionResults() : {};
  const prfOutput = extractPrfOutputB64(getExt);
  if (!prfOutput) {
    throw new Error("Passkey did not return a 32-byte PRF secret; use a PRF-capable passkey.");
  }
  return {
    credential_id: bytesToB64url(created.rawId),
    prf_salt: bytesToB64url(prfSalt),
    rp_id: rpId,
    prf_output: prfOutput,
  };
}

/// Evaluate WebAuthn PRF against a chosen passkey slot (or the first slot matching this host).
async function evalPrfPasskey(slots, chosenSlotId) {
  ensurePasskeyOrigin();
  const rpId = window.location.hostname;
  const matching = (slots || []).filter((s) => s.rp_id === rpId);
  if (!matching.length) {
    throw new Error("No passkey is enrolled for host " + rpId + ".");
  }
  const slot = (chosenSlotId && matching.find((s) => s.id === chosenSlotId)) || matching[0];
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const prfSalt = b64urlToBytes(slot.prf_salt);
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge,
      rpId,
      allowCredentials: [{ type: "public-key", id: b64urlToBytes(slot.credential_id) }],
      userVerification: "required",
      extensions: { prf: { eval: { first: prfSalt } } },
      timeout: 60000,
    },
  });
  if (!assertion) throw new Error("Passkey prompt was cancelled.");
  const ext = assertion.getClientExtensionResults ? assertion.getClientExtensionResults() : {};
  const prfOutput = extractPrfOutputB64(ext);
  if (!prfOutput) {
    throw new Error("Passkey did not produce a PRF key.");
  }
  return { slot_id: slot.id, prf_output: prfOutput };
}

const passkeyTools = {
  enrollPrfPasskey,
  evalPrfPasskey,
  localhostPasskeyHint,
  isLoopbackIpHost,
};

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

// --- theme and hierarchy ----------------------------------------------------

const THEME_KEY = "irondivi_theme";
let activeSpace = "treasury";
let activeDeck = "personal";

function getTheme() {
  return localStorage.getItem(THEME_KEY) || "zen";
}

function setTheme(theme) {
  const valid = ["zen", "sanctuary", "ledger", "dock", "modular"];
  if (!valid.includes(theme)) theme = "zen";
  localStorage.setItem(THEME_KEY, theme);
  document.documentElement.setAttribute("data-theme", theme);
  const sel = document.getElementById("theme-select");
  if (sel && sel.value !== theme) sel.value = theme;
  updateNavHierarchy();
}

function updateNavHierarchy() {
  const theme = getTheme();
  const raw = location.hash.replace(/^#\/?/, "");
  const [root] = raw.split("/");

  const spaceTabs = document.getElementById("space-tabs");
  const deckToggle = document.getElementById("ledger-deck-toggle");

  if (theme === "zen" || theme === "sanctuary" || theme === "modular") {
    if (spaceTabs) spaceTabs.hidden = !state.signed_in;
    if (deckToggle) deckToggle.hidden = true;

    const treasuryRoutes = ["wallet", "wallets", "swaps", "nft"];
    const networkRoutes = ["", "staking", "sidechains", "vaults", "explorer"];
    const systemRoutes = ["security", "settings", "logs", "console"];
    if (treasuryRoutes.includes(root)) activeSpace = "treasury";
    else if (networkRoutes.includes(root)) activeSpace = "network";
    else if (systemRoutes.includes(root)) activeSpace = "system";

    document.querySelectorAll(".space-tab").forEach((tab) => {
      tab.classList.toggle("on", tab.getAttribute("data-space") === activeSpace);
    });

    if (theme === "zen") {
      document.querySelectorAll("#nav a").forEach((a) => {
        const grp = a.getAttribute("data-group");
        a.style.display = grp === activeSpace ? "" : "none";
      });
    } else {
      document.querySelectorAll("#nav a").forEach((a) => {
        a.style.display = "";
      });
    }
  } else if (theme === "ledger") {
    if (spaceTabs) spaceTabs.hidden = true;
    if (deckToggle) deckToggle.hidden = !state.signed_in;

    document.querySelectorAll(".deck-btn").forEach((btn) => {
      btn.classList.toggle("on", btn.getAttribute("data-deck") === activeDeck);
    });

    const opsRoutes = ["explorer", "security", "settings", "logs", "console", "sidechains", "vaults"];
    if (opsRoutes.includes(root)) activeDeck = "ops";

    document.querySelectorAll("#nav a").forEach((a) => {
      const isOps = ["security", "settings", "logs", "console", "explorer", "sidechains", "vaults"].some(
        (p) => a.getAttribute("href") === "#/" + p
      );
      a.style.display = activeDeck === "personal" && isOps ? "none" : "";
    });
  } else {
    // dock
    if (spaceTabs) spaceTabs.hidden = true;
    if (deckToggle) deckToggle.hidden = true;
    document.querySelectorAll("#nav a").forEach((a) => {
      a.style.display = "";
    });
  }
}

// --- state and routing -------------------------------------------------------

async function refresh() {
  state = await getJson("/api/state").catch(() => ({}));
  const isTestnet = state.network === "testnet";
  document.body.classList.toggle("is-testnet", isTestnet);
  const netEl = document.getElementById("net");
  netEl.textContent = [state.chain_mode === "privatedivi" ? "PrivateDivi" : "Divi", state.network].filter(Boolean).join(" · ");
  netEl.className = "badge" + (isTestnet ? " warn" : " live");
  document.getElementById("nav").hidden = !state.signed_in;
  document.getElementById("logout").hidden = !state.signed_in;
  const themeSelect = document.getElementById("theme-select");
  if (themeSelect) {
    themeSelect.value = getTheme();
    themeSelect.onchange = (e) => setTheme(e.target.value);
  }
  document.querySelectorAll(".space-tab").forEach((tab) => {
    tab.onclick = () => {
      activeSpace = tab.getAttribute("data-space");
      document.querySelectorAll(".space-tab").forEach((t) => t.classList.toggle("on", t === tab));
      updateNavHierarchy();
    };
  });
  document.querySelectorAll(".deck-btn").forEach((btn) => {
    btn.onclick = () => {
      activeDeck = btn.getAttribute("data-deck");
      document.querySelectorAll(".deck-btn").forEach((b) => b.classList.toggle("on", b === btn));
      updateNavHierarchy();
    };
  });
  setTheme(getTheme());
  banner();
}

const routes = {
  "": dashboard,
  "security": security,
  "settings": settings,
  "console": consoleView,
  "logs": logsView,
  "explorer": (rest) => window.irondiviExplorer({ h, show, rpc, getJson, kv, note }, rest),
  "nft": () => window.irondiviNft({ h, show, rpc, post, getJson, form, field, val, note, state, passkey: passkeyTools }),
  "sidechains": () => window.irondiviSidechains({ h, show, post, getJson, form, field, val, note, kv, state: () => state }),
  "wallet": walletView,
  "wallets": () => window.irondiviWallets({ h, show, post, del, getJson, form, field, val, note, kv, passkey: passkeyTools, links, rpc }),
  "staking": stakingView,
  "vaults": vaultsView,
  "swaps": swapsView,
};

async function route() {
  const raw = location.hash.replace(/^#\/?/, "");
  const [root, ...rest] = raw.split("/");
  if (state.setup_required) return setupView();
  if (!state.signed_in) return loginView();
  const view = Object.prototype.hasOwnProperty.call(routes, root) ? routes[root] : dashboard;
  clearTimeout(logTimer);
  document.querySelectorAll("#nav a").forEach((a) =>
    a.classList.toggle("on", a.getAttribute("href") === "#/" + root));
  updateNavHierarchy();
  try {
    await view(rest);
  } catch (err) {
    show(h("p", { class: "note err" }, err.message));
  }
}

// --- views -------------------------------------------------------------------

function setupView() {
  // The browser the daemon opened at start is signed in already: no token
  const launched = state.signed_in;
  show(h("section", { class: "narrow" },
    localhostPasskeyHint(),
    h("h2", {}, "Set the web interface password"),
    launched
      ? h("p", {}, "The daemon opened this window and signed it in. Choose the password this interface ",
        "will ask for when you open it any other way. It is not the wallet passphrase.")
      : h("p", {}, "The daemon wrote a one-time setup token to the file ",
        h("code", {}, "webui-setup-token"), " in its data directory. Paste it here and choose the ",
        "password this interface will ask for. It is not the wallet passphrase."),
    form("First sign-in", [
      launched ? null : field("Setup token", "token", "text"),
      field("Password (" + state.min_password + " characters or more)", "password", "password", { autocomplete: "new-password" }),
      field("The password again", "again", "password", { autocomplete: "new-password" }),
    ], "Set password", async (f) => {
      if (val(f, "password") !== val(f, "again")) throw new Error("the passwords differ");
      const r = await post("/api/setup", { token: launched ? "" : val(f, "token"), password: val(f, "password") });
      state.csrf = r.csrf;
      await refresh();
      location.hash = "#/security";
      route();
    })));
}

function loginView() {
  let passkeyBtn = null;
  const loginForm = form("Sign in", [
    field("Password", "password", "password", { autocomplete: "current-password", autofocus: true }),
  ], "Sign in", async (f) => {
    const r = await post("/api/login", { password: val(f, "password") });
    state.csrf = r.csrf;
    await refresh();
    route();
  }, null, state.has_passkey ? [
    (passkeyBtn = h("button", {
      type: "button",
      id: "login-passkey-btn",
      "data-testid": "login-passkey-btn",
      class: "secondary",
      onclick: async () => {
        passkeyBtn.disabled = true;
        note(loginForm._note, "Waiting for passkey…", true);
        try {
          ensurePasskeyOrigin();
          const start = await post("/api/auth/passkey/login/start", {});
          const assertion = await navigator.credentials.get({
            publicKey: {
              challenge: b64urlToBytes(start.challenge),
              rpId: start.rp_id,
              allowCredentials: (start.allow_credentials || []).map((c) => ({
                type: "public-key",
                id: b64urlToBytes(c.id),
              })),
              userVerification: "required",
              timeout: 60000,
            },
          });
          if (!assertion) throw new Error("Passkey sign-in was cancelled.");
          const r = await post("/api/auth/passkey/login/finish", {
            credential_id: bytesToB64url(assertion.rawId),
            client_data_json: bytesToB64url(assertion.response.clientDataJSON),
            authenticator_data: bytesToB64url(assertion.response.authenticatorData),
            signature: bytesToB64url(assertion.response.signature),
          });
          state.csrf = r.csrf;
          await refresh();
          route();
        } catch (err) {
          note(loginForm._note, err.message, false);
        } finally {
          passkeyBtn.disabled = false;
        }
      },
    }, "Sign in with Passkey")),
  ] : []);

  show(h("section", { class: "narrow" }, localhostPasskeyHint(), loginForm));
}

function kv(rows) {
  return h("dl", { class: "kv" }, rows.flatMap(([k, v]) => [h("dt", {}, k),
    h("dd", {}, v === undefined || v === null ? "—" : v instanceof Node ? v : String(v))]));
}

// --- deep links into the explorer ----------------------------------------------

const shortId = (s) => (s && s.length > 20 ? s.slice(0, 10) + "…" + s.slice(-8) : s);

function txLink(txid, label) {
  if (!txid) return "—";
  return h("a", { href: "#/explorer/tx/" + txid, class: "mono", "data-txid": txid }, label || txid);
}

function addrLink(address, label) {
  if (!address) return "—";
  return h("a", { href: "#/explorer/address/" + encodeURIComponent(address), class: "mono" }, label || address);
}

function blockLink(hashOrHeight, label) {
  if (hashOrHeight === undefined || hashOrHeight === null) return "—";
  return h("a", { href: "#/explorer/block/" + hashOrHeight, class: "mono" }, label === undefined ? String(hashOrHeight) : String(label));
}

const links = { txLink, addrLink, blockLink, shortId };

/// A table of `rows` (arrays of cells) under `head`
function table(testid, head, rows) {
  return h("div", { class: "table-wrap" }, h("table", { class: "table", "data-testid": testid },
    h("thead", {}, h("tr", {}, head.map((c) => h("th", {}, c)))),
    h("tbody", {}, rows.map((r) => h("tr", {}, r.map((c) => h("td", {}, c === undefined || c === null ? "—" : c)))))));
}

/// Any RPC reply, readable: objects as key/value lists, arrays of objects as
/// tables, txids and addresses as explorer links
function jsonView(v, testid) {
  const cell = (x) => {
    if (x === null || x === undefined) return "—";
    if (typeof x === "string") {
      if (/^[0-9a-f]{64}$/.test(x)) return txLink(x, shortId(x));
      const pair = x.match(/^([1-9A-HJ-NP-Za-km-z]{26,35}):([1-9A-HJ-NP-Za-km-z]{26,35})$/);
      if (pair) return h("span", {}, addrLink(pair[1]), ":", addrLink(pair[2]));
      if (/^[1-9A-HJ-NP-Za-km-z]{26,35}$/.test(x) && /[A-Za-z]/.test(x) && /\d/.test(x)) return addrLink(x);
      return x;
    }
    if (typeof x === "object") return jsonView(x);
    return String(x);
  };
  if (Array.isArray(v)) {
    if (!v.length) return h("p", { class: "muted", "data-testid": testid || null }, "None.");
    if (v.every((x) => x && typeof x === "object" && !Array.isArray(x))) {
      const cols = [...new Set(v.flatMap((x) => Object.keys(x)))];
      return table(testid || null, cols, v.map((x) => cols.map((c) => cell(x[c]))));
    }
    return h("ul", { "data-testid": testid || null }, v.map((x) => h("li", {}, cell(x))));
  }
  if (v && typeof v === "object") {
    const dl = kv(Object.entries(v).map(([k, x]) => [k, cell(x)]));
    if (testid) dl.setAttribute("data-testid", testid);
    return dl;
  }
  return h("span", { "data-testid": testid || null }, cell(v));
}

// --- the node wallet, unlocked for one action ------------------------------------

function hostNodeSlots() {
  return (state.node_passkeys || []).filter((s) => s.rp_id === location.hostname);
}

/// Unlock the node wallet: for a minute of spending, or for staking only. By
/// the typed passphrase, or with a node wallet passkey (`pk`, from
/// evalPrfPasskey) whose WebAuthn PRF output unseals the passphrase on the node
function nodeUnlock(passphrase, pk, stakingOnly) {
  if (pk) {
    return post("/api/node-wallet/unlock-passkey", {
      slot_id: pk.slot_id, prf_output: pk.prf_output, staking_only: stakingOnly, timeout: stakingOnly ? 0 : 60,
    });
  }
  return rpc("walletpassphrase", passphrase, stakingOnly ? 0 : 60, stakingOnly);
}

/// Run `work` with the node wallet unlocked for spending for a minute, by the
/// passphrase or an enrolled node wallet passkey, then put it back as it was:
/// locked, or unlocked for staking only
async function withNodeUnlocked(passphrase, viaPasskey, work) {
  await refresh();
  const before = state.wallet;
  if (before === "unencrypted") throw new Error("encrypt the wallet on the Security page first");
  let pk = null;
  if (before !== "unlocked") {
    if (viaPasskey) pk = await evalPrfPasskey(hostNodeSlots());
    else if (!passphrase) throw new Error("enter the wallet passphrase");
    await nodeUnlock(passphrase, pk, false);
  }
  let result;
  let restore = null;
  try {
    result = await work();
  } finally {
    const back = before === "unlocked-for-staking" ? nodeUnlock(passphrase, pk, true)
      : before === "locked" ? rpc("walletlock") : null;
    if (pk) pk.prf_output = "";
    if (back) restore = await back.then(() => null, (e) => e.message);
    await refresh();
  }
  return (result || "Done.") + (restore ? " The wallet could not go back to " + walletLabel(before).toLowerCase() + ": " + restore : "");
}

/// A form whose action needs the wallet unlocked: a passphrase field and, with
/// a node wallet passkey enrolled for this host, a "… with Passkey" button
function signingForm(title, fields, label, work, extra, passkeyLabel, testid) {
  const needsP = state.wallet !== "unlocked";
  const slots = hostNodeSlots();
  let pkBtn = null;
  const run = (f, viaPasskey) => withNodeUnlocked(f.elements.p ? f.elements.p.value : "", viaPasskey, () => work(f));
  const f = form(title, [...fields,
    needsP ? field(slots.length ? "Wallet passphrase (or use your passkey)" : "Wallet passphrase", "p", "password", { autocomplete: "current-password" }) : null,
  ], label, (ff) => run(ff, false), extra,
  needsP && slots.length ? [(pkBtn = h("button", {
    type: "button",
    class: "secondary",
    "data-testid": testid || null,
    onclick: async () => {
      pkBtn.disabled = true;
      note(f._note, "Waiting for passkey…", true);
      try {
        note(f._note, await run(f, true), true);
        if (f.elements.p) f.elements.p.value = "";
      } catch (err) {
        note(f._note, err.message, false);
      } finally {
        pkBtn.disabled = false;
      }
    },
  }, passkeyLabel || label + " with Passkey"))] : []);
  return f;
}

/// The node wallet's staking unlock: passphrase form plus passkey button
function unlockForStakingForm(after) {
  const slots = hostNodeSlots();
  let btn = null;
  const f = form("Unlock for staking only", [
    field("Wallet passphrase", "p", "password", { autocomplete: "current-password" }),
  ], "Unlock for staking", async (ff) => {
    await nodeUnlock(val(ff, "p"), null, true);
    flash = "Unlocked for staking. Spending still needs the passphrase.";
    after();
  }, h("p", { class: "muted" }, "The wallet stakes, but cannot send, until it is locked again."),
  slots.length ? [
    (btn = h("button", {
      type: "button",
      class: "secondary",
      "data-testid": "node-unlock-staking-passkey",
      onclick: async () => {
        btn.disabled = true;
        note(f._note, "Waiting for passkey…", true);
        try {
          const unlocked = await evalPrfPasskey(slots);
          await nodeUnlock("", unlocked, true);
          unlocked.prf_output = "";
          flash = "Unlocked for staking with Passkey.";
          after();
        } catch (err) {
          note(f._note, err.message, false);
        } finally {
          btn.disabled = false;
        }
      },
    }, "Unlock for staking with Passkey")),
  ] : []);
  return f;
}

/// An admin passkey assertion, to sign in or to re-authenticate a change
async function adminAssertion() {
  ensurePasskeyOrigin();
  const start = await post("/api/auth/passkey/login/start", {});
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: b64urlToBytes(start.challenge),
      rpId: start.rp_id,
      allowCredentials: (start.allow_credentials || []).map((c) => ({ type: "public-key", id: b64urlToBytes(c.id) })),
      userVerification: "required",
      timeout: 60000,
    },
  });
  if (!assertion) throw new Error("Passkey prompt was cancelled.");
  return {
    credential_id: bytesToB64url(assertion.rawId),
    client_data_json: bytesToB64url(assertion.response.clientDataJSON),
    authenticator_data: bytesToB64url(assertion.response.authenticatorData),
    signature: bytesToB64url(assertion.response.signature),
  };
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
        ["Version", info.version],
        ["Blocks", (chain.blocks ?? info.blocks) !== undefined
          ? h("a", { href: "#/explorer/block/" + (chain.blocks ?? info.blocks), "data-testid": "dashboard-blocks-link" }, String(chain.blocks ?? info.blocks))
          : undefined],
        ["Headers", chain.headers],
        ["Connections", info.connections], ["Network", state.network],
      ])),
      h("div", { class: "card" }, h("h3", {}, "Wallet"), kv([
        ["Encryption", walletLabel(state.wallet)], ["Balance", info.balance],
      ]), h("p", {}, h("a", { href: "#/security" }, "Security settings"))),
      h("div", { class: "card" }, h("h3", {}, "Staking"), staking.error ? h("p", { class: "muted" }, staking.error) :
        kv(Object.entries(staking).map(([k, v]) => [k, typeof v === "object" ? JSON.stringify(v) : v])),
      h("p", {}, h("a", { href: "#/staking" }, "Staking"), " · ", h("a", { href: "#/explorer" }, "Explorer"))),
    )));
}

function adminPasskeysCard() {
  const enrolled = state.passkeys || [];
  const msg = h("p", { class: "note" });
  const pwConfirm = field("Current web interface password (required to add or remove a passkey)", "password", "password", {
    autocomplete: "current-password",
  });
  const labelInput = field("Passkey label (optional)", "label", "text", {
    maxlength: 64,
    placeholder: "Touch ID / Security Key",
  });

  const list = enrolled.length
    ? h("ul", { class: "pk-list" }, enrolled.map((pk) =>
      h("li", { class: "pk-item" },
        h("span", {}, h("strong", {}, pk.label), " ", h("span", { class: "muted small" }, "(" + pk.rp_id + ", added " + new Date(pk.created * 1000).toLocaleDateString() + ")")),
        h("button", {
          type: "button",
          class: "link",
          onclick: async () => {
            const password = pwConfirm.querySelector("input").value;
            if (!password) {
              note(msg, "Enter your current web interface password below first.", false);
              return;
            }
            if (!confirm("Remove sign-in passkey \"" + pk.label + "\"?")) return;
            try {
              await del("/api/auth/passkey/" + pk.id, { password });
              flash = "Removed sign-in passkey \"" + pk.label + "\".";
              security();
            } catch (err) {
              note(msg, err.message, false);
            }
          },
        }, "Remove"))))
    : h("p", { class: "muted" }, "No sign-in passkeys enrolled yet.");

  const addBtn = h("button", {
    type: "submit",
    "data-testid": "admin-add-passkey-btn",
  }, "Add Sign-In Passkey");

  const card = h("form", {
    class: "card",
    "data-testid": "admin-passkeys-card",
    onsubmit: async (e) => {
      e.preventDefault();
      addBtn.disabled = true;
      note(msg, "Waiting for passkey…", true);
      try {
        ensurePasskeyOrigin();
        const password = val(card, "password");
        if (!password) throw new Error("enter your current web interface password");
        const label = val(card, "label").trim() || "Passkey";
        const start = await post("/api/auth/passkey/register/start", { password, label });
        const created = await navigator.credentials.create({
          publicKey: {
            challenge: b64urlToBytes(start.challenge),
            rp: { id: start.rp_id, name: start.rp_name },
            user: {
              id: b64urlToBytes(start.user.id),
              name: start.user.name,
              displayName: start.user.display_name,
            },
            pubKeyCredParams: [{ type: "public-key", alg: -7 }],
            authenticatorSelection: {
              residentKey: "preferred",
              userVerification: "required",
            },
            attestation: "none",
            excludeCredentials: (start.exclude_credentials || []).map((c) => ({
              type: "public-key",
              id: b64urlToBytes(c.id),
            })),
            timeout: 60000,
          },
        });
        if (!created) throw new Error("Passkey registration was cancelled.");
        await post("/api/auth/passkey/register/finish", {
          client_data_json: bytesToB64url(created.response.clientDataJSON),
          attestation_object: bytesToB64url(created.response.attestationObject),
        });
        flash = "Sign-in passkey added.";
        security();
      } catch (err) {
        note(msg, err.message, false);
      } finally {
        addBtn.disabled = false;
      }
    },
  },
    h("h3", {}, "WebUI Sign-In Passkeys"),
    h("p", { class: "muted" }, "Sign in to this web interface with Touch ID, Windows Hello, or a hardware security key instead of typing the admin password."),
    list,
    labelInput,
    pwConfirm,
    h("div", { class: "row" }, addBtn),
    msg);
  return card;
}

function nodePasskeysCard() {
  const slots = state.node_passkeys || [];
  const msg = h("p", { class: "note" });
  const list = slots.length
    ? h("ul", { class: "pk-list" }, slots.map((s) =>
      h("li", { class: "pk-item" },
        h("span", {}, h("strong", {}, s.label), " ", h("span", { class: "muted small" }, "(" + s.rp_id + ")")),
        h("button", {
          type: "button",
          class: "link",
          onclick: async () => {
            if (!confirm("Remove node wallet passkey \"" + s.label + "\"?")) return;
            try {
              await del("/api/node-wallet/passkeys/" + s.id, {});
              flash = "Removed node wallet passkey \"" + s.label + "\".";
              security();
            } catch (err) {
              note(msg, err.message, false);
            }
          },
        }, "Remove"))))
    : h("p", { class: "muted" }, "No passkeys enrolled for wallet.dat yet.");

  const addBtn = h("button", {
    type: "submit",
    "data-testid": "node-add-passkey-btn",
  }, "Add Wallet Passkey");

  const card = h("form", {
    class: "card",
    "data-testid": "node-passkeys-card",
    onsubmit: async (e) => {
      e.preventDefault();
      addBtn.disabled = true;
      note(msg, "Waiting for passkey…", true);
      try {
        const passphrase = val(card, "passphrase");
        if (!passphrase) throw new Error("enter the current wallet passphrase");
        const label = val(card, "label").trim() || "Node Wallet Passkey";
        const enrolled = await enrollPrfPasskey("irondivi-node-wallet", label);
        await post("/api/node-wallet/passkeys", {
          passphrase,
          label,
          credential_id: enrolled.credential_id,
          prf_salt: enrolled.prf_salt,
          rp_id: enrolled.rp_id,
          prf_output: enrolled.prf_output,
        });
        enrolled.prf_output = "";
        flash = "Added passkey \"" + label + "\" for unlocking wallet.dat.";
        security();
      } catch (err) {
        note(msg, err.message, false);
      } finally {
        addBtn.disabled = false;
      }
    },
  },
    h("h3", {}, "Node Wallet Passkeys (wallet.dat)"),
    h("p", { class: "muted" }, "Seal the node's wallet.dat passphrase locally under a WebAuthn PRF passkey so you can unlock staking or sending with a touch. Keep your wallet passphrase and wallet.dat backup safe — passkeys do not replace them."),
    list,
    field("Passkey label (optional)", "label", "text", { maxlength: 64, placeholder: "Touch ID" }),
    field("Current wallet passphrase", "passphrase", "password", { autocomplete: "current-password" }),
    h("div", { class: "row" }, addBtn),
    msg);
  return card;
}

async function security() {
  await refresh();
  const w = state.wallet;
  const parts = [
    localhostPasskeyHint(),
    h("h2", {}, "Security"),
    h("p", {}, "Wallet: ", h("strong", {}, walletLabel(w))),
  ];
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
    const hostNodeSlots = (state.node_passkeys || []).filter((s) => s.rp_id === location.hostname);
    parts.push(unlockForStakingForm(security));
    parts.push(form("Lock the wallet", [], "Lock", async () => {
      await rpc("walletlock");
      flash = "Locked.";
      security();
    }));
    parts.push(nodePasskeysCard());
    let changePkBtn = null;
    const changePass = form("Change the wallet passphrase", [
      field(hostNodeSlots.length ? "Current passphrase (or use your passkey)" : "Current passphrase", "old", "password", { autocomplete: "current-password" }),
      field("New passphrase", "p1", "password", { autocomplete: "new-password" }),
      field("The new passphrase again", "p2", "password", { autocomplete: "new-password" }),
    ], "Change passphrase", async (f) => {
      if (val(f, "p1") !== val(f, "p2")) throw new Error("the passphrases differ");
      if (!val(f, "old")) throw new Error("enter the current passphrase");
      await post("/api/wallet/change-passphrase", { old_passphrase: val(f, "old"), new_passphrase: val(f, "p1") });
      await refresh();
      return "The wallet passphrase is changed. Node wallet passkeys were cleared; re-add them with the new passphrase.";
    }, null, hostNodeSlots.length ? [
      (changePkBtn = h("button", {
        type: "button",
        class: "secondary",
        "data-testid": "node-change-passphrase-passkey",
        onclick: async () => {
          changePkBtn.disabled = true;
          note(changePass._note, "Waiting for passkey…", true);
          try {
            if (val(changePass, "p1") !== val(changePass, "p2")) throw new Error("the passphrases differ");
            if (!val(changePass, "p1")) throw new Error("enter the new passphrase");
            const pk = await evalPrfPasskey(hostNodeSlots);
            await post("/api/wallet/change-passphrase", { passkey: pk, new_passphrase: val(changePass, "p1") });
            pk.prf_output = "";
            flash = "The wallet passphrase is changed with Passkey. Node wallet passkeys were cleared; re-add them with the new passphrase.";
            security();
          } catch (err) {
            note(changePass._note, err.message, false);
          } finally {
            changePkBtn.disabled = false;
          }
        },
      }, "Change with Passkey")),
    ] : []);
    parts.push(changePass);
  }
  parts.push(adminPasskeysCard());
  const hasAdminPasskey = (state.passkeys || []).some((pk) => pk.rp_id === location.hostname);
  let pwPkBtn = null;
  const changePw = form("Change the web interface password", [
    field(hasAdminPasskey ? "Current password (or use your passkey)" : "Current password", "current", "password", { autocomplete: "current-password" }),
    field("New password", "p1", "password", { autocomplete: "new-password" }),
    field("The new password again", "p2", "password", { autocomplete: "new-password" }),
  ], "Change password", async (f) => {
    if (val(f, "p1") !== val(f, "p2")) throw new Error("the passwords differ");
    await post("/api/auth/change-password", { current_password: val(f, "current"), new_password: val(f, "p1") });
    return "Changed. Other browsers are signed out.";
  }, null, hasAdminPasskey ? [
    (pwPkBtn = h("button", {
      type: "button",
      class: "secondary",
      "data-testid": "admin-change-password-passkey",
      onclick: async () => {
        pwPkBtn.disabled = true;
        note(changePw._note, "Waiting for passkey…", true);
        try {
          if (val(changePw, "p1") !== val(changePw, "p2")) throw new Error("the passwords differ");
          if (!val(changePw, "p1")) throw new Error("enter the new password");
          const assertion = await adminAssertion();
          await post("/api/auth/change-password", { passkey_assertion: assertion, new_password: val(changePw, "p1") });
          changePw.querySelectorAll("input[type=password]").forEach((i) => (i.value = ""));
          note(changePw._note, "Changed with Passkey. Other browsers are signed out.", true);
        } catch (err) {
          note(changePw._note, err.message, false);
        } finally {
          pwPkBtn.disabled = false;
        }
      },
    }, "Change with Passkey")),
  ] : []);
  parts.push(changePw);
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

  const curTheme = getTheme();
  const themeCardGrid = h("div", { class: "theme-config-grid" });
  const themeOptions = [
    { id: "zen", name: "Zen Spaces", designer: "Camille Chen", desc: "Serene uncluttered progressive disclosure with spacious calm (Default)." },
    { id: "sanctuary", name: "Tiered Sanctuary", designer: "Astrid Lindholm", desc: "Structured 3-tier hierarchy: Treasury, Network & System." },
    { id: "ledger", name: "Calm Ledger", designer: "Marcus Vance", desc: "Human-first conversational reassurance with Personal / Node Ops dual deck." },
    { id: "dock", name: "Sovereign Dock", designer: "Dr. Elena Rostova", desc: "Compact icon rail, dense telemetry, and command clarity." },
    { id: "modular", name: "Modular Deck", designer: "Torbjörn Berg", desc: "Tactile instrument control units with distinct operational states." },
  ];

  themeOptions.forEach((opt) => {
    const card = h("div", {
      class: "theme-card" + (curTheme === opt.id ? " active" : ""),
      onclick: () => {
        setTheme(opt.id);
        themeCardGrid.querySelectorAll(".theme-card").forEach((c) => c.classList.remove("active"));
        card.classList.add("active");
      },
    },
      h("div", { class: "theme-card-head" },
        h("span", { class: "theme-card-name" }, opt.name),
        h("span", { class: "badge" }, opt.id === "zen" ? "Default" : "Look")
      ),
      h("div", { class: "theme-card-designer" }, "Designer: " + opt.designer),
      h("p", { class: "theme-card-desc" }, opt.desc)
    );
    themeCardGrid.append(card);
  });

  const themeSection = h("div", { class: "card" },
    h("h3", {}, "Interface Design & Look"),
    h("p", { class: "muted small" }, "Select which interface look to use. Your choice is saved and active immediately across all pages."),
    themeCardGrid
  );

  const other = s.file.other.length ? h("p", { class: "muted" },
    "Also in the file, not edited here: " + s.file.other.join(", ")) : null;
  show(h("section", {},
    h("h2", {}, "Settings"),
    themeSection,
    h("p", { class: "muted" }, "File: ", h("code", {}, s.conf), " (" + s.format + "). A backup of the old file is kept beside it as ",
      h("code", {}, ".bak"), "."),
    locked ? h("p", { class: "note err" }, "Encrypt the wallet on the Security page before changing settings.") : null,
    tabs,
    h("div", { class: "opts" }, opts.filter((o) => o.category === settingsTab).map(row)),
    other,
    h("div", { class: "savebar" }, save, count, msg)));
}

// --- QR codes ----------------------------------------------------------------

/// A QR code of `text`, dark on white whatever the theme
function qrCanvas(text) {
  qrcode.stringToBytes = qrcode.stringToBytesFuncs["UTF-8"];
  const q = qrcode(0, "M");
  q.addData(text, "Byte");
  q.make();
  const n = q.getModuleCount();
  const cell = 8;
  const pad = 4 * cell;
  const c = h("canvas", { class: "qr", width: n * cell + 2 * pad, height: n * cell + 2 * pad,
    role: "img", "aria-label": "QR code: " + text });
  const g = c.getContext("2d");
  g.fillStyle = "#fff";
  g.fillRect(0, 0, c.width, c.height);
  g.fillStyle = "#000";
  for (let r = 0; r < n; r++) {
    for (let k = 0; k < n; k++) if (q.isDark(r, k)) g.fillRect(pad + k * cell, pad + r * cell, cell, cell);
  }
  return c;
}

let qrReaderLoad = null;

/// The QR reader, fetched the first time something is scanned
function qrReader() {
  qrReaderLoad = qrReaderLoad || new Promise((ok, fail) => {
    const s = h("script", { src: "/jsqr.js" });
    s.addEventListener("load", () => ok(window.jsQR));
    s.addEventListener("error", () => { qrReaderLoad = null; s.remove(); fail(new Error("could not load the QR reader")); });
    document.head.append(s);
  });
  return qrReaderLoad;
}

/// The text of a QR code in a picture or video frame, or null
async function readQr(source, width, height) {
  const jsQR = await qrReader();
  const scale = Math.min(1, 2000 / Math.max(width, height));
  const w = Math.max(1, Math.round(width * scale));
  const ht = Math.max(1, Math.round(height * scale));
  const c = document.createElement("canvas");
  c.width = w;
  c.height = ht;
  const g = c.getContext("2d", { willReadFrequently: true });
  g.drawImage(source, 0, 0, w, ht);
  const hit = jsQR(g.getImageData(0, 0, w, ht).data, w, ht, { inversionAttempts: "attemptBoth" });
  return hit && hit.data ? hit.data : null;
}

/// Ways to read a QR code into `onText`
function scanner(onText) {
  const msg = h("p", { class: "note" });
  const video = h("video", { class: "scan", playsinline: true, hidden: true });
  video.muted = true;
  const box = h("div", { class: "scanner" });
  const stopButton = h("button", { type: "button", class: "link", hidden: true,
    onclick: () => { stop(); msg.textContent = ""; } }, "Stop");
  let stream = null;

  function stop() {
    if (stream) stream.getTracks().forEach((t) => t.stop());
    stream = null;
    video.srcObject = null;
    video.hidden = stopButton.hidden = true;
  }
  function found(text) {
    stop();
    note(msg, "Read the QR code.", true);
    onText(text);
  }

  async function picture(file) {
    if (!file) return;
    note(msg, "Reading the picture…", true);
    try {
      const bmp = await createImageBitmap(file);
      const text = await readQr(bmp, bmp.width, bmp.height);
      bmp.close();
      if (text) found(text);
      else note(msg, "No QR code found in that picture. Try closer, sharper or with more light.", false);
    } catch (err) {
      note(msg, "Could not read that picture: " + err.message, false);
    }
  }

  async function watch(open, hint) {
    stop();
    let mine;
    try {
      mine = await open();
    } catch (err) {
      note(msg, err.name === "NotAllowedError" ? "Not allowed, so nothing was shared." : err.message, false);
      return;
    }
    stream = mine;
    video.srcObject = mine;
    video.hidden = stopButton.hidden = false;
    await video.play().catch(() => {});
    note(msg, hint, true);
    mine.getTracks().forEach((t) => t.addEventListener("ended", () => { if (stream === mine) stop(); }));
    const tick = async () => {
      if (stream !== mine) return;
      if (!box.isConnected) return stop();
      if (video.videoWidth) {
        let text = null;
        try {
          text = await readQr(video, video.videoWidth, video.videoHeight);
        } catch (err) {
          stop();
          return note(msg, err.message, false);
        }
        if (text && stream === mine) return found(text);
      }
      setTimeout(tick, 300);
    };
    tick();
  }

  const fileInput = (capture) => {
    const i = h("input", { type: "file", accept: "image/*", capture: capture ? "environment" : null, hidden: true });
    i.addEventListener("change", () => { const f = i.files[0]; i.value = ""; picture(f); });
    return i;
  };
  const camera = fileInput(true);
  const image = fileInput(false);
  const media = navigator.mediaDevices;
  const touch = matchMedia("(pointer: coarse)").matches;
  const buttons = [
    touch ? h("button", { type: "button", onclick: () => camera.click() }, "Take a picture") : null,
    h("button", { type: "button", onclick: () => image.click() }, touch ? "Choose a picture" : "Open an image"),
    media && media.getUserMedia ? h("button", { type: "button", onclick: () => watch(
      () => media.getUserMedia({ video: { facingMode: "environment" }, audio: false }),
      "Hold the QR code up to the camera…") }, "Live camera") : null,
    media && media.getDisplayMedia && !touch ? h("button", { type: "button", onclick: () => watch(
      () => media.getDisplayMedia({ video: true, audio: false }),
      "Watching the shared screen or window; bring the QR code into view…") }, "Scan the screen") : null,
  ];

  const onPaste = (e) => {
    if (!box.isConnected) return document.removeEventListener("paste", onPaste);
    const items = [...(e.clipboardData ? e.clipboardData.items : [])];
    const img = items.find((i) => i.kind === "file" && i.type.startsWith("image/"));
    if (img) {
      e.preventDefault();
      picture(img.getAsFile());
    }
  };
  document.addEventListener("paste", onPaste);

  box.append(h("div", { class: "row wrap" }, buttons, camera, image, stopButton),
  h("p", { class: "muted small" }, touch ? null : "You can also paste a screenshot of a QR code on this page. ",
    window.isSecureContext ? null : "The live camera and screen need HTTPS or localhost; a picture works anyway."),
  video, msg);
  return box;
}

/// The request's QR code, its link and ways to hand them over
function requestCard(uri) {
  const qr = qrCanvas(uri);
  const msg = h("p", { class: "note" });
  const code = h("code", { class: "uri" }, uri);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(uri);
      note(msg, "Link copied.", true);
    } catch (_) {
      const r = document.createRange();
      r.selectNodeContents(code);
      getSelection().removeAllRanges();
      getSelection().addRange(r);
      note(msg, "Selected; copy it with Ctrl+C or ⌘C.", true);
    }
  };
  const share = async () => {
    const data = { title: "Divi payment request", text: uri };
    const blob = await new Promise((ok) => qr.toBlob(ok, "image/png"));
    const file = blob && new File([blob], "divi-request.png", { type: "image/png" });
    if (file && navigator.canShare && navigator.canShare({ files: [file] })) data.files = [file];
    await navigator.share(data).catch((e) => { if (e.name !== "AbortError") note(msg, e.message, false); });
  };
  return h("div", { class: "qrbox" }, qr, code, h("div", { class: "row wrap" },
    h("button", { type: "button", onclick: copy }, "Copy link"),
    navigator.share ? h("button", { type: "button", onclick: share }, "Share") : null), msg);
}

// --- wallet ------------------------------------------------------------------

async function walletView() {
  await refresh();
  const w = state.wallet;
  if (w === null || w === undefined) {
    return show(h("section", {}, localhostPasskeyHint(), h("h2", {}, "Wallet"), h("p", { class: "muted" }, "The daemon has no wallet loaded.")));
  }
  const balance = await rpc("getbalance").catch((e) => e.message);

  const reqBox = h("div");
  const receive = form("Request a payment", [
    field("Amount in DIVI (optional)", "amount", "text", { inputmode: "decimal", placeholder: "any amount" }),
    field("Your name or shop (optional)", "label"),
    field("What it is for (optional)", "message"),
    field("Memo for the chain (optional; for wallets that can write one)", "memo", "text", { maxlength: PayUri.MEMO_MAX }),
  ], "Make QR code", async (f) => {
    const req = { amount: val(f, "amount"), label: val(f, "label"), message: val(f, "message"), memo: val(f, "memo") };
    PayUri.build(Object.assign({ address: "1".repeat(34) }, req)); // check the fields before taking a new address
    const address = await rpc("getnewaddress", req.label.trim());
    reqBox.replaceChildren(requestCard(PayUri.build(Object.assign({ address }, req))));
    return "Show the code to the payer, or send them the link. It pays a new address of this wallet.";
  }, h("p", { class: "muted" }, "Makes a QR code the payer scans with their Divi wallet: your address and the amount fill in for them."));
  receive.append(reqBox);

  const canSend = w !== "unencrypted";
  const hostNodeSlots = (state.node_passkeys || []).filter((s) => s.rp_id === location.hostname);
  let request = {};
  const about = h("p", { class: "muted" });
  let sendPasskeyBtn = null;

  async function executeSend(f, viaPasskey) {
    if (!canSend) throw new Error("encrypt the wallet on the Security page before sending");
    const address = val(f, "to").trim();
    const amount = val(f, "amount").trim();
    if (!amount) throw new Error("enter the amount");
    PayUri.build({ address, amount });
    const v = await rpc("validateaddress", address);
    if (!v.isvalid) throw new Error("that is not a valid address on " + (state.network || "this network"));
    const before = state.wallet;
    const p = f.elements.p ? f.elements.p.value : "";
    if (!viaPasskey && before !== "unlocked" && !p) throw new Error("enter the wallet passphrase");
    if (!confirm("Send " + amount + " DIVI to " + address + "?")) return "Not sent.";

    let unlockedPk = null;
    if (before !== "unlocked") {
      if (viaPasskey) {
        unlockedPk = await evalPrfPasskey(hostNodeSlots);
        await post("/api/node-wallet/unlock-passkey", {
          slot_id: unlockedPk.slot_id,
          prf_output: unlockedPk.prf_output,
          staking_only: false,
          timeout: 60,
        });
      } else {
        await rpc("walletpassphrase", p, 60, false);
      }
    }
    let txid;
    let restore = null;
    try {
      const comment = val(f, "note").trim();
      const to = (request.address === address && request.label) || "";
      txid = comment || to
        ? await rpc("sendtoaddress", address, Number(amount), "metadata", comment, to)
        : await rpc("sendtoaddress", address, Number(amount));
    } finally {
      const back = before === "unlocked-for-staking"
        ? (unlockedPk
          ? post("/api/node-wallet/unlock-passkey", {
            slot_id: unlockedPk.slot_id,
            prf_output: unlockedPk.prf_output,
            staking_only: true,
            timeout: 0,
          })
          : rpc("walletpassphrase", p, 0, true))
        : before === "locked" ? rpc("walletlock") : null;
      if (unlockedPk) unlockedPk.prf_output = "";
      if (back) restore = await back.then(() => null, (e) => e.message);
      await refresh();
    }
    f.elements.to.value = f.elements.amount.value = f.elements.note.value = "";
    request = {};
    about.textContent = "";
    return h("span", {}, "Sent. Transaction ", txLink(txid), restore
      ? ". The wallet could not go back to " + walletLabel(before).toLowerCase() + ": " + restore : ".");
  }

  const send = form("Pay", [
    field("Pay to: an address or a divi: link", "to", "text", { spellcheck: "false", placeholder: "D…" }),
    field("Amount in DIVI", "amount", "text", { inputmode: "decimal" }),
    field("Note for your records (optional)", "note"),
    w === "unlocked" ? null : field("Wallet passphrase", "p", "password", { autocomplete: "current-password" }),
  ], "Send", (f) => executeSend(f, false), h("div", {},
    canSend ? null : h("p", { class: "note err" }, "Encrypt the wallet on the Security page before sending."),
    h("p", { class: "muted" }, "Scan the payee's QR code, or type or paste the address."),
    scanner((text) => fill(text)), about),
    w !== "unlocked" && hostNodeSlots.length ? [
      (sendPasskeyBtn = h("button", {
        type: "button",
        class: "secondary",
        "data-testid": "node-send-passkey",
        onclick: async () => {
          sendPasskeyBtn.disabled = true;
          note(send._note, "Waiting for passkey…", true);
          try {
            const done = await executeSend(send, true);
            note(send._note, done, true);
          } catch (err) {
            note(send._note, err.message, false);
          } finally {
            sendPasskeyBtn.disabled = false;
          }
        },
      }, "Send with Passkey")),
    ] : []);

  function fill(text) {
    let req;
    try {
      req = PayUri.parse(text);
    } catch (err) {
      about.className = "note err";
      about.textContent = err.message;
      return;
    }
    request = req;
    send.elements.to.value = req.address;
    send.elements.amount.value = req.amount || "";
    send.elements.note.value = req.memo || req.message || "";
    const lines = [];
    if (req.label) lines.push("Request from " + req.label + ".");
    if (req.message && req.memo) lines.push("For: " + req.message + ".");
    if (req.memo) lines.push("It asks for a memo on the chain; this wallet keeps it as a note in its own history instead.");
    lines.push("Check the details, then send.");
    about.className = "muted";
    about.textContent = lines.join(" ");
    send.elements.amount.focus();
  }
  send.elements.to.addEventListener("change", () => {
    if (/^divi:/i.test(send.elements.to.value.trim())) fill(send.elements.to.value);
  });

  const [history, received, unspent] = await Promise.all([
    rpc("listtransactions", "*", 50, 0, true).catch((e) => e),
    rpc("listreceivedbyaddress", 0, true).catch((e) => e),
    rpc("listunspent", 0).catch((e) => e),
  ]);
  const when = (t) => (t ? new Date(t * 1000).toLocaleString() : "—");
  const failed = (r) => (r instanceof Error ? h("p", { class: "note err" }, r.message) : null);

  const historyCard = h("div", { class: "card", "data-testid": "node-wallet-history" }, h("h3", {}, "Recent transactions"),
    failed(history) || (history.length
      ? table("node-wallet-history-table", ["Time", "Category", "Amount", "Confirmations", "Address", "Transaction"],
        [...history].reverse().map((t) => [when(t.time || t.timereceived), t.category, String(t.amount) + " DIVI",
          String(t.confirmations ?? "—"), t.address ? addrLink(t.address) : "—", txLink(t.txid, shortId(t.txid))]))
      : h("p", { class: "muted" }, "No transactions yet.")));

  const addressesCard = h("details", { class: "card drawer", "data-testid": "node-wallet-addresses" },
    h("summary", {}, "Addresses" + (Array.isArray(received) ? " (" + received.length + ")" : "")),
    h("div", { class: "drawer-body" }, failed(received) || (received.length
      ? table("node-wallet-addresses-table", ["Address", "Label", "Received", "Confirmations"],
        received.map((r) => [addrLink(r.address), r.label || r.account || "", String(r.amount) + " DIVI", String(r.confirmations ?? "—")]))
      : h("p", { class: "muted" }, "No addresses yet."))));

  const utxoCard = h("details", { class: "card drawer", "data-testid": "node-wallet-utxos" },
    h("summary", {}, "Unspent coins" + (Array.isArray(unspent) ? " (" + unspent.length + ")" : "")),
    h("div", { class: "drawer-body" }, failed(unspent) || (unspent.length
      ? table("node-wallet-utxos-table", ["Coin", "Address", "Amount", "Confirmations"],
        unspent.map((u) => [h("span", {}, txLink(u.txid, shortId(u.txid)), ":" + u.vout), addrLink(u.address), String(u.amount) + " DIVI", String(u.confirmations)]))
      : h("p", { class: "muted" }, "No unspent coins."))));

  // Sign & verify a message
  const sigOut = h("textarea", { class: "sig", rows: 3, readonly: true, "data-testid": "node-signature-output" });
  const addrChoices = Array.isArray(received) ? received.map((r) => r.address) : [];
  const signCard = signingForm("Sign a message", [
    h("label", { class: "field" }, h("span", {}, "Address"),
      h("input", { name: "address", list: "node-sign-addrs", spellcheck: "false", autocomplete: "off", value: addrChoices[0] || "" }),
      h("datalist", { id: "node-sign-addrs" }, addrChoices.map((a) => h("option", { value: a })))),
    h("label", { class: "field" }, h("span", {}, "Message"), h("textarea", { name: "message", rows: 3 })),
  ], "Sign", async (f) => {
    const address = val(f, "address").trim();
    const message = f.elements.message.value;
    if (!address) throw new Error("enter an address of this wallet");
    const sig = await rpc("signmessage", address, message);
    sigOut.value = sig;
    return "Signed.";
  }, h("p", { class: "muted" }, "Proves you hold an address: anyone can check the signature with verifymessage."),
  "Sign with Passkey", "node-sign-passkey");
  signCard.setAttribute("data-testid", "node-sign-message-card");
  signCard.append(h("label", { class: "field" }, h("span", {}, "Signature"), sigOut));

  const verifyCard = form("Verify a message", [
    field("Address", "address", "text", { spellcheck: "false" }),
    field("Signature", "signature", "text", { spellcheck: "false" }),
    h("label", { class: "field" }, h("span", {}, "Message"), h("textarea", { name: "message", rows: 3 })),
  ], "Verify", async (f) => {
    const ok = await rpc("verifymessage", val(f, "address").trim(), val(f, "signature").trim(), f.elements.message.value);
    if (!ok) throw new Error("The signature does not match that address and message.");
    return "Valid: the address signed this message.";
  });
  verifyCard.setAttribute("data-testid", "node-verify-message-card");

  const backupMsg = h("p", { class: "note" });
  const backupBtn = h("button", {
    type: "button",
    "data-testid": "node-backup-wallet-btn",
    onclick: async () => {
      backupBtn.disabled = true;
      note(backupMsg, "Backing up…", true);
      try {
        const r = await post("/api/node-wallet/backup", {});
        note(backupMsg, "Saved " + r.path + " in the node's data directory (owner-only).", true);
      } catch (err) {
        note(backupMsg, err.message, false);
      } finally {
        backupBtn.disabled = false;
      }
    },
  }, "Back up wallet.dat");
  const backupCard = h("div", { class: "card", "data-testid": "node-backup-card" }, h("h3", {}, "Back up"),
    h("p", { class: "muted" }, "Writes a consistent copy of wallet.dat to backups/ in the node's data directory, readable only by the node's user. Copy it somewhere safe and offline."),
    h("div", { class: "row" }, backupBtn), backupMsg);

  show(h("section", {}, localhostPasskeyHint(), h("h2", {}, "Wallet"),
    h("div", { class: "card" }, kv([["Balance", typeof balance === "number" ? balance + " DIVI" : balance],
      ["Encryption", walletLabel(w)]]), h("p", {}, h("a", { href: "#/staking" }, "Staking"), " · ", h("a", { href: "#/vaults" }, "Vaults"))),
    h("div", { class: "grid" }, receive, send),
    historyCard, addressesCard, utxoCard,
    h("div", { class: "grid" }, signCard, verifyCard),
    backupCard));
}

// --- staking -----------------------------------------------------------------

async function stakingView() {
  await refresh();
  const w = state.wallet;
  const [status, winfo, threshold, txs] = await Promise.all([
    rpc("getstakingstatus").catch((e) => ({ error: e.message })),
    rpc("getwalletinfo").catch((e) => ({ error: e.message })),
    rpc("getstakesplitthreshold").catch((e) => ({ error: e.message })),
    rpc("listtransactions", "*", 500, 0, true).catch(() => []),
  ]);
  const parts = [localhostPasskeyHint(), h("h2", {}, "Staking")];
  if (flash) {
    parts.push(h("p", { class: "note ok" }, flash));
    flash = null;
  }
  const statusCard = h("div", { class: "card", "data-testid": "staking-status" }, h("h3", {}, "Status"),
    status.error ? h("p", { class: "note err" }, status.error)
      : kv(Object.entries(status).map(([k, v]) => [k, typeof v === "object" ? JSON.stringify(v) : v])));
  const walletCard = h("div", { class: "card" }, h("h3", {}, "Wallet"), kv([
    ["Encryption", walletLabel(w)],
    ["Balance", winfo.balance !== undefined ? winfo.balance + " DIVI" : winfo.error],
    ["Immature", winfo.immature_balance], ["Unconfirmed", winfo.unconfirmed_balance],
    ["Unlocked until", winfo.unlocked_until ? new Date(winfo.unlocked_until * 1000).toLocaleString() : undefined],
    ["Stake split threshold", threshold && threshold.error ? threshold.error : threshold + " DIVI"],
  ]));
  parts.push(h("div", { class: "grid" }, statusCard, walletCard));

  if (w && w !== "unencrypted") {
    if (w === "locked") parts.push(unlockForStakingForm(stakingView));
    else {
      parts.push(form("Lock the wallet", [], "Lock", async () => {
        await rpc("walletlock");
        flash = "Locked: the wallet no longer stakes.";
        stakingView();
      }, h("p", { class: "muted" }, "Staking needs the wallet unlocked (for staking only is enough).")));
    }
  } else if (w === "unencrypted") {
    parts.push(h("p", { class: "note err" }, "Encrypt the wallet on the Security page first; this interface only reads until then."));
  }

  const toggleMsg = h("p", { class: "note" });
  const setStaking = (on) => async () => {
    try {
      await rpc("setstaking", on);
      flash = on ? "Staking enabled." : "Staking disabled.";
      stakingView();
    } catch (err) {
      note(toggleMsg, err.message, false);
    }
  };
  parts.push(h("div", { class: "card", "data-testid": "staking-toggle" }, h("h3", {}, "Staker"),
    h("p", { class: "muted" }, "Switch this node's staker on or off for this run (the setting staking=0/1 decides it at start-up)."),
    h("div", { class: "row wrap" },
      h("button", { type: "button", "data-testid": "staking-enable", onclick: setStaking(true) }, "Enable staking"),
      h("button", { type: "button", class: "secondary", "data-testid": "staking-disable", onclick: setStaking(false) }, "Disable staking")),
    toggleMsg));

  const locked = (m) => /unlock|locked|passphrase/i.test(m || "");
  const slots = hostNodeSlots();
  let splitPkBtn = null;
  const applySplit = async (f, viaPasskey) => {
    const v = val(f, "threshold").trim();
    if (!/^\d+$/.test(v)) throw new Error("enter a whole number of DIVI");
    try {
      if (viaPasskey) throw new Error("locked");
      await rpc("setstakesplitthreshold", Number(v));
      return "The stake split threshold is " + v + " DIVI for this run.";
    } catch (err) {
      if (!locked(err.message)) throw err;
      return withNodeUnlocked(f.elements.p ? f.elements.p.value : "", viaPasskey, async () => {
        await rpc("setstakesplitthreshold", Number(v));
        return "The stake split threshold is " + v + " DIVI for this run.";
      });
    }
  };
  const split = form("Stake split threshold", [
    field("Threshold in whole DIVI", "threshold", "number", { min: 0, step: 1, value: typeof threshold === "number" ? threshold : "" }),
    w && w !== "unlocked" && w !== "unencrypted" ? field("Wallet passphrase (only if the node asks for it)", "p", "password", { autocomplete: "current-password" }) : null,
  ], "Set threshold", (f) => applySplit(f, false),
  h("p", { class: "muted" }, "A stake whose value plus reward exceeds it is paid back as two outputs; smaller coins of the same address are combined up to half of it."),
  w && w !== "unlocked" && w !== "unencrypted" && slots.length ? [
    (splitPkBtn = h("button", {
      type: "button", class: "secondary", "data-testid": "staking-split-passkey",
      onclick: async () => {
        splitPkBtn.disabled = true;
        note(split._note, "Waiting for passkey…", true);
        try { note(split._note, await applySplit(split, true), true); } catch (err) { note(split._note, err.message, false); }
        finally { splitPkBtn.disabled = false; }
      },
    }, "Set with Passkey")),
  ] : []);
  split.setAttribute("data-testid", "staking-split-form");
  parts.push(split);

  const rewards = (Array.isArray(txs) ? txs : []).filter((t) => t.category === "stake" || t.category === "generate" || t.category === "immature")
    .reverse().slice(0, 50);
  parts.push(h("div", { class: "card", "data-testid": "staking-rewards" }, h("h3", {}, "Recent stake rewards"),
    rewards.length ? table("staking-rewards-table", ["Time", "Kind", "Amount", "Confirmations", "Transaction"],
      rewards.map((t) => [t.time ? new Date(t.time * 1000).toLocaleString() : "—", t.category, String(t.amount) + " DIVI",
        String(t.confirmations ?? "—"), txLink(t.txid, shortId(t.txid))]))
      : h("p", { class: "muted" }, "No stake rewards in the last 500 wallet transactions.")));

  show(h("section", { "data-testid": "staking-view" }, parts));
}

// --- vaults ------------------------------------------------------------------

async function vaultsView() {
  await refresh();
  const w = state.wallet;
  if (w === null || w === undefined) {
    return show(h("section", { "data-testid": "vaults-view" }, h("h2", {}, "Vaults"), h("p", { class: "muted" }, "The daemon has no wallet loaded.")));
  }
  const avail = await rpc("getcoinavailability", true).catch((e) => ({ error: e.message }));
  const done = (what) => { setTimeout(vaultsView, 1200); return what; };
  const amount = (f) => {
    const a = val(f, "amount").trim();
    if (!/^\d+(\.\d{1,8})?$/.test(a)) throw new Error("enter the amount in DIVI");
    return Number(a);
  };

  const fund = signingForm("Fund a vault", [
    field("Vault: manager address, or owner:manager", "target", "text", { spellcheck: "false", placeholder: "owner:manager or manager" }),
    field("Amount in DIVI", "amount", "text", { inputmode: "decimal" }),
  ], "Fund vault", async (f) => {
    const target = val(f, "target").trim();
    if (!target) throw new Error("enter the vault's manager address (and owner, if not a new one of yours)");
    const r = await rpc("fundvault", target, amount(f));
    return done("Funded. " + (r && r.txhash ? "Transaction " + r.txhash + "." : JSON.stringify(r)));
  }, h("p", { class: "muted" }, "Sends coins to a vault script: the manager (a staking service) can stake them but never spend them; you, the owner, can reclaim them."),
  "Fund with Passkey", "vault-fund-passkey");

  const add = signingForm("Add a managed vault", [
    field("Vault (owner:manager)", "vault", "text", { spellcheck: "false" }),
    field("Funding transaction id", "txid", "text", { spellcheck: "false" }),
  ], "Add vault", async (f) => {
    const r = await rpc("addvault", val(f, "vault").trim(), val(f, "txid").trim());
    return done("Added: " + JSON.stringify(r));
  }, h("p", { class: "muted" }, "For a manager: start staking a vault an owner funded (needs -vault mode)."),
  "Add with Passkey", "vault-add-passkey");

  const remove = signingForm("Remove a managed vault", [
    field("Vault (owner:manager)", "vault", "text", { spellcheck: "false" }),
  ], "Remove vault", async (f) => {
    const r = await rpc("removevault", val(f, "vault").trim());
    return done("Removed: " + JSON.stringify(r));
  }, null, "Remove with Passkey", "vault-remove-passkey");

  const debit = signingForm("Debit a vault by name", [
    field("Source vault (owner:manager)", "source", "text", { spellcheck: "false" }),
    field("Destination address", "dest", "text", { spellcheck: "false" }),
    field("Amount in DIVI", "amount", "text", { inputmode: "decimal" }),
  ], "Debit vault", async (f) => {
    if (!confirm("Move " + val(f, "amount") + " DIVI out of " + val(f, "source") + "?")) return "Not sent.";
    const r = await rpc("debitvaultbyname", val(f, "source").trim(), val(f, "dest").trim(), amount(f));
    return done("Sent. " + JSON.stringify(r));
  }, h("p", { class: "muted" }, "For an owner: pay out of one vault to an address."),
  "Debit with Passkey", "vault-debit-passkey");

  const reclaim = signingForm("Reclaim vault funds", [
    field("Destination address", "dest", "text", { spellcheck: "false" }),
    field("Amount in DIVI", "amount", "text", { inputmode: "decimal" }),
  ], "Reclaim", async (f) => {
    if (!confirm("Reclaim " + val(f, "amount") + " DIVI from your vaults to " + val(f, "dest") + "?")) return "Not sent.";
    const r = await rpc("reclaimvaultfunds", val(f, "dest").trim(), amount(f));
    return done("Reclaimed. " + JSON.stringify(r));
  }, h("p", { class: "muted" }, "For an owner: take coins back out of your vaults."),
  "Reclaim with Passkey", "vault-reclaim-passkey");

  show(h("section", { "data-testid": "vaults-view" }, localhostPasskeyHint(), h("h2", {}, "Vaults"),
    h("p", { class: "muted" }, "Vaults let a staking service (the manager) stake your coins without being able to spend them."),
    w === "unencrypted" ? h("p", { class: "note err" }, "Encrypt the wallet on the Security page before using vaults.") : null,
    h("div", { class: "card", "data-testid": "vaults-availability" }, h("h3", {}, "Coin availability"),
      avail.error ? h("p", { class: "note err" }, avail.error) : jsonView(avail, "vaults-availability-view")),
    h("div", { class: "grid" }, fund, reclaim),
    h("div", { class: "grid" }, add, remove, debit)));
}

// --- swaps -------------------------------------------------------------------

async function swapsView() {
  const s = await getJson("/api/swaps/status").catch((e) => ({ error: e.message, online: false, pairs: [] }));
  const pairs = h("div", { class: "row wrap" }, (s.pairs || []).map((p) => h("span", { class: "badge" }, "DIVI ↔ " + p)));
  const parts = [h("h2", {}, "Swaps"),
    h("div", { class: "card", "data-testid": "swaps-status" }, h("h3", {}, "Local divi-swapd ",
      h("span", { class: "badge " + (s.online ? "ok" : "err"), "data-testid": "swaps-online" }, s.online ? "running" : "offline")),
    s.error ? h("p", { class: "note err" }, s.error) : null,
    kv([["Endpoint", s.endpoint || (s.probed_ports ? "probed 127.0.0.1:" + s.probed_ports.join(", :") : undefined)]]),
    s.online && s.health ? jsonView(s.health, "swaps-health") : null,
    h("h4", {}, "Supported pairs"), pairs)];
  if (s.online) {
    parts.push(h("div", { class: "card", "data-testid": "swaps-offers" }, h("h3", {}, "Offers"), jsonView(s.offers, "swaps-offers-table")));
    parts.push(h("div", { class: "card", "data-testid": "swaps-active" }, h("h3", {}, "Swaps"),
      s.operator_token_required ? h("p", { class: "muted" }, "Listing swaps needs divi-swapd's operator token; use divi-swap on the command line.") : null,
      jsonView(s.swaps, "swaps-active-table")));
  } else {
    parts.push(h("div", { class: "card", "data-testid": "swaps-offline" }, h("h3", {}, "Start divi-swapd"),
      h("p", {}, "Atomic swaps run in a separate daemon, divi-swapd, beside this node. Start it on this machine, listening on loopback:"),
      h("pre", { class: "out" }, "divi-swapd --config ~/.divi-swapd/swapd.toml\n# swapd.toml: listen = \"127.0.0.1:18480\", plus the node's RPC and the other chain's wallet"),
      h("p", { class: "muted" }, "Then reload this page: it shows the daemon's health, its public offers and your swaps. Use divi-swap (the client) to take an offer.")));
  }
  show(h("section", { "data-testid": "swaps-view" }, parts));
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

async function logsView() {
  const first = await getJson("/api/logs?after=0");
  let next = 0;
  const msg = h("p", { class: "note" });
  const tail = h("pre", { class: "out logs" });
  const follow = h("input", { type: "checkbox", checked: true });
  const stats = h("div", { class: "grid" });
  const env = first.state.env_override;

  const level = h("select", { disabled: env }, first.levels.map((l) => h("option", { value: l }, l)));
  level.value = first.state.level;
  const all = first.state.categories.includes("all");
  const boxes = first.categories.map((c) => {
    const b = h("input", { type: "checkbox", value: c, disabled: env });
    b.checked = all || first.state.categories.includes(c);
    return b;
  });

  async function apply(categories) {
    try {
      const r = await post("/api/logs", { level: level.value, categories: categories ?? boxes.filter((b) => b.checked).map((b) => b.value) });
      const cats = r.state.categories;
      boxes.forEach((b) => { b.checked = cats.includes("all") || cats.includes(b.value); });
      note(msg, "Now logging at " + r.state.level + ", debug: " + (cats.length ? cats.join(", ") : "none") +
        ". This lasts until the daemon restarts; set debug and loglevel on the Settings page to keep it.", true);
    } catch (err) {
      note(msg, err.message, false);
    }
  }
  level.addEventListener("change", () => apply());
  boxes.forEach((b) => b.addEventListener("change", () => apply()));

  function add(lines) {
    const atEnd = tail.scrollTop + tail.clientHeight >= tail.scrollHeight - 4;
    for (const l of lines) {
      const t = new Date(l.time).toISOString().slice(11, 23);
      tail.append(h("span", { class: "lvl-" + l.level.toLowerCase() }, t + " " + l.level.padEnd(5) + " " + l.target + ": " + l.message + "\n"));
    }
    while (tail.childNodes.length > 2000) tail.firstChild.remove();
    if (follow.checked || atEnd) tail.scrollTop = tail.scrollHeight;
  }

  async function loadStats() {
    const [info, net, mem, up] = await Promise.all([
      rpc("getinfo").catch(() => ({})), rpc("getnettotals").catch(() => ({})),
      rpc("getmempoolinfo").catch(() => ({})), rpc("uptime").catch(() => null),
    ]);
    const mb = (n) => n === undefined ? undefined : (n / 1048576).toFixed(1) + " MB";
    stats.replaceChildren(
      h("div", { class: "card" }, h("h3", {}, "Node"), kv([
        ["Blocks", info.blocks], ["Connections", info.connections],
        ["Up", up === null ? undefined : Math.floor(up / 3600) + " h " + Math.floor(up % 3600 / 60) + " min"]])),
      h("div", { class: "card" }, h("h3", {}, "Network"), kv([
        ["Received", mb(net.totalbytesrecv)], ["Sent", mb(net.totalbytessent)]])),
      h("div", { class: "card" }, h("h3", {}, "Mempool"), kv([
        ["Transactions", mem.size], ["Size", mb(mem.bytes)]])));
  }

  let ticks = 0;
  async function poll() {
    if (!document.body.contains(tail)) return;
    try {
      const r = await getJson("/api/logs?after=" + next);
      add(r.lines);
      next = r.next;
      if (ticks++ % 5 === 0) await loadStats();
    } catch (err) {
      note(msg, err.message, false);
    }
    logTimer = setTimeout(poll, 2000);
  }

  show(h("section", {},
    h("h2", {}, "Logs"),
    stats,
    h("div", { class: "card" },
      h("h3", {}, "What is logged"),
      env ? h("p", { class: "note err" }, "RUST_LOG was set when the daemon started; it decides what is logged until a restart without it.") : null,
      h("div", { class: "row wrap" }, h("label", {}, "Level ", level),
        h("button", { type: "button", disabled: env, onclick: () => apply(["all"]) }, "All debug"),
        h("button", { type: "button", disabled: env, onclick: () => apply([]) }, "No debug")),
      h("p", { class: "muted small" }, "Debug categories: each one logs its part of the node at debug level."),
      h("div", { class: "row wrap" }, boxes.map((b) => h("label", { class: "check" }, b, " " + b.value))),
      msg),
    h("div", { class: "row wrap" }, h("label", { class: "check" }, follow, " Follow the newest line"),
      h("span", { class: "muted small" }, "The last 2000 lines the daemon logged, newest at the bottom.")),
    tail));
  add(first.lines);
  next = first.next;
  await loadStats();
  ticks = 1;
  logTimer = setTimeout(poll, 2000);
}

// --- start ---------------------------------------------------------------------

document.getElementById("logout").addEventListener("click", async () => {
  await post("/api/logout").catch(() => {});
  await refresh();
  route();
});
window.addEventListener("hashchange", route);
refresh().then(route);
