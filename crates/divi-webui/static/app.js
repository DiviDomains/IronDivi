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
  "wallet": walletView,
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

/// Ways to read a QR code into `onText`: a picture (a phone's camera works
/// even over plain HTTP), the live camera or the screen (both need HTTPS or
/// localhost), or a screenshot pasted from the clipboard
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
    return show(h("section", {}, h("h2", {}, "Wallet"), h("p", { class: "muted" }, "The daemon has no wallet loaded.")));
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
  let request = {};
  const about = h("p", { class: "muted" });
  const send = form("Pay", [
    field("Pay to: an address or a divi: link", "to", "text", { spellcheck: "false", placeholder: "D…" }),
    field("Amount in DIVI", "amount", "text", { inputmode: "decimal" }),
    field("Note for your records (optional)", "note"),
    w === "unlocked" ? null : field("Wallet passphrase", "p", "password", { autocomplete: "current-password" }),
  ], "Send", async (f) => {
    if (!canSend) throw new Error("encrypt the wallet on the Security page before sending");
    const address = val(f, "to").trim();
    const amount = val(f, "amount").trim();
    if (!amount) throw new Error("enter the amount");
    PayUri.build({ address, amount });
    const v = await rpc("validateaddress", address);
    if (!v.isvalid) throw new Error("that is not a valid address on " + (state.network || "this network"));
    const before = state.wallet;
    const p = f.elements.p ? f.elements.p.value : "";
    if (before !== "unlocked" && !p) throw new Error("enter the wallet passphrase");
    if (!confirm("Send " + amount + " DIVI to " + address + "?")) return "Not sent.";
    if (before !== "unlocked") await rpc("walletpassphrase", p, 60, false);
    let txid;
    let restore = null;
    try {
      const comment = val(f, "note").trim();
      const to = (request.address === address && request.label) || "";
      txid = comment || to
        ? await rpc("sendtoaddress", address, Number(amount), "metadata", comment, to)
        : await rpc("sendtoaddress", address, Number(amount));
    } finally {
      // put the wallet back the way it was: staking only, or locked
      const back = before === "unlocked-for-staking" ? rpc("walletpassphrase", p, 0, true)
        : before === "locked" ? rpc("walletlock") : null;
      if (back) restore = await back.then(() => null, (e) => e.message);
      await refresh();
    }
    f.elements.to.value = f.elements.amount.value = f.elements.note.value = "";
    request = {};
    about.textContent = "";
    return "Sent. Transaction " + txid + (restore
      ? ". The wallet could not go back to " + walletLabel(before).toLowerCase() + ": " + restore : ".");
  }, h("div", {},
    canSend ? null : h("p", { class: "note err" }, "Encrypt the wallet on the Security page before sending."),
    h("p", { class: "muted" }, "Scan the payee's QR code, or type or paste the address."),
    scanner((text) => fill(text)), about));

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

  show(h("section", {}, h("h2", {}, "Wallet"),
    h("div", { class: "card" }, kv([["Balance", typeof balance === "number" ? balance + " DIVI" : balance],
      ["Encryption", walletLabel(w)]])),
    h("div", { class: "grid" }, receive, send)));
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
