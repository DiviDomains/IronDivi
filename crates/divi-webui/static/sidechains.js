// SPDX-License-Identifier: AGPL-3.0-only
// IronDivi web interface: the sidechain market. The node serves it at
// /api/sidechains when irondivi-sidechains is built in; the page follows the
// market's GUI spec (GUI-API.md v1). Amounts are integer satoshis.
"use strict";

window.irondiviSidechains = async function (ui) {
  const { h, show, post, getJson, form, field, val, note, kv } = ui;
  const API = "/api/sidechains";
  const SAT = 100000000;
  const divi = (sat) => (Number(sat || 0) / SAT).toFixed(8).replace(/\.?0+$/, "") + " DIVI";
  const short = (a) => a && a.length > 12 ? a.slice(0, 6) + "…" + a.slice(-4) : a;
  const here = () => location.hash.replace(/^#\/?/, "").split("/")[0] === "sidechains";
  const go = () => window.irondiviSidechains(ui);
  const tabs = { available: "Available", installed: "Installed", updates: "Updates", earnings: "Earnings" };
  const tab = tabs[window.irondiviSidechainsTab] ? window.irondiviSidechainsTab : "available";

  async function put(path, body) {
    const res = await fetch(path, {
      method: "PUT",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": ui.state().csrf || "" },
      body: JSON.stringify(body || {}),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || res.statusText);
    return data;
  }

  // --- badges -----------------------------------------------------------------

  function compatBadge(c) {
    if (!c) return null;
    if (c.status === "ok") return h("span", { class: "badge ok" }, "Compatible");
    const cls = c.status === "blocked" ? "badge err" : "badge warn";
    return h("span", { class: cls, title: (c.reasons || []).join("\n") }, c.reasons[0] || c.status);
  }

  function costBadge(c) {
    if (!c) return null;
    if (c.bond_sat > 0) return h("span", { class: "badge warn", title: c.bond_note || "" }, "Bond " + divi(c.bond_sat) + " (locked)");
    if (c.install_fee_sat > 0) return h("span", { class: "badge" }, "Fee " + divi(c.install_fee_sat));
    return h("span", { class: "badge ok" }, "Free");
  }

  /// The short form of the earnings box, for a card
  function earningsBadge(e) {
    if (!e) return null;
    if (e.model === "none" || e.model === "fees") return h("span", { class: "badge" }, "Pays nothing");
    const o = e.observed;
    if (!o || !o.enough_history) return h("span", { class: "badge" }, "Not enough history yet");
    return h("span", { class: "badge", title: "Past results, not a promise." },
      "Past " + o.window_days + " days: " + divi(o.avg_per_recipient_per_epoch_sat) + " per validator per epoch");
  }

  // --- jobs -------------------------------------------------------------------

  /// Poll a job every second until it ends, reporting its step in `msg`
  async function follow(job, msg) {
    while (here()) {
      if (job.state === "done") {
        note(msg, job.action + " done.", true);
        setTimeout(() => here() && go(), 1200);
        return;
      }
      if (job.state === "failed") return note(msg, job.action + " failed: " + (job.error || job.step), false);
      note(msg, job.action + ": " + (job.step || job.state) + "…", true);
      await new Promise((r) => setTimeout(r, 1000));
      try {
        job = await getJson(API + "/jobs/" + encodeURIComponent(job.id));
      } catch (err) {
        return note(msg, err.message, false);
      }
    }
  }

  async function act(msg, path, body) {
    try {
      const job = await post(API + "/" + path, body || {});
      await follow(job, msg);
    } catch (err) {
      note(msg, err.message, false);
    }
  }

  // --- Available ----------------------------------------------------------------

  function drawer(l) {
    const r = l.latest;
    const links = Object.entries(l.links || {}).filter(([k]) => k !== "tx");
    const ext = (href, text) => h("a", { href, target: "_blank", rel: "noopener noreferrer" }, text);
    return h("details", { class: "drawer" }, h("summary", {}, "Details"),
      r ? h("div", {}, h("h4", {}, "What will run"),
        kv([["Version", r.version + " (" + r.channel + ", released " + r.released + ")"],
          ["Binary", r.run.binary], ["Arguments", r.run.args.join(" ") || "none"],
          ["Ports", r.run.ports.map((p) => p.name + " " + p.port + "/" + p.proto + (p.public ? " public" : " local")).join(", ") || "none"],
          ["Signed by", r.signed_by.map((s) => s.address + (s.delegation_epoch === null ? "" : " (delegation " + s.delegation_epoch + ")")).join(", ")]]))
        : null,
      kv([["Registration", ""], ["Root address", l.root_address], ["Registered at", l.registered_height]]),
      h("p", {}, l.links && l.links.tx ? ext(l.links.tx, l.registration_txid) : h("code", {}, l.registration_txid)),
      l.site ? h("p", {}, ext(l.site, l.site)) : null,
      links.length ? h("p", {}, links.map(([k, v]) => [ext(v, k), " "])) : null);
  }

  function listing(l) {
    const msg = h("p", { class: "note" });
    const blocked = l.compat && l.compat.status === "blocked";
    const install = l.manifest_error || l.installed ? null
      : h("button", { type: "button", disabled: blocked || (l.latest && !l.latest.platform_available),
        title: blocked ? l.compat.reasons.join("\n") : null,
        onclick: () => {
          if (l.cost && l.cost.bond_sat > 0 && !confirm("Installing " + l.name + " locks a bond of " + divi(l.cost.bond_sat) + ". " + (l.cost.bond_note || ""))) return;
          act(msg, encodeURIComponent(l.chain_id) + "/install", l.latest ? { sequence: l.latest.sequence } : {});
        } }, "Install");
    return h("div", { class: l.manifest_error ? "card grey" : "card" },
      h("h3", {}, l.name, l.installed ? h("span", { class: "muted" }, " · installed") : null),
      h("p", { class: "muted small" }, (l.operator && l.operator.name) || "Unknown operator", " · ", l.network, " · ",
        h("code", { title: l.root_address }, short(l.root_address))),
      l.manifest_error ? h("p", { class: "note err" }, l.manifest_error)
        : h("div", { class: "row wrap" }, compatBadge(l.compat), costBadge(l.cost), earningsBadge(l.earnings),
          l.resources ? h("span", { class: "badge" }, l.resources.disk_gb + " GB disk, " + l.resources.ram_mb + " MB RAM") : null,
          l.same_name_conflict ? h("span", { class: "badge warn" }, "Same name, different owner") : null),
      l.cost && l.cost.bond_sat > 0 && l.cost.bond_note ? h("p", { class: "muted small" }, l.cost.bond_note) : null,
      l.manifest_error ? null : drawer(l),
      install ? h("div", { class: "row" }, install) : null, msg);
  }

  // --- Installed ----------------------------------------------------------------

  const POLICIES = [["off", "Off"], ["notify", "Tell me (default)"], ["security", "Security fixes"],
    ["patch", "Patch releases"], ["minor", "Minor releases"], ["all", "Every release"]];

  function uptime(s) {
    if (s === null || s === undefined) return "—";
    const d = Math.floor(s / 86400), hr = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
    return (d ? d + "d " : "") + (d || hr ? hr + "h " : "") + m + "m";
  }

  function installedRow(i) {
    const msg = h("p", { class: "note" });
    const id = encodeURIComponent(i.chain_id);
    const pillCls = i.status === "running" ? "badge ok" : i.status === "crashed" || i.status === "failed" ? "badge err" : "badge warn";
    const control = (verb, label) => h("button", { type: "button", onclick: async () => {
      try {
        await post(API + "/" + id + "/" + verb, {});
        note(msg, label + " sent.", true);
        setTimeout(() => here() && go(), 1000);
      } catch (err) { note(msg, err.message, false); }
    } }, label);
    const policy = h("select", { name: "auto_update", onchange: async (e) => {
      try {
        await put(API + "/" + id + "/policy", { auto_update: e.target.value });
        note(msg, "Updates: " + e.target.selectedOptions[0].textContent + ".", true);
      } catch (err) { note(msg, err.message, false); }
    } }, POLICIES.map(([v, label]) => h("option", { value: v, selected: v === i.auto_update }, label)));
    const logBox = h("div");
    const logs = h("button", { type: "button", class: "link", onclick: async () => {
      if (logBox.childNodes.length) return logBox.replaceChildren();
      try {
        const r = await getJson(API + "/" + id + "/logs?tail=200");
        logBox.replaceChildren(h("pre", { class: "out logs" }, r.lines.join("\n").replace(/\x1b\[[0-9;]*m/g, "") || "No log lines."));
      } catch (err) { note(msg, err.message, false); }
    } }, "Logs");
    const remove = form("Uninstall", [
      h("label", { class: "field check" }, h("input", { type: "checkbox", name: "data" }), h("span", {}, "Also delete its data")),
    ], "Uninstall", async (f) => {
      const del = f.elements.data.checked;
      if (!confirm("Uninstall " + i.name + (del ? " and delete its data" : ", keeping its data") + "?")) return "Kept.";
      act(msg, id + "/uninstall", { delete_data: del });
      return "Uninstalling…";
    });
    remove.className = "drawer-body";
    return h("div", { class: "card" },
      h("h3", {}, i.name, " ", h("span", { class: pillCls }, i.status)),
      kv([["Version", i.version + " (sequence " + i.sequence + ")"], ["Uptime", uptime(i.uptime_secs)],
        ["Health", (i.health.ok ? "Healthy" : "Unhealthy") + (i.health.detail ? ": " + i.health.detail : "")],
        ["Ports", i.ports.map((p) => p.name + " " + p.port + "/" + p.proto).join(", ") || "none"],
        ["Disk", (i.disk_bytes / 1e9).toFixed(2) + " GB"], ["Restarts", i.restarts]]),
      h("label", { class: "field" }, h("span", {}, "Updates"), policy),
      h("div", { class: "row wrap" }, control("start", "Start"), control("stop", "Stop"), control("restart", "Restart"),
        i.previous_version ? h("button", { type: "button", onclick: () => {
          if (confirm("Roll " + i.name + " back to " + i.previous_version + "?")) act(msg, id + "/rollback", {});
        } }, "Roll back to " + i.previous_version) : null,
        logs),
      msg, logBox, h("details", { class: "drawer" }, h("summary", {}, "Uninstall"), remove));
  }

  // --- Updates ------------------------------------------------------------------

  function updateRow(u) {
    const msg = h("p", { class: "note" });
    return h("div", { class: "card" },
      h("h3", {}, u.name, " ", u.from_version, " → ", u.to.version),
      h("div", { class: "row wrap" }, h("span", { class: "badge" }, u.kind),
        u.to.security ? h("span", { class: "badge err" }, "Security") : null, compatBadge(u.compat)),
      u.to.notes ? h("p", {}, u.to.notes) : null,
      h("div", { class: "row" }, h("button", { type: "button", disabled: u.compat && u.compat.status === "blocked",
        onclick: () => act(msg, encodeURIComponent(u.chain_id) + "/update", { sequence: u.to.sequence }) }, "Update")),
      msg);
  }

  // --- Earnings -----------------------------------------------------------------

  function earningsRow(e, name) {
    const o = e.observed;
    const nothing = e.model === "none" || e.model === "fees";
    const observed = h("div", { class: "card" }, h("h4", {}, "Observed on the chain"),
      nothing ? h("p", {}, "This sidechain pays node runners nothing.")
        : !o || !o.enough_history ? h("p", {}, "Not enough history yet")
          : h("div", {},
            h("p", {}, "Past " + o.window_days + " days: average " + divi(o.avg_per_recipient_per_epoch_sat) +
              " per validator per epoch, " + o.recipients + " validators, " + o.epochs + " epochs."),
            o.apr_pct === null ? null : h("p", {}, "≈ " + o.apr_pct + "% a year at the minimum stake"),
            h("p", { class: "muted small" }, "As of block " + o.as_of_height + ".")),
      nothing ? null : h("p", { class: "muted" }, "Past results, not a promise."));
    return h("div", { class: "card" }, h("h3", {}, name),
      h("div", { class: "grid" }, observed,
        e.claimed ? h("div", { class: "card small" }, h("h4", {}, "Operator says"), h("p", { class: "muted" }, e.claimed)) : null),
      e.mine ? h("p", {}, "This wallet received " + divi(e.mine.received_sat) + " in the past " + e.mine.window_days + " days.") : null);
  }

  // --- the page -----------------------------------------------------------------

  const body = h("div", {}, h("p", { class: "muted" }, "Loading…"));
  show(h("section", {}, h("h2", {}, "Sidechains"),
    h("div", { class: "tabs" }, Object.entries(tabs).map(([key, label]) =>
      h("button", { type: "button", class: key === tab ? "on" : null,
        onclick: () => { window.irondiviSidechainsTab = key; go(); } }, label))),
    body));

  let list;
  try {
    list = await getJson(API + "/" + tab);
  } catch (err) {
    return body.replaceChildren(h("p", { class: "note err" }, err.message));
  }
  if (tab === "available") {
    body.replaceChildren(list.length ? h("div", { class: "grid" }, list.map(listing))
      : h("p", { class: "muted" }, "No sidechains are registered yet."));
  } else if (tab === "installed") {
    body.replaceChildren(list.length ? h("div", {}, list.map(installedRow))
      : h("p", { class: "muted" }, "No sidechains are installed. Pick one under Available."));
  } else if (tab === "updates") {
    body.replaceChildren(list.length ? h("div", {}, list.map(updateRow))
      : h("p", { class: "muted" }, "Everything installed is up to date."));
  } else {
    // Earnings carry only the chain id; the names come from the listings
    const names = {};
    await getJson(API + "/available").then((ls) => ls.forEach((l) => (names[l.chain_id] = l.name))).catch(() => {});
    body.replaceChildren(list.length ? h("div", {}, list.map((e) => earningsRow(e, names[e.chain_id] || e.chain_id)))
      : h("p", { class: "muted" }, "No sidechains to show earnings for."));
  }
};
