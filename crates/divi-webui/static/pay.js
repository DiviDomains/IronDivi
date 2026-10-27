// SPDX-License-Identifier: AGPL-3.0-only
// Payment requests as text and QR codes, the same format the IronDivi
// browser extension reads and writes (BIP21 style):
//   divi:<address>?amount=<DIVI, up to 8 decimals>&label=&message=&memo=
// Every parameter is optional and percent-encoded. `memo` is what a paying
// wallet that can writes on the chain (an OP_META output, 512 bytes at most).
"use strict";

const PayUri = (() => {
  const ADDRESS = /^[1-9A-HJ-NP-Za-km-z]{25,40}$/;
  const AMOUNT = /^\d{1,11}(\.\d{1,8})?$/;
  const MEMO_MAX = 512;
  const TEXT = ["label", "message", "memo"];

  function checkAmount(a) {
    if (!AMOUNT.test(a) || Number(a) <= 0) throw new Error("the amount is not a DIVI amount: " + a);
    return a.replace(/(\.\d*?)0+$/, "$1").replace(/\.$/, "");
  }

  function checkMemo(m) {
    if (new TextEncoder().encode(m).length > MEMO_MAX) throw new Error("the memo is over " + MEMO_MAX + " bytes");
  }

  /// A divi: link for `req` = { address, amount?, label?, message?, memo? }
  function build(req) {
    const address = String(req.address || "").trim();
    if (!ADDRESS.test(address)) throw new Error("that is not an address");
    const q = [];
    const amount = String(req.amount ?? "").trim();
    if (amount) q.push("amount=" + checkAmount(amount));
    for (const k of TEXT) {
      const v = String(req[k] ?? "").trim();
      if (!v) continue;
      if (k === "memo") checkMemo(v);
      q.push(k + "=" + encodeURIComponent(v));
    }
    return "divi:" + address + (q.length ? "?" + q.join("&") : "");
  }

  /// The request in a scanned or pasted text: a divi: link or a bare address
  function parse(text) {
    const s = String(text || "").trim();
    if (ADDRESS.test(s)) return { address: s };
    if (!/^divi:/i.test(s)) throw new Error("this is not a Divi payment request");
    const body = s.slice(5).replace(/^\/\//, "");
    const at = body.indexOf("?");
    const address = at < 0 ? body : body.slice(0, at);
    if (!ADDRESS.test(address)) throw new Error("the request has no valid address");
    const req = { address };
    if (at < 0) return req;
    const seen = new Set();
    for (const pair of body.slice(at + 1).split("&")) {
      if (!pair) continue;
      const eq = pair.indexOf("=");
      const key = (eq < 0 ? pair : pair.slice(0, eq)).toLowerCase();
      let value;
      try {
        value = decodeURIComponent(eq < 0 ? "" : pair.slice(eq + 1));
      } catch (_) {
        throw new Error("the request is badly encoded at " + key);
      }
      if (seen.has(key)) throw new Error("the request gives " + key + " twice");
      seen.add(key);
      if (key === "amount") req.amount = checkAmount(value);
      else if (TEXT.includes(key)) {
        if (key === "memo") checkMemo(value);
        req[key] = value;
      } else if (key.startsWith("req-")) throw new Error("the request needs " + key + ", which this wallet does not support");
    }
    return req;
  }

  return { build, parse, MEMO_MAX };
})();

if (typeof module === "object") module.exports = PayUri;
