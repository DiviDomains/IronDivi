// SPDX-License-Identifier: AGPL-3.0-only
// The payment request format of static/pay.js. Run: node --test crates/divi-webui/tests/pay_uri.test.js
"use strict";

const test = require("node:test");
const assert = require("node:assert");
const PayUri = require("../static/pay.js");

const A = "DLhCbGkNnsoeRfiHzSdzr2gnnFRhv3BXpp";

test("builds and parses back", () => {
  const req = { address: A, amount: "12.50000000", label: "Café & co", message: "rent", memo: "inv #7" };
  const uri = PayUri.build(req);
  assert.strictEqual(uri, "divi:" + A + "?amount=12.5&label=Caf%C3%A9%20%26%20co&message=rent&memo=inv%20%237");
  assert.deepStrictEqual(PayUri.parse(uri), { address: A, amount: "12.5", label: "Café & co", message: "rent", memo: "inv #7" });
});

test("leaves out empty parameters", () => {
  assert.strictEqual(PayUri.build({ address: A, amount: "", memo: " " }), "divi:" + A);
});

test("accepts a bare address, DIVI: in capitals and divi://", () => {
  assert.deepStrictEqual(PayUri.parse("  " + A + "\n"), { address: A });
  assert.deepStrictEqual(PayUri.parse("DIVI:" + A + "?AMOUNT=1"), { address: A, amount: "1" });
  assert.deepStrictEqual(PayUri.parse("divi://" + A), { address: A });
});

test("ignores unknown parameters but refuses required ones", () => {
  assert.deepStrictEqual(PayUri.parse("divi:" + A + "?foo=bar"), { address: A });
  assert.throws(() => PayUri.parse("divi:" + A + "?req-expires=1"), /req-expires/);
});

test("refuses bad amounts, addresses, duplicates and encodings", () => {
  for (const bad of ["1.123456789", "-1", "0", "1e5", "1,5", "abc"]) {
    assert.throws(() => PayUri.parse("divi:" + A + "?amount=" + bad), /amount/, bad);
    assert.throws(() => PayUri.build({ address: A, amount: bad }), /amount/, bad);
  }
  assert.throws(() => PayUri.parse("divi:0OIl" + A.slice(4)), /address/);
  assert.throws(() => PayUri.parse("bitcoin:" + A), /not a Divi/);
  assert.throws(() => PayUri.parse("divi:" + A + "?amount=1&amount=2"), /twice/);
  assert.throws(() => PayUri.parse("divi:" + A + "?label=%E0%A4%A"), /badly encoded/);
});

test("caps the memo at 512 bytes", () => {
  assert.ok(PayUri.parse("divi:" + A + "?memo=" + "x".repeat(512)));
  assert.throws(() => PayUri.parse("divi:" + A + "?memo=" + "x".repeat(513)), /512/);
  assert.throws(() => PayUri.build({ address: A, memo: "é".repeat(257) }), /512/);
});
