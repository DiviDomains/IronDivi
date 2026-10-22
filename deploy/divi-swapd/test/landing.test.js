// Run: node --test deploy/divi-swapd/test/
const test = require('node:test');
const assert = require('node:assert');
const L = require('../www/landing.js');

// Tiny DOM: only textContent / appendChild / createTextNode, and no innerHTML so any use throws.
function fakeDoc() {
  function node(tag) {
    const n = { tag, children: [], attrs: {}, _t: '' };
    Object.defineProperty(n, 'textContent', {
      get() { return n._t + n.children.map((c) => c.textContent).join(''); },
      set(v) { n._t = String(v); n.children = []; },
    });
    Object.defineProperty(n, 'innerHTML', { set() { throw new Error('innerHTML used'); } });
    n.appendChild = (c) => { n.children.push(c); return c; };
    n.setAttribute = (k, v) => { n.attrs[k] = v; };
    return n;
  }
  return { createElement: node, createTextNode: (t) => { const n = node('#text'); n._t = t; return n; } };
}
const walk = (n, f) => { f(n); n.children.forEach((c) => walk(c, f)); };

test('coins formats without float error', () => {
  assert.strictEqual(L.coins(300000000000000), '3000000');
  assert.strictEqual(L.coins(5000), '0.00005');
  assert.strictEqual(L.coins(190000), '0.0019');
  assert.strictEqual(L.coins(-1), '?');
  assert.strictEqual(L.coins('1'), '?');
});

test('health: ready', () => {
  const d = L.describeHealth({ ok: true, divi_scan: { state: 'done', next_height: 5, target_height: 5 } });
  assert.strictEqual(d.state, 'ready');
});

test('health: catching up shows progress', () => {
  const d = L.describeHealth({ ok: false, divi_scan: { state: 'scanning', next_height: 355190, target_height: 361301 } });
  assert.strictEqual(d.state, 'catching_up');
  assert.match(d.detail, /355190 of 361301 \(98%\)/);
});

test('health: unreachable on null / junk', () => {
  assert.strictEqual(L.describeHealth(null).state, 'unreachable');
  assert.strictEqual(L.describeHealth('x').state, 'unreachable');
});

test('health: degraded names the failing chains', () => {
  const d = L.describeHealth({ ok: false, divi: { error: 'e' }, btc: { tip: 1 }, counters: { ltc: { error: 'e' } }, divi_scan: { state: 'done' } });
  assert.strictEqual(d.state, 'degraded');
  assert.match(d.detail, /DIVI, LTC/);
});

test('offers: both directions, real shape', () => {
  const rows = L.describeOffers([
    { id: 'divi-btc-testnet', direction: 'taker_pays_btc', counter_chain: 'btc', divi_sats_per_btc: 300000000000000, min_btc_sats: 5000, max_btc_sats: 50000 },
    { id: 'ltc-divi-testnet', direction: 'taker_pays_divi', counter_chain: 'ltc', divi_sats_per_btc: 1000000000000, min_btc_sats: 100000, max_btc_sats: 190000 },
  ]);
  assert.strictEqual(rows[0].you, 'You pay BTC, get DIVI');
  assert.strictEqual(rows[0].price, '3000000 DIVI per 1 BTC');
  assert.strictEqual(rows[1].you, 'You pay DIVI, get LTC');
  assert.strictEqual(rows[1].max, '0.0019 LTC');
});

test('offers: empty list says no offers', () => {
  const doc = fakeDoc(); const el = doc.createElement('div');
  L.renderOffers(doc, el, []);
  assert.strictEqual(el.textContent, 'No offers right now.');
});

test('offers: hostile strings render as text, never markup', () => {
  const doc = fakeDoc(); const el = doc.createElement('div');
  const evil = '<script>alert(1)</script><img src=x onerror=alert(1)>';
  L.renderOffers(doc, el, [{ id: evil, direction: evil, counter_chain: evil, divi_sats_per_btc: evil, min_btc_sats: {}, max_btc_sats: null }]);
  assert.ok(el.textContent.includes(evil));
  const tags = []; walk(el, (n) => tags.push(n.tag));
  assert.deepStrictEqual([...new Set(tags)].sort(), ['div', 'table', 'td', 'th', 'tr']);
});

test('offers: non-array and junk entries do not throw', () => {
  assert.deepStrictEqual(L.describeOffers({}), []);
  assert.strictEqual(L.describeOffers([null, 5, 'x']).length, 3);
});

test('health render: hostile fields cannot inject', () => {
  const doc = fakeDoc(); const el = doc.createElement('div');
  L.renderHealth(doc, el, { ok: false, divi: { error: '<b>x</b>' }, btc: {}, counters: { '<i>': { error: 'x' } }, divi_scan: { state: 'done' } });
  const tags = []; walk(el, (n) => tags.push(n.tag));
  assert.ok(!tags.includes('b') && !tags.includes('i'));
});

test('source has no innerHTML / eval / external URL', () => {
  const src = require('node:fs').readFileSync(require.resolve('../www/landing.js'), 'utf8');
  assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/.test(src));
  assert.ok(!/https?:\/\//.test(src));
});
