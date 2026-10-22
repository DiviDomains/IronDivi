// Run: node --test deploy/divi-swapd/test/
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const L = require('../www/site/site.js');

// Tiny DOM: no innerHTML (any use throws), so a test fails if the script ever builds HTML from data.
function node(tag) {
  const n = { tag, children: [], attrs: {}, _t: '' };
  Object.defineProperty(n, 'textContent', {
    get() { return n._t + n.children.map((c) => c.textContent).join(''); },
    set(v) { n._t = String(v); n.children = []; },
  });
  Object.defineProperty(n, 'innerHTML', { set() { throw new Error('innerHTML used'); }, get() { throw new Error('innerHTML used'); } });
  n.appendChild = (c) => { n.children.push(c); return c; };
  n.setAttribute = (k, v) => { n.attrs[k] = v; };
  n.getAttribute = (k) => (k in n.attrs ? n.attrs[k] : null);
  return n;
}
const doc = () => ({ createElement: node, createTextNode: (t) => { const n = node('#text'); n._t = t; return n; } });
const walk = (n, f) => { f(n); n.children.forEach((c) => walk(c, f)); };

const HOSTILE = [{ id: '<script>alert(1)</script>', direction: '"><img src=x onerror=alert(1)>',
  counter_chain: '<img src=x onerror=alert(1)>', divi_sats_per_btc: '<b>', min_btc_sats: -1, max_btc_sats: 1.5 }];

test('coins formats without float error', () => {
  assert.strictEqual(L.coins(300000000000000), '3000000');
  assert.strictEqual(L.coins(5000), '0.00005');
  assert.strictEqual(L.coins(190000), '0.0019');
  assert.strictEqual(L.coins(0), '0');
  for (const bad of [-1, '1', 1.5, NaN, Infinity, null, undefined]) assert.strictEqual(L.coins(bad), '?');
});

test('describeHealth: ready, scanning, failed chain, unreachable', () => {
  assert.strictEqual(L.describeHealth({ ok: true, divi_scan: { state: 'done' } }).state, 'ready');
  const s = L.describeHealth({ ok: false, divi_scan: { state: 'scanning', next_height: 50, target_height: 100 } });
  assert.strictEqual(s.state, 'catching_up'); assert.match(s.detail, /50 of 100 \(50%\)/);
  const d = L.describeHealth({ ok: false, divi: { error: 'x' }, counters: { ltc: { error: 'y' } }, divi_scan: { state: 'done' } });
  assert.strictEqual(d.state, 'degraded'); assert.match(d.detail, /DIVI, LTC/);
  for (const bad of [null, undefined, 'x', 3]) assert.strictEqual(L.describeHealth(bad).state, 'unreachable');
  assert.strictEqual(L.describeHealth({ ok: false, divi_scan: { state: 'scanning', next_height: 9, target_height: 0 } }).state, 'catching_up');
});

test('describeChains and describeScan', () => {
  const rows = L.describeChains({ divi: { tip: 5, error: null }, btc: { tip: null, error: 'down' }, counters: { zec: { tip: 7, error: null }, ltc: { tip: 6, error: null } } });
  assert.deepStrictEqual(rows.map((r) => r.chain), ['DIVI', 'BTC', 'LTC', 'ZEC']);
  assert.strictEqual(rows[1].error, 'down'); assert.strictEqual(rows[1].tip, '-');
  assert.deepStrictEqual(L.describeChains(null), []);
  assert.strictEqual(L.describeScan({ divi_scan: { state: 'scanning', next_height: 1, target_height: 4 } }).pct, 25);
  assert.strictEqual(L.describeScan({ divi_scan: { state: 'done', next_height: 9, target_height: 8 } }).pct, 100);
  assert.strictEqual(L.describeScan(null).pct, null);
});

test('describeOffers directions and junk input', () => {
  const r = L.describeOffers([{ id: 'a', direction: 'taker_pays_divi', counter_chain: 'ltc', divi_sats_per_btc: 1e12, min_btc_sats: 100000, max_btc_sats: 190000 }]);
  assert.strictEqual(r[0].you, 'You pay DIVI, get LTC'); assert.strictEqual(r[0].price, '10000 DIVI per 1 LTC');
  assert.strictEqual(r[0].min, '0.001 LTC');
  assert.deepStrictEqual(L.describeOffers({}), []); assert.deepStrictEqual(L.describeOffers(null), []);
  assert.strictEqual(L.describeOffers([null])[0].id, '?');
});

test('hostile strings are only ever text, never markup', () => {
  const d = doc(); const el = node('div');
  L.renderOffers(d, el, HOSTILE);
  let found = false;
  walk(el, (n) => { if (n._t.includes('<script>')) found = true; assert.ok(['div', 'table', 'tr', 'th', 'td'].includes(n.tag) || n.tag === '#text'); });
  assert.ok(found, 'the hostile id is shown as text');
  const hl = node('div');
  L.renderHealth(d, hl, { ok: false, divi: { error: '<script>x</script>' }, counters: { '<img onerror=1>': { error: 'e' } }, divi_scan: { state: 'done' } });
  const ch = node('div');
  L.renderChains(d, ch, { divi: { tip: 1, error: '<script>x</script>' }, btc: {}, counters: {} });
  L.renderVersion(d, node('div'), { version: '<script>' });
  L.renderScan(d, node('div'), { divi_scan: { state: '<b>', next_height: 1, target_height: 2, error: '<i>' } });
  walk(ch, (n) => assert.ok(!['script', 'img'].includes(n.tag)));
});

test('renderOffers: empty, null, scan progress element', () => {
  const d = doc(); const e = node('div');
  L.renderOffers(d, e, []); assert.match(e.textContent, /No offers/);
  L.renderOffers(d, e, null); assert.match(e.textContent, /could not be loaded/);
  const s = node('div'); L.renderScan(d, s, { divi_scan: { state: 'scanning', next_height: 1, target_height: 2 } });
  assert.strictEqual(s.children[1].tag, 'progress'); assert.strictEqual(s.children[1].attrs.value, '50');
});

test('refresh fills each data-live element, fetching healthz/offers under the page base', async () => {
  const els = {};
  ['status', 'chains', 'offers'].forEach((k) => { const n = node('div'); n.attrs['data-live'] = k; els[k] = n; });
  const d = Object.assign(doc(), { querySelectorAll: () => Object.values(els) });
  const urls = [];
  const fetchFn = (u) => { urls.push(u); return Promise.resolve({ ok: true, json: () => Promise.resolve(u.endsWith('offers') ? [] : { ok: true, divi: { tip: 1 }, btc: { tip: 2 }, divi_scan: { state: 'done' } }) }); };
  L.refresh(d, fetchFn, '../');
  await new Promise((r) => setTimeout(r, 20));
  assert.deepStrictEqual(urls.sort(), ['../healthz', '../offers']);
  assert.match(els.status.textContent, /Ready/); assert.match(els.offers.textContent, /No offers/); assert.match(els.chains.textContent, /DIVI/);
  // a failing fetch shows the unreachable state, not an exception
  const bad = () => Promise.reject(new Error('net'));
  L.refresh(d, bad, ''); await new Promise((r) => setTimeout(r, 20));
  assert.strictEqual(els.status.attrs['data-state'], 'unreachable'); assert.match(els.offers.textContent, /could not be loaded/);
});

const WWW = path.join(__dirname, '..', 'www');
const PAGES = ['index.html', 'site/how-to-swap.html', 'site/safety.html', 'site/status.html', 'site/faq.html'];
test('every page: testnet wording, no inline script/style, no external URL in src/href, JS-off note where live', () => {
  for (const p of PAGES) {
    const h = fs.readFileSync(path.join(WWW, p), 'utf8');
    assert.match(h, /Practice network only/i, p);
    assert.ok(!/<script(?![^>]*\bsrc=)/i.test(h), p + ' inline script');
    assert.ok(!/<style|\sstyle=|\son[a-z]+=/i.test(h), p + ' inline style/handler');
    assert.ok(!/<(form|input|iframe|img)\b/i.test(h), p + ' form/img');
    for (const m of h.matchAll(/\s(?:src|href)="([^"]*)"/g)) {
      assert.ok(!/^https?:/.test(m[1]) || m[1] === 'https://services.divi.domains/testnet/faucet', p + ' external ' + m[1]);
    }
    if (/data-live/.test(h)) assert.match(h, /needs JavaScript/, p);
    for (const m of h.matchAll(/\s(?:src|href)="([^"#:]*)"/g)) {
      const t = path.join(path.dirname(path.join(WWW, p)), m[1] || '.');
      assert.ok(fs.existsSync(t), p + ' dead link ' + m[1]);
    }
  }
});
