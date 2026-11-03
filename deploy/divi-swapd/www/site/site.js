// IronDivi Swaps website script (testnet, read-only). Same-origin, no libraries. No HTML-string insertion
// anywhere: every API value reaches the page through textContent, because /offers content is untrusted.
(function (root) {
  'use strict';

  var TICKER = { btc: 'BTC', ltc: 'LTC', zec: 'ZEC', xmr: 'XMR', usdc: 'USDC', divi: 'DIVI' };

  function str(v) {
    return typeof v === 'string' || typeof v === 'number' ? String(v) : '?';
  }

  // Satoshi-style integer (1e-8 units) to a coin string, no float rounding.
  function coins(sats) {
    if (typeof sats !== 'number' || !isFinite(sats) || sats < 0 || Math.floor(sats) !== sats) return '?';
    var whole = Math.floor(sats / 1e8);
    var frac = String(sats % 1e8);
    while (frac.length < 8) frac = '0' + frac;
    frac = frac.replace(/0+$/, '');
    return String(whole) + (frac ? '.' + frac : '');
  }

  function ticker(chain) {
    var t = TICKER[chain];
    return t || (typeof chain === 'string' ? chain.toUpperCase().slice(0, 12) : '?');
  }

  // health: parsed /healthz JSON, or null when the request failed or was not JSON.
  function describeHealth(health) {
    if (!health || typeof health !== 'object') {
      return { state: 'unreachable', text: 'Unreachable', detail: 'The swap maker did not answer. Try again in a minute.' };
    }
    var scan = health.divi_scan && typeof health.divi_scan === 'object' ? health.divi_scan : {};
    if (scan.state === 'scanning') {
      var detail = 'The maker is scanning the DIVI test chain.';
      if (typeof scan.next_height === 'number' && typeof scan.target_height === 'number' && scan.target_height > 0) {
        var pct = Math.min(100, Math.floor((scan.next_height / scan.target_height) * 100));
        detail = 'Scanning block ' + scan.next_height + ' of ' + scan.target_height + ' (' + pct + '%).';
      }
      return { state: 'catching_up', text: 'Catching up', detail: detail + ' Offers are shown, but swaps wait until the scan finishes.' };
    }
    if (health.ok === true) {
      return { state: 'ready', text: 'Ready', detail: 'The maker is up and its chains are in sync.' };
    }
    var bad = [];
    if (scan.state === 'failed') bad.push('DIVI scan');
    if (health.divi && health.divi.error) bad.push('DIVI');
    if (health.btc && health.btc.error) bad.push('BTC');
    var c = health.counters && typeof health.counters === 'object' ? health.counters : {};
    Object.keys(c).sort().forEach(function (k) {
      if (c[k] && c[k].error) bad.push(ticker(k));
    });
    return {
      state: 'degraded',
      text: 'Not ready',
      detail: bad.length ? 'Problem with: ' + bad.join(', ') + '.' : 'The maker reports a problem.'
    };
  }

  // Per-chain rows from /healthz: [{chain, tip, error}].
  function describeChains(health) {
    if (!health || typeof health !== 'object') return [];
    var rows = [];
    function add(name, h) {
      h = h && typeof h === 'object' ? h : {};
      rows.push({
        chain: name,
        tip: typeof h.tip === 'number' ? String(h.tip) : '-',
        error: typeof h.error === 'string' && h.error ? h.error.slice(0, 200) : ''
      });
    }
    add('DIVI', health.divi);
    add('BTC', health.btc);
    var c = health.counters && typeof health.counters === 'object' ? health.counters : {};
    Object.keys(c).sort().forEach(function (k) { add(ticker(k), c[k]); });
    return rows;
  }

  // {text, pct|null} for the DIVI scan.
  function describeScan(health) {
    var scan = health && typeof health === 'object' && health.divi_scan && typeof health.divi_scan === 'object' ? health.divi_scan : null;
    if (!scan) return { text: 'Unknown.', pct: null };
    var pct = null;
    if (typeof scan.next_height === 'number' && typeof scan.target_height === 'number' && scan.target_height > 0) {
      pct = Math.max(0, Math.min(100, Math.floor((scan.next_height / scan.target_height) * 100)));
    }
    var text = str(scan.state) + (pct === null ? '' : ': block ' + scan.next_height + ' of ' + scan.target_height + ' (' + pct + '%)');
    if (typeof scan.error === 'string' && scan.error) text += '. Error: ' + scan.error.slice(0, 200);
    return { text: text, pct: pct };
  }

  // offers: parsed /offers JSON array. Returns rows of plain strings.
  function describeOffers(offers) {
    if (!Array.isArray(offers)) return [];
    return offers.map(function (o) {
      o = o && typeof o === 'object' ? o : {};
      var t = ticker(o.counter_chain);
      var paysCounter = o.direction !== 'taker_pays_divi';
      return {
        id: str(o.id),
        you: paysCounter ? 'You pay ' + t + ', get DIVI' : 'You pay DIVI, get ' + t,
        price: coins(o.divi_sats_per_btc) + ' DIVI per 1 ' + t,
        min: coins(o.min_btc_sats) + ' ' + t,
        max: coins(o.max_btc_sats) + ' ' + t
      };
    });
  }

  function para(doc, el, text) {
    el.textContent = '';
    var p = doc.createElement('p');
    p.textContent = text;
    el.appendChild(p);
  }

  function table(doc, el, heads, rows) {
    var t = doc.createElement('table');
    var head = doc.createElement('tr');
    heads.forEach(function (h) {
      var th = doc.createElement('th');
      th.textContent = h;
      head.appendChild(th);
    });
    t.appendChild(head);
    rows.forEach(function (r) {
      var tr = doc.createElement('tr');
      r.forEach(function (v) {
        var td = doc.createElement('td');
        td.textContent = v;
        tr.appendChild(td);
      });
      t.appendChild(tr);
    });
    el.textContent = '';
    el.appendChild(t);
  }

  function renderHealth(doc, el, health) {
    var d = describeHealth(health);
    el.textContent = '';
    el.setAttribute('data-state', d.state);
    var b = doc.createElement('strong');
    b.textContent = d.text;
    el.appendChild(b);
    el.appendChild(doc.createTextNode(' — ' + d.detail));
  }

  function renderOffers(doc, el, offers) {
    if (offers === null) return para(doc, el, 'Offers could not be loaded.');
    var rows = describeOffers(offers);
    if (!rows.length) return para(doc, el, 'No offers right now.');
    table(doc, el, ['Offer', 'Direction', 'Price', 'Smallest swap', 'Largest swap'],
      rows.map(function (r) { return [r.id, r.you, r.price, r.min, r.max]; }));
  }

  function renderChains(doc, el, health) {
    var rows = describeChains(health);
    if (!rows.length) return para(doc, el, 'No chain data: the maker did not answer.');
    table(doc, el, ['Chain', 'Tip (block height)', 'Error'],
      rows.map(function (r) { return [r.chain, r.tip, r.error || 'none']; }));
  }

  function renderScan(doc, el, health) {
    var s = describeScan(health);
    para(doc, el, s.text);
    if (s.pct !== null) {
      var p = doc.createElement('progress');
      p.setAttribute('max', '100');
      p.setAttribute('value', String(s.pct));
      el.appendChild(p);
    }
  }

  function renderVersion(doc, el, health) {
    var v = health && typeof health === 'object' ? health.version : null;
    para(doc, el, typeof v === 'string' ? 'divi-swapd ' + v.slice(0, 40) : 'Unknown: the maker did not answer.');
  }

  var RENDER = {
    status: ['health', renderHealth], chains: ['health', renderChains], scan: ['health', renderScan],
    version: ['health', renderVersion], offers: ['offers', renderOffers]
  };

  function getJson(fetchFn, url) {
    return fetchFn(url, { cache: 'no-store' }).then(function (r) {
      if (!r.ok) throw new Error('http ' + r.status);
      return r.json();
    });
  }

  // base: URL prefix of the API relative to this page ('' on the home page, '../' under /site/).
  function refresh(doc, fetchFn, base) {
    var els = doc.querySelectorAll('[data-live]');
    var wanted = { health: false, offers: false };
    Array.prototype.forEach.call(els, function (el) {
      var r = RENDER[el.getAttribute('data-live')];
      if (r) wanted[r[0]] = true;
    });
    ['health', 'offers'].forEach(function (kind) {
      if (!wanted[kind]) return;
      getJson(fetchFn, base + (kind === 'health' ? 'healthz' : 'offers'))
        .then(function (j) { return j; }, function () { return null; })
        .then(function (j) {
          Array.prototype.forEach.call(els, function (el) {
            var r = RENDER[el.getAttribute('data-live')];
            if (r && r[0] === kind) r[1](doc, el, j);
          });
        });
    });
  }

  var api = { coins: coins, describeHealth: describeHealth, describeChains: describeChains, describeScan: describeScan,
              describeOffers: describeOffers, renderHealth: renderHealth, renderOffers: renderOffers,
              renderChains: renderChains, renderScan: renderScan, renderVersion: renderVersion, refresh: refresh };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (root.document && root.fetch && root.document.body) {
    var base = root.document.body.getAttribute('data-api') || '';
    refresh(root.document, root.fetch.bind(root), base);
    root.setInterval(function () { refresh(root.document, root.fetch.bind(root), base); }, 30000);
  }
})(typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : this));
