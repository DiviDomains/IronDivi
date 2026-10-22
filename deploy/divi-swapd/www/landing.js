// Read-only testnet landing page for divi-swapd. No HTML-string insertion anywhere: every API value
// reaches the page through textContent, because /offers content is untrusted.
(function (root) {
  'use strict';

  var TICKER = { btc: 'BTC', ltc: 'LTC', zec: 'ZEC', xmr: 'XMR', usdc: 'USDC' };

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
  // Returns {state: ready|catching_up|degraded|unreachable, text, detail}.
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
    var rows = describeOffers(offers);
    el.textContent = '';
    if (!rows.length) {
      var p = doc.createElement('p');
      p.textContent = 'No offers right now.';
      el.appendChild(p);
      return;
    }
    var table = doc.createElement('table');
    var head = doc.createElement('tr');
    ['Offer', 'Direction', 'Price', 'Smallest swap', 'Largest swap'].forEach(function (h) {
      var th = doc.createElement('th');
      th.textContent = h;
      head.appendChild(th);
    });
    table.appendChild(head);
    rows.forEach(function (r) {
      var tr = doc.createElement('tr');
      [r.id, r.you, r.price, r.min, r.max].forEach(function (v) {
        var td = doc.createElement('td');
        td.textContent = v;
        tr.appendChild(td);
      });
      table.appendChild(tr);
    });
    el.appendChild(table);
  }

  function getJson(fetchFn, url) {
    return fetchFn(url, { cache: 'no-store' }).then(function (r) {
      if (!r.ok) throw new Error('http ' + r.status);
      return r.json();
    });
  }

  function refresh(doc, fetchFn) {
    getJson(fetchFn, 'healthz').then(function (h) { return h; }, function () { return null; })
      .then(function (h) { renderHealth(doc, doc.getElementById('status'), h); });
    getJson(fetchFn, 'offers').then(function (o) { return o; }, function () { return null; })
      .then(function (o) {
        var el = doc.getElementById('offers');
        if (o === null) {
          el.textContent = '';
          var p = doc.createElement('p');
          p.textContent = 'Offers could not be loaded.';
          el.appendChild(p);
        } else {
          renderOffers(doc, el, o);
        }
      });
  }

  var api = { coins: coins, describeHealth: describeHealth, describeOffers: describeOffers,
              renderHealth: renderHealth, renderOffers: renderOffers, refresh: refresh };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (root.document && root.fetch) {
    refresh(root.document, root.fetch.bind(root));
    root.setInterval(function () { refresh(root.document, root.fetch.bind(root)); }, 30000);
  }
})(typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : this));
