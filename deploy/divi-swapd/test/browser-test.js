// Runs INSIDE the official Playwright docker image (see site-test.sh). Usage: node browser-test.js BASE OUTDIR SCENARIO
// Loads every page at 390 and 1280 px wide; fails on a console error, page error, CSP violation, failed request,
// dialog, horizontal scroll at 390 px, or a live section still saying Loading.
const { chromium } = require('playwright');
const [base, out, scenario] = process.argv.slice(2);
const PAGES = [['home', '/swap/'], ['how-to-swap', '/swap/site/how-to-swap.html'], ['safety', '/swap/site/safety.html'],
               ['status', '/swap/site/status.html'], ['faq', '/swap/site/faq.html']];
(async () => {
  const browser = await chromium.launch();
  let bad = 0;
  const fail = (m) => { bad++; console.log('FAIL ' + m); };
  for (const width of [390, 1280]) {
    const ctx = await browser.newContext({ viewport: { width, height: 900 } });
    for (const [name, p] of PAGES) {
      const page = await ctx.newPage();
      const tag = `${scenario} ${name}@${width}`;
      page.on('console', (m) => { if (['error', 'warning'].includes(m.type())) fail(`${tag} console ${m.type()}: ${m.text()}`); });
      page.on('pageerror', (e) => fail(`${tag} pageerror ${e.message}`));
      page.on('dialog', (d) => { fail(`${tag} dialog ${d.message()}`); d.dismiss(); });
      page.on('requestfailed', (r) => fail(`${tag} requestfailed ${r.url()}`));
      page.on('response', (r) => { if (r.status() >= 400) fail(`${tag} HTTP ${r.status()} ${r.url()}`); });
      await page.addInitScript(() => { document.addEventListener('securitypolicyviolation', (e) => { console.error('CSP violation: ' + e.violatedDirective + ' ' + e.blockedURI); }); });
      await page.goto(base + p, { waitUntil: 'networkidle' });
      await page.waitForTimeout(300);
      const info = await page.evaluate(() => ({
        sw: document.documentElement.scrollWidth, iw: window.innerWidth,
        loading: [...document.querySelectorAll('[data-live]')].filter((e) => /^(Loading|Checking)/.test(e.textContent)).length,
        injected: document.querySelectorAll('img, script:not([src]), [onerror]').length,
        banner: /Practice network only/.test(document.body.textContent),
      }));
      if (width === 390 && info.sw > info.iw) fail(`${tag} horizontal scroll ${info.sw} > ${info.iw}`);
      if (info.loading) fail(`${tag} ${info.loading} live section(s) never filled`);
      if (info.injected) fail(`${tag} injected element(s) found`);
      if (!info.banner) fail(`${tag} no testnet banner`);
      if (out && process.env.SHOTS === '1') await page.screenshot({ path: `${out}/${name}-${width}.png`, fullPage: true });
      await page.close();
    }
    await ctx.close();
  }
  // JS off: live sections must say they need JavaScript
  const ctx = await browser.newContext({ javaScriptEnabled: false, viewport: { width: 390, height: 900 } });
  const pg = await ctx.newPage(); await pg.goto(base + '/swap/', { waitUntil: 'load' });
  if (!/needs JavaScript/.test(await pg.evaluate(() => document.body.innerText))) fail(`${scenario} JS-off note missing`);
  await browser.close();
  console.log(bad ? `BROWSER FAILED (${bad})` : `BROWSER PASS ${scenario}`);
  process.exit(bad ? 1 : 0);
})();
