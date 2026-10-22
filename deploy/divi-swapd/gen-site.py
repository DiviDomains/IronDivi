import sys, os
out = sys.argv[1]
PAGES = [("index","Home"),("how-to-swap","How to swap"),("safety","How it works and safety"),("status","Status"),("faq","FAQ")]
def href(cur, name):
    if cur == "index": return "./" if name == "index" else "site/%s.html" % name
    return "../" if name == "index" else "%s.html" % name
def page(name, title, body, api):
    pre = "site/" if name == "index" else ""
    nav = "".join('<a href="%s"%s>%s</a>' % (href(name, n), ' aria-current="page"' if n == name else "", t) for n, t in PAGES)
    html = f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} - IronDivi Swaps (testnet)</title>
<link rel="stylesheet" href="{pre}site.css">
<script src="{pre}site.js" defer></script>
</head>
<body data-api="{api}">
<header>
<p class="brand">IronDivi Swaps</p>
<nav>{nav}</nav>
</header>
<p class="banner"><strong>Practice network only.</strong> Everything here uses test coins that have no value. Nothing on this site touches real money.</p>
<main>
{body}
</main>
<footer><p>This site is read-only: no sign-in, no wallet, no keys, no forms, no cookies, no analytics. It only reads <code>healthz</code> and <code>offers</code> from the swap maker. Testnet only.</p></footer>
</body>
</html>
'''
    os.makedirs(os.path.join(out, "site"), exist_ok=True)
    open(os.path.join(out, "index.html" if name == "index" else "site/%s.html" % name), "w").write(html)

NOJS = '<noscript><p class="note">This section needs JavaScript. With JavaScript off you can still read the rest of the page.</p></noscript>'

page("index", "Home", f'''<h1>Trade DIVI for other coins, with no exchange in the middle</h1>
<p>IronDivi Swaps lets you swap DIVI for Bitcoin (BTC), Litecoin (LTC), Zcash (ZEC), Monero (XMR) or USDC straight from your own wallet. No exchange ever holds your coins. Each trade is an <em>atomic swap</em>: either both sides get what they agreed to, or both sides get their own coins back.</p>
<p class="note">Right now this runs on <strong>test networks only</strong>. It is a practice run so the software can be proven before any real money is involved.</p>

<h2>Is the swap maker running?</h2>
<div class="live" id="status" data-live="status" data-state="loading">Checking&hellip;</div>
{NOJS}
<p><a href="site/status.html">Full status per chain</a></p>

<h2>Current offers</h2>
<div class="live scroll" id="offers" data-live="offers">Loading&hellip;</div>
{NOJS}
<p>Amounts are in whole coins. The smallest and largest swap are given in the other coin (not DIVI).</p>

<h2>Where to go next</h2>
<ul>
<li><a href="site/how-to-swap.html">How to swap</a> &ndash; the commands, step by step.</li>
<li><a href="site/safety.html">How it works and safety</a> &ndash; who can take their coins back, and when.</li>
<li><a href="site/faq.html">FAQ</a> &ndash; limits, fees, risks.</li>
</ul>''', "")

page("how-to-swap", "How to swap", '''<h1>How to swap (testnet)</h1>

<h2>1. Get test coins</h2>
<p>Test coins are free. Get DIVI test coins from the faucet: <a href="https://services.divi.domains/testnet/faucet" rel="noopener noreferrer">services.divi.domains/testnet/faucet</a>. For the other coin you need test coins on that chain too (Bitcoin signet, Litecoin testnet, Zcash testnet or Monero stagenet).</p>

<h2>2. Get the taker app</h2>
<p><strong>The taker app (<code>divi-swap</code>) is not published yet.</strong> There is no download link on this site because there is nothing to link to. When it is published, the link will be added here.</p>

<h2>3. Pick an offer</h2>
<p>Open the <a href="../">Home page</a> and note an offer id, for example <code>divi-ltc-testnet</code>. The offer says which coin you pay and which you get, and the smallest and largest swap.</p>

<h2>4. Run the swap</h2>
<p>The amount is given in the <em>other</em> coin, in its smallest unit (1 coin = 100,000,000 units). To see a price without committing to anything:</p>
<pre>divi-swap quote --maker https://divi.cx/swap --offer OFFER_ID --btc-sats AMOUNT</pre>
<p>For an offer on Litecoin, Zcash, Monero or USDC add <code>--counter-chain ltc</code> (or <code>zec</code>, <code>xmr</code>, <code>usdc</code>) as well. The command needs your own test keys, given as <code>--divi-key</code> and the key flag for the other coin; run <code>divi-swap --help</code> for the full list. The default network settings are the test networks.</p>

<p>To do the whole swap in one command:</p>
<pre>divi-swap run --maker https://divi.cx/swap --offer OFFER_ID --btc-sats AMOUNT</pre>

<p>Or one step at a time:</p>
<ol>
<li><code>quote</code> &ndash; prints a fresh price. Quotes expire after 60 seconds.</li>
<li><code>accept --maker &hellip; --offer &hellip; --btc-sats &hellip;</code> &ndash; takes a new quote and accepts it. It prints a swap id.</li>
<li><code>lock --swap SWAP_ID</code> &ndash; puts your coins into the swap lock and tells the maker.</li>
<li><code>status --swap SWAP_ID</code> &ndash; shows what the maker sees.</li>
<li><code>claim --swap SWAP_ID</code> &ndash; once the maker has locked its side and it is confirmed, collects your new coins.</li>
<li><code>refund --swap SWAP_ID</code> &ndash; if the swap stalls, takes your own coins back once the waiting time has passed. See <a href="safety.html">how it works and safety</a>.</li>
</ol>
<p><code>run</code> does all of this for you and picks between claim and refund by itself.</p>
<p class="note">The commands above are taken from the <code>divi-swap</code> command-line source. Nothing here is a real-money instruction: the default is the test networks, and mainnet needs an explicit extra flag that this site does not describe.</p>''', "../")

page("safety", "How it works and safety", '''<h1>How it works and safety</h1>
<p class="note">All numbers on this page are the <strong>testnet</strong> settings used by the code today. A real-money version would use longer waits, and this page would be updated first.</p>

<h2>The swap, in plain words (Bitcoin, Litecoin, Zcash, USDC)</h2>
<p>This is a <em>hashlock swap</em>. You and the maker each put coins into a lock on your own chain. Both locks open with the same secret word. Only you know the secret to start with.</p>
<ol>
<li>You lock your coins. They can only be opened with the secret, or taken back by you after a deadline.</li>
<li>The maker sees your lock confirmed and locks its coins the same way, with a <em>shorter</em> deadline.</li>
<li>You use the secret to collect the maker's coins. Doing so shows the secret on that chain.</li>
<li>The maker reads the secret and collects yours.</li>
</ol>
<p>Your deadline is longer than the maker's on purpose: you always have time to refund after the maker has had its chance to.</p>

<h2>The Monero swap, in plain words</h2>
<p>Monero cannot hold this kind of lock, so the Monero swap uses <em>adaptor signatures</em> instead. The DIVI side sits in a lock that needs both of your signatures; the Monero side is sent to an address that only you and the maker together can spend. Handing over a signature to collect the DIVI reveals exactly what the maker needs to collect the Monero. If someone stops, a cancel and refund path exists, and a punish path exists for a side that stalls after cancel. You never have to trust the maker to be honest or online for your coins to be safe.</p>

<h2>Who can take the coins back, and when</h2>
<table>
<tr><th>Swap</th><th>Your refund opens</th><th>Maker's refund opens</th></tr>
<tr><td>BTC, LTC, ZEC, USDC</td><td>6 hours after locking</td><td>3 hours after locking</td></tr>
<tr><td>XMR</td><td>6 hours (cancel), then refund</td><td>3 more hours after cancel (punish window)</td></tr>
</table>
<p>Source: the testnet profile sets a 6 hour taker timeout and a 3 hour maker timeout (<code>crates/divi-swap/src/config.rs</code>, lines 119&ndash;121). The Monero swap uses a 6 hour cancel time, a 3 hour punish window and a 1 hour redeem margin (<code>crates/divi-swap-xmr/src/lib.rs</code>, lines 176&ndash;179).</p>

<h2>Confirmations the code waits for</h2>
<p>A lock must be buried under this many blocks before the other side acts on it (testnet):</p>
<table>
<tr><th>Chain</th><th>Confirmations</th></tr>
<tr><td>DIVI</td><td>3</td></tr>
<tr><td>BTC</td><td>1</td></tr>
<tr><td>LTC</td><td>2</td></tr>
<tr><td>ZEC</td><td>9</td></tr>
<tr><td>USDC</td><td>3</td></tr>
<tr><td>XMR</td><td>10</td></tr>
</table>
<p>Source: <code>crates/divi-swap/src/config.rs</code>, lines 52&ndash;70 and 119&ndash;123.</p>

<h2>If someone disappears</h2>
<ul>
<li><strong>The maker disappears before locking:</strong> nothing of yours is spent beyond your own lock. After your deadline, run <code>refund</code> and your coins come back.</li>
<li><strong>The maker disappears after locking:</strong> you can still collect its coins with <code>claim</code> while its lock is open. If it is too late to claim safely, refund your own side instead.</li>
<li><strong>You disappear:</strong> the maker takes its coins back after its (shorter) deadline. Nobody can take your coins without the secret, and you keep your refund right until you claim.</li>
<li><strong>The website disappears:</strong> nothing changes. The swap runs between the taker app and the maker, not through this site.</li>
</ul>

<h2>What this site never does</h2>
<ul>
<li>It never asks for keys, seed words, passwords or a sign-in.</li>
<li>It has no wallet and cannot move coins.</li>
<li>It has no forms, cookies or analytics, and loads nothing from other sites.</li>
<li>It only reads two public lists from the maker: its health and its offers.</li>
</ul>''', "../")

page("status", "Status", f'''<h1>Status</h1>
<p>Live from the swap maker's <code>healthz</code>. It refreshes every 30 seconds.</p>
<h2>Overall</h2>
<div class="live" id="status" data-live="status" data-state="loading">Checking&hellip;</div>
<h2>Chains</h2>
<div class="live scroll" id="chains" data-live="chains">Loading&hellip;</div>
<h2>DIVI scan</h2>
<div class="live" id="scan" data-live="scan">Loading&hellip;</div>
<h2>Maker version</h2>
<div class="live" id="version" data-live="version">Loading&hellip;</div>
{NOJS}''', "../")

page("faq", "FAQ", f'''<h1>FAQ</h1>

<h2>Is this real money?</h2>
<p>No. Everything here runs on test networks (Bitcoin signet, Litecoin testnet, Zcash testnet, Monero stagenet, DIVI testnet). The coins have no value. A mainnet version would be announced separately and does not exist yet.</p>

<h2>How much can I swap?</h2>
<p>Each offer has a smallest and a largest swap, shown here live. Amounts are in whole coins of the <em>other</em> coin.</p>
<div class="live scroll" id="limits" data-live="offers">Loading&hellip;</div>
{NOJS}
<p>The maker also limits how fast one address can ask: 20 quotes or new swaps per minute and 300 status reads per minute (<code>bin/divi-swapd/src/routes.rs</code>, lines 51&ndash;62). A quote is only valid for 60 seconds.</p>

<h2>What does it cost?</h2>
<p>The price is the one in the offer; read it as "DIVI per 1 coin of the other chain". On top of that, each lock and each claim pays that chain's normal network fee. The Monero swap also pays a 0.001 DIVI network fee on the DIVI side (<code>crates/divi-swap-xmr/src/lib.rs</code>, line 181).</p>

<h2>What can go wrong?</h2>
<ul>
<li>A swap can stall if either side goes offline. The refund rules on <a href="safety.html">how it works and safety</a> cover this: you get your own coins back after the deadline.</li>
<li>You must be online to claim in time. Do not start a swap you cannot supervise for a few hours.</li>
<li>This is new software on test networks. Bugs are expected, which is why it is not on real money.</li>
</ul>

<h2>Testnet or mainnet?</h2>
<p>Testnet only. The taker app refuses mainnet unless you pass an extra flag, and this site does not recommend it.</p>

<h2>Where do I get the taker app and the source?</h2>
<p>The taker app (<code>divi-swap</code>) is not published yet, and there is no public source link to give. When either exists, it will be listed here.</p>

<h2>Where are my test coins?</h2>
<p>Free DIVI test coins: <a href="https://services.divi.domains/testnet/faucet" rel="noopener noreferrer">services.divi.domains/testnet/faucet</a>.</p>''', "../")
