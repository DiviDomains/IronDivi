# Proxy and Tor options next to Divi Core

`run.sh` compares how Divi Core 3.0.0 `divid` and irondivid take the proxy, onion, Tor control, `-dns` and `-upnp`
options:

| option | divid's default | what it does in divid |
|---|---|---|
| `-proxy` | none | a SOCKS5 proxy for IPv4, IPv6 and onion peers and for peer host names; port 9050 when none is given; `0` or empty is none; soft-sets `-listen=0`, `-upnp=0`, `-discover=0` (net.cpp:1690-1779) |
| `-proxyrandomize` | on | random user and password per proxy connection (a Tor circuit each) |
| `-onion` | `-proxy` | the proxy for onion peers only; `0` / `-noonion`: onion is not reachable (net.cpp:1785-1800) |
| `-listenonion` | on | starts the Tor controller; off under `-listen=0` unless given (init.cpp:1621, net.cpp:1706-1711) |
| `-torcontrol` | `127.0.0.1:9051` | the Tor control port |
| `-torpassword` | none | the control port password (HASHEDPASSWORD) |
| `-dns` | on | look up host names given in `-proxy`, `-onion`, `-externalip`, `-addnode` and `-connect` (net.cpp:1759) |
| `-upnp` | off | map the listen port on the gateway by UPnP (net.cpp:908-1007, :1454) |

Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 20
minutes).

```sh
scripts/proxy-tor/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/proxy-tor/run.sh target/release ~/divi-3.0.0/bin 54150 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+49` on 127.0.0.1. Each node gets a p2p and an RPC port and its
  own stand-ins; `<port-base>+49` is a Tor control port nothing listens on. The ports are checked to be free first.
- `[root]`: a fresh directory (mode 0700) is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 8 to 9 minutes and is stopped after 20. However it ends, every node and stand-in is stopped and
every directory deleted. Needs bash and python3 (standard library only).

**Switches:**

- `PROXY_TOR_INJECT=<case name>` changes irondivid's getnetworkinfo of that case before it is compared, so its rows
  FAIL.
- `PROXY_TOR_ONLY=<text>` runs only the cases whose name holds the text.

## Nothing leaves the host

- Every node and stand-in binds to 127.0.0.1. Peers, proxies and the control port are all on 127.0.0.1, or are
  onion names that only ever go to a stand-in proxy.
- Every node gets `listenonion=0` unless the case tests the Tor controller, so no node tries 127.0.0.1:9051 by
  default. `-discover=0` is set too.
- **No `-upnp=1` case is started.** This divid is built with miniupnpc (`-help` says "Use UPnP to map the listening
  port (default: 0)"), so `-upnp=1` would send SSDP multicast to the LAN. Its rows are KNOWN, taken from the source.
  irondivid's UPnP is tested in Rust against a stubbed port mapper and an HTTP stand-in on 127.0.0.1.
- **`-torpassword`:**
  - the conf case's password is made at random per run and written only into that node's 0600 `divi.conf` in the
    work directory;
  - the command-line case uses the fixed fake `dummy-not-a-password`;
  - the stand-in logs a matching password as `<the configured password>` and anything else as
    `<something else>`, never the value.
- RPC passwords are random per run, in the same 0600 files.

## The stand-ins (one set per node)

- **SOCKS5 proxy** (and a second for `-onion`): logs the methods offered, the shape of the credentials ("two
  decimal numbers" for divid's random ones, which can be negative), and the CONNECT address type and destination;
  then refuses the connection.
- **Fake Tor control port:**
  - answers `PROTOCOLINFO 1` with the case's methods (NULL, HASHEDPASSWORD, COOKIE, SAFECOOKIE), `AUTHCHALLENGE`
    (with a real HMAC-SHA256 server hash over a 32-byte cookie file), `AUTHENTICATE` (checked), and `ADD_ONION`
    (service id `abcdefghij234567`, a fake key);
  - logs each command, with nonces, hashes, keys and passwords masked.
- **Target:** a plain TCP listener the `-addnode`/`-connect` cases name, by `127.0.0.1` or by `localhost`; logs
  accepts.

## Cases

Each case starts both nodes on fresh regtest datadirs with the case's `divi.conf` lines (and command-line options).
It compares:

- the start: up, or the exit code and first error line, with each node's own ports shown as their roles (`<socks>`
  etc.);
- getnetworkinfo's `networks` (ipv4, ipv6, onion: limited, reachable, proxy, proxy_randomize_credentials) and
  `localaddresses`;
- what each stand-in saw, 5 s after the start.

| group | cases |
|---|---|
| defaults | defaults, `-upnp=0` |
| `-proxy` | the stand-in; with `-listen=1`; with an added node on 127.0.0.1 (not routable: dialled direct), with and without `-proxyrandomize=0`; an added node by host name (given to the proxy unresolved) and by onion name; `localhost:<port>`, also with `-dns=0`; no port; `0`; empty; `-noproxy`; an unresolvable name; port 99999; `-proxyrandomize=0` alone |
| `-onion` | the stand-in; with `-proxy`; `-proxy` with `-onion=0` and `-noonion`; onion added nodes with `-onion`, and with both; `-onion=0` alone; an unresolvable name; `localhost:<port> -dns=0`; with `-proxyrandomize=0` |
| Tor control | NULL; NULL then a restart on the same datadir (the saved `onion_private_key`); NULL with `-onion`; HASHEDPASSWORD with `-torpassword` in divi.conf and on the command line, and without one; SAFECOOKIE; COOKIE only; `-listenonion=0`; `-listen=0 -listenonion=1`; a control port nothing listens on |
| `-dns` | `-addnode` and `-connect` by `localhost`, each with and without `-dns=0`; `-externalip=localhost -dns=0`; `-dns=0` alone |
| `-upnp=1` | not started (KNOWN) |

## KNOWN

| rows | why |
|---|---|
| `-proxy=localhost:<socks> -dns=0`, `-proxy=notahost.invalid`, `-proxy=127.0.0.1:99999`, `-onion=notahost.invalid`, `-onion=localhost:<onion socks> -dns=0`, `-externalip=localhost -dns=0` | the same error on both. divid then aborts (SIGABRT, exit -6) in the shutdown after the early InitError; irondivid exits 1, as `scripts/start-errors` lists |
| `-upnp=1`, `-upnp=1 -proxy=<socks>` | not started on either node (above). From the source: divid finds the gateway, adds its external address as a local address (score 3) under `-discover`, maps the listen port, renews the mapping every 20 minutes and removes it at shutdown (MapPort net.cpp:989-1007, :1454; ThreadMapPort :908-985). `-proxy` soft-sets `-upnp=0` only when `-upnp` is not given (net.cpp:1690-1700) |

## Results on hp1 (divid 3.0.0)

| irondivid | PASS | KNOWN | FAIL | time |
|---|---|---|---|---|
| d5bb434 (before the fixes) | 86 | 4 | 68 | 7 m 13 s |
| fix/proxy-tor, run 1 | 148 | 8 | 0 | 8 m 11 s |
| fix/proxy-tor, run 2 | 148 | 8 | 0 | 8 m 31 s |
| fix/proxy-tor, `PROXY_TOR_INJECT='tor control, SAFECOOKIE'` | 2 FAILs (networks, localaddresses) | | | |
