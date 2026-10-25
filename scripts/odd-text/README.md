# Odd text in labels, comments and messages, next to Divi Core

`run.sh` starts three regtest nodes on one chain:
- **S**, a Divi Core 3.0.0 `divid` that mines and pays;
- **C**, a `divid` wallet;
- **I**, an irondivid wallet.

C and I are separate wallets. Each gets the same calls with the same text, and their replies are compared: the text
read back, the JSON text of the reply (its escaping), and error codes and messages. Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 15 minutes).

```sh
scripts/odd-text/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid -p irondivi-cli
scripts/odd-text/run.sh target/release ~/divi-3.0.0/bin 53950 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid` and `irondivi-cli`; `<core-bin-dir>` holds `divid` and `divi-cli`.
- `<port-base>`: ports `<port-base>` to `<port-base>+9` on 127.0.0.2 (S, C and I, then a node on each wallet's backup).
  S listens; the others dial it.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 6 minutes (measured on hp1) and is stopped after 15. However it ends, every node is stopped and its
directory deleted. Needs bash and python3 (standard library only). `ODD_TEXT_INJECT=<row name>` makes that row differ, to
show a difference is caught.

## The text

| case | text |
|---|---|
| ascii | `plain label` |
| accents, cjk, emoji | `café Ünïcödé ñ`, `中文标签 日本語`, `💰🚀 coins` |
| empty | `""` |
| long 300, long 5000 | 300 characters (75 of them `é`), 5000 ASCII characters |
| quotes | `say "hi" 'x' back\slash /` |
| tab newline, nul, control | `a<TAB>b<LF>c<CR>d`, `a<NUL>b`, `bell<BEL> esc<ESC> del<DEL>` |
| number, float, json object, json null | `123`, `1e5`, `{"a": 1}`, `null` (as text) |
| spaces, star | `  padded  `, `*` (divid refuses `*` as an account name: -11, rpcwallet.cpp:273-279) |
| null value, number value | a JSON `null` and a JSON `123` where the calls take text |

Each case goes in as UTF-8 JSON. accents, cjk, emoji and long 300 also go in as `\uXXXX` escapes, which is what
Python's `json.dumps` and many tools send. Those cases get ` (escaped)` added to their text so each is an account of its own.

## Rows, per case

- `getnewaddress <text>`, `setaccount <address> <text>`, then `getaccount` of both addresses:
  - the text read back;
  - whether it is the text sent;
  - the JSON text of the reply.
- `getaddressesbyaccount`, `getaccountaddress`.
- Each account gets two coins of 3 DIVI. Then:
  - `listaccounts`, `listreceivedbyaccount`, `getreceivedbyaccount` and `getbalance` for the account;
  - `sendtoaddress <payee> 0.5 "metadata" <text> <text>` (divid takes comments after `metadata`, rpcwallet.cpp:1336-1353);
  - `sendfrom <text> <payee> 0.25 <text> <text>`;
  - `sendmany <text> {payee: 0.125} <text>`;
  - each send's `gettransaction` comment, to and detail accounts;
  - `listtransactions <text>`.
- The coins each send may use are pinned with `lockunspent`. Both wallets then spend the same coins, and the account
  balances (credits less the account's own coins spent, as divid counts them) compare exactly.
- `signmessage <address> <text>`; `verifymessage` of both nodes' signatures on both nodes.
- The escaped cases run the address-book and message rows only.
- **CLIs:** `divi-cli` / `irondivi-cli setaccount <address> <text>` and `getaccount` as command-line arguments: exit code,
  stderr, stdout, and the text read back by RPC. NUL cannot go on a command line.
- **After a restart:** for every case, what differs from before:
  - the labels of its addresses;
  - whether listaccounts has it;
  - each send's comment, to and accounts;
  - the account calls and listtransactions.
- **The backupwallet copy:** `backupwallet` on each wallet, then a fresh node started on the copy. It is checked once
  with no peers and no chain, then again after it syncs from S.
- `dumpwallet`, `importwallet`, `move`: divid 3.0.0 has none of them (rpcserver.cpp:410-470), and both answer -32601.

Text is compared after undoing divid's per-byte escaping (see the first KNOWN row): a divid string whose characters
are all below 256 and form UTF-8 bytes is read as that UTF-8. Only the `JSON text` rows compare the escaping itself.

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c).

## KNOWN

Each KNOWN row is KNOWN only for the difference described; any other difference in it is a FAIL.

- **`...: JSON text`** (each case): the same text, escaped differently.
  - divid's json_spirit writer writes each byte that is not `iswprint` in the C locale as `\u00XX` in capitals
    (json_spirit_writer_template.h:64-90). That is every byte ≥ 0x80 of UTF-8 text, and DEL.
  - So divid's reply for `café` is `"cafÃ©"`, which a JSON reader decodes as `cafÃ©`: one character per
    byte. This is accidental in divid.
  - irondivid writes the UTF-8 text and escapes what JSON requires, so the reply decodes to the text sent.
  - The row is KNOWN when both decode to the same text once divid's per-byte escapes are read as UTF-8, and PASS when
    the two replies are the same.
- **`cjk (escaped)` and `emoji (escaped)`:** the text read back, `same as given`, `JSON text` and `verifymessage`.
  - divid's JSON reader keeps only the low byte of a `\u` escape above `ÿ`
    (json_spirit_reader_template.h, `hex_str_to_char`). `中` is stored as the byte 0x2D, so the text is cut
    before it is stored. This is accidental in divid.
  - irondivid stores the text sent.
  - Each row is KNOWN only when divid's value is exactly the low-byte text and irondivid's the text sent.
- **`accents (escaped)` and `long 300 (escaped)`: verifymessage.**
  - divid's reader stores `é` as the single byte E9 (Latin-1), not as UTF-8. Its JSON replies show `é` again,
    but it signs other bytes than the text's UTF-8.
  - Each node verifies its own signature and not the other's: divid `[true, false]`, irondivid `[false, true]`.
- **`on the backupwallet copy, no chain yet`:** irondivid answers -5 "Invalid or non-wallet transaction id" to the
  sends' `gettransaction`.
  - irondivid's wallet keeps a confirmed transaction as a record that points into the chain database, while
    divid's wallet.dat holds the whole transaction (docs/divid-differences.md W3).
  - The labels and the accounts' address lists match on both copies, and every row after the copy syncs matches
    (`on the backupwallet copy, synced`).
  - The row is KNOWN only when irondivid's only differences are such -5 answers.

No other row differs from divid.
