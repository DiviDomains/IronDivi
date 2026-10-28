# Logging

irondivid writes to `debug.log` in the data directory (`~/.irondivi/` by
default). The file rotates by size: `-maxlogsize=<MB>` per file (default 1)
and `-maxlogfiles=<n>` files kept (default 5: `debug.log`, `debug.log.1`, …).
`-printtoconsole` writes to the terminal instead.

When it starts in the foreground the node prints only where it logs to, and
then nothing more on the console. Follow the log with `tail -f ~/.irondivi/debug.log`.

## What is written

By default only the essentials are written: start-up, the sync progress line,
new peers, warnings, errors and shutdown. Libraries the node uses write
warnings and errors only. Per-block and per-message detail is at `debug`, and
is off until you ask for it. Peer disconnects are ordinary churn and are at
`debug` too.

`debug` is loud: `-debug=sync` during initial sync writes several MB a
minute, so the default rotation keeps only the last minute or so. Raise
`-maxlogsize` while you need it, and turn it back off afterwards.

Levels, quietest first: `off`, `error`, `warn`, `info`, `debug`, `trace`.

Each part of the node is a category with its own level:

| Category | Covers |
|---|---|
| `net` | all peer-to-peer networking (`sync`, `peers`, … included) |
| `sync` | block download and connecting downloaded blocks |
| `peers` | connections, handshakes, the address book |
| `node` | the node core (`mempool`, `staking`, … included) |
| `mempool` | the memory pool |
| `staking` | the staker and stake modifiers |
| `chain` | block storage, validation and import |
| `wallet` | the wallet |
| `masternode` | the masternode list and masternode messages |
| `spork` | sporks |
| `rpc` | the JSON-RPC server |
| `electrum` | the Electrum server |
| `webui` | the web UI |
| `swap` | atomic swaps |
| `zmq` | ZMQ notifications |
| `daemon` | irondivid itself: start-up, signals, shutdown |

A more specific category wins over a broader one: `sync:debug` with `net:warn`
writes sync detail and only warnings from the rest of the network code.

## Setting levels

On the command line, or in the config file without the leading `-`. Each may
repeat, and a value may list several, separated by commas:

| Option | Effect |
|---|---|
| `-loglevel=<level>` | every category at that level |
| `-loglevel=<category>:<level>` | one category at that level |
| `-debug=<category>` | that category at `debug` |
| `-debug`, `-debug=1`, `-debug=all` | every category at `debug` |
| `-debug=0`, `-nodebug` | no `-debug` at all |

Examples:

```
# irondivi.conf: quiet, but full detail on block sync
loglevel=warn
loglevel=sync:debug
```

```
irondivid -debug=rpc -debug=wallet
irondivid -loglevel=info,peers:error
```

An invalid level stops the node at start-up with an error. An unknown
category is accepted with a warning in the log, and matches nothing.

`RUST_LOG`, when set, replaces all of the above with a
[tracing filter](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html)
over the Rust module paths, for example `RUST_LOG=divi_network::sync=trace`.

## Changing levels while the node runs

```
irondivi-cli getlogconfig                       # the levels in force ("levels")
irondivi-cli setlogconfig "info,sync:debug"     # the same syntax as -loglevel
irondivi-cli setlogconfig debug                 # every category at debug
irondivi-cli setlogconfig default               # back to info
irondivi-cli setlogconfig true                  # same as debug
irondivi-cli setlogconfig false                 # same as default
```

A change made this way lasts until the node stops.
