# Release notes

## v0.2.9

### irondivid says when it is running and when it stops

Started in the foreground, 0.2.8 printed nothing after start-up, so a working
node looked hung, and Ctrl+C (a clean stop) looked like a crash. irondivid now
prints one line when start-up is done (`IronDivi is running (chain height N).`),
one when it receives Ctrl+C or SIGTERM, and `IronDivi stopped.` when it has
shut down. Everything else still goes to `debug.log`.

### Quieter logging, with a level per category

0.2.8 wrote about 1 MB of `debug.log` every 20 seconds during sync, so the
default rotation kept only a minute or two of history. By default the node now
writes only the essentials: start-up, the sync progress line, new peers,
warnings, errors and shutdown. Per-block and per-message detail is at `debug`.

Each part of the node is a category with its own level, set with
`-loglevel=<category>:<level>` or `-debug=<category>`, in the config file, or
while the node runs with `irondivi-cli setlogconfig`. The log is flushed on
exit. Details: [docs/logging.md](docs/logging.md).

## Unreleased (next after v0.2.6)

### Wallet: check old copies of an encrypted wallet

Before this version, the daemon stored the HD seed in plaintext on disk even after
`encryptwallet`. Any copy of the datadir made before this version may expose the
seed, including automatic backups, `backupwallet` files and filesystem snapshots.
If such copies exist and the wallet holds real funds, move the funds to a new
wallet.

`encryptwallet` keeps the same seed. It does not make a new one, so encrypting an
existing wallet does not protect copies made before it was encrypted.

Details and steps: [docs/wallet-encryption.md](docs/wallet-encryption.md).
