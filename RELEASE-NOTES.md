# Release notes

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
