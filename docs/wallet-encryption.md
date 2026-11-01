# Wallet encryption

`encryptwallet <passphrase>` encrypts the wallet's private keys and HD seed on
disk. The passphrase key is derived with Argon2id and the data is stored with
authenticated encryption. After it returns, the wallet files hold no plaintext
key material.

## encryptwallet keeps the same seed

`encryptwallet` encrypts the seed the wallet already has. It does not make a new
one. Every address the wallet derived before encryption, and every address it
derives after, comes from that same seed.

So encrypting a wallet protects it from now on. It does nothing for copies of the
wallet made before it was encrypted.

## Datadir copies from v0.2.6 and earlier

Up to and including v0.2.6, the daemon kept the HD seed in plaintext on disk even
after `encryptwallet`. Any copy of the datadir made with one of those versions may
expose the seed. That includes automatic backups, `backupwallet` files, filesystem
snapshots and copies on other machines.

If such copies exist and the wallet holds real funds:

1. Create a new wallet with a release newer than v0.2.6 and encrypt it.
2. Send the funds from the old wallet to an address in the new wallet.
3. Stop using the old wallet and its seed.

If no copy of the datadir from v0.2.6 or earlier exists anywhere, the wallet is safe
to keep using.
