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

## walletpassphrasechange

`walletpassphrasechange` does not make a new master key. The wallet's records
stay encrypted under the same master key. Only the copy of that key sealed
under the passphrase is replaced, with one under the new passphrase.

The new sealed key, salt and Argon2id cost are written together in one synced
write. After a crash or power loss, the wallet opens with either the old or
the new passphrase, never neither.

| Result | What it means |
|---|---|
| Success (`null`) | The new passphrase opens the wallet and the old one doesn't. The secret column families were flushed, the log was synced, and compaction of those column families was requested. RocksDB reports no result for a compaction, so this doesn't prove the old copy has left the files. |
| `-14` "Error: The wallet passphrase entered was incorrect." | Nothing changed (the wallet is locked, as divid does). |
| `-16` "Wallet passphrase changed; use the new passphrase. …" | The new passphrase is in effect. The cleanup of the replaced sealed key failed, so it may still be in the wallet files. Don't retry with the old passphrase. |
| `-16` "Error: the wallet passphrase change could not be confirmed on disk. …" | The write reported an error and the node couldn't tell whether it reached the disk. After a restart, try the new passphrase and then the old one. An unlocked wallet in the older format stays unlocked, but saves, imports and new addresses fail until the node can read the wallet files again (see below). |
| Other `-16` errors | Nothing changed; the old passphrase still opens the wallet. |

The web interface clears its enrolled passkeys after any `-16` result, because
they may hold a passphrase that no longer opens the wallet. Enroll them again.

### What a passphrase change doesn't do

- **It doesn't affect copies of the wallet made before the change.** That
  includes `backupwallet` files, datadir copies and filesystem snapshots. Each
  one still opens with the old passphrase. It also holds the same master key,
  so anyone with the old passphrase and such a copy can decrypt records the
  wallet writes later too.
- **It doesn't erase anything from the disk.** The old sealed key is replaced in the logical database. Flush and compaction
  request retirement of obsolete log and table entries. Storage media can
  retain the underlying blocks.
  Filesystem journals, SSD wear levelling, snapshots and backups can keep
  the bytes.

If the old passphrase may be known to someone who could also have such a copy,
changing the passphrase is not enough. Create a new wallet, encrypt it and
send the funds to it, as described above.

## Wallets encrypted by older IronDivi builds

Builds before Argon2id stored the sealed master key with PBKDF2 and the
records with AES-256-CBC. The first unlock, or passphrase change, after
upgrading rewrites them in the current format. All of them, together with
the master key sealed under the same passphrase, go in one synced write. The
master key stays the same.

- If that write fails before it reaches the disk, the unlock still succeeds.
  The wallet stays in the older format and the next unlock tries again.
- If the write reports an error but reached the disk, the node reads it back
  and uses the new format.
- If the node can't tell whether the write reached the disk, the unlock fails.
  A locked wallet stays locked. A wallet that was already unlocked keeps its
  keys and master key in memory, but doesn't know which format to seal new
  keys in. Writes that need to seal keys fail until the record format can
  be read again. A refused import does not turn a watch-only address into a
  spendable one. Incremental saves that do not write keys may still succeed.
  If `walletlock` cannot safely store the keys, it disables spending and key
  export but returns a wallet error instead of reporting that cleanup finished.
  Keep the wallet running: once persistence works, a successful save retries
  cleanup without requiring another lock. Keys already on disk stay readable
  with the passphrase for whichever outcome reached disk.
- The records in the older format are then flushed and compacted out of the
  wallet files. If a flush or log sync fails, the unlock still succeeds and the
  node logs a warning. The compaction itself reports no result.

Once moved, the wallet can't be opened by an older irondivid; keep a backup
made before upgrading if you might need to go back. Such a backup, like any
other copy, still holds the older-format records and opens with the
passphrase it had.

While the move runs it holds the wallet's save lock, so a save or new key in
progress lands before it and is rewritten with it. Unlocks of wallets already
in the current format don't take that lock.
