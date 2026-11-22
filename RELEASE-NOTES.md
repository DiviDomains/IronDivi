# Release notes

## Unreleased

### Wallet: `planpqsweep` no longer gives out unsupported PQ transactions

Before `DIP-PQ-3` is enforced, `P2PQPKH` and `PQ_STAKING_VAULT` outputs have no
consensus spending rules. `planpqsweep` and the web interface's sweep-plan route used
to return a ready-to-sign `raw_tx_hex` that paid into them. Now any plan that
would create or spend such outputs, including a classical-vault plan whose small
remainder falls back to `P2PQPKH`, is returned as a read-only estimate:
`"signable": false`, with no `txid`, `raw_tx_hex` or output script. Classical
`STAKING_VAULT` plans are still signable, and `getpqposture` is unchanged.

Details: [docs/pq-sweep-activation.md](docs/pq-sweep-activation.md).

### Post-quantum signature checks are no longer called "verified"

IronDivi has no `FN-DSA-512` or `ML-DSA-44` verifier, but the `DIP-PQ-4` block-signature
check returned a `VerifiedBlockSigBinding` after checking only encodings and the staker
key binding. It is now `check_block_sig_envelope_binding`, returning an
`UnverifiedBlockSigBinding`, and the new `verify_pq_block_signature` always refuses with
`PostQuantumSignatureVerifierUnavailable`. A hybrid spork accepted without a configured
`LMS` key is now reported as `SporkAuthKind::HybridV2LmsUnverified`, and its leaf index is
no longer recorded. Which blocks and sporks are accepted is unchanged; post-quantum
consensus rules remain inactive. Details: `docs/plans/dip-pq-4-pos-block-signing.md` §4.3.

### LMS spork signing is disabled until leaf reservation is durable

An `LMS` signature uses a one-time leaf. `LmsPrivateKey` kept its leaf counter only in
memory, could be cloned, and restarted at leaf `0` whenever the key was derived again,
so a restart, restore or second copy would reuse leaves. `sign_hybrid_spork_lms` and
`SporkMessage::attach_lms_signature` now return `LmsSigningUnavailable` without signing.
Signing exists only behind the test-only `lms-volatile-test-signer` feature, which
`tools/release-check.sh` rejects for shipped binaries. Verification and spork acceptance
are unchanged. Requirements for a future signer, and the restore and rollback limits even
such a signer would have: `docs/plans/dip-pq-2-hybrid-sporks.md` §5.1.

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
