#!/bin/bash
# Gate for a release build: run it in the tree being released, before building the
# tarballs, and release nothing if it fails.
#
# Release binaries are built outside GitHub Actions (270b2cd), so the CI audit job
# cannot stop a release on its own. This script is the stop:
#   - cargo deny check: advisories (a known vulnerability fails), bans, licenses
#     and sources, all from deny.toml
#   - cargo audit: RustSec vulnerabilities against Cargo.lock, ignores in
#     .cargo/audit.toml (kept in step with deny.toml); unmaintained and yanked
#     crates are reported but do not fail, as in deny.toml
#   - Cargo.lock matches Cargo.toml (cargo metadata --locked), so the lock file that
#     was audited is the one the build uses (build-linux-gnu.sh builds --locked)
#
# Needs cargo-deny and cargo-audit: cargo install --locked cargo-deny cargo-audit
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0
for tool in cargo-deny cargo-audit; do
  if ! command -v "$tool" >/dev/null; then
    echo "release-check: $tool is not installed (cargo install --locked $tool)" >&2
    fail=1
  fi
done
[ "$fail" = 0 ] || exit 1

echo "release-check: Cargo.lock is current"
cargo metadata --locked --format-version 1 >/dev/null || fail=1

echo "release-check: cargo deny check"
cargo deny check advisories bans licenses sources || fail=1

echo "release-check: cargo audit"
cargo audit || fail=1

if [ "$fail" != 0 ]; then
  echo "release-check: FAILED, do not release this tree" >&2
  exit 1
fi
echo "release-check: passed"
