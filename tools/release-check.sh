#!/bin/bash
# Gate for a release build: run it in the tree being released, before building the
# tarballs, and release nothing if it fails.
#
# Release binaries are built outside GitHub Actions (270b2cd), so the CI audit job
# cannot stop a release on its own. This script is the stop:
#   - Cargo.lock matches Cargo.toml (cargo metadata --locked), so the lock file that
#     was audited is the one the build uses (build-linux-gnu.sh builds --locked)
#   - cargo deny check bans, licenses and sources for the whole workspace, from
#     deny.toml
#   - known vulnerabilities in the shipped binaries (SHIPPED below), and only
#     those: cargo deny check advisories with each binary as the sole root, and
#     cargo audit, where an advisory fails the gate if its crate is in the
#     dependency graph of a shipped binary on any target. Advisories for crates
#     only the swap tools use are printed and do not fail. Unmaintained and yanked
#     crates are reported but do not fail, as in deny.toml.
#
# Needs cargo-deny, cargo-audit and jq: cargo install --locked cargo-deny cargo-audit
set -euo pipefail
cd "$(dirname "$0")/.."

# The binaries in the release tarballs (build-linux-gnu.sh). A binary added to the
# tarballs must be added here.
SHIPPED="irondivid irondivi-cli"

fail=0
for tool in cargo-deny cargo-audit jq; do
  if ! command -v "$tool" >/dev/null; then
    echo "release-check: $tool is not installed" >&2
    fail=1
  fi
done
[ "$fail" = 0 ] || exit 1

echo "release-check: Cargo.lock is current"
cargo metadata --locked --format-version 1 >/dev/null || fail=1

echo "release-check: cargo deny check bans licenses sources"
cargo deny check bans licenses sources || fail=1

for bin in $SHIPPED; do
  echo "release-check: cargo deny check advisories for $bin"
  cargo deny --manifest-path "bin/$bin/Cargo.toml" check advisories || fail=1
done

echo "release-check: cargo audit"
pkg_args=()
for bin in $SHIPPED; do pkg_args+=(-p "$bin"); done
# Every crate (name@version) linked into a shipped binary, for any target
if ! shipped_crates=$(cargo tree --locked "${pkg_args[@]}" -e normal,build --target all \
    --prefix none --format '{p}' | awk '{ sub(/^v/, "", $2); print $1 "@" $2 }' | sort -u) \
    || [ -z "$shipped_crates" ]; then
  echo "release-check: cargo tree failed" >&2
  fail=1
fi
# cargo audit exits 1 when it finds a vulnerability; the JSON report is checked
# below, and anything that is not a report fails the gate.
audit_json=$(cargo audit --json) || true
if ! jq -e '.vulnerabilities.list | type == "array"' <<<"$audit_json" >/dev/null 2>&1; then
  echo "release-check: cargo audit did not produce a report" >&2
  fail=1
else
  while read -r crate id; do
    [ -n "$crate" ] || continue
    if grep -qxF "$crate" <<<"$shipped_crates"; then
      echo "release-check: $id in $crate, which a shipped binary links" >&2
      fail=1
    else
      echo "release-check: $id in $crate, not in a shipped binary (swap tools only), not failing"
    fi
  done < <(jq -r '.vulnerabilities.list[] | "\(.package.name)@\(.package.version) \(.advisory.id)"' <<<"$audit_json")
fi

if [ "$fail" != 0 ]; then
  echo "release-check: FAILED, do not release this tree" >&2
  exit 1
fi
echo "release-check: passed"
