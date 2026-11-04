#!/bin/bash
# Keep each release binary's unstripped copy under its build-id, and check
# that every shipped binary has one (diag plan A16).
#
#   release-symbols.sh keep  <bin dir> <symbols dir> <ship dir>
#       For irondivid and irondivi-cli in <bin dir> (a cargo release
#       output): copy the unstripped binary to
#       <symbols dir>/<build-id>/<name>, and a stripped copy to
#       <ship dir>/<name>. Then run `check` on the two.
#   release-symbols.sh check <ship dir> <symbols dir>
#       Fails when a shipped binary has no build-id, when
#       <symbols dir>/<build-id>/<name> is missing, or when that file's
#       build-id differs from the shipped one.
#
# The build-id is the ELF NT_GNU_BUILD_ID note (readelf -n) or the Mach-O
# LC_UUID (otool -l), lowercase hex: the `build-id=` the node writes in
# runs.log and crash.log. Build with `-C link-arg=-Wl,--build-id=sha1` on
# ELF targets (lld adds none by default) and with
# CARGO_PROFILE_RELEASE_DEBUG=line-tables-only so the kept copy has line
# numbers; build-linux-gnu.sh does both.
#
# STRIP names the strip for the target (default: strip). Uploading
# <symbols dir> to the developer's private release storage is not done
# here: that storage is not in this repository.
set -euo pipefail

BINS="irondivid irondivi-cli"

build_id() {
  local f=$1 kind
  kind=$(head -c 4 "$f" | od -An -tx1 | tr -d ' \n')
  case "$kind" in
    7f454c46)
      LC_ALL=C readelf -n "$f" | awk '/Build ID:/ {print tolower($3); exit}' ;;
    cffaedfe|feedfacf)
      otool -l "$f" | awk '/LC_UUID/ {u=1} u && /uuid/ {gsub("-", "", $2); print tolower($2); exit}' ;;
    *) echo "" ;;
  esac
}

check() {
  local ship=$1 symbols=$2 failed=0 name id kept
  for name in $BINS; do
    if [ ! -f "$ship/$name" ]; then
      echo "release-symbols: $ship/$name: not built" >&2; failed=1; continue
    fi
    id=$(build_id "$ship/$name")
    if [ -z "$id" ]; then
      echo "release-symbols: $ship/$name: no build-id" >&2; failed=1; continue
    fi
    if [ ! -f "$symbols/$id/$name" ]; then
      echo "release-symbols: $name $id: unstripped binary missing" >&2; failed=1; continue
    fi
    kept=$(build_id "$symbols/$id/$name")
    if [ "$kept" != "$id" ]; then
      echo "release-symbols: $name: kept build-id $kept, shipped $id" >&2; failed=1; continue
    fi
    echo "release-symbols: $name $id kept"
  done
  return $failed
}

keep() {
  local bins=$1 symbols=$2 ship=$3 name id
  mkdir -p "$ship"
  for name in $BINS; do
    id=$(build_id "$bins/$name")
    if [ -z "$id" ]; then
      echo "release-symbols: $bins/$name: no build-id" >&2; exit 1
    fi
    mkdir -p "$symbols/$id"
    cp "$bins/$name" "$symbols/$id/$name"
    cp "$bins/$name" "$ship/$name"
    "${STRIP:-strip}" "$ship/$name"
  done
  check "$ship" "$symbols"
}

case "${1:-}" in
  keep)  [ $# -eq 4 ] || { echo "usage: $0 keep <bin dir> <symbols dir> <ship dir>" >&2; exit 2; }
         keep "$2" "$3" "$4" ;;
  check) [ $# -eq 3 ] || { echo "usage: $0 check <ship dir> <symbols dir>" >&2; exit 2; }
         check "$2" "$3" ;;
  *) echo "usage: $0 keep|check ..." >&2; exit 2 ;;
esac
