#!/bin/bash
# Build irondivid and irondivi-cli for a linux-gnu target inside ubuntu:20.04 (glibc 2.31),
# so the release binaries run on any distribution with glibc 2.31 or newer
# (Debian 11+, Ubuntu 20.04+, Raspberry Pi OS Bullseye+).
#
# A binary needs the glibc of the system it was built on: building on ubuntu-latest
# (glibc 2.39) made every gnu release need GLIBC_2.38 (__isoc23_strtol & co. pulled
# in by the C++ RocksDB build). Non-x86_64 targets use Ubuntu's cross gcc, whose
# target libc is the same 2.31.
#
# Usage (as root, in ubuntu:20.04): build-linux-gnu.sh <rust target triple>
set -euo pipefail

TARGET=$1
MAX_GLIBC=2.31

case "$TARGET" in
  x86_64-unknown-linux-gnu)        TRIPLE= ;;
  aarch64-unknown-linux-gnu)       TRIPLE=aarch64-linux-gnu ;;
  armv7-unknown-linux-gnueabihf)   TRIPLE=arm-linux-gnueabihf ;;
  i686-unknown-linux-gnu)          TRIPLE=i686-linux-gnu ;;
  powerpc64le-unknown-linux-gnu)   TRIPLE=powerpc64le-linux-gnu ;;
  s390x-unknown-linux-gnu)         TRIPLE=s390x-linux-gnu ;;
  riscv64gc-unknown-linux-gnu)     TRIPLE=riscv64-linux-gnu ;;
  *) echo "unsupported target $TARGET" >&2; exit 1 ;;
esac

export DEBIAN_FRONTEND=noninteractive
PKGS="build-essential clang libclang-dev curl git pkg-config ca-certificates binutils"
[ -n "$TRIPLE" ] && PKGS="$PKGS g++-$TRIPLE"
apt-get update -qq
apt-get install -y -qq $PKGS >/dev/null

if ! command -v cargo >/dev/null; then
  curl -sSf https://sh.rustup.rs | sh -s -- -y -q --profile minimal --default-toolchain stable
  . "${CARGO_HOME:-$HOME/.cargo}/env"
fi
rustup target add "$TARGET"

if [ -n "$TRIPLE" ]; then
  ENV_TARGET=$(echo "$TARGET" | tr 'a-z-' 'A-Z_')
  export "CARGO_TARGET_${ENV_TARGET}_LINKER=$TRIPLE-gcc"
  export "CC_${TARGET//-/_}=$TRIPLE-gcc" "CXX_${TARGET//-/_}=$TRIPLE-g++" "AR_${TARGET//-/_}=$TRIPLE-ar"
  # bindgen (librocksdb-sys) parses the target's headers
  export BINDGEN_EXTRA_CLANG_ARGS="--target=$TRIPLE --sysroot=/usr/$TRIPLE"
fi

cargo build --release --locked --target "$TARGET" --bin irondivid --bin irondivi-cli

# Refuse a binary that needs a newer glibc than the build system's
for bin in irondivid irondivi-cli; do
  f="${CARGO_TARGET_DIR:-target}/$TARGET/release/$bin"
  need=$(readelf -V --wide "$f" | grep -o 'GLIBC_[0-9.]*' | sed 's/GLIBC_//' | sort -uV | tail -1)
  echo "$bin needs glibc $need"
  if [ "$(printf '%s\n' "$need" "$MAX_GLIBC" | sort -V | tail -1)" != "$MAX_GLIBC" ]; then
    echo "::error::$bin needs glibc $need, more than $MAX_GLIBC" >&2
    exit 1
  fi
done
