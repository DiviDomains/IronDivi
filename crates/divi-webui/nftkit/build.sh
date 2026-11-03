#!/usr/bin/env bash
# Rebuild static/nftkit.js from a divi-nft checkout (packages/nft-kit, docs/WALLET-INTEGRATION.md).
# Usage: build.sh <divi-nft checkout> [rev, default 9b35408]. Exports the committed packages at
# that rev to a temp dir (never the working tree, which may hold another lane's edits); never
# writes the checkout.
set -euo pipefail
src=${1:?divi-nft checkout}; here=$(cd "$(dirname "$0")" && pwd); tmp=$(mktemp -d)
rev=$(git -C "$src" rev-parse --short "${2:-9b35408}^{commit}")
git -C "$src" archive "$rev" packages/divi-assets packages/wallet packages/nft-kit apps/server/src/contract.ts | tar -x -C "$tmp"
cp "$here/entry.ts" "$here/csrf-fetch.js" "$tmp/"
cd "$tmp"
cat > package.json <<'J'
{ "private": true, "type": "module",
  "dependencies": { "@noble/curves": "2.4.0", "@noble/hashes": "2.4.0", "@scure/base": "2.4.0" },
  "devDependencies": { "esbuild": "0.25.10" } }
J
npm install --no-audit --no-fund --ignore-scripts >/dev/null
{ echo "// divi-nft nft-kit $rev, bundled by crates/divi-webui/nftkit/build.sh (esbuild 0.25.10). Testnet; window.IronDiviNftKit."
  ./node_modules/.bin/esbuild entry.ts --bundle --format=iife --target=es2022 --minify --legal-comments=none --log-level=error \
    --alias:@divi-nft/wallet=./packages/wallet/src/index.ts --alias:@divi-nft/divi-assets=./packages/divi-assets/src/index.ts \
    --inject:./csrf-fetch.js; } > "$here/../static/nftkit.js"
rm -rf "$tmp"
