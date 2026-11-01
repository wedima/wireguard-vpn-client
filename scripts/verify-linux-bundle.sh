#!/bin/bash
# Confirm the Linux build is the AppImage this project ships, and that the
# binary reaches --version.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BIN="$(find src-tauri/target/release -maxdepth 1 -type f -executable ! -name '*.d' -print -quit)"
test -n "$BIN"
"$BIN" --version | grep -q 'wedima-vpn-wg'

APPIMAGE="$(find src-tauri/target/release/bundle/appimage -name '*.AppImage' -print -quit)"
test -n "$APPIMAGE"
node scripts/verify-artifact.mjs --kind appimage "$APPIMAGE"
echo "linux appimage ok: $APPIMAGE"
