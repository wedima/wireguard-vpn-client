#!/bin/bash
# Structural and, when secrets are present, signature checks for the macOS bundle.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TARGET="src-tauri/target/universal-apple-darwin/release"
APP="$(find "$TARGET/bundle/macos" -name '*.app' -print -quit)"
test -n "$APP"
BIN="$APP/Contents/MacOS/wedima-vpn-wg"
test -x "$BIN"

INFO="$(lipo -info "$BIN")"
echo "$INFO"
printf '%s\n' "$INFO" | grep -q 'x86_64'
printf '%s\n' "$INFO" | grep -q 'arm64'
"$BIN" --version | grep -q 'wedima-vpn-wg'

ID="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$APP/Contents/Info.plist")"
test "$ID" = "com.wedima.vpn.wg"

DMG="$(find "$TARGET/bundle/dmg" -name '*.dmg' -print -quit)"
TGZ="$(find "$TARGET/bundle/macos" -name '*.app.tar.gz' -print -quit)"
test -n "$DMG"
test -n "$TGZ"
node scripts/verify-artifact.mjs --kind dmg "$DMG"
node scripts/verify-artifact.mjs --kind gzip "$TGZ"
hdiutil verify "$DMG"

SIGNING_MODE="$(tr -d '[:space:]' < src-tauri/target/macos-code-signing.txt 2>/dev/null || true)"
if [[ "$SIGNING_MODE" == "signed" ]]; then
  codesign --verify --deep --strict --verbose=2 "$APP"
  spctl --assess --type execute --verbose=4 "$APP"
  echo "macOS bundle is signed"
else
  echo "::warning::This macOS artifact is unsigned. Replace GitHub Actions secrets APPLE_CERTIFICATE (base64 of a Developer ID PKCS#12 or a PEM bundle with the certificate and private key) and APPLE_CERTIFICATE_PASSWORD (the matching export password)."
fi

if [[ -n "${TAURI_SIGNING_PRIVATE_KEY:-}" ]]; then
  SIG="$(find "$TARGET/bundle/macos" -name '*.app.tar.gz.sig' -print -quit)"
  test -n "$SIG"
  node scripts/verify-artifact.mjs --kind sig "$SIG"
else
  echo "::warning::TAURI_SIGNING_PRIVATE_KEY is not set. Updater metadata will not be published."
fi
