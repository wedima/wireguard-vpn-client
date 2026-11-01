#!/bin/bash
# Structural checks for the macOS bundle. Developer ID checks run only when
# prepare-apple-signing.sh recorded a real certificate. An ad-hoc signature
# is not treated as signed.
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
[[ "$INFO" == *"x86_64"* && "$INFO" == *"arm64"* ]]

version_log="$(mktemp)"
set +e
"$BIN" --version >"$version_log" 2>&1
version_status=$?
set -e
echo "macos binary --version exit ${version_status}"
cat "$version_log"
if [[ "$version_status" -ne 0 ]]; then
  echo "error: universal binary exited ${version_status} before printing its version" >&2
  exit "$version_status"
fi
version_text="$(cat "$version_log")"
rm -f "$version_log"
[[ "$version_text" == *"wedima-vpn-wg"* ]]

ID="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$APP/Contents/Info.plist")"
test "$ID" = "com.wedima.vpn.wg"

DMG="$(find "$TARGET/bundle/dmg" -name '*.dmg' -print -quit)"
test -n "$DMG"
node scripts/verify-artifact.mjs --kind dmg "$DMG"
hdiutil verify "$DMG"

SIGNING_MODE="$(tr -d '[:space:]' < src-tauri/target/macos-code-signing.txt 2>/dev/null || true)"
signature="$(codesign -dv --verbose=4 "$APP" 2>&1 || true)"
printf '%s\n' "$signature"
if [[ "$SIGNING_MODE" == "signed" ]]; then
  if [[ "$signature" != *"Developer ID"* ]]; then
    echo "error: build was marked signed but codesign does not show a Developer ID signature" >&2
    exit 1
  fi
  codesign --verify --deep --strict --verbose=2 "$APP"
  spctl --assess --type execute --verbose=4 "$APP"
  echo "macOS bundle is Developer ID signed"
else
  if [[ "$signature" == *"Developer ID"* ]]; then
    echo "error: refusing to treat this artifact as unsigned while a Developer ID signature is present" >&2
    exit 1
  fi
  if [[ "$signature" != *"Signature=adhoc"* ]]; then
    echo "error: unsigned universal build has no ad-hoc signature, so Apple Silicon cannot execute it" >&2
    exit 1
  fi
  echo "::warning::This macOS artifact is not Developer ID signed. It only has an ad-hoc signature so the universal binary can run. Replace GitHub Actions secrets APPLE_CERTIFICATE (base64 of a Developer ID PKCS#12, or a PEM bundle with the certificate and private key) and APPLE_CERTIFICATE_PASSWORD (the matching export password)."
fi

if [[ -n "${TAURI_SIGNING_PRIVATE_KEY:-}" ]]; then
  TGZ="$(find "$TARGET/bundle/macos" -name '*.app.tar.gz' -print -quit)"
  test -n "$TGZ"
  node scripts/verify-artifact.mjs --kind gzip "$TGZ"
  SIG="$(find "$TARGET/bundle/macos" -name '*.app.tar.gz.sig' -print -quit)"
  test -n "$SIG"
  node scripts/verify-artifact.mjs --kind sig "$SIG"
else
  echo "::warning::TAURI_SIGNING_PRIVATE_KEY is not set. Updater metadata will not be published."
fi
