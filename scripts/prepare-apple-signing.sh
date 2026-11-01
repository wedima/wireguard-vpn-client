# Source this from the macOS build step. It unsets Apple signing variables
# when the certificate cannot be imported, so Tauri still produces a universal
# binary. It never prints secret values.
macos_signing=unsigned
if [[ -n "${APPLE_CERTIFICATE:-}" && -n "${APPLE_CERTIFICATE_PASSWORD:-}" ]]; then
  cert_file="$(mktemp)"
  if python3 -c 'import os,base64,pathlib,sys
data=base64.b64decode(os.environ.get("APPLE_CERTIFICATE",""), validate=False)
pathlib.Path(sys.argv[1]).write_bytes(data)
pem=b"BEGIN CERTIFICATE" in data
sys.exit(0 if (data.startswith(b"\x30") or pem) else 3)' "$cert_file"; then
    if openssl pkcs12 -in "$cert_file" -nokeys -passin env:APPLE_CERTIFICATE_PASSWORD >/dev/null 2>&1 \
      || openssl pkcs12 -in "$cert_file" -nokeys -legacy -passin env:APPLE_CERTIFICATE_PASSWORD >/dev/null 2>&1 \
      || { grep -q "BEGIN CERTIFICATE" "$cert_file" && grep -Eq "BEGIN (RSA |EC |ENCRYPTED )?PRIVATE KEY" "$cert_file"; }; then
      macos_signing=signed
    fi
  fi
  rm -f "$cert_file"
fi

mkdir -p src-tauri/target
printf '%s\n' "$macos_signing" > src-tauri/target/macos-code-signing.txt

if [[ "$macos_signing" != "signed" ]]; then
  echo "::warning::APPLE_CERTIFICATE is missing or not a PKCS#12 file or PEM bundle with its private key, or APPLE_CERTIFICATE_PASSWORD does not match. The universal binary will only receive an ad-hoc signature so Apple Silicon can launch it. Replace those two GitHub Actions secrets. This artifact is not Developer ID signed."
  unset APPLE_CERTIFICATE APPLE_CERTIFICATE_PASSWORD APPLE_SIGNING_IDENTITY APPLE_ID APPLE_PASSWORD APPLE_TEAM_ID
fi
