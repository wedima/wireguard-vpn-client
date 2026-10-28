# Release Guide

## Voraussetzungen

- Sauberer `main`-Branch (alle Änderungen committed & gepusht)
- GitHub Actions auf dem Repository aktiviert
- `pnpm` installiert

> **Windows ARM64**: Der Job baut nativ mit `aarch64-pc-windows-msvc` auf `windows-11-arm`. Schlägt der Runner fehl, werden macOS und Windows x64 trotzdem veröffentlicht; ARM64 lädt dann nichts hoch.

---

## Release erstellen

### 1. Branch prüfen

```bash
git status        # muss sauber sein
git pull          # aktuellsten Stand holen
```

### 2. Release-Kommando ausführen

```bash
pnpm run release:patch   # Bugfix        0.1.0 → 0.1.1
pnpm run release:minor   # Feature       0.1.0 → 0.2.0
pnpm run release:major   # Breaking      0.1.0 → 1.0.0
```

Das Script macht automatisch:
- Version in `package.json`, `src-tauri/tauri.conf.json` und `src-tauri/Cargo.toml` bumpen
- Commit erstellen (`chore: release vX.Y.Z`)
- Git-Tag setzen und pushen
- GitHub Actions startet sofort

### 3. GitHub Actions beobachten

Unter **GitHub → Actions → Release** läuft der Workflow mit drei parallelen Jobs:

| Job | Runner | Output |
|-----|--------|--------|
| macOS Universal | `macos-latest` | `.dmg` (x64 + ARM64 in einem Binary) |
| Windows x64 | `windows-latest` | `.exe` + `.msi` |
| Windows ARM64 | `windows-11-arm` | `.exe` + `.msi` |

Nach Abschluss aller drei Jobs wird automatisch ein **GitHub Release** mit allen Dateien erstellt.

---

## Windows nachliefern (zu bestehendem Release)

Falls der Windows-Build gefailed ist oder nachträglich hinzugefügt werden soll:

1. GitHub → **Actions** → **"Release Windows (Nachliefern)"**
2. **Run workflow** klicken
3. Eingaben:
   - **Tag**: z.B. `v0.1.1` (muss bereits als Release existieren)
   - **Target**: `both` / `x64` / `arm64`
4. Der Workflow checkt exakt diesen Tag-Stand aus, baut und lädt die Dateien in das **bestehende** Release hoch

---

## Versionsnummern-Konvention

Schema: `MAJOR.MINOR.PATCH`

| Typ | Wann | Beispiel |
|-----|------|---------|
| `patch` | Bugfixes, kleine Korrekturen | `0.1.0 → 0.1.1` |
| `minor` | Neue Features, abwärtskompatibel | `0.1.0 → 0.2.0` |
| `major` | Breaking Changes, Protokolländerungen | `0.1.0 → 1.0.0` |

Pre-Release Tags (z.B. `v1.0.0-beta.1`) werden von GitHub automatisch als **Pre-Release** markiert.

---

## Lokaler macOS-Build (zum Testen)

```bash
pnpm run build:mac
```

Output: `src-tauri/target/universal-apple-darwin/release/bundle/`

> Dieser Build ist **nicht signiert/notarisiert** — für interne Tests ausreichend, für Endnutzer muss macOS-Codesigning eingerichtet werden (siehe unten).

---

## Wichtige Hinweise

### Release-Prüfung

Jeder Plattform-Job bricht ab, wenn das Paket strukturell ungültig ist:

- macOS: universelles Binary (`lipo` enthält x86_64 und arm64), `--version` antwortet, Bundle-ID stimmt, DMG-Trailer und `hdiutil verify`
- Windows: `--version` startet die EXE, NSIS ist ein PE der richtigen Architektur, MSI hat einen OLE-Header, `wintun.dll` liegt neben der EXE
- Der Release-Job prüft die hochgeladenen Dateien noch einmal und legt `latest.json` **nur** an, wenn jede Updater-Datei eine Minisign-Signatur hat

Ohne die Signatur-Secrets bleiben die Installer veröffentlicht, aber es gibt kein `latest.json`. Die App installiert dann kein Update.

### macOS Codesigning & Notarisierung
Ohne Signierung zeigt macOS eine Sicherheitswarnung. Für signierte Builds folgende GitHub Secrets setzen:

| Secret | Beschreibung |
|--------|-------------|
| `APPLE_CERTIFICATE` | Base64-kodiertes `.p12` Zertifikat |
| `APPLE_CERTIFICATE_PASSWORD` | Passwort des Zertifikats |
| `APPLE_SIGNING_IDENTITY` | z.B. `Developer ID Application: Firmenname (TEAMID)` |
| `APPLE_ID` | Apple Developer Account E-Mail |
| `APPLE_PASSWORD` | App-spezifisches Passwort (nicht das Account-Passwort) |
| `APPLE_TEAM_ID` | 10-stellige Team-ID aus dem Apple Developer Portal |

Danach in `release.yml` beim macOS-Job ergänzen:
```yaml
env:
  APPLE_CERTIFICATE: ${{ secrets.APPLE_CERTIFICATE }}
  APPLE_CERTIFICATE_PASSWORD: ${{ secrets.APPLE_CERTIFICATE_PASSWORD }}
  APPLE_SIGNING_IDENTITY: ${{ secrets.APPLE_SIGNING_IDENTITY }}
  APPLE_ID: ${{ secrets.APPLE_ID }}
  APPLE_PASSWORD: ${{ secrets.APPLE_PASSWORD }}
  APPLE_TEAM_ID: ${{ secrets.APPLE_TEAM_ID }}
```

### Automatische Updates

Die App prüft nur `https://github.com/wedima/wireguard-vpn-client/releases/latest/download/latest.json`. Ohne die beiden Secrets unten schreibt der Workflow **kein** `latest.json`. Die App installiert dann kein Update. Ein Artefakt ohne gültige Minisign-Signatur, mit einer anderen Version im Trusted Comment, oder von einer anderen URL wird verworfen.

Der Public Key steht in `src-tauri/tauri.conf.json` (`plugins.updater.pubkey`). Die Secrets müssen zu genau diesem Key passen:

| Secret | Wert |
|--------|------|
| `TAURI_SIGNING_PRIVATE_KEY` | Gesamter Inhalt der Private-Key-Datei, ohne sie ins Repo zu committen |
| `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` | Passwort dieser Datei, ebenfalls nur als Secret |

Dieses Environment kann die Secrets nicht setzen (GitHub antwortet mit 403). Der Repo-Owner muss sie unter **Settings → Secrets and variables → Actions** anlegen. Danach signiert `tauri build` die Updater-Artefakte, und der Release-Job veröffentlicht `latest.json` nur wenn jede Datei eine Signatur hat.

### Windows Code Signing
Ohne Signierung zeigt Windows SmartScreen eine Warnung. Für signierte Builds:

| Secret | Beschreibung |
|--------|-------------|
| `WINDOWS_CERTIFICATE` | Base64-kodiertes `.pfx` Zertifikat |
| `WINDOWS_CERTIFICATE_PASSWORD` | Passwort des Zertifikats |

### wintun.dll
Das Projekt enthält `wintun.dll` für den WireGuard-Tunnel auf Windows. Die `build.rs` kopiert automatisch die korrekte Architektur-Version (`amd64` / `arm64`) — keine manuelle Anpassung nötig.

### Cargo.lock committen
`Cargo.lock` sollte **committed** sein (für Binaries empfohlen), damit Builds reproduzierbar sind.
