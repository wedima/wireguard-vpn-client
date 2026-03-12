# Release Guide

## Voraussetzungen

- Sauberer `main`-Branch (alle Änderungen committed & gepusht)
- GitHub Actions auf dem Repository aktiviert
- `pnpm` installiert

> **Windows ARM64**: Der `windows-11-arm` Runner benötigt GitHub **Team oder Enterprise**. Bei Free/Pro-Plan den Runner in beiden Workflows auf `windows-latest` ändern und `rustup target add aarch64-pc-windows-msvc` ergänzen (Cross-Compilation, kann bei nativen Abhängigkeiten eingeschränkt sein).

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
