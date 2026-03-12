# Wedima VPN WG

A simple, secure, cross-platform WireGuard VPN client built with **Tauri 2** (Rust) + **React** + **TypeScript**.

The user **never sees or touches** the raw WireGuard configuration. Everything is encrypted at rest using **argon2id + AES-256-GCM**. The VPN tunnel runs entirely in userspace via [boringtun](https://github.com/cloudflare/boringtun) — **no external WireGuard installation required**.

---

## How It Works

```
[SETUP – once]
  Admin encrypts wg.conf → sends encrypted file to user
  User imports file + enters Admin password → config decrypted in RAM
  User sets personal connection password → config re-encrypted on disk

[EVERY CONNECTION]
  User enters personal password → config decrypted in RAM
  Userspace WireGuard tunnel created in-process (boringtun)
  No plaintext config is ever written to disk
```

### Two Separate Passwords

| | Password 1 (Import) | Password 2 (Connect) |
|---|---|---|
| **Source** | Admin / Provider | Set by the user |
| **Used when** | One-time import | Every connection |
| **Purpose** | Decrypt the delivered file | Unlock the stored config |

---

## Features

- Import **encrypted** (`.enc`) or **plain** WireGuard `.conf` files
- Config is **never stored unencrypted** on disk
- User can **never view or edit** the raw config
- Personal connection password set on first connect, required for every reconnect
- One-button **connect / disconnect**
- Live **traffic statistics** (↑ upload / ↓ download) updated every second
- **Connection name** displayed from `# Client name:` comment in config
- **English + German UI translations** (auto-detected from system language, user-switchable)
- **IPv6 kill switch** — disables ISP IPv6 when the VPN server doesn't provide an IPv6 tunnel, preventing leaks on public Wi-Fi
- **System tray** — minimizes to tray, click to show/hide, right-click menu
- Settings menu: Delete Connection, Uninstall Helper, Quit Application
- **No external dependencies** — boringtun userspace WireGuard is bundled

---

## Requirements

### All Platforms
- [Node.js](https://nodejs.org/) 18+
- [Rust](https://rustup.rs/) (stable)
- [pnpm](https://pnpm.io/) (or npm/yarn)

### macOS — Privileged Helper

On macOS, creating VPN network interfaces requires root. The app installs a **LaunchDaemon helper** automatically on first connect. You will see a macOS system prompt asking for administrator credentials — this is expected and required.

The helper runs only while the app is running and can be removed via **Settings → Uninstall Helper**.

### Windows / Linux

The app uses a userspace TUN device (via platform APIs). No special setup required on most systems. On Linux, your user may need to be in the `tun` group:
```bash
sudo usermod -aG tun $USER
```

---

## Localization (i18n)

The frontend uses `i18next` + `react-i18next` with JSON locale files.

- Locale files:
  - `src/i18n/locales/en.json`
  - `src/i18n/locales/de.json`
- Initialization:
  - `src/i18n/index.ts`
- Language selector UI:
  - `src/components/LanguageSwitcher.tsx`

### Behavior

- On first run, language is auto-detected from the OS/webview language (`navigator.language`).
- The selected language is cached in `localStorage` and reused on next launch.
- This behavior works the same way in Tauri WebView on macOS, Windows, and Linux.

### Add a New Language

1. Create `src/i18n/locales/<code>.json` by copying `en.json`.
2. Add the locale in `src/i18n/index.ts` resources and `supportedLngs`.
3. Add an option to `src/components/LanguageSwitcher.tsx`.
4. Keep keys stable; translate values only.

---

## Development

This project is standardized on **pnpm**. Keep Tauri hook commands (`beforeDevCommand` / `beforeBuildCommand`) in `src-tauri/tauri.conf.json` set to `pnpm run ...` to avoid npm-specific environment warning noise and keep builds consistent.

```bash
# Install frontend dependencies
pnpm install

# Run in development mode (hot reload)
pnpm run tauri dev

# Build for production (produces .app on macOS, .exe on Windows, AppImage on Linux)
pnpm run tauri build
```

---

## Creating Encrypted Config Files (Admin)

Use one of the included admin scripts to encrypt a WireGuard config for distribution:

```bash
python3 -m pip install cryptography argon2-cffi
python3 scripts/encrypt-config.py wg0.conf wg0.enc

# or Node.js version
pnpm add argon2
node scripts/encrypt-config.mjs wg0.conf wg0.enc
```

The script prompts for a password and produces a `.enc` file to distribute to users. Alternatively, a plain `.conf` file can be imported directly — the app will detect it automatically.

### Encrypted File Format

```
[6 bytes]   Magic: "WGCV1\0"
[32 bytes]  argon2id salt
[12 bytes]  AES-GCM nonce
[N bytes]   AES-256-GCM ciphertext
```

**argon2id parameters:** `m=19456`, `t=2`, `p=1`

### Optional: Name Your Config

Add a comment at the top of your `wg.conf` to display a friendly name in the app:

```ini
# Client name: My Company VPN
[Interface]
...
```

---

## Project Structure

```
wedima-vpn-wg/
├── src/                            # React frontend
│   ├── assets/
│   │   └── wedima-logo.svg         # Wedima logo (shown in app header)
│   ├── screens/
│   │   ├── ImportScreen.tsx        # Step 1 – import config (encrypted or plain)
│   │   ├── SetupPasswordScreen.tsx # Step 2 – set personal connection password
│   │   └── ConnectScreen.tsx       # Step 3 – connect / disconnect + stats
│   ├── App.tsx                     # Screen router
│   └── index.css
├── src-tauri/                      # Rust backend (Tauri)
│   ├── icons/                      # App icons (PNG, ICNS, ICO)
│   └── src/
│       ├── crypto.rs               # argon2id + AES-256-GCM
│       ├── wg_config.rs            # WireGuard config parser
│       ├── tunnel_daemon.rs        # macOS privileged helper (boringtun + utun)
│       ├── wg_tunnel.rs            # Windows/Linux userspace tunnel (boringtun)
│       ├── wireguard.rs            # Platform routing helpers
│       ├── commands.rs             # All Tauri IPC commands
│       ├── lib.rs                  # App setup + system tray
│       └── main.rs
├── scripts/
│   ├── encrypt-config.py           # Admin Python tool to create .enc files
│   └── encrypt-config.mjs          # Admin Node.js tool to create .enc files
├── .gitignore
└── README.md
```

---

## Security Notes

- The WireGuard config is **never written to disk in plaintext** at any point.
- Key derivation uses **argon2id** (memory-hard, resistant to GPU brute-force).
- Encryption uses **AES-256-GCM** (authenticated encryption — detects tampering).
- The stored `config.enc` can only be decrypted by someone who knows the user's personal password.
- The import password (Admin password) is only used transiently during import and is never stored.
- IPv6 is disabled on the host when the tunnel does not carry IPv6, preventing address leaks on untrusted networks.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Framework | [Tauri 2](https://tauri.app/) |
| Frontend | React 18 + TypeScript + Tailwind CSS |
| Backend | Rust |
| Encryption | `aes-gcm` + `argon2` (Rust crates) |
| VPN Engine | [boringtun](https://crates.io/crates/boringtun) (userspace WireGuard) |
| Icons | `lucide-react` |
| macOS VPN | utun socket + LaunchDaemon privileged helper |
| Windows/Linux VPN | TUN device via `tun2` |
