use std::path::PathBuf;
use std::sync::Mutex;
use tauri::Manager;

use crate::crypto;

#[cfg(not(target_os = "macos"))]
use std::sync::atomic::Ordering;

#[cfg(not(target_os = "macos"))]
use crate::wg_tunnel::WgSession;

pub struct AppState {
    pub pending_config: Mutex<Option<Vec<u8>>>,
    #[cfg(not(target_os = "macos"))]
    pub session: tokio::sync::Mutex<Option<WgSession>>,
    #[cfg(target_os = "macos")]
    pub daemon_stream: tokio::sync::Mutex<Option<tokio::net::UnixStream>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            pending_config: Mutex::new(None),
            #[cfg(not(target_os = "macos"))]
            session: tokio::sync::Mutex::new(None),
            #[cfg(target_os = "macos")]
            daemon_stream: tokio::sync::Mutex::new(None),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct StoredState {
    has_config: bool,
    has_password: bool,
    connection_name: Option<String>,
}

#[derive(serde::Serialize)]
pub struct StatusResult {
    pub has_config: bool,
    pub has_password: bool,
    pub is_connected: bool,
    pub connection_name: Option<String>,
}

#[derive(serde::Serialize)]
pub struct StatsResult {
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub connection_name: Option<String>,
}

fn state_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    Ok(app.path().app_data_dir().map_err(|e| e.to_string())?.join("state.json"))
}

fn config_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    Ok(app.path().app_data_dir().map_err(|e| e.to_string())?.join("config.enc"))
}

fn ensure_data_dir(app: &tauri::AppHandle) -> Result<(), String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())
}

fn read_state(app: &tauri::AppHandle) -> StoredState {
    let Ok(path) = state_path(app) else { return StoredState::default() };
    let Ok(s) = std::fs::read_to_string(path) else { return StoredState::default() };
    serde_json::from_str(&s).unwrap_or_default()
}

fn write_state(app: &tauri::AppHandle, s: &StoredState) -> Result<(), String> {
    ensure_data_dir(app)?;
    let content = serde_json::to_string(s).map_err(|e| e.to_string())?;
    std::fs::write(state_path(app)?, content).map_err(|e| e.to_string())
}

// ── Commands ──────────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn check_status(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<StatusResult, String> {
    let stored = read_state(&app);

    #[cfg(target_os = "macos")]
    let is_connected = state.daemon_stream.lock().await.is_some();
    #[cfg(not(target_os = "macos"))]
    let is_connected = state.session.lock().await.is_some();

    let has_config = if stored.has_config && stored.has_password {
        config_path(&app).map(|p| p.exists()).unwrap_or(false)
    } else if stored.has_config {
        state.pending_config.lock().unwrap().is_some()
    } else {
        false
    };

    Ok(StatusResult {
        has_config,
        has_password: stored.has_password && has_config,
        is_connected,
        connection_name: stored.connection_name,
    })
}

#[tauri::command]
pub async fn detect_config_type(file_path: String) -> Result<String, String> {
    let data = std::fs::read(&file_path).map_err(|e| format!("Cannot read file: {}", e))?;
    if crypto::is_encrypted(&data) {
        Ok("encrypted".into())
    } else if crypto::is_plain_wireguard(&data) {
        Ok("plain".into())
    } else {
        Err("File is not a valid WireGuard config or supported encrypted format.".into())
    }
}

#[tauri::command]
pub async fn import_config(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    file_path: String,
    password: Option<String>,
) -> Result<(), String> {
    let data = std::fs::read(&file_path).map_err(|e| format!("Cannot read file: {}", e))?;

    let plaintext = if crypto::is_encrypted(&data) {
        let pwd = password.ok_or("Encrypted file requires a decryption password.")?;
        crypto::decrypt_imported(&data, &pwd)?
    } else if crypto::is_plain_wireguard(&data) {
        data
    } else {
        return Err("Not a valid WireGuard config or supported encrypted format.".into());
    };

    let conf_str = std::str::from_utf8(&plaintext).map_err(|_| "Config is not valid UTF-8.")?;
    if !conf_str.contains("[Interface]") {
        return Err("File does not appear to be a WireGuard configuration.".into());
    }

    let connection_name = crate::wg_config::parse(conf_str).ok().and_then(|c| c.name);

    *state.pending_config.lock().unwrap() = Some(plaintext);
    ensure_data_dir(&app)?;
    write_state(&app, &StoredState { has_config: true, has_password: false, connection_name })
}

#[tauri::command]
pub async fn setup_connection_password(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    password: String,
) -> Result<(), String> {
    let plaintext = state
        .pending_config
        .lock()
        .unwrap()
        .clone()
        .ok_or("No config in memory. Please import again.")?;

    let encrypted = crypto::encrypt_for_storage(&plaintext, &password)?;

    ensure_data_dir(&app)?;
    std::fs::write(config_path(&app)?, &encrypted)
        .map_err(|e| format!("Failed to save config: {}", e))?;

    let connection_name = read_state(&app).connection_name;
    *state.pending_config.lock().unwrap() = None;
    write_state(&app, &StoredState { has_config: true, has_password: true, connection_name })
}

#[tauri::command]
pub async fn connect(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    password: String,
) -> Result<(), String> {
    let encrypted = std::fs::read(config_path(&app)?)
        .map_err(|_| "No config found. Please import first.")?;
    let plaintext = crypto::decrypt_from_storage(&encrypted, &password)?;
    let conf_str =
        String::from_utf8(plaintext).map_err(|_| "Config content is invalid UTF-8.")?;

    #[cfg(target_os = "macos")]
    {
        use crate::tunnel_daemon;
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let exe = std::env::current_exe()
            .map_err(|e| format!("Cannot get binary path: {}", e))?
            .to_string_lossy()
            .into_owned();

        if !tunnel_daemon::is_installed() {
            tunnel_daemon::install(&exe)?;
        }

        let config_b64 = B64.encode(conf_str.as_bytes());

        let stream = tokio::net::UnixStream::connect(tunnel_daemon::SOCKET_PATH)
            .await
            .map_err(|e| format!("Cannot reach helper daemon: {}. Try restarting the app.", e))?;

        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = BufReader::new(reader);

        writer
            .write_all(format!("START {}\n", config_b64).as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        writer.flush().await.ok();

        let mut response = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            buf_reader.read_line(&mut response),
        )
        .await
        .map_err(|_| "Daemon did not respond in time.".to_string())?
        .map_err(|e| e.to_string())?;

        let response = response.trim().to_string();

        if response.starts_with("ERROR") {
            return Err(response[6..].to_string());
        }
        if !response.starts_with("READY") {
            return Err(format!("Unexpected daemon response: {}", response));
        }

        let read_half = buf_reader.into_inner();
        let stream = read_half
            .reunite(writer)
            .map_err(|_| "Failed to reunite stream halves".to_string())?;

        *state.daemon_stream.lock().await = Some(stream);
    }

    #[cfg(not(target_os = "macos"))]
    {
        use crate::wg_tunnel::WgSession;
        let session = WgSession::start(&conf_str).await?;
        *state.session.lock().await = Some(session);
    }

    Ok(())
}

#[tauri::command]
pub async fn disconnect(state: tauri::State<'_, AppState>) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        use tokio::io::AsyncWriteExt;

        let mut stream_guard = state.daemon_stream.lock().await;
        if let Some(mut stream) = stream_guard.take() {
            let _ = stream.write_all(b"STOP\n").await;
            let _ = stream.flush().await;
        } else {
            return Err("Not connected.".into());
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        let session = state
            .session
            .lock()
            .await
            .take()
            .ok_or("Not connected.")?;
        session.stop()?;
    }

    Ok(())
}

#[tauri::command]
pub async fn reset_config(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    if let Ok(p) = config_path(&app) {
        let _ = std::fs::remove_file(p);
    }
    if let Ok(p) = state_path(&app) {
        let _ = std::fs::remove_file(p);
    }
    *state.pending_config.lock().unwrap() = None;
    Ok(())
}

#[tauri::command]
pub async fn get_stats(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<StatsResult, String> {
    let connection_name = read_state(&app).connection_name;

    #[cfg(target_os = "macos")]
    {
        use crate::tunnel_daemon;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let is_connected = state.daemon_stream.lock().await.is_some();
        if !is_connected {
            return Ok(StatsResult { bytes_tx: 0, bytes_rx: 0, connection_name });
        }

        let mut stream = tokio::net::UnixStream::connect(tunnel_daemon::SOCKET_PATH)
            .await
            .map_err(|e| format!("Stats connect: {}", e))?;
        stream.write_all(b"STATS\n").await.map_err(|e| e.to_string())?;
        let mut buf = vec![0u8; 64];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read(&mut buf),
        )
        .await
        .map_err(|_| "Stats timeout".to_string())?
        .map_err(|e| e.to_string())?;
        let s = String::from_utf8_lossy(&buf[..n]);
        let mut parts = s.split_whitespace();
        let tx = parts.next().and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
        let rx = parts.next().and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
        return Ok(StatsResult { bytes_tx: tx, bytes_rx: rx, connection_name });
    }

    #[cfg(not(target_os = "macos"))]
    {
        let session = state.session.lock().await;
        let (tx, rx) = if let Some(s) = session.as_ref() {
            (
                s.bytes_tx.load(Ordering::Relaxed),
                s.bytes_rx.load(Ordering::Relaxed),
            )
        } else {
            (0, 0)
        };
        Ok(StatsResult { bytes_tx: tx, bytes_rx: rx, connection_name })
    }
}

#[tauri::command]
pub async fn quit_app(app: tauri::AppHandle) {
    app.exit(0);
}

#[tauri::command]
pub async fn uninstall_helper() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        use crate::tunnel_daemon;
        let script = format!(
            "launchctl unload -w '{plist}' 2>/dev/null; \
             rm -f '{plist}'; \
             rm -f '{helper}'",
            plist = tunnel_daemon::PLIST_DEST,
            helper = tunnel_daemon::HELPER_DEST,
        );
        let apple_script = format!(
            "do shell script \"{}\" with administrator privileges",
            script.replace('"', "\\\"")
        );
        let out = std::process::Command::new("osascript")
            .args(["-e", &apple_script])
            .output()
            .map_err(|e| format!("osascript failed: {}", e))?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).to_string());
        }
    }
    Ok(())
}
