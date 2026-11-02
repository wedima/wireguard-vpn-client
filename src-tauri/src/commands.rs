use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tauri::Manager;
use zeroize::Zeroize;

use crate::crypto;
use crate::secret_file;

const MAX_CONFIG_BYTES: u64 = 256 * 1024;
const MIN_PASSWORD_CHARS: usize = 8;

struct Wipe(String);

impl Drop for Wipe {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(target_os = "windows")]
fn is_elevated() -> bool {
    use windows_sys::Win32::UI::Shell::IsUserAnAdmin;
    unsafe { IsUserAnAdmin() != 0 }
}

#[cfg(target_os = "windows")]
fn relaunch_as_admin(app: &tauri::AppHandle) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe_wide: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0u16)).collect();
    let verb: Vec<u16> = "runas\0".encode_utf16().collect();

    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            exe_wide.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL as i32,
        )
    };

    if result as isize <= 32 {
        return Err("Konnte die App nicht als Administrator starten. Bitte manuell als Administrator ausführen.".to_string());
    }

    std::process::exit(0);
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
use std::sync::atomic::Ordering;

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
use crate::wg_tunnel::WgSession;

pub struct AppState {
    pub pending_config: Mutex<Option<Vec<u8>>>,
    #[cfg(target_os = "macos")]
    pub daemon_stream: tokio::sync::Mutex<Option<tokio::net::UnixStream>>,
    #[cfg(target_os = "windows")]
    pub daemon_stream: tokio::sync::Mutex<Option<tokio::net::windows::named_pipe::NamedPipeClient>>,
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    pub session: tokio::sync::Mutex<Option<WgSession>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            pending_config: Mutex::new(None),
            #[cfg(target_os = "macos")]
            daemon_stream: tokio::sync::Mutex::new(None),
            #[cfg(target_os = "windows")]
            daemon_stream: tokio::sync::Mutex::new(None),
            #[cfg(not(any(target_os = "macos", target_os = "windows")))]
            session: tokio::sync::Mutex::new(None),
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
    Ok(app
        .path()
        .app_data_dir()
        .map_err(|e| e.to_string())?
        .join("state.json"))
}

fn config_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    Ok(app
        .path()
        .app_data_dir()
        .map_err(|e| e.to_string())?
        .join("config.enc"))
}

fn ensure_data_dir(app: &tauri::AppHandle) -> Result<(), String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

fn read_limited_file(path: &Path) -> Result<Vec<u8>, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("Cannot read file: {}", e))?;
    if !meta.is_file() {
        return Err("Not a file.".into());
    }
    if meta.len() > MAX_CONFIG_BYTES {
        return Err("Config file is too large.".into());
    }
    std::fs::read(path).map_err(|e| format!("Cannot read file: {}", e))
}

fn read_state(app: &tauri::AppHandle) -> StoredState {
    let Ok(path) = state_path(app) else {
        return StoredState::default();
    };
    let Ok(s) = std::fs::read_to_string(path) else {
        return StoredState::default();
    };
    serde_json::from_str(&s).unwrap_or_default()
}

fn write_state(app: &tauri::AppHandle, s: &StoredState) -> Result<(), String> {
    ensure_data_dir(app)?;
    let content = serde_json::to_vec(s).map_err(|e| e.to_string())?;
    secret_file::write_private(&state_path(app)?, &content)
}

// ── Commands ──────────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn check_status(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<StatusResult, String> {
    let stored = read_state(&app);

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    let is_connected = state.daemon_stream.lock().await.is_some();
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
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
    let data = read_limited_file(Path::new(&file_path))?;
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
    let data = read_limited_file(Path::new(&file_path))?;

    let mut password = password;
    let plaintext = if crypto::is_encrypted(&data) {
        let pwd = password
            .as_deref()
            .ok_or("Encrypted file requires a decryption password.")?;
        crypto::decrypt_imported(&data, pwd)?
    } else if crypto::is_plain_wireguard(&data) {
        data
    } else {
        return Err("Not a valid WireGuard config or supported encrypted format.".into());
    };

    let conf_str = std::str::from_utf8(&plaintext).map_err(|_| "Config is not valid UTF-8.")?;
    let parsed = crate::wg_config::parse(conf_str)?;
    let connection_name = parsed.name;

    if let Some(previous) = state.pending_config.lock().unwrap().replace(plaintext) {
        let mut previous = previous;
        previous.zeroize();
    }
    if let Some(pwd) = password.as_mut() {
        pwd.zeroize();
    }
    ensure_data_dir(&app)?;
    write_state(
        &app,
        &StoredState {
            has_config: true,
            has_password: false,
            connection_name,
        },
    )
}

#[tauri::command]
pub async fn setup_connection_password(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    password: String,
) -> Result<(), String> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err("Password must be at least 8 characters.".into());
    }
    let mut password = password;
    let mut plaintext = state
        .pending_config
        .lock()
        .unwrap()
        .take()
        .ok_or("No config in memory. Please import again.")?;

    let encrypted = crypto::encrypt_for_storage(&plaintext, &password);
    plaintext.zeroize();
    password.zeroize();
    let encrypted = encrypted?;

    ensure_data_dir(&app)?;
    secret_file::write_private(&config_path(&app)?, &encrypted)?;

    let connection_name = read_state(&app).connection_name;
    write_state(
        &app,
        &StoredState {
            has_config: true,
            has_password: true,
            connection_name,
        },
    )
}

#[tauri::command]
pub async fn connect(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    password: String,
) -> Result<(), String> {
    let mut password = password;
    let encrypted =
        std::fs::read(config_path(&app)?).map_err(|_| "No config found. Please import first.")?;
    let plaintext = crypto::decrypt_from_storage(&encrypted, &password);
    password.zeroize();
    let plaintext = plaintext?;
    let mut conf_str = match String::from_utf8(plaintext) {
        Ok(text) => Wipe(text),
        Err(err) => {
            let mut bytes = err.into_bytes();
            bytes.zeroize();
            return Err("Config content is invalid UTF-8.".into());
        }
    };
    // Parsing here rejects configs that would be unsafe to hand to the helper.
    crate::wg_config::parse(&conf_str.0)?;

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        use crate::tunnel_daemon;
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let exe = std::env::current_exe()
            .map_err(|e| format!("Cannot get binary path: {}", e))?
            .to_string_lossy()
            .into_owned();

        if !tunnel_daemon::helper_is_current(&exe) {
            tunnel_daemon::install(&exe)?;
        }

        let config_b64 = Wipe(B64.encode(conf_str.0.as_bytes()));
        conf_str.0.zeroize();

        #[cfg(target_os = "macos")]
        let stream_res = tokio::net::UnixStream::connect(tunnel_daemon::SOCKET_PATH).await;
        #[cfg(target_os = "windows")]
        let stream_res = tunnel_daemon::open_helper_pipe().await;

        let stream = stream_res
            .map_err(|e| format!("Cannot reach helper daemon: {e}. Try restarting the app."))?;
        let mut stream = stream;

        stream
            .write_all(b"START ")
            .await
            .map_err(|e| e.to_string())?;
        stream
            .write_all(config_b64.0.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        stream.write_all(b"\n").await.map_err(|e| e.to_string())?;
        stream.flush().await.ok();

        let mut response = String::new();
        {
            let mut buf_reader = BufReader::new(&mut stream);
            tokio::time::timeout(
                std::time::Duration::from_secs(30),
                buf_reader.read_line(&mut response),
            )
            .await
            .map_err(|_| "Daemon did not respond in time.".to_string())?
            .map_err(|e| e.to_string())?;
        }

        let response = response.trim().to_string();

        if response.starts_with("ERROR") {
            return Err(response[6..].to_string());
        }
        if !response.starts_with("READY") {
            return Err(format!("Unexpected daemon response: {}", response));
        }

        *state.daemon_stream.lock().await = Some(stream);
    }

    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    {
        use crate::wg_tunnel::WgSession;
        let session = WgSession::start(&conf_str.0).await?;
        conf_str.0.zeroize();
        *state.session.lock().await = Some(session);
    }

    Ok(())
}

#[tauri::command]
pub async fn disconnect(state: tauri::State<'_, AppState>) -> Result<(), String> {
    #[cfg(any(target_os = "macos", target_os = "windows"))]
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

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let session = state.session.lock().await.take().ok_or("Not connected.")?;
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
        let _ = secret_file::shred_remove(&p);
    }
    if let Ok(p) = state_path(&app) {
        let _ = secret_file::shred_remove(&p);
    }
    if let Some(mut pending) = state.pending_config.lock().unwrap().take() {
        pending.zeroize();
    }
    Ok(())
}

#[tauri::command]
pub async fn get_stats(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<StatsResult, String> {
    let connection_name = read_state(&app).connection_name;

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        use crate::tunnel_daemon;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let is_connected = state.daemon_stream.lock().await.is_some();
        if !is_connected {
            return Ok(StatsResult {
                bytes_tx: 0,
                bytes_rx: 0,
                connection_name,
            });
        }

        #[cfg(target_os = "macos")]
        let stream_res = tokio::net::UnixStream::connect(tunnel_daemon::SOCKET_PATH).await;
        #[cfg(target_os = "windows")]
        let stream_res = tunnel_daemon::open_helper_pipe().await;

        let mut stream = stream_res.map_err(|e| format!("Stats connect: {}", e))?;

        stream
            .write_all(b"STATS\n")
            .await
            .map_err(|e| e.to_string())?;
        stream.flush().await.map_err(|e| e.to_string())?;

        let mut line = String::new();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let mut reader = BufReader::new(&mut stream);
            reader.read_line(&mut line).await
        })
        .await
        .map_err(|_| "Stats timeout".to_string())?
        .map_err(|e| e.to_string())?;

        let mut parts = line.split_whitespace();
        let tx = parts
            .next()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        let rx = parts
            .next()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        return Ok(StatsResult {
            bytes_tx: tx,
            bytes_rx: rx,
            connection_name,
        });
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
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
        Ok(StatsResult {
            bytes_tx: tx,
            bytes_rx: rx,
            connection_name,
        })
    }
}

#[tauri::command]
pub async fn quit_app(_app: tauri::AppHandle) {
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    crate::tunnel_daemon::request_shutdown().await;
    std::process::exit(0);
}

#[tauri::command]
pub async fn uninstall_helper() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        use crate::tunnel_daemon;
        let script = format!(
            "launchctl unload -w '{plist}' 2>/dev/null; \
             rm -f '{plist}' '{helper}' '{uid}' '{version}' '{client}' '{socket}'",
            plist = tunnel_daemon::PLIST_DEST,
            helper = tunnel_daemon::HELPER_DEST,
            uid = tunnel_daemon::UID_FILE,
            version = tunnel_daemon::VERSION_FILE,
            client = tunnel_daemon::CLIENT_FILE,
            socket = tunnel_daemon::SOCKET_PATH,
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

    #[cfg(target_os = "windows")]
    {
        use crate::tunnel_daemon;
        let script = format!(
            "if (Get-Service {label} -ErrorAction SilentlyContinue) {{ \
                 Stop-Service {label} -ErrorAction SilentlyContinue; \
                 sc.exe delete {label} \
             }}",
            label = tunnel_daemon::HELPER_LABEL
        );

        use windows_sys::Win32::UI::Shell::ShellExecuteW;
        use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

        let verb: Vec<u16> = "runas\0".encode_utf16().collect();
        let file: Vec<u16> = "powershell\0".encode_utf16().collect();
        let params: Vec<u16> = format!("-NoProfile -NonInteractive -Command \"{}\"", script)
            .encode_utf16()
            .chain(Some(0u16))
            .collect();

        let result = unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                verb.as_ptr(),
                file.as_ptr(),
                params.as_ptr(),
                std::ptr::null(),
                SW_HIDE as i32,
            )
        };

        if result as isize <= 32 {
            return Err("Failed to uninstall service with administrator privileges.".to_string());
        }
    }

    Ok(())
}
