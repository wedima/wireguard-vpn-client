//! Opt-in updates from this repository's GitHub releases.
//!
//! The Tauri updater downloads the artifact and checks its minisign signature
//! against the key compiled into the app before it installs anything. This
//! module additionally refuses non-HTTPS URLs, empty signatures, and hosts
//! other than GitHub's release hosts. Automatic checks run only when the user
//! turns them on.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use serde::Serialize;
use tauri::Manager;
use tauri_plugin_updater::UpdaterExt;
use url::Url;

use crate::secret_file;

pub const RELEASE_ENDPOINT: &str =
    "https://github.com/wedima/wireguard-vpn-client/releases/latest/download/latest.json";

const ALLOWED_HOSTS: &[&str] = &[
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "github-releases.githubusercontent.com",
];

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateReport {
    pub status: String,
    pub version: Option<String>,
    pub message: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct UpdatePrefs {
    auto_update: bool,
}

static LAST_REPORT: Mutex<Option<UpdateReport>> = Mutex::new(None);

fn prefs_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    Ok(app
        .path()
        .app_data_dir()
        .map_err(|e| e.to_string())?
        .join("update-settings.json"))
}

pub fn auto_update_enabled(app: &tauri::AppHandle) -> bool {
    let Ok(path) = prefs_path(app) else {
        return false;
    };
    let Ok(raw) = std::fs::read_to_string(path) else {
        return false;
    };
    serde_json::from_str::<UpdatePrefs>(&raw)
        .map(|prefs| prefs.auto_update)
        .unwrap_or(false)
}

pub fn set_auto_update_enabled(app: &tauri::AppHandle, enabled: bool) -> Result<(), String> {
    let path = prefs_path(app)?;
    let body = serde_json::to_vec(&UpdatePrefs {
        auto_update: enabled,
    })
    .map_err(|e| e.to_string())?;
    secret_file::write_private(&path, &body)
}

fn remember(report: UpdateReport) -> UpdateReport {
    if let Ok(mut slot) = LAST_REPORT.lock() {
        *slot = Some(report.clone());
    }
    report
}

pub fn endpoint_is_trusted(value: &str) -> Result<(), String> {
    let url = Url::parse(value).map_err(|_| "Update endpoint is not a valid URL".to_string())?;
    if url.scheme() != "https" {
        return Err("Update endpoint must use HTTPS".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("Update endpoint must not contain credentials".into());
    }
    if url.host_str() != Some("github.com") {
        return Err("Update endpoint must be this repository's GitHub releases".into());
    }
    if !url
        .path()
        .starts_with("/wedima/wireguard-vpn-client/releases/")
    {
        return Err("Update endpoint is not this repository".into());
    }
    Ok(())
}

pub fn artifact_url_is_trusted(value: &str) -> Result<(), String> {
    let url = Url::parse(value).map_err(|_| "Update URL is not valid".to_string())?;
    if url.scheme() != "https" {
        return Err("Refusing update: download URL is not HTTPS".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("Refusing update: download URL contains credentials".into());
    }
    let host = url.host_str().unwrap_or("");
    if !ALLOWED_HOSTS.contains(&host) {
        return Err("Refusing update: download host is not a GitHub release host".into());
    }
    if host == "github.com"
        && !url
            .path()
            .starts_with("/wedima/wireguard-vpn-client/releases/download/")
    {
        return Err("Refusing update: artifact is not from this repository's releases".into());
    }
    Ok(())
}

pub fn signature_is_present(signature: &str) -> Result<(), String> {
    let signature = signature.trim();
    if signature.is_empty() || signature.len() < 80 {
        return Err("Refusing update: release artifact has no signature".into());
    }
    Ok(())
}

#[tauri::command]
pub fn get_auto_update(app: tauri::AppHandle) -> bool {
    auto_update_enabled(&app)
}

#[tauri::command]
pub fn set_auto_update(app: tauri::AppHandle, enabled: bool) -> Result<(), String> {
    set_auto_update_enabled(&app, enabled)
}

#[tauri::command]
pub fn get_update_status() -> Option<UpdateReport> {
    LAST_REPORT.lock().ok().and_then(|slot| slot.clone())
}

#[tauri::command]
pub async fn check_for_update(app: tauri::AppHandle) -> Result<UpdateReport, String> {
    let report = match download_verified_update(&app).await {
        Ok(report) => report,
        Err(err) => {
            return Err(remember(UpdateReport {
                status: "error".into(),
                version: None,
                message: err,
            })
            .message);
        }
    };
    Ok(remember(report))
}

async fn download_verified_update(app: &tauri::AppHandle) -> Result<UpdateReport, String> {
    endpoint_is_trusted(RELEASE_ENDPOINT)?;
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    crate::tunnel_daemon::request_shutdown().await;

    let endpoint = Url::parse(RELEASE_ENDPOINT).map_err(|e| e.to_string())?;
    let updater = app
        .updater_builder()
        .endpoints(vec![endpoint])
        .map_err(|e| e.to_string())?
        .timeout(Duration::from_secs(180))
        .build()
        .map_err(|e| e.to_string())?;

    let update = updater.check().await.map_err(|e| e.to_string())?;
    let Some(update) = update else {
        return Ok(UpdateReport {
            status: "up-to-date".into(),
            version: None,
            message: "You're on the latest version.".into(),
        });
    };

    artifact_url_is_trusted(update.download_url.as_str())?;
    signature_is_present(&update.signature)?;
    let version = update.version.clone();

    update
        .download_and_install(|_, _| {}, || {})
        .await
        .map_err(|e| e.to_string())?;

    let report = UpdateReport {
        status: "installed".into(),
        version: Some(version),
        message: "Update installed. Restart to finish.".into(),
    };
    // The Windows installer exits this process. macOS and Linux keep running
    // the old binary until we relaunch.
    #[cfg(target_os = "windows")]
    return Ok(report);
    #[cfg(not(target_os = "windows"))]
    {
        let _ = report;
        app.restart();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_endpoint_is_https_github() {
        endpoint_is_trusted(RELEASE_ENDPOINT).unwrap();
        assert!(endpoint_is_trusted("http://github.com/wedima/wireguard-vpn-client/releases/latest/download/latest.json").is_err());
        assert!(endpoint_is_trusted("https://example.com/latest.json").is_err());
        assert!(endpoint_is_trusted(
            "https://user:token@github.com/wedima/wireguard-vpn-client/releases/latest/download/latest.json"
        )
        .is_err());
    }

    #[test]
    fn artifact_must_be_signed_https_release() {
        artifact_url_is_trusted(
            "https://github.com/wedima/wireguard-vpn-client/releases/download/v0.1.7/app.tar.gz",
        )
        .unwrap();
        artifact_url_is_trusted("https://objects.githubusercontent.com/github-production-release-asset/abc").unwrap();
        assert!(artifact_url_is_trusted("http://github.com/wedima/wireguard-vpn-client/releases/download/v1/a").is_err());
        assert!(artifact_url_is_trusted("https://evil.example/app.exe").is_err());
        assert!(artifact_url_is_trusted(
            "https://github.com/other/repo/releases/download/v1/a.exe"
        )
        .is_err());
        assert!(signature_is_present("").is_err());
        assert!(signature_is_present("short").is_err());
        assert!(signature_is_present(&"A".repeat(80)).is_ok());
    }
}
