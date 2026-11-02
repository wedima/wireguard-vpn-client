//! Updates from this repository's GitHub releases.
//!
//! Startup checks for an update and installs one only when it is strictly
//! newer, the download URL is HTTPS on this repository's release hosts, and
//! the bytes verify with the minisign key compiled into the app. An explicit
//! `auto_update: false` skips that startup install. A missing manifest, a
//! downgrade, or a bad signature installs nothing.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use base64::Engine;
use minisign_verify::{PublicKey, Signature};
use semver::Version;
use serde::Serialize;
use tauri::Manager;
use tauri_plugin_updater::UpdaterExt;
use url::Url;

use crate::secret_file;

pub const RELEASE_ENDPOINT: &str =
    "https://github.com/wedima/wireguard-vpn-client/releases/latest/download/latest.json";

/// Minisign public key compiled into the app. This is the base64 form Tauri
/// stores in `tauri.conf.json`; the updater refuses to install unless a
/// signature verifies against this exact key.
pub const UPDATE_PUBKEY: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDU3OTM4ODEwOTEzRUU2NzEKUldSeDVqNlJFSWlUVjB3b1g4WEcvTzJMOWJsTmtWcUtpZ0dBTnZ2MGtZc1V3aU1PY0Fnd2lwT2EK";

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

/// True only when the file explicitly says so. Missing and malformed stay off.
pub fn parse_auto_update(raw: Option<&str>) -> bool {
    let Some(raw) = raw else {
        return false;
    };
    serde_json::from_str::<UpdatePrefs>(raw)
        .map(|prefs| prefs.auto_update)
        .unwrap_or(false)
}

/// Startup installs unless the user saved an explicit opt-out. A missing or
/// unreadable file keeps the signed startup check. A malformed file does too,
/// so a truncated write cannot silently disable it.
pub fn startup_update_enabled(raw: Option<&str>) -> bool {
    let Some(raw) = raw else {
        return true;
    };
    match serde_json::from_str::<UpdatePrefs>(raw) {
        Ok(prefs) => prefs.auto_update,
        Err(_) => true,
    }
}

pub fn auto_update_enabled(app: &tauri::AppHandle) -> bool {
    let Ok(path) = prefs_path(app) else {
        return true;
    };
    let Ok(raw) = std::fs::read_to_string(path) else {
        return true;
    };
    startup_update_enabled(Some(&raw))
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

fn decode_base64_text(value: &str) -> Result<String, String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .map_err(|_| "Refusing update: signature is not a minisign signature".to_string())?;
    String::from_utf8(bytes)
        .map_err(|_| "Refusing update: signature is not a minisign signature".to_string())
}

fn versions_match(signed: &str, announced: &str) -> bool {
    let signed = signed.trim().trim_start_matches('v');
    let announced = announced.trim().trim_start_matches('v');
    match (Version::parse(signed), Version::parse(announced)) {
        (Ok(signed), Ok(announced)) => signed == announced,
        _ => signed == announced,
    }
}

/// Verify artifact bytes the same way the Tauri updater does: minisign over
/// the bytes and over the trusted comment, then require that comment's
/// `version:` to match the manifest. Nothing is installed unless this returns
/// `Ok`.
pub fn verify_update_artifact(
    bytes: &[u8],
    signature_b64: &str,
    announced_version: &str,
) -> Result<(), String> {
    if bytes.is_empty() {
        return Err("Refusing update: artifact is empty".into());
    }
    signature_is_present(signature_b64)?;
    let pubkey_text = decode_base64_text(UPDATE_PUBKEY)?;
    let signature_text = decode_base64_text(signature_b64)?;
    let public_key = PublicKey::decode(&pubkey_text)
        .map_err(|_| "Refusing update: embedded public key is invalid".to_string())?;
    let signature = Signature::decode(&signature_text)
        .map_err(|_| "Refusing update: signature is not a minisign signature".to_string())?;
    // `allow_legacy` matches tauri-plugin-updater: Tauri signatures are not prehashed.
    public_key
        .verify(bytes, &signature, true)
        .map_err(|_| "Refusing update: signature does not match the artifact".to_string())?;
    let trusted = signature.trusted_comment();
    let Some(signed_version) = trusted
        .split('\t')
        .find_map(|field| field.strip_prefix("version:"))
    else {
        return Err("Refusing update: signature does not name a version".into());
    };
    if !versions_match(signed_version, announced_version) {
        return Err("Refusing update: signed version does not match the manifest".into());
    }
    Ok(())
}

/// The plugin compares versions before download. Check again here so a
/// downgrade cannot be installed even if that comparator is widened.
pub fn require_newer_version(current: &str, announced: &str) -> Result<(), String> {
    let parse = |value: &str| -> Result<Version, String> {
        Version::parse(value.trim().trim_start_matches('v'))
            .map_err(|_| "Refusing update: version is not valid".to_string())
    };
    let current = parse(current)?;
    let announced = parse(announced)?;
    if announced <= current {
        return Err("Refusing update: release is not newer than the installed version".into());
    }
    Ok(())
}

/// URL and signature gate used immediately before an update is installed.
pub fn authorize_update_install(
    download_url: &str,
    signature: &str,
    bytes: &[u8],
    announced_version: &str,
) -> Result<(), String> {
    artifact_url_is_trusted(download_url)?;
    verify_update_artifact(bytes, signature, announced_version)
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

/// Check this repository's release and install it when the signature is valid.
/// Does not read or write `update-settings.json`.
pub fn spawn_startup_update(app: &tauri::AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        if !auto_update_enabled(&app) {
            remember(UpdateReport {
                status: "disabled".into(),
                version: None,
                message: String::new(),
            });
            return;
        }
        let report = match download_verified_update(&app).await {
            Ok(report) => report,
            Err(message) => UpdateReport {
                status: "error".into(),
                version: None,
                message,
            },
        };
        remember(report);
    });
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

    let endpoint = Url::parse(RELEASE_ENDPOINT).map_err(|e| e.to_string())?;
    let updater = app
        .updater_builder()
        .pubkey(UPDATE_PUBKEY)
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
    // The plugin verifies during download. We verify again and only then install.
    let bytes = update
        .download(|_, _| {}, || {})
        .await
        .map_err(|_| "Refusing update: download or signature check failed".to_string())?;
    authorize_update_install(
        update.download_url.as_str(),
        &update.signature,
        &bytes,
        &version,
    )?;
    require_newer_version(env!("CARGO_PKG_VERSION"), &version)?;
    // The Windows service is this same executable, so it has to exit before
    // the installer can replace it. macOS keeps a root-owned copy; stopping
    // it here also drops routes before the process restarts. If install fails
    // after this, the tunnel stays down until the user connects again.
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    crate::tunnel_daemon::request_shutdown().await;
    if let Err(err) = update.install(&bytes) {
        let _ = err;
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        return Err(
            "Refusing update: verified artifact could not be installed. The VPN was disconnected; connect again."
                .into(),
        );
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        return Err("Refusing update: verified artifact could not be installed".into());
    }

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
        assert!(endpoint_is_trusted(
            "http://github.com/wedima/wireguard-vpn-client/releases/latest/download/latest.json"
        )
        .is_err());
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
        artifact_url_is_trusted(
            "https://objects.githubusercontent.com/github-production-release-asset/abc",
        )
        .unwrap();
        assert!(artifact_url_is_trusted(
            "http://github.com/wedima/wireguard-vpn-client/releases/download/v1/a"
        )
        .is_err());
        assert!(artifact_url_is_trusted("https://evil.example/app.exe").is_err());
        assert!(artifact_url_is_trusted(
            "https://github.com/other/repo/releases/download/v1/a.exe"
        )
        .is_err());
        assert!(signature_is_present("").is_err());
        assert!(signature_is_present("short").is_err());
        assert!(signature_is_present(&"A".repeat(80)).is_ok());
    }

    const FIXTURE: &[u8] = include_bytes!("../update-fixtures/payload.bin");
    const FIXTURE_SIG: &str = include_str!("../update-fixtures/payload.bin.sig");

    #[test]
    fn auto_update_stays_off_without_an_explicit_setting() {
        assert!(!parse_auto_update(None));
        assert!(!parse_auto_update(Some("")));
        assert!(!parse_auto_update(Some("not json")));
        assert!(!parse_auto_update(Some("{}")));
        assert!(!parse_auto_update(Some(r#"{"auto_update":false}"#)));
        assert!(parse_auto_update(Some(r#"{"auto_update":true}"#)));
    }

    const RETIRED_UPDATE_PUBKEY: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDNCQTA3REU1QzYzMkMwOUQKUldTZHdETEc1WDJnTzR4cWNIWms1Z2NKejJzUlZUcGkzU0w5UVptYThVS0t2d2dPLy8vcEhFaUcK";

    #[test]
    fn retired_public_key_does_not_match_embedded_key() {
        assert_ne!(UPDATE_PUBKEY, RETIRED_UPDATE_PUBKEY);
        let retired_sig = include_str!("../update-fixtures/retired-payload.bin.sig");
        let url = "https://github.com/wedima/wireguard-vpn-client/releases/download/v0.1.7/payload.bin";
        assert!(authorize_update_install(url, retired_sig.trim(), FIXTURE, "0.1.7").is_err());
    }

    #[test]
    fn embedded_pubkey_matches_tauri_config() {
        let conf: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let updater = &conf["plugins"]["updater"];
        assert_eq!(updater["pubkey"].as_str(), Some(UPDATE_PUBKEY));
        assert_eq!(updater["dangerousInsecureTransportProtocol"], false);
        assert_eq!(updater["requireSignedVersion"], true);
        assert_eq!(updater["allowDowngrades"], false);
        assert_eq!(conf["bundle"]["windows"]["allowDowngrades"], false);
        endpoint_is_trusted(updater["endpoints"][0].as_str().unwrap()).unwrap();
    }

    #[test]
    fn startup_updates_stop_only_for_an_explicit_opt_out() {
        assert!(startup_update_enabled(None));
        assert!(startup_update_enabled(Some("")));
        assert!(startup_update_enabled(Some("not json")));
        assert!(startup_update_enabled(Some("{}")));
        assert!(startup_update_enabled(Some(r#"{"auto_update":true}"#)));
        assert!(!startup_update_enabled(Some(r#"{"auto_update":false}"#)));
    }

    #[test]
    fn older_and_equal_releases_are_refused() {
        require_newer_version("0.1.6", "0.1.7").unwrap();
        require_newer_version("0.1.6", "v0.1.7").unwrap();
        assert!(require_newer_version("0.1.6", "0.1.6").is_err());
        assert!(require_newer_version("0.1.6", "0.1.5").is_err());
        assert!(require_newer_version("0.1.6", "v0.0.1").is_err());
        assert!(require_newer_version("0.1.6", "not-a-version").is_err());
    }

    #[test]
    fn signed_fixture_installs_only_after_a_valid_signature() {
        let url =
            "https://github.com/wedima/wireguard-vpn-client/releases/download/v0.1.7/payload.bin";
        authorize_update_install(url, FIXTURE_SIG.trim(), FIXTURE, "0.1.7").unwrap();
        authorize_update_install(url, FIXTURE_SIG.trim(), FIXTURE, "v0.1.7").unwrap();

        let mut tampered = FIXTURE.to_vec();
        tampered[0] ^= 0xff;
        assert!(authorize_update_install(url, FIXTURE_SIG.trim(), &tampered, "0.1.7").is_err());
        assert!(authorize_update_install(url, "", FIXTURE, "0.1.7").is_err());
        assert!(authorize_update_install(url, &"A".repeat(80), FIXTURE, "0.1.7").is_err());
        assert!(authorize_update_install(url, FIXTURE_SIG.trim(), FIXTURE, "9.9.9").is_err());
        assert!(authorize_update_install(
            "http://github.com/wedima/wireguard-vpn-client/releases/download/v0.1.7/payload.bin",
            FIXTURE_SIG.trim(),
            FIXTURE,
            "0.1.7"
        )
        .is_err());
    }
}
