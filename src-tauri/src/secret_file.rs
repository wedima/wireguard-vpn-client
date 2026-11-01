use std::io::Write;
use std::path::Path;

/// Write bytes so that only the current user can read them back.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| e.to_string())?;
        file.write_all(bytes).map_err(|e| e.to_string())?;
        let _ = file.sync_all();
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Overwrite a file with zeros before deleting it.
pub fn shred_remove(path: &Path) -> Result<(), String> {
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.is_file() {
            if let Ok(mut file) = std::fs::OpenOptions::new().write(true).open(path) {
                let zeros = vec![0u8; 8192];
                let mut left = meta.len() as usize;
                while left > 0 {
                    let n = left.min(zeros.len());
                    if file.write_all(&zeros[..n]).is_err() {
                        break;
                    }
                    left -= n;
                }
                let _ = file.sync_all();
            }
        }
    }
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.to_string()),
    }
}
