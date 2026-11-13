//! Lecture et écriture du fichier `.vault` : écriture atomique et sauvegardes
//! rotatives. Les sauvegardes sont des copies du fichier chiffré, jamais du clair.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Nombre de sauvegardes conservées par défaut.
pub const DEFAULT_BACKUPS: usize = 3;
/// Délai minimal entre deux rotations de sauvegarde : évite que plusieurs
/// enregistrements rapprochés n'écrasent toutes les sauvegardes.
pub const DEFAULT_BACKUP_INTERVAL: Duration = Duration::from_secs(600);

/// Emplacement par défaut : `%APPDATA%\gestionnaire-mdp\coffre.vault`.
pub fn default_vault_path() -> Option<PathBuf> {
    let appdata = std::env::var_os("APPDATA")?;
    Some(
        PathBuf::from(appdata)
            .join("gestionnaire-mdp")
            .join("coffre.vault"),
    )
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(suffix);
    path.with_file_name(name)
}

fn backup_path(path: &Path, n: usize) -> PathBuf {
    sibling(path, &format!(".bak{n}"))
}

/// Lit le fichier ; `None` s'il n'existe pas encore.
pub fn load(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn backup_due(path: &Path, min_interval: Duration) -> bool {
    let Ok(meta) = fs::metadata(backup_path(path, 1)) else {
        return true;
    };
    let age = meta
        .modified()
        .ok()
        .and_then(|m| SystemTime::now().duration_since(m).ok())
        .unwrap_or(Duration::MAX);
    age >= min_interval
}

fn remove_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

fn rotate_backups(path: &Path, keep: usize) -> io::Result<()> {
    remove_if_exists(&backup_path(path, keep))?;
    for i in (1..keep).rev() {
        let from = backup_path(path, i);
        if from.exists() {
            fs::rename(&from, backup_path(path, i + 1))?;
        }
    }
    fs::copy(path, backup_path(path, 1))?;
    Ok(())
}

/// Écrit `bytes` de façon atomique : fichier temporaire synchronisé sur le
/// disque, puis renommage qui remplace l'ancien fichier en une seule opération.
/// En cas de coupure, on garde soit l'ancienne version, soit la nouvelle.
/// L'ancienne version est sauvegardée (jusqu'à `backups` copies) si la dernière
/// sauvegarde a plus de `min_backup_interval`.
pub fn save_atomic(
    path: &Path,
    bytes: &[u8],
    backups: usize,
    min_backup_interval: Duration,
) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let tmp = sibling(path, ".tmp");
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    let result = (|| {
        if backups > 0 && path.exists() && backup_due(path, min_backup_interval) {
            rotate_backups(path, backups)?;
        }
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("gmdp-test-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn load_missing_file_is_none() {
        let dir = temp_dir("missing");
        assert_eq!(load(&dir.join("absent.vault")).unwrap(), None);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn save_then_load_roundtrip_and_no_temp_left() {
        let dir = temp_dir("roundtrip");
        let path = dir.join("v.vault");
        save_atomic(&path, b"un", 3, Duration::ZERO).unwrap();
        save_atomic(&path, b"deux", 3, Duration::ZERO).unwrap();
        assert_eq!(load(&path).unwrap().unwrap(), b"deux");
        assert!(!sibling(&path, ".tmp").exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn creates_missing_parent_directories() {
        let dir = temp_dir("parents");
        let path = dir.join("a").join("b").join("v.vault");
        save_atomic(&path, b"x", 3, Duration::ZERO).unwrap();
        assert!(path.exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn backups_hold_previous_versions_and_are_capped() {
        let dir = temp_dir("backups");
        let path = dir.join("v.vault");
        for version in ["v1", "v2", "v3", "v4", "v5"] {
            save_atomic(&path, version.as_bytes(), 3, Duration::ZERO).unwrap();
        }
        assert_eq!(load(&path).unwrap().unwrap(), b"v5");
        assert_eq!(fs::read(backup_path(&path, 1)).unwrap(), b"v4");
        assert_eq!(fs::read(backup_path(&path, 2)).unwrap(), b"v3");
        assert_eq!(fs::read(backup_path(&path, 3)).unwrap(), b"v2");
        assert!(!backup_path(&path, 4).exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn rapid_saves_do_not_burn_every_backup() {
        let dir = temp_dir("interval");
        let path = dir.join("v.vault");
        let hour = Duration::from_secs(3600);
        for version in ["v1", "v2", "v3", "v4"] {
            save_atomic(&path, version.as_bytes(), 3, hour).unwrap();
        }
        // Seule la première rotation a eu lieu : la sauvegarde garde v1.
        assert_eq!(fs::read(backup_path(&path, 1)).unwrap(), b"v1");
        assert!(!backup_path(&path, 2).exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn zero_backups_keeps_none() {
        let dir = temp_dir("nobackup");
        let path = dir.join("v.vault");
        save_atomic(&path, b"a", 0, Duration::ZERO).unwrap();
        save_atomic(&path, b"b", 0, Duration::ZERO).unwrap();
        assert!(!backup_path(&path, 1).exists());
        let _ = fs::remove_dir_all(dir);
    }
}
