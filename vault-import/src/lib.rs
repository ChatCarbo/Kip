//! Import et export de mots de passe.
//!
//! Formats lus : CSV (Chrome, Edge, Firefox, Bitwarden, KeePassXC, LastPass,
//! 1Password, Dashlane, RoboForm et tout CSV dont l'en-tête est reconnaissable),
//! JSON Bitwarden non chiffré, XML KeePass / KeePassXC.
//! Formats écrits : CSV et JSON Bitwarden, en clair.
//!
//! Le format `.kdbx` (chiffré) n'est pas encore pris en charge : le fichier est
//! reconnu et l'utilisateur est invité à exporter en XML ou CSV depuis KeePass.

#![deny(unsafe_code)]

pub mod csv;
mod export;
pub mod json;
mod readers;
mod secret;
pub mod xml;

use std::collections::HashSet;
use std::fmt;
use std::hash::{DefaultHasher, Hash, Hasher};

pub use export::{export_bitwarden_json, export_csv, ExportEntry};
pub use secret::SecretString;

/// Taille maximale d'un fichier à importer.
pub const MAX_FILE_SIZE: usize = 64 * 1024 * 1024;

/// Une entrée lue dans un fichier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedEntry {
    pub title: String,
    pub url: String,
    pub username: String,
    pub password: SecretString,
}

/// Format d'un fichier à importer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Csv,
    BitwardenJson,
    KeePassXml,
}

/// Ce qui n'a pas été importé, et pourquoi.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Lignes sans mot de passe.
    pub skipped_no_password: usize,
    /// Éléments qui ne sont pas des identifiants (notes, cartes, identités…).
    pub skipped_non_login: usize,
    /// Notes présentes dans le fichier, non reprises (hors périmètre de la v1).
    pub dropped_notes: usize,
    /// Secrets TOTP présents dans le fichier, non repris (hors périmètre de la v1).
    pub dropped_totp: usize,
    /// Entrées déjà présentes dans le coffre ou répétées dans le fichier.
    pub duplicates: usize,
}

impl Report {
    /// Phrase de bilan pour l'utilisateur.
    pub fn summary(&self, imported: usize) -> String {
        let mut text = format!("{imported} entrée(s) importée(s).");
        let skipped: Vec<String> = [
            (self.duplicates, "doublon(s)"),
            (self.skipped_no_password, "sans mot de passe"),
            (self.skipped_non_login, "autre(s) que des identifiants"),
        ]
        .iter()
        .filter(|(n, _)| *n > 0)
        .map(|(n, what)| format!("{n} {what}"))
        .collect();
        if !skipped.is_empty() {
            text.push_str(&format!(" Ignorées : {}.", skipped.join(", ")));
        }
        let dropped: Vec<String> = [
            (self.dropped_notes, "notes"),
            (self.dropped_totp, "codes TOTP"),
        ]
        .iter()
        .filter(|(n, _)| *n > 0)
        .map(|(n, what)| format!("{what} ({n})"))
        .collect();
        if !dropped.is_empty() {
            text.push_str(&format!(
                " Non repris (hors périmètre de cette version) : {}.",
                dropped.join(", ")
            ));
        }
        text
    }
}

/// Résultat de la lecture d'un fichier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    pub format: Format,
    pub entries: Vec<ImportedEntry>,
    pub report: Report,
}

/// Raisons pour lesquelles un fichier ne peut pas être importé.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportError {
    TooLarge,
    Kdbx,
    NotText,
    Empty,
    Csv(String),
    Json(String),
    Xml(String),
    EncryptedBitwarden,
    ProtectedValues,
    NoPasswordColumn(String),
    NotKeePassXml,
    NotBitwarden,
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImportError::TooLarge => write!(f, "Fichier trop volumineux (64 Mio au maximum)."),
            ImportError::Kdbx => f.write_str(
                "Fichier KeePass (.kdbx) : ce format chiffré n'est pas encore pris en charge. \
                 Dans KeePass ou KeePassXC, exportez la base en XML ou en CSV, puis importez ce fichier.",
            ),
            ImportError::NotText => f.write_str("Le fichier n'est pas un texte UTF-8."),
            ImportError::Empty => f.write_str("Le fichier est vide."),
            ImportError::Csv(m) | ImportError::Json(m) | ImportError::Xml(m) => f.write_str(m),
            ImportError::EncryptedBitwarden => f.write_str(
                "Export Bitwarden chiffré : refaites l'export au format JSON non chiffré.",
            ),
            ImportError::ProtectedValues => f.write_str(
                "Les mots de passe de ce fichier XML sont protégés. Exportez-les depuis KeePassXC \
                 (Base de données > Exporter > XML) ou au format CSV.",
            ),
            ImportError::NoPasswordColumn(columns) => write!(
                f,
                "Colonne de mot de passe introuvable. Colonnes trouvées : {columns}."
            ),
            ImportError::NotKeePassXml => f.write_str("Ce XML n'est pas un export KeePass."),
            ImportError::NotBitwarden => f.write_str("Ce JSON n'est pas un export Bitwarden."),
        }
    }
}

impl std::error::Error for ImportError {}

/// Signature des fichiers KeePass (`.kdb` et `.kdbx`).
const KEEPASS_SIGNATURE: [u8; 4] = [0x03, 0xD9, 0xA2, 0x9A];

fn as_text(bytes: &[u8]) -> Result<&str, ImportError> {
    if bytes.len() > MAX_FILE_SIZE {
        return Err(ImportError::TooLarge);
    }
    if bytes.starts_with(&KEEPASS_SIGNATURE) {
        return Err(ImportError::Kdbx);
    }
    std::str::from_utf8(bytes).map_err(|_| ImportError::NotText)
}

/// Devine le format d'un fichier d'après son contenu.
pub fn detect(bytes: &[u8]) -> Result<Format, ImportError> {
    let text = as_text(bytes)?;
    let start = text.trim_start_matches('\u{feff}').trim_start();
    match start.chars().next() {
        None => Err(ImportError::Empty),
        Some('{') => Ok(Format::BitwardenJson),
        Some('<') => Ok(Format::KeePassXml),
        Some(_) => Ok(Format::Csv),
    }
}

/// Lit un fichier. Sans `format`, il est deviné d'après le contenu.
pub fn parse(bytes: &[u8], format: Option<Format>) -> Result<Parsed, ImportError> {
    let format = match format {
        Some(format) => format,
        None => detect(bytes)?,
    };
    let text = as_text(bytes)?;
    let (entries, report) = match format {
        Format::Csv => readers::csv_entries(text)?,
        Format::BitwardenJson => readers::bitwarden_entries(text)?,
        Format::KeePassXml => readers::keepass_entries(text)?,
    };
    Ok(Parsed {
        format,
        entries,
        report,
    })
}

/// Hôte d'une adresse : sans schéma, sans identifiants, sans port, sans chemin, sans `www.`.
pub fn host_of(url: &str) -> String {
    let url = url.trim();
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    let end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..end];
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = if let Some(rest) = authority.strip_prefix('[') {
        // Adresse IPv6 : on garde ce qui est entre crochets.
        rest.split(']').next().unwrap_or("")
    } else {
        authority.split(':').next().unwrap_or("")
    };
    let host = host.to_lowercase();
    host.strip_prefix("www.").unwrap_or(&host).to_string()
}

/// Empreinte d'une entrée, pour repérer les doublons sans garder les mots de passe en clair.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Fingerprint {
    host: String,
    username: String,
    password_hash: u64,
}

impl Fingerprint {
    /// Deux entrées sont des doublons si l'hôte, l'identifiant (sans tenir compte de la
    /// casse) et le mot de passe sont les mêmes.
    pub fn new(url: &str, username: &str, password: &str) -> Self {
        let mut hasher = DefaultHasher::new();
        password.hash(&mut hasher);
        Self {
            host: host_of(url),
            username: username.trim().to_lowercase(),
            password_hash: hasher.finish(),
        }
    }
}

/// Retire de `parsed` les entrées déjà présentes (`existing`) et celles répétées
/// dans le fichier lui-même, et les compte dans le rapport.
pub fn dedup(existing: &[Fingerprint], parsed: &mut Parsed) {
    let mut seen: HashSet<Fingerprint> = existing.iter().cloned().collect();
    let before = parsed.entries.len();
    parsed.entries.retain(|entry| {
        seen.insert(Fingerprint::new(
            &entry.url,
            &entry.username,
            entry.password.as_str(),
        ))
    });
    parsed.report.duplicates += before - parsed.entries.len();
}

#[cfg(test)]
mod tests;
