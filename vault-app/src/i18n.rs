//! Langue de l'interface (français ou anglais) et traduction des messages
//! d'erreur des autres crates. Aucun appel système ici : tout se teste hors Windows.

use std::fmt::Display;
use std::path::Path;

use vault_core::Error;
use vault_import::{ImportError, Report};

/// Langue de l'interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Fr,
    En,
}

impl Lang {
    /// Choisit le texte dans la langue courante.
    pub fn t(self, fr: &'static str, en: &'static str) -> &'static str {
        match self {
            Lang::Fr => fr,
            Lang::En => en,
        }
    }

    /// Message suivi d'un détail, avec la typographie de la langue
    /// (« texte : détail » en français, « text: detail » en anglais).
    pub fn detail(self, fr: &str, en: &str, detail: impl Display) -> String {
        match self {
            Lang::Fr => format!("{fr} : {detail}"),
            Lang::En => format!("{en}: {detail}"),
        }
    }

    /// Code enregistré dans le fichier de réglages.
    pub fn code(self) -> &'static str {
        match self {
            Lang::Fr => "fr",
            Lang::En => "en",
        }
    }

    /// Lit un code de langue ; tolère les espaces, la casse et les variantes régionales (`fr-FR`).
    pub fn from_code(text: &str) -> Option<Lang> {
        let code = text.trim().to_ascii_lowercase();
        match code.split(['-', '_']).next()? {
            "fr" => Some(Lang::Fr),
            "en" => Some(Lang::En),
            _ => None,
        }
    }

    /// Langue enregistrée, si le fichier existe et est lisible.
    pub fn load(path: &Path) -> Option<Lang> {
        let text = std::fs::read_to_string(path).ok()?;
        Lang::from_code(text.lines().next()?)
    }

    /// Enregistre la langue. Au mieux : un échec n'empêche pas de continuer.
    pub fn save(self, path: &Path) {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(path, format!("{}\n", self.code()));
    }

    /// Erreur du noyau, dans la langue courante.
    pub fn core_error(self, error: &Error) -> String {
        if self == Lang::Fr {
            return error.to_string();
        }
        match error {
            Error::BadMagic => "Not a valid vault file".into(),
            Error::UnsupportedVersion(v) => format!("Unsupported file format version ({v})"),
            Error::UnsupportedKdf(k) => format!("Unsupported key derivation ({k})"),
            Error::InvalidKdfParams => "Key derivation parameters out of bounds".into(),
            Error::InvalidHeader => "Invalid vault header".into(),
            Error::Truncated => "Vault file is truncated".into(),
            Error::TrailingData => "Unexpected data at the end of the file".into(),
            Error::EmptyPassword => "The master password cannot be empty".into(),
            Error::WrongPasswordOrCorrupt => "Wrong password or corrupted vault".into(),
            Error::Kdf => "Key derivation failed".into(),
            Error::Encrypt => "Encryption failed".into(),
            Error::Random => "The system random generator failed".into(),
            Error::Serialize => "Serialization failed".into(),
            Error::Deserialize => "Vault content is unreadable".into(),
            Error::InvalidGeneratorOptions => "Impossible generator options".into(),
            Error::WordlistTooShort => "Word list is too short".into(),
            Error::EntryNotFound => "Entry not found".into(),
            Error::FieldTooLong => "A field is too long".into(),
        }
    }

    /// Erreur d'import, dans la langue courante. Le détail des erreurs de
    /// syntaxe JSON et XML reste en français (il vient de l'analyseur).
    pub fn import_error(self, error: &ImportError) -> String {
        if self == Lang::Fr {
            return error.to_string();
        }
        match error {
            ImportError::TooLarge => "File too large (64 MiB maximum).".into(),
            ImportError::Kdbx => "KeePass file (.kdbx): this encrypted format is not supported \
                yet. In KeePass or KeePassXC, export the database as XML or CSV, then import that file."
                .into(),
            ImportError::NotText => "The file is not UTF-8 text.".into(),
            ImportError::Empty => "The file is empty.".into(),
            ImportError::Csv(_) => "Invalid CSV: a quote is never closed.".into(),
            ImportError::Json(m) => format!("Invalid JSON file: {m}"),
            ImportError::Xml(m) => format!("Invalid XML file: {m}"),
            ImportError::EncryptedBitwarden => {
                "Encrypted Bitwarden export: export again as unencrypted JSON.".into()
            }
            ImportError::ProtectedValues => "The passwords in this XML file are protected. \
                Export them from KeePassXC (Database > Export > XML) or as CSV."
                .into(),
            ImportError::NoPasswordColumn(columns) => {
                format!("Password column not found. Columns found: {columns}.")
            }
            ImportError::NotKeePassXml => "This XML is not a KeePass export.".into(),
            ImportError::NotBitwarden => "This JSON is not a Bitwarden export.".into(),
        }
    }

    /// Bilan d'un import, dans la langue courante.
    pub fn import_summary(self, report: &Report, imported: usize) -> String {
        if self == Lang::Fr {
            return report.summary(imported);
        }
        let mut text = format!("{imported} item(s) imported.");
        let skipped: Vec<String> = [
            (report.duplicates, "duplicate(s)"),
            (report.skipped_no_password, "without password"),
            (report.skipped_non_login, "not logins"),
        ]
        .iter()
        .filter(|(n, _)| *n > 0)
        .map(|(n, what)| format!("{n} {what}"))
        .collect();
        if !skipped.is_empty() {
            text.push_str(&format!(" Skipped: {}.", skipped.join(", ")));
        }
        let dropped: Vec<String> = [
            (report.dropped_notes, "notes"),
            (report.dropped_totp, "TOTP codes"),
        ]
        .iter()
        .filter(|(n, _)| *n > 0)
        .map(|(n, what)| format!("{what} ({n})"))
        .collect();
        if !dropped.is_empty() {
            text.push_str(&format!(
                " Not imported (out of scope for this version): {}.",
                dropped.join(", ")
            ));
        }
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_roundtrip_and_tolerate_variants() {
        for lang in [Lang::Fr, Lang::En] {
            assert_eq!(Lang::from_code(lang.code()), Some(lang));
        }
        assert_eq!(Lang::from_code(" EN \n"), Some(Lang::En));
        assert_eq!(Lang::from_code("fr-FR"), Some(Lang::Fr));
        assert_eq!(Lang::from_code("en_US"), Some(Lang::En));
        assert_eq!(Lang::from_code("de"), None);
        assert_eq!(Lang::from_code(""), None);
    }

    #[test]
    fn choice_and_detail_follow_the_language() {
        assert_eq!(Lang::Fr.t("oui", "yes"), "oui");
        assert_eq!(Lang::En.t("oui", "yes"), "yes");
        assert_eq!(Lang::Fr.detail("Échec", "Failed", "x"), "Échec : x");
        assert_eq!(Lang::En.detail("Échec", "Failed", "x"), "Failed: x");
    }

    #[test]
    fn language_file_roundtrip() {
        let dir = std::env::temp_dir().join(format!("kip-lang-test-{}", std::process::id()));
        let file = dir.join("sous").join("kip.lang");
        assert_eq!(Lang::load(&file), None);
        Lang::En.save(&file);
        assert_eq!(Lang::load(&file), Some(Lang::En));
        Lang::Fr.save(&file);
        assert_eq!(Lang::load(&file), Some(Lang::Fr));
        std::fs::write(&file, "n'importe quoi").unwrap();
        assert_eq!(Lang::load(&file), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn french_core_errors_are_unchanged_and_english_ones_differ() {
        let all = [
            Error::BadMagic,
            Error::UnsupportedVersion(9),
            Error::UnsupportedKdf(3),
            Error::InvalidKdfParams,
            Error::InvalidHeader,
            Error::Truncated,
            Error::TrailingData,
            Error::EmptyPassword,
            Error::WrongPasswordOrCorrupt,
            Error::Kdf,
            Error::Encrypt,
            Error::Random,
            Error::Serialize,
            Error::Deserialize,
            Error::InvalidGeneratorOptions,
            Error::WordlistTooShort,
            Error::EntryNotFound,
            Error::FieldTooLong,
        ];
        for error in &all {
            assert_eq!(Lang::Fr.core_error(error), error.to_string());
            let english = Lang::En.core_error(error);
            assert!(!english.is_empty());
            assert_ne!(english, error.to_string(), "{error:?}");
        }
        assert!(Lang::En.core_error(&Error::UnsupportedVersion(9)).contains('9'));
    }

    #[test]
    fn import_errors_in_english() {
        let all = [
            ImportError::TooLarge,
            ImportError::Kdbx,
            ImportError::NotText,
            ImportError::Empty,
            ImportError::Csv("x".into()),
            ImportError::Json("x".into()),
            ImportError::Xml("x".into()),
            ImportError::EncryptedBitwarden,
            ImportError::ProtectedValues,
            ImportError::NoPasswordColumn("a, b".into()),
            ImportError::NotKeePassXml,
            ImportError::NotBitwarden,
        ];
        for error in &all {
            assert_eq!(Lang::Fr.import_error(error), error.to_string());
            assert!(!Lang::En.import_error(error).is_empty());
        }
        assert!(Lang::En
            .import_error(&ImportError::NoPasswordColumn("a, b".into()))
            .contains("a, b"));
    }

    #[test]
    fn import_summary_in_both_languages() {
        let report = Report {
            skipped_no_password: 1,
            skipped_non_login: 2,
            dropped_notes: 3,
            dropped_totp: 4,
            duplicates: 5,
        };
        assert_eq!(Lang::Fr.import_summary(&report, 7), report.summary(7));
        let english = Lang::En.import_summary(&report, 7);
        assert!(english.starts_with("7 item(s) imported."));
        for needle in ["5 duplicate(s)", "1 without password", "2 not logins", "notes (3)", "TOTP codes (4)"] {
            assert!(english.contains(needle), "{needle} dans {english}");
        }
        assert_eq!(
            Lang::En.import_summary(&Report::default(), 0),
            "0 item(s) imported."
        );
    }
}
