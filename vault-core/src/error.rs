//! Erreurs du noyau. Aucun message n'expose de secret, et un mauvais mot de
//! passe n'est volontairement pas distinguable d'un fichier altéré.

use std::fmt;

/// Résultat standard du noyau.
pub type Result<T> = std::result::Result<T, Error>;

/// Erreurs possibles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Le fichier ne commence pas par la signature attendue.
    BadMagic,
    /// Version de format inconnue.
    UnsupportedVersion(u16),
    /// Algorithme de dérivation inconnu.
    UnsupportedKdf(u8),
    /// Paramètres Argon2id hors des bornes autorisées.
    InvalidKdfParams,
    /// En-tête invalide (champ hors des valeurs permises).
    InvalidHeader,
    /// Fichier trop court.
    Truncated,
    /// Octets en trop après le contenu chiffré.
    TrailingData,
    /// Mot de passe maître vide.
    EmptyPassword,
    /// Mauvais mot de passe ou fichier altéré.
    WrongPasswordOrCorrupt,
    /// Échec de la dérivation de clé.
    Kdf,
    /// Échec du chiffrement.
    Encrypt,
    /// Échec du tirage aléatoire du système.
    Random,
    /// Échec de sérialisation.
    Serialize,
    /// Contenu déchiffré illisible.
    Deserialize,
    /// Options du générateur impossibles à satisfaire.
    InvalidGeneratorOptions,
    /// Liste de mots trop courte pour une phrase de passe sûre.
    WordlistTooShort,
    /// Aucune entrée avec cet identifiant.
    EntryNotFound,
    /// Un champ dépasse la taille maximale autorisée.
    FieldTooLong,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BadMagic => f.write_str("fichier de coffre invalide"),
            Error::UnsupportedVersion(v) => {
                write!(f, "version de format non prise en charge ({v})")
            }
            Error::UnsupportedKdf(k) => write!(f, "dérivation de clé non prise en charge ({k})"),
            Error::InvalidKdfParams => f.write_str("paramètres de dérivation de clé hors bornes"),
            Error::InvalidHeader => f.write_str("en-tête de coffre invalide"),
            Error::Truncated => f.write_str("fichier de coffre tronqué"),
            Error::TrailingData => f.write_str("données inattendues à la fin du fichier"),
            Error::EmptyPassword => f.write_str("le mot de passe maître ne peut pas être vide"),
            Error::WrongPasswordOrCorrupt => {
                f.write_str("mot de passe incorrect ou coffre corrompu")
            }
            Error::Kdf => f.write_str("échec de la dérivation de clé"),
            Error::Encrypt => f.write_str("échec du chiffrement"),
            Error::Random => f.write_str("échec du générateur aléatoire du système"),
            Error::Serialize => f.write_str("échec de la sérialisation"),
            Error::Deserialize => f.write_str("contenu du coffre illisible"),
            Error::InvalidGeneratorOptions => f.write_str("options de génération impossibles"),
            Error::WordlistTooShort => f.write_str("liste de mots trop courte"),
            Error::EntryNotFound => f.write_str("entrée introuvable"),
            Error::FieldTooLong => f.write_str("un champ est trop long"),
        }
    }
}

impl std::error::Error for Error {}
