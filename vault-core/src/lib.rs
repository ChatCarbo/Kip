//! Noyau du gestionnaire de mots de passe.
//!
//! Aucun code `unsafe` ici : les appels système (VirtualLock, Windows Hello,
//! presse-papiers) vivent dans `vault-app`.

#![forbid(unsafe_code)]

mod crypto;
pub mod entry;
pub mod error;
pub mod generator;
pub mod header;
pub mod search;
pub mod storage;
pub mod vault;

use zeroize::Zeroizing;

pub use crypto::calibrate_kdf;
pub use error::{Error, Result};
pub use generator::PasswordOptions;
pub use header::KdfParams;
pub use entry::Entry;
pub use vault::Vault;

/// Génère un mot de passe avec l'aléa du système. Le résultat est effacé de la
/// mémoire à la libération.
pub fn generate_password(options: &PasswordOptions) -> Result<Zeroizing<String>> {
    let bytes = generator::generate_password(options, &mut crypto::fill_random)?;
    // Le générateur ne produit que de l'ASCII : la conversion déplace le tampon sans le copier.
    String::from_utf8(bytes)
        .map(Zeroizing::new)
        .map_err(|_| Error::InvalidGeneratorOptions)
}

/// Génère une phrase de passe (mots tirés au hasard dans `words`) avec l'aléa du système.
pub fn generate_passphrase(
    words: &[&str],
    count: usize,
    separator: &str,
    capitalize: bool,
) -> Result<Zeroizing<String>> {
    generator::generate_passphrase(
        words,
        count,
        separator,
        capitalize,
        &mut crypto::fill_random,
    )
    .map(Zeroizing::new)
}
