//! Chaîne secrète effacée de la mémoire à la libération.

use std::fmt;
use std::ptr::write_volatile;
use std::sync::atomic::{compiler_fence, Ordering};

/// Texte secret (un mot de passe importé). Effacé à la libération, jamais affiché par `Debug`.
///
/// Limite : les copies intermédiaires faites pendant la lecture du fichier (cellules CSV,
/// arbre JSON ou XML) sont libérées sans être effacées. Seul le résultat final l'est.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SecretString(String);

impl SecretString {
    /// Prend possession d'un texte.
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Accès en lecture.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Rend le texte à l'appelant, qui devient responsable de l'effacer
    /// (typiquement en le plaçant dans un `Zeroizing<String>`).
    pub fn into_string(mut self) -> String {
        std::mem::take(&mut self.0)
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(***)")
    }
}

#[allow(unsafe_code)]
fn wipe(text: &mut String) {
    // SAFETY: des octets à zéro forment de l'UTF-8 valide, la chaîne reste donc valide.
    // Les écritures sont volatiles pour que le compilateur ne les supprime pas.
    unsafe {
        for byte in text.as_bytes_mut() {
            write_volatile(byte, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
    text.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_hides_the_content() {
        assert_eq!(
            format!("{:?}", SecretString::new("abc".into())),
            "SecretString(***)"
        );
    }

    #[test]
    fn into_string_returns_the_text() {
        assert_eq!(SecretString::new("abc".into()).into_string(), "abc");
    }

    #[test]
    fn wipe_zeroes_the_bytes() {
        let mut text = String::from("secret");
        let ptr = text.as_ptr();
        let len = text.len();
        wipe(&mut text);
        assert!(text.is_empty());
        // `clear` garde la zone allouée : on relit les octets d'origine pour vérifier
        // qu'ils ont bien été écrasés, pas seulement que la longueur est tombée à zéro.
        #[allow(unsafe_code)]
        let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
        assert!(bytes.iter().all(|&b| b == 0));
    }
}
