//! Utilitaires sans dépendance.

use std::fmt;
use std::sync::{Arc, Mutex};

/// Permet de faire transiter par un message `Clone` une valeur qui ne l'est pas
/// (le coffre déverrouillé, par exemple) sans jamais la dupliquer : `take`
/// la sort une seule fois, les autres clones reçoivent `None`.
/// Le contenu n'apparaît jamais dans le `Debug`.
pub struct Handoff<T>(Arc<Mutex<Option<T>>>);

impl<T> Handoff<T> {
    /// Enveloppe une valeur.
    pub fn new(value: T) -> Self {
        Self(Arc::new(Mutex::new(Some(value))))
    }

    /// Récupère la valeur, une seule fois.
    pub fn take(&self) -> Option<T> {
        self.0.lock().ok()?.take()
    }
}

impl<T> Clone for Handoff<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<T> fmt::Debug for Handoff<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Handoff(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_can_be_taken_exactly_once() {
        let h = Handoff::new(String::from("secret"));
        assert_eq!(h.take().as_deref(), Some("secret"));
        assert_eq!(h.take(), None);
    }

    #[test]
    fn clones_share_the_same_slot() {
        let a = Handoff::new(7u32);
        let b = a.clone();
        assert_eq!(b.take(), Some(7));
        assert_eq!(a.take(), None);
    }

    #[test]
    fn debug_never_shows_the_content() {
        let h = Handoff::new(String::from("mot-de-passe"));
        assert_eq!(format!("{h:?}"), "Handoff(..)");
    }
}
