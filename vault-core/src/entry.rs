//! Entrée du coffre et son encodage binaire. Module sans dépendance externe.
//!
//! Une entrée ne contient jamais son mot de passe en clair : elle porte une valeur
//! scellée (nonce + texte chiffré) que seul `Vault::password` sait ouvrir. Les
//! titres, adresses et identifiants restent lisibles en mémoire : ils servent à
//! la recherche et à l'affichage.
//!
//! Encodage (entiers en little-endian) :
//!
//! ```text
//! nombre d'entrées (u32), puis pour chaque entrée :
//!   identifiant (16 octets), création (u64), modification (u64),
//!   titre, adresse, identifiant de connexion (u32 longueur + octets UTF-8),
//!   valeur scellée (u32 longueur + octets)
//! ```

use std::fmt;

use crate::error::{Error, Result};
use crate::header::{NONCE_LEN, TAG_LEN};

/// Taille maximale du titre, en octets.
pub const MAX_TITLE: usize = 1024;
/// Taille maximale de l'adresse, en octets.
pub const MAX_URL: usize = 4096;
/// Taille maximale de l'identifiant de connexion, en octets.
pub const MAX_USERNAME: usize = 1024;
/// Taille maximale d'un mot de passe, en octets.
pub const MAX_PASSWORD: usize = 4096;
/// Nombre maximal d'entrées.
pub const MAX_ENTRIES: usize = 1_000_000;

const MIN_SEALED: usize = NONCE_LEN + TAG_LEN;
const MAX_SEALED: usize = NONCE_LEN + MAX_PASSWORD + TAG_LEN;
/// Taille minimale d'une entrée encodée : identifiant, deux dates, trois chaînes
/// vides et une valeur scellée vide.
const MIN_ENTRY_BYTES: usize = 16 + 8 + 8 + 3 * 4 + 4 + MIN_SEALED;

/// Une entrée du coffre, sans son mot de passe en clair.
#[derive(Clone, PartialEq, Eq)]
pub struct Entry {
    /// Identifiant stable de l'entrée.
    pub id: [u8; 16],
    /// Libellé affiché.
    pub title: String,
    /// Adresse du site (sert à la correspondance de domaine pour la saisie automatique).
    pub url: String,
    /// Identifiant de connexion.
    pub username: String,
    /// Création, en secondes Unix.
    pub created_at: u64,
    /// Dernière modification, en secondes Unix.
    pub modified_at: u64,
    sealed: Vec<u8>,
}

impl Entry {
    pub(crate) fn from_parts(
        id: [u8; 16],
        title: String,
        url: String,
        username: String,
        created_at: u64,
        modified_at: u64,
        sealed: Vec<u8>,
    ) -> Self {
        Self {
            id,
            title,
            url,
            username,
            created_at,
            modified_at,
            sealed,
        }
    }

    pub(crate) fn sealed(&self) -> &[u8] {
        &self.sealed
    }

    pub(crate) fn set_sealed(&mut self, sealed: Vec<u8>) {
        self.sealed = sealed;
    }
}

// Pas de `derive(Debug)` : on n'affiche jamais la valeur scellée.
impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("title", &self.title)
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

/// Vérifie la taille des champs de texte d'une entrée.
pub(crate) fn validate_fields(title: &str, url: &str, username: &str) -> Result<()> {
    if title.len() > MAX_TITLE || url.len() > MAX_URL || username.len() > MAX_USERNAME {
        return Err(Error::FieldTooLong);
    }
    Ok(())
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let length = u32::try_from(bytes.len()).map_err(|_| Error::Serialize)?;
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Encode les entrées.
pub(crate) fn encode(entries: &[Entry]) -> Result<Vec<u8>> {
    if entries.len() > MAX_ENTRIES {
        return Err(Error::Serialize);
    }
    let mut out = Vec::new();
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for entry in entries {
        out.extend_from_slice(&entry.id);
        out.extend_from_slice(&entry.created_at.to_le_bytes());
        out.extend_from_slice(&entry.modified_at.to_le_bytes());
        put_bytes(&mut out, entry.title.as_bytes())?;
        put_bytes(&mut out, entry.url.as_bytes())?;
        put_bytes(&mut out, entry.username.as_bytes())?;
        put_bytes(&mut out, &entry.sealed)?;
    }
    Ok(out)
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.remaining() {
            return Err(Error::Deserialize);
        }
        let slice = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn u32(&mut self) -> Result<u32> {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64> {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(bytes))
    }

    /// Champ préfixé par sa longueur, dont la taille doit être dans `min..=max`.
    fn bytes(&mut self, min: usize, max: usize) -> Result<&'a [u8]> {
        let length = self.u32()? as usize;
        if length < min || length > max {
            return Err(Error::Deserialize);
        }
        self.take(length)
    }

    fn string(&mut self, max: usize) -> Result<String> {
        let bytes = self.bytes(0, max)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| Error::Deserialize)
    }
}

/// Décode les entrées. Toute incohérence (taille, UTF-8, octets en trop) est une erreur.
pub(crate) fn decode(bytes: &[u8]) -> Result<Vec<Entry>> {
    let mut reader = Reader { buf: bytes, pos: 0 };
    let count = reader.u32()? as usize;
    // Le nombre annoncé doit tenir dans ce qui reste : on n'alloue jamais selon un
    // compteur invraisemblable.
    let needed = count.checked_mul(MIN_ENTRY_BYTES);
    if count > MAX_ENTRIES || needed.map_or(true, |n| n > reader.remaining()) {
        return Err(Error::Deserialize);
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let mut id = [0u8; 16];
        id.copy_from_slice(reader.take(16)?);
        let created_at = reader.u64()?;
        let modified_at = reader.u64()?;
        let title = reader.string(MAX_TITLE)?;
        let url = reader.string(MAX_URL)?;
        let username = reader.string(MAX_USERNAME)?;
        let sealed = reader.bytes(MIN_SEALED, MAX_SEALED)?.to_vec();
        entries.push(Entry::from_parts(
            id,
            title,
            url,
            username,
            created_at,
            modified_at,
            sealed,
        ));
    }
    if reader.remaining() != 0 {
        return Err(Error::TrailingData);
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sealed(fill: u8, len: usize) -> Vec<u8> {
        vec![fill; len]
    }

    fn sample() -> Vec<Entry> {
        vec![
            Entry::from_parts(
                [1; 16],
                "Exemple".into(),
                "https://example.org".into(),
                "jérôme".into(),
                100,
                200,
                sealed(7, MIN_SEALED + 10),
            ),
            Entry::from_parts(
                [2; 16],
                String::new(),
                String::new(),
                "é€😀".into(),
                u64::MAX,
                0,
                sealed(9, MIN_SEALED),
            ),
        ]
    }

    #[test]
    fn roundtrip() {
        let entries = sample();
        let decoded = decode(&encode(&entries).unwrap()).unwrap();
        assert_eq!(decoded, entries);
    }

    #[test]
    fn empty_list_roundtrip() {
        assert_eq!(decode(&encode(&[]).unwrap()).unwrap(), vec![]);
    }

    #[test]
    fn every_truncation_is_an_error() {
        let bytes = encode(&sample()).unwrap();
        for len in 0..bytes.len() {
            assert!(decode(&bytes[..len]).is_err(), "longueur {len}");
        }
    }

    #[test]
    fn trailing_bytes_are_an_error() {
        let mut bytes = encode(&sample()).unwrap();
        bytes.push(0);
        assert_eq!(decode(&bytes).unwrap_err(), Error::TrailingData);
    }

    #[test]
    fn hostile_entry_count_is_refused_without_allocating() {
        for count in [u32::MAX, MAX_ENTRIES as u32 + 1, 1_000_000, 10] {
            let mut bytes = count.to_le_bytes().to_vec();
            bytes.extend_from_slice(&[0; 64]);
            assert_eq!(decode(&bytes).unwrap_err(), Error::Deserialize, "{count}");
        }
    }

    #[test]
    fn oversized_fields_are_refused() {
        let long_title = Entry::from_parts(
            [0; 16],
            "x".repeat(MAX_TITLE + 1),
            String::new(),
            String::new(),
            0,
            0,
            sealed(0, MIN_SEALED),
        );
        assert_eq!(
            decode(&encode(&[long_title]).unwrap()).unwrap_err(),
            Error::Deserialize
        );
        for bad_len in [MIN_SEALED - 1, MAX_SEALED + 1] {
            let entry = Entry::from_parts(
                [0; 16],
                String::new(),
                String::new(),
                String::new(),
                0,
                0,
                sealed(0, bad_len),
            );
            assert_eq!(
                decode(&encode(&[entry]).unwrap()).unwrap_err(),
                Error::Deserialize,
                "{bad_len}"
            );
        }
    }

    #[test]
    fn invalid_utf8_is_refused() {
        let mut bytes = encode(&sample()).unwrap();
        // Premier octet du titre de la première entrée : 4 + 16 + 8 + 8 + 4 = 40.
        bytes[40] = 0xff;
        assert_eq!(decode(&bytes).unwrap_err(), Error::Deserialize);
    }

    #[test]
    fn field_validation() {
        assert!(validate_fields("t", "u", "n").is_ok());
        assert!(validate_fields(&"x".repeat(MAX_TITLE), "", "").is_ok());
        assert_eq!(
            validate_fields(&"x".repeat(MAX_TITLE + 1), "", ""),
            Err(Error::FieldTooLong)
        );
        assert_eq!(
            validate_fields("", &"x".repeat(MAX_URL + 1), ""),
            Err(Error::FieldTooLong)
        );
        assert_eq!(
            validate_fields("", "", &"x".repeat(MAX_USERNAME + 1)),
            Err(Error::FieldTooLong)
        );
    }

    #[test]
    fn debug_never_shows_the_sealed_value() {
        let text = format!("{:?}", sample()[0]);
        assert!(text.contains("Exemple"));
        assert!(!text.contains("sealed"));
    }
}
