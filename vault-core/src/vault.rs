//! Coffre déverrouillé : création, scellement, ouverture, changement de mot de
//! passe maître, et gestion des entrées.
//!
//! Chaque mot de passe est chiffré séparément sous la clé du coffre. En mémoire,
//! seul l'index (titre, adresse, identifiant) est lisible ; un mot de passe n'est
//! déchiffré qu'à la demande (`Vault::password`) et effacé dès que l'appelant
//! lâche la valeur renvoyée. Le contenu entier (index et mots de passe scellés)
//! est en plus chiffré en bloc dans le fichier.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use crate::crypto::{decrypt, derive_key, encrypt, random_array, random_key, unwrap_key, wrap_key};
use crate::entry::{self, validate_fields, Entry, MAX_ENTRIES, MAX_PASSWORD};
use crate::error::{Error, Result};
use crate::header::{
    body_aad, wrap_aad, Envelope, Header, KdfParams, KEY_LEN, NONCE_LEN, SALT_LEN, VAULT_ID_LEN,
};

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Données authentifiées d'un mot de passe scellé : il est lié à ce coffre et à
/// cette entrée, donc une valeur scellée ne peut pas être déplacée ailleurs.
fn password_aad(vault_id: &[u8; VAULT_ID_LEN], entry_id: &[u8; 16]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(2 + VAULT_ID_LEN + 16);
    aad.extend_from_slice(b"pw");
    aad.extend_from_slice(vault_id);
    aad.extend_from_slice(entry_id);
    aad
}

/// Scelle un mot de passe : `nonce (24) || texte chiffré + étiquette`.
fn seal_password(
    key: &[u8; KEY_LEN],
    vault_id: &[u8; VAULT_ID_LEN],
    entry_id: &[u8; 16],
    password: &[u8],
) -> Result<Vec<u8>> {
    if password.len() > MAX_PASSWORD {
        return Err(Error::FieldTooLong);
    }
    let nonce = random_array::<NONCE_LEN>()?;
    let ciphertext = encrypt(key, &nonce, &password_aad(vault_id, entry_id), password)?;
    let mut sealed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    Ok(sealed)
}

/// Ouvre un mot de passe scellé.
fn open_password(
    key: &[u8; KEY_LEN],
    vault_id: &[u8; VAULT_ID_LEN],
    entry: &Entry,
) -> Result<Zeroizing<Vec<u8>>> {
    let sealed = entry.sealed();
    if sealed.len() < NONCE_LEN {
        return Err(Error::WrongPasswordOrCorrupt);
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| Error::WrongPasswordOrCorrupt)?;
    decrypt(key, &nonce, &password_aad(vault_id, &entry.id), ciphertext)
}

/// Un coffre déverrouillé en mémoire.
pub struct Vault {
    vault_id: [u8; VAULT_ID_LEN],
    kdf: KdfParams,
    salt: [u8; SALT_LEN],
    password_envelope: Envelope,
    hello_envelope: Option<Envelope>,
    /// Sur le tas, dans un `Box` : adresse stable pour `key_region`.
    vault_key: Box<Zeroizing<[u8; KEY_LEN]>>,
    entries: Vec<Entry>,
}

impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vault")
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Crée un coffre vide protégé par `password`.
    pub fn create(password: &[u8], kdf: KdfParams) -> Result<Self> {
        if password.is_empty() {
            return Err(Error::EmptyPassword);
        }
        kdf.validate()?;
        let vault_id = random_array::<VAULT_ID_LEN>()?;
        let salt = random_array::<SALT_LEN>()?;
        let vault_key = random_key()?;
        let kek = derive_key(password, &salt, &kdf)?;
        let password_envelope = wrap_key(&kek, &vault_key, &wrap_aad(&vault_id, &kdf, &salt))?;
        Ok(Self {
            vault_id,
            kdf,
            salt,
            password_envelope,
            hello_envelope: None,
            vault_key,
            entries: Vec::new(),
        })
    }

    /// Ouvre un coffre à partir du contenu complet du fichier.
    pub fn open(bytes: &[u8], password: &[u8]) -> Result<Self> {
        let (header, body_offset) = Header::decode(bytes)?;
        let kek = derive_key(password, &header.salt, &header.kdf)?;
        let vault_key = unwrap_key(
            &kek,
            &header.password_envelope,
            &wrap_aad(&header.vault_id, &header.kdf, &header.salt),
        )?;
        let plaintext = decrypt(
            &vault_key,
            &header.body_nonce,
            &body_aad(&header.vault_id),
            &bytes[body_offset..],
        )?;
        let entries = entry::decode(&plaintext)?;
        Ok(Self {
            vault_id: header.vault_id,
            kdf: header.kdf,
            salt: header.salt,
            password_envelope: header.password_envelope,
            hello_envelope: header.hello_envelope,
            vault_key,
            entries,
        })
    }

    /// Produit le contenu complet du fichier. Un nouveau nonce aléatoire est
    /// tiré à chaque appel ; l'écriture sur disque (atomique) relève de l'appelant.
    pub fn seal(&self) -> Result<Vec<u8>> {
        let plaintext = Zeroizing::new(entry::encode(&self.entries)?);
        let body_nonce = random_array::<NONCE_LEN>()?;
        let ciphertext = encrypt(
            &self.vault_key,
            &body_nonce,
            &body_aad(&self.vault_id),
            &plaintext,
        )?;
        let header = Header {
            vault_id: self.vault_id,
            kdf: self.kdf,
            salt: self.salt,
            password_envelope: self.password_envelope.clone(),
            hello_envelope: self.hello_envelope.clone(),
            body_nonce,
        };
        let mut out = header.encode(ciphertext.len());
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Les entrées, sans leurs mots de passe.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Une entrée par identifiant.
    pub fn entry(&self, id: &[u8; 16]) -> Option<&Entry> {
        self.entries.iter().find(|e| e.id == *id)
    }

    /// Déchiffre le mot de passe d'une entrée. La valeur renvoyée s'efface de la
    /// mémoire à sa libération : la garder le moins longtemps possible.
    pub fn password(&self, id: &[u8; 16]) -> Result<Zeroizing<String>> {
        let entry = self.entry(id).ok_or(Error::EntryNotFound)?;
        let bytes = open_password(&self.vault_key, &self.vault_id, entry)?;
        // La copie est effacée à sa libération ; `bytes` l'est aussi en sortie de fonction.
        std::str::from_utf8(&bytes)
            .map(|s| Zeroizing::new(s.to_owned()))
            .map_err(|_| Error::Deserialize)
    }

    /// Ajoute une entrée et renvoie son identifiant.
    pub fn add(
        &mut self,
        title: &str,
        url: &str,
        username: &str,
        password: &str,
    ) -> Result<[u8; 16]> {
        validate_fields(title, url, username)?;
        if self.entries.len() >= MAX_ENTRIES {
            return Err(Error::FieldTooLong);
        }
        let id = random_array::<16>()?;
        let sealed = seal_password(&self.vault_key, &self.vault_id, &id, password.as_bytes())?;
        let now = unix_now();
        self.entries.push(Entry::from_parts(
            id,
            title.to_owned(),
            url.to_owned(),
            username.to_owned(),
            now,
            now,
            sealed,
        ));
        Ok(id)
    }

    /// Modifie une entrée. `password: None` conserve le mot de passe actuel.
    /// Rien n'est modifié si une vérification échoue.
    pub fn update(
        &mut self,
        id: &[u8; 16],
        title: &str,
        url: &str,
        username: &str,
        password: Option<&str>,
    ) -> Result<()> {
        validate_fields(title, url, username)?;
        let index = self
            .entries
            .iter()
            .position(|e| e.id == *id)
            .ok_or(Error::EntryNotFound)?;
        let new_sealed = match password {
            Some(p) => Some(seal_password(&self.vault_key, &self.vault_id, id, p.as_bytes())?),
            None => None,
        };
        let entry = &mut self.entries[index];
        entry.title = title.to_owned();
        entry.url = url.to_owned();
        entry.username = username.to_owned();
        entry.modified_at = unix_now();
        if let Some(sealed) = new_sealed {
            entry.set_sealed(sealed);
        }
        Ok(())
    }

    /// Supprime une entrée. Renvoie `false` si elle n'existe pas.
    pub fn remove(&mut self, id: &[u8; 16]) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.id != *id);
        self.entries.len() != before
    }

    /// Change le mot de passe maître. Le sel ET la clé du coffre sont renouvelés,
    /// et chaque mot de passe est rechiffré sous la nouvelle clé : si l'ancien mot
    /// de passe maître était compromis, une copie du coffre sauvegardée après ce
    /// changement reste illisible avec lui. Tout est préparé avant d'être appliqué :
    /// en cas d'erreur, le coffre reste inchangé. Le contenu est écrit au prochain
    /// `seal`. L'enveloppe Windows Hello, liée à l'ancienne clé, est supprimée et
    /// devra être réenrôlée.
    pub fn change_password(&mut self, new_password: &[u8], kdf: KdfParams) -> Result<()> {
        if new_password.is_empty() {
            return Err(Error::EmptyPassword);
        }
        kdf.validate()?;
        let salt = random_array::<SALT_LEN>()?;
        let vault_key = random_key()?;
        let kek = derive_key(new_password, &salt, &kdf)?;
        let password_envelope = wrap_key(&kek, &vault_key, &wrap_aad(&self.vault_id, &kdf, &salt))?;

        let mut resealed = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            let plain = open_password(&self.vault_key, &self.vault_id, entry)?;
            resealed.push(seal_password(&vault_key, &self.vault_id, &entry.id, &plain)?);
        }

        for (entry, sealed) in self.entries.iter_mut().zip(resealed) {
            entry.set_sealed(sealed);
        }
        self.kdf = kdf;
        self.salt = salt;
        self.vault_key = vault_key;
        self.password_envelope = password_envelope;
        self.hello_envelope = None;
        Ok(())
    }

    /// Paramètres Argon2id actuellement utilisés par ce coffre.
    pub fn kdf_params(&self) -> KdfParams {
        self.kdf
    }

    /// Adresse et taille de la clé du coffre, pour que l'application la
    /// verrouille en RAM (VirtualLock) et évite son écriture dans le fichier
    /// d'échange. Le pointeur n'est valable que tant que le coffre existe, et
    /// change après `change_password` : verrouiller à nouveau dans ce cas.
    pub fn key_region(&self) -> (*const u8, usize) {
        (self.vault_key.as_ptr(), KEY_LEN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PW: &[u8] = b"correct horse battery staple";

    fn kdf() -> KdfParams {
        KdfParams {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        }
    }

    fn sample_vault() -> Vault {
        let mut vault = Vault::create(PW, kdf()).unwrap();
        vault
            .add("Exemple", "https://example.org", "jerome", "mdp-test-1")
            .unwrap();
        vault
            .add("Autre", "https://example.net", "j.c", "mdp-test-2")
            .unwrap();
        vault
    }

    fn ids(vault: &Vault) -> Vec<[u8; 16]> {
        vault.entries().iter().map(|e| e.id).collect()
    }

    #[test]
    fn roundtrip_preserves_entries_and_passwords() {
        let vault = sample_vault();
        let reopened = Vault::open(&vault.seal().unwrap(), PW).unwrap();
        assert_eq!(reopened.entries().len(), 2);
        for (a, b) in vault.entries().iter().zip(reopened.entries()) {
            assert_eq!(a.id, b.id);
            assert_eq!(a.title, b.title);
            assert_eq!(a.url, b.url);
            assert_eq!(a.username, b.username);
            assert_eq!(a.created_at, b.created_at);
        }
        let ids = ids(&reopened);
        assert_eq!(&*reopened.password(&ids[0]).unwrap(), "mdp-test-1");
        assert_eq!(&*reopened.password(&ids[1]).unwrap(), "mdp-test-2");
    }

    #[test]
    fn empty_vault_roundtrip() {
        let vault = Vault::create(PW, kdf()).unwrap();
        let reopened = Vault::open(&vault.seal().unwrap(), PW).unwrap();
        assert!(reopened.entries().is_empty());
    }

    #[test]
    fn wrong_password_is_rejected() {
        let bytes = sample_vault().seal().unwrap();
        assert_eq!(
            Vault::open(&bytes, b"mauvais").unwrap_err(),
            Error::WrongPasswordOrCorrupt
        );
    }

    #[test]
    fn empty_password_is_rejected() {
        assert_eq!(Vault::create(b"", kdf()).unwrap_err(), Error::EmptyPassword);
    }

    #[test]
    fn invalid_kdf_params_are_rejected_on_create() {
        let bad = KdfParams {
            m_cost_kib: 7,
            ..kdf()
        };
        assert_eq!(Vault::create(PW, bad).unwrap_err(), Error::InvalidKdfParams);
    }

    #[test]
    fn any_single_bit_flip_is_detected() {
        let bytes = sample_vault().seal().unwrap();
        for i in 0..bytes.len() {
            let mut tampered = bytes.clone();
            tampered[i] ^= 0x01;
            assert!(Vault::open(&tampered, PW).is_err(), "octet {i} modifié");
        }
    }

    #[test]
    fn truncation_and_trailing_data_are_detected() {
        let bytes = sample_vault().seal().unwrap();
        for len in 0..bytes.len() {
            assert!(Vault::open(&bytes[..len], PW).is_err(), "longueur {len}");
        }
        let mut longer = bytes;
        longer.push(0);
        assert!(Vault::open(&longer, PW).is_err());
    }

    #[test]
    fn each_seal_uses_a_fresh_nonce() {
        let vault = sample_vault();
        let a = vault.seal().unwrap();
        let b = vault.seal().unwrap();
        assert_ne!(a, b);
        assert!(Vault::open(&a, PW).is_ok());
        assert!(Vault::open(&b, PW).is_ok());
    }

    #[test]
    fn two_vaults_with_same_password_differ() {
        let a = Vault::create(PW, kdf()).unwrap().seal().unwrap();
        let b = Vault::create(PW, kdf()).unwrap().seal().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn body_cannot_be_moved_between_vaults() {
        let a = sample_vault().seal().unwrap();
        let b = sample_vault().seal().unwrap();
        let (_, offset) = Header::decode(&a).unwrap();
        let mut mixed = b[..offset].to_vec();
        mixed.extend_from_slice(&a[offset..]);
        assert!(Vault::open(&mixed, PW).is_err());
    }

    #[test]
    fn sealed_password_cannot_be_swapped_between_entries() {
        let mut vault = sample_vault();
        let ids = ids(&vault);
        let first = vault.entries[0].sealed().to_vec();
        let second = vault.entries[1].sealed().to_vec();
        vault.entries[0].set_sealed(second);
        vault.entries[1].set_sealed(first);
        assert_eq!(
            vault.password(&ids[0]).unwrap_err(),
            Error::WrongPasswordOrCorrupt
        );
        assert_eq!(
            vault.password(&ids[1]).unwrap_err(),
            Error::WrongPasswordOrCorrupt
        );
    }

    #[test]
    fn sealed_password_cannot_be_moved_between_vaults() {
        let mut a = sample_vault();
        let b = sample_vault();
        let ida = ids(&a)[0];
        a.entries[0].set_sealed(b.entries[0].sealed().to_vec());
        assert!(a.password(&ida).is_err());
    }

    #[test]
    fn password_is_never_stored_in_clear() {
        let vault = sample_vault();
        let bytes = vault.seal().unwrap();
        let needle = b"mdp-test-1";
        assert!(!bytes.windows(needle.len()).any(|w| w == needle));
        for entry in vault.entries() {
            assert!(!entry.sealed().windows(needle.len()).any(|w| w == needle));
        }
    }

    #[test]
    fn add_update_remove() {
        let mut vault = sample_vault();
        let id = ids(&vault)[0];

        // Sans nouveau mot de passe, l'ancien est conservé.
        vault
            .update(&id, "Titre", "https://x.org", "moi", None)
            .unwrap();
        assert_eq!(vault.entry(&id).unwrap().title, "Titre");
        assert_eq!(&*vault.password(&id).unwrap(), "mdp-test-1");

        vault
            .update(&id, "Titre", "https://x.org", "moi", Some("nouveau"))
            .unwrap();
        assert_eq!(&*vault.password(&id).unwrap(), "nouveau");

        assert!(vault.remove(&id));
        assert!(!vault.remove(&id));
        assert_eq!(vault.entries().len(), 1);
        assert_eq!(vault.password(&id).unwrap_err(), Error::EntryNotFound);
        assert_eq!(
            vault.update(&id, "a", "b", "c", None).unwrap_err(),
            Error::EntryNotFound
        );
    }

    #[test]
    fn limits_are_enforced_without_changing_the_vault() {
        let mut vault = sample_vault();
        let id = ids(&vault)[0];
        let long = "x".repeat(MAX_PASSWORD + 1);
        assert_eq!(
            vault.add("t", "u", "n", &long).unwrap_err(),
            Error::FieldTooLong
        );
        assert_eq!(
            vault.update(&id, "t", "u", "n", Some(&long)).unwrap_err(),
            Error::FieldTooLong
        );
        assert_eq!(
            vault
                .update(&id, &"t".repeat(entry::MAX_TITLE + 1), "u", "n", None)
                .unwrap_err(),
            Error::FieldTooLong
        );
        assert_eq!(vault.entries().len(), 2);
        assert_eq!(vault.entry(&id).unwrap().title, "Exemple");
        assert_eq!(&*vault.password(&id).unwrap(), "mdp-test-1");
        // La taille maximale elle-même est acceptée.
        let max = "y".repeat(MAX_PASSWORD);
        let new_id = vault.add("t", "u", "n", &max).unwrap();
        let reopened = Vault::open(&vault.seal().unwrap(), PW).unwrap();
        assert_eq!(&*reopened.password(&new_id).unwrap(), max.as_str());
    }

    #[test]
    fn unicode_and_empty_passwords_roundtrip() {
        let mut vault = Vault::create(PW, kdf()).unwrap();
        let a = vault.add("a", "", "", "é€😀 mot de passe").unwrap();
        let b = vault.add("b", "", "", "").unwrap();
        let reopened = Vault::open(&vault.seal().unwrap(), PW).unwrap();
        assert_eq!(&*reopened.password(&a).unwrap(), "é€😀 mot de passe");
        assert_eq!(&*reopened.password(&b).unwrap(), "");
    }

    #[test]
    fn change_password_rotates_everything() {
        let mut vault = sample_vault();
        let ids = ids(&vault);
        let old_file = vault.seal().unwrap();
        let old_key = **vault.vault_key;
        let old_salt = vault.salt;
        let old_sealed = vault.entries[0].sealed().to_vec();

        let new_pw: &[u8] = b"nouveau mot de passe";
        vault.change_password(new_pw, kdf()).unwrap();
        assert_ne!(**vault.vault_key, old_key);
        assert_ne!(vault.salt, old_salt);
        assert_ne!(vault.entries[0].sealed(), &old_sealed[..]);
        // Les mots de passe restent lisibles sous la nouvelle clé.
        assert_eq!(&*vault.password(&ids[0]).unwrap(), "mdp-test-1");
        assert_eq!(&*vault.password(&ids[1]).unwrap(), "mdp-test-2");

        let new_file = vault.seal().unwrap();
        assert!(Vault::open(&new_file, PW).is_err());
        let reopened = Vault::open(&new_file, new_pw).unwrap();
        assert_eq!(reopened.entries().len(), 2);
        assert_eq!(&*reopened.password(&ids[1]).unwrap(), "mdp-test-2");
        // L'ancien fichier reste lisible avec l'ancien mot de passe.
        assert!(Vault::open(&old_file, PW).is_ok());
    }

    #[test]
    fn change_password_leaves_vault_untouched_on_failure() {
        let mut vault = sample_vault();
        let ids = ids(&vault);
        // Corrompt un mot de passe scellé : le rechiffrement doit échouer entièrement.
        let mut broken = vault.entries[1].sealed().to_vec();
        let last = broken.len() - 1;
        broken[last] ^= 1;
        vault.entries[1].set_sealed(broken);
        let key_before = **vault.vault_key;
        let sealed_before = vault.entries[0].sealed().to_vec();

        assert!(vault.change_password(b"autre mot de passe", kdf()).is_err());
        assert_eq!(**vault.vault_key, key_before);
        assert_eq!(vault.entries[0].sealed(), &sealed_before[..]);
        assert_eq!(&*vault.password(&ids[0]).unwrap(), "mdp-test-1");
        assert!(Vault::open(&vault.seal().unwrap(), PW).is_ok());
    }

    #[test]
    fn change_password_rejects_empty_and_invalid() {
        let mut vault = sample_vault();
        assert_eq!(
            vault.change_password(b"", kdf()).unwrap_err(),
            Error::EmptyPassword
        );
        let bad = KdfParams { t_cost: 0, ..kdf() };
        assert_eq!(
            vault.change_password(b"x", bad).unwrap_err(),
            Error::InvalidKdfParams
        );
    }

    #[test]
    fn debug_output_never_contains_the_password() {
        let vault = sample_vault();
        let text = format!("{:?} {:?}", vault, vault.entries()[0]);
        assert!(!text.contains("mdp-test-1"));
        assert!(!text.contains("mdp-test-2"));
    }
}
