//! Format du fichier `.vault`, version 2 (mots de passe scellés un par un dans le contenu). Module sans dépendance externe.
//!
//! Disposition (entiers en little-endian) :
//!
//! ```text
//!   0..8    signature "PWVAULT\0"
//!   8..10   version du format (u16)
//!  10..26   identifiant du coffre (16 octets aléatoires)
//!  26       algorithme de dérivation (1 = Argon2id)
//!  27..39   m_cost (Kio), t_cost, p_cost (3 × u32)
//!  39..71   sel (32 octets)
//!  71..95   nonce de l'enveloppe « mot de passe »
//!  95..143  clé du coffre chiffrée (32 + 16 octets d'étiquette)
//!  143      présence d'une enveloppe Windows Hello (0 ou 1)
//!  [72 octets d'enveloppe Hello si présente]
//!  puis     nonce du contenu (24 octets)
//!  puis     longueur du contenu chiffré (u64)
//!  puis     contenu chiffré (étiquette Poly1305 incluse)
//! ```
//!
//! Authentification :
//! - l'enveloppe « mot de passe » est authentifiée avec les octets `0..71`
//!   (signature, version, identifiant, paramètres Argon2id, sel) : modifier un
//!   paramètre fait échouer le déchiffrement ;
//! - le contenu est authentifié avec les octets `0..26` (signature, version,
//!   identifiant), qui ne changent jamais pour un même coffre.

use crate::error::{Error, Result};

/// Signature du fichier.
pub const MAGIC: [u8; 8] = *b"PWVAULT\0";
/// Version courante du format.
pub const FORMAT_VERSION: u16 = 2;
/// Identifiant de l'algorithme Argon2id dans l'en-tête.
pub const KDF_ARGON2ID: u8 = 1;

/// Taille de l'identifiant du coffre.
pub const VAULT_ID_LEN: usize = 16;
/// Taille du sel Argon2id.
pub const SALT_LEN: usize = 32;
/// Taille d'une clé (256 bits).
pub const KEY_LEN: usize = 32;
/// Taille du nonce XChaCha20 (192 bits).
pub const NONCE_LEN: usize = 24;
/// Taille de l'étiquette Poly1305.
pub const TAG_LEN: usize = 16;
/// Taille d'une clé enveloppée (clé + étiquette).
pub const WRAPPED_KEY_LEN: usize = KEY_LEN + TAG_LEN;

/// Longueur des données authentifiées du contenu.
pub const BODY_AAD_LEN: usize = 8 + 2 + VAULT_ID_LEN;
/// Longueur des données authentifiées de l'enveloppe « mot de passe ».
pub const WRAP_AAD_LEN: usize = BODY_AAD_LEN + 1 + 12 + SALT_LEN;

/// Plancher de mémoire Argon2id : 64 Mio (réduit pour les tests unitaires).
#[cfg(not(test))]
pub const MIN_M_COST_KIB: u32 = 64 * 1024;
#[cfg(test)]
pub const MIN_M_COST_KIB: u32 = 8;
/// Plancher de passes Argon2id (réduit pour les tests unitaires).
#[cfg(not(test))]
pub const MIN_T_COST: u32 = 3;
#[cfg(test)]
pub const MIN_T_COST: u32 = 1;
/// Plafond de mémoire accepté à l'ouverture : 4 Gio (protège contre un fichier piégé).
pub const MAX_M_COST_KIB: u32 = 4 * 1024 * 1024;
/// Plafond de passes accepté à l'ouverture.
pub const MAX_T_COST: u32 = 64;
/// Plafond de voies de parallélisme accepté à l'ouverture.
pub const MAX_P_COST: u32 = 16;

/// Paramètres Argon2id stockés dans l'en-tête.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Mémoire en Kio.
    pub m_cost_kib: u32,
    /// Nombre de passes.
    pub t_cost: u32,
    /// Degré de parallélisme.
    pub p_cost: u32,
}

impl KdfParams {
    /// Vérifie les bornes : plancher de sécurité et plafond anti-déni de service.
    /// Appelé avant toute dérivation, donc avant d'allouer la mémoire demandée.
    pub fn validate(&self) -> Result<()> {
        let ok = (MIN_M_COST_KIB..=MAX_M_COST_KIB).contains(&self.m_cost_kib)
            && (MIN_T_COST..=MAX_T_COST).contains(&self.t_cost)
            && (1..=MAX_P_COST).contains(&self.p_cost)
            && self.m_cost_kib >= 8 * self.p_cost;
        if ok {
            Ok(())
        } else {
            Err(Error::InvalidKdfParams)
        }
    }
}

/// Clé du coffre enveloppée par une clé dérivée (mot de passe ou Windows Hello).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Nonce aléatoire de l'enveloppe.
    pub nonce: [u8; NONCE_LEN],
    /// Clé du coffre chiffrée, étiquette comprise.
    pub wrapped_key: [u8; WRAPPED_KEY_LEN],
}

/// En-tête décodé.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Identifiant aléatoire du coffre.
    pub vault_id: [u8; VAULT_ID_LEN],
    /// Paramètres Argon2id.
    pub kdf: KdfParams,
    /// Sel Argon2id.
    pub salt: [u8; SALT_LEN],
    /// Enveloppe de la clé du coffre sous le mot de passe maître.
    pub password_envelope: Envelope,
    /// Enveloppe optionnelle sous la clé Windows Hello.
    pub hello_envelope: Option<Envelope>,
    /// Nonce du contenu chiffré.
    pub body_nonce: [u8; NONCE_LEN],
}

/// Données authentifiées communes : signature, version, identifiant.
fn base_aad(vault_id: &[u8; VAULT_ID_LEN]) -> Vec<u8> {
    let mut v = Vec::with_capacity(WRAP_AAD_LEN);
    v.extend_from_slice(&MAGIC);
    v.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    v.extend_from_slice(vault_id);
    v
}

/// Données authentifiées du contenu chiffré.
pub fn body_aad(vault_id: &[u8; VAULT_ID_LEN]) -> Vec<u8> {
    base_aad(vault_id)
}

/// Données authentifiées de l'enveloppe « mot de passe ».
pub fn wrap_aad(vault_id: &[u8; VAULT_ID_LEN], kdf: &KdfParams, salt: &[u8; SALT_LEN]) -> Vec<u8> {
    let mut v = base_aad(vault_id);
    v.push(KDF_ARGON2ID);
    v.extend_from_slice(&kdf.m_cost_kib.to_le_bytes());
    v.extend_from_slice(&kdf.t_cost.to_le_bytes());
    v.extend_from_slice(&kdf.p_cost.to_le_bytes());
    v.extend_from_slice(salt);
    v
}

impl Header {
    /// Encode l'en-tête. `body_len` est la taille du contenu chiffré que
    /// l'appelant ajoutera juste après.
    pub fn encode(&self, body_len: usize) -> Vec<u8> {
        let mut out = wrap_aad(&self.vault_id, &self.kdf, &self.salt);
        out.extend_from_slice(&self.password_envelope.nonce);
        out.extend_from_slice(&self.password_envelope.wrapped_key);
        match &self.hello_envelope {
            None => out.push(0),
            Some(env) => {
                out.push(1);
                out.extend_from_slice(&env.nonce);
                out.extend_from_slice(&env.wrapped_key);
            }
        }
        out.extend_from_slice(&self.body_nonce);
        out.extend_from_slice(&(body_len as u64).to_le_bytes());
        out
    }

    /// Décode et valide un fichier complet. Renvoie l'en-tête et le décalage
    /// où commence le contenu chiffré. Le contenu doit occuper exactement le
    /// reste du fichier.
    pub fn decode(bytes: &[u8]) -> Result<(Header, usize)> {
        let mut r = Reader { buf: bytes, pos: 0 };

        if r.array::<8>()? != MAGIC {
            return Err(Error::BadMagic);
        }
        let version = r.u16()?;
        if version != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        let vault_id = r.array::<VAULT_ID_LEN>()?;
        let kdf_id = r.u8()?;
        if kdf_id != KDF_ARGON2ID {
            return Err(Error::UnsupportedKdf(kdf_id));
        }
        let kdf = KdfParams {
            m_cost_kib: r.u32()?,
            t_cost: r.u32()?,
            p_cost: r.u32()?,
        };
        kdf.validate()?;
        let salt = r.array::<SALT_LEN>()?;
        let password_envelope = r.envelope()?;
        let hello_envelope = match r.u8()? {
            0 => None,
            1 => Some(r.envelope()?),
            _ => return Err(Error::InvalidHeader),
        };
        let body_nonce = r.array::<NONCE_LEN>()?;
        let body_len = r.u64()?;

        let body_offset = r.pos;
        let remaining = (bytes.len() - body_offset) as u64;
        if body_len < TAG_LEN as u64 || body_len > remaining {
            return Err(Error::Truncated);
        }
        if body_len < remaining {
            return Err(Error::TrailingData);
        }

        let header = Header {
            vault_id,
            kdf,
            salt,
            password_envelope,
            hello_envelope,
            body_nonce,
        };
        Ok((header, body_offset))
    }
}

/// Lecteur séquentiel qui refuse tout dépassement.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(Error::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array::<2>()?))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array::<4>()?))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array::<8>()?))
    }

    fn envelope(&mut self) -> Result<Envelope> {
        Ok(Envelope {
            nonce: self.array::<NONCE_LEN>()?,
            wrapped_key: self.array::<WRAPPED_KEY_LEN>()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(b: u8) -> Envelope {
        Envelope {
            nonce: [b; NONCE_LEN],
            wrapped_key: [b.wrapping_add(1); WRAPPED_KEY_LEN],
        }
    }

    fn sample(with_hello: bool) -> Header {
        Header {
            vault_id: [7; VAULT_ID_LEN],
            kdf: KdfParams {
                m_cost_kib: 16,
                t_cost: 2,
                p_cost: 1,
            },
            salt: [9; SALT_LEN],
            password_envelope: envelope(1),
            hello_envelope: with_hello.then(|| envelope(5)),
            body_nonce: [3; NONCE_LEN],
        }
    }

    /// En-tête + faux contenu chiffré de `body_len` octets.
    fn file(header: &Header, body_len: usize) -> Vec<u8> {
        let mut v = header.encode(body_len);
        v.extend(std::iter::repeat(0xAA).take(body_len));
        v
    }

    #[test]
    fn roundtrip_with_and_without_hello() {
        for with_hello in [false, true] {
            let header = sample(with_hello);
            let bytes = file(&header, 40);
            let (decoded, offset) = Header::decode(&bytes).unwrap();
            assert_eq!(decoded, header);
            assert_eq!(offset, bytes.len() - 40);
        }
    }

    #[test]
    fn aad_matches_the_encoded_prefix() {
        let header = sample(false);
        let bytes = file(&header, 20);
        assert_eq!(
            wrap_aad(&header.vault_id, &header.kdf, &header.salt),
            bytes[..WRAP_AAD_LEN]
        );
        assert_eq!(body_aad(&header.vault_id), bytes[..BODY_AAD_LEN]);
        // L'enveloppe « mot de passe » commence juste après les octets authentifiés.
        assert_eq!(
            bytes[WRAP_AAD_LEN..WRAP_AAD_LEN + NONCE_LEN],
            header.password_envelope.nonce
        );
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = file(&sample(false), 20);
        bytes[0] ^= 1;
        assert_eq!(Header::decode(&bytes).unwrap_err(), Error::BadMagic);
    }

    #[test]
    fn rejects_unknown_version_and_kdf() {
        let mut bytes = file(&sample(false), 20);
        bytes[8] = 9;
        assert_eq!(
            Header::decode(&bytes).unwrap_err(),
            Error::UnsupportedVersion(9)
        );

        let mut bytes = file(&sample(false), 20);
        bytes[BODY_AAD_LEN] = 9;
        assert_eq!(
            Header::decode(&bytes).unwrap_err(),
            Error::UnsupportedKdf(9)
        );
    }

    #[test]
    fn rejects_invalid_hello_flag() {
        let mut bytes = file(&sample(false), 20);
        bytes[WRAP_AAD_LEN + NONCE_LEN + WRAPPED_KEY_LEN] = 2;
        assert_eq!(Header::decode(&bytes).unwrap_err(), Error::InvalidHeader);
    }

    #[test]
    fn rejects_every_truncation() {
        let bytes = file(&sample(true), 20);
        for len in 0..bytes.len() {
            assert!(Header::decode(&bytes[..len]).is_err(), "longueur {len}");
        }
    }

    #[test]
    fn rejects_trailing_data() {
        let mut bytes = file(&sample(false), 20);
        bytes.push(0);
        assert_eq!(Header::decode(&bytes).unwrap_err(), Error::TrailingData);
    }

    #[test]
    fn rejects_body_shorter_than_a_tag() {
        let bytes = file(&sample(false), TAG_LEN - 1);
        assert_eq!(Header::decode(&bytes).unwrap_err(), Error::Truncated);
    }

    #[test]
    fn kdf_bounds() {
        let ok = KdfParams {
            m_cost_kib: 64,
            t_cost: 2,
            p_cost: 2,
        };
        assert!(ok.validate().is_ok());

        let bad = [
            KdfParams {
                m_cost_kib: MIN_M_COST_KIB - 1,
                ..ok
            },
            KdfParams {
                m_cost_kib: MAX_M_COST_KIB + 1,
                ..ok
            },
            KdfParams { t_cost: 0, ..ok },
            KdfParams {
                t_cost: MAX_T_COST + 1,
                ..ok
            },
            KdfParams { p_cost: 0, ..ok },
            KdfParams {
                p_cost: MAX_P_COST + 1,
                ..ok
            },
            // Argon2 exige au moins 8 Kio par voie.
            KdfParams {
                m_cost_kib: 8,
                p_cost: 2,
                ..ok
            },
        ];
        for params in bad {
            assert_eq!(
                params.validate(),
                Err(Error::InvalidKdfParams),
                "{params:?}"
            );
        }
    }

    #[test]
    fn hostile_kdf_params_are_rejected_before_any_derivation() {
        let mut header = sample(false);
        header.kdf.m_cost_kib = u32::MAX;
        let bytes = file(&header, 20);
        assert_eq!(Header::decode(&bytes).unwrap_err(), Error::InvalidKdfParams);
    }
}
