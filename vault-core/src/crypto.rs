//! Primitives cryptographiques : uniquement des crates RustCrypto, rien de maison.

use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::header::{
    Envelope, KdfParams, KEY_LEN, MIN_M_COST_KIB, MIN_T_COST, NONCE_LEN, WRAPPED_KEY_LEN,
};

/// Mémoire maximale essayée pendant la calibration (512 Mio).
const CALIBRATION_MAX_M_KIB: u32 = 512 * 1024;
/// Nombre de passes maximal essayé pendant la calibration.
const CALIBRATION_MAX_T: u32 = 12;

/// Octets aléatoires du système.
pub fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    OsRng.try_fill_bytes(&mut buf).map_err(|_| Error::Random)?;
    Ok(buf)
}

/// Remplit `buf` d'octets aléatoires du système (source du générateur de mots de passe).
pub fn fill_random(buf: &mut [u8]) -> Result<()> {
    OsRng.try_fill_bytes(buf).map_err(|_| Error::Random)
}

/// Clé de 256 bits tirée directement dans un tampon alloué sur le tas (adresse
/// stable, donc verrouillable en mémoire par l'application) et effacé à la
/// libération. Le secret ne transite jamais par la pile.
pub fn random_key() -> Result<Box<Zeroizing<[u8; KEY_LEN]>>> {
    let mut key = Box::new(Zeroizing::new([0u8; KEY_LEN]));
    OsRng
        .try_fill_bytes(&mut **key)
        .map_err(|_| Error::Random)?;
    Ok(key)
}

/// Dérive une clé de 256 bits du mot de passe avec Argon2id.
pub fn derive_key(
    password: &[u8],
    salt: &[u8],
    kdf: &KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    kdf.validate()?;
    let params = Params::new(kdf.m_cost_kib, kdf.t_cost, kdf.p_cost, Some(KEY_LEN))
        .map_err(|_| Error::InvalidKdfParams)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password, salt, &mut *out)
        .map_err(|_| Error::Kdf)?;
    Ok(out)
}

fn cipher(key: &[u8; KEY_LEN]) -> Result<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::Encrypt)
}

/// Chiffre et authentifie `plaintext` ainsi que `aad`.
pub fn encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    cipher(key)?
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Encrypt)
}

/// Déchiffre après vérification de l'étiquette. Toute erreur est la même :
/// mauvaise clé et données altérées ne sont pas distinguables.
pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let plaintext = cipher(key)?
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::WrongPasswordOrCorrupt)?;
    Ok(Zeroizing::new(plaintext))
}

/// Enveloppe la clé du coffre sous `kek`.
pub fn wrap_key(kek: &[u8; KEY_LEN], vault_key: &[u8; KEY_LEN], aad: &[u8]) -> Result<Envelope> {
    let nonce = random_array::<NONCE_LEN>()?;
    let ciphertext = encrypt(kek, &nonce, aad, vault_key)?;
    let wrapped_key: [u8; WRAPPED_KEY_LEN] = ciphertext.try_into().map_err(|_| Error::Encrypt)?;
    Ok(Envelope { nonce, wrapped_key })
}

/// Ouvre une enveloppe et renvoie la clé du coffre.
pub fn unwrap_key(
    kek: &[u8; KEY_LEN],
    envelope: &Envelope,
    aad: &[u8],
) -> Result<Box<Zeroizing<[u8; KEY_LEN]>>> {
    let plaintext = decrypt(kek, &envelope.nonce, aad, &envelope.wrapped_key)?;
    if plaintext.len() != KEY_LEN {
        return Err(Error::WrongPasswordOrCorrupt);
    }
    let mut key = Box::new(Zeroizing::new([0u8; KEY_LEN]));
    key.copy_from_slice(&plaintext);
    Ok(key)
}

/// Cherche les paramètres Argon2id les plus coûteux qui restent sous `target`
/// sur cette machine, sans jamais descendre sous le plancher de sécurité.
/// À appeler une fois au premier lancement ; le résultat est stocké dans l'en-tête.
pub fn calibrate_kdf(target: Duration) -> Result<KdfParams> {
    let lanes = std::thread::available_parallelism()
        .map_or(1, |n| n.get() as u32)
        .clamp(1, 4);
    let salt = [0u8; 32];
    let measure = |params: &KdfParams| -> Result<Duration> {
        let start = Instant::now();
        derive_key(b"calibration", &salt, params)?;
        Ok(start.elapsed())
    };

    let mut best = KdfParams {
        m_cost_kib: MIN_M_COST_KIB.max(8 * lanes),
        t_cost: MIN_T_COST,
        p_cost: lanes,
    };
    best.validate()?;

    // D'abord la mémoire (plus efficace contre le matériel d'attaque), par doublement.
    loop {
        let next_m = best.m_cost_kib.saturating_mul(2);
        if next_m > CALIBRATION_MAX_M_KIB {
            break;
        }
        let candidate = KdfParams {
            m_cost_kib: next_m,
            ..best
        };
        if measure(&candidate)? > target {
            break;
        }
        best = candidate;
    }
    // Puis les passes, tant que le budget de temps le permet.
    while best.t_cost < CALIBRATION_MAX_T {
        let candidate = KdfParams {
            t_cost: best.t_cost + 1,
            ..best
        };
        if measure(&candidate)? > target {
            break;
        }
        best = candidate;
    }
    Ok(best)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; KEY_LEN] = [0x11; KEY_LEN];
    const NONCE: [u8; NONCE_LEN] = [0x22; NONCE_LEN];

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let ct = encrypt(&KEY, &NONCE, b"aad", b"message").unwrap();
        assert_eq!(ct.len(), b"message".len() + 16);
        let pt = decrypt(&KEY, &NONCE, b"aad", &ct).unwrap();
        assert_eq!(&pt[..], b"message");
    }

    #[test]
    fn decrypt_fails_on_wrong_key_aad_nonce_or_tamper() {
        let ct = encrypt(&KEY, &NONCE, b"aad", b"message").unwrap();
        let other_key = [0x12; KEY_LEN];
        let other_nonce = [0x23; NONCE_LEN];
        assert!(decrypt(&other_key, &NONCE, b"aad", &ct).is_err());
        assert!(decrypt(&KEY, &other_nonce, b"aad", &ct).is_err());
        assert!(decrypt(&KEY, &NONCE, b"aae", &ct).is_err());
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(decrypt(&KEY, &NONCE, b"aad", &bad).is_err());
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let vault_key = [0x33; KEY_LEN];
        let env = wrap_key(&KEY, &vault_key, b"hdr").unwrap();
        assert_eq!(**unwrap_key(&KEY, &env, b"hdr").unwrap(), vault_key);
        assert!(unwrap_key(&KEY, &env, b"other").is_err());
    }

    #[test]
    fn derive_key_is_deterministic_and_input_sensitive() {
        let kdf = KdfParams {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        };
        let a = derive_key(b"pw", &[1u8; 32], &kdf).unwrap();
        let b = derive_key(b"pw", &[1u8; 32], &kdf).unwrap();
        let c = derive_key(b"pw2", &[1u8; 32], &kdf).unwrap();
        let d = derive_key(b"pw", &[2u8; 32], &kdf).unwrap();
        assert_eq!(*a, *b);
        assert_ne!(*a, *c);
        assert_ne!(*a, *d);
    }

    #[test]
    fn random_values_differ() {
        assert_ne!(random_array::<32>().unwrap(), random_array::<32>().unwrap());
    }

    #[test]
    fn calibration_returns_valid_params() {
        let params = calibrate_kdf(Duration::from_millis(1)).unwrap();
        assert!(params.validate().is_ok());
    }
}
