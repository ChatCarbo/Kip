//! Générateur de mots de passe et de phrases de passe.
//!
//! Module sans dépendance : la source d'aléa est injectée (`fill`), ce qui permet
//! de le tester avec une source déterministe. L'application utilise l'aléa du
//! système via `generate_password` / `generate_passphrase` de la racine du crate.

use crate::error::{Error, Result};

/// Longueur minimale d'un mot de passe généré.
pub const MIN_LENGTH: usize = 4;
/// Longueur maximale d'un mot de passe généré.
pub const MAX_LENGTH: usize = 128;
/// Taille minimale de la liste de mots d'une phrase de passe (liste EFF « large » : 7776).
pub const MIN_WORDLIST: usize = 7776;
/// Nombre de mots minimal et maximal d'une phrase de passe.
pub const MIN_WORDS: usize = 3;
pub const MAX_WORDS: usize = 12;

const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?/";
/// Caractères faciles à confondre à la lecture.
const AMBIGUOUS: &[u8] = b"Il1O0o";

/// Options de génération d'un mot de passe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordOptions {
    /// Longueur en caractères.
    pub length: usize,
    /// Inclure des minuscules.
    pub lowercase: bool,
    /// Inclure des majuscules.
    pub uppercase: bool,
    /// Inclure des chiffres.
    pub digits: bool,
    /// Inclure des symboles.
    pub symbols: bool,
    /// Exclure les caractères ambigus (`I l 1 O 0 o`).
    pub avoid_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
        }
    }
}

impl PasswordOptions {
    /// Alphabets retenus, un par catégorie cochée, ambigus retirés si demandé.
    fn pools(&self) -> Vec<Vec<u8>> {
        let selected = [
            (self.lowercase, LOWERCASE),
            (self.uppercase, UPPERCASE),
            (self.digits, DIGITS),
            (self.symbols, SYMBOLS),
        ];
        selected
            .iter()
            .filter(|(on, _)| *on)
            .map(|(_, set)| {
                set.iter()
                    .copied()
                    .filter(|c| !(self.avoid_ambiguous && AMBIGUOUS.contains(c)))
                    .collect()
            })
            .collect()
    }

    fn validate(&self, pool_count: usize) -> Result<()> {
        if pool_count == 0
            || self.length < MIN_LENGTH
            || self.length > MAX_LENGTH
            || self.length < pool_count
        {
            return Err(Error::InvalidGeneratorOptions);
        }
        Ok(())
    }
}

/// Entropie approximative en bits : `longueur × log2(taille de l'alphabet)`.
/// Légèrement surestimée, car chaque catégorie cochée est garantie présente.
pub fn password_entropy_bits(options: &PasswordOptions) -> f64 {
    let alphabet: usize = options.pools().iter().map(Vec::len).sum();
    if alphabet == 0 {
        return 0.0;
    }
    options.length as f64 * (alphabet as f64).log2()
}

/// Entier uniforme dans `0..bound`, par rejet (aucun biais de modulo).
fn uniform<R>(bound: usize, fill: &mut R) -> Result<usize>
where
    R: FnMut(&mut [u8]) -> Result<()>,
{
    if bound == 0 || bound as u64 > u32::MAX as u64 {
        return Err(Error::InvalidGeneratorOptions);
    }
    let bound = bound as u64;
    // Plus grand multiple de `bound` inférieur ou égal à 2^32 : au-delà, on rejette.
    let zone = (1u64 << 32) / bound * bound;
    loop {
        let mut bytes = [0u8; 4];
        fill(&mut bytes)?;
        let x = u32::from_le_bytes(bytes) as u64;
        if x < zone {
            return Ok((x % bound) as usize);
        }
    }
}

/// Génère un mot de passe ASCII. Chaque catégorie cochée apparaît au moins une
/// fois ; l'ordre est ensuite mélangé (Fisher-Yates avec tirage sans biais).
pub fn generate_password<R>(options: &PasswordOptions, fill: &mut R) -> Result<Vec<u8>>
where
    R: FnMut(&mut [u8]) -> Result<()>,
{
    let pools = options.pools();
    options.validate(pools.len())?;
    let alphabet: Vec<u8> = pools.iter().flatten().copied().collect();

    let mut out: Vec<u8> = Vec::with_capacity(options.length);
    for pool in &pools {
        out.push(pool[uniform(pool.len(), fill)?]);
    }
    while out.len() < options.length {
        out.push(alphabet[uniform(alphabet.len(), fill)?]);
    }
    for i in (1..out.len()).rev() {
        let j = uniform(i + 1, fill)?;
        out.swap(i, j);
    }
    Ok(out)
}

/// Génère une phrase de passe de `count` mots tirés dans `words`.
pub fn generate_passphrase<R>(
    words: &[&str],
    count: usize,
    separator: &str,
    capitalize: bool,
    fill: &mut R,
) -> Result<String>
where
    R: FnMut(&mut [u8]) -> Result<()>,
{
    if words.len() < MIN_WORDLIST {
        return Err(Error::WordlistTooShort);
    }
    if !(MIN_WORDS..=MAX_WORDS).contains(&count) {
        return Err(Error::InvalidGeneratorOptions);
    }
    let mut out = String::new();
    for i in 0..count {
        if i > 0 {
            out.push_str(separator);
        }
        let word = words[uniform(words.len(), fill)?];
        if capitalize {
            let mut chars = word.chars();
            if let Some(first) = chars.next() {
                out.extend(first.to_uppercase());
                out.push_str(chars.as_str());
            }
        } else {
            out.push_str(word);
        }
    }
    Ok(out)
}

/// Extrait les mots d'une liste au format EFF (`11111<TAB>mot`) ou d'une liste
/// simple (un mot par ligne). Les lignes vides sont ignorées.
pub fn parse_wordlist(text: &str) -> Vec<&str> {
    text.lines()
        .filter_map(|line| line.split_whitespace().last())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Source déterministe (congruentiel linéaire) : suffisante pour tester la logique.
    fn lcg(seed: u64) -> impl FnMut(&mut [u8]) -> Result<()> {
        let mut state = seed;
        move |buf: &mut [u8]| {
            for b in buf.iter_mut() {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *b = (state >> 56) as u8;
            }
            Ok(())
        }
    }

    fn only(
        lower: bool,
        upper: bool,
        digits: bool,
        symbols: bool,
        length: usize,
    ) -> PasswordOptions {
        PasswordOptions {
            length,
            lowercase: lower,
            uppercase: upper,
            digits,
            symbols,
            avoid_ambiguous: false,
        }
    }

    #[test]
    fn respects_length_and_alphabet() {
        let mut rng = lcg(1);
        for length in [4, 8, 20, 64, 128] {
            let pw = generate_password(&only(true, false, true, false, length), &mut rng).unwrap();
            assert_eq!(pw.len(), length);
            assert!(pw
                .iter()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
        }
    }

    #[test]
    fn every_selected_class_is_present() {
        let mut rng = lcg(2);
        for _ in 0..200 {
            let pw = generate_password(&PasswordOptions::default(), &mut rng).unwrap();
            assert!(pw.iter().any(u8::is_ascii_lowercase));
            assert!(pw.iter().any(u8::is_ascii_uppercase));
            assert!(pw.iter().any(u8::is_ascii_digit));
            assert!(pw.iter().any(|c| SYMBOLS.contains(c)));
        }
    }

    #[test]
    fn minimum_length_still_covers_all_four_classes() {
        let mut rng = lcg(3);
        for _ in 0..200 {
            let opts = PasswordOptions {
                length: 4,
                ..PasswordOptions::default()
            };
            let pw = generate_password(&opts, &mut rng).unwrap();
            assert_eq!(pw.len(), 4);
            assert!(pw.iter().any(u8::is_ascii_lowercase));
            assert!(pw.iter().any(u8::is_ascii_uppercase));
            assert!(pw.iter().any(u8::is_ascii_digit));
            assert!(pw.iter().any(|c| SYMBOLS.contains(c)));
        }
    }

    #[test]
    fn ambiguous_characters_can_be_excluded() {
        let mut rng = lcg(4);
        let opts = PasswordOptions {
            avoid_ambiguous: true,
            length: 128,
            ..PasswordOptions::default()
        };
        for _ in 0..50 {
            let pw = generate_password(&opts, &mut rng).unwrap();
            assert!(pw.iter().all(|c| !AMBIGUOUS.contains(c)));
        }
    }

    #[test]
    fn impossible_options_are_rejected() {
        let mut rng = lcg(5);
        let none = only(false, false, false, false, 20);
        assert_eq!(
            generate_password(&none, &mut rng).unwrap_err(),
            Error::InvalidGeneratorOptions
        );
        let too_short = PasswordOptions {
            length: MIN_LENGTH - 1,
            ..PasswordOptions::default()
        };
        assert!(generate_password(&too_short, &mut rng).is_err());
        let too_long = PasswordOptions {
            length: MAX_LENGTH + 1,
            ..PasswordOptions::default()
        };
        assert!(generate_password(&too_long, &mut rng).is_err());
    }

    #[test]
    fn random_source_errors_are_propagated() {
        let mut failing = |_: &mut [u8]| Err(Error::Random);
        assert_eq!(
            generate_password(&PasswordOptions::default(), &mut failing).unwrap_err(),
            Error::Random
        );
    }

    #[test]
    fn rejection_sampling_discards_the_biased_zone() {
        // bound = 3 : zone = 2^32 / 3 * 3 = 4294967295. 0xFFFFFFFF doit être rejeté.
        let mut calls = 0;
        let mut rng = |buf: &mut [u8]| {
            calls += 1;
            let value: u32 = if calls == 1 { u32::MAX } else { 5 };
            buf.copy_from_slice(&value.to_le_bytes());
            Ok(())
        };
        assert_eq!(uniform(3, &mut rng).unwrap(), 5 % 3);
        assert_eq!(calls, 2);
    }

    #[test]
    fn uniform_rejects_zero_bound() {
        let mut rng = lcg(6);
        assert!(uniform(0, &mut rng).is_err());
    }

    #[test]
    fn digits_are_roughly_uniform() {
        let mut rng = lcg(7);
        let opts = only(false, false, true, false, 128);
        let mut counts = [0usize; 10];
        for _ in 0..200 {
            for c in generate_password(&opts, &mut rng).unwrap() {
                counts[(c - b'0') as usize] += 1;
            }
        }
        let expected = 200.0 * 128.0 / 10.0;
        for (digit, &n) in counts.iter().enumerate() {
            let deviation = (n as f64 - expected).abs() / expected;
            assert!(deviation < 0.10, "chiffre {digit} : {n}");
        }
    }

    #[test]
    fn entropy_estimate() {
        let digits = only(false, false, true, false, 10);
        assert!((password_entropy_bits(&digits) - 10.0 * 10f64.log2()).abs() < 1e-9);
        assert_eq!(
            password_entropy_bits(&only(false, false, false, false, 10)),
            0.0
        );
        assert!(password_entropy_bits(&PasswordOptions::default()) > 100.0);
    }

    fn synthetic_words(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("mot{i:04}")).collect()
    }

    #[test]
    fn passphrase_shape() {
        let owned = synthetic_words(MIN_WORDLIST);
        let words: Vec<&str> = owned.iter().map(String::as_str).collect();
        let mut rng = lcg(8);
        let phrase = generate_passphrase(&words, 6, "-", true, &mut rng).unwrap();
        let parts: Vec<&str> = phrase.split('-').collect();
        assert_eq!(parts.len(), 6);
        assert!(parts.iter().all(|p| p.starts_with("Mot") && p.len() == 7));
        let plain = generate_passphrase(&words, 4, " ", false, &mut rng).unwrap();
        assert_eq!(plain.split(' ').count(), 4);
        assert!(plain.starts_with("mot"));
    }

    #[test]
    fn passphrase_rejects_short_list_and_bad_counts() {
        let owned = synthetic_words(MIN_WORDLIST - 1);
        let short: Vec<&str> = owned.iter().map(String::as_str).collect();
        let mut rng = lcg(9);
        assert_eq!(
            generate_passphrase(&short, 5, "-", false, &mut rng).unwrap_err(),
            Error::WordlistTooShort
        );
        let owned = synthetic_words(MIN_WORDLIST);
        let words: Vec<&str> = owned.iter().map(String::as_str).collect();
        assert!(generate_passphrase(&words, MIN_WORDS - 1, "-", false, &mut rng).is_err());
        assert!(generate_passphrase(&words, MAX_WORDS + 1, "-", false, &mut rng).is_err());
    }

    #[test]
    fn wordlist_parsing_handles_eff_and_plain_formats() {
        let text = "11111\tabacus\n11112\tabdomen\n\nsimple\n  \n";
        assert_eq!(parse_wordlist(text), vec!["abacus", "abdomen", "simple"]);
    }
}
