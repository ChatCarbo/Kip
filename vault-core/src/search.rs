//! Recherche instantanée dans les entrées : filtre en mémoire, sans index.

/// Score d'une entrée pour une requête (plus bas = meilleur), ou `None` si elle
/// ne correspond pas. `fields` est ordonné par importance (titre, adresse,
/// identifiant). Chaque mot de la requête doit apparaître dans au moins un champ,
/// sans tenir compte de la casse. Une requête vide correspond à tout.
pub fn score(query: &str, fields: &[&str]) -> Option<u32> {
    let terms: Vec<String> = query.split_whitespace().map(str::to_lowercase).collect();
    if terms.is_empty() {
        return Some(0);
    }
    let lowered: Vec<String> = fields.iter().map(|f| f.to_lowercase()).collect();
    let mut total = 0u32;
    for term in &terms {
        let best = lowered
            .iter()
            .enumerate()
            .filter_map(|(i, field)| {
                field
                    .find(term.as_str())
                    .map(|pos| i as u32 * 1000 + pos.min(999) as u32)
            })
            .min()?;
        total = total.saturating_add(best);
    }
    Some(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_query_matches_everything() {
        assert_eq!(score("", &["a", "b"]), Some(0));
        assert_eq!(score("   ", &["a"]), Some(0));
    }

    #[test]
    fn matching_is_case_insensitive() {
        assert!(score("GITHUB", &["github", "", ""]).is_some());
        assert!(score("github", &["GitHub", "", ""]).is_some());
    }

    #[test]
    fn all_terms_must_match() {
        let fields = ["GitHub perso", "https://github.com", "jerome"];
        assert!(score("github jerome", &fields).is_some());
        assert!(score("github inconnu", &fields).is_none());
    }

    #[test]
    fn title_matches_rank_before_url_matches() {
        let title_hit = score("banque", &["Ma banque", "https://exemple.org", "jc"]).unwrap();
        let url_hit = score("banque", &["Compte", "https://banque.example", "jc"]).unwrap();
        assert!(title_hit < url_hit);
    }

    #[test]
    fn earlier_positions_rank_first() {
        let early = score("mail", &["mail pro", "", ""]).unwrap();
        let late = score("mail", &["ma boîte mail", "", ""]).unwrap();
        assert!(early < late);
    }

    #[test]
    fn no_match_returns_none() {
        assert_eq!(score("zzz", &["abc", "def", "ghi"]), None);
    }
}
