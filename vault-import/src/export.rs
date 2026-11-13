//! Export en clair. L'appelant doit avertir l'utilisateur que le fichier produit
//! contient tous les mots de passe lisibles.
//!
//! Les valeurs sont écrites telles quelles, sans neutralisation de formules : un
//! mot de passe commençant par `=`, `+`, `-` ou `@` doit pouvoir être réimporté
//! à l'identique. Ne pas ouvrir ces exports dans un tableur.

use crate::csv::write_row;
use crate::json::escape;

/// Une entrée à exporter.
#[derive(Debug, Clone, Copy)]
pub struct ExportEntry<'a> {
    pub title: &'a str,
    pub url: &'a str,
    pub username: &'a str,
    pub password: &'a str,
}

/// CSV au format des navigateurs (`name,url,username,password,note`), que Chrome,
/// Edge, Firefox et la plupart des gestionnaires savent importer.
pub fn export_csv(entries: &[ExportEntry<'_>]) -> String {
    let mut out = String::new();
    write_row(&mut out, &["name", "url", "username", "password", "note"]);
    for entry in entries {
        write_row(
            &mut out,
            &[entry.title, entry.url, entry.username, entry.password, ""],
        );
    }
    out
}

/// JSON non chiffré au format d'export de Bitwarden.
pub fn export_bitwarden_json(entries: &[ExportEntry<'_>]) -> String {
    let mut out = String::from("{\n  \"encrypted\": false,\n  \"folders\": [],\n  \"items\": [");
    for (index, entry) in entries.iter().enumerate() {
        out.push_str(if index == 0 { "\n    " } else { ",\n    " });
        let uris = if entry.url.is_empty() {
            "[]".to_string()
        } else {
            format!("[{{\"match\":null,\"uri\":{}}}]", escape(entry.url))
        };
        out.push_str(&format!(
            "{{\"type\":1,\"reprompt\":0,\"name\":{},\"notes\":null,\"favorite\":false,\
             \"login\":{{\"uris\":{},\"username\":{},\"password\":{},\"totp\":null}},\
             \"folderId\":null,\"organizationId\":null,\"collectionIds\":null}}",
            escape(entry.title),
            uris,
            escape(entry.username),
            escape(entry.password),
        ));
    }
    out.push_str(if entries.is_empty() {
        "]\n}\n"
    } else {
        "\n  ]\n}\n"
    });
    out
}
