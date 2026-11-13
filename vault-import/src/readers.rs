//! Lecteurs par format : transforment un texte en entrées et en rapport.

use crate::json::{self, Json};
use crate::xml::{self, Element};
use crate::{csv, host_of, ImportError, ImportedEntry, Report, SecretString};

type Output = (Vec<ImportedEntry>, Report);

/// Construit une entrée : espaces retirés sauf dans le mot de passe, titre déduit si absent.
fn make_entry(title: &str, url: &str, username: &str, password: &str) -> ImportedEntry {
    let url = url.trim().to_string();
    let username = username.trim().to_string();
    let mut title = title.trim().to_string();
    if title.is_empty() {
        title = host_of(&url);
    }
    if title.is_empty() {
        title = username.clone();
    }
    if title.is_empty() {
        title = "(sans titre)".to_string();
    }
    ImportedEntry {
        title,
        url,
        username,
        password: SecretString::new(password.to_string()),
    }
}

// ---------------------------------------------------------------------- CSV

/// Retire casse, espaces, tirets et soulignés : « Web Site », « web_site » et « website » se valent.
fn normalize(name: &str) -> String {
    name.chars()
        .filter(|c| !matches!(c, ' ' | '_' | '-'))
        .flat_map(char::to_lowercase)
        .collect()
}

fn find_column(header: &[String], aliases: &[&str]) -> Option<usize> {
    header
        .iter()
        .position(|name| aliases.contains(&normalize(name).as_str()))
}

struct Columns {
    title: Option<usize>,
    url: Option<usize>,
    username: Option<usize>,
    password: usize,
    notes: Option<usize>,
    totp: Option<usize>,
    kind: Option<usize>,
}

impl Columns {
    fn from_header(header: &[String]) -> Result<Self, ImportError> {
        let password = find_column(
            header,
            &[
                "password",
                "loginpassword",
                "pass",
                "passwd",
                "pwd",
                "motdepasse",
            ],
        )
        .ok_or_else(|| ImportError::NoPasswordColumn(header.join(", ")))?;
        Ok(Self {
            title: find_column(
                header,
                &[
                    "name",
                    "title",
                    "account",
                    "accountname",
                    "label",
                    "titre",
                    "nom",
                ],
            ),
            url: find_column(
                header,
                &[
                    "url", "loginuri", "website", "address", "loginurl", "hostname", "site",
                ],
            ),
            username: find_column(
                header,
                &[
                    "username",
                    "loginusername",
                    "user",
                    "login",
                    "loginname",
                    "identifiant",
                ],
            ),
            password,
            notes: find_column(header, &["notes", "note", "extra", "comments", "comment"]),
            totp: find_column(header, &["totp", "logintotp", "otpsecret", "otp"]),
            kind: find_column(header, &["type"]),
        })
    }
}

pub fn csv_entries(text: &str) -> Result<Output, ImportError> {
    let delimiter = csv::detect_delimiter(text);
    let rows = csv::parse(text, delimiter).map_err(|_| {
        ImportError::Csv("CSV invalide : un guillemet n'est jamais refermé.".into())
    })?;
    let (header, body) = rows.split_first().ok_or(ImportError::Empty)?;
    let columns = Columns::from_header(header)?;

    let mut report = Report::default();
    let mut entries = Vec::new();
    for row in body {
        let cell = |index: Option<usize>| -> &str {
            index.and_then(|i| row.get(i)).map_or("", String::as_str)
        };
        if columns.kind.is_some() {
            let kind = cell(columns.kind).trim().to_lowercase();
            if !matches!(kind.as_str(), "" | "login" | "password") {
                report.skipped_non_login += 1;
                continue;
            }
        }
        let password = cell(Some(columns.password));
        if password.is_empty() {
            report.skipped_no_password += 1;
            continue;
        }
        if !cell(columns.notes).trim().is_empty() {
            report.dropped_notes += 1;
        }
        if !cell(columns.totp).trim().is_empty() {
            report.dropped_totp += 1;
        }
        entries.push(make_entry(
            cell(columns.title),
            cell(columns.url),
            cell(columns.username),
            password,
        ));
    }
    Ok((entries, report))
}

// ----------------------------------------------------------- JSON Bitwarden

fn non_empty_str(value: Option<&Json>) -> Option<&str> {
    value
        .and_then(Json::as_str)
        .filter(|s| !s.trim().is_empty())
}

pub fn bitwarden_entries(text: &str) -> Result<Output, ImportError> {
    let root = json::parse(text).map_err(ImportError::Json)?;
    // Un export chiffré n'a pas de clé « items » (il contient « data ») : on teste donc
    // « encrypted » en premier pour donner le bon message.
    if root.get("encrypted").and_then(Json::as_bool) == Some(true) {
        return Err(ImportError::EncryptedBitwarden);
    }
    let items = root
        .get("items")
        .and_then(Json::as_array)
        .ok_or(ImportError::NotBitwarden)?;

    let mut report = Report::default();
    let mut entries = Vec::new();
    for item in items {
        // Type 1 = identifiant ; 2 = note, 3 = carte, 4 = identité.
        let login = match (item.get("type").and_then(Json::as_i64), item.get("login")) {
            (Some(1), Some(login)) => login,
            _ => {
                report.skipped_non_login += 1;
                continue;
            }
        };
        let password = login.get("password").and_then(Json::as_str).unwrap_or("");
        if password.is_empty() {
            report.skipped_no_password += 1;
            continue;
        }
        if non_empty_str(item.get("notes")).is_some() {
            report.dropped_notes += 1;
        }
        if non_empty_str(login.get("totp")).is_some() {
            report.dropped_totp += 1;
        }
        let url = login
            .get("uris")
            .and_then(Json::as_array)
            .and_then(|uris| uris.iter().find_map(|u| non_empty_str(u.get("uri"))))
            .unwrap_or("");
        entries.push(make_entry(
            item.get("name").and_then(Json::as_str).unwrap_or(""),
            url,
            login.get("username").and_then(Json::as_str).unwrap_or(""),
            password,
        ));
    }
    Ok((entries, report))
}

// -------------------------------------------------------------- XML KeePass

fn walk_group(
    group: &Element,
    recycle_bin: Option<&str>,
    entries: &mut Vec<ImportedEntry>,
    report: &mut Report,
) -> Result<(), ImportError> {
    // La corbeille contient des entrées supprimées : on ne les importe pas.
    if let (Some(bin), Some(uuid)) = (recycle_bin, group.child("UUID")) {
        if uuid.text.trim() == bin {
            return Ok(());
        }
    }
    for entry in group.children_named("Entry") {
        let mut fields = Fields::default();
        // Seuls les `String` directs comptent : l'historique des versions précédentes
        // est dans `History/Entry` et n'est pas visité.
        for string in entry.children_named("String") {
            let (Some(key), Some(value)) = (string.child("Key"), string.child("Value")) else {
                continue;
            };
            if value.attribute("Protected") == Some("True") && !value.text.is_empty() {
                return Err(ImportError::ProtectedValues);
            }
            match key.text.as_str() {
                "Title" => fields.title = value.text.clone(),
                "UserName" => fields.username = value.text.clone(),
                "Password" => fields.password = value.text.clone(),
                "URL" => fields.url = value.text.clone(),
                "Notes" => fields.has_notes = !value.text.trim().is_empty(),
                "otp" => fields.has_totp = !value.text.trim().is_empty(),
                _ => {}
            }
        }
        if fields.password.is_empty() {
            report.skipped_no_password += 1;
            continue;
        }
        report.dropped_notes += usize::from(fields.has_notes);
        report.dropped_totp += usize::from(fields.has_totp);
        entries.push(make_entry(
            &fields.title,
            &fields.url,
            &fields.username,
            &fields.password,
        ));
    }
    for child in group.children_named("Group") {
        walk_group(child, recycle_bin, entries, report)?;
    }
    Ok(())
}

#[derive(Default)]
struct Fields {
    title: String,
    url: String,
    username: String,
    password: String,
    has_notes: bool,
    has_totp: bool,
}

pub fn keepass_entries(text: &str) -> Result<Output, ImportError> {
    let root = xml::parse(text).map_err(ImportError::Xml)?;
    if root.name != "KeePassFile" {
        return Err(ImportError::NotKeePassXml);
    }
    let recycle_bin = root
        .child("Meta")
        .and_then(|meta| meta.child("RecycleBinUUID"))
        .map(|uuid| uuid.text.trim())
        .filter(|uuid| !uuid.is_empty());
    let top = root.child("Root").ok_or(ImportError::NotKeePassXml)?;

    let mut report = Report::default();
    let mut entries = Vec::new();
    for group in top.children_named("Group") {
        walk_group(group, recycle_bin, &mut entries, &mut report)?;
    }
    Ok((entries, report))
}
