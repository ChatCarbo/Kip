use super::*;

fn parse_csv(text: &str) -> Parsed {
    parse(text.as_bytes(), None).unwrap()
}

/// (titre, adresse, identifiant, mot de passe) de chaque entrée.
fn rows(parsed: &Parsed) -> Vec<(String, String, String, String)> {
    parsed
        .entries
        .iter()
        .map(|e| {
            (
                e.title.clone(),
                e.url.clone(),
                e.username.clone(),
                e.password.as_str().to_string(),
            )
        })
        .collect()
}

fn row(t: &str, u: &str, n: &str, p: &str) -> (String, String, String, String) {
    (t.into(), u.into(), n.into(), p.into())
}

// ------------------------------------------------------------- détection

#[test]
fn detects_formats_from_content() {
    assert_eq!(detect(b"{\"items\":[]}"), Ok(Format::BitwardenJson));
    assert_eq!(
        detect(b"  \n<?xml version=\"1.0\"?><a/>"),
        Ok(Format::KeePassXml)
    );
    assert_eq!(detect(b"name,url,password\n"), Ok(Format::Csv));
    assert_eq!(
        detect("\u{feff}{\"a\":1}".as_bytes()),
        Ok(Format::BitwardenJson)
    );
    assert_eq!(
        detect("\u{feff}name,password\n".as_bytes()),
        Ok(Format::Csv)
    );
}

#[test]
fn rejects_empty_binary_and_oversized_files() {
    assert_eq!(detect(b""), Err(ImportError::Empty));
    assert_eq!(detect(b" \n\t "), Err(ImportError::Empty));
    assert_eq!(detect(&[0xff, 0xfe, 0x00, 0x41]), Err(ImportError::NotText));
    assert_eq!(
        detect(&vec![b'a'; MAX_FILE_SIZE + 1]),
        Err(ImportError::TooLarge)
    );
}

#[test]
fn keepass_databases_are_recognised_and_explained() {
    let kdbx = [0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5, 0, 0, 4, 0];
    assert_eq!(detect(&kdbx), Err(ImportError::Kdbx));
    assert_eq!(parse(&kdbx, None).unwrap_err(), ImportError::Kdbx);
    // Même avec un format forcé : on ne lit jamais un binaire comme du texte.
    assert_eq!(
        parse(&kdbx, Some(Format::Csv)).unwrap_err(),
        ImportError::Kdbx
    );
    assert!(ImportError::Kdbx.to_string().contains("XML"));
}

// ------------------------------------------------------------------- CSV

#[test]
fn chrome_and_edge_csv() {
    let parsed = parse_csv(
        "name,url,username,password,note\n\
         GitHub,https://github.com/login,jerome,pw-gh-1,\n\
         Banque,https://www.banque.example/,j.c,\"p,w\"\"2\",un commentaire\n",
    );
    assert_eq!(parsed.format, Format::Csv);
    assert_eq!(
        rows(&parsed),
        vec![
            row("GitHub", "https://github.com/login", "jerome", "pw-gh-1"),
            row("Banque", "https://www.banque.example/", "j.c", "p,w\"2"),
        ]
    );
    assert_eq!(parsed.report.dropped_notes, 1);
}

#[test]
fn firefox_csv_derives_titles_from_the_address() {
    let parsed = parse_csv(
        "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"\n\
         \"https://www.exemple.org\",\"moi\",\"mdp-ff\",\"\",\"https://www.exemple.org\",\"{g}\",\"1\",\"2\",\"3\"\n",
    );
    assert_eq!(
        rows(&parsed),
        vec![row(
            "exemple.org",
            "https://www.exemple.org",
            "moi",
            "mdp-ff"
        )]
    );
}

#[test]
fn bitwarden_csv_skips_non_logins_and_counts_dropped_data() {
    let parsed = parse_csv(
        "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
         ,0,login,Site A,,,0,https://a.example,ua,pa,\n\
         ,0,note,Une note,secret,,0,,,,\n\
         ,1,login,Site B,\"note b\",,0,https://b.example,ub,pb,JBSWY3DPEHPK3PXP\n",
    );
    assert_eq!(
        rows(&parsed),
        vec![
            row("Site A", "https://a.example", "ua", "pa"),
            row("Site B", "https://b.example", "ub", "pb"),
        ]
    );
    assert_eq!(parsed.report.skipped_non_login, 1);
    assert_eq!(parsed.report.dropped_notes, 1);
    assert_eq!(parsed.report.dropped_totp, 1);
}

#[test]
fn keepassxc_csv() {
    let parsed = parse_csv(
        "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\",\"Icon\",\"Last Modified\",\"Created\"\n\
         \"Root\",\"Mail\",\"moi@example.org\",\"pw-mail\",\"https://mail.example\",\"\",\"\",\"0\",\"2026-01-01T00:00:00Z\",\"2026-01-01T00:00:00Z\"\n",
    );
    assert_eq!(
        rows(&parsed),
        vec![row(
            "Mail",
            "https://mail.example",
            "moi@example.org",
            "pw-mail"
        )]
    );
}

#[test]
fn lastpass_csv_skips_secure_notes_without_password() {
    let parsed = parse_csv(
        "url,username,password,totp,extra,name,grouping,fav\n\
         http://sn,,,,\"Note\",Ma note,,0\n\
         https://l.example,lu,lp,,,LP site,Perso,0\n",
    );
    assert_eq!(
        rows(&parsed),
        vec![row("LP site", "https://l.example", "lu", "lp")]
    );
    assert_eq!(parsed.report.skipped_no_password, 1);
}

#[test]
fn onepassword_csv_keeps_logins_and_passwords_only() {
    let parsed = parse_csv(
        "Title,Url,Username,Password,Notes,Type\n\
         Compte,https://op.example,opu,opp,,Login\n\
         Carte,,,,\"n\",Credit Card\n",
    );
    assert_eq!(
        rows(&parsed),
        vec![row("Compte", "https://op.example", "opu", "opp")]
    );
    assert_eq!(parsed.report.skipped_non_login, 1);
}

#[test]
fn roboform_style_headers_are_understood() {
    let parsed =
        parse_csv("Name,Url,MatchUrl,Login,Pwd,Note,Folder\nRF,https://rf.example,,rfu,rfp,,\n");
    assert_eq!(
        rows(&parsed),
        vec![row("RF", "https://rf.example", "rfu", "rfp")]
    );
}

#[test]
fn semicolon_separated_csv_from_french_spreadsheets() {
    let parsed = parse_csv("name;url;username;password\nSite;https://s.example;u;\"p;1\"\n");
    assert_eq!(
        rows(&parsed),
        vec![row("Site", "https://s.example", "u", "p;1")]
    );
}

#[test]
fn passwords_keep_their_exact_spaces_while_other_fields_are_trimmed() {
    let parsed =
        parse_csv("name,url,username,password\n  Site  , https://s.example ,  u  ,\" pw \"\n");
    assert_eq!(
        rows(&parsed),
        vec![row("Site", "https://s.example", "u", " pw ")]
    );
}

#[test]
fn title_falls_back_to_host_then_username_then_placeholder() {
    let parsed = parse_csv("url,username,password\nhttps://www.h.example/x,u1,p1\n,u2,p2\n,,p3\n");
    let titles: Vec<_> = parsed.entries.iter().map(|e| e.title.as_str()).collect();
    assert_eq!(titles, vec!["h.example", "u2", "(sans titre)"]);
}

#[test]
fn short_rows_do_not_panic() {
    let parsed =
        parse_csv("name,url,username,password\nA,https://a.example\nB,https://b.example,u,p\n");
    assert_eq!(parsed.entries.len(), 1);
    assert_eq!(parsed.report.skipped_no_password, 1);
}

#[test]
fn csv_without_a_password_column_is_refused_and_lists_the_columns() {
    let error = parse(b"nom,adresse\nx,y\n", None).unwrap_err();
    assert_eq!(error, ImportError::NoPasswordColumn("nom, adresse".into()));
    assert!(error.to_string().contains("nom, adresse"));
}

#[test]
fn broken_csv_is_refused() {
    assert!(matches!(
        parse(b"name,password\n\"a,b\n", None),
        Err(ImportError::Csv(_))
    ));
    // Seulement l'en-tête : aucune entrée, mais ce n'est pas une erreur.
    let parsed = parse_csv("name,url,username,password\n");
    assert!(parsed.entries.is_empty());
}

// ------------------------------------------------------- JSON Bitwarden

#[test]
fn bitwarden_json() {
    let parsed = parse_csv(
        r#"{"encrypted":false,"folders":[{"id":"f1","name":"Perso"}],"items":[
            {"type":1,"name":"Site","notes":"n","login":{"uris":[{"match":null,"uri":""},{"match":null,"uri":"https://site.example/login"}],"username":"u","password":"pé","totp":"JBSW"}},
            {"type":2,"name":"Note","notes":"x"},
            {"type":3,"name":"Carte","card":{}},
            {"type":1,"name":"Vide","login":{"username":"u","password":null}},
            {"type":1,"name":"Sans adresse","login":{"uris":[],"username":"v","password":"q"}}
        ]}"#,
    );
    assert_eq!(parsed.format, Format::BitwardenJson);
    assert_eq!(
        rows(&parsed),
        vec![
            row("Site", "https://site.example/login", "u", "pé"),
            row("Sans adresse", "", "v", "q"),
        ]
    );
    let report = &parsed.report;
    assert_eq!(report.skipped_non_login, 2);
    assert_eq!(report.skipped_no_password, 1);
    assert_eq!(report.dropped_notes, 1);
    assert_eq!(report.dropped_totp, 1);
}

#[test]
fn encrypted_bitwarden_export_is_refused_with_the_right_message() {
    let real_shape = br#"{"encrypted":true,"encKeyValidation_DO_NOT_EDIT":"2.abc","data":"2.def"}"#;
    assert_eq!(
        parse(real_shape, None).unwrap_err(),
        ImportError::EncryptedBitwarden
    );
}

#[test]
fn other_json_is_refused() {
    assert_eq!(
        parse(br#"{"a":1}"#, None).unwrap_err(),
        ImportError::NotBitwarden
    );
    assert!(matches!(
        parse(b"{\"items\":", None),
        Err(ImportError::Json(_))
    ));
}

// ------------------------------------------------------------ XML KeePass

const KEEPASS_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<KeePassFile>
 <Meta><RecycleBinUUID>BIN=</RecycleBinUUID></Meta>
 <Root>
  <Group><UUID>ROOT</UUID><Name>Racine</Name>
   <Entry><UUID>e1</UUID>
     <String><Key>Title</Key><Value>Site &amp; Co</Value></String>
     <String><Key>UserName</Key><Value>moi</Value></String>
     <String><Key>Password</Key><Value ProtectInMemory="True">pw&lt;1&gt;</Value></String>
     <String><Key>URL</Key><Value>https://xml.example</Value></String>
     <String><Key>Notes</Key><Value>une note</Value></String>
     <String><Key>otp</Key><Value>otpauth://totp/x?secret=ABC</Value></String>
     <String><Key>Custom</Key><Value>ignoré</Value></String>
     <History><Entry><String><Key>Password</Key><Value>ancien</Value></String></Entry></History>
   </Entry>
   <Entry><String><Key>Title</Key><Value>Sans mdp</Value></String><String><Key>Password</Key><Value/></String></Entry>
   <Group><UUID>g2</UUID><Name>Sous</Name>
     <Entry><String><Key>Title</Key><Value>Imbriqué</Value></String><String><Key>Password</Key><Value>pw2</Value></String></Entry>
   </Group>
   <Group><UUID>BIN=</UUID><Name>Corbeille</Name>
     <Entry><String><Key>Title</Key><Value>Supprimé</Value></String><String><Key>Password</Key><Value>pw3</Value></String></Entry>
   </Group>
  </Group>
 </Root>
</KeePassFile>"#;

#[test]
fn keepass_xml_reads_nested_groups_and_skips_history_and_recycle_bin() {
    let parsed = parse_csv(KEEPASS_XML);
    assert_eq!(parsed.format, Format::KeePassXml);
    assert_eq!(
        rows(&parsed),
        vec![
            row("Site & Co", "https://xml.example", "moi", "pw<1>"),
            row("Imbriqué", "", "", "pw2"),
        ]
    );
    assert_eq!(parsed.report.skipped_no_password, 1);
    assert_eq!(parsed.report.dropped_notes, 1);
    assert_eq!(parsed.report.dropped_totp, 1);
}

#[test]
fn keepass_xml_with_protected_values_is_refused() {
    let xml = KEEPASS_XML.replace("ProtectInMemory=\"True\"", "Protected=\"True\"");
    assert_eq!(
        parse(xml.as_bytes(), None).unwrap_err(),
        ImportError::ProtectedValues
    );
}

#[test]
fn other_xml_is_refused() {
    assert_eq!(
        parse(b"<a/>", None).unwrap_err(),
        ImportError::NotKeePassXml
    );
    assert_eq!(
        parse(b"<KeePassFile></KeePassFile>", None).unwrap_err(),
        ImportError::NotKeePassXml
    );
    assert!(matches!(parse(b"<a>", None), Err(ImportError::Xml(_))));
}

// ---------------------------------------------------------------- doublons

#[test]
fn host_extraction() {
    for (url, host) in [
        ("https://www.Example.com:8443/path?x#y", "example.com"),
        ("user:pw@host.org/x", "host.org"),
        ("http://[::1]:8080/a", "::1"),
        ("android://hash@com.app", "com.app"),
        ("example.com", "example.com"),
        ("  https://a.b.example/  ", "a.b.example"),
        ("", ""),
    ] {
        assert_eq!(host_of(url), host, "{url}");
    }
}

#[test]
fn duplicates_against_the_vault_and_inside_the_file_are_removed() {
    let mut parsed = parse_csv(
        "name,url,username,password\n\
         A,https://www.a.example/login,Moi,pw1\n\
         A bis,http://a.example/,moi,pw1\n\
         A autre mot de passe,https://a.example,moi,pw2\n\
         B,https://b.example,x,pb\n\
         B encore,https://b.example,x,pb\n",
    );
    let existing = [Fingerprint::new("https://b.example/", "X", "pb")];
    dedup(&existing, &mut parsed);
    let titles: Vec<_> = parsed.entries.iter().map(|e| e.title.as_str()).collect();
    assert_eq!(titles, vec!["A", "A autre mot de passe"]);
    assert_eq!(parsed.report.duplicates, 3);
}

#[test]
fn fingerprint_ignores_scheme_www_and_case_but_not_the_password() {
    let a = Fingerprint::new("https://www.A.example/x", "Moi", "pw");
    assert_eq!(a, Fingerprint::new("http://a.example", " moi ", "pw"));
    assert_ne!(a, Fingerprint::new("http://a.example", "moi", "PW"));
    assert_ne!(a, Fingerprint::new("http://other.example", "moi", "pw"));
}

// ----------------------------------------------------------------- rapport

#[test]
fn report_summary_wording() {
    assert_eq!(Report::default().summary(3), "3 entrée(s) importée(s).");
    let report = Report {
        skipped_no_password: 2,
        skipped_non_login: 1,
        dropped_notes: 4,
        dropped_totp: 1,
        duplicates: 5,
    };
    assert_eq!(
        report.summary(10),
        "10 entrée(s) importée(s). Ignorées : 5 doublon(s), 2 sans mot de passe, 1 autre(s) que des identifiants. \
         Non repris (hors périmètre de cette version) : notes (4), codes TOTP (1)."
    );
}

#[test]
fn imported_entries_never_show_their_password_in_debug_output() {
    let parsed = parse_csv("name,url,username,password\nA,https://a.example,u,tres-secret\n");
    assert!(!format!("{parsed:?}").contains("tres-secret"));
}

// ------------------------------------------------------------------ export

fn sample_export() -> Vec<ExportEntry<'static>> {
    vec![
        ExportEntry {
            title: "Simple",
            url: "https://a.example",
            username: "u",
            password: "p",
        },
        ExportEntry {
            title: "Virgule, \"guillemets\" et\nligne",
            url: "https://b.example/?a=1&b=2",
            username: "é€😀",
            password: "=+-@ \"x\", y\\z\n",
        },
        ExportEntry {
            title: "Sans adresse",
            url: "",
            username: "",
            password: "seul",
        },
    ]
}

fn expected_rows() -> Vec<(String, String, String, String)> {
    sample_export()
        .iter()
        .map(|e| row(e.title, e.url, e.username, e.password))
        .collect()
}

#[test]
fn csv_export_reimports_identically() {
    let text = export_csv(&sample_export());
    assert!(text.starts_with("name,url,username,password,note\n"));
    let parsed = parse(text.as_bytes(), None).unwrap();
    assert_eq!(parsed.format, Format::Csv);
    // Le titre multi-lignes est préservé tel quel, les espaces du mot de passe aussi.
    let mut expected = expected_rows();
    expected[1].0 = expected[1].0.trim().to_string();
    assert_eq!(rows(&parsed), expected);
}

#[test]
fn bitwarden_json_export_reimports_identically() {
    let text = export_bitwarden_json(&sample_export());
    assert!(json::parse(&text).is_ok());
    let parsed = parse(text.as_bytes(), None).unwrap();
    assert_eq!(parsed.format, Format::BitwardenJson);
    assert_eq!(rows(&parsed), expected_rows());
}

#[test]
fn empty_exports_are_valid() {
    assert_eq!(export_csv(&[]), "name,url,username,password,note\n");
    let text = export_bitwarden_json(&[]);
    let doc = json::parse(&text).unwrap();
    assert_eq!(doc.get("items").unwrap().as_array().unwrap().len(), 0);
    assert_eq!(doc.get("encrypted").unwrap().as_bool(), Some(false));
}
