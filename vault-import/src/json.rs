//! Lecteur JSON minimal (RFC 8259) pour les exports de gestionnaires de mots de passe.
//! Profondeur limitée : un fichier piégé ne peut pas faire déborder la pile.

/// Profondeur d'imbrication maximale acceptée.
pub const MAX_DEPTH: usize = 64;

/// Valeur JSON.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    /// Nombre, conservé sous forme de texte (aucun besoin de le calculer).
    Number(String),
    Str(String),
    Array(Vec<Json>),
    /// Membres dans l'ordre du fichier ; les clés répétées sont toutes conservées.
    Object(Vec<(String, Json)>),
}

impl Json {
    /// Premier membre portant ce nom, si `self` est un objet.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Texte, si `self` est une chaîne.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    /// Éléments, si `self` est un tableau.
    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(items) => Some(items),
            _ => None,
        }
    }

    /// Booléen, si `self` en est un.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Entier, si `self` est un nombre entier.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Json::Number(n) => n.parse().ok(),
            _ => None,
        }
    }
}

/// Lit un document JSON complet.
pub fn parse(text: &str) -> Result<Json, String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut parser = Parser {
        text,
        bytes: text.as_bytes(),
        pos: 0,
    };
    let value = parser.value(0)?;
    parser.skip_whitespace();
    if parser.pos != parser.bytes.len() {
        return Err(parser.error("contenu inattendu après la valeur"));
    }
    Ok(value)
}

/// Échappe un texte pour l'écrire entre guillemets dans un document JSON.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

struct Parser<'a> {
    text: &'a str,
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn error(&self, message: &str) -> String {
        format!("JSON invalide à l'octet {} : {message}", self.pos)
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.bytes.get(self.pos), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn expect(&mut self, byte: u8) -> Result<(), String> {
        if self.peek() == Some(byte) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.error(&format!("« {} » attendu", byte as char)))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, String> {
        if depth > MAX_DEPTH {
            return Err(self.error("imbrication trop profonde"));
        }
        self.skip_whitespace();
        match self.peek() {
            None => Err(self.error("fin de fichier inattendue")),
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b't') => self.literal("true", Json::Bool(true)),
            Some(b'f') => self.literal("false", Json::Bool(false)),
            Some(b'n') => self.literal("null", Json::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => Err(self.error("caractère inattendu")),
        }
    }

    fn literal(&mut self, word: &str, value: Json) -> Result<Json, String> {
        if self.text[self.pos..].starts_with(word) {
            self.pos += word.len();
            Ok(value)
        } else {
            Err(self.error("mot inconnu"))
        }
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.pos;
        while matches!(
            self.peek(),
            Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
        ) {
            self.pos += 1;
        }
        Ok(Json::Number(self.text[start..self.pos].to_string()))
    }

    fn object(&mut self, depth: usize) -> Result<Json, String> {
        self.expect(b'{')?;
        let mut members = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Object(members));
        }
        loop {
            self.skip_whitespace();
            if self.peek() != Some(b'"') {
                return Err(self.error("nom de membre attendu"));
            }
            let key = self.string()?;
            self.skip_whitespace();
            self.expect(b':')?;
            let value = self.value(depth + 1)?;
            members.push((key, value));
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Object(members));
                }
                _ => return Err(self.error("« , » ou « } » attendu")),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Json, String> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Array(items));
        }
        loop {
            items.push(self.value(depth + 1)?);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Array(items));
                }
                _ => return Err(self.error("« , » ou « ] » attendu")),
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let digits = self
            .text
            .get(self.pos..self.pos + 4)
            .ok_or_else(|| self.error("séquence \\u incomplète"))?;
        let value =
            u32::from_str_radix(digits, 16).map_err(|_| self.error("séquence \\u invalide"))?;
        // `from_str_radix` accepte un signe : on n'en veut pas.
        if !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(self.error("séquence \\u invalide"));
        }
        self.pos += 4;
        Ok(value)
    }

    fn string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let run_start = self.pos;
            while let Some(b) = self.peek() {
                if b == b'"' || b == b'\\' {
                    break;
                }
                self.pos += 1;
            }
            // Les coupures tombent sur des octets ASCII : ce sont des frontières de caractères.
            out.push_str(&self.text[run_start..self.pos]);
            match self.peek() {
                None => return Err(self.error("chaîne non terminée")),
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some(_) => {
                    self.pos += 1; // la barre oblique inverse
                    let escape = self
                        .peek()
                        .ok_or_else(|| self.error("échappement incomplet"))?;
                    self.pos += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let first = self.hex4()?;
                            let code = if (0xD800..0xDC00).contains(&first) {
                                if !self.text[self.pos..].starts_with("\\u") {
                                    return Err(self.error("demi-paire de substitution seule"));
                                }
                                self.pos += 2;
                                let second = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&second) {
                                    return Err(self.error("paire de substitution invalide"));
                                }
                                0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
                            } else if (0xDC00..0xE000).contains(&first) {
                                return Err(self.error("demi-paire de substitution seule"));
                            } else {
                                first
                            };
                            out.push(
                                char::from_u32(code)
                                    .ok_or_else(|| self.error("caractère invalide"))?,
                            );
                        }
                        _ => return Err(self.error("échappement inconnu")),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalars() {
        assert_eq!(parse("null").unwrap(), Json::Null);
        assert_eq!(parse(" true ").unwrap(), Json::Bool(true));
        assert_eq!(parse("false").unwrap(), Json::Bool(false));
        assert_eq!(parse("-12.5e3").unwrap(), Json::Number("-12.5e3".into()));
        assert_eq!(parse("\"abc\"").unwrap(), Json::Str("abc".into()));
    }

    #[test]
    fn nested_structures_and_accessors() {
        let doc = parse(r#"{"a":[1,2,{"b":"x"}],"c":null,"d":true,"n":42}"#).unwrap();
        assert_eq!(doc.get("a").unwrap().as_array().unwrap().len(), 3);
        assert_eq!(
            doc.get("a").unwrap().as_array().unwrap()[2]
                .get("b")
                .unwrap()
                .as_str(),
            Some("x")
        );
        assert_eq!(doc.get("c"), Some(&Json::Null));
        assert_eq!(doc.get("d").unwrap().as_bool(), Some(true));
        assert_eq!(doc.get("n").unwrap().as_i64(), Some(42));
        assert_eq!(doc.get("absent"), None);
        assert_eq!(doc.as_str(), None);
    }

    #[test]
    fn empty_containers() {
        assert_eq!(parse("{}").unwrap(), Json::Object(vec![]));
        assert_eq!(parse("[ ]").unwrap(), Json::Array(vec![]));
    }

    #[test]
    fn string_escapes() {
        let value = parse(r#""a\"b\\c\/d\n\t\u00e9\u20ac""#).unwrap();
        assert_eq!(value.as_str(), Some("a\"b\\c/d\n\té€"));
    }

    #[test]
    fn surrogate_pairs_decode_and_lone_halves_are_rejected() {
        assert_eq!(parse(r#""\ud83d\ude00""#).unwrap().as_str(), Some("😀"));
        assert!(parse(r#""\ud83d""#).is_err());
        assert!(parse(r#""\ud83dx""#).is_err());
        assert!(parse(r#""\ude00""#).is_err());
        assert!(parse(r#""\ud83d\u0041""#).is_err());
    }

    #[test]
    fn raw_utf8_is_preserved() {
        assert_eq!(parse("\"é€😀\"").unwrap().as_str(), Some("é€😀"));
    }

    #[test]
    fn duplicate_keys_keep_the_first_for_get() {
        let doc = parse(r#"{"a":1,"a":2}"#).unwrap();
        assert_eq!(doc.get("a").unwrap().as_i64(), Some(1));
    }

    #[test]
    fn bom_is_accepted() {
        assert!(parse("\u{feff}{}").is_ok());
    }

    #[test]
    fn malformed_documents_are_rejected() {
        for bad in [
            "",
            "{",
            "[1,",
            "{\"a\"}",
            "{\"a\":}",
            "{a:1}",
            "[1 2]",
            "\"abc",
            "tru",
            "{} x",
            "\"\\q\"",
            "\"\\u12\"",
            "\"\\u+123\"",
            "{\"a\":1,}",
            "nul",
        ] {
            assert!(parse(bad).is_err(), "devrait échouer : {bad:?}");
        }
    }

    #[test]
    fn depth_limit_stops_hostile_nesting() {
        let ok = format!("{}1{}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH));
        assert!(parse(&ok).is_ok());
        let deep = format!("{}1{}", "[".repeat(100_000), "]".repeat(100_000));
        assert!(parse(&deep).is_err());
    }

    #[test]
    fn escape_roundtrips_through_the_parser() {
        for text in [
            "simple",
            "a\"b",
            "a\\b",
            "ligne\nsuivante",
            "tab\t",
            "\u{1}ctrl",
            "é€😀",
            "",
        ] {
            let encoded = escape(text);
            assert_eq!(parse(&encoded).unwrap().as_str(), Some(text), "{text:?}");
        }
    }
}
