//! Lecteur XML minimal pour l'export XML de KeePass et KeePassXC.
//!
//! Gère les éléments, attributs, texte, CDATA, commentaires, instructions de
//! traitement et les cinq entités standard ainsi que les références numériques.
//! Refuse les déclarations `<!DOCTYPE>` (pas d'entités personnalisées, donc pas
//! d'expansion d'entités) et limite la profondeur.

/// Profondeur d'imbrication maximale acceptée.
pub const MAX_DEPTH: usize = 64;

/// Élément XML.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Element {
    pub name: String,
    pub attributes: Vec<(String, String)>,
    pub children: Vec<Element>,
    /// Texte direct de l'élément, tel quel (espaces compris).
    pub text: String,
}

impl Element {
    /// Premier enfant portant ce nom.
    pub fn child(&self, name: &str) -> Option<&Element> {
        self.children.iter().find(|c| c.name == name)
    }

    /// Tous les enfants portant ce nom.
    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> {
        self.children.iter().filter(move |c| c.name == name)
    }

    /// Valeur d'un attribut.
    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Lit un document XML et renvoie son élément racine.
pub fn parse(text: &str) -> Result<Element, String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut parser = Parser { text, pos: 0 };
    parser.skip_misc()?;
    if !parser.rest().starts_with('<') {
        return Err(parser.error("élément racine attendu"));
    }
    let root = parser.element(0)?;
    parser.skip_misc()?;
    if parser.pos != text.len() {
        return Err(parser.error("contenu après l'élément racine"));
    }
    Ok(root)
}

struct Parser<'a> {
    text: &'a str,
    pos: usize,
}

impl Parser<'_> {
    fn rest(&self) -> &str {
        &self.text[self.pos..]
    }

    fn error(&self, message: &str) -> String {
        format!("XML invalide à l'octet {} : {message}", self.pos)
    }

    fn skip_whitespace(&mut self) {
        let trimmed = self.rest().trim_start_matches([' ', '\t', '\n', '\r']);
        self.pos = self.text.len() - trimmed.len();
    }

    /// Saute espaces, commentaires et instructions de traitement (`<?xml … ?>`).
    fn skip_misc(&mut self) -> Result<(), String> {
        loop {
            self.skip_whitespace();
            if self.rest().starts_with("<!--") {
                self.skip_past("-->")?;
            } else if self.rest().starts_with("<?") {
                self.skip_past("?>")?;
            } else if self.rest().starts_with("<!DOCTYPE") || self.rest().starts_with("<!doctype") {
                return Err(self.error("les déclarations DOCTYPE ne sont pas prises en charge"));
            } else {
                return Ok(());
            }
        }
    }

    fn skip_past(&mut self, end: &str) -> Result<(), String> {
        match self.rest().find(end) {
            Some(index) => {
                self.pos += index + end.len();
                Ok(())
            }
            None => Err(self.error(&format!("« {end} » manquant"))),
        }
    }

    fn name(&mut self) -> Result<String, String> {
        let rest = self.rest();
        let length = rest
            .find(|c: char| c.is_whitespace() || matches!(c, '>' | '/' | '=' | '<' | '"' | '\''))
            .unwrap_or(rest.len());
        if length == 0 {
            return Err(self.error("nom attendu"));
        }
        let name = rest[..length].to_string();
        self.pos += length;
        Ok(name)
    }

    fn element(&mut self, depth: usize) -> Result<Element, String> {
        if depth > MAX_DEPTH {
            return Err(self.error("imbrication trop profonde"));
        }
        self.pos += 1; // '<'
        let mut element = Element {
            name: self.name()?,
            ..Element::default()
        };

        loop {
            self.skip_whitespace();
            if self.rest().starts_with("/>") {
                self.pos += 2;
                return Ok(element);
            }
            if self.rest().starts_with('>') {
                self.pos += 1;
                break;
            }
            let key = self.name()?;
            self.skip_whitespace();
            if !self.rest().starts_with('=') {
                return Err(self.error("« = » attendu après le nom de l'attribut"));
            }
            self.pos += 1;
            self.skip_whitespace();
            let quote = match self.rest().chars().next() {
                Some(q @ ('"' | '\'')) => q,
                _ => return Err(self.error("valeur d'attribut entre guillemets attendue")),
            };
            self.pos += 1;
            let end = self
                .rest()
                .find(quote)
                .ok_or_else(|| self.error("valeur d'attribut non terminée"))?;
            let raw = &self.text[self.pos..self.pos + end];
            let value = decode_entities(raw).map_err(|m| self.error(&m))?;
            self.pos += end + 1;
            element.attributes.push((key, value));
        }

        loop {
            if self.pos >= self.text.len() {
                return Err(self.error(&format!("élément « {} » non fermé", element.name)));
            }
            let rest = self.rest();
            if rest.starts_with("</") {
                self.pos += 2;
                let closing = self.name()?;
                if closing != element.name {
                    return Err(
                        self.error(&format!("« {closing} » ne ferme pas « {} »", element.name))
                    );
                }
                self.skip_whitespace();
                if !self.rest().starts_with('>') {
                    return Err(self.error("« > » attendu"));
                }
                self.pos += 1;
                return Ok(element);
            } else if rest.starts_with("<!--") {
                self.skip_past("-->")?;
            } else if rest.starts_with("<![CDATA[") {
                self.pos += "<![CDATA[".len();
                let end = self
                    .rest()
                    .find("]]>")
                    .ok_or_else(|| self.error("« ]]> » manquant"))?;
                element.text.push_str(&self.text[self.pos..self.pos + end]);
                self.pos += end + 3;
            } else if rest.starts_with("<?") {
                self.skip_past("?>")?;
            } else if rest.starts_with('<') {
                let child = self.element(depth + 1)?;
                element.children.push(child);
            } else {
                let end = rest.find('<').unwrap_or(rest.len());
                let decoded = decode_entities(&rest[..end]).map_err(|m| self.error(&m))?;
                element.text.push_str(&decoded);
                self.pos += end;
            }
        }
    }
}

fn decode_entities(raw: &str) -> Result<String, String> {
    if !raw.contains('&') {
        return Ok(raw.to_string());
    }
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(start) = rest.find('&') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let end = after
            .find(';')
            .ok_or_else(|| "entité non terminée".to_string())?;
        let entity = &after[..end];
        match entity {
            "amp" => out.push('&'),
            "lt" => out.push('<'),
            "gt" => out.push('>'),
            "quot" => out.push('"'),
            "apos" => out.push('\''),
            _ => {
                let number = entity
                    .strip_prefix("#x")
                    .or_else(|| entity.strip_prefix("#X"))
                    .map(|hex| u32::from_str_radix(hex, 16))
                    .or_else(|| entity.strip_prefix('#').map(|dec| dec.parse::<u32>()));
                let character = match number {
                    Some(Ok(code)) => char::from_u32(code),
                    _ => None,
                };
                out.push(character.ok_or_else(|| format!("entité inconnue « &{entity}; »"))?);
            }
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elements_attributes_and_text() {
        let root = parse("<a x=\"1\" y='2'><b>texte</b><c/><b>deux</b></a>").unwrap();
        assert_eq!(root.name, "a");
        assert_eq!(root.attribute("x"), Some("1"));
        assert_eq!(root.attribute("y"), Some("2"));
        assert_eq!(root.attribute("z"), None);
        assert_eq!(root.children.len(), 3);
        assert_eq!(root.child("b").unwrap().text, "texte");
        assert_eq!(root.children_named("b").count(), 2);
        assert!(root.child("c").unwrap().children.is_empty());
    }

    #[test]
    fn prolog_comments_and_processing_instructions_are_skipped() {
        let doc = "\u{feff}<?xml version=\"1.0\"?>\n<!-- un commentaire -->\n<a><!-- x --><b/></a>\n<!-- fin -->\n";
        let root = parse(doc).unwrap();
        assert_eq!(root.children.len(), 1);
    }

    #[test]
    fn entities_are_decoded_in_text_and_attributes() {
        let root =
            parse("<a t=\"&lt;&amp;&quot;\">&amp;&lt;&gt;&quot;&apos;&#65;&#x42;&#x1F600;</a>")
                .unwrap();
        assert_eq!(root.attribute("t"), Some("<&\""));
        assert_eq!(root.text, "&<>\"'AB😀");
    }

    #[test]
    fn cdata_is_taken_literally() {
        let root = parse("<a><![CDATA[<b> & </b>]]></a>").unwrap();
        assert_eq!(root.text, "<b> & </b>");
    }

    #[test]
    fn whitespace_in_values_is_preserved() {
        let root = parse("<a>  x  </a>").unwrap();
        assert_eq!(root.text, "  x  ");
    }

    #[test]
    fn non_ascii_text_survives() {
        let root = parse("<a>é€😀</a>").unwrap();
        assert_eq!(root.text, "é€😀");
    }

    #[test]
    fn doctype_is_refused() {
        let doc = "<!DOCTYPE a [<!ENTITY x \"y\">]><a>&x;</a>";
        assert!(parse(doc).unwrap_err().contains("DOCTYPE"));
    }

    #[test]
    fn unknown_or_broken_entities_are_errors() {
        for bad in [
            "<a>&inconnue;</a>",
            "<a>&amp</a>",
            "<a>&#xZZ;</a>",
            "<a>&#1114112;</a>",
        ] {
            assert!(parse(bad).is_err(), "devrait échouer : {bad}");
        }
    }

    #[test]
    fn malformed_documents_are_rejected() {
        for bad in [
            "",
            "texte",
            "<a>",
            "<a></b>",
            "<a><b></a></b>",
            "<a x=1/>",
            "<a x=\"1/>",
            "<a/><b/>",
            "<a/> x",
            "<a><!-- x </a>",
            "<a><![CDATA[x</a>",
            "<a x></a>",
        ] {
            assert!(parse(bad).is_err(), "devrait échouer : {bad:?}");
        }
    }

    #[test]
    fn depth_limit_stops_hostile_nesting() {
        let ok = format!("{}{}", "<a>".repeat(MAX_DEPTH), "</a>".repeat(MAX_DEPTH));
        assert!(parse(&ok).is_ok());
        let deep = format!("{}{}", "<a>".repeat(100_000), "</a>".repeat(100_000));
        assert!(parse(&deep).is_err());
    }
}
