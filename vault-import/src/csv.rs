//! Lecture et écriture CSV (RFC 4180) : champs entre guillemets, guillemets doublés,
//! retours à la ligne dans les champs, fins de ligne `\n` ou `\r\n`.

/// Erreur de lecture CSV.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsvError {
    /// Un guillemet ouvrant n'est jamais refermé.
    UnterminatedQuote,
}

/// Devine le séparateur d'après la première ligne : virgule, point-virgule
/// (exports Excel en français) ou tabulation. La virgule l'emporte en cas d'égalité.
pub fn detect_delimiter(text: &str) -> char {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let first_line = text.lines().next().unwrap_or("");
    let mut counts = [(',', 0usize), (';', 0), ('\t', 0)];
    let mut in_quotes = false;
    for c in first_line.chars() {
        if c == '"' {
            in_quotes = !in_quotes;
        } else if !in_quotes {
            for (delimiter, count) in counts.iter_mut() {
                if c == *delimiter {
                    *count += 1;
                }
            }
        }
    }
    let mut best = counts[0];
    for candidate in &counts[1..] {
        if candidate.1 > best.1 {
            best = *candidate;
        }
    }
    best.0
}

fn end_row(
    rows: &mut Vec<Vec<String>>,
    row: &mut Vec<String>,
    field: &mut String,
    quoted: &mut bool,
) {
    row.push(std::mem::take(field));
    // Une ligne vide (sans guillemets) est ignorée ; `""` seul reste une ligne d'un champ vide.
    let blank = row.len() == 1 && row[0].is_empty() && !*quoted;
    *quoted = false;
    if blank {
        row.clear();
    } else {
        rows.push(std::mem::take(row));
    }
}

/// Découpe `text` en lignes de champs.
pub fn parse(text: &str, delimiter: char) -> Result<Vec<Vec<String>>, CsvError> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut rows = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut quoted = false;
    let mut chars = text.chars().peekable();

    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(c);
            }
        } else if c == '"' && field.is_empty() && !quoted {
            in_quotes = true;
            quoted = true;
        } else if c == delimiter {
            row.push(std::mem::take(&mut field));
            quoted = false;
        } else if c == '\n' || c == '\r' {
            if c == '\r' && chars.peek() == Some(&'\n') {
                chars.next();
            }
            end_row(&mut rows, &mut row, &mut field, &mut quoted);
        } else {
            field.push(c);
        }
    }
    if in_quotes {
        return Err(CsvError::UnterminatedQuote);
    }
    if !field.is_empty() || !row.is_empty() || quoted {
        end_row(&mut rows, &mut row, &mut field, &mut quoted);
    }
    Ok(rows)
}

/// Ajoute un champ, entre guillemets seulement si nécessaire.
pub fn write_field(out: &mut String, field: &str) {
    let needs_quotes =
        field.contains([',', '"', '\n', '\r']) || field.starts_with(' ') || field.ends_with(' ');
    if needs_quotes {
        out.push('"');
        for c in field.chars() {
            if c == '"' {
                out.push('"');
            }
            out.push(c);
        }
        out.push('"');
    } else {
        out.push_str(field);
    }
}

/// Ajoute une ligne complète (séparateur virgule, fin de ligne `\n`).
pub fn write_row(out: &mut String, fields: &[&str]) {
    for (i, field) in fields.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        write_field(out, field);
    }
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(text: &str) -> Vec<Vec<String>> {
        parse(text, ',').unwrap()
    }

    #[test]
    fn simple_rows_and_line_endings() {
        let expected = vec![vec!["a", "b", "c"], vec!["1", "2", "3"]];
        assert_eq!(rows("a,b,c\n1,2,3\n"), expected);
        assert_eq!(rows("a,b,c\r\n1,2,3\r\n"), expected);
        assert_eq!(rows("a,b,c\r1,2,3"), expected);
        assert_eq!(rows("a,b,c\n1,2,3"), expected);
    }

    #[test]
    fn quoted_fields_with_commas_quotes_and_newlines() {
        let parsed = rows("\"a,b\",\"say \"\"hi\"\"\",\"line1\nline2\"\n");
        assert_eq!(parsed, vec![vec!["a,b", "say \"hi\"", "line1\nline2"]]);
    }

    #[test]
    fn empty_fields_and_trailing_delimiter() {
        assert_eq!(rows("a,,c,\n"), vec![vec!["a", "", "c", ""]]);
    }

    #[test]
    fn blank_lines_are_skipped_but_quoted_empty_is_kept() {
        assert_eq!(rows("a\n\n\nb\n"), vec![vec!["a"], vec!["b"]]);
        assert_eq!(rows("a\n\"\"\nb\n"), vec![vec!["a"], vec![""], vec!["b"]]);
    }

    #[test]
    fn stray_quote_inside_an_unquoted_field_is_literal() {
        assert_eq!(rows("ab\"c,d\n"), vec![vec!["ab\"c", "d"]]);
    }

    #[test]
    fn bom_is_removed() {
        assert_eq!(rows("\u{feff}a,b\n"), vec![vec!["a", "b"]]);
    }

    #[test]
    fn unterminated_quote_is_an_error() {
        assert_eq!(parse("a,\"b\n", ','), Err(CsvError::UnterminatedQuote));
    }

    #[test]
    fn leading_and_trailing_spaces_are_preserved() {
        assert_eq!(rows(" a ,b\n"), vec![vec![" a ", "b"]]);
    }

    #[test]
    fn delimiter_detection() {
        assert_eq!(detect_delimiter("a,b,c\n"), ',');
        assert_eq!(detect_delimiter("a;b;c\n"), ';');
        assert_eq!(detect_delimiter("a\tb\tc\n"), '\t');
        assert_eq!(detect_delimiter("\"a;b\",c,d\n"), ',');
        assert_eq!(detect_delimiter("seul\n"), ',');
        assert_eq!(detect_delimiter("\u{feff}a;b\n"), ';');
    }

    #[test]
    fn semicolon_files_parse() {
        assert_eq!(
            parse("a;b\n1;\"x;y\"\n", ';').unwrap(),
            vec![vec!["a", "b"], vec!["1", "x;y"]]
        );
    }

    #[test]
    fn write_then_parse_roundtrip() {
        let fields = [
            "simple",
            "a,b",
            "say \"hi\"",
            "ligne1\nligne2",
            " espace",
            "",
            "é€😀",
        ];
        let mut out = String::new();
        write_row(&mut out, &fields);
        write_row(&mut out, &fields);
        let parsed = parse(&out, ',').unwrap();
        assert_eq!(parsed.len(), 2);
        for row in parsed {
            assert_eq!(row, fields);
        }
    }

    #[test]
    fn plain_fields_are_not_quoted() {
        let mut out = String::new();
        write_row(&mut out, &["a", "b"]);
        assert_eq!(out, "a,b\n");
    }
}
