//! Valve's `KeyValues` text format, as in Steam's `libraryfolders.vdf` and `appmanifest_<id>.acf`.
//!
//! Quoted or bare tokens, `{ }` for nesting, `//` comments. Keys compare without case, as Steam does.

/// A value: a string, or an object of keyed children in file order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Vdf {
    Str(String),
    Obj(Vec<(String, Vdf)>),
}

impl Vdf {
    /// The first child named `key` (any case).
    pub fn get(&self, key: &str) -> Option<&Vdf> {
        match self {
            Vdf::Obj(items) => items.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| v),
            Vdf::Str(_) => None,
        }
    }

    pub fn str(&self, key: &str) -> Option<&str> {
        match self.get(key)? {
            Vdf::Str(s) => Some(s),
            Vdf::Obj(_) => None,
        }
    }

    /// The children, empty for a string.
    pub fn items(&self) -> &[(String, Vdf)] {
        match self {
            Vdf::Obj(items) => items,
            Vdf::Str(_) => &[],
        }
    }
}

#[derive(Debug, PartialEq)]
enum Token {
    Str(String),
    Open,
    Close,
}

fn tokens(text: &str) -> Vec<Token> {
    let mut out = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            c if c.is_whitespace() => {
                chars.next();
            }
            '{' => {
                chars.next();
                out.push(Token::Open);
            }
            '}' => {
                chars.next();
                out.push(Token::Close);
            }
            '/' => {
                // `//` to the end of the line
                for c in chars.by_ref() {
                    if c == '\n' {
                        break;
                    }
                }
            }
            '"' => {
                chars.next();
                let mut s = String::new();
                while let Some(c) = chars.next() {
                    match c {
                        '"' => break,
                        '\\' => match chars.next() {
                            Some('n') => s.push('\n'),
                            Some('t') => s.push('\t'),
                            Some(other) => s.push(other),
                            None => break,
                        },
                        c => s.push(c),
                    }
                }
                out.push(Token::Str(s));
            }
            _ => {
                let mut s = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_whitespace() || c == '{' || c == '}' || c == '"' {
                        break;
                    }
                    s.push(c);
                    chars.next();
                }
                out.push(Token::Str(s));
            }
        }
    }
    out
}

fn object(tokens: &mut std::iter::Peekable<std::vec::IntoIter<Token>>, depth: usize) -> Vec<(String, Vdf)> {
    let mut items = Vec::new();
    while let Some(t) = tokens.next() {
        let Token::Str(key) = t else { break };
        match tokens.next() {
            Some(Token::Str(v)) => items.push((key, Vdf::Str(v))),
            // Deeper than any Steam file goes: someone's crafted file, read no further
            Some(Token::Open) if depth < 32 => items.push((key, Vdf::Obj(object(tokens, depth + 1)))),
            _ => break,
        }
    }
    items
}

/// Parses a file. Anything malformed ends the object it's in; what came before is kept.
pub fn parse(text: &str) -> Vdf {
    let mut t = tokens(text).into_iter().peekable();
    Vdf::Obj(object(&mut t, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_steam_files() {
        let lib = parse(
            r#"
"libraryfolders"
{
	"0"
	{
		"path"		"C:\\Program Files (x86)\\Steam"
		"apps" { "228980" "123" "730" "456" }
	}
	// a comment
	"1" { "path" "D:\\SteamLibrary" }
}"#,
        );
        let folders = lib.get("LibraryFolders").unwrap();
        let paths: Vec<_> = folders.items().iter().filter_map(|(_, v)| v.str("path")).collect();
        assert_eq!(paths, [r"C:\Program Files (x86)\Steam", r"D:\SteamLibrary"]);

        let acf = parse(
            "\"AppState\"\n{\n\"appid\" \"730\"\n\"name\" \"Counter-Strike 2\"\n\"installdir\" \"Counter-Strike Global Offensive\"\n}",
        );
        let app = acf.get("appstate").unwrap();
        assert_eq!(app.str("appid"), Some("730"));
        assert_eq!(app.str("installdir"), Some("Counter-Strike Global Offensive"));
    }

    #[test]
    fn malformed_files_dont_panic() {
        for text in ["", "{", "}", "\"a\"", "\"a\" {", "\"a\" { \"b\" }", "\"unterminated", &"\"a\" {".repeat(100)] {
            let _ = parse(text);
        }
    }
}
