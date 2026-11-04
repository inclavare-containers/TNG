use std::io::Read;

use anyhow::Context;
use jsonc_parser::{parse_to_serde_value, ParseOptions};

use super::TngConfig;

/// Every JSON5 extension is off; only comments and trailing commas stay on.
/// The crate defaults all of these to true, so the options must be spelled out
/// instead of using ..Default::default().
const JSONC_OPTIONS: ParseOptions = ParseOptions {
    allow_comments: true,
    allow_trailing_commas: true,
    allow_loose_object_property_names: false,
    allow_missing_commas: false,
    allow_single_quoted_strings: false,
    allow_hexadecimal_numbers: false,
    allow_unary_plus_numbers: false,
    allow_bare_decimal_point_numbers: false,
    allow_non_finite_numbers: false,
    allow_extended_string_escapes: false,
};

pub fn parse_config_str(text: &str) -> anyhow::Result<TngConfig> {
    // Some Windows editors prepend a UTF-8 BOM when saving. Strip only one at
    // the very start; a U+FEFF anywhere else is still invalid input.
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    parse_to_serde_value(text, &JSONC_OPTIONS).map_err(anyhow::Error::from)
}

pub fn parse_config_reader(mut reader: impl Read) -> anyhow::Result<TngConfig> {
    let mut text = String::new();
    reader
        .read_to_string(&mut text)
        .context("read config text")?;
    parse_config_str(&text)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use anyhow::Result;

    use super::{parse_config_reader, parse_config_str};

    fn admin_bind(text: &str) -> Result<(Option<String>, u16)> {
        let config = parse_config_str(text)?;
        let endpoint = config.admin_bind.expect("admin_bind should be present");
        Ok((endpoint.host, endpoint.port))
    }

    #[test]
    fn strict_json_still_parses() -> Result<()> {
        let (host, port) = admin_bind(r#"{"admin_bind": {"host": "127.0.0.1", "port": 10081}}"#)?;
        assert_eq!(host.as_deref(), Some("127.0.0.1"));
        assert_eq!(port, 10081);
        Ok(())
    }

    #[test]
    fn line_comments_are_accepted() -> Result<()> {
        let text = r#"
            // leading comment
            {
                // between fields
                "admin_bind": {
                    "host": "127.0.0.1", // inline comment
                    "port": 10081
                }
            }
            // trailing comment
        "#;
        let (host, port) = admin_bind(text)?;
        assert_eq!(host.as_deref(), Some("127.0.0.1"));
        assert_eq!(port, 10081);
        Ok(())
    }

    #[test]
    fn block_comments_are_accepted() -> Result<()> {
        let text = r#"
            /* leading
               block comment */
            {
                "admin_bind": {
                    /* inline */ "host": "127.0.0.1",
                    "port": 10081
                }
            }
        "#;
        let (host, port) = admin_bind(text)?;
        assert_eq!(host.as_deref(), Some("127.0.0.1"));
        assert_eq!(port, 10081);
        Ok(())
    }

    #[test]
    fn trailing_commas_are_accepted() -> Result<()> {
        let text = r#"
            {
                "add_ingress": [
                    {
                        "http_proxy": {
                            "proxy_listen": {
                                "host": "127.0.0.1",
                                "port": 10080,
                            },
                        },
                    },
                ],
                "admin_bind": {
                    "host": "127.0.0.1",
                    "port": 10081,
                },
            }
        "#;
        let config = parse_config_str(text)?;
        assert_eq!(config.add_ingress.len(), 1);
        assert_eq!(config.admin_bind.expect("admin_bind").port, 10081);
        Ok(())
    }

    #[test]
    fn comment_markers_inside_strings_are_literal() -> Result<()> {
        let (host, _) = admin_bind(
            r#"{"admin_bind": {"host": "http://example.test/*not-a-comment*/", "port": 1}}"#,
        )?;
        assert_eq!(
            host.as_deref(),
            Some("http://example.test/*not-a-comment*/")
        );
        Ok(())
    }

    #[test]
    fn reader_matches_str() -> Result<()> {
        let text = r#"// comment
            {"admin_bind": {"host": "127.0.0.1", "port": 10081},}
        "#;
        let from_str = parse_config_str(text)?;
        let from_reader = parse_config_reader(Cursor::new(text.as_bytes()))?;
        assert_eq!(
            serde_json::to_value(from_str)?,
            serde_json::to_value(from_reader)?
        );
        Ok(())
    }

    #[test]
    fn leading_bom_is_accepted() -> Result<()> {
        let text = "\u{feff}{\"admin_bind\": {\"host\": \"127.0.0.1\", \"port\": 10081}}";
        let (host, port) = admin_bind(text)?;
        assert_eq!(host.as_deref(), Some("127.0.0.1"));
        assert_eq!(port, 10081);
        Ok(())
    }

    #[test]
    fn leading_bom_combines_with_comments_and_trailing_commas() -> Result<()> {
        let text =
            "\u{feff}// comment\n{\"admin_bind\": {\"host\": \"127.0.0.1\", \"port\": 10081,},}\n";
        let (_, port) = admin_bind(text)?;
        assert_eq!(port, 10081);
        Ok(())
    }

    #[test]
    fn bom_inside_document_is_rejected() {
        assert!(parse_config_str("{}\u{feff}").is_err());
    }

    #[test]
    fn unquoted_property_names_are_rejected() {
        assert!(parse_config_str(r#"{admin_bind: {"host": "h", "port": 1}}"#).is_err());
    }

    #[test]
    fn single_quoted_strings_are_rejected() {
        assert!(parse_config_str(r#"{'admin_bind': {"host": "h", "port": 1}}"#).is_err());
    }

    #[test]
    fn hexadecimal_numbers_are_rejected() {
        assert!(parse_config_str(r#"{"admin_bind": {"host": "h", "port": 0x10}}"#).is_err());
    }

    #[test]
    fn non_finite_numbers_are_rejected() {
        assert!(parse_config_str(r#"{"admin_bind": {"host": "h", "port": NaN}}"#).is_err());
        assert!(parse_config_str(r#"{"admin_bind": {"host": "h", "port": Infinity}}"#).is_err());
    }

    #[test]
    fn missing_commas_are_rejected() {
        assert!(
            parse_config_str(r#"{"admin_bind": {"host": "h", "port": 1} "add_ingress": []}"#)
                .is_err()
        );
    }

    #[test]
    fn unterminated_block_comment_reports_position() {
        let error = parse_config_str("{\n/* unterminated\n").expect_err("should fail");
        let message = format!("{error:#}");
        assert!(message.contains("line"), "unexpected message: {message}");
        assert!(message.contains("column"), "unexpected message: {message}");
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let error = parse_config_str(r#"{"nope": 1}"#).expect_err("should fail");
        assert!(
            format!("{error:#}").contains("unknown field"),
            "unexpected message: {error:#}"
        );
    }

    #[test]
    fn duplicate_fields_are_rejected() {
        let error = parse_config_str(
            r#"{"admin_bind": {"host": "h", "port": 1}, "admin_bind": {"host": "h", "port": 2}}"#,
        )
        .expect_err("should fail");
        assert!(
            format!("{error:#}").contains("duplicate"),
            "unexpected message: {error:#}"
        );
    }
}
