use std::{collections::HashSet, sync::LazyLock};

/// Marker that (de)serializes only to/from the literal string `"all"`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct All;

impl std::convert::TryFrom<String> for All {
    type Error = &'static str;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        if s == "all" {
            Ok(All)
        } else {
            Err("expected the string \"all\"")
        }
    }
}

impl From<All> for String {
    fn from(_: All) -> Self {
        "all".to_string()
    }
}

/// Either copy every non-protected header (`All`) or an explicit allowlist (`List`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum HeaderPassthroughSpec {
    All(All),
    List(Vec<String>),
}

impl Default for HeaderPassthroughSpec {
    fn default() -> Self {
        HeaderPassthroughSpec::List(Vec::new())
    }
}

impl HeaderPassthroughSpec {
    /// True if `name` should be copied source→dest under this spec.
    /// Protected headers are never copied.
    pub fn should_passthrough(&self, name: &http::HeaderName, protected: &HashSet<&str>) -> bool {
        if protected.contains(name.as_str()) {
            return false;
        }
        match self {
            HeaderPassthroughSpec::All(_) => true,
            HeaderPassthroughSpec::List(names) => {
                names.iter().any(|n| n.eq_ignore_ascii_case(name.as_str()))
            }
        }
    }

    /// Collect every (name, value) from `src` that this spec allows through,
    /// skipping protected headers. Preserves multi-valued headers.
    pub fn collect_passthrough_headers(
        &self,
        src: &http::HeaderMap,
        protected: &HashSet<&str>,
    ) -> Vec<(http::HeaderName, http::HeaderValue)> {
        // An empty allowlist can match nothing, so skip the whole-map scan.
        // This is the default configuration and runs per request in each
        // passthrough direction on both ingress and egress.
        if matches!(self, HeaderPassthroughSpec::List(names) if names.is_empty()) {
            return Vec::new();
        }
        // `All` copies every non-protected header, so `src.len()` bounds the
        // result size; `List` matches a small allowlist and grows lazily.
        let mut out = match self {
            HeaderPassthroughSpec::All(_) => Vec::with_capacity(src.len()),
            HeaderPassthroughSpec::List(_) => Vec::new(),
        };
        for (name, value) in src.iter() {
            if self.should_passthrough(name, protected) {
                out.push((name.clone(), value.clone()));
            }
        }
        out
    }
}

/// Headers that must never be copied by any passthrough direction.
///
/// These would corrupt the OHTTP protocol contract or HTTP framing, or are
/// managed explicitly by TNG. `origin` is deliberately NOT protected — it is
/// the header egress `request_headers` exists to copy.
///
/// Built once and shared: every ohttp request consults it twice on each
/// host (request and response direction), and a per-request `HashSet` build
/// was measurable in the hot-path profile.
static PROTECTED_OHTTP_HEADERS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        http::header::CONTENT_TYPE.as_str(), // "content-type"
        "content-length",
        "content-encoding",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "te",
        "trailer",
        "upgrade",
        "proxy-authenticate",
        "proxy-authorization",
        crate::tunnel::ohttp::protocol::header::OhttpApi::HEADER_NAME, // "x-tng-ohttp-api"
        http::header::SERVER.as_str(), // "server" — TNG sets its own Server header
        http::header::HOST.as_str(),   // "host" — managed explicitly by TNG/SDK
    ]
    .into_iter()
    .collect()
});

pub fn protected_ohttp_headers() -> &'static HashSet<&'static str> {
    &PROTECTED_OHTTP_HEADERS
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr as _;

    fn spec(s: &str) -> HeaderPassthroughSpec {
        serde_json::from_str(s).unwrap()
    }

    #[test]
    fn deserialize_all() {
        assert_eq!(spec("\"all\""), HeaderPassthroughSpec::All(All));
    }

    #[test]
    fn deserialize_list() {
        assert_eq!(
            spec(r#"["a","b"]"#),
            HeaderPassthroughSpec::List(vec!["a".into(), "b".into()])
        );
    }

    #[test]
    fn deserialize_empty_list() {
        assert_eq!(spec("[]"), HeaderPassthroughSpec::List(vec![]));
    }

    #[test]
    fn default_is_empty_list() {
        assert_eq!(
            HeaderPassthroughSpec::default(),
            HeaderPassthroughSpec::List(vec![])
        );
    }

    #[test]
    fn backward_compat_array_form() {
        // The legacy Vec<String> JSON form still parses to List.
        assert_eq!(
            serde_json::from_str::<HeaderPassthroughSpec>(r#"["x-custom"]"#).unwrap(),
            HeaderPassthroughSpec::List(vec!["x-custom".into()])
        );
    }

    #[test]
    fn all_marker_rejects_non_all_string() {
        assert!(All::try_from("not-all".to_string()).is_err());
        assert!(All::try_from("all".to_string()).is_ok());
    }

    #[test]
    fn all_marker_serializes_back() {
        assert_eq!(String::from(All), "all".to_string());
    }

    #[test]
    fn serde_roundtrip_all_and_list() {
        // The `into = "String"` serde wiring (not just the From impl).
        assert_eq!(
            serde_json::to_string(&HeaderPassthroughSpec::All(All)).unwrap(),
            "\"all\""
        );
        assert_eq!(
            serde_json::to_string(&HeaderPassthroughSpec::List(vec!["a".into()])).unwrap(),
            "[\"a\"]"
        );
    }

    #[test]
    fn should_passthrough_all_copies_non_protected() {
        let protected: HashSet<&str> = ["content-type"].into_iter().collect();
        let spec = HeaderPassthroughSpec::All(All);
        assert!(spec.should_passthrough(&http::HeaderName::from_str("origin").unwrap(), &protected));
        assert!(!spec.should_passthrough(&http::header::CONTENT_TYPE, &protected));
    }

    #[test]
    fn should_passthrough_list_case_insensitive_and_skips_protected() {
        let protected: HashSet<&str> = ["content-type"].into_iter().collect();
        let spec = HeaderPassthroughSpec::List(vec!["X-Custom".into(), "content-type".into()]);
        // Case-insensitive match for listed name.
        assert!(
            spec.should_passthrough(&http::HeaderName::from_str("x-custom").unwrap(), &protected)
        );
        // Protected header never copied even if explicitly listed.
        assert!(!spec.should_passthrough(&http::header::CONTENT_TYPE, &protected));
        // Unlisted, unprotected header not copied.
        assert!(
            !spec.should_passthrough(&http::HeaderName::from_str("x-other").unwrap(), &protected)
        );
    }

    #[test]
    fn collect_preserves_multi_valued() {
        let protected: HashSet<&str> = [].into_iter().collect();
        let spec = HeaderPassthroughSpec::All(All);
        let mut src = http::HeaderMap::new();
        src.append("x-multi", "1".parse().unwrap());
        src.append("x-multi", "2".parse().unwrap());
        let out = spec.collect_passthrough_headers(&src, &protected);
        assert_eq!(out.len(), 2);
        // Both values of the multi-valued header are preserved in source order.
        let values: Vec<&str> = out.iter().map(|(_, v)| v.to_str().unwrap()).collect();
        assert_eq!(values, vec!["1", "2"]);
    }

    #[test]
    fn collect_empty_list_returns_nothing() {
        // The default spec: nothing may pass, whatever the source map holds.
        let protected = super::protected_ohttp_headers();
        let spec = HeaderPassthroughSpec::default();
        let mut src = http::HeaderMap::new();
        src.insert("origin", "https://app.example".parse().unwrap());
        src.insert(http::header::CONTENT_TYPE, "text/plain".parse().unwrap());
        assert!(spec.collect_passthrough_headers(&src, protected).is_empty());
    }

    #[test]
    fn collect_list_selects_only_allowed_non_protected() {
        let protected = super::protected_ohttp_headers();
        let spec: HeaderPassthroughSpec =
            serde_json::from_str(r#"["origin","content-type","x-none"]"#).unwrap();
        let mut src = http::HeaderMap::new();
        src.insert("origin", "https://app.example".parse().unwrap());
        // Listed but protected: never copied.
        src.insert(http::header::CONTENT_TYPE, "text/plain".parse().unwrap());
        src.insert("x-other", "1".parse().unwrap());
        let out = spec.collect_passthrough_headers(&src, protected);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0.as_str(), "origin");
    }

    #[test]
    fn collect_all_copies_non_protected_only() {
        let protected = super::protected_ohttp_headers();
        let spec = HeaderPassthroughSpec::All(All);
        let mut src = http::HeaderMap::new();
        src.insert("origin", "https://app.example".parse().unwrap());
        src.insert(http::header::CONTENT_TYPE, "text/plain".parse().unwrap());
        src.insert(http::header::HOST, "egress.example".parse().unwrap());
        let out = spec.collect_passthrough_headers(&src, protected);
        // `origin` passes; protected headers do not.
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0.as_str(), "origin");
    }

    #[test]
    fn protected_set_covers_protocol_and_framing_headers() {
        let p = super::protected_ohttp_headers();
        assert!(p.contains("content-type"));
        assert!(p.contains("content-length"));
        assert!(p.contains("content-encoding"));
        assert!(p.contains("transfer-encoding"));
        assert!(p.contains("connection"));
        assert!(p.contains("keep-alive"));
        assert!(p.contains("te"));
        assert!(p.contains("trailer"));
        assert!(p.contains("upgrade"));
        assert!(p.contains("proxy-authorization"));
        assert!(p.contains("proxy-authenticate"));
        assert!(p.contains("x-tng-ohttp-api"));
        assert!(p.contains("server"));
        assert!(p.contains("host"));
        // origin is NOT protected (it is what A copies).
        assert!(!p.contains("origin"));
    }
}
