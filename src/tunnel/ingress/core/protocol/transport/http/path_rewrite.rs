use anyhow::{Context, Result};
use regex::Regex;

pub struct PathRewriteGroup {
    pub path_rewrites: Vec<PathRewrite>,
}

impl PathRewriteGroup {
    pub fn new(path_rewrites_config: Vec<crate::config::ingress::PathRewrite>) -> Result<Self> {
        Ok(Self {
            path_rewrites: path_rewrites_config
                .iter()
                .map(|path_rewrite| {
                    PathRewrite::new(&path_rewrite.match_regex, &path_rewrite.substitution)
                })
                .collect::<Result<_>>()?,
        })
    }

    pub fn rewrite(&self, path: &str) -> String {
        for path_rewrite in &self.path_rewrites {
            match path_rewrite.try_rewrite(path) {
                PathRewriteResult::NotMatched => { /* Try next */ }
                PathRewriteResult::Rewritted(rewrited_path) => {
                    return rewrited_path;
                }
            }
        }

        // If no path_rewrite matched, return the path `/`.
        "/".to_string()
    }
}

pub struct PathRewrite {
    match_regex: Regex,
    substitution: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PathRewriteResult {
    NotMatched,
    Rewritted(String),
}

impl PathRewrite {
    pub fn new(match_regex: &str, substitution: &str) -> Result<Self> {
        let _re = regex::Regex::new(match_regex)
            .with_context(|| format!("Failed to compile user provided regex: {}", match_regex))?;

        // Let's wrap the match_regex to match the whole string.
        let match_whole_string = format!("^(?:{match_regex})$");
        let re = regex::Regex::new(&match_whole_string)
            .with_context(|| format!("Failed to compile internal regex: {}", match_whole_string))?;

        Ok(Self {
            match_regex: re,
            substitution: Self::substitution_str_with_back_compatibility(substitution)?,
        })
    }

    fn substitution_str_with_back_compatibility(substitution: &str) -> Result<String> {
        // As a back compatibility on version before 2.0.0, we have to add support for "\num" in the substitution string.
        // The detailed description of the format is in https://www.envoyproxy.io/docs/envoy/latest/api-v3/type/matcher/v3/regex.proto#type-matcher-v3-regexmatchandsubstitute

        // First find all the "\num" in the substitution string.
        let re = regex::Regex::new(r"((?:[^\\]|^)(?:\\\\)*)(?:\\)(\d+)")
            .context("failed to compile internal regex")?;

        Ok(re.replace_all(substitution, r"${1}$${${2}}").to_string())
    }

    pub fn try_rewrite(&self, path: &str) -> PathRewriteResult {
        if self.match_regex.is_match(path) {
            PathRewriteResult::Rewritted(
                self.match_regex
                    .replace(path, &self.substitution)
                    .to_string(),
            )
        } else {
            PathRewriteResult::NotMatched
        }
    }
}

#[cfg(test)]
mod tests {

    use anyhow::Result;
    use serde_json::json;

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_compatibility_on_substitution() -> Result<()> {
        assert_eq!(
            PathRewrite::substitution_str_with_back_compatibility(r"\1")?,
            r"${1}"
        );

        assert_eq!(
            PathRewrite::substitution_str_with_back_compatibility(r"\\1")?,
            r"\\1"
        );

        assert_eq!(
            PathRewrite::substitution_str_with_back_compatibility(r"\\\1")?,
            r"\\${1}"
        );

        assert_eq!(
            PathRewrite::substitution_str_with_back_compatibility(r"\123")?,
            r"${123}"
        );

        assert_eq!(
            PathRewrite::substitution_str_with_back_compatibility(r"\\123")?,
            r"\\123"
        );

        assert_eq!(
            PathRewrite::substitution_str_with_back_compatibility(r"ab\123cd")?,
            r"ab${123}cd"
        );

        assert_eq!(
            PathRewrite::substitution_str_with_back_compatibility(r"ab\\123cd")?,
            r"ab\\123cd"
        );

        assert_eq!(
            PathRewrite::substitution_str_with_back_compatibility(r"ab\\\123cd")?,
            r"ab\\${123}cd"
        );

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_rewrite() -> Result<()> {
        let path_rewrite = PathRewrite::new(r"^/foo/bar/([^/]+)([/]?.*)$", r"/foo/bar/$1")?;
        assert_eq!(
            path_rewrite.try_rewrite(r"/sss"),
            PathRewriteResult::NotMatched
        );

        assert_eq!(
            path_rewrite.try_rewrite(r"/foo/bar/user/idxxxxx/info"),
            PathRewriteResult::Rewritted(r"/foo/bar/user".to_string())
        );

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_rewrite_old_version_compatibility() -> Result<()> {
        let path_rewrite = PathRewrite::new(r"^/foo/bar/([^/]+)([/]?.*)$", r"/foo/bar/\1")?;
        assert_eq!(
            path_rewrite.try_rewrite(r"/sss"),
            PathRewriteResult::NotMatched
        );

        assert_eq!(
            path_rewrite.try_rewrite(r"/foo/bar/user/idxxxxx/info"),
            PathRewriteResult::Rewritted(r"/foo/bar/user".to_string())
        );

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_rewrite_group() -> Result<()> {
        let path_rewrite_group = PathRewriteGroup::new(serde_json::from_value(json! {
            [
                {
                    "match_regex": "^/foo/bar/([^/]+)([/]?.*)$",
                    "substitution": "/foo/bar/$1"
                }
            ]
        })?)?;

        assert_eq!(path_rewrite_group.rewrite("/sss"), "/".to_string());
        assert_eq!(
            path_rewrite_group.rewrite(r"/foo/bar/user/idxxxxx/info"),
            r"/foo/bar/user".to_string()
        );

        let path_rewrite_group = PathRewriteGroup::new(serde_json::from_value(json! {
            [
                {
                    "match_regex": "/bar/([^/]+)([/]?.*)",
                    "substitution": "/bar/$1"
                }
            ]
        })?)?;

        assert_eq!(path_rewrite_group.rewrite("/sss"), "/".to_string());
        assert_eq!(
            path_rewrite_group.rewrite(r"/bar/user/idxxxxx/info"),
            r"/bar/user".to_string()
        );

        assert_eq!(
            path_rewrite_group.rewrite(r"/foo/bar/user/idxxxxx/info"),
            r"/".to_string()
        );

        Ok(())
    }
}
