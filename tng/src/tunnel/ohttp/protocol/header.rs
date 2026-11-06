pub const OHTTP_CHUNKED_REQUEST_CONTENT_TYPE: &str = "message/ohttp-chunked-req";

pub const OHTTP_CHUNKED_RESPONSE_CONTENT_TYPE: &str = "message/ohttp-chunked-res";

#[derive(Debug, Clone)]
#[allow(unused)]
pub enum OhttpApi {
    KeyConfig,
    Tunnel,
    BackgroundCheckChallenge,
    BackgroundCheckVerify,
}

impl OhttpApi {
    pub const HEADER_NAME: &'static str = "x-tng-ohttp-api";
    /// - POST /tng/key-config: Get HPKE configuration
    pub const KEY_CONFIG: &'static str = "/tng/key-config";
    /// - POST /tng/tunnel: Process encrypted requests
    pub const TUNNEL: &'static str = "/tng/tunnel";
    /// - GET /tng/background-check/challenge: Get attestation challenge
    pub const BACKGROUND_CHECK_CHALLENGE: &'static str = "/tng/background-check/challenge";
    /// - POST /tng/background-check/verify: Verify attestation evidence
    pub const BACKGROUND_CHECK_VERIFY: &'static str = "/tng/background-check/verify";
}

/// Returns true if the HTTP request is a WebSocket upgrade request.
///
/// Per RFC 6455 an upgrade is a GET whose `Upgrade` header carries the
/// `websocket` token and whose `Connection` header carries the `upgrade`
/// token. Both headers are comma separated token lists and token matching
/// is case insensitive. Native-only: every tunnel end that inspects upgrades
/// is outside the wasm build.
#[cfg(not(wasm))]
pub fn is_websocket_upgrade<B>(req: &http::Request<B>) -> bool {
    if req.method() != http::Method::GET {
        return false;
    }

    let has_token = |name: http::HeaderName, token: &str| {
        req.headers()
            .get_all(name)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .any(|part| part.trim().eq_ignore_ascii_case(token))
    };

    has_token(http::header::UPGRADE, "websocket") && has_token(http::header::CONNECTION, "upgrade")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request(headers: &[(&str, &str)]) -> http::Request<()> {
        let mut builder = http::Request::builder();
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        builder.body(()).unwrap()
    }

    #[test]
    fn returns_true_for_valid_websocket_upgrade() {
        let req = make_request(&[("Upgrade", "websocket"), ("Connection", "Upgrade")]);
        assert!(is_websocket_upgrade(&req));
    }

    #[test]
    fn returns_false_without_upgrade_header() {
        let req = make_request(&[("Connection", "Upgrade")]);
        assert!(!is_websocket_upgrade(&req));
    }

    #[test]
    fn returns_false_without_connection_header() {
        let req = make_request(&[("Upgrade", "websocket")]);
        assert!(!is_websocket_upgrade(&req));
    }

    #[test]
    fn returns_false_for_non_websocket_upgrade() {
        let req = make_request(&[("Upgrade", "h2c"), ("Connection", "Upgrade")]);
        assert!(!is_websocket_upgrade(&req));
    }

    #[test]
    fn returns_false_for_non_get_method() {
        let req = http::Request::builder()
            .method(http::Method::POST)
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .body(())
            .unwrap();
        assert!(!is_websocket_upgrade(&req));
    }

    #[test]
    fn case_insensitive_upgrade_value() {
        let req = make_request(&[("Upgrade", "WebSocket"), ("Connection", "upgrade")]);
        assert!(is_websocket_upgrade(&req));
    }

    #[test]
    fn connection_can_contain_multiple_values() {
        let req = make_request(&[
            ("Upgrade", "websocket"),
            ("Connection", "keep-alive, Upgrade"),
        ]);
        assert!(is_websocket_upgrade(&req));
    }

    #[test]
    fn upgrade_can_contain_multiple_values() {
        let req = make_request(&[
            ("Upgrade", "keepalive, websocket"),
            ("Connection", "Upgrade"),
        ]);
        assert!(is_websocket_upgrade(&req));
    }

    #[test]
    fn tokens_must_match_whole_list_entry() {
        let req = make_request(&[("Upgrade", "websocketx"), ("Connection", "notupgrade")]);
        assert!(!is_websocket_upgrade(&req));
    }

    #[test]
    fn returns_false_for_empty_headers() {
        let req: http::Request<()> = http::Request::builder().body(()).unwrap();
        assert!(!is_websocket_upgrade(&req));
    }
}
