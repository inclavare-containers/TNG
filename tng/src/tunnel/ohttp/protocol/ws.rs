use std::time::Duration;

use http::header::{HOST, SEC_WEBSOCKET_PROTOCOL};
use http::{HeaderMap, HeaderValue};

use crate::error::TngError;
use crate::tunnel::ohttp::protocol::header::OhttpApi;

/// Subprotocol token that claims a WebSocket upgrade as a TNG ws tunnel.
/// It is the single dispatch signal on the egress: the native ingress adds
/// it when relaying, and a browser in the client role (whose WebSocket API
/// cannot set custom handshake headers) offers it itself.
pub const TNG_WS_MARKER: &str = "tng-ohttp-ws";

/// Budget for completing the ws negotiation before the tunnel is considered failed.
pub const TNG_WS_NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(10);

/// Parse the Sec-WebSocket-Protocol list (comma-separated).
pub fn parse_subprotocols(value: &HeaderValue) -> Vec<String> {
    // A non-utf8 header value cannot carry the ascii marker, so it has no tokens for us.
    let Ok(raw) = value.to_str() else {
        return Vec::new();
    };
    raw.split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .collect()
}

/// True when the offered list contains the TNG marker.
pub fn has_tng_marker(value: &HeaderValue) -> bool {
    // The marker is a fixed ascii constant, so an exact case-sensitive token
    // match is the whole contract; subprotocol tokens are otherwise case-insensitive.
    parse_subprotocols(value)
        .iter()
        .any(|token| token == TNG_WS_MARKER)
}

/// Remove the TNG marker from the list, keeping the rest in order.
pub fn strip_tng_marker(value: &HeaderValue) -> Option<HeaderValue> {
    let rest: Vec<String> = parse_subprotocols(value)
        .into_iter()
        .filter(|token| token != TNG_WS_MARKER)
        .collect();
    if rest.is_empty() {
        return None;
    }
    // Tokens derive from a valid header value, so the rebuilt list is always valid.
    HeaderValue::from_str(&rest.join(", ")).ok()
}

/// Backend target carried by a relayed upgrade request (proxy semantics,
/// the same rule as ordinary ohttp inner requests): an absolute-form
/// request URI names the target in its authority, an origin-form one
/// carries it in the `Host` header. The path is the request's
/// path-and-query, defaulting to `/` when the URI has none.
pub fn backend_target(uri: &http::Uri, headers: &HeaderMap) -> Result<(String, String), TngError> {
    let authority = uri
        .authority()
        .map(|a| a.as_str().to_owned())
        .or_else(|| {
            headers
                .get(HOST)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        })
        .filter(|value| !value.is_empty())
        .ok_or(TngError::InvalidHttpRequest)?;
    let path = uri
        .path_and_query()
        .map(|pq| pq.as_str().to_owned())
        .unwrap_or_else(|| "/".to_string());
    Ok((authority, path))
}

/// Header set for a relayed WebSocket handshake request. Everything the
/// app offered is copied through except what a hop owns or decides: `Host`
/// (the relay re-names the next target) and the subprotocol list (the relay
/// caller appends or strips the marker before re-inserting it) and the
/// `x-tng-ohttp-api` dispatch header (it must never leave the tunnel or
/// reach the backend). `Connection`, `Upgrade`, `Sec-WebSocket-Version`,
/// `Sec-WebSocket-Key` and `Sec-WebSocket-Extensions` pass through untouched:
/// the handshake is the app's own and relays end to end, so the app and the
/// backend can negotiate any extension (compression included) and TNG relays
/// the resulting frames opaquely.
pub fn ws_relay_request_headers(incoming: &HeaderMap, protocol: Option<HeaderValue>) -> HeaderMap {
    let mut relayed = HeaderMap::new();
    for (name, value) in incoming {
        if *name == HOST
            || *name == SEC_WEBSOCKET_PROTOCOL
            || name.as_str() == OhttpApi::HEADER_NAME
        {
            continue;
        }
        relayed.append(name.clone(), value.clone());
    }
    if let Some(protocol) = protocol {
        relayed.insert(SEC_WEBSOCKET_PROTOCOL, protocol);
    }
    relayed
}

/// Header set for a relayed 101 response: the backend's headers verbatim
/// minus the ones a single HTTP connection owns. `Connection` and `Upgrade`
/// are the deliberate exception to hop-by-hop stripping: the next hop up
/// verifies the WebSocket handshake through them, and hyper requires them to
/// hand the connection over.
pub fn ws_relay_response_headers(incoming: &HeaderMap) -> HeaderMap {
    // http::header has no constants for all of these; iterated HeaderMap
    // names are always lowercase, so plain string comparison is exact.
    const CONNECTION_OWNED: [&str; 6] = [
        "transfer-encoding",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
    ];
    let mut relayed = HeaderMap::new();
    for (name, value) in incoming {
        if CONNECTION_OWNED.contains(&name.as_str()) {
            continue;
        }
        relayed.append(name.clone(), value.clone());
    }
    relayed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_roundtrip() {
        let v = http::HeaderValue::from_str("tng-ohttp-ws, chat.v2, json").unwrap();
        assert!(has_tng_marker(&v));
        let stripped = strip_tng_marker(&v).unwrap();
        assert_eq!(stripped.to_str().unwrap(), "chat.v2, json");
        assert!(!has_tng_marker(&stripped));
    }

    #[test]
    fn parse_subprotocols_splits_and_trims() {
        let v = http::HeaderValue::from_static(" chat.v1 ,tng-ohttp-ws, json");
        assert_eq!(
            parse_subprotocols(&v),
            vec![
                "chat.v1".to_string(),
                "tng-ohttp-ws".to_string(),
                "json".to_string()
            ]
        );
    }

    #[test]
    fn marker_match_is_exact_token_case_sensitive() {
        let v = http::HeaderValue::from_static("TNG-OHTTP-WS, tng-ohttp-ws-x, xtng-ohttp-ws");
        assert!(!has_tng_marker(&v));
        // No exact token matches, so nothing is stripped and the list is kept.
        let stripped = strip_tng_marker(&v).unwrap();
        assert_eq!(
            stripped.to_str().unwrap(),
            "TNG-OHTTP-WS, tng-ohttp-ws-x, xtng-ohttp-ws"
        );
    }

    #[test]
    fn strip_leaves_none_when_list_becomes_empty() {
        let v = http::HeaderValue::from_static("tng-ohttp-ws");
        assert!(strip_tng_marker(&v).is_none());
    }

    #[test]
    fn strip_removes_every_marker_occurrence() {
        let v = http::HeaderValue::from_static("tng-ohttp-ws, chat, tng-ohttp-ws");
        let stripped = strip_tng_marker(&v).unwrap();
        assert_eq!(stripped.to_str().unwrap(), "chat");
        assert!(!has_tng_marker(&stripped));
        let v = http::HeaderValue::from_static("tng-ohttp-ws, tng-ohttp-ws");
        assert!(strip_tng_marker(&v).is_none());
    }

    #[test]
    fn backend_target_prefers_absolute_uri_authority() {
        let uri: http::Uri = "http://backend.example:9000/ws/chat?room=1"
            .parse()
            .unwrap();
        let headers = HeaderMap::new();
        let (authority, path) = backend_target(&uri, &headers).unwrap();
        assert_eq!(authority, "backend.example:9000");
        assert_eq!(path, "/ws/chat?room=1");
    }

    #[test]
    fn backend_target_falls_back_to_host_header() {
        let uri: http::Uri = "/ws/chat".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("backend:80"));
        let (authority, path) = backend_target(&uri, &headers).unwrap();
        assert_eq!(authority, "backend:80");
        // Origin-form path without query still yields an absolute backend path.
        assert_eq!(path, "/ws/chat");
    }

    #[test]
    fn backend_target_errors_when_neither_present() {
        let uri: http::Uri = "/ws/chat".parse().unwrap();
        assert!(backend_target(&uri, &HeaderMap::new()).is_err());

        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static(""));
        assert!(backend_target(&uri, &headers).is_err());
    }

    fn app_handshake_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("app.example:1"));
        headers.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("keep-alive, Upgrade"),
        );
        headers.insert(http::header::UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(
            http::header::SEC_WEBSOCKET_VERSION,
            HeaderValue::from_static("13"),
        );
        headers.insert(
            http::header::SEC_WEBSOCKET_KEY,
            HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ=="),
        );
        headers.insert(
            SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static("tng-ohttp-ws, chat.v2"),
        );
        headers.insert(
            http::header::SEC_WEBSOCKET_EXTENSIONS,
            HeaderValue::from_static("permessage-deflate"),
        );
        headers.insert(
            OhttpApi::HEADER_NAME,
            HeaderValue::from_static(OhttpApi::TUNNEL),
        );
        headers.insert("x-app-meta", HeaderValue::from_static("keep-me"));
        headers
    }

    #[test]
    fn request_relay_copies_through_except_hop_owned_headers() {
        let relayed = ws_relay_request_headers(&app_handshake_headers(), None);
        // The handshake identity stays the app's own; business headers survive.
        assert_eq!(
            relayed[http::header::SEC_WEBSOCKET_KEY],
            "dGhlIHNhbXBsZSBub25jZQ=="
        );
        assert_eq!(relayed[http::header::SEC_WEBSOCKET_VERSION], "13");
        assert_eq!(relayed[http::header::CONNECTION], "keep-alive, Upgrade");
        assert_eq!(relayed[http::header::UPGRADE], "websocket");
        assert_eq!(relayed["x-app-meta"], "keep-me");
        // The extension offer passes through with the rest of the handshake:
        // the app and the backend negotiate it end to end and TNG relays the
        // frames opaquely. Only Host, the protocol list and the dispatch
        // header are rewritten or dropped per hop.
        assert_eq!(
            relayed[http::header::SEC_WEBSOCKET_EXTENSIONS],
            "permessage-deflate"
        );
        assert!(!relayed.contains_key(HOST));
        assert!(!relayed.contains_key(SEC_WEBSOCKET_PROTOCOL));
        assert!(!relayed.contains_key(OhttpApi::HEADER_NAME));

        let with_protocol = ws_relay_request_headers(
            &app_handshake_headers(),
            Some(HeaderValue::from_static("chat.v2")),
        );
        assert_eq!(with_protocol[SEC_WEBSOCKET_PROTOCOL], "chat.v2");
    }

    #[test]
    fn response_relay_keeps_handshake_headers_and_drops_connection_owned() {
        let mut incoming = HeaderMap::new();
        incoming.insert(
            http::header::SEC_WEBSOCKET_ACCEPT,
            HeaderValue::from_static("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
        );
        incoming.insert(SEC_WEBSOCKET_PROTOCOL, HeaderValue::from_static("chat.v2"));
        incoming.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("Upgrade"),
        );
        incoming.insert(http::header::UPGRADE, HeaderValue::from_static("websocket"));
        incoming.insert(
            http::header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        let keep_alive = http::HeaderName::from_static("keep-alive");
        incoming.insert(keep_alive.clone(), HeaderValue::from_static("timeout=5"));

        let relayed = ws_relay_response_headers(&incoming);
        // The accept and subprotocol the backend chose must survive verbatim;
        // Connection/Upgrade must survive even though they are hop-by-hop,
        // because the next hop's handshake verification reads them.
        assert_eq!(
            relayed[http::header::SEC_WEBSOCKET_ACCEPT],
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
        assert_eq!(relayed[SEC_WEBSOCKET_PROTOCOL], "chat.v2");
        assert_eq!(relayed[http::header::CONNECTION], "Upgrade");
        assert_eq!(relayed[http::header::UPGRADE], "websocket");
        assert!(!relayed.contains_key(http::header::TRANSFER_ENCODING));
        assert!(!relayed.contains_key(&keep_alive));
    }
}
