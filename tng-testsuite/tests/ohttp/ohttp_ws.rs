use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{
    run_test,
    task::{
        app::{AppType, WsCloseMode},
        function::FunctionTask,
        shell::{ShellMode, ShellTask},
        tng::TngInstance,
        NodeType, Task as _,
    },
};
use tokio_util::sync::CancellationToken;

#[path = "tls_fixtures.rs"]
mod tls_fixtures;

// End-to-end scenarios for the ohttp WebSocket tunnel: an app dials the
// ingress with a WS upgrade, the ingress relays that upgrade (the app's key
// and subprotocol offer unchanged, plus the `tng-ohttp-ws` dispatch marker)
// to the egress, the egress strips the marker and runs the relayed handshake
// as a real upgrade to the backend named by the request (proxy semantics),
// and the backend's 101 travels back verbatim to the app. Frames then cross
// the middle hop as sealed records.
//
// Topology (mapping mode, following `ohttp_tls.rs`):
//   Client netns 192.168.1.253: ingress listens on :10001, posts OHTTP to
//     192.168.1.1:20001 (egress gateway).
//   Server netns 192.168.1.1: egress gateway :20001; backend ws app :30010
//     (it also answers plain HTTP for the regression). The egress dials its
//     mapping out (127.0.0.1:30010) through the shared upstream connector
//     for ws tunnels exactly like every other protocol; the relayed
//     handshake's Host is preserved data, never a dial target.
//
// The ingress configs set `path_default: original` so the relayed ws path is
// the app's own path when it reaches the backend (`/tng/ws-tunnel` here);
// with the default `root` it would be rewritten to `/`.

const EGRESS_NO_RA: &str = r#"
    {
        "add_egress": [
            {
                "mapping": {
                    "in": { "host": "0.0.0.0", "port": 20001 },
                    "out": { "host": "127.0.0.1", "port": 30010 }
                },
                "ohttp": {},
                "no_ra": true
            }
        ]
    }
    "#;

const INGRESS_NO_RA: &str = r#"
    {
        "add_ingress": [
            {
                "mapping": {
                    "in": { "host": "0.0.0.0", "port": 10001 },
                    "out": { "host": "192.168.1.1", "port": 20001 }
                },
                "ohttp": { "path_default": "original" },
                "no_ra": true
            }
        ]
    }
    "#;

const EGRESS_ATTEST: &str = r#"
    {
        "add_egress": [
            {
                "mapping": {
                    "in": { "host": "0.0.0.0", "port": 20001 },
                    "out": { "host": "127.0.0.1", "port": 30010 }
                },
                "ohttp": {},
                "attest": {
                    "model": "passport",
                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
                    "as_addr": "http://192.168.1.254:8080/",
                    "policy_ids": [
                        "default"
                    ]
                }
            }
        ]
    }
    "#;

const INGRESS_VERIFY: &str = r#"
    {
        "add_ingress": [
            {
                "mapping": {
                    "in": { "host": "0.0.0.0", "port": 10001 },
                    "out": { "host": "192.168.1.1", "port": 20001 }
                },
                "ohttp": { "path_default": "original" },
                "verify": {
                    "model": "passport",
                    "as_addr": "http://192.168.1.254:8080/",
                    "policy_ids": [
                        "default"
                    ]
                }
            }
        ]
    }
    "#;

/// One verifier covering both payload shapes through the same tunnel: the ws
/// echo round trip first, then a plain HTTP request via the same ingress.
/// It has to be a single task because the harness tears the scenario down on
/// the first client completion, and each inner client gets a throwaway token
/// so only this wrapper cancels the shared test token.
fn ws_then_http_verifier() -> FunctionTask {
    FunctionTask {
        name: "app_ws_then_http_client".to_owned(),
        node_type: NodeType::Client,
        func: Box::new(|token| {
            Ok(tokio::task::spawn(async move {
                let _drop_guard = token.drop_guard();

                let ws = AppType::WsClient {
                    host: "192.168.1.1",
                    port: 30010,
                    proxy: Some("127.0.0.1:10001".to_owned()),
                    subprotocol: None,
                    close: WsCloseMode::None,
                }
                .launch(CancellationToken::new())
                .await?;
                ws.await
                    .map_err(|e| anyhow::anyhow!("ws client task join failed: {e}"))??;

                // Plain HTTP must keep working on the same ingress
                // listener alongside the ws relay; the ws app answers it.
                let http = AppType::HttpClient {
                    host: "127.0.0.1",
                    port: 10001,
                    host_header: "example.com",
                    path_and_query: "/ws-e2e/http?q=1",
                }
                .launch(CancellationToken::new())
                .await?;
                http.await
                    .map_err(|e| anyhow::anyhow!("http client task join failed: {e}"))??;

                Ok(())
            }))
        }),
    }
}

/// The ws client adds no subprotocol itself; the ingress stamps the
/// `tng-ohttp-ws` marker on the egress hop, so a successful echo run also
/// proves the ingress-side marker handling.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ohttp_ws_tunnel() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(EGRESS_NO_RA).boxed(),
        TngInstance::TngClient(INGRESS_NO_RA).boxed(),
        AppType::WsServer {
            port: 30010,
            close_after_greeting: false,
        }
        .boxed(),
        ws_then_http_verifier().boxed(),
    ])
    .await?;

    Ok(())
}

/// A raw ws upgrade without the `tng-ohttp-ws` marker must be refused at the
/// egress with the existing 403 (`RejectNonTngRequest`): dispatch happens on
/// the marker (or the api header), never on the URL path, so an ordinary
/// path is used to prove the egress does not match paths. It dials the
/// egress (not the ingress: the ingress would add the marker itself) from
/// the middleware node, which runs no TNG process, so nothing rewrites the
/// request on the way. The marker-bearing variant must get past dispatch
/// instead: it is dialed with `Host` naming the egress itself, so the egress
/// relays to its own front, the (marker-stripped) inner request is refused
/// there, and the failure surfaces as a backend-handshake error, not a 403
/// rejection of the outer upgrade.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ohttp_ws_rejects_missing_marker() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(EGRESS_NO_RA).boxed(),
        ShellTask {
            name: "ws_endpoint_requires_marker".to_owned(),
            node_type: NodeType::Middleware,
            script: r#"
                code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 \
                    -H 'Upgrade: websocket' \
                    -H 'Connection: Upgrade' \
                    -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
                    -H 'Sec-WebSocket-Version: 13' \
                    'http://192.168.1.1:20001/some/business/path')
                [ "$code" = "403" ] || { echo "FAIL: expected 403, got '$code'"; exit 1; }
                echo "PASS: egress refused the markerless ws upgrade"

                code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 \
                    -H 'Upgrade: websocket' \
                    -H 'Connection: Upgrade' \
                    -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
                    -H 'Sec-WebSocket-Version: 13' \
                    -H 'Sec-WebSocket-Protocol: tng-ohttp-ws' \
                    'http://192.168.1.1:20001/some/business/path')
                if [ -z "$code" ] || [ "$code" = "403" ]; then
                    echo "FAIL: marked upgrade should reach the ws handler, got '$code'"; exit 1
                fi
                echo "PASS: marked upgrade dispatched to the ws handler (http $code)"
            "#
            .to_owned(),
            mode: ShellMode::ForegroundStop,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

/// The app's business subprotocol must cross both tunnel hops untouched and
/// reach the backend: the ws_server echoes any offered subprotocol into its
/// greeting, so the client seeing `ws-tng-test chat.v1` proves the offer
/// arrived verbatim and that the egress stripped only the marker (a leaked
/// marker would break the egress's own handshake verification against the
/// backend's response, failing the run before the greeting).
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ohttp_ws_subprotocol_passthrough() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(EGRESS_NO_RA).boxed(),
        TngInstance::TngClient(INGRESS_NO_RA).boxed(),
        AppType::WsServer {
            port: 30010,
            close_after_greeting: false,
        }
        .boxed(),
        AppType::WsClient {
            host: "192.168.1.1",
            port: 30010,
            proxy: Some("127.0.0.1:10001".to_owned()),
            subprotocol: Some("chat.v1"),
            close: WsCloseMode::None,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

/// A backend-initiated Close must travel back through the tunnel: the egress
/// turns the backend Close frame into a Close record, the ingress replays it
/// to the app, and the client observes the Close instead of an echo.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ohttp_ws_backend_close() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(EGRESS_NO_RA).boxed(),
        TngInstance::TngClient(INGRESS_NO_RA).boxed(),
        AppType::WsServer {
            port: 30010,
            close_after_greeting: true,
        }
        .boxed(),
        AppType::WsClient {
            host: "192.168.1.1",
            port: 30010,
            proxy: Some("127.0.0.1:10001".to_owned()),
            subprotocol: None,
            close: WsCloseMode::ExpectServerClose,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

/// The mirror case: the app starts the close handshake after the echo round
/// trip. The Close must reach the backend as a record, the backend's echo
/// must come back through both relay hops, and the client must observe a
/// Close frame rather than an abruptly dropped socket.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ohttp_ws_app_initiated_close() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(EGRESS_NO_RA).boxed(),
        TngInstance::TngClient(INGRESS_NO_RA).boxed(),
        AppType::WsServer {
            port: 30010,
            close_after_greeting: false,
        }
        .boxed(),
        AppType::WsClient {
            host: "192.168.1.1",
            port: 30010,
            proxy: Some("127.0.0.1:10001".to_owned()),
            subprotocol: None,
            close: WsCloseMode::InitiateAndRequireEcho,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

/// The main tunnel scenario with remote attestation enabled on both ends
/// (server attest + client verify, passport model), so the ws control message
/// is proven to carry the attested key exchange too.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ohttp_ws_tunnel_ra() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(EGRESS_ATTEST).boxed(),
        TngInstance::TngClient(INGRESS_VERIFY).boxed(),
        AppType::WsServer {
            port: 30010,
            close_after_greeting: false,
        }
        .boxed(),
        AppType::WsClient {
            host: "192.168.1.1",
            port: 30010,
            proxy: Some("127.0.0.1:10001".to_owned()),
            subprotocol: None,
            close: WsCloseMode::None,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

/// The same tunnel with `ohttp.tls` on: the ingress wraps its egress hop in
/// TLS (rustls, ALPN http/1.1, roots from `tls_ca_certs`), a TLS-terminating
/// gateway stands in front of the egress, and the ws echo still runs green.
/// This is the only end-to-end coverage of the websocket middle hop's TLS
/// path, which carries the rustls version deviation from the reqwest path.
///
/// Topology follows `ohttp_tls.rs`: the gateway is forced into the Server
/// netns so it shares loopback with the egress; the ingress dials its TLS port
/// 20002, covered by the gateway cert's IP:192.168.1.1 SAN.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ohttp_ws_tunnel_tls() -> Result<()> {
    let ca_path = tls_fixtures::write_ca_to_tempfile()?;
    let ca_path_str = ca_path.to_string_lossy().to_string();

    run_test!(vec![
        TngInstance::TngServer(EGRESS_NO_RA).boxed(),
        AppType::TlsTcpProxy {
            listen_port: 20002,
            upstream_host: "127.0.0.1",
            upstream_port: 20001,
            cert_pem: tls_fixtures::SERVER_CERT_PEM,
            key_pem: tls_fixtures::SERVER_KEY_PEM,
        }
        .with_overwrite_node_type(NodeType::Server)
        .boxed(),
        TngInstance::TngClient(
            // `TngClient` requires `&'static str`; the test process is
            // short-lived, so leaking the formatted config is safe.
            Box::leak(
                format!(
                    r#"
                    {{
                        "add_ingress": [
                            {{
                                "mapping": {{
                                    "in": {{ "host": "0.0.0.0", "port": 10001 }},
                                    "out": {{ "host": "192.168.1.1", "port": 20002 }}
                                }},
                                "ohttp": {{
                                    "tls": true,
                                    "tls_ca_certs": ["{ca_path_str}"],
                                    "path_default": "original"
                                }},
                                "no_ra": true
                            }}
                        ]
                    }}
                    "#
                )
                .into_boxed_str(),
            ),
        )
        .boxed(),
        AppType::WsServer {
            port: 30010,
            close_after_greeting: false,
        }
        .boxed(),
        AppType::WsClient {
            host: "192.168.1.1",
            port: 30010,
            proxy: Some("127.0.0.1:10001".to_owned()),
            subprotocol: None,
            close: WsCloseMode::None,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}
