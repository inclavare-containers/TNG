use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{
    run_test,
    task::{app::AppType, tng::TngInstance, NodeType, Task as _},
};

#[path = "tls_fixtures.rs"]
mod tls_fixtures;

/// wasm ingress derives the outer OHTTP POST scheme from the fetch URL's
/// scheme (`https` ⇒ `https`, anything else ⇒ `http`) — there is no `ohttp.tls`
/// field on wasm. These tests exercise both schemes end-to-end through a
/// BrowserClient (headless Chrome running the wasm SDK) against an egress that
/// sits behind a TLS-terminating gateway for the https case.
///
/// Unlike `ohttp_tls.rs` (native, `no_ra: true`), the wasm fetch path REQUIRES
/// a real attestation result — `forward_request` bails with "The attestation
/// result is missing" when the egress returns `None` (see
/// `tng-wasm/src/fetch/mod.rs`), so `no_ra` cannot be used through the wasm
/// path. These tests therefore mirror `js_sdk_http.rs`: the egress `attest`s
/// via the Attestation Agent (`make test-dep-aa`) and the wasm ingress
/// `verify`s against the Attestation Service at `http://192.168.1.254:8080/`
/// (the bridge-network gateway = host, served by `make test-dep-as`). The JS
/// checks `response.ok` plus the presence of `attest_info.attestation_result`;
/// the wasm SDK's own bail-on-missing-attestation guarantees the RA actually
/// ran.
///
/// ## Topology (https case)
/// Browser (Client netns, 192.168.1.253) → https POST to 192.168.1.1:20002
/// (TlsTcpProxy gateway, Server netns, self-signed `SERVER_CERT_PEM`) → TLS
/// termination → plain TCP to 127.0.0.1:20001 (egress mapping-in, Server netns)
/// → OHTTP decap (+ egress attests via AA) → 127.0.0.1:30001 (HttpServer).
///
/// Chrome is launched with `--ignore-certificate-errors` (see browser_client.rs)
/// so it accepts the self-signed gateway cert; `--disable-web-security` alone
/// only bypasses CORS, not certificate validation.
///
/// ## Topology (http case)
/// Browser → http POST to 192.168.1.1:20001 (egress mapping-in directly, no
/// gateway) → OHTTP decap (+ egress attests via AA) → 127.0.0.1:30001.
///
/// The two cases have different inner Host headers (192.168.1.1:20002 vs
/// 192.168.1.1:20001), and `http_server.rs` asserts the expected host header
/// per request, so they must be separate test functions.
#[cfg(feature = "js-sdk")]
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ohttps_forwarded_over_tls_wasm() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
            {
                "add_egress": [
                    {
                        "mapping": {
                            "in": { "host": "0.0.0.0", "port": 20001 },
                            "out": { "host": "127.0.0.1", "port": 30001 }
                        },
                        "ohttp": {},
                        "attest": {
                            "model": "background_check",
                            "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                        }
                    }
                ]
            }
            "#,
        )
        .boxed(),
        // TLS-terminating gateway in front of the egress. Forwards decrypted
        // bytes to the egress mapping-in at 127.0.0.1:20001. Forced into the
        // Server netns (192.168.1.1) so it shares loopback with the egress and
        // is reachable from the BrowserClient at 192.168.1.1:20002.
        AppType::TlsTcpProxy {
            listen_port: 20002,
            upstream_host: "127.0.0.1",
            upstream_port: 20001,
            cert_pem: tls_fixtures::SERVER_CERT_PEM,
            key_pem: tls_fixtures::SERVER_KEY_PEM,
        }
        .with_overwrite_node_type(NodeType::Server)
        .boxed(),
        AppType::HttpServer {
            port: 30001,
            // The wasm ingress sets the inner Host header from the fetch URL's
            // authority, which here is the gateway address.
            expected_host_header: "192.168.1.1:20002",
            expected_path_and_query: "/foo/bar?type=1&case=1",
        }
        .boxed(),
        AppType::BrowserClient {
            js: r#"
                await tng_init();

                const config = {
                    ohttp: {},
                    verify: {
                        model: "background_check",
                        as_addr: "http://192.168.1.254:8080/",
                        policy_ids: ["default"]
                    }
                };
                const response = await tng_fetch(
                    "https://192.168.1.1:20002/foo/bar?type=1&case=1",
                    { method: "GET" },
                    config
                );
                if (!response.ok) {
                    let msg = `https fetch failed: ${response.status} ${response.statusText}`;
                    try {
                        const body = await response.text();
                        if (body) msg += `\n${body.trim()}`;
                    } catch (e) {}
                    throw new Error(msg);
                }
                if (!(response.attest_info && response.attest_info.attestation_result != null)) {
                    throw new Error('https: attest_info.attestation_result is missing');
                }
            "#
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

/// http case: the wasm ingress picks `http` from the fetch URL and posts the
/// OHTTP directly to the egress mapping-in (no gateway). See the module-level
/// comment on `test_ohttps_forwarded_over_tls_wasm` for the shared rationale.
#[cfg(feature = "js-sdk")]
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ohttp_forwarded_plain_wasm() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
            {
                "add_egress": [
                    {
                        "mapping": {
                            "in": { "host": "0.0.0.0", "port": 20001 },
                            "out": { "host": "127.0.0.1", "port": 30001 }
                        },
                        "ohttp": {},
                        "attest": {
                            "model": "background_check",
                            "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                        }
                    }
                ]
            }
            "#,
        )
        .boxed(),
        AppType::HttpServer {
            port: 30001,
            expected_host_header: "192.168.1.1:20001",
            expected_path_and_query: "/foo/bar?type=1&case=1",
        }
        .boxed(),
        AppType::BrowserClient {
            js: r#"
                await tng_init();

                const config = {
                    ohttp: {},
                    verify: {
                        model: "background_check",
                        as_addr: "http://192.168.1.254:8080/",
                        policy_ids: ["default"]
                    }
                };
                const response = await tng_fetch(
                    "http://192.168.1.1:20001/foo/bar?type=1&case=1",
                    { method: "GET" },
                    config
                );
                if (!response.ok) {
                    let msg = `http fetch failed: ${response.status} ${response.statusText}`;
                    try {
                        const body = await response.text();
                        if (body) msg += `\n${body.trim()}`;
                    } catch (e) {}
                    throw new Error(msg);
                }
                if (!(response.attest_info && response.attest_info.attestation_result != null)) {
                    throw new Error('http: attest_info.attestation_result is missing');
                }
            "#
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}
