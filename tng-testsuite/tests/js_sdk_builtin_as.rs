use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{
    run_test,
    task::{app::AppType, tng::TngInstance, Task as _},
};

/// End-to-end test for the wasm builtin-as path.
///
/// The server (egress) STILL uses the Attestation Agent (AA) to produce
/// evidence — builtin-as only replaces the Attestation *Service* (the
/// convert/verify side), not the AA (the evidence-collection side). What
/// changes is the BrowserClient (wasm SDK) `verify` config: instead of
/// `as_addr`/`as_type: "restful"` pointing at an external AS over HTTP, it
/// uses `as_type: "builtin"` so the wasm SDK converts + verifies the server's
/// token in-process. This test therefore requires `make test-dep-aa` (for the
/// AA + ASR) but MUST NOT require `make test-dep-as` (the external AS) — that
/// is the whole point of builtin-as.
///
/// Note on the assertion: the harness's default `common_check_response`
/// requires `attest_info.as_addr` and `attest_info.policy_ids` for the coco
/// provider in background_check mode. The builtin path exposes neither (it
/// has no remote address or policy ids), so a dedicated
/// `builtin_check_response` is used instead.
#[cfg(feature = "js-sdk")]
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn server_background_check_builtin_as() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
            {
                "add_egress": [
                    {
                        "netfilter": {
                            "capture_dst": {
                                "port": 30001
                            }
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
        ).boxed(),
        AppType::HttpServer {
            port: 30001,
            expected_host_header: "192.168.1.1:30001",
            expected_path_and_query: "/foo/bar/www?type=1&case=1",
        }.boxed(),
        AppType::BrowserClient {
            js: r#"
                await tng_init();

                const config = {
                    ohttp: {},
                    verify: {
                        model: "background_check",
                        as_type: "builtin"
                    }
                };
                {
                    const response = await tng_fetch("http://192.168.1.1:30001/foo/bar/www?type=1&case=1",
                        {
                            method: "GET",
                            headers: {
                                "custom": "custom-value",
                            },
                        }, config);
                    await builtin_check_response(response);
                }
                {
                    const response = await tng_fetch("http://192.168.1.1:30001/foo/bar/www?type=1&case=1",
                        {
                            method: "POST",
                            headers: {
                                "custom": "custom-value",
                            },
                            body: JSON.stringify({ answer: 42 }),
                        }, config);
                    await builtin_check_response(response);
                }

                // Builtin AS has no remote address (as_addr) or policy_ids to
                // expose; the wasm SDK converts + verifies the server's token
                // in-process. Only assert that attestation ran end-to-end and
                // the as_provider is still "coco".
                async function builtin_check_response(response) {
                    if (!response.ok) {
                        let errorMessage = `Response status: ${response.status} ${response.statusText}`;
                        try {
                            const responseBody = await response.text();
                            if (responseBody) {
                                errorMessage += `\nResponse body: ${responseBody.trim()}`;
                            }
                        } catch (err) {
                            errorMessage += `\nFailed to read response body: ${err.message}`;
                        }
                        throw new Error(errorMessage);
                    }

                    if (!(response.attest_info !== undefined && response.attest_info !== null)) {
                        throw new Error('attest_info not exist');
                    }

                    const info = response.attest_info;

                    if (!(info.attestation_result !== undefined && info.attestation_result !== null)) {
                        throw new Error('attest_info.attestation_result not exist');
                    }

                    const provider = info.as_provider;
                    if (!provider) {
                        throw new Error('attest_info.as_provider not exist');
                    }

                    // The builtin AS path still reports the coco provider, but
                    // intentionally omits as_addr and policy_ids (there is no
                    // remote AS to point at). Ensure those are indeed absent so
                    // we are actually exercising the builtin path rather than a
                    // leftover restful config.
                    if (provider === 'coco') {
                        if (info.as_addr !== undefined && info.as_addr !== null) {
                            throw new Error(`builtin path should not expose as_addr, got: ${info.as_addr}`);
                        }
                        if (info.policy_ids !== undefined && info.policy_ids !== null) {
                            throw new Error(`builtin path should not expose policy_ids, got: ${info.policy_ids}`);
                        }
                    } else {
                        throw new Error(`Unknown as_provider for builtin-as: ${provider}`);
                    }
                }
            "#
        }.boxed(),
    ])
    .await?;

    Ok(())
}
