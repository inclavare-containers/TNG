use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{
    run_test,
    task::{app::AppType, tng::TngInstance, Task as _},
};

/// End-to-end builtin-AS verification through the WASM SDK in a headless browser.
///
/// Unlike `js_sdk_http` (which drives a *remote* attestation service via
/// `as_addr`), here the browser-side `verify` config selects `as_type: "builtin"`,
/// so the attestation service runs **in-process inside the wasm SDK** — exactly
/// the migrated path (`JwtChallenger` by value, WebCrypto RSA keygen on wasm via
/// `build_challenger_webcrypto`, and `get_nonce` extracting the bare JWT). The
/// builtin AS generates the challenge and verifies the egress's evidence itself,
/// so this test does **not** depend on `make test-dep-as`.
///
/// The egress still attests via the remote Attestation Agent (`aa_addr` unix
/// socket, `make test-dep-aa`): the builtin *attester* (server-side evidence
/// production) is not yet implemented (`tng/src/tunnel/provider/factory.rs`),
/// so the AA is the evidence source. The builtin AS (verifier) then verifies
/// that evidence end-to-end.
#[cfg(feature = "js-sdk")]
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn server_builtin_as_background_check() -> Result<()> {
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
                        // Run the attestation service in-process (builtin) inside
                        // the wasm SDK instead of calling a remote AS. No as_addr.
                        as_type: "builtin",
                        // `trust_all` affirms every trustworthiness dimension
                        // unconditionally — but only AFTER the builtin AS has
                        // cryptographically verified the AA's TDX evidence (quote
                        // signature + PCCS collateral). It is the right level for
                        // this integration test, which exercises the builtin-as
                        // plumbing (WebCrypto keygen → challenge → evidence
                        // verification → token issuance) rather than asserting
                        // specific TEE measurements (the AA's quotes carry no
                        // known-good reference values to match against).
                        attestation_policy: {
                            type: "trust_all"
                        },
                        reference_values: []
                    }
                };

                // Builtin-as leaves as_addr / policy_ids null (the shared
                // common_check_response helper requires them for coco), so use a
                // dedicated check that asserts the builtin path produced an
                // attestation result (only issued after evidence verification
                // succeeded) and that no remote AS address is present.
                async function check_builtin_response(response) {
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
                    if (typeof info.attestation_result !== 'string' || info.attestation_result.length === 0) {
                        throw new Error(`attest_info.attestation_result should be a non-empty token string but got ${info.attestation_result}`);
                    }

                    if (info.as_provider !== 'coco') {
                        throw new Error(`expected as_provider='coco', got '${info.as_provider}'`);
                    }

                    // Builtin AS has no remote attestation service address.
                    if (info.as_addr !== undefined && info.as_addr !== null) {
                        throw new Error(`builtin-as should have no as_addr, got '${info.as_addr}'`);
                    }
                }

                {
                    const response = await tng_fetch("http://192.168.1.1:30001/foo/bar/www?type=1&case=1",
                        {
                            method: "GET",
                            headers: {
                                "custom": "custom-value",
                            },
                        }, config);
                    await check_builtin_response(response);
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
                    await check_builtin_response(response);
                }
            "#
        }.boxed(),
    ])
    .await?;

    Ok(())
}
