use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{
    run_test,
    task::{app::AppType, tng::TngInstance, Task as _},
};

/// The standalone `verify()` wasm export runs the ohttp key-config handshake
/// and reports the verification info WITHOUT sending any inner HTTP request.
/// These tests are the integration coverage for that export (the fetch-driven
/// `js_sdk_http` / `js_sdk_builtin_as` harnesses only exercise `tng_fetch`).
///
/// The SDK module is re-imported inside each JS block via
/// `window.location.origin` (the page already sits on
/// `http://127.0.0.1:<port>/tng_wasm.js`, served by the harness's static file
/// server); the harness's own `load_sdk` line only binds `tng_init`/`tng_fetch`,
/// and the module cache means this yields the same already-initialized instance.

/// NoRa mode: `verify_endpoint` returns `None` (no verification configured)
/// and `verify()` surfaces that as `verified: false` with the token/claims/exp
/// fields absent, instead of failing the way `tng_fetch` does on a missing
/// attestation result. The egress runs NoRa too, so no AA/AS services are
/// needed, and since no inner request is forwarded there is no backend server.
#[cfg(feature = "js-sdk")]
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn verify_no_ra_reports_unverified() -> Result<()> {
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
                        "no_ra": true
                    }
                ]
            }
            "#,
        ).boxed(),
        AppType::BrowserClient {
            js: r#"
                await tng_init();
                const { verify: tng_verify } = await import(`${window.location.origin}/tng_wasm.js`);

                const config = {
                    ohttp: {},
                    no_ra: true
                };

                // NoRa must not bail the way fetch does: the call resolves and
                // reports verified=false with no token/claims/exp.
                const info = await tng_verify("http://192.168.1.1:30001/foo/bar/www?type=1&case=1", config);
                if (typeof info !== 'object' || info === null ||
                        Object.getPrototypeOf(info) !== Object.prototype) {
                    throw new Error(`verify() should resolve to a plain object, got ${info && info.constructor && info.constructor.name}`);
                }
                if (info.verified !== false) {
                    throw new Error(`NoRa verify should report verified=false, got ${info.verified}`);
                }
                if (info.endpoint !== '192.168.1.1:30001') {
                    throw new Error(`expected endpoint='192.168.1.1:30001', got '${info.endpoint}'`);
                }
                for (const field of ['token', 'claims', 'exp']) {
                    if (info[field] != null) {
                        throw new Error(`NoRa verify should leave ${field} absent, got ${JSON.stringify(info[field])}`);
                    }
                }
                // The NoRa summary carries no AS address or provider either.
                if (info.as_addr != null) {
                    throw new Error(`NoRa verify should have no as_addr, got '${info.as_addr}'`);
                }
            "#
        }.boxed(),
    ])
    .await?;

    Ok(())
}

/// Positive path with the builtin AS: the browser-side `verify` config runs the
/// attestation service in-process inside the wasm SDK (`as_type: "builtin"`,
/// `trust_all`), so `verify()` reports `verified: true` with a token, decoded
/// claims, and a numeric expiry. Mirrors `js_sdk_builtin_as`'s egress exactly:
/// the egress attests via the remote Attestation Agent (`make test-dep-aa`);
/// no external AS is contacted.
#[cfg(feature = "js-sdk")]
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn verify_builtin_as_reports_verified() -> Result<()> {
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
        AppType::BrowserClient {
            js: r#"
                await tng_init();
                const { verify: tng_verify } = await import(`${window.location.origin}/tng_wasm.js`);

                const config = {
                    ohttp: {},
                    verify: {
                        model: "background_check",
                        as_type: "builtin",
                        attestation_policy: {
                            type: "trust_all"
                        },
                        reference_values: []
                    }
                };

                const info = await tng_verify("http://192.168.1.1:30001/foo/bar/www?type=1&case=1", config);
                if (typeof info !== 'object' || info === null ||
                        Object.getPrototypeOf(info) !== Object.prototype) {
                    throw new Error(`verify() should resolve to a plain object, got ${info && info.constructor && info.constructor.name}`);
                }
                if (info.verified !== true) {
                    throw new Error(`builtin-as verify should report verified=true, got ${info.verified}`);
                }
                if (typeof info.token !== 'string' || info.token.length === 0) {
                    throw new Error(`expected a non-empty token string, got ${JSON.stringify(info.token)}`);
                }
                if (typeof info.claims !== 'object' || info.claims === null ||
                        Object.keys(info.claims).length === 0) {
                    throw new Error(`expected a non-empty claims object, got ${JSON.stringify(info.claims)}`);
                }
                if (typeof info.exp !== 'number' || !Number.isFinite(info.exp) || info.exp <= 0) {
                    throw new Error(`expected a positive numeric exp, got ${JSON.stringify(info.exp)}`);
                }
            "#
        }.boxed(),
    ])
    .await?;

    Ok(())
}
