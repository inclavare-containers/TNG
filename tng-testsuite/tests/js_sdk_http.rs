use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{
    run_test,
    task::{app::AppType, tng::TngInstance, Task as _},
};

#[cfg(feature = "js-sdk")]
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn server_background_check() -> Result<()> {
    run_test(vec![
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
                        as_addr: "http://192.168.1.254:8080/",
                        policy_ids: [
                            "default"
                        ]
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
                    await common_check_response(response, false);
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
                    await common_check_response(response, false);
                }
            "#
        }.boxed(),
    ])
    .await?;

    Ok(())
}

#[cfg(feature = "js-sdk")]
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn server_passport() -> Result<()> {
    run_test(vec![
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
                        model: "passport",
                        policy_ids: ["default"]
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
                    await common_check_response(response, true);
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
                    await common_check_response(response, true);
                }
            "#
        }.boxed(),
    ])
    .await?;

    Ok(())
}
