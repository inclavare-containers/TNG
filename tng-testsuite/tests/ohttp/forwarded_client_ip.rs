use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{
    run_test,
    task::{app::AppType, tng::TngInstance, Task as _},
};

/// The egress's direct TCP peer in the test netns is the client node
/// (NodeType::Client = 192.168.1.253). The injected X-Real-IP / X-Forwarded-For
/// must carry that address to the upstream backend.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_egress_ohttp_injects_forwarded_client_ip() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
            {
                "add_egress": [
                    {
                        "netfilter": {
                            "capture_dst": { "port": 30001 }
                        },
                        "ohttp": {},
                        "attest": {
                            "model": "passport",
                            "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
                            "as_addr": "http://192.168.1.254:8080/",
                            "policy_ids": ["default"]
                        }
                    }
                ]
            }
            "#,
        )
        .boxed(),
        TngInstance::TngClient(
            r#"
            {
                "add_ingress": [
                    {
                        "netfilter": {
                            "capture_dst": { "port": 30001 }
                        },
                        "ohttp": {},
                        "verify": {
                            "model": "passport",
                            "as_addr": "http://192.168.1.254:8080/",
                            "policy_ids": ["default"]
                        }
                    }
                ]
            }
            "#,
        )
        .boxed(),
        AppType::HttpServerWithHeaders {
            port: 30001,
            expected_host_header: "example.com",
            expected_path_and_query: "/forwarded/test",
            expected_request_headers: vec![
                ("x-real-ip", "192.168.1.253"),
                ("x-forwarded-for", "192.168.1.253"),
            ],
        }
        .boxed(),
        AppType::HttpClient {
            host: "192.168.1.1",
            port: 30001,
            host_header: "example.com",
            path_and_query: "/forwarded/test",
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}
