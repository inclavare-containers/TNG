use serial_test::serial;
use tng_testsuite::{
    run_test,
    task::{app::AppType, tng::TngInstance, Task},
};

// =============================================================================
// Client Auth Mode (HPKE Auth) Integration Tests
//
// These tests verify the HPKE Auth Mode path where:
// 1. Client generates X25519 key pair and embeds public key in attestation token
// 2. Client uses HPKE Auth encapsulation (sender authenticated via sk_s)
// 3. Server extracts client pk from attestation, uses Auth decapsulation
// 4. The HPKE shared secret is derived with both parties' keys in the KDF
//
// This is distinct from Base Mode tests where client_key is unused.
// =============================================================================

/// Test: Client attest (passport) + Server verify (passport) via netfilter.
/// This is the primary Auth Mode integration test — both sides use RA,
/// the client's HPKE Auth encapsulation must succeed for the tunnel to work.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ohttp_client_auth_mode_passport() -> anyhow::Result<()> {
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
            "#,
        ).boxed(),
        TngInstance::TngClient(
            r#"
            {
                "add_ingress": [
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
            expected_host_header: "example.com",
            expected_path_and_query: "/auth-mode/test?query=1",
        }.boxed(),
        AppType::HttpClient {
            host: "192.168.1.1",
            port: 30001,
            host_header: "example.com",
            path_and_query: "/auth-mode/test?query=1",
        }.boxed(),
    ])
    .await?;

    Ok(())
}

/// Test: Client attest (background_check) + Server verify (background_check) via netfilter.
/// Covers Auth Mode in netfilter capture mode with background_check RA model.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ohttp_client_auth_mode_background_check() -> anyhow::Result<()> {
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
                        "verify": {
                            "model": "background_check",
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
        TngInstance::TngClient(
            r#"
            {
                "add_ingress": [
                    {
                        "netfilter": {
                            "capture_dst": {
                                "port": 30001
                            }
                        },
                        "ohttp": {},
                        "attest": {
                            "model": "background_check",
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
            expected_host_header: "example.com",
            expected_path_and_query: "/auth-mode/bg-check",
        }.boxed(),
        AppType::HttpClient {
            host: "192.168.1.1",
            port: 30001,
            host_header: "example.com",
            path_and_query: "/auth-mode/bg-check",
        }.boxed(),
    ])
    .await?;

    Ok(())
}

/// Test: Client attest (passport) + Server verify (passport) with path rewrites.
/// Covers Auth Mode with OHTTP path_rewrites on the client side.
/// Note: path_rewrites only apply in mapping mode, not netfilter mode.
/// In netfilter mode the full original HTTP request is encapsulated.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ohttp_client_auth_mode_path_rewrite() -> anyhow::Result<()> {
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
            "#,
        ).boxed(),
        TngInstance::TngClient(
            r#"
            {
                "add_ingress": [
                    {
                        "netfilter": {
                            "capture_dst": {
                                "port": 30001
                            }
                        },
                        "ohttp": {
                            "path_rewrites": [
                                {
                                    "match_regex": "^/api/(.*)$",
                                    "substitution": "/resource/\\1"
                                }
                            ]
                        },
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
            expected_host_header: "auth.example.com",
            expected_path_and_query: "/api/data?detail=true",
        }.boxed(),
        AppType::HttpClient {
            host: "192.168.1.1",
            port: 30001,
            host_header: "auth.example.com",
            path_and_query: "/api/data?detail=true",
        }.boxed(),
    ])
    .await?;

    Ok(())
}
