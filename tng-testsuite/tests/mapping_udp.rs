use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{
    run_test,
    task::{app::AppType, tng::TngInstance, Task as _},
};

/// Basic UDP datagram forwarding through ingress->egress tunnel with no RA
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_mapping_udp_basic() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
        {
            "add_egress": [
                {
                    "mapping_udp": {
                        "in": {
                            "host": "0.0.0.0",
                            "port": 20001
                        },
                        "out": {
                            "host": "127.0.0.1",
                            "port": 30001
                        }
                    },
                    "quic": {
                        "max_datagram_size": 1200
                    },
                    "no_ra": true
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
                    "mapping_udp": {
                        "in": {
                            "port": 10001
                        },
                        "out": {
                            "host": "192.168.1.1",
                            "port": 20001
                        },
                        "idle_timeout_secs": 30
                    },
                    "quic": {
                        "max_datagram_size": 1200
                    },
                    "no_ra": true
                }
            ]
        }
        "#,
        )
        .boxed(),
        AppType::UdpServer { port: 30001 }.boxed(),
        AppType::UdpClient {
            host: "127.0.0.1",
            port: 10001,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

/// UDP datagram forwarding with one-way RA: egress attests, ingress verifies
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_mapping_udp_one_way_ra() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
        {
            "add_egress": [
                {
                    "mapping_udp": {
                        "in": {
                            "host": "0.0.0.0",
                            "port": 20001
                        },
                        "out": {
                            "host": "127.0.0.1",
                            "port": 30001
                        }
                    },
                    "attest": {
                        "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
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
                    "mapping_udp": {
                        "in": {
                            "port": 10001
                        },
                        "out": {
                            "host": "192.168.1.1",
                            "port": 20001
                        },
                        "idle_timeout_secs": 30
                    },
                    "verify": {
                        "as_addr": "http://192.168.1.254:8080/",
                        "policy_ids": [
                            "default"
                        ]
                    }
                }
            ]
        }
        "#,
        )
        .boxed(),
        AppType::UdpServer { port: 30001 }.boxed(),
        AppType::UdpClient {
            host: "127.0.0.1",
            port: 10001,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

/// UDP datagram forwarding with two-way RA: both sides attest and verify
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_mapping_udp_two_way_ra() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
        {
            "add_egress": [
                {
                    "mapping_udp": {
                        "in": {
                            "host": "0.0.0.0",
                            "port": 20004
                        },
                        "out": {
                            "host": "127.0.0.1",
                            "port": 30004
                        }
                    },
                    "attest": {
                        "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                    },
                    "verify": {
                        "as_addr": "http://192.168.1.254:8080/",
                        "policy_ids": [
                            "default"
                        ]
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
                    "mapping_udp": {
                        "in": {
                            "port": 10004
                        },
                        "out": {
                            "host": "192.168.1.1",
                            "port": 20004
                        },
                        "idle_timeout_secs": 30
                    },
                    "attest": {
                        "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                    },
                    "verify": {
                        "as_addr": "http://192.168.1.254:8080/",
                        "policy_ids": [
                            "default"
                        ]
                    }
                }
            ]
        }
        "#,
        )
        .boxed(),
        AppType::UdpServer { port: 30004 }.boxed(),
        AppType::UdpClient {
            host: "127.0.0.1",
            port: 10004,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

/// UDP forwarding without explicit quic config — uses default max_datagram_size
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_mapping_udp_default_quic_config() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
        {
            "add_egress": [
                {
                    "mapping_udp": {
                        "in": {
                            "host": "0.0.0.0",
                            "port": 20002
                        },
                        "out": {
                            "host": "127.0.0.1",
                            "port": 30002
                        }
                    },
                    "no_ra": true
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
                    "mapping_udp": {
                        "in": {
                            "port": 10002
                        },
                        "out": {
                            "host": "192.168.1.1",
                            "port": 20002
                        }
                    },
                    "no_ra": true
                }
            ]
        }
        "#,
        )
        .boxed(),
        AppType::UdpServer { port: 30002 }.boxed(),
        AppType::UdpClient {
            host: "127.0.0.1",
            port: 10002,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

/// UDP forwarding with default idle_timeout_secs — smoke test that the config is accepted
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_mapping_udp_with_default_idle_timeout() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
        {
            "add_egress": [
                {
                    "mapping_udp": {
                        "in": {
                            "host": "0.0.0.0",
                            "port": 20003
                        },
                        "out": {
                            "host": "127.0.0.1",
                            "port": 30003
                        }
                    },
                    "no_ra": true
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
                    "mapping_udp": {
                        "in": {
                            "port": 10003
                        },
                        "out": {
                            "host": "192.168.1.1",
                            "port": 20003
                        }
                    },
                    "no_ra": true
                }
            ]
        }
        "#,
        )
        .boxed(),
        AppType::UdpServer { port: 30003 }.boxed(),
        AppType::UdpClient {
            host: "127.0.0.1",
            port: 10003,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

/// Multiple UDP mapping rules — verify TNG can host multiple egress/ingress rules.
/// Tests one tunnel (rule 1) at a time to avoid race conditions between QUIC
/// connection setup and UDP server startup.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_mapping_udp_multi_rule() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
        {
            "add_egress": [
                {
                    "mapping_udp": {
                        "in": {
                            "host": "0.0.0.0",
                            "port": 20011
                        },
                        "out": {
                            "host": "127.0.0.1",
                            "port": 30011
                        }
                    },
                    "quic": {
                        "max_datagram_size": 1200
                    },
                    "no_ra": true
                },
                {
                    "mapping_udp": {
                        "in": {
                            "host": "0.0.0.0",
                            "port": 20012
                        },
                        "out": {
                            "host": "127.0.0.1",
                            "port": 30012
                        }
                    },
                    "quic": {
                        "max_datagram_size": 1200
                    },
                    "no_ra": true
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
                    "mapping_udp": {
                        "in": {
                            "port": 10011
                        },
                        "out": {
                            "host": "192.168.1.1",
                            "port": 20011
                        },
                        "idle_timeout_secs": 30
                    },
                    "quic": {
                        "max_datagram_size": 1200
                    },
                    "no_ra": true
                },
                {
                    "mapping_udp": {
                        "in": {
                            "port": 10012
                        },
                        "out": {
                            "host": "192.168.1.1",
                            "port": 20012
                        },
                        "idle_timeout_secs": 30
                    },
                    "quic": {
                        "max_datagram_size": 1200
                    },
                    "no_ra": true
                }
            ]
        }
        "#,
        )
        .boxed(),
        AppType::UdpServer { port: 30011 }.boxed(),
        AppType::UdpClient {
            host: "127.0.0.1",
            port: 10011,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

/// Second multi-rule test — verifies the second tunnel path works independently.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_mapping_udp_multi_rule_second_path() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
        {
            "add_egress": [
                {
                    "mapping_udp": {
                        "in": {
                            "host": "0.0.0.0",
                            "port": 20013
                        },
                        "out": {
                            "host": "127.0.0.1",
                            "port": 30013
                        }
                    },
                    "quic": {
                        "max_datagram_size": 1200
                    },
                    "no_ra": true
                },
                {
                    "mapping_udp": {
                        "in": {
                            "host": "0.0.0.0",
                            "port": 20014
                        },
                        "out": {
                            "host": "127.0.0.1",
                            "port": 30014
                        }
                    },
                    "quic": {
                        "max_datagram_size": 1200
                    },
                    "no_ra": true
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
                    "mapping_udp": {
                        "in": {
                            "port": 10013
                        },
                        "out": {
                            "host": "192.168.1.1",
                            "port": 20013
                        },
                        "idle_timeout_secs": 30
                    },
                    "quic": {
                        "max_datagram_size": 1200
                    },
                    "no_ra": true
                },
                {
                    "mapping_udp": {
                        "in": {
                            "port": 10014
                        },
                        "out": {
                            "host": "192.168.1.1",
                            "port": 20014
                        },
                        "idle_timeout_secs": 30
                    },
                    "quic": {
                        "max_datagram_size": 1200
                    },
                    "no_ra": true
                }
            ]
        }
        "#,
        )
        .boxed(),
        AppType::UdpServer { port: 30014 }.boxed(),
        AppType::UdpClient {
            host: "127.0.0.1",
            port: 10014,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

/// UDP forwarding with short idle_timeout_secs — smoke test that the config is accepted
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_mapping_udp_short_idle_timeout() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
        {
            "add_egress": [
                {
                    "mapping_udp": {
                        "in": {
                            "host": "0.0.0.0",
                            "port": 20021
                        },
                        "out": {
                            "host": "127.0.0.1",
                            "port": 30021
                        },
                        "idle_timeout_secs": 10
                    },
                    "quic": {
                        "max_datagram_size": 1200
                    },
                    "no_ra": true
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
                    "mapping_udp": {
                        "in": {
                            "port": 10021
                        },
                        "out": {
                            "host": "192.168.1.1",
                            "port": 20021
                        },
                        "idle_timeout_secs": 10
                    },
                    "quic": {
                        "max_datagram_size": 1200
                    },
                    "no_ra": true
                }
            ]
        }
        "#,
        )
        .boxed(),
        AppType::UdpServer { port: 30021 }.boxed(),
        AppType::UdpClient {
            host: "127.0.0.1",
            port: 10021,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}
