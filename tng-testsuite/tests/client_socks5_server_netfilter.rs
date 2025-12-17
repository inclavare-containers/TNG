use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{
    run_test,
    task::{app::AppType, shell::ShellTask, tng::TngInstance, NodeType, Task as _},
};

#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test() -> Result<()> {
    let tng_server = TngInstance::TngServer(
        r#"
        {
            "add_egress": [
                {
                    "netfilter": {
                        "capture_dst": {
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
    );

    // Test socks5 with no auth requirement
    run_test(vec![
        tng_server.clone().boxed(),
        TngInstance::TngClient(
            r#"
                {
                    "add_ingress": [
                        {
                            "socks5": {
                                "proxy_listen": {
                                    "host": "0.0.0.0",
                                    "port": 1080
                                }
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
        AppType::HttpServer {
            port: 30001,
            expected_host_header: "example.com",
            expected_path_and_query: "/foo/bar/www?type=1&case=1",
        }
        .boxed(),
        ShellTask {
            name: "curl_via_socks5".to_owned(),
            node_type: NodeType::Client,
            script: r#"
                curl --socks5 127.0.0.1:1080 -H "Host: example.com" "http://192.168.1.1:30001/foo/bar/www?type=1&case=1"
            "#
            .to_owned(),
            stop_test_on_finish: true,
            run_in_foreground: false,
        }
        .boxed(),
    ])
    .await?;

    // Test socks5 with password auth
    run_test(vec![
        tng_server.clone().boxed(),
        TngInstance::TngClient(
            r#"
                {
                    "add_ingress": [
                        {
                            "socks5": {
                                "proxy_listen": {
                                    "host": "0.0.0.0",
                                    "port": 1080
                                },
                                "auth": {
                                    "username": "user",
                                    "password": "ppppppwd"
                                }
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
        AppType::HttpServer {
            port: 30001,
            expected_host_header: "example.com",
            expected_path_and_query: "/foo/bar/www?type=1&case=1",
        }
        .boxed(),
        ShellTask {
            name: "curl_via_socks5".to_owned(),
            node_type: NodeType::Client,
            script: r#"
                curl --socks5 user:ppppppwd@127.0.0.1:1080 --socks5-basic -H "Host: example.com" "http://192.168.1.1:30001/foo/bar/www?type=1&case=1"
            "#
            .to_owned(),
            stop_test_on_finish: true,
            run_in_foreground: false,
        }
        .boxed(),
    ])
    .await?;

    // Test socks5 with wrong password
    run_test(vec![
        tng_server.clone().boxed(),
        TngInstance::TngClient(
            r#"
                {
                    "add_ingress": [
                        {
                            "socks5": {
                                "proxy_listen": {
                                    "host": "0.0.0.0",
                                    "port": 1080
                                },
                                "auth": {
                                    "username": "user",
                                    "password": "ppppppwd"
                                }
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
        AppType::HttpServer {
            port: 30001,
            expected_host_header: "example.com",
            expected_path_and_query: "/foo/bar/www?type=1&case=1",
        }
        .boxed(),
        ShellTask {
            name: "curl_via_socks5".to_owned(),
            node_type: NodeType::Client,
            script: r#"
                if curl --socks5 user:wrong_passwd@127.0.0.1:1080 --socks5-basic -H "Host: example.com" "http://192.168.1.1:30001/foo/bar/www?type=1&case=1" ; then
                    echo "curl should fail due to wrong password"
                    exit 1
                fi

                # Let's try again with the correct password
                curl --socks5 user:ppppppwd@127.0.0.1:1080 --socks5-basic -H "Host: example.com" "http://192.168.1.1:30001/foo/bar/www?type=1&case=1"
            "#
            .to_owned(),
            stop_test_on_finish: true,
            run_in_foreground: false,

        }
        .boxed(),
    ])
    .await?;

    // Test socks5 with dst_filters
    run_test(vec![
        tng_server.clone().boxed(),
        TngInstance::TngClient(
            r#"
                {
                    "add_ingress": [
                        {
                            "socks5": {
                                "proxy_listen": {
                                    "host": "0.0.0.0",
                                    "port": 1080
                                },
                                "dst_filters": [
                                    {
                                        "domain": "192.168.1.1",
                                        "port": 30001
                                    }
                                ]
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
        AppType::HttpServer {
            port: 30001,
            expected_host_header: "example.com",
            expected_path_and_query: "/foo/bar/www?type=1&case=1",
        }
        .boxed(),
        AppType::HttpServer {
            port: 40001,
            expected_host_header: "example.com",
            expected_path_and_query: "/foo/bar/www?type=1&case=1",
        }
        .boxed(),
        ShellTask {
            name: "curl_via_socks5".to_owned(),
            node_type: NodeType::Client,
            script: r#"
                curl --socks5 127.0.0.1:1080 -H "Host: example.com" "http://192.168.1.1:30001/foo/bar/www?type=1&case=1"
                curl --socks5 127.0.0.1:1080 -H "Host: example.com" "http://192.168.1.1:40001/foo/bar/www?type=1&case=1"
            "#
            .to_owned(),
            stop_test_on_finish: true,
            run_in_foreground: false,
        }
        .boxed(),
    ])
    .await?;
    Ok(())
}
