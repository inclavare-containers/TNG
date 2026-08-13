use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{
    run_test,
    task::{
        app::AppType,
        shell::{ShellMode, ShellTask},
        tng::TngInstance,
        NodeType, Task as _,
    },
};

fn tng_server() -> TngInstance {
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
                    "attest": {
                        "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                    }
                }
            ]
        }
        "#,
    )
}

fn tng_client_no_auth() -> TngInstance {
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
}

fn tng_client_password_auth() -> TngInstance {
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
}

fn tng_client_dst_filters() -> TngInstance {
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
                                "ip": "192.168.1.1",
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
}

fn http_server(port: u16) -> AppType {
    AppType::HttpServer {
        port,
        expected_host_header: "example.com",
        expected_path_and_query: "/foo/bar/www?type=1&case=1",
    }
}

fn curl_via_socks5(script: &str) -> ShellTask {
    ShellTask {
        name: "curl_via_socks5".to_owned(),
        node_type: NodeType::Client,
        script: script.to_owned(),
        mode: ShellMode::ForegroundStop,
    }
}

fn assert_curl_body(command: &str) -> String {
    format!(
        r#"
            body=$({command})
            if [ "$body" != "Hello World HTTP!" ]; then
                echo "unexpected curl response body: $body" >&2
                exit 1
            fi
        "#
    )
}

#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn socks5_no_auth() -> Result<()> {
    run_test!(vec![
        tng_server().boxed(),
        tng_client_no_auth().boxed(),
        http_server(30001).boxed(),
        curl_via_socks5(&assert_curl_body(
            r#"curl -sS --socks5 127.0.0.1:1080 -H "Host: example.com" "http://192.168.1.1:30001/foo/bar/www?type=1&case=1""#
        ))
        .boxed(),
    ])
    .await
}

#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn socks5_password_auth() -> Result<()> {
    run_test!(vec![
        tng_server().boxed(),
        tng_client_password_auth().boxed(),
        http_server(30001).boxed(),
        curl_via_socks5(&assert_curl_body(
            r#"curl -sS --socks5 user:ppppppwd@127.0.0.1:1080 --socks5-basic -H "Host: example.com" "http://192.168.1.1:30001/foo/bar/www?type=1&case=1""#
        ))
        .boxed(),
    ])
    .await
}

#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn socks5_wrong_password_then_correct_password() -> Result<()> {
    run_test!(vec![
        tng_server().boxed(),
        tng_client_password_auth().boxed(),
        http_server(30001).boxed(),
        curl_via_socks5(&format!(
            r#"
                if curl --socks5 user:wrong_passwd@127.0.0.1:1080 --socks5-basic -H "Host: example.com" "http://192.168.1.1:30001/foo/bar/www?type=1&case=1" ; then
                    echo "curl should fail due to wrong password"
                    exit 1
                fi

                {}
            "#,
            assert_curl_body(
                r#"curl -sS --socks5 user:ppppppwd@127.0.0.1:1080 --socks5-basic -H "Host: example.com" "http://192.168.1.1:30001/foo/bar/www?type=1&case=1""#
            )
        ))
        .boxed(),
    ])
    .await
}

#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn socks5_dst_filters() -> Result<()> {
    run_test!(vec![
        tng_server().boxed(),
        tng_client_dst_filters().boxed(),
        http_server(30001).boxed(),
        http_server(40001).boxed(),
        curl_via_socks5(&format!(
            r#"
                {}
                {}
            "#,
            assert_curl_body(
                r#"curl -sS --socks5 127.0.0.1:1080 -H "Host: example.com" "http://192.168.1.1:30001/foo/bar/www?type=1&case=1""#
            ),
            assert_curl_body(
                r#"curl -sS --socks5 127.0.0.1:1080 -H "Host: example.com" "http://192.168.1.1:40001/foo/bar/www?type=1&case=1""#
            )
        ))
        .boxed(),
    ])
    .await
}
