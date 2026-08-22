use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{
    run_test,
    task::{app::AppType, tng::TngInstance, Task as _},
};

/// Common topology for the egress-only tests below:
///   Client node (192.168.1.253): TNG Client (ingress mapping_udp) + UdpClient
///   Server node (192.168.1.1):   TNG Server (egress netfilter_udp) + UdpServer
///
/// Data flow:
///   UdpClient → 127.0.0.1:1000x (ingress mapping_udp, client node)
///     → QUIC datagram tunnel → 192.168.1.1:3000x (egress capture_dst, server node)
///     → egress TPROXY intercepts, orig_dst = 192.168.1.1:3000x
///     → egress forwards UDP → 192.168.1.1:3000x (UdpServer, server node)
///
/// The QUIC tunnel targets the capture_dst port (the real backend), so the
/// egress derives the backend address directly from IP_ORIGDSTADDR — no
/// `backend` override and no fixed `listen_port` are needed (the listener
/// picks a free, non-overlapping port at random).
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_egress_netfilter_udp_basic() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
        {
            "add_egress": [
                {
                    "netfilter_udp": {
                        "capture_dst": [
                            { "host": "192.168.1.1", "port": 30001 }
                        ],
                        "capture_local_traffic": true
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
                            "port": 30001
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

/// Egress netfilter_udp with port range capture
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_egress_netfilter_udp_port_range() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
        {
            "add_egress": [
                {
                    "netfilter_udp": {
                        "capture_dst": [
                            { "host": "192.168.1.1", "port": 30010, "port_end": 30020 }
                        ],
                        "capture_local_traffic": true
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
                            "port": 10010
                        },
                        "out": {
                            "host": "192.168.1.1",
                            "port": 30015
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
        AppType::UdpServer { port: 30015 }.boxed(),
        AppType::UdpClient {
            host: "127.0.0.1",
            port: 10010,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

/// Egress netfilter_udp with custom max_datagram_size
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_egress_netfilter_udp_datagram_size() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
        {
            "add_egress": [
                {
                    "netfilter_udp": {
                        "capture_dst": [
                            { "host": "192.168.1.1", "port": 30041 }
                        ],
                        "capture_local_traffic": true
                    },
                    "quic": {
                        "max_datagram_size": 1400
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
                            "port": 10041
                        },
                        "out": {
                            "host": "192.168.1.1",
                            "port": 30041
                        }
                    },
                    "quic": {
                        "max_datagram_size": 1400
                    },
                    "no_ra": true
                }
            ]
        }
        "#,
        )
        .boxed(),
        AppType::UdpServer { port: 30041 }.boxed(),
        AppType::UdpClient {
            host: "127.0.0.1",
            port: 10041,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

/// Egress netfilter_udp without explicit capture_dst (capture all UDP)
///
/// Uses the default `capture_local_traffic: false`. With the `! --src-type
/// LOCAL` filter, the co-located backend's forward/reply traffic (source IP is
/// local) is exempted from the catch-all TPROXY rule, while the remote
/// client's QUIC tunnel packets are still captured. Setting
/// `capture_local_traffic: true` here would re-capture the backend's reply
/// into the QUIC listener (silently dropped), breaking the round-trip — see
/// the warn emitted by the egress when that combo is configured.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_egress_netfilter_udp_capture_all() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
        {
            "add_egress": [
                {
                    "netfilter_udp": {},
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
                            "port": 10051
                        },
                        "out": {
                            "host": "192.168.1.1",
                            "port": 30051
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
        AppType::UdpServer { port: 30051 }.boxed(),
        AppType::UdpClient {
            host: "127.0.0.1",
            port: 10051,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

/// Mixed direction: ingress netfilter_udp (client) + egress mapping_udp (server).
///
///   Client node (192.168.1.253): TNG Client (ingress netfilter_udp) + UdpClient
///   Server node (192.168.1.1):   TNG Server (egress mapping_udp) + UdpServer
///
/// Data flow:
///   UdpClient → 192.168.1.1:20071 (captured by ingress TPROXY on the client)
///     → ingress orig_dst = 192.168.1.1:20071
///     → ingress QUIC tunnel (SO_MARK bypasses the client's own OUTPUT capture)
///       → 192.168.1.1:20071 (egress mapping_udp `in` listener, server node)
///     → egress forwards UDP → 127.0.0.1:30071 (UdpServer, server node)
///
/// Unlike the egress-netfilter topology, the egress side is a fixed mapping
/// listener: the QUIC tunnel targets the egress `in` port, which the ingress
/// derives from the captured original destination. So `capture_dst` must
/// exactly name the egress `in` address (host + port).
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ingress_netfilter_egress_mapping_basic() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
        {
            "add_egress": [
                {
                    "mapping_udp": {
                        "in": {
                            "host": "0.0.0.0",
                            "port": 20071
                        },
                        "out": {
                            "host": "127.0.0.1",
                            "port": 30071
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
                    "netfilter_udp": {
                        "capture_dst": [
                            { "host": "192.168.1.1", "port": 20071 }
                        ]
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
        AppType::UdpServer { port: 30071 }.boxed(),
        AppType::UdpClient {
            host: "192.168.1.1",
            port: 20071,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

/// Mixed direction with an ingress port-range capture. The ingress captures a
/// range of destination ports; the egress mapping_udp `in` port must fall inside
/// that range so the captured original destination routes to the egress listener.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ingress_netfilter_egress_mapping_port_range() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
        {
            "add_egress": [
                {
                    "mapping_udp": {
                        "in": {
                            "host": "0.0.0.0",
                            "port": 20085
                        },
                        "out": {
                            "host": "127.0.0.1",
                            "port": 30085
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
                    "netfilter_udp": {
                        "capture_dst": [
                            { "host": "192.168.1.1", "port": 20080, "port_end": 20090 }
                        ]
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
        AppType::UdpServer { port: 30085 }.boxed(),
        AppType::UdpClient {
            host: "192.168.1.1",
            port: 20085,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}

/// Full ingress+egress netfilter_udp on a single machine (both sides TPROXY).
///
///   Client node (192.168.1.253): TNG Client (ingress netfilter_udp) + UdpClient
///   Server node (192.168.1.1):   TNG Server (egress netfilter_udp) + UdpServer
///
/// Data flow:
///   UdpClient → 192.168.1.1:30061 (captured by ingress TPROXY on the client)
///     → ingress orig_dst = 192.168.1.1:30061
///     → ingress QUIC tunnel (SO_MARK bypasses the client's own OUTPUT capture)
///       → 192.168.1.1:30061 (captured by egress TPROXY on the server)
///     → egress orig_dst = 192.168.1.1:30061
///     → egress forwards UDP → 192.168.1.1:30061 (UdpServer, server node)
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_netfilter_udp_full_path() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
        {
            "add_egress": [
                {
                    "netfilter_udp": {
                        "capture_dst": [
                            { "host": "192.168.1.1", "port": 30061 }
                        ],
                        "capture_local_traffic": true
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
                    "netfilter_udp": {
                        "capture_dst": [
                            { "host": "192.168.1.1", "port": 30061 }
                        ]
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
        AppType::UdpServer { port: 30061 }.boxed(),
        AppType::UdpClient {
            host: "192.168.1.1",
            port: 30061,
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}
