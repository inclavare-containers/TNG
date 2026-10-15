use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context as _, Result};
use serial_test::serial;
use tng_testsuite::{
    run_test,
    task::{app::AppType, function::FunctionTask, tng::TngInstance, NodeType, Task as _},
};
use tokio_util::sync::CancellationToken;

/// REST control-interface port for the ingress under test. The tests are
/// `#[serial]` and each `run_test!` gets its own network namespace, so one
/// port serves all three.
const CONTROL_PORT: u16 = 18081;

const EGRESS: &str = r#"
{
    "add_egress": [
        {
            "mapping": {
                "in": { "host": "0.0.0.0", "port": 20001 },
                "out": { "host": "127.0.0.1", "port": 30001 }
            },
            "no_ra": true,
            "rats_tls": { "multiplex": true }
        }
    ]
}
"#;

const INGRESS_SHARDED: &str = r#"
{
    "control_interface": {
        "restful": { "host": "127.0.0.1", "port": 18081 }
    },
    "add_ingress": [
        {
            "mapping": {
                "in": { "port": 10001 },
                "out": { "host": "192.168.1.1", "port": 20001 }
            },
            "no_ra": true,
            "rats_tls": {
                "multiplex": true,
                "multiplex_max_streams_per_connection": 1,
                "multiplex_max_connections": 5
            }
        }
    ]
}
"#;

const INGRESS_SINGLE: &str = r#"
{
    "control_interface": {
        "restful": { "host": "127.0.0.1", "port": 18081 }
    },
    "add_ingress": [
        {
            "mapping": {
                "in": { "port": 10001 },
                "out": { "host": "192.168.1.1", "port": 20001 }
            },
            "no_ra": true,
            "rats_tls": { "multiplex": true }
        }
    ]
}
"#;

const INGRESS_TUNNEL_BOUND: &str = r#"
{
    "control_interface": {
        "restful": { "host": "127.0.0.1", "port": 18081 }
    },
    "add_ingress": [
        {
            "mapping": {
                "in": { "port": 10001 },
                "out": { "host": "192.168.1.1", "port": 20001 }
            },
            "no_ra": true,
            "rats_tls": {
                "multiplex": true,
                "multiplex_max_streams_per_connection": 1,
                "multiplex_max_connections": 2
            }
        }
    ]
}
"#;

/// Hold `count` downstream connections open so all of their mux stream
/// allocations are concurrently active on the ingress side, query the pool
/// status through the control interface while they are held, and store the
/// JSON for the test to assert on. Asserting on the status API (instead of
/// counting in-process log lines) keeps the test valid in both CI modes:
/// `on-source-code` runs TNG in-process, `on-bin` runs it as an external
/// binary whose logs never reach this process.
fn hold_streams_and_query_pool(
    count: usize,
) -> (FunctionTask, Arc<Mutex<Option<serde_json::Value>>>) {
    let status = Arc::new(Mutex::new(None));
    let status_slot = status.clone();
    let task = FunctionTask {
        name: "hold_streams".to_owned(),
        node_type: NodeType::Client,
        func: Box::new(move |token: CancellationToken| {
            let status_slot = status_slot.clone();
            Ok(tokio::spawn(async move {
                let _drop_guard = token.drop_guard();
                let mut conns = Vec::new();
                for i in 0..count {
                    let stream = tokio::net::TcpStream::connect("127.0.0.1:10001")
                        .await
                        .with_context(|| format!("connect {i}"))?;
                    conns.push(stream);
                }
                // Give every accepted connection time to complete its CONNECT
                // allocation before the pool state is sampled.
                tokio::time::sleep(Duration::from_millis(500)).await;
                let client = reqwest::ClientBuilder::new()
                    .no_proxy()
                    .build()
                    .context("build status-query client")?;
                let value = client
                    .get(format!(
                        "http://127.0.0.1:{CONTROL_PORT}/status/ingress/0/rats_tls/pool"
                    ))
                    .send()
                    .await
                    .context("query mux pool status")?
                    .json::<serde_json::Value>()
                    .await
                    .context("parse mux pool status")?;
                *status_slot.lock().unwrap() = Some(value);
                drop(conns);
                Ok(())
            }))
        }),
    };
    (task, status)
}

/// The single pooled endpoint's entry from the pool status JSON.
fn sole_endpoint(pool: &serde_json::Value) -> &serde_json::Value {
    let endpoints = pool["endpoints"]
        .as_array()
        .expect("pool status must list endpoints");
    assert_eq!(endpoints.len(), 1, "expected exactly one pooled endpoint");
    &endpoints[0]
}

fn shard_active_streams(endpoint: &serde_json::Value) -> Vec<u32> {
    endpoint["shards"]
        .as_array()
        .map(|shards| {
            shards
                .iter()
                .map(|shard| shard["active_streams"].as_u64().unwrap_or(u64::MAX) as u32)
                .collect()
        })
        .unwrap_or_default()
}

/// With multiplex_max_streams_per_connection = 1, five concurrently held
/// downstream connections must each ride its own shard tunnel. The tunnel
/// bound is set explicitly: the unset default derives from the CPU core
/// count, which differs between dev boxes and CI runners and would change
/// how many tunnels five streams can open.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn multiplex_shards_at_stream_cap() -> Result<()> {
    let (hold, status) = hold_streams_and_query_pool(5);
    run_test!(vec![
        TngInstance::TngServer(EGRESS).boxed(),
        TngInstance::TngClient(INGRESS_SHARDED).boxed(),
        AppType::TcpServer { port: 30001 }.boxed(),
        hold.boxed(),
    ])
    .await?;

    let pool = status
        .lock()
        .unwrap()
        .clone()
        .context("the pool status was never queried")?;
    assert_eq!(pool["multiplex"], serde_json::json!(true));
    assert_eq!(
        pool["multiplex_max_streams_per_connection"],
        serde_json::json!(1)
    );
    assert_eq!(pool["overflowed_streams"], serde_json::json!(0));
    let endpoint = sole_endpoint(&pool);
    assert_eq!(endpoint["shard_count"], serde_json::json!(5));
    let actives = shard_active_streams(endpoint);
    assert_eq!(
        actives,
        vec![1, 1, 1, 1, 1],
        "each of the five streams must ride its own tunnel, got {actives:?}"
    );
    Ok(())
}

/// Control for the sharding default: with the field unset, the same five
/// concurrent streams multiplex over a single tunnel, exactly as before the
/// feature existed.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn multiplex_single_tunnel_without_cap() -> Result<()> {
    let (hold, status) = hold_streams_and_query_pool(5);
    run_test!(vec![
        TngInstance::TngServer(EGRESS).boxed(),
        TngInstance::TngClient(INGRESS_SINGLE).boxed(),
        AppType::TcpServer { port: 30001 }.boxed(),
        hold.boxed(),
    ])
    .await?;

    let pool = status
        .lock()
        .unwrap()
        .clone()
        .context("the pool status was never queried")?;
    assert_eq!(pool["multiplex"], serde_json::json!(true));
    assert!(
        pool["multiplex_max_streams_per_connection"].is_null(),
        "the stream cap must be unset, got {}",
        pool["multiplex_max_streams_per_connection"]
    );
    let endpoint = sole_endpoint(&pool);
    assert_eq!(endpoint["shard_count"], serde_json::json!(1));
    let actives = shard_active_streams(endpoint);
    assert_eq!(
        actives,
        vec![5],
        "all five streams must multiplex over the one tunnel, got {actives:?}"
    );
    Ok(())
}

/// With the tunnel bound at 2 and the stream cap at 1, streams past the bound
/// overflow onto the least-loaded existing tunnels instead of opening a third
/// one: the tunnel bound is a hard watermark, the per-tunnel stream cap is
/// soft past it, and each overflow is counted.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn multiplex_tunnel_bound_overflows_stream_cap() -> Result<()> {
    let (hold, status) = hold_streams_and_query_pool(4);
    run_test!(vec![
        TngInstance::TngServer(EGRESS).boxed(),
        TngInstance::TngClient(INGRESS_TUNNEL_BOUND).boxed(),
        AppType::TcpServer { port: 30001 }.boxed(),
        hold.boxed(),
    ])
    .await?;

    let pool = status
        .lock()
        .unwrap()
        .clone()
        .context("the pool status was never queried")?;
    assert_eq!(pool["multiplex_max_connections"], serde_json::json!(2));
    assert_eq!(
        pool["overflowed_streams"],
        serde_json::json!(2),
        "streams 3-4 must overflow past the stream cap, got {}",
        pool["overflowed_streams"]
    );
    let endpoint = sole_endpoint(&pool);
    assert_eq!(endpoint["shard_count"], serde_json::json!(2));
    let actives = shard_active_streams(endpoint);
    assert_eq!(
        actives,
        vec![2, 2],
        "each of the two bound tunnels must carry two overflowed streams, got {actives:?}"
    );
    Ok(())
}
