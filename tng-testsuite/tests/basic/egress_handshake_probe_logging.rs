// The assertions read DEBUG events emitted by the in-process TNG runtime
// through the tracing capture layer. The on-bin and on-podman runners execute
// TNG as a separate process at its default INFO filter, so those events never
// reach the capture buffer and the test cannot observe what it asserts.
#![cfg(all(
    feature = "on-source-code",
    not(any(feature = "on-bin", feature = "on-podman"))
))]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{
    capture_logs, run_test,
    task::{function::FunctionTask, tng::TngInstance, NodeType, Task as _},
};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const OHTTP_EGRESS_CONFIG: &str = r#"
{
    "add_egress": [
        {
            "mapping": {
                "in": { "host": "0.0.0.0", "port": 20001 },
                "out": { "host": "127.0.0.1", "port": 30001 }
            },
            "ohttp": {},
            "no_ra": true
        }
    ]
}
"#;

/// A bare TCP probe is the shape an SLB health check takes. The probe resets
/// or closes the connection before the TLS handshake starts, so it never
/// becomes a TNG session. Both the tunnel-level error line and the access-log
/// fallback line must drop to DEBUG, and the access-log line must still be
/// emitted (one line per connection).
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_egress_probe_logs_at_debug() -> Result<()> {
    let logs = capture_logs().await;
    let probe_logs = Arc::clone(&logs);

    run_test!(vec![
        TngInstance::TngServer(
            r#"
            {
                "add_egress": [
                    {
                        "mapping": {
                            "in": { "host": "0.0.0.0", "port": 20001 },
                            "out": { "host": "127.0.0.1", "port": 30001 }
                        },
                        "no_ra": true
                    }
                ]
            }
            "#
        )
        .boxed(),
        FunctionTask {
            name: "tcp_probe".to_owned(),
            node_type: NodeType::Client,
            func: Box::new(move |token| probe_call(token, Arc::clone(&probe_logs))),
        }
        .boxed(),
    ])
    .await?;

    let captured = logs.lock().unwrap();
    let joined = captured.join("\n");
    assert!(
        captured
            .iter()
            .any(|line| line.contains("DEBUG") && line.contains("accepted only")),
        "expected the probe's access-log line at DEBUG; captured:\n{joined}"
    );
    assert!(
        !captured
            .iter()
            .any(|line| line.contains("ERROR") && line.contains("accepted only")),
        "the probe's access-log line must not be ERROR; captured:\n{joined}"
    );
    assert!(
        !captured
            .iter()
            .any(|line| line.contains("ERROR")
                && line.contains("Failed to consume stream from client")),
        "the probe must not log a tunnel-level ERROR; captured:\n{joined}"
    );

    Ok(())
}

/// The OHTTP egress terminates plain HTTP, so a bare TCP probe never becomes a
/// session either. Its setup failures come from the outer HTTP server instead
/// of a TLS handshake, and a clean close reaches that server as a successful
/// serve.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ohttp_egress_probe_logs_at_debug() -> Result<()> {
    let logs = capture_logs().await;
    let probe_logs = Arc::clone(&logs);

    run_test!(vec![
        TngInstance::TngServer(OHTTP_EGRESS_CONFIG).boxed(),
        FunctionTask {
            name: "tcp_probe".to_owned(),
            node_type: NodeType::Client,
            func: Box::new(move |token| ohttp_probe_call(token, Arc::clone(&probe_logs))),
        }
        .boxed(),
    ])
    .await?;

    let captured = logs.lock().unwrap();
    let joined = captured.join("\n");
    assert!(
        captured
            .iter()
            .any(|line| line.contains("DEBUG") && line.contains("accepted only")),
        "expected the probe's access-log line at DEBUG; captured:\n{joined}"
    );
    assert!(
        captured.iter().any(|line| line.contains("DEBUG")
            && line
                .contains("Downstream connection ended before the protocol handshake completed")),
        "expected the OHTTP setup failure to be classified; captured:\n{joined}"
    );
    assert!(
        !captured
            .iter()
            .any(|line| line.contains("ERROR") && line.contains("accepted only")),
        "the probe's access-log line must not be ERROR; captured:\n{joined}"
    );
    assert!(
        !captured
            .iter()
            .any(|line| line.contains("ERROR") && line.contains("Failed to handle OHTTP stream")),
        "the probe must not log an OHTTP tunnel-level ERROR; captured:\n{joined}"
    );

    Ok(())
}

/// A malformed request is a real protocol disagreement and still logs at
/// error. This is the negative control for the benign classification above.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ohttp_egress_malformed_request_logs_at_error() -> Result<()> {
    let logs = capture_logs().await;
    let probe_logs = Arc::clone(&logs);

    run_test!(vec![
        TngInstance::TngServer(OHTTP_EGRESS_CONFIG).boxed(),
        FunctionTask {
            name: "bad_request".to_owned(),
            node_type: NodeType::Client,
            func: Box::new(move |token| malformed_probe_call(token, Arc::clone(&probe_logs))),
        }
        .boxed(),
    ])
    .await?;

    let captured = logs.lock().unwrap();
    let joined = captured.join("\n");
    assert!(
        captured
            .iter()
            .any(|line| line.contains("ERROR") && line.contains("Failed to handle OHTTP stream")),
        "expected a tunnel-level ERROR for the malformed request; captured:\n{joined}"
    );
    assert!(
        captured
            .iter()
            .any(|line| line.contains("ERROR") && line.contains("accepted only")),
        "expected the access-log line at ERROR; captured:\n{joined}"
    );

    Ok(())
}

// tokio deprecated set_linger because a nonzero SO_LINGER can block the thread
// on drop; a zero timeout only turns the close into an immediate RST.
#[allow(deprecated)]
fn probe_call(
    token: CancellationToken,
    logs: Arc<Mutex<Vec<String>>>,
) -> Result<JoinHandle<Result<()>>> {
    Ok(tokio::spawn(async move {
        let _drop_guard = token.drop_guard();

        // Give the egress time to accept and start reading before the socket
        // goes away; otherwise the reset can race the accept() call and never
        // reach the handshake this test is about.
        let reset = TcpStream::connect("192.168.1.1:20001").await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        reset.set_linger(Some(Duration::ZERO))?;
        drop(reset);

        // A graceful close reaches the egress as EOF in the handshake
        // (UnexpectedEof), which is the same benign class as a reset.
        let closed = TcpStream::connect("192.168.1.1:20001").await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(closed);

        wait_for_lines(
            &logs,
            &[
                "Downstream connection ended before the protocol handshake completed",
                "accepted only",
            ],
        )
        .await;

        Ok(())
    }))
}

/// Cover the probe shapes an SLB produces: reset while the outer HTTP server
/// is reading, clean close, silent until the transport-layer first-byte
/// timeout fires, and a partial request that hyper reports as an incomplete
/// message.
#[allow(deprecated)]
fn ohttp_probe_call(
    token: CancellationToken,
    logs: Arc<Mutex<Vec<String>>>,
) -> Result<JoinHandle<Result<()>>> {
    Ok(tokio::spawn(async move {
        let _drop_guard = token.drop_guard();

        let reset = TcpStream::connect("192.168.1.1:20001").await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        reset.set_linger(Some(Duration::ZERO))?;
        drop(reset);

        let closed = TcpStream::connect("192.168.1.1:20001").await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(closed);

        // Held past the 5s first-byte timeout so the server side has already
        // classified the silent peer when the client finally closes.
        let silent = TcpStream::connect("192.168.1.1:20001").await?;
        tokio::time::sleep(Duration::from_secs(6)).await;
        drop(silent);

        // A request that stops mid-headers. hyper reports IncompleteMessage,
        // which is the same benign class as an idle close.
        let mut partial = TcpStream::connect("192.168.1.1:20001").await?;
        partial.write_all(b"POST /tng/").await?;
        drop(partial);

        wait_for_lines(
            &logs,
            &[
                "Downstream connection ended before the protocol handshake completed",
                "accepted only",
            ],
        )
        .await;
        // The partial request is the third classified failure (after reset and
        // the silent timeout). Wait for it so the test does not cancel the
        // instance while its connection is still being torn down.
        wait_for_line_count(
            &logs,
            "Downstream connection ended before the protocol handshake completed",
            3,
        )
        .await;

        Ok(())
    }))
}

/// Wait until `marker` has been captured at least `count` times, with the same
/// bound as `wait_for_lines`.
async fn wait_for_line_count(logs: &Arc<Mutex<Vec<String>>>, marker: &str, count: usize) {
    let _ = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let enough = {
                let captured = logs.lock().unwrap();
                captured.iter().filter(|line| line.contains(marker)).count() >= count
            };
            if enough {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
}

/// A complete request line with an unsupported HTTP version. hyper parses it
/// and rejects it, which is a protocol disagreement rather than a vanished
/// peer.
fn malformed_probe_call(
    token: CancellationToken,
    logs: Arc<Mutex<Vec<String>>>,
) -> Result<JoinHandle<Result<()>>> {
    Ok(tokio::spawn(async move {
        let _drop_guard = token.drop_guard();

        let mut bad = TcpStream::connect("192.168.1.1:20001").await?;
        bad.write_all(b"GET / HTTP/9.9\r\nHost: example.com\r\n\r\n")
            .await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(bad);

        wait_for_lines(&logs, &["Failed to handle OHTTP stream", "accepted only"]).await;

        Ok(())
    }))
}

/// Wait until every marker has been captured, or give up after a bound so a
/// regression surfaces as a failed assertion with the captured log rather than
/// a hanging test.
async fn wait_for_lines(logs: &Arc<Mutex<Vec<String>>>, markers: &[&str]) {
    let _ = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let all_present = {
                let captured = logs.lock().unwrap();
                markers
                    .iter()
                    .all(|marker| captured.iter().any(|line| line.contains(*marker)))
            };
            if all_present {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
}
