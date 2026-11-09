//! A client that resets its connection while the response is still in flight
//! must not wedge the ingress or leak the tunnel; after several aborts a clean
//! exchange must still succeed.
//!
//! This reproduces the teardown shape seen with real HTTP clients that close
//! with unread response bytes (RST instead of FIN), which reaches the forward
//! loop as a write error on the downstream side while the other direction is
//! still active.

// The harness runs each task inside its node's tokio runtime and hands back a
// JoinHandle, so there is no TokioRuntime handle to spawn from here.
#![allow(clippy::disallowed_methods)]

use std::time::Duration;

use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{
    run_test,
    task::{function::FunctionTask, tng::TngInstance, NodeType, Task as _},
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

const APP_PORT: u16 = 30001;
const INGRESS_PORT: u16 = 10001;

/// 64 chunks of 64 KiB: large enough that the client's reset lands while the
/// ingress still holds response bytes to deliver.
const RESPONSE_CHUNKS: usize = 64;
const RESPONSE_CHUNK_SIZE: usize = 64 * 1024;
const RESPONSE_LEN: usize = RESPONSE_CHUNKS * RESPONSE_CHUNK_SIZE;
const RESET_ROUNDS: usize = 5;
const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: bench\r\nConnection: close\r\n\r\n";

/// Serves every connection by streaming a fixed-size body, then closing the
/// write half. A peer that resets mid-body just makes `write_all` fail early;
/// the connection task exits and the listener keeps serving.
fn big_response_server(
) -> Box<dyn Fn(CancellationToken) -> Result<JoinHandle<Result<()>>> + Sync + Send> {
    Box::new(|token: CancellationToken| {
        Ok(tokio::spawn(async move {
            let listener = TcpListener::bind(("0.0.0.0", APP_PORT)).await?;
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    accepted = listener.accept() => {
                        let (mut stream, _peer) = accepted?;
                        tokio::spawn(async move {
                            let mut request = [0u8; 1024];
                            let _ = tokio::time::timeout(
                                Duration::from_secs(1),
                                stream.read(&mut request),
                            )
                            .await;
                            let chunk = vec![b'A'; RESPONSE_CHUNK_SIZE];
                            for _ in 0..RESPONSE_CHUNKS {
                                if stream.write_all(&chunk).await.is_err() {
                                    return;
                                }
                            }
                            let _ = stream.shutdown().await;
                        });
                    }
                }
            }
            Ok(())
        }))
    })
}

/// Aborts the connection with an RST (SO_LINGER 0) after reading only part of
/// the response, then proves a clean request still works.
fn reset_mid_response_client(
) -> Box<dyn Fn(CancellationToken) -> Result<JoinHandle<Result<()>>> + Sync + Send> {
    Box::new(|token: CancellationToken| {
        Ok(tokio::spawn(async move {
            let _drop_guard = token.drop_guard();

            for round in 0..RESET_ROUNDS {
                let mut stream = TcpStream::connect(("127.0.0.1", INGRESS_PORT)).await?;
                stream.write_all(REQUEST).await?;

                // Read only a prefix, leaving the rest of the body unread in
                // the socket when the connection is reset.
                let mut prefix = [0u8; 8192];
                let received = stream.read(&mut prefix).await?;
                anyhow::ensure!(
                    received > 0,
                    "round {round}: no response bytes before reset"
                );

                // SO_LINGER(0) turns close into RST, the abortive shape a
                // client leaves when it gives up mid-response.
                let socket = socket2::Socket::from(stream.into_std()?);
                socket.set_linger(Some(Duration::ZERO))?;
                drop(socket);
            }

            // The aborted connections must not leave the ingress or the
            // backend stuck: a fresh exchange still has to complete.
            let mut stream = TcpStream::connect(("127.0.0.1", INGRESS_PORT)).await?;
            stream.write_all(REQUEST).await?;
            let mut body = Vec::new();
            stream.read_to_end(&mut body).await?;
            anyhow::ensure!(
                body.len() == RESPONSE_LEN,
                "clean response after resets was truncated: got {} of {} bytes",
                body.len(),
                RESPONSE_LEN
            );

            Ok(())
        }))
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
#[serial]
async fn test() -> Result<()> {
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
        "#,
        )
        .boxed(),
        TngInstance::TngClient(
            r#"
        {
            "add_ingress": [
                {
                    "mapping": {
                        "in": { "host": "0.0.0.0", "port": 10001 },
                        "out": { "host": "192.168.1.1", "port": 20001 }
                    },
                    "no_ra": true
                }
            ]
        }
        "#,
        )
        .boxed(),
        FunctionTask {
            name: "big_response_server".to_owned(),
            node_type: NodeType::Server,
            func: big_response_server(),
        }
        .boxed(),
        FunctionTask {
            name: "reset_mid_response_client".to_owned(),
            node_type: NodeType::Client,
            func: reset_mid_response_client(),
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}
