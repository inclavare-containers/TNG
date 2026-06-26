use anyhow::Result;
use tng_testsuite::{
    run_test,
    task::{
        app::AppType,
        tng::{TngExecTask, TngInstance},
        Task as _,
    },
};

/// Test hook mode: LD_PRELOAD-based port interception.
///
/// Server side: `tng exec` wraps a Python echo server. The hook intercepts
/// the server's `bind(20001)` call and redirects it to an auto-allocated
/// real port. TNG listens on 20001 for tunnel traffic and forwards to the
/// real port.
///
/// Client side: TNG client with ingress mapping sends traffic through the
/// tunnel to the server's hook port.
///
/// This verifies the full hook egress flow: tunnel establishment, port
/// interception, data forwarding, and echo response.
///
/// This test requires `libtng_hook.so` to be installed alongside the `tng`
/// binary, so it only runs in `on-bin` mode (via `required-features`).
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test() -> Result<()> {
    run_test!(vec![
        // Server side: tng exec wrapping a Python TCP echo server.
        // The hook intercepts bind(20001) and redirects to an auto-allocated real port.
        TngExecTask::new(
            r#"{"add_egress": [{"hook": {"capture_listen": [{"port": 20001}]}, "no_ra": true}]}"#.to_string(),
            vec![
                "python3".to_string(),
                "-c".to_string(),
                concat!(
                    "import socket\n",
                    "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
                    "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n",
                    "s.bind(('0.0.0.0', 20001))\n",
                    "s.listen(5)\n",
                    "while True:\n",
                    "    c, a = s.accept()\n",
                    "    d = c.recv(4096)\n",
                    "    if d: c.sendall(d)\n",
                    "    c.close()",
                )
                .to_string(),
            ],
            false,
        )
        .boxed(),
        // Client side: TNG client with ingress mapping to server's hook port.
        TngInstance::TngClient(
            r#"{"add_ingress": [{"mapping": {"in": {"port": 10001}, "out": {"host": "192.168.1.1", "port": 20001}}, "no_ra": true}]}"#,
        )
        .boxed(),
        // TCP client that connects to 127.0.0.1:10001, sends payload, verifies echo.
        AppType::TcpClient {
            host: "127.0.0.1",
            port: 10001,
            http_proxy: None,
        }
        .boxed(),
    ])
    .await?;
    Ok(())
}
