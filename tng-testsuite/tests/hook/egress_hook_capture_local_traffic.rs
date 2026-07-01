use anyhow::Result;
use tng_testsuite::{
    run_test,
    task::tng::TngExecTask,
    task::NodeType,
    task::Task as _,
};

/// Test egress hook with `capture_local_traffic` defaulting to `false`.
///
/// Architecture:
/// - Server side: `tng exec` with egress hook `capture_listen: [{"host":
///   "127.0.0.1", "port": 20001}]` (no `capture_local_traffic` field ->
///   defaults to `false`) wrapping a Python echo server that binds to
///   127.0.0.1:20001. Inside the wrapper, a local TCP client connects to
///   127.0.0.1:20001, sends data, and verifies the echo response.
///
/// Flow:
/// 1. `tng exec` starts on the server node with egress hook configuration.
/// 2. The Python echo server binds to 127.0.0.1:20001 (loopback).
/// 3. Since `127.0.0.1` is a local IP and `capture_local_traffic` defaults
///    to `false`, the egress hook does NOT intercept this bind/listen.
///    `encrypted()` returns `false` for connections to this endpoint.
/// 4. A local TCP client inside the same `tng exec` wrapper connects to
///    127.0.0.1:20001, sends a payload, and receives the echo response.
///
/// Expected result:
/// - The echo round-trip succeeds DIRECTLY on loopback, proving the tunnel
///   did NOT capture this local traffic. If the tunnel had captured it,
///   the connection would have been routed through the tunnel infrastructure
///   and likely failed or produced different behavior.
///
/// This test requires `libtng_hook.so` to be installed alongside the `tng`
/// binary, so it only runs in `on-bin` mode (via `required-features`).
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test() -> Result<()> {
    run_test!(vec![
        // Server side: tng exec wrapping a Python echo server on 127.0.0.1:20001.
        // capture_listen: [{"host": "127.0.0.1", "port": 20001}] with NO
        // capture_local_traffic field -> defaults to false.
        //
        // Inside the `tng exec` wrapper:
        // 1. Echo server starts on 127.0.0.1:20001 (background thread).
        // 2. Local TCP client connects to 127.0.0.1:20001, sends data, verifies echo.
        //
        // Since capture_local_traffic defaults to false and 127.0.0.1 is a local IP,
        // the hook does NOT intercept -> connection goes directly to the echo server.
        // Successful echo proves local traffic bypassed the tunnel.
        TngExecTask::new(
            r#"{"add_egress": [{"hook": {"capture_listen": [{"host": "127.0.0.1", "port": 20001}]}, "no_ra": true}]}"#.to_string(),
            vec![
                "sh".to_string(),
                "-c".to_string(),
                concat!(
                    "python3 -c '\n",
                    "import socket, threading, time\n",
                    "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
                    "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n",
                    "s.bind((\"127.0.0.1\", 20001))\n",
                    "s.listen(5)\n",
                    "def handle():\n",
                    "    while True:\n",
                    "        c, a = s.accept()\n",
                    "        d = c.recv(4096)\n",
                    "        if d: c.sendall(d)\n",
                    "        c.close()\n",
                    "threading.Thread(target=handle, daemon=True).start()\n",
                    "time.sleep(1)\n",
                    "c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
                    "c.connect((\"127.0.0.1\", 20001))\n",
                    "c.sendall(b\"Hello from local bypass!\")\n",
                    "c.shutdown(socket.SHUT_WR)\n",
                    "d = c.recv(4096)\n",
                    "assert d == b\"Hello from local bypass!\", f\"Expected echo, got: {d}\"\n",
                    "c.close()\n",
                    "print(\"OK: egress hook local traffic bypass verified\")\n",
                    "'",
                )
                .to_string(),
            ],
            false,
            NodeType::Server,
        )
        .boxed(),
    ])
    .await?;
    Ok(())
}
