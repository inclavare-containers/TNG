use anyhow::Result;
use tng_testsuite::{
    run_test,
    task::{
        shell::{ShellMode, ShellTask},
        tng::TngExecTask,
        NodeType, Task as _,
    },
};

/// Test ingress hook with `capture_local_traffic` defaulting to `false`.
///
/// Architecture (all on the Client node):
/// - Echo server listens on 127.0.0.1:20001 (loopback).
/// - `tng exec` with ingress hook `capture_dst: [{"port": 20001}]`
///   (no `capture_local_traffic` field -> defaults to `false`) runs a
///   Python TCP client that connects to 127.0.0.1:20001.
///
/// Flow:
/// 1. Echo server starts on 127.0.0.1:20001.
/// 2. Python client inside `tng exec` attempts to connect to 127.0.0.1:20001.
/// 3. Since `127.0.0.1` is a local IP and `capture_local_traffic` defaults
///    to `false`, the ingress hook does NOT intercept this connection.
/// 4. The connection goes directly to the echo server on 127.0.0.1:20001.
///
/// Expected result:
/// - Echo round-trip succeeds, proving the tunnel was NOT used for this
///   local traffic. If the hook had captured the connection, it would have
///   been routed through the tunnel (and likely failed since no tunnel
///   endpoint exists for this flow).
///
/// This test requires `libtng_hook.so` to be installed alongside the `tng`
/// binary, so it only runs in `on-bin` mode (via `required-features`).
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test() -> Result<()> {
    run_test!(vec![
        // Echo server on the Client node, loopback only.
        ShellTask {
            name: "echo server on loopback".to_owned(),
            node_type: NodeType::Client,
            script: r#"
python3 -c '
import socket, threading, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 20001))
s.listen(5)
def handle():
    while True:
        c, a = s.accept()
        d = c.recv(4096)
        if d: c.sendall(d)
        c.close()
threading.Thread(target=handle, daemon=True).start()
time.sleep(120)
' &
sleep 120
                "#
            .to_owned(),
            mode: ShellMode::BackgroundContinue,
        }
        .boxed(),
        // Client side: tng exec with ingress hook.
        // capture_dst: [{"port": 20001}] with NO capture_local_traffic field -> defaults to false.
        //
        // The Python client connects to 127.0.0.1:20001 (loopback).
        // Since 127.0.0.1 is a local IP and capture_local_traffic defaults to
        // false, the ingress hook does NOT intercept -> connection goes directly
        // to the echo server on 127.0.0.1:20001.
        //
        // Successful echo proves local traffic bypassed the tunnel.
        // If capture_local_traffic were true (or the check were broken),
        // the hook would intercept, tunnel the connection, and it would fail.
        TngExecTask::new(
            r#"{
                "add_ingress": [{
                    "hook": {
                        "capture_dst": [{"port": 20001}]
                    },
                    "no_ra": true
                }]
            }"#
            .to_string(),
            vec![
                "sh".to_string(),
                "-c".to_string(),
                r#"
python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(10)
s.connect(("127.0.0.1", 20001))
s.sendall(b"Hello from local bypass!")
s.shutdown(socket.SHUT_WR)
d = s.recv(4096)
assert d == b"Hello from local bypass!", f"Expected echo, got: {d}"
print("OK: local traffic bypassed tunnel via ingress hook")
'
"#
                .to_string(),
            ],
            true,
            NodeType::Client,
        )
        .boxed(),
    ])
    .await?;
    Ok(())
}
