use anyhow::Result;
use tng_testsuite::{
    run_test,
    task::{
        shell::{ShellMode, ShellTask},
        tng::{TngExecTask, TngInstance},
        NodeType, Task as _,
    },
};

/// Test ingress hook with `capture_local_traffic` defaulting to `false`.
///
/// Architecture:
/// - Server side: Echo server on port 30001 + TNG with egress mapping
///   (0.0.0.0:20001 -> 127.0.0.1:30001).
/// - Client side: `tng exec` with ingress hook `capture_dst: [{"port": 20001}]`
///   (no `capture_local_traffic` field -> defaults to `false`) running a
///   Python TCP client.
///
/// Flow:
/// 1. Echo server listens on 0.0.0.0:30001 (server node).
/// 2. Python client attempts to connect to 127.0.0.1:20001 (loopback).
/// 3. Since `127.0.0.1` is a local IP and `capture_local_traffic` defaults
///    to `false`, the ingress hook does NOT intercept this connection.
/// 4. The connection goes directly to 127.0.0.1:20001 on the client machine,
///    where there is no listener -> "Connection refused".
///
/// Expected result:
/// - The connection is REFUSED, proving the tunnel was NOT established for
///   local traffic. This verifies the default behavior of excluding local
///   interface IP traffic from hook-based capture.
///
/// This test requires `libtng_hook.so` to be installed alongside the `tng`
/// binary, so it only runs in `on-bin` mode (via `required-features`).
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test() -> Result<()> {
    run_test!(vec![
        // Echo server on the Server node, port 30001.
        ShellTask {
            name: "echo server".to_owned(),
            node_type: NodeType::Server,
            script: r#"
python3 -c '
import socket, threading, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 30001))
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
        // Server side: TNG with egress mapping.
        // Traffic arriving on 20001 is forwarded locally to echo server on 30001.
        TngInstance::TngServer(
            r#"{
                "add_egress": [{
                    "mapping": {
                        "in": {"host": "0.0.0.0", "port": 20001},
                        "out": {"host": "127.0.0.1", "port": 30001}
                    },
                    "no_ra": true
                }]
            }"#,
        )
        .boxed(),
        // Client side: tng exec with ingress hook.
        // capture_dst: [{"port": 20001}] with NO capture_local_traffic field -> defaults to false.
        //
        // The Python client attempts to connect to 127.0.0.1:20001 (loopback).
        // Since 127.0.0.1 is a local IP and capture_local_traffic defaults to
        // false, the ingress hook does NOT intercept -> connection goes directly
        // to 127.0.0.1:20001 on the client, where there is no listener.
        //
        // We verify the connection is REFUSED (ConnectionRefusedError), which
        // proves the tunnel was NOT used for this local traffic.
        //
        // If capture_local_traffic were true (or the check were missing/broken),
        // the hook would intercept the connection, tunnel it to the server, and
        // the echo response would arrive -> the test below would fail (unexpected
        // success means the tunnel captured local traffic).
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
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
try:
    s.connect(("127.0.0.1", 20001))
    # If we get here, the tunnel captured local traffic -> test FAILS
    print("UNEXPECTED: connection succeeded - tunnel captured local traffic!", file=sys.stderr)
    sys.exit(1)
except ConnectionRefusedError:
    # Expected: no local listener on 127.0.0.1:20001, proving tunnel was NOT used
    print("OK: connection refused as expected - local traffic bypassed tunnel")
    sys.exit(0)
except Exception as e:
    print(f"UNEXPECTED error: {e}", file=sys.stderr)
    sys.exit(1)
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
