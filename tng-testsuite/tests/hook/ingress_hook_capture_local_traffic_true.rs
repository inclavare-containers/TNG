use anyhow::Result;
use tng_testsuite::{
    run_test,
    task::{
        shell::{ShellMode, ShellTask},
        tng::{TngExecTask, TngInstance},
        NodeType, Task as _,
    },
};

/// Test ingress hook with `capture_local_traffic: true` — local traffic
/// SHOULD be captured and tunneled.
///
/// NOTE: This test intentionally runs the echo server and the TNG egress
/// mapping on the Client node (not the Server node). This is NOT a mistake —
/// the purpose is to test `capture_local_traffic: true` on loopback traffic.
/// With `capture_local_traffic: true`, the ingress hook intercepts the local
/// connection to 127.0.0.1:20001, tunnels it to the TNG egress mapping on
/// the same node, which forwards to the echo server on 127.0.0.1:30001.
///
/// Architecture (all on the Client node):
/// - Echo server on 127.0.0.1:30001.
/// - TNG Client with ingress mapping (127.0.0.1:20001 → 127.0.0.1:30001).
/// - `tng exec` with ingress hook `capture_dst: [{"port": 20001}]`
///   and `capture_local_traffic: true` running a Python TCP client.
///
/// Flow:
/// 1. Echo server listens on 127.0.0.1:30001 (client node).
/// 2. TNG Client ingress mapping forwards 127.0.0.1:20001 → 127.0.0.1:30001.
/// 3. Python client connects to 127.0.0.1:20001 (loopback).
/// 4. Since `capture_local_traffic: true`, the ingress hook DOES intercept
///    this local connection, tunneling it through to the TNG Client mapping.
/// 5. TNG Client mapping forwards to 127.0.0.1:30001 → echo server.
/// 6. Echo response travels back through the tunnel to client.
///
/// Expected result:
/// - Echo round-trip succeeds, proving the tunnel WAS used for local traffic
///   when `capture_local_traffic: true`. This is the opposite of the default
///   (`false`) behavior where local traffic bypasses the tunnel.
///
/// This test requires `libtng_hook.so` to be installed alongside the `tng`
/// binary, so it only runs in `on-bin` mode (via `required-features`).
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test() -> Result<()> {
    run_test!(vec![
        // Echo server on the Client node, loopback only on port 30001.
        // NOTE: This is intentional — we test capture_local_traffic: true
        // with all components on the same node's loopback interface.
        ShellTask {
            name: "echo server on loopback".to_owned(),
            node_type: NodeType::Client,
            script: r#"
python3 -c '
import socket, threading, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 30001))
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
        // TNG Client with ingress mapping on the Client node.
        // Traffic arriving on 127.0.0.1:20001 is forwarded to echo server on 127.0.0.1:30001.
        // NOTE: This runs on Client (not Server) because we are testing loopback
        // traffic interception with capture_local_traffic: true.
        TngInstance::TngClient(
            r#"{
                "add_ingress": [{
                    "mapping": {
                        "in": {"host": "127.0.0.1", "port": 20001},
                        "out": {"host": "127.0.0.1", "port": 30001}
                    },
                    "no_ra": true
                }]
            }"#,
        )
        .boxed(),
        // Client side: tng exec with ingress hook, capture_local_traffic: true.
        //
        // The Python client connects to 127.0.0.1:20001 (loopback).
        // Since capture_local_traffic is true, the ingress hook DOES intercept
        // this local connection and tunnels it to the TNG Client mapping,
        // which forwards to the echo server.
        //
        // Successful echo proves local traffic WAS captured by the tunnel.
        // If capture_local_traffic were false (default), the connection would
        // go directly to 127.0.0.1:20001 where there is no listener, and fail.
        TngExecTask::new(
            r#"{
                "add_ingress": [{
                    "hook": {
                        "capture_dst": [{"port": 20001}],
                        "capture_local_traffic": true
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
s.sendall(b"Hello from captured local traffic!")
s.shutdown(socket.SHUT_WR)
d = s.recv(4096)
assert d == b"Hello from captured local traffic!", f"Expected echo, got: {d}"
print("OK: local traffic tunneled via ingress hook with capture_local_traffic: true")
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
