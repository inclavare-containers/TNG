use anyhow::Result;
use tng_testsuite::{
    run_test,
    task::{
        shell::{ShellMode, ShellTask},
        tng::{TngExecTask, TngInstance},
        NodeType, Task as _,
    },
};

/// Test ingress hook mode: LD_PRELOAD-based connect() interception.
///
/// Architecture:
/// - Server side: Echo server on port 30001 + TNG with egress mapping
///   (0.0.0.0:20001 → 127.0.0.1:30001).
/// - Client side: `tng exec` with ingress hook (captures connect to 192.168.1.1:20001)
///   running a Python TCP client.
///
/// Flow:
/// 1. Echo server listens on 0.0.0.0:30001 (server node).
/// 2. Python client connects to 127.0.0.1:20001 → intercepted by ingress hook,
///    tunneled to server's egress mapping on 20001.
/// 3. Server egress mapping forwards to 127.0.0.1:30001 → echo server.
/// 4. Echo response travels back through the tunnel to client.
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
        // Client side: tng exec with ingress hook, running on Client node.
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
s.connect(("192.168.1.1", 20001))
s.sendall(b"Hello World TCP!")
s.shutdown(socket.SHUT_WR)
d = s.recv(4096)
assert d == b"Hello World TCP!", f"Expected echo, got: {d}"
print("OK: ingress hook test passed")
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
