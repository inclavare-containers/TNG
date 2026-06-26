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
/// - Server side: TNG with egress mapping (0.0.0.0:20001 → 127.0.0.1:30001).
/// - Client side: `tng exec` with BOTH ingress hook (captures connect to 20001)
///   AND egress hook (wraps echo server on port 30001, intercepts bind).
///
/// Flow:
/// 1. Echo server (wrapped by egress hook) binds to 0.0.0.0:30001 → redirected
///    to internal real port. TNG listens on 30001 for tunneled traffic.
/// 2. Python client connects to 127.0.0.1:20001 → intercepted by ingress hook,
///    tunneled to server's egress mapping on 192.168.1.1:20001.
/// 3. Server egress mapping receives tunneled traffic, forwards to 127.0.0.1:30001.
///    But wait — 127.0.0.1:30001 is the CLIENT's echo server!
///
/// So we need the server's egress mapping to point BACK to the client's port 30001:
///   out.host = 192.168.1.253 (client IP), out.port = 30001
///
/// This test requires `libtng_hook.so` to be installed alongside the `tng`
/// binary, so it only runs in `on-bin` mode (via `required-features`).
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test() -> Result<()> {
    run_test!(vec![
        ShellTask {
            name: "dummy server".to_owned(),
            node_type: NodeType::Client,
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
        // Server side: TNG with egress mapping. Receives tunneled traffic on 20001,
        // forwards back to the client's egress-hook-wrapped echo server on port 30001.
        TngInstance::TngServer(
            r#"{
                "add_egress": [{
                    "mapping": {
                        "in": {"host": "0.0.0.0", "port": 20001},
                        "out": {"host": "192.168.1.253", "port": 30001}
                    },
                    "no_ra": true
                }]
            }"#,
        )
        .boxed(),
        // Client side: tng exec with ingress hook (captures 20001) + egress hook
        // (wraps echo server on 30001). Both hook modes are supported by tng exec.
        //
        // Flow: client connects to 127.0.0.1:20001 → ingress hook intercepts →
        // tunnels to server's egress mapping (192.168.1.1:20001) → server forwards
        // to 192.168.1.253:30001 (client) → egress hook receives → forwards to
        // real echo server port → echo → reverse path back to client.
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
s.connect(("127.0.0.1", 20001))
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
        )
        .boxed(),
    ])
    .await?;
    Ok(())
}
