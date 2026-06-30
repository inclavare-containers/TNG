use anyhow::Result;
use tng_testsuite::{
    run_test,
    task::{
        shell::{ShellMode, ShellTask},
        tng::{TngExecTask, TngInstance},
        NodeType, Task as _,
    },
};

/// Test sendto hook intercepting TCP Fast Open (MSG_FASTOPEN) connections.
///
/// Applications using TCP Fast Open call `sendto()` with `MSG_FASTOPEN`
/// without calling `connect()` first, which would bypass the connect()
/// hook and proxy hijacking. The sendto hook ensures TFO connections
/// go through the same proxy logic.
///
/// Architecture:
/// - Server side: Python echo server on port 30001 + TNG with egress mapping
///   (0.0.0.0:20001 → 127.0.0.1:30001).
/// - Client side: `tng exec` with ingress hook (captures connections to port
///   20001) running a Python script that uses sendto() with MSG_FASTOPEN.
///
/// Flow:
/// 1. Echo server (on server node) listens on port 30001.
/// 2. Python client (inside `tng exec`) calls sendto(data, MSG_FASTOPEN,
///    (127.0.0.1, 20001)) without calling connect() first.
/// 3. sendto hook detects MSG_FASTOPEN, calls connect() hook to trigger
///    proxy hijacking → connection tunneled to server's egress mapping.
/// 4. Server egress mapping forwards locally to echo server on 127.0.0.1:30001.
/// 5. Echo server responds, data travels back through the tunnel to client.
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_sendto_tfo_intercept() -> Result<()> {
    run_test!(vec![
        // Echo server on the Server node, port 30001 (local to server).
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
import socket, struct

# MSG_FASTOPEN value for Linux
MSG_FASTOPEN = 0x20000000
# TCP_FASTOPEN socket option
TCP_FASTOPEN = 23

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Enable TCP Fast Open on this socket
s.setsockopt(socket.IPPROTO_TCP, TCP_FASTOPEN, 1)

# Send data using sendto with MSG_FASTOPEN — this bypasses connect().
# The sendto hook must intercept this and route through the proxy tunnel.
data = b"Hello TFO via sendto!"
n = s.sendto(data, MSG_FASTOPEN, ("127.0.0.1", 20001))
assert n == len(data), f"Expected sendto to send {len(data)} bytes, got {n}"

# Read the echo response through the tunnel.
s.shutdown(socket.SHUT_WR)
response = s.recv(4096)
assert response == data, f"Expected echo {data!r}, got {response!r}"
print("OK: sendto TFO intercept test passed")
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
