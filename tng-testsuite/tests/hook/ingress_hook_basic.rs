use anyhow::Result;
use tng_testsuite::{
    run_test,
    task::{tng::TngExecTask, Task as _},
};

/// Test ingress hook mode: LD_PRELOAD-based connect() interception.
///
/// Single-node architecture (all on the same TngExecTask process):
/// - A background TCP echo server listens on 127.0.0.1:30001.
/// - `tng exec` with ingress hook intercepts connect() to 127.0.0.1:20001.
/// - Egress mapping listens on 0.0.0.0:20001 and forwards to 127.0.0.1:30001.
/// - A foreground Python TCP client connects through the tunnel.
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test() -> Result<()> {
    run_test!(vec![
        // tng exec with ingress hook + egress mapping.
        // The child command starts a background echo server, then runs a TCP client.
        TngExecTask::new(
            r#"{
                "add_ingress": [{
                    "hook": {
                        "capture_dst": [{"port": 20001}]
                    },
                    "no_ra": true
                }],
                "add_egress": [{
                    "mapping": {
                        "in": {"host": "0.0.0.0", "port": 20001},
                        "out": {"host": "127.0.0.1", "port": 30001}
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
time.sleep(60)
' &
sleep 1
python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 20001))
s.sendall(b"Hello World TCP!")
s.shutdown(socket.SHUT_WR)
d = s.recv(4096)
assert d == b"Hello World TCP!", f"Expected echo, got: {d}"
'
"#
                .to_string(),
            ],
        )
        .boxed(),
    ])
    .await?;
    Ok(())
}
