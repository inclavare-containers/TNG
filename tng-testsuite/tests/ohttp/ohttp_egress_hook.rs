use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{
    run_test,
    task::{
        shell::{ShellMode, ShellTask},
        tng::{TngExecTask, TngInstance},
        NodeType, Task as _,
    },
};

/// Marker the hook-captured Python backend touches after bind+listen
/// complete. Nodes are network namespaces only, so the file is visible on
/// every node's filesystem. Embedded in the Python and shell source below
/// through the `{ready}` placeholder.
const BACKEND_READY_FILE: &str = "/tmp/tng-ohttp-egress-hook-ready";

/// Regression coverage for ohttp egress on top of the hook capture mode.
/// Hook is the one egress mode whose upstream endpoint is resolved at
/// accept time from the LD_PRELOAD bind interception (landing IP + the
/// redirected real port), so the pairing pins that the ohttp backend leg
/// connects to what the capture mode decided, not to the inner request's
/// Host header.
///
/// Topology: `tng exec` wraps a Python HTTP echo server whose bind(20001)
/// the hook redirects to an auto-allocated real port; TNG egress listens on
/// 20001 and every ohttp backend connection lands on that real port. The
/// client node sends through an ohttp ingress mapping.
///
/// This test requires `libtng_hook.so` to be installed alongside the `tng`
/// binary, so it only runs in `on-bin` mode (via `required-features`).
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ohttp_egress_hook() -> Result<()> {
    // A leftover marker from an earlier run would let the wait below pass
    // before this run's backend is listening. The test is `#[serial]`, so
    // no concurrent run is writing it.
    let _ = std::fs::remove_file(BACKEND_READY_FILE);

    // HTTP/1.1 echo server: GET echoes the request target, POST echoes the
    // body verbatim. Content-Length framing on every response keeps the
    // keep-alive connection the egress dials reusable. Written against the
    // Python 3.6 stdlib (`ThreadingHTTPServer` landed in 3.7).
    // The constructor binds and listens (on the hook-redirected real port);
    // only then is the ready marker written, so a client that waits on it
    // cannot dial the port between hook's bind hijack and Python's listen.
    const ECHO_SERVER: &str = concat!(
        "import socketserver, sys\n",
        "from http.server import BaseHTTPRequestHandler, HTTPServer\n",
        "class H(BaseHTTPRequestHandler):\n",
        "    protocol_version = 'HTTP/1.1'\n",
        "    def _reply(self, body):\n",
        "        self.send_response(200)\n",
        "        self.send_header('content-type', 'application/octet-stream')\n",
        "        self.send_header('content-length', str(len(body)))\n",
        "        self.end_headers()\n",
        "        self.wfile.write(body)\n",
        "    def do_GET(self):\n",
        "        self._reply(self.path.encode())\n",
        "    def do_POST(self):\n",
        "        n = int(self.headers.get('content-length') or 0)\n",
        "        self._reply(self.rfile.read(n))\n",
        "    def log_message(self, *args):\n",
        "        pass\n",
        "class S(socketserver.ThreadingMixIn, HTTPServer):\n",
        "    daemon_threads = True\n",
        "srv = S(('0.0.0.0', int(sys.argv[1])), H)\n",
        "open('{ready}', 'w').close()\n",
        "srv.serve_forever()\n",
    );

    run_test!(vec![
        TngExecTask::new(
            r#"
            {
                "add_egress": [
                    {
                        "hook": {
                            "capture_listen": [
                                {
                                    "port": 20001
                                }
                            ]
                        },
                        "ohttp": {},
                        "no_ra": true
                    }
                ]
            }
            "#
            .to_string(),
            vec![
                "python3".to_string(),
                "-c".to_string(),
                ECHO_SERVER.replace("{ready}", BACKEND_READY_FILE),
                "20001".to_string(),
            ],
            false,
            NodeType::Server,
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
                        "ohttp": {},
                        "no_ra": true
                    }
                ]
            }
            "#,
        )
        .boxed(),
        ShellTask {
            name: "ohttp-egress-hook-echo".to_string(),
            node_type: NodeType::Client,
            mode: ShellMode::ForegroundStop,
            script: r#"
set -e

# The egress tunnel listener comes up before the LD_PRELOAD-wrapped Python
# finishes bind+listen on the hook-redirected real port; on a warm machine
# the first backend dial then lands a millisecond before the socket accepts
# and ECONNREFUSEDs. Wait for the backend's ready marker instead of racing
# it; the request checks below keep their full cold-request assertions.
waited=0
while [ ! -e {ready} ] && [ "$waited" -lt 300 ]; do
    sleep 0.1
    waited=$((waited + 1))
done
[ -e {ready} ] || { echo "FAIL: hook backend never became ready"; exit 1; }

# Small GET: basic tunnel health through the hook egress.
got=$(curl -sS --fail --max-time 30 -H 'Host: example.com' http://127.0.0.1:10001/hook-check)
[ "$got" = "/hook-check" ] || { echo "FAIL: GET echo returned '$got'"; exit 1; }
echo "PASS: GET echoed through egress hook"

# A second request on a fresh outer connection: the backend slot per outer
# connection must redial the hook-resolved endpoint and still reach the app.
got=$(curl -sS --fail --max-time 30 -H 'Host: example.com' http://127.0.0.1:10001/hook-check2)
[ "$got" = "/hook-check2" ] || { echo "FAIL: second GET echo returned '$got'"; exit 1; }
echo "PASS: repeated request served"

# 128 KiB POST body byte-exact: exceeds the seal frame and AEAD chunk sizes,
# streaming request and response over the hook-resolved backend connection.
head -c 131072 /dev/urandom > /tmp/hookbody.bin
curl -sS --fail --max-time 60 -X POST --data-binary @/tmp/hookbody.bin \
    -H 'Host: example.com' http://127.0.0.1:10001/echo -o /tmp/hookresp.bin
cmp /tmp/hookbody.bin /tmp/hookresp.bin && echo "PASS: 128 KiB body echoed byte-exact"

echo "SUCCESS: egress hook ohttp checks passed"
"#
            .replace("{ready}", BACKEND_READY_FILE),
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}
