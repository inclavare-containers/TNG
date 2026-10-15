use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{
    run_test,
    task::{
        app::AppType,
        shell::{ShellMode, ShellTask},
        tng::TngInstance,
        NodeType, Task as _,
    },
};

/// Byte-exact large-body coverage for the ohttp seal pumps (both directions,
/// multi-AEAD-chunk requests and multi-frame responses), the mid-stream
/// upstream abort surfacing as a client-visible failure, and tunnel health
/// after that abort. Bodies here exceed the 64 KiB frame coalescing size and
/// the 16 KiB AEAD chunk size, so a single request/response exercises every
/// boundary of the stream paths.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_ohttp_stream_bodies() -> Result<()> {
    run_test!(vec![
        TngInstance::TngServer(
            r#"
            {
                "add_egress": [
                    {
                        "mapping": {
                            "in": { "host": "0.0.0.0", "port": 20001 },
                            "out": { "host": "127.0.0.1", "port": 30001 }
                        },
                        "ohttp": {},
                        "no_ra": true
                    }
                ]
            }
            "#,
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
        AppType::HttpEchoServer { port: 30001 }.boxed(),
        ShellTask {
            name: "large-body-echo".to_string(),
            node_type: NodeType::Client,
            mode: ShellMode::ForegroundStop,
            script: r#"
set -e
head -c 131072 /dev/urandom > /tmp/body128k.bin
curl -sS --fail --max-time 60 -X POST --data-binary @/tmp/body128k.bin \
    -H 'Host: example.com' http://127.0.0.1:10001/echo -o /tmp/resp128k.bin
cmp /tmp/body128k.bin /tmp/resp128k.bin && echo PASS: 128 KiB body echoed byte-exact

head -c 1048576 /dev/urandom > /tmp/body1m.bin
curl -sS --fail --max-time 60 -X POST --data-binary @/tmp/body1m.bin \
    -H 'Host: example.com' http://127.0.0.1:10001/echo -o /tmp/resp1m.bin
cmp /tmp/body1m.bin /tmp/resp1m.bin && echo PASS: 1 MiB body echoed byte-exact

# Upstream aborts mid-response: the client must see an error status, never
# a silently "successful" truncated body.
code=$(curl -sS --max-time 30 -o /tmp/respabort.bin -w '%{http_code}' \
    -X POST --data-binary @/tmp/body128k.bin \
    -H 'Host: example.com' http://127.0.0.1:10001/abort-mid) || code=ERR
case "$code" in
    5[0-9][0-9]|ERR) echo "PASS: mid-stream upstream abort surfaced as error (code=$code)" ;;
    *) echo "FAIL: aborted response reached the client as code=$code"; exit 1 ;;
esac

# The tunnel must still serve large bodies correctly after that abort. The
# first request afterwards must not be handed the pooled backend connection
# that the abort killed: a failed send evicts the slot, so this single
# request must redial and return 200 on its own, with no retry.
code=$(curl -sS --max-time 60 -o /tmp/resp128k-2.bin -w '%{http_code}' \
    -X POST --data-binary @/tmp/body128k.bin \
    -H 'Host: example.com' http://127.0.0.1:10001/echo) || code=ERR
if [ "$code" != 200 ]; then
    echo "FAIL: first post-abort request returned code=$code, expected 200 on the first try"
    exit 1
fi
cmp /tmp/body128k.bin /tmp/resp128k-2.bin && echo PASS: 128 KiB echo still exact after abort

echo SUCCESS: all stream body checks passed
"#
            .to_string(),
        }
        .boxed(),
    ])
    .await?;

    Ok(())
}
