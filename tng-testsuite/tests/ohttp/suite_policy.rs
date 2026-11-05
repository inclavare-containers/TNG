use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{
    capture_logs, run_test,
    task::{
        app::AppType,
        shell::{ShellMode, ShellTask},
        tng::TngInstance,
        NodeType, Task as _,
    },
};

/// Egress at 192.168.1.1:20001 (OHTTP API + mapping to the backend at
/// 127.0.0.1:30001). `ohttp_body` is the inside of the `ohttp` object, for
/// example `"aead_suites": ["aes256_gcm"]`.
fn tng_server(ohttp_body: &str) -> TngInstance {
    let config = format!(
        r#"{{
            "add_egress": [
                {{
                    "mapping": {{
                        "in": {{ "host": "0.0.0.0", "port": 20001 }},
                        "out": {{ "host": "127.0.0.1", "port": 30001 }}
                    }},
                    "ohttp": {{ {ohttp_body} }},
                    "no_ra": true
                }}
            ]
        }}"#
    );
    TngInstance::TngServer(Box::leak(config.into_boxed_str()))
}

/// Ingress at 127.0.0.1:10001 forwarding to the egress above.
fn tng_client(ohttp_body: &str) -> TngInstance {
    let config = format!(
        r#"{{
            "add_ingress": [
                {{
                    "mapping": {{
                        "in": {{ "host": "0.0.0.0", "port": 10001 }},
                        "out": {{ "host": "192.168.1.1", "port": 20001 }}
                    }},
                    "ohttp": {{ {ohttp_body} }},
                    "no_ra": true
                }}
            ]
        }}"#
    );
    TngInstance::TngClient(Box::leak(config.into_boxed_str()))
}

fn http_server() -> AppType {
    AppType::HttpServer {
        port: 30001,
        expected_host_header: "example.com",
        expected_path_and_query: "/foo",
    }
}

fn http_client() -> AppType {
    AppType::HttpClient {
        host: "127.0.0.1",
        port: 10001,
        host_header: "example.com",
        path_and_query: "/foo",
    }
}

/// Assert every decapsulated request logged the expected AEAD, and that at
/// least one request was decapsulated. The egress logs the header suite at
/// debug level, and the testsuite subscriber captures `tng=debug`.
fn assert_negotiated_aead(
    logs: &std::sync::MutexGuard<'_, Vec<String>>,
    expected: &str,
) -> Result<()> {
    let requests: Vec<&String> = logs
        .iter()
        .filter(|line| line.contains("Received OHTTP request"))
        .collect();
    assert!(
        !requests.is_empty(),
        "no decapsulated request was logged; captured lines:\n{}",
        logs.join("\n")
    );
    for line in requests {
        assert!(
            line.contains(expected),
            "expected AEAD {expected} in: {line}"
        );
    }
    Ok(())
}

/// Decode the base64 key-config list the egress returns and echo its hex.
/// The list layout ends with `symmetric len | (kdf, aead)*`, so the suffix
/// identifies exactly which suites are advertised.
const FETCH_KEY_CONFIG_HEX: &str = r#"
resp=$(curl -sS --max-time 15 -X POST http://192.168.1.1:20001/ \
    -H 'x-tng-ohttp-api: /tng/key-config' \
    -H 'Content-Type: application/json' \
    -d '{}')
b64=$(printf '%s' "$resp" | jq -r '.hpke_key_config.encoded_key_config_list')
printf '%s' "$b64" | base64 -d | od -An -v -tx1 | tr -d ' \n'
"#;

/// A raw tunnel POST with a hand-built metadata block and request header.
/// `aead_id` is 1 = AES-128-GCM, 2 = AES-256-GCM, 3 = ChaCha20-Poly1305.
/// The body is `metadata_len | Metadata{no_auth} | key_id | kem | kdf | aead`;
/// the suite check runs before the key hint is consulted, so no real key is
/// needed.
fn raw_tunnel_post(aead_id: u8, expected_code: &str) -> String {
    // Two-byte big-endian AEAD id, for example `\000\003`.
    let aead_escape = format!("\\000\\{aead_id:03o}");
    format!(
        r#"
printf '\000\000\000\002\012\000\001\000\040\000\001{aead_escape}' > /tmp/tng-suite-req.bin
code=$(curl -sS --max-time 15 -o /dev/null -w '%{{http_code}}' \
    -X POST http://192.168.1.1:20001/ \
    -H 'x-tng-ohttp-api: /tng/tunnel' \
    -H 'Content-Type: message/ohttp-chunked-req' \
    --data-binary @/tmp/tng-suite-req.bin) || code=ERR
if [ "$code" != "{expected_code}" ]; then
    echo "FAIL: expected HTTP {expected_code}, got $code"
    exit 1
fi
echo "PASS: raw tunnel POST returned HTTP {expected_code}"
"#
    )
}

fn shell(name: &str, script: String) -> ShellTask {
    shell_with_mode(name, script, ShellMode::ForegroundStop)
}

/// Use after a shell assertion when an `HttpClient` runs next: a
/// `ForegroundStop` shell cancels the token and tears the tunnels down before
/// the client can connect.
fn shell_continue(name: &str, script: String) -> ShellTask {
    shell_with_mode(name, script, ShellMode::ForegroundContinue)
}

fn shell_with_mode(name: &str, script: String, mode: ShellMode) -> ShellTask {
    ShellTask {
        name: name.to_string(),
        node_type: NodeType::Client,
        script,
        mode,
    }
}

/// Enable the debug line the suite assertions read when tng runs as a separate
/// process. The external binary inherits `RUST_LOG`, and its `EnvFilter` then
/// emits `tng=debug`; the in-process subscriber reads the same variable.
fn enable_tng_trace_logs() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        std::env::set_var(
            "RUST_LOG",
            "info,tokio_graceful=off,rats_cert=trace,tng=trace",
        );
    });
}

/// Both sides unset: the egress advertises the default three suites and the
/// ingress keeps picking the first one (AES-128-GCM), exactly as before the
/// policy existed. The advertised list is asserted explicitly because the
/// fork adds AES-256-GCM to the default set.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn suite_policy_default_unchanged() -> Result<()> {
    enable_tng_trace_logs();
    let logs = capture_logs().await;

    run_test!(vec![
        tng_server("").boxed(),
        tng_client("").boxed(),
        http_server().boxed(),
        shell_continue(
            "default-policy-key-config",
            format!(
                r#"
hex=$({FETCH_KEY_CONFIG_HEX})
case "$hex" in
    *000c000100010001000200010003) echo "PASS: default three suites advertised" ;;
    *) echo "FAIL: unexpected key config $hex"; exit 1 ;;
esac
"#
            ),
        )
        .boxed(),
        http_client().boxed(),
    ])
    .await?;

    assert_negotiated_aead(&logs.lock().unwrap(), "Aes128Gcm")?;
    Ok(())
}

/// Egress policy only: AES-256-GCM is the sole advertised and accepted suite,
/// so an unset ingress negotiates it.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn suite_policy_egress_only_aes256() -> Result<()> {
    enable_tng_trace_logs();
    let logs = capture_logs().await;

    run_test!(vec![
        tng_server(r#""aead_suites": ["aes256_gcm"]"#).boxed(),
        tng_client("").boxed(),
        http_server().boxed(),
        shell_continue(
            "egress-key-config",
            format!(
                r#"
hex=$({FETCH_KEY_CONFIG_HEX})
case "$hex" in
    *000400010002) echo "PASS: only AES-256-GCM advertised" ;;
    *) echo "FAIL: unexpected key config $hex"; exit 1 ;;
esac
"#
            ),
        )
        .boxed(),
        http_client().boxed(),
    ])
    .await?;

    assert_negotiated_aead(&logs.lock().unwrap(), "Aes256Gcm")?;
    Ok(())
}

/// Ingress policy only: the egress still advertises all three suites, and the
/// ingress prefers and negotiates AES-256-GCM.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn suite_policy_ingress_only_aes256() -> Result<()> {
    enable_tng_trace_logs();
    let logs = capture_logs().await;

    run_test!(vec![
        tng_server("").boxed(),
        tng_client(r#""aead_suites": ["aes256_gcm"]"#).boxed(),
        http_server().boxed(),
        http_client().boxed(),
    ])
    .await?;

    assert_negotiated_aead(&logs.lock().unwrap(), "Aes256Gcm")?;
    Ok(())
}

/// The egress advertises ChaCha first, but the ingress preference order puts
/// AES-128 first. Ingress order wins, which is the documented deviation from
/// RFC 9458's "first advertised suite" rule.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn suite_policy_ingress_preference_wins_over_server_order() -> Result<()> {
    enable_tng_trace_logs();
    let logs = capture_logs().await;

    run_test!(vec![
        tng_server(r#""aead_suites": ["chacha20_poly1305", "aes128_gcm"]"#).boxed(),
        tng_client(r#""aead_suites": ["aes128_gcm", "chacha20_poly1305"]"#).boxed(),
        http_server().boxed(),
        shell_continue(
            "egress-advertised-order",
            format!(
                r#"
hex=$({FETCH_KEY_CONFIG_HEX})
case "$hex" in
    *00080001000300010001) echo "PASS: ChaCha then AES-128 advertised" ;;
    *) echo "FAIL: unexpected key config $hex"; exit 1 ;;
esac
"#
            ),
        )
        .boxed(),
        http_client().boxed(),
    ])
    .await?;

    // Server order would have picked ChaCha; ingress order picks AES-128.
    assert_negotiated_aead(&logs.lock().unwrap(), "Aes128Gcm")?;
    Ok(())
}

/// Disjoint policies fail closed on both sides: the ingress reports no
/// acceptable suite and never falls back, and the egress rejects a request
/// header carrying a suite it does not allow with HTTP 422.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn suite_policy_no_intersection_fails() -> Result<()> {
    enable_tng_trace_logs();
    let logs = capture_logs().await;

    run_test!(vec![
        tng_server(r#""aead_suites": ["aes256_gcm"]"#).boxed(),
        tng_client(r#""aead_suites": ["chacha20_poly1305"]"#).boxed(),
        http_server().boxed(),
        shell(
            "no-intersection",
            format!(
                r#"
# The egress only allows AES-256-GCM; a ChaCha header is rejected with 422.
{}
# The ingress cannot use the advertised suite and must fail the request
# rather than fall back to the default.
code=$(curl -sS --max-time 15 -o /dev/null -w '%{{http_code}}' \
    -H 'Host: example.com' http://127.0.0.1:10001/foo) || code=ERR
case "$code" in
    2[0-9][0-9]) echo "FAIL: request unexpectedly succeeded with $code"; exit 1 ;;
    *) echo "PASS: no-intersection request failed (code=$code)" ;;
esac
"#,
                raw_tunnel_post(3, "422")
            ),
        )
        .boxed(),
    ])
    .await?;

    let logs = logs.lock().unwrap();
    let no_intersection = logs
        .iter()
        .find(|line| line.contains("no intersection between server and ingress"))
        .expect("ingress must warn about the empty intersection");
    assert!(
        no_intersection.contains("Aes256Gcm") && no_intersection.contains("ChaCha20Poly1305"),
        "warning must list both sides: {no_intersection}"
    );
    Ok(())
}

/// A request sealed under a suite the egress no longer accepts is rejected
/// with 422 and logged with the suite, key id and peer. A normal request
/// afterwards succeeds, proving the tunnel serves the allowed suite.
///
/// The client-side key config cache cannot be aged within one process (the
/// policy is read once at startup), so the raw POST stands in for a client
/// that still holds an older key config advertising ChaCha20-Poly1305 while
/// the egress policy now allows only AES-256-GCM. That is the exact state
/// `peer_shared` peers with mismatched policies and not-yet-refreshed clients
/// produce, and it is the state the 422-and-refetch path recovers from.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn suite_policy_stale_ciphertext_rejected_then_recovers() -> Result<()> {
    enable_tng_trace_logs();
    let logs = capture_logs().await;

    run_test!(vec![
        tng_server(r#""aead_suites": ["aes256_gcm"]"#).boxed(),
        tng_client("").boxed(),
        http_server().boxed(),
        shell_continue("stale-ciphertext", raw_tunnel_post(3, "422")).boxed(),
        http_client().boxed(),
    ])
    .await?;

    let logs = logs.lock().unwrap();
    let rejection = logs
        .iter()
        .find(|line| line.contains("Rejected OHTTP request"))
        .expect("egress must log the rejected suite");
    assert!(
        rejection.contains("ChaCha20Poly1305"),
        "rejection must name the suite: {rejection}"
    );
    assert!(
        rejection.contains("key_id"),
        "rejection must name the key id: {rejection}"
    );

    let requests: Vec<&String> = logs
        .iter()
        .filter(|line| line.contains("Received OHTTP request"))
        .collect();
    assert!(
        requests.iter().all(|line| line.contains("Aes256Gcm")),
        "only the allowed suite may reach decapsulation"
    );
    assert!(!requests.is_empty(), "a recovered request must succeed");
    Ok(())
}

/// File-mode keys honor the egress policy: the loaded key config advertises
/// only the configured suite, not the default three.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn suite_policy_file_key_advertises_only_allowed() -> Result<()> {
    let key_dir = "/tmp/tng-test";
    let key_path = "/tmp/tng-test/ohttp-suite-key.pem";

    tokio::fs::create_dir_all(key_dir).await?;

    // X25519 PKCS#8 fixture, same as the other file-mode tests.
    let initial_key = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VuBCIEIOixlJE0Ykdc4ePwmaf2LLAea8Lfkfb+SARsKYmCBRpR
-----END PRIVATE KEY-----";
    tokio::fs::write(key_path, initial_key).await?;

    enable_tng_trace_logs();
    let logs = capture_logs().await;

    run_test!(vec![
        tng_server(&format!(
            r#""key": {{ "source": "file", "path": "{key_path}" }}, "aead_suites": ["aes256_gcm"]"#
        ))
        .boxed(),
        tng_client("").boxed(),
        http_server().boxed(),
        shell_continue(
            "file-key-config",
            format!(
                r#"
hex=$({FETCH_KEY_CONFIG_HEX})
case "$hex" in
    *000400010002) echo "PASS: file-mode key advertises only AES-256-GCM" ;;
    *) echo "FAIL: unexpected key config $hex"; exit 1 ;;
esac
"#
            ),
        )
        .boxed(),
        http_client().boxed(),
    ])
    .await?;

    assert_negotiated_aead(&logs.lock().unwrap(), "Aes256Gcm")?;
    Ok(())
}
