use serial_test::serial;
use tng_testsuite::{
    run_test,
    task::{tng::TngInstance, Task as _},
};

/// `ktls: "required"` must fail setup when it cannot be honored, rather than
/// silently falling back to rustls. The cheapest such case is pairing it with
/// H2 multiplexing (`multiplex: true`): kTLS needs one TLS record layer per
/// connection, and under multiplexing the splice pipe's far end is demux
/// logic, not a socket, so kTLS is impossible — `required` therefore rejects
/// the config at startup (the `resolve()` bail in the netfilter gate / trusted
/// stream manager).
///
/// This guards the `required` failure path — the one tier that changes failure
/// semantics versus the old boolean — so a future refactor that accidentally
/// downgrades `required` to a silent rustls fallback fails this test loudly.
/// The bail happens during `add_egress` at startup, before any netfilter /
/// iptables setup or kTLS handshake, so it is deterministic and exercises no
/// data plane (and thus does not depend on a fixed kTLS kernel).
///
/// The assertion checks the specific bail message (not just "setup failed"),
/// so it cannot false-positive on an unrelated startup error.
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_ktls_required_with_multiplex_fails_setup() {
    let result = run_test!(vec![TngInstance::TngServer(
        r#"
            {
                "add_egress": [
                    {
                        "netfilter": {
                            "capture_dst": {
                                "port": 30002
                            }
                        },
                        "rats_tls": {
                            "ktls": "required",
                            "multiplex": true
                        },
                        "no_ra": true
                    }
                ]
            }
            "#,
    )
    .boxed(),])
    .await;

    let err = result.expect_err(
        "expected setup to fail: `ktls: \"required\"` is incompatible with H2 multiplexing",
    );
    // anyhow's Debug prints the full error chain (context + source), which
    // includes the resolve() bail message from the netfilter gate.
    let msg = format!("{err:?}");
    assert!(
        msg.contains("kTLS is incompatible") && msg.contains("multiplexing"),
        "expected the kTLS-required bail error, got: {msg}"
    );
}
