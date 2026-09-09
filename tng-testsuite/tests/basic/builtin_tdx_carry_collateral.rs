use anyhow::Result;
use serial_test::serial;
use tng_testsuite::{
    run_test,
    task::{app::AppType, tng::TngInstance, Task as _},
};

/// Builtin-AS verify with attest-side DCAP collateral carry.
///
/// The egress (attester) sets `tdx_carry_collateral: true`: it fetches DCAP
/// verification collateral from PCCS and embeds it in the evidence. The
/// ingress (verifier) runs the builtin AS in-process (`as_type: "builtin"`);
/// when the carried collateral is present it is used directly and the verify
/// side skips contacting a PCCS — this is the deployment where the verifier
/// has no PCCS connectivity.
///
/// PCCS: the attester side uses the Alibaba Cloud PCCS
/// (`https://sgx-dcap-server.cn-beijing.aliyuncs.com`, trustee's
/// `DEFAULT_PCCS_URL`) — either set `PCCS_URL` in the env or rely on the
/// built-in default.
///
/// Requires: real TDX hardware (the AA produces a TDX quote), `make
/// test-dep-aa` for the Attestation Agent, and the `tdx-carry-collateral` feature.
/// Run with:
///
/// ```sh
/// make test-dep-aa &
/// # wait for /run/confidential-containers/attestation-agent/attestation-agent.sock
/// make run-test TEST_NAME=builtin_tdx_carry_collateral EXTRA_CARGO_ARGS="--features tdx-carry-collateral"
/// ```
///
/// The test self-skips (returns Ok) when the AA socket is absent, so CI
/// without a running AA does not report a failure.
#[cfg(feature = "tdx-carry-collateral")]
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn builtin_tdx_carry_collateral() -> Result<()> {
    let aa_sock = "/run/confidential-containers/attestation-agent/attestation-agent.sock";
    if !std::path::Path::new(aa_sock).exists() {
        eprintln!(
            "skipping: AA socket {aa_sock} not found; run `make test-dep-aa` and run on TDX hardware"
        );
        return Ok(());
    }

    run_test!(vec![
        TngInstance::TngServer(r#"
            {
                "add_egress": [
                    {
                        "mapping": {
                            "in": { "port": 20001 },
                            "out": { "host": "127.0.0.1", "port": 30001 }
                        },
                        "ohttp": {},
                        "attest": {
                            "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
                            "tdx_carry_collateral": true
                        }
                    }
                ]
            }
        "#).boxed(),
        AppType::HttpServer {
            port: 30001,
            expected_host_header: "example.com",
            expected_path_and_query: "/foo/bar/www?type=1&case=1",
        }.boxed(),
        TngInstance::TngClient(r#"
            {
                "add_ingress": [
                    {
                        "mapping": {
                            "in": { "host": "0.0.0.0", "port": 10001 },
                            "out": { "host": "192.168.1.1", "port": 20001 }
                        },
                        "ohttp": {},
                        "verify": {
                            "model": "background_check",
                            "as_type": "builtin",
                            "attestation_policy": { "type": "trust_all" }
                        }
                    }
                ]
            }
        "#).boxed(),
        AppType::HttpClient {
            host: "127.0.0.1",
            port: 10001,
            host_header: "example.com",
            path_and_query: "/foo/bar/www?type=1&case=1",
        }.boxed(),
    ])
    .await?;

    Ok(())
}
