use super::*;
use crate::{
    config::ra::{CocoVerifierArgs, VerifierArgs, VerifyArgs},
    tests::run_test_with_tokio_runtime,
    tunnel::ohttp::{
        key_config::KeyConfigExtend,
        protocol::{header::OhttpApi, HpkeKeyConfig, KeyConfigResponse, ServerAttestationInfo},
    },
};
use axum::{body::Body, response::IntoResponse, routing::post, Json, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, prelude::BASE64_STANDARD, Engine};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use ohttp::KeyConfig;
use p256::{elliptic_curve::sec1::ToEncodedPoint, pkcs8::EncodePrivateKey};
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};

use web_time_compat::{SystemTime, SystemTimeExt};

fn server_key(id: u8) -> Result<KeyConfig> {
    Ok(KeyConfig::new(
        id,
        ohttp::hpke::Kem::X25519Sha256,
        vec![ohttp::SymmetricSuite::new(
            ohttp::hpke::Kdf::HkdfSha256,
            ohttp::hpke::Aead::Aes128Gcm,
        )],
    )?)
}

async fn passport_context() -> Result<Arc<RaContext>> {
    // Isolate transport pinning from issuer discovery. JWT signatures, expiry,
    // policy IDs and the binding to the HPKE configuration are still verified.
    let verify =
        crate::tunnel::ra_context::VerifyContext::from_verify_args(&VerifyArgs::Passport {
            verifier: VerifierArgs::Coco(CocoVerifierArgs::Restful {
                as_addr: None,
                policy_ids: vec!["default".into()],
                as_headers: HashMap::new(),
                trusted_certs_paths: None,
                verify_signer_transparency: false,
                skip_as_token_cert_verify: true,
            }),
        })
        .await?;
    Ok(Arc::new(RaContext::VerifyOnly(Arc::new(verify))))
}

struct TestServer {
    endpoint: TngEndpoint,
    key_requests: Arc<AtomicUsize>,
    application_requests: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TestServer {
    async fn start(
        runtime: &TokioRuntime,
        keys: &[KeyConfig],
        attested: bool,
        tamper_binding: bool,
    ) -> Result<Self> {
        let expire = SystemTime::get()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs()
            + 3600;
        let config = HpkeKeyConfig {
            expire_timestamp: expire,
            encoded_key_config_list: BASE64_STANDARD.encode(KeyConfig::encode_list(keys)?),
        };
        let secret = p256::SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let point = secret.public_key().to_encoded_point(false);
        let mut header = Header::new(Algorithm::ES256);
        header.jwk = Some(serde_json::from_value(json!({
            "kty": "EC", "crv": "P-256", "alg": "ES256",
            "x": URL_SAFE_NO_PAD.encode(point.x().context("test signing key must have x coordinate")?),
            "y": URL_SAFE_NO_PAD.encode(point.y().context("test signing key must have y coordinate")?),
        }))?);
        let token = jsonwebtoken::encode(
            &header,
            &json!({
                "exp": expire,
                "customized_claims": {"runtime_data": {"hpke_key_config": config}},
                "evaluation-reports": [{"policy-id": "default"}],
            }),
            &EncodingKey::from_ec_der(secret.to_pkcs8_der()?.as_bytes()),
        )?;
        let mut response = KeyConfigResponse {
            hpke_key_config: config,
            attestation_info: attested.then_some(ServerAttestationInfo::Passport {
                attestation_result: token,
                as_provider: None,
            }),
        };
        if tamper_binding {
            response.hpke_key_config.expire_timestamp += 1;
        }
        let response = serde_json::to_value(response)?;
        let key_requests = Arc::new(AtomicUsize::new(0));
        let application_requests = Arc::new(AtomicUsize::new(0));
        let router = Router::new().route(
            "/",
            post({
                let key_requests = key_requests.clone();
                let application_requests = application_requests.clone();
                move |headers: http::HeaderMap| {
                    let response = response.clone();
                    let key_requests = key_requests.clone();
                    let application_requests = application_requests.clone();
                    async move {
                        if headers
                            .get(OhttpApi::HEADER_NAME)
                            .and_then(|v| v.to_str().ok())
                            == Some(OhttpApi::KEY_CONFIG)
                        {
                            key_requests.fetch_add(1, Ordering::SeqCst);
                            Json(response).into_response()
                        } else {
                            application_requests.fetch_add(1, Ordering::SeqCst);
                            http::StatusCode::BAD_GATEWAY.into_response()
                        }
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = TngEndpoint::new("127.0.0.1", listener.local_addr()?.port());
        let task = runtime.spawn_unsupervised_task_current_span(async move {
            axum::serve(listener, router).await
        });
        Ok(Self {
            endpoint,
            key_requests,
            application_requests,
            task,
        })
    }
}

async fn layer(
    runtime: TokioRuntime,
    context: Arc<RaContext>,
    pin: Option<String>,
) -> Result<OHttpSecurityLayer> {
    OHttpSecurityLayer::new(
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        None,
        &OHttpArgs {
            expected_server_public_key: pin,
            ..Default::default()
        },
        context,
        runtime,
    )
    .await
}

fn application_request() -> Result<axum::extract::Request> {
    Ok(http::Request::builder()
        .uri("http://workload.invalid/private")
        .header(http::header::AUTHORIZATION, "Bearer test-only-credential")
        .body(Body::from("test-only-application-secret"))?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enrollment_preflight_returns_and_caches_the_attested_key() -> Result<()> {
    run_test_with_tokio_runtime(|runtime| async move {
        let approved = server_key(1)?;
        let pin = hex::encode(approved.public_key().unwrap().as_ref());
        let server = TestServer::start(&runtime, &[approved], true, false).await?;
        let layer = layer(runtime, passport_context().await?, None).await?;
        for _ in 0..2 {
            let verified = layer
                .verified_server_public_key(&server.endpoint, &application_request()?)
                .await?;
            assert_eq!(verified.as_deref(), Some(pin.as_str()));
        }
        assert_eq!(server.key_requests.load(Ordering::SeqCst), 1);
        assert_eq!(server.application_requests.load(Ordering::SeqCst), 0);
        Ok(())
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enrolled_pin_rejects_substitution_before_sending_application_data() -> Result<()> {
    run_test_with_tokio_runtime(|runtime| async move {
        let approved = server_key(1)?;
        let pin = hex::encode(approved.public_key().unwrap().as_ref());
        let copy = server_key(2)?;
        for (keys, attested, tampered, reason) in [
            (vec![approved.clone()], true, false, None),
            (
                vec![copy.clone()],
                true,
                false,
                Some("instance public key changed"),
            ),
            (
                vec![copy, approved.clone()],
                true,
                false,
                Some("instance public key changed"),
            ),
            (
                vec![],
                true,
                false,
                Some("Missing enrolled OHTTP server key"),
            ),
            (
                vec![approved.clone()],
                false,
                false,
                Some("no attestation_info"),
            ),
            (vec![approved], true, true, Some("Runtime data mismatch")),
        ] {
            let server = TestServer::start(&runtime, &keys, attested, tampered).await?;
            let layer = layer(
                runtime.clone(),
                passport_context().await?,
                Some(pin.clone()),
            )
            .await?;
            if let Some(reason) = reason {
                let error = layer
                    .forward_http_request(&server.endpoint, application_request()?)
                    .await
                    .unwrap_err();
                let message = format!("{:#}", anyhow::Error::new(error));
                assert!(
                    message.contains(reason),
                    "expected {reason:?}, got {message}"
                );
            } else {
                assert_eq!(
                    layer
                        .verified_server_public_key(&server.endpoint, &application_request()?)
                        .await?
                        .as_deref(),
                    Some(pin.as_str())
                );
            }
            assert_eq!(server.key_requests.load(Ordering::SeqCst), 1);
            assert_eq!(server.application_requests.load(Ordering::SeqCst), 0);
        }
        Ok(())
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_pins_and_unverified_enrollment_fail_before_network_access() -> Result<()> {
    run_test_with_tokio_runtime(|runtime| async move {
        let server = TestServer::start(&runtime, &[server_key(1)?], true, false).await?;
        for (pin, reason) in [
            ("not-hex".to_string(), "Invalid enrolled OHTTP public key"),
            ("ab".repeat(31), "must contain 32 bytes"),
            ("ab".repeat(33), "must contain 32 bytes"),
            ("ab".repeat(32), "instance pin requires attestation"),
        ] {
            let layer = layer(runtime.clone(), Arc::new(RaContext::NoRa), Some(pin)).await?;
            let error = layer
                .forward_http_request(&server.endpoint, application_request()?)
                .await
                .unwrap_err();
            let message = format!("{:#}", anyhow::Error::new(error));
            assert!(
                message.contains(reason),
                "expected {reason:?}, got {message}"
            );
        }
        let layer = layer(runtime, Arc::new(RaContext::NoRa), None).await?;
        let error = layer
            .verified_server_public_key(&server.endpoint, &application_request()?)
            .await
            .unwrap_err();
        assert!(format!("{:#}", anyhow::Error::new(error))
            .contains("enrollment requires attestation verification"));
        assert_eq!(server.key_requests.load(Ordering::SeqCst), 0);
        assert_eq!(server.application_requests.load(Ordering::SeqCst), 0);
        Ok(())
    })
    .await
}
