// Copyright (c) 2024 by Intel Corporation
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#[cfg(unix)]
use crate::tee::coco::converter::restful::RESTFUL_AS_CONNECT_TIMEOUT_DEFAULT;

use super::AttestationTokenVerifierConfig;
use anyhow::{anyhow, bail, Context};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk};
use jsonwebtoken::{decode, decode_header, jwk, Algorithm, DecodingKey, Header, Validation};
use reqwest::Url;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, TrustAnchor, UnixTime};
use rustls_webpki::ring::{
    ECDSA_P256_SHA256, ECDSA_P256_SHA384, ECDSA_P384_SHA256, ECDSA_P384_SHA384,
    RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512,
};
use rustls_webpki::{EndEntityCert, ALL_VERIFICATION_ALGS};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::result::Result::Ok;
use std::str::FromStr;
#[cfg(unix)]
use std::time::Duration;
use thiserror::Error;
use x509_cert::der::{Decode, DecodePem, Encode};
use x509_cert::Certificate;

const OPENID_CONFIG_URL_SUFFIX: &str = ".well-known/openid-configuration";

#[derive(Error, Debug)]
pub enum JwksGetError {
    #[error("Invalid source path: {0}")]
    InvalidSourcePath(String),
    #[error("Failed to access source: {0}")]
    AccessFailed(String),
    #[error("Failed to deserialize source data: {0}")]
    DeserializeSource(String),
}

#[derive(Deserialize)]
struct OpenIDConfig {
    jwks_uri: String,
}

#[derive(Clone)]
pub struct JwkAttestationTokenVerifier {
    trusted_jwk_sets: jwk::JwkSet,
    trusted_certs: Vec<CertificateDer<'static>>,
    insecure_key: bool,
}

async fn get_jwks_from_file_or_url(
    client: &reqwest::Client,
    p: &str,
) -> Result<jwk::JwkSet, JwksGetError> {
    let mut url = Url::parse(p).map_err(|e| JwksGetError::InvalidSourcePath(e.to_string()))?;
    match url.scheme() {
        "https" => {
            url.set_path(OPENID_CONFIG_URL_SUFFIX);

            #[cfg(all(
                target_arch = "wasm32",
                target_vendor = "unknown",
                target_os = "unknown"
            ))]
            let client = client.clone(); // Fix compile lifetime error

            let fut = async move {
                let oidc = client
                    .get(url.as_str())
                    .send()
                    .await
                    .map_err(|e| JwksGetError::AccessFailed(e.to_string()))?
                    .json::<OpenIDConfig>()
                    .await
                    .map_err(|e| JwksGetError::DeserializeSource(e.to_string()))?;

                let jwkset = client
                    .get(oidc.jwks_uri)
                    .send()
                    .await
                    .map_err(|e| JwksGetError::AccessFailed(e.to_string()))?
                    .json::<jwk::JwkSet>()
                    .await
                    .map_err(|e| JwksGetError::DeserializeSource(e.to_string()))?;

                Ok(jwkset)
            };

            #[cfg(all(
                target_arch = "wasm32",
                target_vendor = "unknown",
                target_os = "unknown"
            ))]
            // In wasm32 (web), the reqwest Response future is not `Send` but #[async_trait::async_trait] requires the function body to be Send. So we have to spawn it with tokio_with_wasm::task::spawn and await for it.
            let ret = tokio_with_wasm::task::spawn(fut)
                .await
                .map_err(|e| JwksGetError::AccessFailed(e.to_string()))
                .and_then(|e| e);
            #[cfg(not(all(
                target_arch = "wasm32",
                target_vendor = "unknown",
                target_os = "unknown"
            )))]
            let ret = fut.await;
            ret
        }
        "file" => {
            #[cfg(not(all(
                target_arch = "wasm32",
                target_vendor = "unknown",
                target_os = "unknown"
            )))]
            {
                let file_content = tokio::fs::read(url.path()).await.map_err(|e| {
                    JwksGetError::AccessFailed(format!("open {}: {}", url.path(), e))
                })?;

                serde_json::from_slice(&file_content)
                    .map_err(|e| JwksGetError::DeserializeSource(e.to_string()))
            }
            #[cfg(all(
                target_arch = "wasm32",
                target_vendor = "unknown",
                target_os = "unknown"
            ))]
            {
                Err(JwksGetError::AccessFailed(format!(
                    "open {}: file access is not supported in wasm",
                    url.path(),
                )))
            }
        }
        _ => Err(JwksGetError::InvalidSourcePath(format!(
            "unsupported scheme {} (must be either file or https)",
            url.scheme()
        ))),
    }
}

fn new_http_client() -> reqwest::Client {
    let builder =
        reqwest::Client::builder().user_agent(format!("rats-rs/{}", env!("CARGO_PKG_VERSION")));
    #[cfg(unix)]
    let builder = builder.connect_timeout(Duration::from_secs(RESTFUL_AS_CONNECT_TIMEOUT_DEFAULT));
    builder.build().unwrap()
}

impl JwkAttestationTokenVerifier {
    pub async fn new(config: &AttestationTokenVerifierConfig) -> anyhow::Result<Self> {
        let client = new_http_client();

        let mut trusted_jwk_sets = jwk::JwkSet { keys: Vec::new() };

        for path in config.trusted_jwk_sets.iter() {
            match get_jwks_from_file_or_url(&client, path).await {
                Ok(mut jwkset) => trusted_jwk_sets.keys.append(&mut jwkset.keys),
                Err(e) => bail!("error getting JWKS: {:?}", e),
            }
        }

        let mut trusted_certs = Vec::new();

        // Fetch certificates from AS address if provided
        if let Some(as_addr) = &config.as_addr {
            match Self::fetch_certs_from_as(&client, as_addr, &config.as_headers).await {
                Ok(certs) => trusted_certs.extend(certs),
                Err(error) => {
                    tracing::warn!(?error, "Failed to fetch certificates from AS")
                }
            }
        }

        // Load certificates from file paths
        for path in &config.trusted_certs_paths {
            #[cfg(not(all(
                target_arch = "wasm32",
                target_vendor = "unknown",
                target_os = "unknown"
            )))]
            {
                let cert_content = tokio::fs::read(path).await.map_err(|e| {
                    JwksGetError::AccessFailed(format!("failed to read certificate {path}: {e:?}"))
                })?;

                let cert_der = CertificateDer::from_pem_slice(&cert_content)
                    .with_context(|| format!("Failed to parse PEM certificate {}", path))?;

                trusted_certs.push(cert_der);
            }
            #[cfg(all(
                target_arch = "wasm32",
                target_vendor = "unknown",
                target_os = "unknown"
            ))]
            {
                Err(JwksGetError::AccessFailed(format!(
                    "failed to read certificate {path}: not supported in wasm"
                )))?
            }
        }

        Ok(Self {
            trusted_jwk_sets,
            trusted_certs,
            insecure_key: config.insecure_key,
        })
    }

    /// Fetch trusted certificates from AS endpoint
    async fn fetch_certs_from_as(
        client: &reqwest::Client,
        as_addr: &str,
        as_headers: &Option<HashMap<String, String>>,
    ) -> anyhow::Result<Vec<CertificateDer<'static>>> {
        let mut headers = reqwest::header::HeaderMap::new();
        if let Some(as_headers) = as_headers {
            for (k, v) in as_headers {
                headers.insert(reqwest::header::HeaderName::from_str(k)?, v.parse()?);
            }
        }

        let url = format!("{}/certificate", as_addr.trim_end_matches('/'));

        #[cfg(all(
            target_arch = "wasm32",
            target_vendor = "unknown",
            target_os = "unknown"
        ))]
        let client = client.clone(); // Fix compile lifetime error

        let fut = async move {
            let response = client
                .get(&url)
                .headers(headers)
                .send()
                .await
                .with_context(|| format!("Failed to fetch certificates chain from {}", url))?
                .error_for_status()
                .with_context(|| format!("HTTP error when fetching certificates from {}", url))?;

            let cert_pem_chain = response.text().await.with_context(|| {
                format!("Failed to read certificate chain response from {}", url)
            })?;

            let cert_ders = CertificateDer::pem_slice_iter(cert_pem_chain.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .with_context(|| {
                    format!("Failed to parse PEM certificate chain from AS {}", url)
                })?;

            Ok(cert_ders)
        };

        #[cfg(all(
            target_arch = "wasm32",
            target_vendor = "unknown",
            target_os = "unknown"
        ))]
        let ret = tokio_with_wasm::task::spawn(fut)
            .await
            .map_err(|e| anyhow!("Failed to spawn task: {}", e))
            .and_then(|r| r);

        #[cfg(not(all(
            target_arch = "wasm32",
            target_vendor = "unknown",
            target_os = "unknown"
        )))]
        let ret = fut.await;

        ret
    }

    fn verify_jwk_endorsement(&self, key: &Jwk) -> anyhow::Result<()> {
        // Get x5c certificate chain from JWK
        let Some(x5c) = &key.common.x509_chain else {
            bail!("No x5c extension inside JWK. Invalid public key.")
        };

        if x5c.is_empty() {
            bail!("Empty x5c extension inside JWK. Invalid public key.")
        }

        // Parse leaf certificate
        let pem = x5c[0].split('\n').collect::<String>();
        let leaf_der = URL_SAFE_NO_PAD.decode(pem).context("Illegal x5c cert")?;

        // Verify JWK public key matches certificate public key
        {
            let leaf_cert = Certificate::from_der(&leaf_der).context("Invalid x509 in x5c")?;
            self.verify_jwk_matches_cert(key, &leaf_cert)?;
        }

        let leaf_cert = CertificateDer::from(leaf_der);
        let end_entity = EndEntityCert::try_from(&leaf_cert)
            .map_err(|e| anyhow!("Failed to parse end entity certificate: {}", e))?;

        // Build a
        let trust_anchors: Vec<_> = self
            .trusted_certs
            .iter()
            .map(|cert_der| {
                rustls_webpki::anchor_from_trusted_cert(cert_der)
                    .map_err(|e| anyhow!("Failed to create trust anchor from certificate: {e:?}"))
            })
            .collect::<Result<_, _>>()?;

        // Build certificate chain
        let mut intermediates = Vec::new();
        for cert_pem in &x5c[1..] {
            let pem = cert_pem.split('\n').collect::<String>();
            let der = URL_SAFE_NO_PAD.decode(&pem).context("Illegal x5c cert")?;
            intermediates.push(CertificateDer::from(der));
        }

        // Use ring signature algorithms
        let supported_algs = &[
            ECDSA_P256_SHA256,
            ECDSA_P256_SHA384,
            ECDSA_P384_SHA256,
            ECDSA_P384_SHA384,
            RSA_PKCS1_2048_8192_SHA256,
            RSA_PKCS1_2048_8192_SHA384,
            RSA_PKCS1_2048_8192_SHA512,
        ];

        // Use current time for verification
        let time = UnixTime::now();

        // Verify certificate chain using rustls-webpki
        end_entity
            .verify_for_usage(
                supported_algs,
                &trust_anchors,
                &intermediates,
                time,
                rustls_webpki::KeyUsage::client_auth(),
                None, // No revocation checking
                None, // No additional path verification
            )
            .map_err(|e| anyhow!("JWK cannot be validated by trust anchor: {}", e))?;

        Ok(())
    }

    // Verify JWK public key matches certificate public key
    fn verify_jwk_matches_cert(&self, key: &Jwk, cert: &Certificate) -> anyhow::Result<()> {
        let cert_spki = &cert.tbs_certificate.subject_public_key_info;
        let cert_public_key_bytes = cert_spki.subject_public_key.raw_bytes();

        match &key.algorithm {
            AlgorithmParameters::RSA(rsa) => {
                // For RSA, check if modulus is in the certificate
                let n_bytes = URL_SAFE_NO_PAD
                    .decode(&rsa.n)
                    .context("decode RSA public key parameter n")?;

                // Search for modulus in DER-encoded public key
                if !cert_public_key_bytes
                    .windows(n_bytes.len())
                    .any(|w| w == n_bytes.as_slice())
                {
                    bail!("RSA modulus from JWK does not match certificate");
                }
            }
            AlgorithmParameters::EllipticCurve(ec) => {
                // For EC, construct the uncompressed point and compare
                let x = URL_SAFE_NO_PAD
                    .decode(&ec.x)
                    .context("decode EC public key parameter x")?;
                let y = URL_SAFE_NO_PAD
                    .decode(&ec.y)
                    .context("decode EC public key parameter y")?;

                let mut point_bytes = vec![0x04]; // Uncompressed point marker
                point_bytes.extend_from_slice(&x);
                point_bytes.extend_from_slice(&y);

                if cert_public_key_bytes != point_bytes.as_slice() {
                    bail!("EC point from JWK does not match certificate");
                }
            }
            _ => bail!("Only RSA or EC JWKs are supported."),
        }

        Ok(())
    }

    fn get_verification_jwk<'a>(&'a self, header: &'a Header) -> anyhow::Result<&'a Jwk> {
        if let Some(key) = &header.jwk {
            if self.insecure_key {
                return Ok(key);
            }
            if self.trusted_certs.is_empty() {
                bail!("Cannot verify token since trusted cert is empty");
            };
            self.verify_jwk_endorsement(key)?;
            return Ok(key);
        }

        if self.trusted_jwk_sets.keys.is_empty() {
            bail!("Cannot verify token since trusted JWK Set is empty");
        };

        let kid = header
            .kid
            .as_ref()
            .ok_or(anyhow!("Failed to decode kid in the token header"))?;

        let key = &self
            .trusted_jwk_sets
            .find(kid)
            .ok_or(anyhow!("Failed to find Jwk with kid {kid} in JwkSet"))?;

        Ok(key)
    }

    pub async fn verify(&self, token: String) -> anyhow::Result<Value> {
        let header = decode_header(&token)
            .map_err(|e| anyhow!("Failed to decode attestation token header: {}", e))?;

        let key = self.get_verification_jwk(&header)?;
        let key_alg = key
            .common
            .key_algorithm
            .ok_or(anyhow!("Failed to find key_algorithm in Jwk"))?
            .to_string();

        let alg = Algorithm::from_str(key_alg.as_str())?;

        let dkey = DecodingKey::from_jwk(key)?;
        let mut validation = Validation::new(alg);
        #[cfg(test)]
        {
            validation.validate_exp = false;
        }
        validation.validate_nbf = true;
        let token_data = decode::<Value>(&token, &dkey, &validation)
            .map_err(|e| anyhow!("Failed to decode attestation token: {}", e))?;

        Ok(token_data.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::get_jwks_from_file_or_url;
    use rstest::rstest;

    #[rstest]
    #[case("https://", true)]
    #[case("http://example.com", true)]
    #[case("file:///does/not/exist/keys.jwks", true)]
    #[case("/does/not/exist/keys.jwks", true)]
    #[tokio::test]
    async fn test_source_path_validation(#[case] source_path: &str, #[case] expect_error: bool) {
        let client = reqwest::Client::new();
        assert_eq!(
            expect_error,
            get_jwks_from_file_or_url(&client, source_path)
                .await
                .is_err()
        )
    }

    #[rstest]
    #[case(
        "{\"keys\":[{\"kty\":\"oct\",\"alg\":\"HS256\",\"kid\":\"coco123\",\"k\":\"foobar\"}]}",
        false
    )]
    #[case(
        "{\"keys\":[{\"kty\":\"oct\",\"alg\":\"COCO42\",\"kid\":\"coco123\",\"k\":\"foobar\"}]}",
        true
    )]
    #[tokio::test]
    async fn test_source_reads(#[case] json: &str, #[case] expect_error: bool) {
        let client = reqwest::Client::new();

        let tmp_dir = tempfile::tempdir().expect("to get tmpdir");
        let jwks_file = tmp_dir.path().join("test.jwks");

        let _ = tokio::fs::write(&jwks_file, json)
            .await
            .expect("to get testdata written to tmpdir");

        let p = "file://".to_owned() + jwks_file.to_str().expect("to get path as str");

        assert_eq!(
            expect_error,
            get_jwks_from_file_or_url(&client, &p).await.is_err()
        )
    }
}
