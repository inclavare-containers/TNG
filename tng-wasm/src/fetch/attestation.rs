use anyhow::{Context as _, Result};
use gloo::utils::format::JsValueSerdeExt;
use serde::Serialize;
use tng::{
    config::ra::{
        CocoConverterArgs, CocoVerifierArgs, ConverterArgs, RaArgs, VerifierArgs, VerifyArgs,
    },
    AttestationResult,
};
use wasm_bindgen::prelude::*;

use super::to_js_error;

/// Non-sensitive subset of verification config exposed to JavaScript.
///
/// Only public, non-secret fields are extracted here.  Sensitive values
/// (`api_key`, `as_headers`, `trusted_certs_paths`, …) are intentionally
/// omitted.  The explicit match arms ensure a compile error when a new
/// provider variant is added, forcing a review of which fields to expose.
#[derive(Serialize, Default)]
pub(super) struct RaSummary {
    pub as_addr: Option<String>,
    pub policy_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ita_jwks_addr: Option<String>,
}

/// Extract the RA-config summary for `ra_args`. Shared by the fetch response's
/// `attest_info` and the standalone `verify()` export.
pub(super) fn ra_summary(ra_args: &RaArgs) -> RaSummary {
    let mut summary = RaSummary::default();

    let verify_args = match ra_args {
        RaArgs::VerifyOnly(v) => Some(v),
        RaArgs::NoRa => None,
        #[allow(unreachable_patterns)]
        _ => None,
    };

    if let Some(verify_args) = verify_args {
        match verify_args {
            VerifyArgs::Passport { verifier } => match verifier {
                VerifierArgs::Coco(coco) => {
                    summary.as_provider = Some("coco".into());
                    match coco {
                        CocoVerifierArgs::Restful {
                            as_addr,
                            policy_ids,
                            ..
                        }
                        | CocoVerifierArgs::Grpc {
                            as_addr,
                            policy_ids,
                            ..
                        } => {
                            summary.as_addr = as_addr.clone();
                            summary.policy_ids = Some(policy_ids.clone());
                        }
                        CocoVerifierArgs::Builtin { .. } => {
                            // Nothing to do
                        }
                    }
                }
                VerifierArgs::Ita(ita) => {
                    summary.as_provider = Some("ita".into());
                    summary.ita_jwks_addr = Some(ita.ita_jwks_addr.clone());
                    summary.policy_ids = Some(ita.policy_ids.clone());
                }
            },
            VerifyArgs::BackgroundCheck {
                converter,
                verifier,
            } => match converter {
                ConverterArgs::Coco(coco) => {
                    summary.as_provider = Some("coco".into());
                    match coco {
                        CocoConverterArgs::Restful {
                            as_addr,
                            policy_ids,
                            ..
                        }
                        | CocoConverterArgs::Grpc {
                            as_addr,
                            policy_ids,
                            ..
                        } => {
                            summary.as_addr = Some(as_addr.clone());
                            summary.policy_ids = Some(policy_ids.clone());
                        }
                        CocoConverterArgs::Builtin { .. } => {
                            // Nothing to do
                        }
                    }
                }
                ConverterArgs::Ita(ita) => {
                    summary.as_provider = Some("ita".into());
                    summary.as_addr = Some(ita.as_addr.clone());
                    summary.policy_ids = Some(ita.policy_ids.clone());
                    if let VerifierArgs::Ita(v) = verifier {
                        summary.ita_jwks_addr = Some(v.ita_jwks_addr.clone());
                    }
                }
            },
        }
    }

    summary
}

#[derive(Serialize)]
struct AttestationInfo {
    #[serde(flatten)]
    summary: RaSummary,
    attestation_result: AttestationResult,
}

pub(super) fn attach_attestation_info(
    web_response: web_sys::Response,
    attestation_result: AttestationResult,
    ra_args: &RaArgs,
) -> Result<web_sys::Response, JsValue> {
    let attest_info = AttestationInfo {
        summary: ra_summary(ra_args),
        attestation_result,
    };

    // Create a JavaScript object
    let attest_info_obj = JsValue::from_serde(&attest_info)
        .context("Failed to serialize attestation_info object")
        .map_err(to_js_error)?;

    // Set attest_info as a property on the web_response
    js_sys::Reflect::set(
        &web_response,
        &JsValue::from_str("attest_info"),
        &attest_info_obj,
    )?;

    Ok(web_response)
}
