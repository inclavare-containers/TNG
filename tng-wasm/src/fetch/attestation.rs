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
#[derive(Serialize)]
struct AttestationInfo {
    as_addr: Option<String>,
    policy_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    as_provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ita_jwks_addr: Option<String>,
    attestation_result: AttestationResult,
}

pub(super) fn attach_attestation_info(
    web_response: web_sys::Response,
    attestation_result: AttestationResult,
    ra_args: &RaArgs,
) -> Result<web_sys::Response, JsValue> {
    let mut attest_info = AttestationInfo {
        as_addr: None,
        policy_ids: None,
        as_provider: None,
        ita_jwks_addr: None,
        attestation_result,
    };

    let verify_args = match ra_args {
        RaArgs::VerifyOnly(v) => Some(v),
        RaArgs::NoRa => None,
        #[allow(unreachable_patterns)]
        _ => None,
    };

    if let Some(verify_args) = verify_args {
        match verify_args {
            VerifyArgs::Passport { verifier } => match verifier {
                VerifierArgs::Coco(coco) => match coco {
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
                        attest_info.as_provider = Some("coco".into());
                        attest_info.as_addr = as_addr.clone();
                        attest_info.policy_ids = Some(policy_ids.clone());
                    }
                    // Builtin AS has no remote address or policy ids to expose.
                    CocoVerifierArgs::Builtin => {
                        attest_info.as_provider = Some("coco".into());
                    }
                },
                VerifierArgs::Ita(ita) => {
                    attest_info.as_provider = Some("ita".into());
                    attest_info.ita_jwks_addr = Some(ita.ita_jwks_addr.clone());
                    attest_info.policy_ids = Some(ita.policy_ids.clone());
                }
            },
            VerifyArgs::BackgroundCheck {
                converter,
                verifier,
            } => match converter {
                ConverterArgs::Coco(coco) => match coco {
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
                        attest_info.as_provider = Some("coco".into());
                        attest_info.as_addr = Some(as_addr.clone());
                        attest_info.policy_ids = Some(policy_ids.clone());
                    }
                    // Builtin AS has no remote address or policy ids to expose.
                    CocoConverterArgs::Builtin { .. } => {
                        attest_info.as_provider = Some("coco".into());
                    }
                },
                ConverterArgs::Ita(ita) => {
                    attest_info.as_provider = Some("ita".into());
                    attest_info.as_addr = Some(ita.as_addr.clone());
                    attest_info.policy_ids = Some(ita.policy_ids.clone());
                    if let VerifierArgs::Ita(v) = verifier {
                        attest_info.ita_jwks_addr = Some(v.ita_jwks_addr.clone());
                    }
                }
            },
        }
    }

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
