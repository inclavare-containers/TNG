use anyhow::{Context as _, Result};
use gloo::utils::format::JsValueSerdeExt;
use serde::Serialize;
use tng::config::capabilities::ConfigCapabilities;
use tng::{
    config::ra::{
        CocoConverterArgs, CocoVerifierArgs, ConverterArgs, RaArgs, VerifierArgs, VerifyArgs,
    },
    AttestationResult,
};
use wasm_bindgen::prelude::*;

use super::to_js_error;

/// The `as_type` tag of a CoCo converter variant.
fn coco_converter_as_type(converter: &CocoConverterArgs) -> &'static str {
    match converter {
        CocoConverterArgs::Restful { .. } => "restful",
        CocoConverterArgs::Grpc { .. } => "grpc",
        CocoConverterArgs::Builtin { .. } => "builtin",
    }
}

/// The `as_type` tag of a CoCo verifier variant.
fn coco_verifier_as_type(verifier: &CocoVerifierArgs) -> &'static str {
    match verifier {
        CocoVerifierArgs::Restful { .. } => "restful",
        CocoVerifierArgs::Grpc { .. } => "grpc",
        CocoVerifierArgs::Builtin => "builtin",
    }
}

/// Address and policy IDs a CoCo converter would send to the AS.
fn coco_converter_service(converter: &CocoConverterArgs) -> (Option<String>, Option<Vec<String>>) {
    match converter {
        CocoConverterArgs::Restful {
            as_addr,
            policy_ids,
            ..
        }
        | CocoConverterArgs::Grpc {
            as_addr,
            policy_ids,
            ..
        } => (Some(as_addr.clone()), Some(policy_ids.clone())),
        CocoConverterArgs::Builtin { .. } => (None, None),
    }
}

/// Address and policy IDs a CoCo verifier consults.
fn coco_verifier_service(verifier: &CocoVerifierArgs) -> (Option<String>, Option<Vec<String>>) {
    match verifier {
        CocoVerifierArgs::Restful {
            as_addr,
            policy_ids,
            ..
        }
        | CocoVerifierArgs::Grpc {
            as_addr,
            policy_ids,
            ..
        } => (as_addr.clone(), Some(policy_ids.clone())),
        CocoVerifierArgs::Builtin => (None, None),
    }
}

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
                VerifierArgs::Coco(coco) => {
                    attest_info.as_provider = Some("coco".into());
                    let caps =
                        ConfigCapabilities::new("coco", "passport", coco_verifier_as_type(coco));
                    let (as_addr, policy_ids) = coco_verifier_service(coco);
                    if caps.as_addr {
                        attest_info.as_addr = as_addr;
                    }
                    if caps.policy_ids {
                        attest_info.policy_ids = policy_ids;
                    }
                }
                VerifierArgs::Ita(ita) => {
                    attest_info.as_provider = Some("ita".into());
                    let caps = ConfigCapabilities::new("ita", "passport", "restful");
                    if caps.ita_jwks_addr {
                        attest_info.ita_jwks_addr = Some(ita.ita_jwks_addr.clone());
                    }
                    if caps.policy_ids {
                        attest_info.policy_ids = Some(ita.policy_ids.clone());
                    }
                }
            },
            VerifyArgs::BackgroundCheck {
                converter,
                verifier,
            } => match converter {
                ConverterArgs::Coco(coco) => {
                    attest_info.as_provider = Some("coco".into());
                    let caps = ConfigCapabilities::new(
                        "coco",
                        "background_check",
                        coco_converter_as_type(coco),
                    );
                    let (as_addr, policy_ids) = coco_converter_service(coco);
                    if caps.as_addr {
                        attest_info.as_addr = as_addr;
                    }
                    if caps.policy_ids {
                        attest_info.policy_ids = policy_ids;
                    }
                }
                ConverterArgs::Ita(ita) => {
                    attest_info.as_provider = Some("ita".into());
                    let caps = ConfigCapabilities::new("ita", "background_check", "restful");
                    if caps.as_addr {
                        attest_info.as_addr = Some(ita.as_addr.clone());
                    }
                    if caps.policy_ids {
                        attest_info.policy_ids = Some(ita.policy_ids.clone());
                    }
                    if caps.ita_jwks_addr {
                        if let VerifierArgs::Ita(v) = verifier {
                            attest_info.ita_jwks_addr = Some(v.ita_jwks_addr.clone());
                        }
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
