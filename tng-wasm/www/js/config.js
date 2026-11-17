// Pure TNG verify/ohttp config builder for the demo. No DOM access; imported
// by app.js (browser) and by tests/config.test.mjs (Node). Policy kinds and
// the config-field matrix are loaded once from the wasm SDK at init.

export const DEFAULT_ITA_API_URL = "https://api.trustauthority.intel.com";
export const DEFAULT_ITA_JWKS_URL = "https://portal.trustauthority.intel.com";

// Policy kinds and the reference-value rule are owned by Rust
// (PolicyConfig::capabilities) and exported by the wasm SDK as
// policy_capabilities(). This module only consumes that list.
let policyCapabilities = null;

// Load the policy capabilities from the initialized wasm SDK. Must be awaited
// before building a builtin converter config.
export async function initPolicyCapabilities(sdk) {
  const capabilities = await sdk.policy_capabilities();
  if (!Array.isArray(capabilities)) {
    throw new Error("policy_capabilities() did not return an array");
  }
  policyCapabilities = capabilities;
  return capabilities;
}

function findPolicyCapability(type) {
  return (policyCapabilities || []).find((cap) => cap.type === type) || null;
}

// The provider x model x as_type field matrix is owned by Rust
// (ConfigCapabilities) and exported as config_capabilities(). Cache the
// function itself so visibleFields stays synchronous.
let configCapabilities = null;

export function initConfigCapabilities(sdk) {
  if (typeof sdk.config_capabilities !== "function") {
    throw new Error("config_capabilities() is not exported by the SDK");
  }
  configCapabilities = sdk.config_capabilities;
}

export function configCapabilitiesReady() {
  return configCapabilities !== null;
}

// Which form rows should be visible for a given (provider, model, asType).
// The matrix itself lives in tng (ConfigCapabilities); this forwards to the
// exported capability. asType defaults to "restful" (the server-side default)
// so existing two-arg callers behave as before.
export function visibleFields(provider, model, asType = "restful") {
  if (!configCapabilities) {
    throw new Error("config capabilities not loaded");
  }
  return configCapabilities(provider, model, asType);
}

// Build a single CoCo reference value (inline payload) from a { type, content } row.
// Returns null for empty or unparseable rows so the caller can drop them.
function buildBuiltinReferenceValue(row) {
  const type = row.type;
  const raw = (row && typeof row.content === "string" ? row.content : "").trim();
  if (!raw) return null;
  let content;
  try {
    content = JSON.parse(raw);
  } catch {
    return null;
  }
  return { type, payload: { type: "inline", content } };
}

// Build the CoCo builtin attestation_policy object, or null when the selected
// kind is the default (omitted per the minimal-config rule) or carries empty
// content. The kind list and content rule come from Rust.
function buildBuiltinPolicy(cap, content) {
  if (cap.is_default) return null;
  if (cap.has_content) {
    return content && content.trim() ? { type: cap.type, content: content.trim() } : null;
  }
  return { type: cap.type };
}

// Build the { ohttp, verify } config object passed to tng_fetch().
// Non-defaults are omitted to preserve the demo's minimal-config convention:
// as_provider defaults to "coco" server-side (tng/src/config/ra.rs
// inject_tag_defaults), so it is only emitted for "ita". Empty optional fields
// are omitted too. OHTTP path options (tng/src/config/ingress.rs OHttpArgs):
// path_default=root and no rewrites are defaults and omitted.
export function buildTngConfig(inputs) {
  const {
    provider = "coco",
    model,
    asAddr = "",
    apiKey = "",
    itaJwksAddr = "",
    policyIds = [],
    skipAsTokenCertVerify = false,
    asType = "restful",
    builtinPolicy = "hardware_only",
    builtinPolicyContent = "",
    builtinReferenceValues = [],
    ohttpPathDefault = "root",
    ohttpPathRewrites = [],
  } = inputs;

  const verify = { model };

  if (provider === "ita") {
    verify.as_provider = "ita";
    // ita background_check: as_addr = ITA API URL, api_key required by the converter.
    // ita passport: verifier is JWKS-only — as_addr and api_key are not consumed,
    // so they are never emitted even if stale values sit in the form.
    if (model !== "passport") {
      if (asAddr) verify.as_addr = asAddr;
      if (apiKey) verify.api_key = apiKey;
    }
    if (itaJwksAddr) verify.ita_jwks_addr = itaJwksAddr;
    verify.policy_ids = policyIds;
  } else if (asType === "builtin") {
    // coco builtin (internal AS): no as_addr, no skip, no policy_ids. The
    // converter/verifier carry attestation_policy + reference_values instead;
    // defaults (hardware_only + empty RVs) are omitted.
    verify.as_type = "builtin";
    const cap = findPolicyCapability(builtinPolicy);
    if (!cap) {
      throw new Error(
        `unknown builtin attestation policy "${builtinPolicy}"; policy capabilities not loaded`
      );
    }
    const policy = buildBuiltinPolicy(cap, builtinPolicyContent);
    if (policy) verify.attestation_policy = policy;
    // Only kinds whose rules consume reference values accept them; the bundled
    // templates reject a non-empty list.
    if (cap.accepts_reference_values) {
      const rvs = builtinReferenceValues
        .map(buildBuiltinReferenceValue)
        .filter(Boolean);
      if (rvs.length) verify.reference_values = rvs;
    }
  } else {
    // coco restful (default) or grpc. policy_ids is consumed by the AS.
    verify.policy_ids = policyIds;
    if (asType === "grpc") verify.as_type = "grpc";
    // restful is the server-side default → as_type omitted.
    if (asAddr) verify.as_addr = asAddr;
    // Skips TLS cert verification when the verifier fetches the AS token
    // (flat verify.skip_as_token_cert_verify field in tng/src/config/ra.rs).
    if (skipAsTokenCertVerify) verify.skip_as_token_cert_verify = true;
  }

  const ohttp = {};
  if (ohttpPathDefault === "original") ohttp.path_default = "original";
  if (ohttpPathRewrites.length) ohttp.path_rewrites = ohttpPathRewrites;

  return { ohttp, verify };
}
