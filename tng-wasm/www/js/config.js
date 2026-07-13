// Pure TNG verify/ohttp config builder for the demo. No DOM access, no side
// effects — imported by app.js (browser) and by tests/config.test.mjs (Node).
//
// The field matrix (which verify fields each provider×model consumes) mirrors
// tng-wasm/src/fetch/attestation.rs:51-105 and is documented in
// docs/superpowers/specs/2026-07-10-www-ita-provider-support-design.md.

export const DEFAULT_ITA_API_URL = "https://api.trustauthority.intel.com";
export const DEFAULT_ITA_JWKS_URL = "https://portal.trustauthority.intel.com";

// Which form rows should be visible for a given (provider, model).
// Centralized so the visibility rule cannot drift from buildTngConfig().
export function visibleFields(provider, model) {
  const isIta = provider === "ita";
  const isPassport = model === "passport";
  return {
    // coco: both models; ita: background_check only (passport verify is JWKS-only).
    asAddr: !isIta || !isPassport,
    // ita background_check only: the converter needs the key to call Intel's cloud.
    apiKey: isIta && !isPassport,
    // ita both models (advanced/optional).
    itaJwksAddr: isIta,
    // coco only — ITA verifies via JWKS JWT validation, not an AS token cert.
    skipAsTokenCertVerify: !isIta,
  };
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
    ohttpPathDefault = "root",
    ohttpPathRewrites = [],
  } = inputs;

  const verify = { model, policy_ids: policyIds };

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
  } else {
    // coco (trustee): as_provider defaults to "coco" server-side, omitted here.
    // Skips TLS cert verification when the verifier fetches the AS token
    // (flat verify.skip_as_token_cert_verify field in tng/src/config/ra.rs).
    if (asAddr) verify.as_addr = asAddr;
    if (skipAsTokenCertVerify) verify.skip_as_token_cert_verify = true;
  }

  const ohttp = {};
  if (ohttpPathDefault === "original") ohttp.path_default = "original";
  if (ohttpPathRewrites.length) ohttp.path_rewrites = ohttpPathRewrites;

  return { ohttp, verify };
}
