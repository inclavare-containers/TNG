// Unit tests for the pure config builder. Runs under `node --test`: no browser,
// no DOM, no wasm SDK. The field matrix itself is covered by Rust tests; these
// tests exercise the builder and the capability delegation.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  buildTngConfig,
  initConfigCapabilities,
  initPolicyCapabilities,
  visibleFields,
  DEFAULT_ITA_API_URL,
  DEFAULT_ITA_JWKS_URL,
} from "../www/js/config.js";

// Rust owns the policy-kind list and the reference-value rule; the browser
// gets them from the wasm SDK. Node cannot load the wasm module, so inject the
// same shape the export produces.
await initPolicyCapabilities({
  policy_capabilities: async () => [
    { type: "hardware_only", name: "Hardware only", accepts_reference_values: false, is_default: true, has_content: false },
    { type: "hardware_only_strict", name: "Hardware only, strict", accepts_reference_values: false, is_default: false, has_content: false },
    { type: "modules", name: "Modules", accepts_reference_values: false, is_default: false, has_content: false },
    { type: "trust_all", name: "Trust all", accepts_reference_values: false, is_default: false, has_content: false },
    { type: "inline", name: "Inline", accepts_reference_values: true, is_default: false, has_content: true },
  ],
});

// The field matrix is owned by tng (ConfigCapabilities) and exported by the
// wasm SDK. Node cannot load the wasm module, so inject a stub. The matrix
// itself is covered by tng's Rust tests.
initConfigCapabilities({
  config_capabilities: (provider, model, asType) => ({ provider, model, asType }),
});

const base = { model: "background_check", policyIds: ["default"] };

test("coco background_check: omits as_provider, emits as_addr + skip when set", () => {
  const cfg = buildTngConfig({
    ...base,
    provider: "coco",
    asAddr: "http://127.0.0.1:8080/",
    skipAsTokenCertVerify: true,
  });
  assert.deepEqual(cfg, {
    ohttp: {},
    verify: {
      model: "background_check",
      policy_ids: ["default"],
      as_addr: "http://127.0.0.1:8080/",
      skip_as_token_cert_verify: true,
    },
  });
});

test("coco background_check: omits as_addr when empty, omits skip when unchecked", () => {
  const cfg = buildTngConfig({ ...base, provider: "coco", asAddr: "" });
  assert.deepEqual(cfg, {
    ohttp: {},
    verify: { model: "background_check", policy_ids: ["default"] },
  });
});

test("ita background_check: emits as_provider + as_addr + api_key + ita_jwks_addr", () => {
  const cfg = buildTngConfig({
    ...base,
    provider: "ita",
    asAddr: DEFAULT_ITA_API_URL,
    apiKey: "secret-key",
    itaJwksAddr: DEFAULT_ITA_JWKS_URL,
  });
  assert.deepEqual(cfg, {
    ohttp: {},
    verify: {
      model: "background_check",
      policy_ids: ["default"],
      as_provider: "ita",
      as_addr: "https://api.trustauthority.intel.com",
      api_key: "secret-key",
      ita_jwks_addr: "https://portal.trustauthority.intel.com",
    },
  });
});

test("ita background_check: omits api_key/ita_jwks_addr when empty, keeps as_provider", () => {
  const cfg = buildTngConfig({
    ...base,
    provider: "ita",
    asAddr: DEFAULT_ITA_API_URL,
  });
  assert.deepEqual(cfg, {
    ohttp: {},
    verify: {
      model: "background_check",
      policy_ids: ["default"],
      as_provider: "ita",
      as_addr: "https://api.trustauthority.intel.com",
    },
  });
});

test("ita passport: emits as_provider + ita_jwks_addr only, never as_addr/api_key", () => {
  const cfg = buildTngConfig({
    model: "passport",
    policyIds: ["default"],
    provider: "ita",
    asAddr: "should-be-ignored",
    apiKey: "should-be-ignored",
    itaJwksAddr: DEFAULT_ITA_JWKS_URL,
  });
  assert.deepEqual(cfg, {
    ohttp: {},
    verify: {
      model: "passport",
      policy_ids: ["default"],
      as_provider: "ita",
      ita_jwks_addr: "https://portal.trustauthority.intel.com",
    },
  });
});

test("ohttp: emits path_default only when original, path_rewrites when present", () => {
  const cfg = buildTngConfig({
    ...base,
    provider: "coco",
    ohttpPathDefault: "original",
    ohttpPathRewrites: [{ match_regex: "^/x", substitution: "/y" }],
  });
  assert.deepEqual(cfg, {
    ohttp: {
      path_default: "original",
      path_rewrites: [{ match_regex: "^/x", substitution: "/y" }],
    },
    verify: { model: "background_check", policy_ids: ["default"] },
  });
});

test("visibleFields: forwards provider/model/asType to the SDK capability export", () => {
  assert.deepEqual(visibleFields("coco", "background_check", "grpc"), {
    provider: "coco",
    model: "background_check",
    asType: "grpc",
  });
});

test("visibleFields: defaults asType to restful", () => {
  assert.deepEqual(visibleFields("ita", "passport"), {
    provider: "ita",
    model: "passport",
    asType: "restful",
  });
});

test("visibleFields: returns the SDK capability object unchanged", () => {
  const marker = { asType: "marker" };
  initConfigCapabilities({ config_capabilities: () => marker });
  assert.equal(visibleFields("ignored", "ignored", "ignored"), marker);
  initConfigCapabilities({
    config_capabilities: (provider, model, asType) => ({ provider, model, asType }),
  });
});

// ---- CoCo as_type: grpc ----

test("coco grpc background_check: emits as_type grpc + as_addr", () => {
  const cfg = buildTngConfig({
    ...base,
    provider: "coco",
    asType: "grpc",
    asAddr: "http://127.0.0.1:5000/",
  });
  assert.deepEqual(cfg, {
    ohttp: {},
    verify: {
      model: "background_check",
      policy_ids: ["default"],
      as_type: "grpc",
      as_addr: "http://127.0.0.1:5000/",
    },
  });
});

test("coco grpc background_check: emits as_type grpc even without as_addr (validity gated in app.js)", () => {
  const cfg = buildTngConfig({
    ...base,
    provider: "coco",
    asType: "grpc",
    asAddr: "",
  });
  assert.deepEqual(cfg, {
    ohttp: {},
    verify: {
      model: "background_check",
      policy_ids: ["default"],
      as_type: "grpc",
    },
  });
});

test("coco grpc background_check: emits skip_as_token_cert_verify when checked", () => {
  const cfg = buildTngConfig({
    ...base,
    provider: "coco",
    asType: "grpc",
    asAddr: "http://127.0.0.1:5000/",
    skipAsTokenCertVerify: true,
  });
  assert.deepEqual(cfg.verify, {
    model: "background_check",
    policy_ids: ["default"],
    as_type: "grpc",
    as_addr: "http://127.0.0.1:5000/",
    skip_as_token_cert_verify: true,
  });
});

// ---- CoCo as_type: builtin (internal AS) ----

test("coco builtin background_check: default policy + no RVs emits only as_type builtin, omits policy_ids", () => {
  const cfg = buildTngConfig({
    ...base,
    provider: "coco",
    asType: "builtin",
  });
  assert.deepEqual(cfg, {
    ohttp: {},
    verify: {
      model: "background_check",
      as_type: "builtin",
    },
  });
});

test("coco builtin background_check: trust_all policy emits attestation_policy", () => {
  const cfg = buildTngConfig({
    ...base,
    provider: "coco",
    asType: "builtin",
    builtinPolicy: "trust_all",
  });
  assert.deepEqual(cfg.verify, {
    model: "background_check",
    as_type: "builtin",
    attestation_policy: { type: "trust_all" },
  });
});

test("coco builtin background_check: hardware_only_strict policy", () => {
  const cfg = buildTngConfig({
    ...base,
    provider: "coco",
    asType: "builtin",
    builtinPolicy: "hardware_only_strict",
  });
  assert.deepEqual(cfg.verify, {
    model: "background_check",
    as_type: "builtin",
    attestation_policy: { type: "hardware_only_strict" },
  });
});

test("coco builtin background_check: inline policy emits attestation_policy with content", () => {
  const cfg = buildTngConfig({
    ...base,
    provider: "coco",
    asType: "builtin",
    builtinPolicy: "inline",
    builtinPolicyContent: "cGFja2FnZSBwb2xpY3kK",
  });
  assert.deepEqual(cfg.verify, {
    model: "background_check",
    as_type: "builtin",
    attestation_policy: { type: "inline", content: "cGFja2FnZSBwb2xpY3kK" },
  });
});

test("coco builtin background_check: inline policy with empty content omits attestation_policy", () => {
  const cfg = buildTngConfig({
    ...base,
    provider: "coco",
    asType: "builtin",
    builtinPolicy: "inline",
    builtinPolicyContent: "",
  });
  assert.deepEqual(cfg.verify, {
    model: "background_check",
    as_type: "builtin",
  });
});

test("coco builtin background_check: one slsa RV with inline JSON content", () => {
  const cfg = buildTngConfig({
    ...base,
    provider: "coco",
    asType: "builtin",
    builtinPolicy: "inline",
    builtinReferenceValues: [
      { type: "slsa", content: '{"rv_list":[{"id":"a","version":"1.0.0","type":"binary"}]}' },
    ],
  });
  assert.deepEqual(cfg.verify, {
    model: "background_check",
    as_type: "builtin",
    reference_values: [
      {
        type: "slsa",
        payload: { type: "inline", content: { rv_list: [{ id: "a", version: "1.0.0", type: "binary" }] } },
      },
    ],
  });
});

test("coco builtin background_check: sample RV with object content", () => {
  const cfg = buildTngConfig({
    ...base,
    provider: "coco",
    asType: "builtin",
    builtinPolicy: "inline",
    builtinReferenceValues: [
      { type: "sample", content: '{"rvs":{"example-measurement":[]}}' },
    ],
  });
  assert.deepEqual(cfg.verify, {
    model: "background_check",
    as_type: "builtin",
    reference_values: [
      {
        type: "sample",
        payload: { type: "inline", content: { rvs: { "example-measurement": [] } } },
      },
    ],
  });
});

test("coco builtin background_check: RV row with invalid JSON is dropped", () => {
  const cfg = buildTngConfig({
    ...base,
    provider: "coco",
    asType: "builtin",
    builtinPolicy: "inline",
    builtinReferenceValues: [
      { type: "slsa", content: "not valid json" },
      { type: "sample", content: '{"rvs":{}}' },
    ],
  });
  assert.deepEqual(cfg.verify, {
    model: "background_check",
    as_type: "builtin",
    reference_values: [
      {
        type: "sample",
        payload: { type: "inline", content: { rvs: {} } },
      },
    ],
  });
});

test("coco builtin background_check: empty RV rows are dropped, reference_values omitted when all empty", () => {
  const cfg = buildTngConfig({
    ...base,
    provider: "coco",
    asType: "builtin",
    builtinPolicy: "inline",
    builtinReferenceValues: [{ type: "slsa", content: "" }],
  });
  assert.deepEqual(cfg.verify, {
    model: "background_check",
    as_type: "builtin",
  });
});

test("coco builtin background_check: bundled policy drops RV rows (only inline consumes them)", () => {
  const cfg = buildTngConfig({
    ...base,
    provider: "coco",
    asType: "builtin",
    builtinPolicy: "hardware_only_strict",
    builtinReferenceValues: [
      { type: "sample", content: '{"rvs":{"example-measurement":[]}}' },
    ],
  });
  assert.deepEqual(cfg.verify, {
    model: "background_check",
    as_type: "builtin",
    attestation_policy: { type: "hardware_only_strict" },
  });
});

test("coco builtin background_check: inline policy emits both attestation_policy and reference_values", () => {
  const cfg = buildTngConfig({
    ...base,
    provider: "coco",
    asType: "builtin",
    builtinPolicy: "inline",
    builtinPolicyContent: "cGFja2FnZSBwb2xpY3kK",
    builtinReferenceValues: [
      { type: "sample", content: '{"rvs":{"example-measurement":[]}}' },
    ],
  });
  assert.deepEqual(cfg.verify, {
    model: "background_check",
    as_type: "builtin",
    attestation_policy: { type: "inline", content: "cGFja2FnZSBwb2xpY3kK" },
    reference_values: [
      {
        type: "sample",
        payload: { type: "inline", content: { rvs: { "example-measurement": [] } } },
      },
    ],
  });
});

test("coco builtin background_check: unknown policy is rejected", () => {
  assert.throws(
    () =>
      buildTngConfig({
        ...base,
        provider: "coco",
        asType: "builtin",
        builtinPolicy: "not_a_policy",
      }),
    /unknown builtin attestation policy/
  );
});

test("coco restful background_check: asType omitted still produces restful-default config (backward compat)", () => {
  const cfg = buildTngConfig({
    ...base,
    provider: "coco",
    asAddr: "http://127.0.0.1:8080/",
  });
  assert.deepEqual(cfg, {
    ohttp: {},
    verify: {
      model: "background_check",
      policy_ids: ["default"],
      as_addr: "http://127.0.0.1:8080/",
    },
  });
});
