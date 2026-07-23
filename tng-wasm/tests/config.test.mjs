// Unit tests for the pure config builder. Runs under `node --test` — no browser,
// no DOM, no wasm SDK. Covers every (provider, model) combo in the field matrix
// from docs/superpowers/specs/2026-07-10-www-ita-provider-support-design.md.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  buildTngConfig,
  visibleFields,
  DEFAULT_ITA_API_URL,
  DEFAULT_ITA_JWKS_URL,
} from "../www/js/config.js";

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

test("visibleFields: coco background_check restful shows asType + asAddr + skip, hides apiKey/itaJwks/builtin", () => {
  assert.deepEqual(visibleFields("coco", "background_check"), {
    asType: true,
    asAddr: true,
    apiKey: false,
    itaJwksAddr: false,
    skipAsTokenCertVerify: true,
    builtinPolicy: false,
    builtinReferenceValues: false,
  });
});

test("visibleFields: coco builtin shows asType + builtinPolicy + builtinRV, hides asAddr + skip", () => {
  assert.deepEqual(visibleFields("coco", "background_check", "builtin"), {
    asType: true,
    asAddr: false,
    apiKey: false,
    itaJwksAddr: false,
    skipAsTokenCertVerify: false,
    builtinPolicy: true,
    builtinReferenceValues: true,
  });
});

test("visibleFields: coco grpc shows asType + asAddr + skip, hides builtin", () => {
  assert.deepEqual(visibleFields("coco", "background_check", "grpc"), {
    asType: true,
    asAddr: true,
    apiKey: false,
    itaJwksAddr: false,
    skipAsTokenCertVerify: true,
    builtinPolicy: false,
    builtinReferenceValues: false,
  });
});

test("visibleFields: ita background_check hides asType + builtin", () => {
  assert.deepEqual(visibleFields("ita", "background_check"), {
    asType: false,
    asAddr: true,
    apiKey: true,
    itaJwksAddr: true,
    skipAsTokenCertVerify: false,
    builtinPolicy: false,
    builtinReferenceValues: false,
  });
});

test("visibleFields: ita passport hides asType + asAddr + apiKey + skip + builtin", () => {
  assert.deepEqual(visibleFields("ita", "passport"), {
    asType: false,
    asAddr: false,
    apiKey: false,
    itaJwksAddr: true,
    skipAsTokenCertVerify: false,
    builtinPolicy: false,
    builtinReferenceValues: false,
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

test("coco builtin background_check: hardware_with_reference_values policy", () => {
  const cfg = buildTngConfig({
    ...base,
    provider: "coco",
    asType: "builtin",
    builtinPolicy: "hardware_with_reference_values",
  });
  assert.deepEqual(cfg.verify, {
    model: "background_check",
    as_type: "builtin",
    attestation_policy: { type: "hardware_with_reference_values" },
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
    builtinReferenceValues: [{ type: "slsa", content: "" }],
  });
  assert.deepEqual(cfg.verify, {
    model: "background_check",
    as_type: "builtin",
  });
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
