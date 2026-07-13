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

test("visibleFields: coco shows asAddr + skip, hides apiKey + itaJwks", () => {
  assert.deepEqual(visibleFields("coco", "background_check"), {
    asAddr: true,
    apiKey: false,
    itaJwksAddr: false,
    skipAsTokenCertVerify: true,
  });
});

test("visibleFields: ita background_check shows asAddr + apiKey + itaJwks, hides skip", () => {
  assert.deepEqual(visibleFields("ita", "background_check"), {
    asAddr: true,
    apiKey: true,
    itaJwksAddr: true,
    skipAsTokenCertVerify: false,
  });
});

test("visibleFields: ita passport hides asAddr + apiKey + skip, shows itaJwks", () => {
  assert.deepEqual(visibleFields("ita", "passport"), {
    asAddr: false,
    apiKey: false,
    itaJwksAddr: true,
    skipAsTokenCertVerify: false,
  });
});
