// Unit tests for the pure claims-view helpers. Runs under `node --test`: no
// browser, no DOM, no wasm SDK.
import { test } from "node:test";
import assert from "node:assert/strict";
import { decodeJwtClaims, tierLabel, summarizeClaims } from "../www/js/claims-view.js";

function b64url(obj) {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}

test("decodeJwtClaims decodes a 3-segment JWT payload", () => {
  const claims = { exp: 123, submods: { cpu0: { "ear.status": "affirming" } } };
  assert.deepEqual(decodeJwtClaims(`aaa.${b64url(claims)}.bbb`), claims);
});

test("decodeJwtClaims returns null on malformed input", () => {
  assert.equal(decodeJwtClaims("not-a-jwt"), null);
  assert.equal(decodeJwtClaims(`aaa.${"!!!!not-base64!!!!"}.bbb`), null);
  assert.equal(decodeJwtClaims(`aaa.${b64url({ a: 1 })}`), null); // missing segment
  assert.equal(decodeJwtClaims(`.${b64url("{invalid json")}.bbb`), null);
});

test("tierLabel maps the EAR tier ranges", () => {
  assert.equal(tierLabel(-1), "none");
  assert.equal(tierLabel(1), "none");
  assert.equal(tierLabel(2), "affirming");
  assert.equal(tierLabel(32), "affirming");
  assert.equal(tierLabel(33), "warning");
  assert.equal(tierLabel(96), "warning");
  assert.equal(tierLabel(97), "contraindicated");
  assert.equal(tierLabel(1000), "contraindicated");
  assert.equal(tierLabel("x"), null);
  assert.equal(tierLabel(null), null);
});

test("summarizeClaims extracts verifiers, trustworthiness and registered claims", () => {
  const claims = {
    exp: 2000000000,
    iss: "builtin-as",
    submods: {
      cpu0: {
        "ear.status": "affirming",
        "ear.appraisal-policy-id": "policy-1",
        "ear.trustworthiness-vector": { hardware: 2, executables: 33 },
      },
    },
  };
  const s = summarizeClaims(claims);
  assert.equal(s.status, "warning"); // worst tier across dimensions
  assert.deepEqual(s.verifiers, [
    {
      id: "cpu0",
      earStatus: "affirming",
      policyId: "policy-1",
      trustworthiness: [
        { dimension: "hardware", value: 2, tier: "affirming" },
        { dimension: "executables", value: 33, tier: "warning" },
      ],
    },
  ]);
  assert.equal(s.exp, 2000000000);
  assert.equal(s.iss, "builtin-as");
});

test("summarizeClaims handles missing submods and non-object inputs", () => {
  assert.deepEqual(summarizeClaims({}), {
    status: null,
    verifiers: [],
    exp: null,
    nbf: null,
    iss: null,
  });
  assert.equal(summarizeClaims(null).status, null);
  // submods present but not an object
  assert.deepEqual(summarizeClaims({ submods: 5 }).verifiers, []);
});

test("summarizeClaims picks contraindicated over warning as overall status", () => {
  const s = summarizeClaims({
    submods: { v: { "ear.status": "contraindicated", "ear.trustworthiness-vector": { a: 2 } } },
  });
  assert.equal(s.status, "contraindicated");
});
