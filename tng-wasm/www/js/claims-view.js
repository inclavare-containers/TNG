// Pure helpers turning an attestation-result JWT's claims into panel data.
// No DOM access, no SDK dependency; imported by chat.js (browser) and by
// tests/claims-view.test.mjs (Node).
//
// Claim shape (builtin-as TDX token): the JWT payload holds registered claims
// (exp, nbf, iss) plus a `submods` object keyed by verifier id (e.g. cpu0);
// each verifier carries FLAT keys "ear.status", "ear.trustworthiness-vector"
// (object mapping dimension name to a tier number) and
// "ear.appraisal-policy-id".

// ear crate tier map: [-1,1] -> None (no claim), [2,32] -> Affirming,
// [33,96] -> Warning, 97+ -> Contraindicated.
export function tierLabel(value) {
  if (typeof value !== "number" || Number.isNaN(value)) return null;
  if (value >= 97) return "contraindicated";
  if (value >= 33) return "warning";
  if (value >= 2) return "affirming";
  if (value >= -1) return "none";
  return null;
}

const TIER_RANK = { contraindicated: 3, warning: 2, affirming: 1 };

// Locally decode a JWT's payload segment (base64url + JSON). Returns null on
// any malformed input; no signature check (the wasm side verified it).
export function decodeJwtClaims(token) {
  if (typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length < 3) return null;
  let json;
  try {
    json = atob(parts[1].replace(/-/g, "+").replace(/_/g, "/"));
  } catch {
    return null;
  }
  try {
    const obj = JSON.parse(json);
    return obj && typeof obj === "object" ? obj : null;
  } catch {
    return null;
  }
}

function trustworthinessList(vector) {
  if (!vector || typeof vector !== "object") return [];
  return Object.entries(vector)
    .filter(([, v]) => typeof v === "number")
    .map(([dimension, value]) => ({ dimension, value, tier: tierLabel(value) }));
}

function verifierSummary(id, submod) {
  if (!submod || typeof submod !== "object") return null;
  const hasEar = Object.keys(submod).some((k) => k.startsWith("ear."));
  if (!hasEar) return null;
  return {
    id,
    earStatus: typeof submod["ear.status"] === "string" ? submod["ear.status"] : null,
    policyId:
      typeof submod["ear.appraisal-policy-id"] === "string"
        ? submod["ear.appraisal-policy-id"]
        : null,
    trustworthiness: trustworthinessList(submod["ear.trustworthiness-vector"]),
  };
}

export function summarizeClaims(claims) {
  const out = { status: null, verifiers: [], exp: null, nbf: null, iss: null };
  if (!claims || typeof claims !== "object") return out;

  if (typeof claims.exp === "number") out.exp = claims.exp;
  if (typeof claims.nbf === "number") out.nbf = claims.nbf;
  if (typeof claims.iss === "string") out.iss = claims.iss;

  const submods = claims.submods;
  if (submods && typeof submods === "object") {
    for (const [id, submod] of Object.entries(submods)) {
      const v = verifierSummary(id, submod);
      if (v) out.verifiers.push(v);
    }
  }

  // Overall status: the worst tier seen across every verifier, counting both
  // its ear.status verdict and every trustworthiness dimension. "none" tiers
  // make no claim and never downgrade the overall.
  let worst = 0;
  for (const v of out.verifiers) {
    const own = TIER_RANK[v.earStatus] || 0;
    if (own > worst) worst = own;
    for (const t of v.trustworthiness) {
      const rank = TIER_RANK[t.tier] || 0;
      if (rank > worst) worst = rank;
    }
  }
  for (const [tier, rank] of Object.entries(TIER_RANK)) {
    if (rank === worst && worst > 0) out.status = tier;
  }
  return out;
}
