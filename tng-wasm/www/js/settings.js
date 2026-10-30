// Shared settings-card wiring for the demo pages (index.html and chat.html).
// Owns every DOM interaction for the TNG settings card: field visibility per
// (provider, model, asType), the builtin reference-value editor, the ohttp
// path-rewrite editor, the JSON config preview, and the localStorage field
// history. The pure config builder stays in config.js (unit-tested).

import { t } from "./i18n.js";
import {
  buildTngConfig as buildTngConfigFromInputs,
  visibleFields,
  DEFAULT_ITA_API_URL,
} from "./config.js";

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// ---------- TNG config ----------
function readPathRewrites() {
  const out = [];
  document.querySelectorAll("#ohttp-path-rewrites .rewrite-row").forEach((row) => {
    const match = row.querySelector(".r-match").value;
    const sub = row.querySelector(".r-sub").value;
    if (match.trim() || sub.trim()) {
      out.push({ match_regex: match, substitution: sub });
    }
  });
  return out;
}

// Read the builtin reference-value rows into { type, content } objects.
function readBuiltinReferenceValues() {
  const out = [];
  document.querySelectorAll("#tng-builtin-rvs .rv-row").forEach((row) => {
    const type = row.querySelector(".rv-type").value;
    const content = row.querySelector(".rv-content").value;
    out.push({ type, content });
  });
  return out;
}

export function buildTngConfig() {
  // Thin DOM-reading wrapper over the pure builder in config.js. The pure
  // builder owns the field matrix + minimal-config rules and is unit-tested.
  return buildTngConfigFromInputs({
    provider: document.getElementById("tng-as-provider").value,
    model: document.getElementById("tng-model").value,
    asType: document.getElementById("tng-as-type").value,
    asAddr: document.getElementById("tng-as-addr").value.trim(),
    apiKey: document.getElementById("tng-api-key").value.trim(),
    itaJwksAddr: document.getElementById("tng-ita-jwks-addr").value.trim(),
    policyIds: document
      .getElementById("tng-policy-ids")
      .value.split(",")
      .map((s) => s.trim())
      .filter(Boolean),
    skipAsTokenCertVerify: document.getElementById("tng-skip-as-token-cert-verify").checked,
    builtinPolicy: document.getElementById("tng-builtin-policy").value,
    builtinPolicyContent: document.getElementById("tng-builtin-policy-content").value,
    builtinReferenceValues: readBuiltinReferenceValues(),
    ohttpPathDefault: document.getElementById("ohttp-path-default").value,
    ohttpPathRewrites: readPathRewrites(),
  });
}

// ---------- provider/model/asType field visibility ----------
// Toggles which config rows are visible for the (provider, model, asType) combo,
// swaps the AS URL placeholder to hint the ITA API URL, and prefills that URL
// when switching to ITA background_check — but only if the user has not typed a
// value. Visibility rules come from visibleFields() in config.js.
function updateProviderFields() {
  const provider = document.getElementById("tng-as-provider").value;
  const model = document.getElementById("tng-model").value;
  const asTypeSelect = document.getElementById("tng-as-type");
  const asType = asTypeSelect ? asTypeSelect.value : "restful";

  // builtin is unsupported in passport mode (the verifier factory bails).
  // Force-reset to restful and disable the option so it can't be re-picked.
  if (asTypeSelect) {
    const builtinOpt = asTypeSelect.querySelector('option[value="builtin"]');
    if (provider === "coco" && model === "passport") {
      if (asType === "builtin") {
        asTypeSelect.value = "restful";
      }
      if (builtinOpt) builtinOpt.disabled = true;
    } else {
      if (builtinOpt) builtinOpt.disabled = false;
    }
  }
  const effectiveAsType = asTypeSelect ? asTypeSelect.value : "restful";

  const vis = visibleFields(provider, model, effectiveAsType);

  const setWrap = (id, show) => {
    const el = document.getElementById(id);
    if (el) el.hidden = !show;
  };
  setWrap("tng-as-type-wrap", vis.asType);
  setWrap("tng-as-addr-wrap", vis.asAddr);
  setWrap("tng-api-key-wrap", vis.apiKey);
  setWrap("tng-ita-jwks-wrap", vis.itaJwksAddr);
  setWrap("tng-skip-as-token-cert-verify-wrap", vis.skipAsTokenCertVerify);
  setWrap("tng-builtin-settings", vis.builtinPolicy || vis.builtinReferenceValues);
  setWrap(
    "tng-builtin-policy-content-wrap",
    vis.builtinPolicy && document.getElementById("tng-builtin-policy").value === "inline"
  );

  // Swap the AS URL placeholder to hint the ITA API URL in ITA mode.
  const asAddrEl = document.getElementById("tng-as-addr");
  if (asAddrEl) {
    asAddrEl.setAttribute(
      "placeholder",
      provider === "ita"
        ? t("tng.as_addr.placeholder.ita")
        : t("tng.as_addr.placeholder")
    );
  }

  // Clear the auto-prefilled ITA API URL when switching back to CoCo, so it
  // doesn't leak into a CoCo verify config as a bogus AS address. We only
  // clear the exact prefilled value — a user-typed CoCo AS URL is untouched.
  if (provider === "coco" && asAddrEl && asAddrEl.value === DEFAULT_ITA_API_URL) {
    asAddrEl.value = "";
  }

  // Prefill the ITA API URL when switching to ITA background_check, but never
  // overwrite a value the user has typed.
  if (
    provider === "ita" &&
    model !== "passport" &&
    asAddrEl &&
    asAddrEl.value.trim() === ""
  ) {
    asAddrEl.value = DEFAULT_ITA_API_URL;
  }
}

// ITA background_check requires an API key; CoCo grpc requires an as_addr;
// CoCo builtin inline policy requires content. Builtin reference-value rows,
// if non-empty, must parse as JSON. Gate Send on all of these.
export function isFormValid() {
  const provider = document.getElementById("tng-as-provider").value;
  const model = document.getElementById("tng-model").value;
  const asType = document.getElementById("tng-as-type").value;
  if (provider === "ita" && model !== "passport") {
    return document.getElementById("tng-api-key").value.trim() !== "";
  }
  if (provider === "coco") {
    if (asType === "grpc" && document.getElementById("tng-as-addr").value.trim() === "") {
      return false;
    }
    if (asType === "builtin") {
      const policy = document.getElementById("tng-builtin-policy").value;
      if (policy === "inline" && document.getElementById("tng-builtin-policy-content").value.trim() === "") {
        return false;
      }
      // Every non-empty RV row must parse as JSON.
      for (const row of readBuiltinReferenceValues()) {
        const raw = (row.content || "").trim();
        if (!raw) continue;
        try {
          JSON.parse(raw);
        } catch {
          return false;
        }
      }
    }
  }
  return true;
}

// Pages own what happens when validity changes (index.html gates the Send
// buttons on sdkReady && valid); initSettingsCard installs the callback.
let onValidityChange = () => {};

function updateFormValidity() {
  const valid = isFormValid();
  const provider = document.getElementById("tng-as-provider").value;
  const model = document.getElementById("tng-model").value;
  const needKey = provider === "ita" && model !== "passport";
  const hint = document.getElementById("tng-api-key-hint");
  if (hint) hint.hidden = !needKey || valid;
  onValidityChange(valid);
}

// Re-apply the settings-card texts a language switch resets: the ITA AS-URL
// placeholder (applyI18n() overwrites it with the CoCo hint) and the labels of
// existing builtin reference-value rows.
export function refreshSettingsI18n() {
  updateProviderFields();
  refreshRvRowLabels();
  updateFormValidity();
}

// ---------- builtin reference values editor ----------
// Mirrors the headers-list / ohttp-rewrites-list pattern: add/remove rows of
// (type select + JSON textarea). The placeholder swaps per type so the user
// sees an example payload shape for the chosen RV kind.
const RV_CONTENT_PLACEHOLDERS = {
  sample: JSON.stringify({ rvs: { "example-measurement": [] } }, null, 2),
  slsa: JSON.stringify(
    {
      rv_list: [
        {
          id: "test-artifact",
          version: "1.0.0",
          type: "binary",
        },
      ],
    },
    null,
    2,
  ),
  release_manifest: JSON.stringify(
    {
      rv_list: [
        {
          id: "cvm_uki",
          version: "1.0.0",
          type: "uki",
        },
      ],
    },
    null,
    2,
  ),
};

function initBuiltinRvEditor() {
  const list = document.getElementById("tng-builtin-rvs");
  const addBtn = document.getElementById("tng-builtin-add-rv");
  if (!list || !addBtn) return;

  function addRvRow(type = "slsa", content = "") {
    const row = document.createElement("div");
    row.className = "header-row rv-row";
    // Column 1: type select; column 2: JSON textarea spans wide.
    row.style.gridTemplateColumns = "auto 1fr auto";
    row.innerHTML = `
      <select class="rv-type">
        <option value="sample">${t("tng.builtin.reference_values.type.sample")}</option>
        <option value="slsa">${t("tng.builtin.reference_values.type.slsa")}</option>
        <option value="release_manifest">${t("tng.builtin.reference_values.type.release_manifest")}</option>
      </select>
      <textarea class="rv-content" rows="3" spellcheck="false" placeholder="${escapeHtml(RV_CONTENT_PLACEHOLDERS[type] || "")}"></textarea>
      <button type="button" class="rv-rm">${t("tng.builtin.reference_values.remove")}</button>
    `;
    const typeSelect = row.querySelector(".rv-type");
    const contentEl = row.querySelector(".rv-content");
    typeSelect.value = type;
    contentEl.value = content;
    typeSelect.addEventListener("change", () => {
      contentEl.setAttribute("placeholder", RV_CONTENT_PLACEHOLDERS[typeSelect.value] || "");
    });
    contentEl.addEventListener("input", updateFormValidity);
    row.querySelector(".rv-rm").addEventListener("click", () => {
      row.remove();
      updateFormValidity();
    });
    list.appendChild(row);
  }

  addBtn.addEventListener("click", () => addRvRow());
}

// Re-label existing RV rows on language switch (option text + remove button).
function refreshRvRowLabels() {
  document.querySelectorAll("#tng-builtin-rvs .rv-row").forEach((row) => {
    const sel = row.querySelector(".rv-type");
    if (sel) {
      const v = sel.value;
      sel.innerHTML = `
        <option value="sample">${t("tng.builtin.reference_values.type.sample")}</option>
        <option value="slsa">${t("tng.builtin.reference_values.type.slsa")}</option>
        <option value="release_manifest">${t("tng.builtin.reference_values.type.release_manifest")}</option>
      `;
      sel.value = v;
    }
    const rm = row.querySelector(".rv-rm");
    if (rm) rm.textContent = t("tng.builtin.reference_values.remove");
  });
}

function initProviderFields() {
  const provider = document.getElementById("tng-as-provider");
  const model = document.getElementById("tng-model");
  const asType = document.getElementById("tng-as-type");
  const builtinPolicy = document.getElementById("tng-builtin-policy");
  const apiKey = document.getElementById("tng-api-key");
  for (const el of [provider, model, asType, builtinPolicy, apiKey].filter(Boolean)) {
    el.addEventListener("change", () => {
      updateProviderFields();
      updateFormValidity();
    });
  }
  // Re-check validity as the user types the API key / policy content / RV JSON.
  if (apiKey) apiKey.addEventListener("input", updateFormValidity);
  const policyContent = document.getElementById("tng-builtin-policy-content");
  if (policyContent) policyContent.addEventListener("input", updateFormValidity);
  initBuiltinRvEditor();
  updateProviderFields();
  updateFormValidity();
}

// ---------- ohttp path options ----------
function initOhttpDemo() {
  const rewritesList = document.getElementById("ohttp-path-rewrites");
  const addBtn = document.getElementById("ohttp-add-rewrite");
  if (!rewritesList || !addBtn) return;

  function addRewriteRow(match = "", sub = "") {
    const row = document.createElement("div");
    row.className = "header-row rewrite-row";
    row.innerHTML = `
      <input type="text" class="r-match" value="${escapeHtml(match)}" placeholder="${escapeHtml(t("ohttp.path_rewrites.match"))}" />
      <input type="text" class="r-sub" value="${escapeHtml(sub)}" placeholder="${escapeHtml(t("ohttp.path_rewrites.sub"))}" />
      <button type="button" class="r-rm">${t("ohttp.path_rewrites.remove")}</button>
    `;
    row.querySelector(".r-rm").addEventListener("click", () => {
      row.remove();
      renderConfigPreview();
    });
    rewritesList.appendChild(row);
  }

  addBtn.addEventListener("click", () => {
    addRewriteRow();
    renderConfigPreview();
  });
}

// ---------- config preview ----------
function renderConfigPreview() {
  const pre = document.getElementById("config-preview");
  if (!pre || pre.hidden) return;
  try {
    pre.textContent = JSON.stringify(buildTngConfig(), null, 2);
  } catch (e) {
    pre.textContent = "Failed to build config: " + (e.message || e);
  }
}

function initConfigPreview() {
  const btn = document.getElementById("view-config-btn");
  const pre = document.getElementById("config-preview");
  if (!btn || !pre) return;
  btn.addEventListener("click", () => {
    pre.hidden = !pre.hidden;
    if (!pre.hidden) renderConfigPreview();
  });
  // Live-update the preview as any config input changes (events bubble up to the wrapper).
  const wrap = document.getElementById("tng-config-wrap");
  if (wrap) {
    wrap.addEventListener("input", renderConfigPreview);
    wrap.addEventListener("change", renderConfigPreview);
  }
}

// ---------- field history (localStorage + datalist) ----------
// Persists the last value and a short history for URL-ish inputs so they
// survive a page refresh and can be picked from a dropdown. Pages pass the
// ids of the fields they own.
const HISTORY_MAX = 10;

function fieldKey(id) {
  return "tng-demo-field:" + id;
}

function loadFieldHistory(id) {
  try {
    const obj = JSON.parse(localStorage.getItem(fieldKey(id)) || "{}");
    if (!Array.isArray(obj.history)) obj.history = [];
    return { last: obj.last || "", history: obj.history };
  } catch {
    return { last: "", history: [] };
  }
}

function saveFieldHistory(id, obj) {
  localStorage.setItem(fieldKey(id), JSON.stringify(obj));
}

function renderFieldDatalist(id, history) {
  const dl = document.getElementById("dl-" + id);
  if (!dl) return;
  dl.innerHTML = history.map((v) => `<option value="${escapeHtml(v)}">`).join("");
}

export function restoreField(id) {
  const el = document.getElementById(id);
  if (!el) return;
  const { last, history } = loadFieldHistory(id);
  // Only restore a saved value; leave the HTML default in place otherwise.
  if (last) el.value = last;
  renderFieldDatalist(id, history);
}

export function commitField(id) {
  const el = document.getElementById(id);
  if (!el) return;
  const v = el.value.trim();
  if (!v) return;
  const obj = loadFieldHistory(id);
  obj.last = v;
  obj.history = [v, ...obj.history.filter((x) => x !== v)].slice(0, HISTORY_MAX);
  saveFieldHistory(id, obj);
  renderFieldDatalist(id, obj.history);
}

export function initPersistedFields(ids) {
  ids.forEach((id) => {
    restoreField(id);
    const el = document.getElementById(id);
    if (el) {
      // Commit on blur so typed values become history/persisted even without
      // sending a request.
      el.addEventListener("blur", () => commitField(id));
    }
  });
}

export function initSettingsCard({ onValidityChange: cb } = {}) {
  if (cb) onValidityChange = cb;
  initOhttpDemo();
  initConfigPreview();
  initProviderFields();
}
