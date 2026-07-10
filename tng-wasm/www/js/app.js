import { t, applyI18n, setLang, getLang } from "./i18n.js";
import { HTTP_METHODS, BODY_METHODS, METHOD_EXAMPLE_BODIES, LLM_ENDPOINTS, LLM_EXAMPLE_BODIES } from "./examples.js";
import { readSseStream } from "./sse.js";

// SDK is imported from ./tng_wasm.js (copied into www/ at assemble time by CI
// or by `make www-demo`). The import is dynamic so the page still loads if the
// file is missing, showing a clear error in the init badge.
let tng_init, tng_fetch;
let sdkState = "waiting"; // "waiting" | "ready" | "failed"

// ---------- i18n ----------
function initI18n() {
  const select = document.getElementById("lang-select");
  select.value = getLang();
  select.addEventListener("change", () => {
    setLang(select.value);
    updateInitBadge();
    refreshEmptyResponses();
  });
  applyI18n();
  updateInitBadge();
  refreshEmptyResponses();
}

// Refresh the "no response yet" placeholder on response containers that are
// still empty. Containers with a rendered response carry data-empty="false"
// and are left untouched, so switching language no longer wipes the result.
function refreshEmptyResponses() {
  for (const id of ["general-response", "llm-response"]) {
    const el = document.getElementById(id);
    if (el && el.dataset.empty === "true") {
      el.textContent = t("resp.empty");
    }
  }
}

// ---------- SDK init ----------
function updateInitBadge() {
  const badge = document.getElementById("init-badge");
  if (!badge) return;
  badge.textContent = t("app.init." + sdkState);
  badge.className = "badge badge-" + sdkState;
}

async function initSdk() {
  try {
    const mod = await import("../tng_wasm.js");
    tng_init = mod.default;
    tng_fetch = mod.fetch;
    await tng_init();
    sdkState = "ready";
    updateInitBadge();
    setSendEnabled(true);
  } catch (err) {
    console.error("SDK init failed", err);
    sdkState = "failed";
    updateInitBadge();
  }
}

function setSendEnabled(enabled) {
  document.getElementById("general-send").disabled = !enabled;
  document.getElementById("llm-send").disabled = !enabled;
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

function buildTngConfig() {
  const asAddr = document.getElementById("tng-as-addr").value.trim();
  const policyIds = document
    .getElementById("tng-policy-ids")
    .value.split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const model = document.getElementById("tng-model").value;
  const verify = { model, as_addr: asAddr, policy_ids: policyIds };
  if (document.getElementById("tng-skip-as-token-cert-verify").checked) {
    // Skips TLS cert verification when the verifier fetches the AS token.
    // Matches the flat `verify.skip_as_token_cert_verify` field in tng/src/config/ra.rs.
    verify.skip_as_token_cert_verify = true;
  }
  // OHTTP path options (tng/src/config/ingress.rs OHttpArgs). Non-default values
  // are emitted; defaults (path_default=root, no rewrites) are omitted to keep
  // the config minimal — same philosophy as skip_as_token_cert_verify above.
  const ohttp = {};
  if (document.getElementById("ohttp-path-default").value === "original") {
    ohttp.path_default = "original";
  }
  const rewrites = readPathRewrites();
  if (rewrites.length) ohttp.path_rewrites = rewrites;
  return { ohttp, verify };
}

// ---------- tabs ----------
function initTabs() {
  const tabs = document.querySelectorAll(".tab");
  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      tabs.forEach((t2) => t2.classList.remove("active"));
      tab.classList.add("active");
      document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
      document.getElementById("tab-" + tab.dataset.tab).classList.add("active");
    });
  });
}

// ---------- response rendering helpers ----------
function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function prettyJson(value) {
  try {
    return escapeHtml(JSON.stringify(value, null, 2));
  } catch {
    return escapeHtml(String(value));
  }
}

async function readBodyText(response) {
  try {
    return await response.text();
  } catch (e) {
    return `(failed to read body: ${e.message || e})`;
  }
}

function maybePretty(text, contentType) {
  if (contentType && contentType.includes("application/json")) {
    try {
      return prettyJson(JSON.parse(text));
    } catch {
      // fall through
    }
  }
  return escapeHtml(text);
}

function renderResponseHeaders(response) {
  let rows = "<table>";
  response.headers.forEach((value, key) => {
    rows += `<tr><td class="label">${escapeHtml(key)}</td><td>${escapeHtml(value)}</td></tr>`;
  });
  rows += "</table>";
  return rows;
}

// ---------- response panel helpers ----------
// All long content (body, streamed output, raw SSE, attest info) is wrapped in
// <pre class="code-block"> blocks that scroll horizontally instead of expanding
// the response card. Sections are grouped consistently: a status bar, then
// labelled sections, with raw SSE / attest info collapsible by default.

function respStatusBar(res) {
  const cls = res.ok ? "ok" : "err";
  return `<div class="resp-status ${cls}"><span class="resp-code">${res.status}</span><span class="resp-text">${escapeHtml(res.statusText)}</span></div>`;
}

function respSection(label, contentHtml) {
  return `<div class="resp-section"><div class="resp-label">${escapeHtml(label)}</div>${contentHtml}</div>`;
}

function respCollapsible(label, contentHtml) {
  return `<details class="resp-section resp-collapsible"><summary>${escapeHtml(label)}</summary>${contentHtml}</details>`;
}

function respPending(out) {
  out.dataset.empty = "false";
  out.innerHTML = `<div class="resp-status"><span class="resp-text">${escapeHtml(t("resp.title"))}…</span></div>`;
}

function renderResponseError(out, message) {
  out.dataset.empty = "false";
  out.innerHTML =
    `<div class="resp-status err"><span class="resp-code">${escapeHtml(t("resp.error"))}</span></div>` +
    respSection(t("resp.error"), `<pre class="code-block">${escapeHtml(message)}</pre>`);
}

// ---------- general request demo ----------
function initGeneralDemo() {
  const methodSelect = document.getElementById("general-method");
  for (const m of HTTP_METHODS) {
    const opt = document.createElement("option");
    opt.value = m;
    opt.textContent = m;
    methodSelect.appendChild(opt);
  }
  methodSelect.value = "GET";

  const headersList = document.getElementById("general-headers");
  const addHeaderBtn = document.getElementById("general-add-header");
  const bodyField = document.getElementById("general-body-field");
  const bodyHidden = document.getElementById("general-body-hidden");
  const bodyEl = document.getElementById("general-body");

  function addHeaderRow(key = "", value = "") {
    const row = document.createElement("div");
    row.className = "header-row";
    row.innerHTML = `
      <input type="text" class="h-key" value="${escapeHtml(key)}" />
      <input type="text" class="h-val" value="${escapeHtml(value)}" />
      <button type="button" class="h-rm">${t("general.header.remove")}</button>
    `;
    row.querySelector(".h-rm").addEventListener("click", () => row.remove());
    headersList.appendChild(row);
  }

  function syncBodyVisibility() {
    const hasBody = BODY_METHODS.has(methodSelect.value);
    bodyField.style.display = hasBody ? "" : "none";
    bodyHidden.hidden = hasBody;
    if (hasBody && bodyEl.value.trim() === "") {
      bodyEl.value = METHOD_EXAMPLE_BODIES[methodSelect.value] || "";
    }
  }

  methodSelect.addEventListener("change", syncBodyVisibility);
  addHeaderBtn.addEventListener("click", () => addHeaderRow());

  // Seed a Content-Type header by default for body methods.
  addHeaderRow("Content-Type", "application/json");
  syncBodyVisibility();

  document.getElementById("general-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    await sendGeneral();
  });

  async function sendGeneral() {
    const out = document.getElementById("general-response");
    respPending(out);
    commitField("general-url");
    commitField("tng-as-addr");
    const url = document.getElementById("general-url").value.trim();
    const method = methodSelect.value;
    const headers = {};
    headersList.querySelectorAll(".header-row").forEach((row) => {
      const k = row.querySelector(".h-key").value.trim();
      const v = row.querySelector(".h-val").value.trim();
      if (k) headers[k] = v;
    });
    const init = { method, headers };
    if (BODY_METHODS.has(method)) {
      init.body = bodyEl.value;
    }
    try {
      const res = await tng_fetch(url, init, buildTngConfig());
      await renderGeneralResponse(res);
    } catch (err) {
      renderResponseError(out, err.message || String(err));
    }
  }

  async function renderGeneralResponse(res) {
    const out = document.getElementById("general-response");
    out.dataset.empty = "false";
    const contentType = res.headers.get("content-type") || "";
    const bodyText = await readBodyText(res);
    const attest = res.attest_info;
    let html = respStatusBar(res);
    html += respSection(t("resp.headers"), `<div class="resp-headers">${renderResponseHeaders(res)}</div>`);
    html += respSection(t("resp.body"), `<pre class="code-block">${maybePretty(bodyText, contentType)}</pre>`);
    html += respCollapsible(t("resp.attest_info"), `<pre class="code-block">${prettyJson(attest)}</pre>`);
    out.innerHTML = html;
  }
}

// ---------- llm demo ----------
function initLlmDemo() {
  const endpointSelect = document.getElementById("llm-endpoint");
  for (const ep of LLM_ENDPOINTS) {
    const opt = document.createElement("option");
    opt.value = ep;
    opt.textContent = ep;
    endpointSelect.appendChild(opt);
  }
  endpointSelect.value = LLM_ENDPOINTS[0];

  const bodyEl = document.getElementById("llm-body");
  const streamCheckbox = document.getElementById("llm-stream");

  function loadExampleBody() {
    bodyEl.value = LLM_EXAMPLE_BODIES[endpointSelect.value] || "";
    syncStreamFlagFromBody();
  }

  // Keep the checkbox and the body's "stream" field in sync.
  function syncStreamFlagFromBody() {
    try {
      const obj = JSON.parse(bodyEl.value);
      streamCheckbox.checked = !!obj.stream;
    } catch {
      // body isn't valid JSON yet; leave checkbox as-is
    }
  }

  function writeStreamFlagToBody(checked) {
    try {
      const obj = JSON.parse(bodyEl.value);
      obj.stream = checked;
      bodyEl.value = JSON.stringify(obj, null, 2);
    } catch {
      // body isn't valid JSON; don't clobber the user's edits
    }
  }

  endpointSelect.addEventListener("change", loadExampleBody);
  streamCheckbox.addEventListener("change", () => writeStreamFlagToBody(streamCheckbox.checked));
  bodyEl.addEventListener("blur", syncStreamFlagFromBody);

  loadExampleBody();

  document.getElementById("llm-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    await sendLlm();
  });

  async function sendLlm() {
    const out = document.getElementById("llm-response");
    respPending(out);
    commitField("llm-base-url");
    commitField("tng-as-addr");
    const baseUrl = document.getElementById("llm-base-url").value.trim().replace(/\/+$/, "");
    const endpoint = endpointSelect.value;
    const url = baseUrl + endpoint;
    const token = document.getElementById("llm-token").value;
    const headers = {
      "Content-Type": "application/json",
    };
    if (token) {
      headers["Authorization"] = "Bearer " + token;
    }
    const body = bodyEl.value;

    let streamRequested = false;
    try {
      streamRequested = !!JSON.parse(body).stream;
    } catch {
      // ignore parse errors
    }

    try {
      const res = await tng_fetch(url, { method: "POST", headers, body }, buildTngConfig());
      await renderLlmResponse(res, { stream: streamRequested });
    } catch (err) {
      renderResponseError(out, err.message || String(err));
    }
  }

  async function renderLlmResponse(res, { stream }) {
    const out = document.getElementById("llm-response");
    out.dataset.empty = "false";
    const contentType = res.headers.get("content-type") || "";
    const isSse = stream || contentType.includes("text/event-stream");

    let html = respStatusBar(res);

    if (isSse && res.body) {
      html += respSection(t("resp.sse.output"), `<pre class="code-block" id="llm-stream-out"></pre>`);
      html += respCollapsible(t("resp.sse.raw"), `<pre class="code-block" id="llm-stream-raw"></pre>`);
      out.innerHTML = html;
      const streamOut = document.getElementById("llm-stream-out");
      const streamRaw = document.getElementById("llm-stream-raw");
      await readSseStream(res, {
        onDelta: (text) => {
          streamOut.append(text);
          streamOut.scrollTop = streamOut.scrollHeight;
        },
        onRaw: (eventStr) => {
          streamRaw.append(eventStr + "\n\n");
          streamRaw.scrollTop = streamRaw.scrollHeight;
        },
      });
      // Append attest_info after the stream completes.
      out.insertAdjacentHTML("beforeend", respCollapsible(t("resp.attest_info"), `<pre class="code-block">${prettyJson(res.attest_info)}</pre>`));
    } else {
      const bodyText = await readBodyText(res);
      html += respSection(t("resp.body"), `<pre class="code-block">${maybePretty(bodyText, contentType)}</pre>`);
      html += respCollapsible(t("resp.attest_info"), `<pre class="code-block">${prettyJson(res.attest_info)}</pre>`);
      out.innerHTML = html;
    }
  }
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
// Persists the last value and a short history for the AS URL / Base URL / URL
// inputs so they survive a page refresh and can be picked from a dropdown.
const HISTORY_MAX = 10;
const PERSISTED_FIELDS = ["tng-as-addr", "general-url", "llm-base-url"];

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

function restoreField(id) {
  const el = document.getElementById(id);
  if (!el) return;
  const { last, history } = loadFieldHistory(id);
  // Only restore a saved value; leave the HTML default in place otherwise.
  if (last) el.value = last;
  renderFieldDatalist(id, history);
}

function commitField(id) {
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

function initPersistedFields() {
  PERSISTED_FIELDS.forEach((id) => {
    restoreField(id);
    const el = document.getElementById(id);
    if (el) {
      // Commit on blur so typed values become history/persisted even without
      // sending a request.
      el.addEventListener("blur", () => commitField(id));
    }
  });
}

// ---------- boot ----------
function boot() {
  initI18n();
  initTabs();
  initOhttpDemo();
  initConfigPreview();
  initGeneralDemo();
  initLlmDemo();
  initPersistedFields();
  initSdk();
}

boot();
