import { t, applyI18n, setLang, getLang } from "./i18n.js";
import { HTTP_METHODS, BODY_METHODS, METHOD_EXAMPLE_BODIES, LLM_ENDPOINTS, LLM_EXAMPLE_BODIES } from "./examples.js";
import { readSseStream } from "./sse.js";
import {
  buildTngConfig,
  isFormValid,
  refreshSettingsI18n,
  initPersistedFields,
  initSettingsCard,
  commitField,
} from "./settings.js";

// SDK is imported from ./tng_wasm.js (copied into www/ at assemble time by CI
// or by `make www-demo`). The import is dynamic so the page still loads if the
// file is missing, showing a clear error in the init badge.
let tng_init, tng_fetch;
let sdkState = "waiting"; // "waiting" | "ready" | "failed"
let sdkReady = false; // mirrors sdkState === "ready"; used to gate Send on form validity

// ---------- i18n ----------
function initI18n() {
  const select = document.getElementById("lang-select");
  select.value = getLang();
  select.addEventListener("change", () => {
    setLang(select.value);
    updateInitBadge();
    refreshEmptyResponses();
    // Re-apply the settings-card texts applyI18n() reset: the ITA AS-URL
    // placeholder and the builtin reference-value row labels.
    refreshSettingsI18n();
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
    sdkReady = true;
    updateInitBadge();
    updateSendState();
  } catch (err) {
    console.error("SDK init failed", err);
    sdkState = "failed";
    sdkReady = false;
    updateInitBadge();
  }
}

function updateSendState() {
  // sdkReady + settings validity gate the Send buttons, exactly as before.
  const enabled = sdkReady && isFormValid();
  document.getElementById("general-send").disabled = !enabled;
  document.getElementById("llm-send").disabled = !enabled;
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

// ---------- boot ----------
function boot() {
  initI18n();
  initTabs();
  // Restore persisted values before the settings card runs its provider-switch
  // field-clear, so a stale ITA-prefilled as_addr cannot survive into a CoCo
  // config at boot (this was the pre-refactor order).
  initPersistedFields(["general-url", "llm-base-url", "tng-as-addr"]);
  initSettingsCard({ onValidityChange: () => updateSendState() });
  initGeneralDemo();
  initLlmDemo();
  initSdk();
}

boot();
