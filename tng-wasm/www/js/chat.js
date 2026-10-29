import { t, applyI18n, setLang, getLang } from "./i18n.js";
import { readSseStream } from "./sse.js";
import {
  initSettingsCard,
  buildTngConfig,
  isFormValid,
  refreshSettingsI18n,
  initPersistedFields,
  commitField,
} from "./settings.js";
import { buildChatRequestBody } from "./chat-logic.js";
import { decodeJwtClaims, summarizeClaims, tierLabel } from "./claims-view.js";

// SDK is imported from ./tng_wasm.js (copied into www/ at assemble time by CI
// or by `make www-demo`), same dynamic-import pattern as app.js.
let tng_init, tng_fetch, tng_verify;
let sdkState = "waiting"; // "waiting" | "ready" | "failed"
let sdkReady = false;

// Conversation history sent as the messages array on every request.
const conversation = [];
let sending = false;

// ---------- i18n ----------
function initI18n() {
  const select = document.getElementById("lang-select");
  select.value = getLang();
  select.addEventListener("change", () => {
    setLang(select.value);
    updateInitBadge();
    refreshChatEmpty();
    // Re-apply the settings-card texts applyI18n() reset: the ITA AS-URL
    // placeholder and the builtin reference-value row labels.
    refreshSettingsI18n();
    renderPanelI18n();
  });
  applyI18n();
  updateInitBadge();
  refreshChatEmpty();
}

function refreshChatEmpty() {
  const log = document.getElementById("chat-log");
  if (log && log.dataset.empty === "true") {
    log.textContent = t("chat.empty");
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
    tng_verify = mod.verify;
    await tng_init();
    sdkState = "ready";
    sdkReady = true;
  } catch (err) {
    console.error("SDK init failed", err);
    sdkState = "failed";
    sdkReady = false;
  }
  updateInitBadge();
  updateSendState();
  // Covers the failed path too: the panel badge then reads "waiting" instead
  // of staying blank.
  maybeAutoVerify();
}

function updateSendState() {
  const btn = document.getElementById("chat-send");
  if (btn) btn.disabled = !sdkReady || !isFormValid() || sending;
}

// ---------- chat ----------
function appendMsg(role) {
  const log = document.getElementById("chat-log");
  log.dataset.empty = "false";
  if (log.dataset.emptyApplied !== "true") {
    // Drop the "say something" placeholder before the first message.
    log.textContent = "";
    log.dataset.emptyApplied = "true";
  }
  const el = document.createElement("div");
  el.className = "msg msg-" + role;
  log.appendChild(el);
  log.scrollTop = log.scrollHeight;
  return el;
}

function autoscroll(log) {
  const nearBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 80;
  if (nearBottom) log.scrollTop = log.scrollHeight;
}

async function sendChat() {
  if (sending || !sdkReady || !isFormValid()) return;
  const input = document.getElementById("chat-input");
  const text = input.value.trim();
  const baseUrl = document.getElementById("chat-base-url").value.trim().replace(/\/+$/, "");
  const model = document.getElementById("chat-model").value.trim();
  if (!text || !baseUrl || !model) return;

  input.value = "";
  commitField("chat-base-url");
  commitField("chat-model");
  commitField("tng-as-addr");

  conversation.push({ role: "user", content: text });
  appendMsg("user").textContent = text;

  const bubble = appendMsg("assistant");
  const log = document.getElementById("chat-log");
  sending = true;
  updateSendState();

  const url = baseUrl + "/v1/chat/completions";
  const headers = { "Content-Type": "application/json" };
  const token = document.getElementById("chat-token").value;
  if (token) headers["Authorization"] = "Bearer " + token;
  const body = JSON.stringify(buildChatRequestBody(conversation, model, true));

  let streamed = false;
  try {
    const res = await tng_fetch(url, { method: "POST", headers, body }, buildTngConfig());
    if (!res.ok) {
      const errText = await res.text().catch(() => "");
      throw new Error(`HTTP ${res.status}: ${errText.slice(0, 300)}`);
    }
    const contentType = res.headers.get("content-type") || "";
    if (contentType.includes("text/event-stream") && res.body) {
      await readSseStream(res, {
        onDelta: (delta) => {
          streamed = true;
          bubble.append(delta);
          autoscroll(log);
        },
      });
    } else {
      const data = await res.json();
      const content = data?.choices?.[0]?.message?.content;
      bubble.textContent = typeof content === "string" ? content : JSON.stringify(data, null, 2);
    }
    conversation.push({ role: "assistant", content: bubble.textContent });
    refreshPanelFromResponse(res);
  } catch (err) {
    // Some deltas rendered means the stream broke mid-response; everything
    // else is a request-level failure.
    const label = streamed ? t("chat.stream.error") : t("chat.assistant.error");
    bubble.textContent = (bubble.textContent ? bubble.textContent + "\n" : "") +
      (label + ": " + (err.message || String(err)));
    bubble.classList.add("msg-error");
  } finally {
    sending = false;
    updateSendState();
  }
}

function clearConversation() {
  conversation.length = 0;
  const log = document.getElementById("chat-log");
  log.textContent = t("chat.empty");
  log.dataset.empty = "true";
  log.dataset.emptyApplied = "false";
}

function initChat() {
  document.getElementById("chat-form").addEventListener("submit", (e) => {
    e.preventDefault();
    sendChat();
  });
  document.getElementById("chat-input").addEventListener("keydown", (e) => {
    // Enter sends; Shift+Enter inserts a newline.
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendChat();
    }
  });
  document.getElementById("chat-clear").addEventListener("click", clearConversation);
  // Validity can change as the user edits settings; re-gate the Send button.
  document.getElementById("tng-config-wrap").addEventListener("input", updateSendState);
  document.getElementById("tng-config-wrap").addEventListener("change", updateSendState);
}

// ---------- verification panel ----------
// The panel has four sources of state: waiting (settings incomplete),
// verifying, a VerificationInfo from tng_verify, or an error. Per-message
// responses refresh it from res.attest_info (raw token string), decoded
// locally with the same claims-view helpers.
let verifyInFlight = false;
let panelState = "waiting";
// Last claims rendered into the verifier list; kept so a language switch can
// re-render the baked-in label texts (verifier prefix, tier chips).
let panelClaims = null;

function panelBadgeKey(state) {
  return {
    waiting: "panel.status.waiting",
    verifying: "panel.status.verifying",
    verified: "panel.status.verified",
    failed: "panel.status.failed",
    nora: "panel.status.nora",
  }[state] || "panel.status.waiting";
}

function setPanelState(state) {
  panelState = state;
  const badge = document.getElementById("verify-badge");
  if (!badge) return;
  badge.textContent = t(panelBadgeKey(state));
  // Reuse the three visual classes styles.css already defines (init badge):
  // verified is green, failed is red, every other state stays neutral.
  badge.className =
    "badge " +
    (state === "verified" ? "badge-ready" : state === "failed" ? "badge-failed" : "badge-waiting");
}

function fmtTime(epochSeconds) {
  if (typeof epochSeconds !== "number") return "";
  return new Date(epochSeconds * 1000).toLocaleString();
}

function chatUrl() {
  return (
    document.getElementById("chat-base-url").value.trim().replace(/\/+$/, "") +
    "/v1/chat/completions"
  );
}

function canVerify() {
  return (
    sdkReady &&
    isFormValid() &&
    document.getElementById("chat-base-url").value.trim() !== ""
  );
}

function maybeAutoVerify() {
  if (canVerify()) runVerify();
  else setPanelState("waiting");
}

async function runVerify() {
  if (verifyInFlight || !canVerify()) return;
  verifyInFlight = true;
  setPanelState("verifying");
  document.getElementById("verify-error").hidden = true;
  try {
    const info = await tng_verify(chatUrl(), buildTngConfig());
    renderPanel(info);
  } catch (err) {
    renderPanelError(err);
  } finally {
    verifyInFlight = false;
  }
}

function renderPanelError(err) {
  setPanelState("failed");
  const box = document.getElementById("verify-error");
  box.hidden = false;
  box.textContent = err?.message || String(err);
  // Clear the last appraisal so a failed verify leaves no stale claims or
  // verifier chips under the error badge.
  renderVerifiers(null);
  document.getElementById("verify-claims").textContent = "";
}

function renderPanel(info) {
  setPanelState(info.verified ? "verified" : "nora");

  document.getElementById("verify-time").textContent = info.verified
    ? new Date().toLocaleString()
    : "";
  document.getElementById("verify-endpoint").textContent = info.endpoint || "";

  // AS summary: provider label plus address when present. NoRa leaves both
  // unset; the row stays blank rather than claiming a built-in AS that the
  // config never used (a real builtin AS reports its provider label).
  const asBits = [];
  if (info.as_provider) asBits.push(info.as_provider === "ita" ? "ITA" : "CoCo");
  if (info.as_addr) asBits.push(info.as_addr);
  if (info.policy_ids && info.policy_ids.length) asBits.push(info.policy_ids.join(", "));
  document.getElementById("verify-as").textContent = asBits.join(" · ");

  document.getElementById("verify-exp").textContent = fmtTime(info.exp);

  renderVerifiers(info.claims);
  // claims absent but token present means the wasm-side payload decode failed;
  // show the raw token rather than nothing.
  document.getElementById("verify-claims").textContent = info.claims
    ? JSON.stringify(info.claims, null, 2)
    : info.token || "";
}

function renderVerifiers(claims) {
  panelClaims = claims || null;
  const ul = document.getElementById("verify-verifiers");
  ul.textContent = "";
  if (!claims) return;
  const summary = summarizeClaims(claims);
  for (const v of summary.verifiers) {
    const li = document.createElement("li");
    const meta = document.createElement("div");
    meta.className = "verifier-meta";
    const idEl = document.createElement("span");
    idEl.textContent = `${t("panel.verifier")}: ${v.id}`;
    const statusEl = document.createElement("span");
    // ear.status may be a non-tier verdict string (e.g. "expired"); show it as-is.
    statusEl.textContent = v.earStatus || "";
    meta.append(idEl, statusEl);
    li.append(meta);
    for (const tw of v.trustworthiness) {
      const tier = tierLabel(tw.value);
      const chip = document.createElement("span");
      chip.className = "tier tier-" + (tier || "none");
      chip.textContent = `${tw.dimension}: ${t("panel.trust." + (tier || "none"))}`;
      li.append(chip);
    }
    if (v.policyId) {
      const p = document.createElement("div");
      p.textContent = v.policyId;
      li.append(p);
    }
    ul.appendChild(li);
  }
}

// Refresh the panel from a chat response's attest_info: the token string is
// decoded locally; the endpoint/AS/exp fields keep the current values.
function refreshPanelFromResponse(res) {
  const token = res?.attest_info?.attestation_result;
  if (typeof token !== "string" || !token) {
    setPanelState("nora");
    return;
  }
  const claims = decodeJwtClaims(token);
  setPanelState("verified");
  document.getElementById("verify-time").textContent = new Date().toLocaleString();
  renderVerifiers(claims);
  document.getElementById("verify-claims").textContent = claims
    ? JSON.stringify(claims, null, 2)
    : token;
}

// Re-label the panel after a language switch from the tracked state: the
// badge plus the verifier list, whose labels were baked in at render time.
function renderPanelI18n() {
  setPanelState(panelState);
  renderVerifiers(panelClaims);
}

function initPanel() {
  document.getElementById("reverify-btn").addEventListener("click", runVerify);
  // Re-run verification when the endpoint changes (blur) and when settings
  // validity flips (e.g. AS provider switch invalidates the old result).
  document.getElementById("chat-base-url").addEventListener("blur", maybeAutoVerify);
  document.getElementById("tng-config-wrap").addEventListener("change", maybeAutoVerify);
}

// ---------- boot ----------
function boot() {
  initI18n();
  initChat();
  initPanel();
  // Restore persisted values before the settings card runs its provider-switch
  // field-clear, so a stale ITA-prefilled as_addr cannot survive into a CoCo
  // config at boot (same order as app.js).
  initPersistedFields(["chat-base-url", "chat-model", "tng-as-addr"]);
  initSettingsCard({ onValidityChange: () => updateSendState() });
  initSdk();
}

boot();
