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
  if (sdkReady) maybeAutoVerify();
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

// ---------- verification panel (stubs) ----------
// The panel task fills these in: render the EAR claim summary from the last
// response, re-label panel texts on language switch, and re-verify on boot.
function refreshPanelFromResponse() {}
function renderPanelI18n() {}
function maybeAutoVerify() {}

// ---------- boot ----------
function boot() {
  initI18n();
  initChat();
  // Restore persisted values before the settings card runs its provider-switch
  // field-clear, so a stale ITA-prefilled as_addr cannot survive into a CoCo
  // config at boot (same order as app.js).
  initPersistedFields(["chat-base-url", "chat-model", "tng-as-addr"]);
  initSettingsCard({ onValidityChange: () => updateSendState() });
  initSdk();
}

boot();
