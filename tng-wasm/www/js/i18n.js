// Bilingual string sets for the demo site. Every user-visible string lives here.
const STRINGS = {
  en: {
    "app.title": "TNG JS SDK Demo",
    "app.subtitle": "Interactive playground for the TNG client SDK",
    "app.init.waiting": "Initializing SDK…",
    "app.init.ready": "SDK ready",
    "app.init.failed": "SDK init failed",

    "tng.title": "Settings",
    "tng.as_addr": "Attestation Service URL",
    "tng.as_addr.placeholder": "https://attestation-service.example.com",
    "tng.as_addr.placeholder.ita": "https://api.trustauthority.intel.com",
    "tng.as_provider": "AS Provider",
    "tng.as_provider.coco": "CoCo (Trustee)",
    "tng.as_provider.ita": "Intel Trust Authority (ITA)",
    "tng.api_key": "ITA API Key",
    "tng.api_key.placeholder": "your-ita-api-key",
    "tng.api_key.help": "Required for ITA background-check. Not persisted to localStorage.",
    "tng.ita_jwks_addr": "ITA JWKS URL (optional)",
    "tng.ita_jwks_addr.placeholder": "https://portal.trustauthority.intel.com",
    "tng.policy_ids": "Policy IDs (comma-separated)",
    "tng.model": "Attestation model",
    "tng.model.background_check": "background_check",
    "tng.model.passport": "passport",
    "tng.skip_as_token_cert_verify": "Skip AS token certificate verification",
    "tng.view_config": "View JSON config",

    "tng.as_type": "AS access mode",
    "tng.as_type.restful": "RESTful (external)",
    "tng.as_type.grpc": "gRPC (external)",
    "tng.as_type.builtin": "Builtin (internal)",
    "tng.as_type.builtin.passport_unavailable": "Builtin AS is unavailable in passport mode.",

    "tng.builtin.title": "Builtin AS settings",
    "tng.builtin.policy": "Attestation policy",
    "tng.builtin.policy.hardware_only": "Hardware only (default)",
    "tng.builtin.policy.hardware_with_reference_values": "Hardware + reference values",
    "tng.builtin.policy.trust_all": "Trust all (dev/test only)",
    "tng.builtin.policy.inline": "Inline (base64)",
    "tng.builtin.policy.content": "Policy content (base64)",
    "tng.builtin.policy.content.placeholder": "base64-encoded Rego policy",
    "tng.builtin.reference_values": "Reference values",
    "tng.builtin.reference_values.add": "Add reference value",
    "tng.builtin.reference_values.type": "Type",
    "tng.builtin.reference_values.type.sample": "sample",
    "tng.builtin.reference_values.type.slsa": "slsa",
    "tng.builtin.reference_values.type.release_manifest": "release_manifest",
    "tng.builtin.reference_values.content": "Inline payload (JSON)",
    "tng.builtin.reference_values.remove": "Remove",
    "tng.builtin.hint": "Builtin AS verifies evidence in-process. Reference-value rows whose JSON does not parse are dropped. See trustee ear_default_policy_cpu.rego for the default policy.",

    "ohttp.title": "OHTTP Settings",
    "ohttp.path_default": "Default outer path (path_default)",
    "ohttp.path_default.root": "root (/)",
    "ohttp.path_default.original": "original (request path)",
    "ohttp.path_rewrites": "Path rewrites (path_rewrites)",
    "ohttp.path_rewrites.add": "Add rewrite",
    "ohttp.path_rewrites.match": "match_regex",
    "ohttp.path_rewrites.sub": "substitution",
    "ohttp.path_rewrites.remove": "Remove",

    "tab.general": "General Request",
    "tab.llm": "LLM Inference",

    "general.url": "URL",
    "general.url.placeholder": "https://example.com/path?query=1",
    "general.method": "Method",
    "general.headers": "Headers",
    "general.header.key": "Header",
    "general.header.value": "Value",
    "general.header.add": "Add header",
    "general.header.remove": "Remove",
    "general.body": "Body (JSON)",
    "general.send": "Send",
    "general.body.hidden": "Body is not sent for this method.",

    "llm.base_url": "Base URL",
    "llm.base_url.placeholder": "https://<your-inference-endpoint>",
    "llm.endpoint": "Inference endpoint",
    "llm.token": "API Token",
    "llm.token.placeholder": "token sent as Authorization header",
    "llm.stream": "Stream (SSE)",
    "llm.body": "Body (JSON, editable)",
    "llm.send": "Send",

    "resp.title": "Response",
    "resp.status": "Status",
    "resp.headers": "Headers",
    "resp.body": "Body",
    "resp.attest_info": "Attest info",
    "resp.sse.raw": "Raw SSE",
    "resp.sse.output": "Streamed output",
    "resp.empty": "No response yet.",
    "resp.error": "Error",
  },
  zh: {
    "app.title": "TNG JS SDK 演示",
    "app.subtitle": "TNG 客户端 SDK 交互式演示",
    "app.init.waiting": "正在初始化 SDK…",
    "app.init.ready": "SDK 就绪",
    "app.init.failed": "SDK 初始化失败",

    "tng.title": "设置",
    "tng.as_addr": "证明服务地址 (AS URL)",
    "tng.as_addr.placeholder": "https://attestation-service.example.com",
    "tng.as_addr.placeholder.ita": "https://api.trustauthority.intel.com",
    "tng.as_provider": "证明服务提供方",
    "tng.as_provider.coco": "CoCo (Trustee)",
    "tng.as_provider.ita": "Intel 信任机构 (ITA)",
    "tng.api_key": "ITA API 密钥",
    "tng.api_key.placeholder": "你的 ITA API 密钥",
    "tng.api_key.help": "ITA background-check 必需，不会保存到 localStorage。",
    "tng.ita_jwks_addr": "ITA JWKS 地址（可选）",
    "tng.ita_jwks_addr.placeholder": "https://portal.trustauthority.intel.com",
    "tng.policy_ids": "Policy ID（逗号分隔）",
    "tng.model": "证明模型",
    "tng.model.background_check": "背调模型",
    "tng.model.passport": "护照模型",
    "tng.skip_as_token_cert_verify": "跳过 AS token 证书校验",
    "tng.view_config": "查看 JSON 配置",

    "tng.as_type": "AS 访问方式",
    "tng.as_type.restful": "RESTful（外部）",
    "tng.as_type.grpc": "gRPC（外部）",
    "tng.as_type.builtin": "内置（内部）",
    "tng.as_type.builtin.passport_unavailable": "passport 模式下不可用内置 AS。",

    "tng.builtin.title": "内置 AS 设置",
    "tng.builtin.policy": "证明策略",
    "tng.builtin.policy.hardware_only": "仅硬件（默认）",
    "tng.builtin.policy.hardware_with_reference_values": "硬件 + 参考值",
    "tng.builtin.policy.trust_all": "全部信任（仅开发测试）",
    "tng.builtin.policy.inline": "内联（base64）",
    "tng.builtin.policy.content": "策略内容（base64）",
    "tng.builtin.policy.content.placeholder": "base64 编码的 Rego 策略",
    "tng.builtin.reference_values": "参考值",
    "tng.builtin.reference_values.add": "新增参考值",
    "tng.builtin.reference_values.type": "类型",
    "tng.builtin.reference_values.type.sample": "sample",
    "tng.builtin.reference_values.type.slsa": "slsa",
    "tng.builtin.reference_values.type.release_manifest": "release_manifest",
    "tng.builtin.reference_values.content": "内联 payload（JSON）",
    "tng.builtin.reference_values.remove": "删除",
    "tng.builtin.hint": "内置 AS 在进程内校验 evidence。JSON 无法解析的参考值行会被丢弃。默认策略见 trustee 的 ear_default_policy_cpu.rego。",

    "ohttp.title": "OHTTP 设置",
    "ohttp.path_default": "默认外层路径 (path_default)",
    "ohttp.path_default.root": "root（/）",
    "ohttp.path_default.original": "original（沿用请求路径）",
    "ohttp.path_rewrites": "路径重写规则 (path_rewrites)",
    "ohttp.path_rewrites.add": "新增重写规则",
    "ohttp.path_rewrites.match": "match_regex",
    "ohttp.path_rewrites.sub": "substitution",
    "ohttp.path_rewrites.remove": "删除",

    "tab.general": "通用请求",
    "tab.llm": "大模型推理",

    "general.url": "URL",
    "general.url.placeholder": "https://example.com/path?query=1",
    "general.method": "方法",
    "general.headers": "请求头",
    "general.header.key": "头部名",
    "general.header.value": "头部值",
    "general.header.add": "新增头部",
    "general.header.remove": "删除",
    "general.body": "请求体 (JSON)",
    "general.send": "发送",
    "general.body.hidden": "该方法不发送请求体。",

    "llm.base_url": "Base URL",
    "llm.base_url.placeholder": "https://<你的推理服务地址>",
    "llm.endpoint": "推理端点",
    "llm.token": "API Token",
    "llm.token.placeholder": "作为 Authorization 头发送的 token",
    "llm.stream": "流式 (SSE)",
    "llm.body": "请求体 (JSON，可编辑)",
    "llm.send": "发送",

    "resp.title": "响应",
    "resp.status": "状态",
    "resp.headers": "响应头",
    "resp.body": "响应体",
    "resp.attest_info": "证明信息",
    "resp.sse.raw": "原始 SSE",
    "resp.sse.output": "流式输出",
    "resp.empty": "暂无响应。",
    "resp.error": "错误",
  },
};

let currentLang = localStorage.getItem("tng-demo-lang") || "en";

export function getLang() {
  return currentLang;
}

export function setLang(lang) {
  if (!STRINGS[lang]) return;
  currentLang = lang;
  localStorage.setItem("tng-demo-lang", lang);
  applyI18n();
}

export function t(key) {
  return (STRINGS[currentLang] && STRINGS[currentLang][key]) || STRINGS.en[key] || key;
}

// Render strings into every element marked data-i18n="key" (textContent)
// and data-i18n-placeholder="key" (placeholder attribute).
export function applyI18n() {
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    el.textContent = t(el.getAttribute("data-i18n"));
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
    el.setAttribute("placeholder", t(el.getAttribute("data-i18n-placeholder")));
  });
  const select = document.getElementById("lang-select");
  if (select) select.value = currentLang;
}
