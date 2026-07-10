// Example request bodies. Provider-neutral; no internal product names.

// One example body per HTTP method that carries a body.
export const METHOD_EXAMPLE_BODIES = {
  POST: JSON.stringify({ key: "value", number: 42 }, null, 2),
  PUT: JSON.stringify({ key: "updated-value" }, null, 2),
  PATCH: JSON.stringify({ key: "patched-value" }, null, 2),
};

// One example body per LLM inference endpoint. Model names are generic.
export const LLM_EXAMPLE_BODIES = {
  "/v1/completions": JSON.stringify(
    {
      model: "qwen2.5-3b-instruct",
      prompt: "Tell me about remote attestation.",
      temperature: 0.0,
      max_tokens: 1024,
      stream: true,
    },
    null,
    2,
  ),
  "/v1/chat/completions": JSON.stringify(
    {
      model: "qwen2.5-3b-instruct",
      messages: [{ role: "user", content: "What is TNG?" }],
      temperature: 0.0,
      max_tokens: 1024,
      stream: true,
    },
    null,
    2,
  ),
  "/v1/embeddings": JSON.stringify(
    {
      model: "text-embedding-v1",
      input: "remote attestation",
    },
    null,
    2,
  ),
};

// HTTP methods offered in the general demo.
export const HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

// Methods that normally carry a request body.
export const BODY_METHODS = new Set(["POST", "PUT", "PATCH"]);

// LLM endpoints offered in the LLM demo.
export const LLM_ENDPOINTS = ["/v1/completions", "/v1/chat/completions", "/v1/embeddings"];
