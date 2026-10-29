// Pure builder for OpenAI-compatible /v1/chat/completions request bodies.
// No DOM access. Imported by chat.js (browser) and tests/chat-logic.test.mjs
// (Node). Only role/content are copied per turn so UI-side bookkeeping fields
// can never leak into the request body.
export function buildChatRequestBody(messages, model, stream = true) {
  return {
    model,
    messages: messages.map(({ role, content }) => ({ role, content })),
    stream,
  };
}
