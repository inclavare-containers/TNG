// Unit tests for the pure chat request builder. Runs under `node --test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildChatRequestBody } from "../www/js/chat-logic.js";

test("builds an OpenAI-compatible chat completion body with full history", () => {
  const body = buildChatRequestBody(
    [
      { role: "user", content: "hi" },
      { role: "assistant", content: "hello" },
      { role: "user", content: "bye" },
    ],
    "qwen2.5-3b-instruct",
  );
  assert.deepEqual(body, {
    model: "qwen2.5-3b-instruct",
    messages: [
      { role: "user", content: "hi" },
      { role: "assistant", content: "hello" },
      { role: "user", content: "bye" },
    ],
    stream: true,
  });
});

test("strips extra fields from turns so UI bookkeeping cannot leak into the body", () => {
  const body = buildChatRequestBody([{ role: "user", content: "x", pending: true, id: 7 }], "m");
  assert.deepEqual(body.messages, [{ role: "user", content: "x" }]);
});

test("stream flag is configurable and defaults to true", () => {
  assert.equal(buildChatRequestBody([], "m").stream, true);
  assert.equal(buildChatRequestBody([], "m", false).stream, false);
});
