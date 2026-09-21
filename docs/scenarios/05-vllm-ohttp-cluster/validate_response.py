#!/usr/bin/env python3
"""Strict validator for a vLLM /v1/completions response body.

Reads the raw response body (streaming SSE or a single JSON object) from a
file and an optional expected model name, and asserts the response is a
legitimate model inference result, not just a vLLM-shaped string:

  - the body is well-formed: valid JSON, or a sequence of valid `data:` SSE
    chunks (no vLLM `{"error": ...}` object);
  - choices[0].text exists and the concatenated completion text is non-empty
    (the model actually produced output, not an empty/echo reply);
  - the `model` field, when present, matches the expected model (catches a
    proxy/egress routing the request to the wrong service or model);
  - for streaming responses, the stream terminates with `data: [DONE]`
    (a truncated stream, e.g. a cut connection, is rejected).

Stdlib only (json). Prints exactly one line to stdout starting with VALID or
INVALID; exits 0 on valid, 1 on invalid, 2 on bad usage. Designed to be
greppable from the shell harness.
"""
import json
import sys


def fail(reason):
    print("INVALID: " + reason)
    sys.exit(1)


def summarize(model, text):
    preview = text[:40].replace("\n", "\\n")
    print("VALID model=%s text_len=%d preview=%r" % (model, len(text), preview))


def main():
    if len(sys.argv) < 2:
        print("INVALID: usage: validate_response.py <resp_file> [expected_model]", file=sys.stderr)
        sys.exit(2)
    path = sys.argv[1]
    expected = sys.argv[2] if len(sys.argv) > 2 else None

    try:
        with open(path, "r", errors="replace") as f:
            body = f.read()
    except OSError as e:
        fail("cannot read response file: %s" % e)

    if not body.strip():
        fail("empty response body")

    # Streaming SSE: one or more "data:" lines.
    data_lines = [ln for ln in body.splitlines() if ln.startswith("data:")]
    if data_lines:
        chunks = []
        got_done = False
        resp_model = None
        for ln in data_lines:
            payload = ln[len("data:"):].strip()
            if payload == "[DONE]":
                got_done = True
                continue
            try:
                obj = json.loads(payload)
            except json.JSONDecodeError as e:
                fail("non-JSON SSE chunk (%s): %s" % (e, payload[:80]))
            if isinstance(obj, dict) and "error" in obj:
                fail("error chunk: %s" % str(obj["error"])[:160])
            choices = obj.get("choices") if isinstance(obj, dict) else None
            if not choices:
                continue
            first = choices[0] if isinstance(choices[0], dict) else {}
            text = first.get("text")
            if text:
                chunks.append(text)
            if resp_model is None and isinstance(obj, dict) and obj.get("model"):
                resp_model = obj["model"]
        if not got_done:
            fail("stream ended without [DONE] (truncated?)")
        text = "".join(chunks)
        if not text:
            fail("empty completion text (no model output)")
        if expected and resp_model and resp_model != expected:
            fail("model mismatch: response=%r expected=%r" % (resp_model, expected))
        summarize(resp_model, text)
        sys.exit(0)

    # Non-streaming: a single JSON object.
    try:
        obj = json.loads(body)
    except json.JSONDecodeError as e:
        fail("non-JSON body (%s): %s" % (e, body[:80]))
    if isinstance(obj, dict) and "error" in obj:
        fail("error response: %s" % str(obj["error"])[:160])
    choices = obj.get("choices") if isinstance(obj, dict) else None
    if not isinstance(choices, list) or not choices:
        fail("no choices[] in response")
    first = choices[0] if isinstance(choices[0], dict) else {}
    text = first.get("text")
    if not text:
        fail("empty choices[0].text")
    resp_model = obj.get("model")
    if expected and resp_model and resp_model != expected:
        fail("model mismatch: response=%r expected=%r" % (resp_model, expected))
    summarize(resp_model, text)
    sys.exit(0)


if __name__ == "__main__":
    main()
