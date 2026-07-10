// Incremental SSE reader for an OpenAI-compatible streaming response.
//
// The TNG SDK returns a web_sys::Response whose .body is a real ReadableStream
// (convert_to_web_response streams the decrypted BodyDataStream through), so we
// can render tokens incrementally rather than buffering the whole response.
//
// Usage:
//   await readSseStream(response, {
//     onDelta: (text) => outputEl.append(text),
//     onRaw:   (eventStr) => rawEl.append(eventStr + "\n\n"),
//   });

export async function readSseStream(response, { onDelta, onRaw } = {}) {
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  // eslint-disable-next-line no-constant-condition
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    // SSE events are separated by a blank line (\n\n).
    let sep;
    while ((sep = buffer.indexOf("\n\n")) !== -1) {
      const rawEvent = buffer.slice(0, sep);
      buffer = buffer.slice(sep + 2);
      if (onRaw) onRaw(rawEvent);

      for (const line of rawEvent.split("\n")) {
        if (!line.startsWith("data:")) continue;
        const data = line.slice(5).trim();
        if (data === "" || data === "[DONE]") continue;
        let delta = "";
        try {
          const json = JSON.parse(data);
          const choice = json.choices && json.choices[0];
          if (!choice) continue;
          delta = choice.text ?? (choice.delta && choice.delta.content) ?? "";
        } catch {
          // Non-JSON keepalive or comment line — ignore.
        }
        if (delta && onDelta) onDelta(delta);
      }
    }
  }
  // Flush any trailing decoder state.
  buffer += decoder.decode();
  if (buffer.trim() && onRaw) onRaw(buffer);
}
