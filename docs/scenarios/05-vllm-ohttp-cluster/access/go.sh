#!/usr/bin/env bash
# run_go() — Go SDK method (method 3 of 4).
# Sourced by run.sh; defines ONLY run_go().
#
# Verifies the Go SDK (github.com/inclavare-containers/tng/tng-go) can reach
# the real completions service via OHTTP+verify, using the go-openai lib's
# CreateCompletionStream on the /v1/completions endpoint.
#
# NOTE: the tng-go/transport.go path-loss bug is fixed in-source (it now uses
#       net/http's http.Transport.Proxy, which emits the absolute-URI request
#       line that the TNG http_proxy ingress expects). No patching needed.

run_go() {
    command -v go >/dev/null 2>&1 || { skip go-sdk "go toolchain missing"; return 0; }

    # --- Resolve a tng binary for the SDK subprocess (it spawns `tng launch`).
    # Prefer the repo's own build over a system `tng` on PATH: the system one
    # may be an older release that doesn't know newer config fields (e.g.
    # `path_default`), which would make the subprocess fail to start. ---
    local tngpath=""
    if [[ -n "${TNG_BINARY:-}" && -f "$TNG_BINARY" ]]; then
        tngpath="$TNG_BINARY"
    fi
    if [[ -z "$tngpath" ]] && [[ -x "$REPO/target/release/tng" ]]; then
        tngpath="$REPO/target/release/tng"
    fi
    if [[ -z "$tngpath" ]] && [[ -x "$REPO/target/debug/tng" ]]; then
        tngpath="$REPO/target/debug/tng"
    fi
    if [[ -z "$tngpath" ]]; then
        # Build via the Makefile (default features incl builtin-as-tdx); fall
        # back to a system tng only if the build fails.
        if _ensure_make_target "$REPO/target/release/tng" bin-build "tng binary"; then
            tngpath="$REPO/target/release/tng"
        elif command -v tng >/dev/null 2>&1; then
            tngpath="$(command -v tng)"
        fi
    fi
    if [[ -z "$tngpath" ]]; then
        skip go-sdk "tng binary not found and make bin-build failed"
        return 0
    fi
    export TNG_BINARY="$tngpath"

    local testdir="$WORKDIR/tng-go-test"
    mkdir -p "$testdir"

    # Decide on a runner (timeout if available).
    local runbin="go run ."
    if command -v timeout >/dev/null 2>&1; then
        runbin="timeout 120 go run ."
    fi

    local rc=0
    (
        set -e
        cd "$testdir"
        rm -f go.mod go.sum main.go
        go mod init tnggotest >/dev/null 2>&1 || true
        go get github.com/sashabaranov/go-openai
        printf 'replace github.com/inclavare-containers/tng/tng-go => %s/tng-go\n' "$REPO" >> go.mod
        go get github.com/inclavare-containers/tng/tng-go || true
        cat > main.go <<'GOEOF'
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	openai "github.com/sashabaranov/go-openai"
	tng "github.com/inclavare-containers/tng/tng-go"
)

func main() {
	cfg := &tng.Config{
		OHttp: map[string]any{
			"path_default": "original",
		},
		Verify: ___VERIFY_BODY___,
	}

	rt, err := tng.NewRoundTripper(cfg)
	if err != nil {
		log.Fatalf("NewRoundTripper: %v", err)
	}
	defer rt.Close()

	ocfg := openai.DefaultConfig("___TOKEN___")
	ocfg.BaseURL = "___COMPLETIONS_BASE___"
	ocfg.HTTPClient = &http.Client{Transport: rt}
	client := openai.NewClientWithConfig(ocfg)

	model := "___MODEL___"
	stream, err := client.CreateCompletionStream(
		context.Background(),
		openai.CompletionRequest{
			Model:  model,
			Prompt: "Do you know the book Traction by Gino Wickman",
		},
	)
	if err != nil {
		log.Fatalf("INVALID: CreateCompletionStream: %v", err)
	}
	defer stream.Close()

	// Strict validation at the SDK level: accumulate the streamed choices
	// text, record the model the server echoed, and require a clean EOF (the
	// SDK returns io.EOF on the [DONE] sentinel). Anything else is a failure.
	var sb strings.Builder
	var respModel string
	gotChunk := false
	for {
		resp, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			log.Fatalf("INVALID: stream recv: %v", err)
		}
		gotChunk = true
		if respModel == "" && resp.Model != "" {
			respModel = resp.Model
		}
		if len(resp.Choices) > 0 {
			sb.WriteString(resp.Choices[0].Text)
		}
	}
	if !gotChunk {
		log.Fatalf("INVALID: no stream chunks")
	}
	if sb.Len() == 0 {
		log.Fatalf("INVALID: empty completion text (no model output)")
	}
	if respModel != "" && respModel != model {
		log.Fatalf("INVALID: model mismatch: response=%s expected=%s", respModel, model)
	}
	preview := sb.String()
	if len(preview) > 40 {
		preview = preview[:40]
	}
	fmt.Printf("VALID model=%s text_len=%d preview=%q\n", respModel, sb.Len(), preview)
}
GOEOF
        if [[ "$AS_MODE" == "builtin" ]]; then
            verify_body='map[string]any{"model":"background_check","as_type":"builtin","attestation_policy":map[string]any{"type":"default"},"reference_values":[]any{}}'
        else
            verify_body='map[string]any{"model":"background_check","as_addr":"'"$AS_URL"'","policy_ids":[]string{"default"}}'
        fi
        sed -i \
            -e "s#___VERIFY_BODY___#$verify_body#g" \
            -e "s#___AS_URL___#$AS_URL#g" \
            -e "s#___TOKEN___#$TOKEN#g" \
            -e "s#___COMPLETIONS_BASE___#$COMPLETIONS_BASE#g" \
            -e "s#___MODEL___#$MODEL#g" \
            main.go
        go mod tidy
        $runbin
    ) >"$testdir/out.log" 2>&1
    rc=$?

    # Safety net: kill any SDK-spawned tng subprocess still alive (config under /tmp).
    if [[ "$KEEP" != "1" ]]; then
        local pid
        for pid in $(pgrep -x tng 2>/dev/null); do
            if tr '\0' ' ' < /proc/"$pid"/cmdline 2>/dev/null | grep -q 'tng-cfg-'; then
                kill -9 "$pid" 2>/dev/null
            fi
        done
    fi

    if [[ $rc -eq 0 ]] && grep -q '^VALID model=' "$testdir/out.log" 2>/dev/null; then
        grep '^VALID model=' "$testdir/out.log" | head -1 | { read -r v; [ -n "$v" ] && log "  $v"; }
        pass go-sdk
        return 0
    fi
    fail go-sdk "invalid/no model response (rc=$rc; see $testdir/out.log)"
    logtail "$testdir/out.log" 40 >&2
    return 1
}
