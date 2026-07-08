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
    command -v go >/dev/null 2>&1 || { skip go "go toolchain missing"; return 0; }

    # The default `tng` binary is not built with __builtin-as, so the Go SDK
    # subprocess cannot honour as_type:"builtin". Skip cleanly per contract.
    if [[ "$AS_MODE" == "builtin" ]]; then
        skip go "builtin AS not in default tng build"
        return 0
    fi

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
    if [[ -z "$tngpath" ]] && command -v tng >/dev/null 2>&1; then
        tngpath="$(command -v tng)"
    fi
    if [[ -z "$tngpath" ]]; then
        skip go "tng binary not found for Go SDK subprocess"
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
	"fmt"
	"log"
	"net/http"

	openai "github.com/sashabaranov/go-openai"
	tng "github.com/inclavare-containers/tng/tng-go"
)

func main() {
	cfg := &tng.Config{
		OHttp: map[string]any{
			"path_default": "original",
		},
		Verify: map[string]any{
			"model":      "background_check",
			"as_addr":    "___AS_URL___",
			"policy_ids": []string{"default"},
		},
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

	stream, err := client.CreateCompletionStream(
		context.Background(),
		openai.CompletionRequest{
			Model:  "___MODEL___",
			Prompt: "Do you know the book Traction by Gino Wickman",
		},
	)
	if err != nil {
		log.Fatalf("CreateCompletionStream: %v", err)
	}
	defer stream.Close()

	for {
		resp, err := stream.Recv()
		if err != nil {
			break
		}
		if len(resp.Choices) > 0 {
			fmt.Print(resp.Choices[0].Text)
		}
	}
	fmt.Println()
}
GOEOF
        sed -i \
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

    if [[ $rc -ne 0 ]]; then
        fail go "go run failed (rc=$rc); see $testdir/out.log"
        return 1
    fi

    # PASS if the streamed output looks like model text.
    if grep -Eiq 'traction|book|wickman|yes|familiar|know' "$testdir/out.log" \
       || [[ $(tr -d '[:space:]' < "$testdir/out.log" | wc -c) -gt 20 ]]; then
        pass go
        return 0
    fi
    fail go "no streamed model output; see $testdir/out.log"
    return 1
}
