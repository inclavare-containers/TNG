---
name: perf-iterate
description: Use when optimizing TNG rats-tls performance to close the gap with HAProxy (or another TLS proxy baseline). Drives the measure→profile→optimize→re-measure loop. Every run measures RA (attestation on) in BOTH HTTP scenarios (keep-alive and no-keep-alive). no_ra is a debug-level option: never measured, never reported, never optimized for.
---

# Performance Iteration Loop

Drive the iterative optimization of TNG rats-tls performance against a TLS proxy baseline (HAProxy).

Two hosts: a server (TEE) host and a client host. Pass the server IP as `bash bench/client.sh <SERVER_IP>` or via the `SERVER_IP` env (see `bench/README.md`). The controller is the repo worktree (cargo + bench scripts). The client-side tng is the **ingress** and carries RA `verify` (builtin AS, hardware_only); the server-side tng is the **egress** and carries RA `attest` (via AA socket). So the RA verification hotspot (`verity_pending_cert`) lives in the client-side tng process.

**RA is the evaluation and decision anchor.** `no_ra: true` is a debug-level option that disables remote attestation. It is never measured, never reported, and never optimized for: an optimization whose benefit exists only under no_ra is worthless to production and is FORBIDDEN in this loop. Every proposal is evaluated on RA numbers; every verdict lands on RA numbers.

## Performance report format (canonical, script-generated)

For performance PR titles/bodies, read and follow `bench/performance-pr-requirements.md`. Its presentation rules take precedence over legacy formatting prose below. Use five-class before/after markers (🟢/⚪/🟡/🟠/🔴), an expanded per-scenario count table with `Count (%)` as the second column and exact full-table metric headers, and complete scenario tables collapsed by default. Do not add an N/A class; flag incomplete data. Generate counts and markers from the same data/function; extend and verify the generator before future PRs if needed. Verify evidence attribution and disclose anomalies and resource costs. When a PR lands multiple separable optimizations, also follow the requirements doc's multi-optimization section: the Ablation section carries one full generator-produced report per optimization step (baseline vs step-1, step-(N-1) vs step-N), each whole report default-collapsed in a single details block naming its arm revisions and run IDs, with the isolated-delta headline table and composition statement visible outside the folds.

All performance reports come out of `bench/gen-report.sh`. Never hand-build, re-type, or "improve" a results table by hand — if the format is missing something, extend the script.

**Report writing rules (apply to ALL performance reports, summaries, and PR descriptions):**

1. **A reader with zero session context must understand the report.** No session-internal references ("the agent", "the state file", "iteration N" without defining what was tried). No shorthand without definition. If a term appears, it must be either self-evident or defined at first use.
2. **State the test setup before any number.** What system, what test tool, what configuration (RA on, tunnel mode, body size), what hardware. Numbers without context are meaningless.
3. **One column, one unit.** A table column must not mix absolute values, percentages, and "of HAProxy" fractions. If you need both, use two columns with clear headers.
4. **Baseline must be stated as absolute numbers, not just percentages.** "27% of HAProxy" is meaningless without "HAProxy = 23,000 RPS" printed somewhere.
5. **If a baseline is re-measured per run and jitters, say so before showing percentages.** Otherwise a reader sees RPS go up while "vs baseline %" goes down and thinks the table is broken.
6. **Do not contradict yourself.** If the summary says "ineffective", the body must not prove "the mechanism engaged but the effect was noise". Use precise language: "mechanism verified, effect within measurement noise" not "ineffective".
7. **Explain the causal mechanism, do not just assert it.** "Sharding to N tunnels improved throughput because [the specific bottleneck it removed]" — not just "sharding improved throughput".
8. **Numbers from different measurement runs must be labeled as such.** If the baseline table and the iteration table use different runs, say "measured in a separate run" or use the same numbers.

**Naming convention for all prose, commit messages, PR descriptions, and reports:**

Always describe a measured case as: **test tool + connection mode + encryption mode** — never mix layers. TNG has THREE tunnel configurations that must always be named explicitly: (1) "rats-tls, non-multiplexed" (one TLS connection per client connection), (2) "rats-tls, multiplexed" (multiple client connections share one HTTP/2 tunnel), (3) "ohttp" (HPKE-sealed envelopes, separate protocol). Never say "TNG latency" or "TNG throughput" without naming the configuration. iperf3 and keep-alive are different layers (transport vs HTTP behavior); comparing them in one label ("iperf3 vs keep-alive") is meaningless. Correct forms:

- "TCP (iperf3) through the multiplexed TNG tunnel" — NOT "iperf3 mux" or "iperf3+mux"
- "HTTP (wrk, keep-alive) through the multiplexed TNG tunnel" — NOT "keep-alive mux"
- "HTTP (wrk, no keep-alive) through the multiplexed TNG tunnel" — NOT "short-conn mux" or "no-keep-alive mux"
- "TCP (iperf3) through the non-multiplexed TNG tunnel" — NOT "iperf3 non-mux" or just "iperf3 rats-tls"
- "HTTP (wrk, keep-alive) through the non-multiplexed TNG tunnel" — NOT "keep-alive rats-tls" or just "keep-alive"
- "HTTP (wrk, no keep-alive) through the non-multiplexed TNG tunnel" — NOT "short-conn rats-tls" or just "short-conn"

In tables where space is limited, use full self-contained labels: "TCP/iperf3, mux tunnel", "HTTP/wrk KA, mux tunnel", "HTTP/wrk SC, mux tunnel", "HTTP/wrk KA, non-mux tunnel" etc. Never use bare "mux" or bare "keep-alive" as a row/column label without the test tool and connection mode.

**Single-test report** (one binary, one environment) — the script's md output, three result scenarios:
- `### Scenario A` — TCP throughput (iperf3)
- `### Scenario B` — HTTP / wrk, keep-alive (persistent connections)
- `### Scenario C` — HTTP / wrk, no keep-alive (`Connection: close`, each request = new TCP+TLS)
The bench measures BOTH HTTP modes in every run and the report shows both; there is no single-mode pin anymore.

**Performance PRs must include the full comparison report.** Every PR that claims a performance improvement must have the complete `gen-report.sh --compare` output (all scenarios, all workloads, all metrics, all concurrency levels) in the PR body — not just a summary table. The comparison report is the evidence; a summary table without the full report is not acceptable.

**Comparison report** (baseline vs experimental — a tng change or an environment change), generated by `bench/gen-report.sh` in compare mode from the two result datasets:
- `1. Test Environment`, `2. Test Conditions`, `3. Test Tool Versions`: show changed entries in an expanded difference table (or `No differences.`), then a default-collapsed COMPLETE actual Baseline/Experimental table including unchanged entries. `4. Test Methodology`: keep the heading visible and collapse the canonical methodology text by default. Place a Markdown horizontal rule between the PR narrative and benchmark report. Verify actual ingress/egress build identities for both runs; `git unknown` is a collection failure, not a publishable final identity.
- Result scenarios (A/B/C): preserve adjacent baseline/experimental rows and all metrics. Follow the mandatory five-class thresholds, comparator legend, per-metric count table and default-collapsed full data tables in `bench/performance-pr-requirements.md`. Reference-only rows do not enter the counts. The former two-state ✅/⚠️ presentation is superseded for future performance PRs.

## ALWAYS

- Always read `bench/.perf-iteration-state.md` first to resume from the correct iteration. If it is missing, this is iteration 0 (baseline).
- Always do DEEP architectural analysis before proposing an optimization. Shallow profiling (pidstat/strace alone) is NOT sufficient. You must read the tng source code, trace the per-connection lifecycle (accept → TLS → forward → close), compare it step-by-step with how HAProxy handles the same lifecycle, and explain the architectural reason for the performance gap. An optimization proposal must include: (1) the specific code path that causes overhead, with file:line references; (2) why HAProxy doesn't have this overhead; (3) the concrete change and its expected impact.
- Always record a complete analysis in the state file after each iteration, regardless of whether the optimization improved, degraded, or had no effect. The analysis must explain WHY the result is what it is by correlating measured numbers with the architecture. "Null" is not an acceptable result label — every iteration produces understanding.
- Always have the proposed optimization reviewed before executing, at a depth proportional to its risk class. Wire-format, cryptographic, protocol-adjacent, or dependency-fork changes get THREE independent expert subagents (proceed only if at least 2 of 3 agree). TNG-local allocation/buffer/hygiene changes get ONE expert review. Purely mechanical local changes (renames, comment work) need self-review plus the Phase-4 post-implement review. Record all opinions in the state file either way.
- Always run a SECOND review on the actual implemented diff (Phase 4), after Implement and before Build. Phase 2 reviews the plan; Phase 4 reviews the code that ships. Apply the superpowers:receiving-code-review discipline: verify each finding against source, reject incorrect findings with a reason, do not apply suggestions out of performative agreement.
- Always anchor evaluation and decisions on RA. `no_ra: true` is a debug-level option; production uses RA. This loop measures and reports RA only. An optimization whose benefit exists only under no_ra is forbidden outright — it optimizes a debug toggle, not the product. If an analysis is easier to reason about conceptually on no_ra, that is fine as reasoning, but the measured verdict is RA.
- Always surface the script-generated md report to the user as the FULL results table. The bench scripts write the complete table (every workload, every concurrency, p50/p90/p95/p99, success%, egress CPU%/mem, vs-raw deltas, Scenarios A/B/C) to `bench/artifacts/iter-N-ra-report.md` via `gen-report.sh`. The workflow's text return is a SHORT highlight (verdict + key deltas + success-criteria check + the md report path), NOT a re-typed full table. Do not re-extract or re-table what the md already contains; point the user at the md and highlight the cells that changed and the ones that did not.
- Always report p95 (and p99), not just p50. p50 is the median and hides tail latency; a regression at p95/p99 is invisible if only p50 is shown. The md report carries p90/p95/p99 (p95 comes from a wrk Lua done() callback, `latency:percentile(95), since wrk --latency omits 95%); the highlight should call out p95/p99, not only p50.
- Always report the EGRESS-side component CPU% + mem alongside the latency/RPS. The egress tng (or haproxy-srv on the server host) is frequently the bottleneck (iter-5 root-caused the RA egress as the wall, 95% brotli); the md report's Egress CPU%/Mem columns come from `pidstat -u -r -p <PIDs> 1 <duration>` (Average row, haproxy master+workers summed, mem in MiB, client proxy excluded). The highlight should include egress-side numbers, not only client-visible RPS/latency.
- Always run exactly ONE optimization per iteration. No batching. Clean attribution requires a single variable change between measurements.
- Always record before/after metrics (RPS, p50, p95, CPU%, Mem, gap%) in `bench/.perf-iteration-state.md` after each iteration, for RA at every concurrency level (c=1,8,16,32,64,128).
- Always compare rats-tls against HAProxy (the TLS proxy baseline), not against raw. The gap is `rats-tls vs HAProxy`; raw is context only.
- Always rebuild (`cargo build --release -p tng`) AND redeploy to both hosts (`scp` to `/root/tng` on the server and client host) after each code change.
- Always run the full pre-commit gate before measuring, not just `cargo build`: `cargo fmt`, then `make clippy` (which is `cargo clippy --all-targets -- -D warnings`), then `cargo build --release -p tng`. The crate denies `clippy::expect_used` and `clippy::unwrap_used` in `tng/src/lib.rs` and `tng/src/bin/tng/main.rs` (`clippy.toml` allows them only in tests) — production paths must propagate errors with `.context()`/`?`, never `expect`/`unwrap` to panic. Skipping clippy lets a `.expect()` slip in (this happened in iteration 4's first cut and was caught only on review).
- Always verify the deployed binary version after redeploy: `ssh` to the client host `'/root/tng --version'` (and the server). The running tng must be the binary you just built, not a stale one.
- Always use the exact same bench parameters for comparable runs. Pin `WRK_CONNS=1,8,16,32,64,128` and `IPERF_STREAMS=1,8,16,32,64,128` (both sweep the full concurrency range), `WRK_DURATION=3 WRK_ROUNDS=2 IPERF_DURATION=3 IPERF_ROUNDS=2` (fast iteration values; the README defaults of 15s/3 rounds are for full baselines, not the per-iteration loop). The HTTP workloads run BOTH keep-alive and no-keep-alive (Scenarios B and C) in every run — the bench does this itself; there is no `WRK_SHORT_CONN` pin anymore. Leave `HTTP_BODY_KB` and `WRK_WARMUP` at their defaults (64 and 1). Run RA only (`RA_MODE=1`); do not run or generate a no_ra report. Fast A/B gating between iterations may restrict the sweep to the gate cells (c=1/8/32/128, both HTTP connection modes, three alternating rounds) because the gate is defined there; the full pinned matrix is mandatory for the final PR comparison report and for any run that feeds a published number.
- Always verify proportionally to risk, and never duplicate CI locally. Per iteration: run the test binaries that cover the touched code (the module's unit tests plus the integration suites exercising the changed path) — not the full suite. The full `make run-test` runs exactly ONCE, right before opening the PR, and CI's test.yml runs it again on the PR itself; running it locally per iteration is duplicate labor. wasm and cross-target builds run only when a diff touches `#[cfg]`-gated or platform-specific code, plus one full pass (wasm + mac/windows cross) before the PR.
- Always run the bench scripts via the remote paths they expect: `bash /root/bench/server.sh` and `bash /root/bench/client.sh <SERVER_IP>` (they `source lib/common.sh` relative to their own dir, so the `lib/` tree must be deployed alongside them on both hosts).
- Always profile before optimizing. Identify the top hotspot from a `perf` flamegraph (or `pidstat` fallback) before touching code. Never guess the bottleneck.
- Always tear down the server after the client run finishes (it ends in `wait` and stays foreground): kill the backgrounded server ssh and stop its tng so the next iteration starts clean.
- Always tear down even on phase failure. Every phase that starts a server ssh or a tng process must clean it up before returning (whether it returns `ok` or a `*_failed` status). The bench scripts' own `trap ... EXIT` handles their internal containers; the workflow is responsible for the ssh backgrounded server and any manually-launched tng (Phase 1 profiling). A stale server holding ports 40001-40005 / 50003 is the most common cause of "Address already in use" on the next iteration.

## NEVER

- Never propose an optimization without DEEP architectural analysis. "futex is 45%" is a symptom, not a root cause. You must trace the code path that causes the overhead, compare with HAProxy's equivalent path, and explain WHY the gap exists at the implementation level. Shallow profiling (just running pidstat/strace and picking the top syscall) is NOT analysis.
- Never skip the pre-implementation review for the proposal's risk tier (see ALWAYS). Never skip the post-implement review (Phase 4) for shipped code regardless of tier: a 3/3-approved proposal can still ship a buggy implementation (wrong cfg gate, a cached snapshot that breaks attestation freshness, a missed error path). The diff is reviewed against the safety checklist before it builds and ships.
- Never execute an optimization that fewer than 2 of 3 experts approve. If all 3 reject, go back to analysis. If 2/3 reject, revise based on their feedback and re-review.
- Never label an iteration's result as "no_change" or leave the state file without a complete analysis. Every iteration — whether it improved by 50%, by 2%, or not at all — must produce a full before/after comparison with an architectural explanation of WHY the numbers are what they are.
- Never report a number without naming the exact case. Every reported metric must carry: the scenario (RA short-conn), the workload pair being compared (http+rats-tls vs http+haproxy), and the concurrency level. A bare claim like "rats-tls improved 3-5x, now beats HAProxy" is useless without "RA, short-conn, http+rats-tls vs http+haproxy, c=32: 388→4358 RPS, gap 89%→+25%". The reader cannot assess a result they cannot locate.
- Never re-extract or re-type the full results table in the workflow's text return. The full table is the generated md report (surfaced to the user by path); the workflow returns a short highlight only. When highlighting, cover RA at every concurrency (not just the improved rows), and include p95/p99 and egress-side metrics, so the user can see what moved and what did not.
- Never optimize for no_ra. `no_ra` is a debug-level option; an optimization whose benefit exists only under no_ra optimizes a debug toggle, not the product, and is forbidden in this loop. Every measured verdict is RA.
- Never hand-build a comparison table. The comparison report (baseline vs experimental) is generated by `bench/gen-report.sh` in compare mode, following the format defined in "Performance report format" above: expanded differences plus collapsed full environment/conditions/tool tables, TNG workload rows doubled (baseline row + bolded experimental row), reference baselines shown once, no delta columns.
- Never change bench parameters between iterations (`WRK_CONNS`, `WRK_DURATION`, `WRK_ROUNDS`, `HTTP_BODY_KB`, `WRK_WARMUP`, `RA_MODE`, `WRK_SHORT_CONN`). A changed parameter invalidates the before/after comparison.
- Never modify the RA blocking contract: `forward_stream` must wait for `verity_pending_cert` before forwarding data. "Async RA verification (don't block the data plane)" is explicitly rejected (see guide Phase 4); verification must complete before data flows.
- Never touch the HAProxy or stunnel configs/code/deploy. They are baselines, not optimization targets. A "faster baseline" is cheating, not optimizing.
- Never run more than one optimization per iteration. If two proposals are viable, rank them in the state file and execute the top one this iteration; the next iteration picks #2.
- Never forget to update `bench/.perf-iteration-state.md` after each iteration (results + gap + expert opinions + next proposal). The state file is the only continuity across sessions and compaction.
- Never use `Co-Authored-By:` trailers in commits. Use the repo's `Assisted-by:` trailer convention only, and never add AI attribution footers to commit messages or PR descriptions.
- Never edit `TODO.md`. It is human-curated; record deferred optimization candidates in the state file instead, and surface them in your reply to the caller.
- Never relabel or move the baseline columns. The state file's table shape (Conns | rats-tls RPS | HAProxy RPS | Gap % | rats-tls p50 | HAProxy p50 | rats-tls CPU % | rats-tls Mem) must stay stable so prior rows remain comparable.

## Workflow-based execution

Each iteration is a **Workflow** (via the Workflow tool) with 7 phases. The main session only manages the big loop (evaluate results, decide continue/stop, launch next workflow).

**Main session responsibilities** (ONLY these):
1. Read the state file to recover context (iteration, baseline, previous results, ranked proposals).
2. Launch a workflow for the current iteration.
3. Review the workflow returned JSON (analysis, expert opinions, verdict, metrics).
4. Update the state file: record the analysis, expert opinions (ranked), results, and next proposals.
5. Decide: continue (launch next workflow with the top-ranked proposal) or stop.

The main session does NOT: write code, run SSH commands, build, deploy, profile, or analyze architecture. All of that is inside the workflow.

### Workflow template (8 phases)

Phase 1: Deep Architecture Analysis (expert subagent)
  This is the MOST IMPORTANT phase. Do NOT skip it or do it shallowly.
  Actions:
  - Read the tng source code for the per-connection lifecycle in the short-conn scenario:
    - Ingress path: tng/src/tunnel/ingress/ (how a connection is accepted, TLS handshake initiated, data forwarded, connection closed)
    - Egress path: tng/src/tunnel/egress/ (how the egress accepts the TLS connection, decrypts, forwards to backend)
    - TLS config: tng/src/tunnel/utils/rustls/config/ (how rustls ClientConfig/ServerConfig is built per connection)
    - Forward: tng/src/tunnel/utils/forward.rs (the bidirectional copy loop)
    - Runtime: tng/src/bin/tng/main.rs (tokio runtime setup)
  - Read the HAProxy source/docs for its per-connection lifecycle:
    - How HAProxy accepts, does TLS handshake, forwards, closes (its event loop model, worker thread model, buffer management)
    - Key architectural differences: epoll+callbacks vs tokio async tasks; OpenSSL vs rustls; buffer pooling vs per-connection allocation
  - Read previous bench results (bench/.perf-iteration-state.md) and correlate with the architecture:
    - Why is rats-tls 4x slower than HAProxy in RA short-conn? What specific code path accounts for this?
    - Why is RA 50x slower? What in the RA verification path (verity_pending_cert, builtin-AS, TDX quote) accounts for this?
    - Why did jemalloc and ClientConfig caching show results? What does this tell us about the real bottleneck?
  - Propose ONE optimization with:
    - Root cause: the specific code path (file:line) that causes the overhead, with a trace from accept to close
    - HAProxy comparison: why HAProxy does not have this overhead (specific architectural reason)
    - Concrete change: what to edit (file:line), expected mechanism, expected impact (quantified, e.g. "reduces per-connection syscalls from N to M")
    - Risk assessment: what could break, what to verify
  Return: the proposal as structured text (root cause + HAProxy comparison + change + expected impact + risk)
  SHOULD: read actual source files, not guess from function names
  SHOULD: trace the full per-connection path (accept → TLS connect → forward → TLS accept → forward → close), not just one side
  SHOULD: consider both ingress and egress (the tunnel has two ends)
  SHOULD: explain WHY previous results (jemalloc, ClientConfig caching) failed — what does the results tell us about where the bottleneck ISN'T
  SHOULD NOT: propose an optimization based on shallow profiling alone ("futex is high")
  SHOULD NOT: propose symptomatic fixes (swap allocator, reduce threads) without architectural justification
  SHOULD NOT: guess — if unsure, say so and propose profiling that would resolve the uncertainty

Phase 2: Expert Review (3 parallel subagents)
  Each expert independently reviews the proposal from Phase 1.
  Actions (per expert):
  - Read the proposal
  - Read the relevant source code to verify the root cause claim
  - Assess: (1) Is the root cause analysis correct? (2) Is the proposed change feasible? (3) Is the expected impact realistic? (4) Are there risks not mentioned?
  - Return: verdict (approve/reject/modify) + specific feedback
  SHOULD: independently verify the root cause by reading the code (don't just trust the proposal)
  SHOULD: suggest modifications if the proposal is close but has issues
  SHOULD NOT: approve without understanding the proposal
  SHOULD NOT: reject without providing a specific reason + alternative

Phase 3: Decision + Implement (sequential, after Phase 2)
  Actions:
  - Read all 3 expert opinions
  - If >=2 approve: implement the proposal (or the modified version if experts suggested changes)
  - If <2 approve: do NOT implement. Return status="proposal_rejected" with the opinions. The main session re-analyzes next iteration.
  - Implement via Edit/Write (the specific files from the proposal)
  Return: files changed, expert opinions summary, whether implemented or rejected

Phase 4: Post-Implement Review + Fix (sequential, after Phase 3)
  Phase 2 reviewed the PLAN; this phase reviews the CODE that will actually ship. A sound proposal can still ship a buggy implementation (wrong cfg gate, a cached snapshot that breaks attestation freshness, a missed error path, a stale comment). Do NOT skip it.
  Actions:
  - Run `cargo build -p tng` (debug, local) to confirm the change compiles before reviewing.
  - Dispatch ONE reviewer subagent to review `git diff` against a fixed checklist:
    (1) Proposal intent — does the diff do what Phase 1 proposed, no more no less?
    (2) RA freshness — if the change touches the RA/egress server path: DynamicCertResolver still queries get_latest_cert_blocking() per handshake (no cert snapshot); LazyClientCertVerifier.verity_pending_cert() still runs per connection; the rustls brotli LRU still auto-invalidates on cert refresh (no stale compressed cert served).
    (3) RA data-plane contract — forward_stream still waits for verity_pending_cert before forwarding data.
    (4) Error handling — errors propagated with .context()/?; NO expect/unwrap in production paths (the crate denies clippy::expect_used/unwrap_used); no error-to-string formatting (anyhow::anyhow!("{}" , e)).
    (5) Cross-platform — Linux-only facilities are #[cfg(target_os = "linux")]-gated; Attest arms keep #[cfg(unix)]; the cache primitive is std (fine on mac/windows/wasm); wasm does not reach the egress server path.
    (6) Code craft — comments explain why not what; existing comments carried over; minimal diff; no em dash in prose comments.
  - Apply the superpowers:receiving-code-review discipline: verify EACH finding against the source before acting. A finding that is technically wrong is rejected with a specific reason, not applied out of performative agreement. Apply the valid fixes via Edit. If findings conflict with the Phase-2 expert reasoning, prefer whichever is backed by source evidence.
  - Re-run `cargo build -p tng` after fixes.
  Return: the review findings (applied vs rejected-with-reason) + final diff summary.
  SHOULD: have the reviewer read the actual `git diff`, not the proposal text
  SHOULD: treat the checklist as a gate the diff must pass
  SHOULD NOT: blindly apply every suggestion; reject incorrect ones with a reason
  SHOULD NOT: skip this phase even when the proposal was approved 3/3

Phase 5: Build + Deploy
  Actions:
  - Kill stale tng on both hosts
  - Run the full gate in order: `cargo fmt` && `make clippy` && `cargo build --release -p tng`. fmt and clippy run BEFORE build; clippy (`cargo clippy --all-targets -- -D warnings`) catches `expect_used`/`unwrap_used` that the crate denies in production paths. Treat a clippy warning as a build failure. (Phase 4 ran a debug build; this is the release gate that ships.)
  - scp to both hosts + deploy scripts
  - Verify version
  Return: commit hash + version (or clippy_failed / build_failed / deploy_failed)
  SHOULD: fail fast if fmt, clippy, or build fails
  SHOULD NOT: run bench here

Phase 6: Measure (RA, both HTTP scenarios)
  Actions:
  - Clean stale on both hosts
  - RA run: verify AA, start server (RA_MODE=1), run client (WRK_CONNS=1,8,16,32,64,128 IPERF_STREAMS=1,8,16,32,64,128 — the bench measures keep-alive AND no-keep-alive in one run), tear down. RA only; do not run a no_ra round and do not generate a no_ra report.
  - Fetch results + generate the RA md report (Scenarios A/B/C) to bench/artifacts/ (iter-N-ra-report.md)
  Return: raw metrics + the generated md report path
  SHOULD: retry once if Connection refused
  SHOULD: check AA before RA run
  SHOULD NOT: change env vars between runs

Phase 7: Compare + Decide
  Actions:
  - The bench scripts already wrote the FULL results (Scenarios A/B/C) to the generated md report. For iterations comparing against a baseline run, generate the COMPARISON report via `bench/gen-report.sh` compare mode (baseline results JSON + experimental results JSON) — the canonical comparison format (expanded differences plus collapsed full env/conditions/tools; TNG rows doubled with the bolded experimental row; no delta columns). Do NOT re-type either table in the workflow's return.
  - Read `bench-results.json` + the state file baseline; compute change% vs baseline and gap% (rats-tls vs HAProxy) at each concurrency for RA, in both HTTP scenarios.
  - Gate discipline: every proposal pre-registers its expected per-host CPU-per-request and RPS deltas (derived from the profile/cost model, written into the state file) BEFORE the A/B runs. The pass rule is: measured deltas fall inside or above the pre-registered band, AND no cell regresses beyond run noise. Fixed percentage thresholds (like the +5%/-5% labels below or a "-15% CPU / +8% RPS" gate) are calibration defaults for large-change classes; re-derive the threshold from the current cost model at campaign start instead of copying a previous campaign's numbers — a post-crypto-swap micro-optimization will never hit a crypto-swap-sized gate, and "failed the nominal gate but landed inside the pre-registered band, zero regression" is a KEPT iteration, not a revert.
  - Verdict labels: improved (+5% at >=2 levels) / degraded (-5%) / no_change (+-5%) / done (gap <10% all levels).
  - Pull a SHORT highlight only (a few numbers, not a re-typed table): per-concurrency rats-tls RPS + rats-vs-HAProxy gap% + p50/p95/p99 + egress CPU%/mem, and an explicit success-criteria check. Note unchanged cases as well as changed ones.
  Return: verdict + the highlight (key numbers, not a full table) + the path to the generated report (single or comparison) so the main session surfaces the full table from the md.
  SHOULD: surface the generated report path prominently; the user reads the full table from the md
  SHOULD: cover RA at every concurrency in the highlight (not just the improved rows)
  SHOULD NOT: re-extract or re-type the full results table (the md report already has it)
  SHOULD NOT: make optimization decisions

Phase 8: Revert if no_change/degraded
  Actions:
  - If no_change/degraded: git checkout changed files (from Phase 3), rebuild, redeploy
  - If improved/done: keep
  Return: kept or reverted

### What the workflow returns to the main session

{
  "iteration": N,
  "status": "ok" | "analysis_failed" | "proposal_rejected" | "build_failed" | "deploy_failed" | "aa_unavailable" | "bench_failed",
  "error": "<empty on ok>",
  "analysis": {
    "root_cause": "<the specific code path causing overhead, with file:line>",
    "haproxy_comparison": "<why HAProxy does not have this overhead>",
    "previous_results_explained": "<what jemalloc/ClientConfig results tell us>",
    "proposal": "<what to change, expected impact, risk>"
  },
  "expert_opinions": [
    {"expert": 1, "verdict": "approve"|"reject"|"modify", "feedback": "..."},
    {"expert": 2, "verdict": "...", "feedback": "..."},
    {"expert": 3, "verdict": "...", "feedback": "..."}
  ],
  "implemented": true | false,
  "post_implement_review": {"findings_applied": ["..."], "findings_rejected": ["... + reason"], "final_diff": "<summary>"},
  "binary": {"version": "tng 2.9.2", "commit": "<hash>"},
  "ra": {"1": {...}, "8": {...}, "16": {...}, "32": {...}, "64": {...}, "128": {...}},
  "verdict": "improved" | "no_change" | "degraded" | "done",
  "reverted": true | false,
  "artifacts": {"ra_report": "bench/artifacts/iter-N-ra-report.md", "comparison_report": "bench/artifacts/iter-N-vs-baseline-report.md (when a baseline run is compared)"},
  "next_proposals": "<ranked list of future optimization candidates for the state file>"
}

The main session reads this, updates the state file (including the analysis, expert opinions, and ranked proposals), and either launches the next workflow or stops.

## Result analysis (every iteration, regardless of outcome)

Every iteration produces a complete analysis result — whether the optimization improved RPS by 50%, by 2%, or not at all. There is no "no_change" concept and no mechanical counter. Instead:

1. **Keep or revert based on measured impact**: if the change improved RPS by any measurable amount (>0%) at most concurrency levels without degrading p50, keep it. If it degraded performance, revert. If it had zero effect, revert (no reason to keep dead code).

2. **Record a complete analysis in the state file**: regardless of outcome, document:
   - What was the root cause identified in Phase 1 (the architectural analysis).
   - What was changed (file:line + description).
   - Before/after numbers at every concurrency level (RPS, p50, CPU%, Mem, gap%).
   - **Why the result is what it is**: correlate the measured numbers with the architecture. If it improved, explain which code path's overhead was reduced. If it didn't, explain why — what did the analysis miss? What does the data tell us about where the bottleneck really is?
   - Expert opinions (all 3, with their reasoning).
   - Updated understanding of the bottleneck: has the analysis been confirmed, refined, or overturned by the measurement?

3. **Decide next step based on understanding, not a counter**: after each iteration, the main session reviews the accumulated analysis and decides:
   - If the gap is closing: continue with the next proposal from the ranked list.
   - If the gap is not closing after a well-understood attempt: either propose a different approach targeting the SAME root cause (informed by why the first attempt failed), or conclude the root cause is architectural and report to the user with the full analysis.
   - There is no "max N nulls" rule. The decision is based on whether the analysis is deep enough and whether the proposed changes are architecturally sound.

4. **The state file accumulates understanding**: each iteration adds a row to the optimization log with the full analysis (not just "no_change"). The log is a growing knowledge base — future iterations and future sessions read it to avoid repeating dead ends and to build on confirmed insights.

## Startup (every invocation)

1. Read `bench/.perf-iteration-state.md` to recover the current state (iteration count, last results, current gap, next target). If it doesn't exist, this is iteration 0 (baseline).
2. Read `bench/perf-optimization-guide.md` for the detailed methodology.

## Success criteria

The deliverable target is the **RA** gap (production uses RA; `no_ra` is a debug option, never measured). Must hold at c=1,8,16,32,64,128 (all six levels), in BOTH HTTP scenarios (keep-alive, Scenario B; no-keep-alive, Scenario C):

| Metric | Target |
|---|---|
| RA RPS / HAProxy RPS | >= 90% |
| RA p50 / HAProxy p50 | <= 110% |
| RA p95 / HAProxy p95 | <= 110% |

RA-only bottlenecks not closed by this loop (attestation cert-verify, 0-RTT resumption, shared CertVerifyCache) are tracked under PRs #220/#216/#215; this loop targets the non-RA-path cost (e.g. per-handshake TLS config / cert work, scheduling, syscalls) that those PRs do not cover.

## Key references

- Detailed methodology: `bench/perf-optimization-guide.md`
- Bench README (commands + env vars): `bench/README.md`
- State file: `bench/.perf-iteration-state.md` (gitignored, persists across sessions)

Report automation: use `bench/gen-report.sh --compare` for policy-compliant counts/markers, folds and validation; see `bench/reporting.md`. New benchmark builds must use `bench/record-build.py` and deploy the matching binary manifest. Run `python3 bench/test_report.py` after renderer/identity changes. In the final phase, regenerate the `docs/performance{,_zh}.md` snapshot page and its `docs/performance/` SVG charts from the final single-run results via `bench/gen-svg.py`, per the snapshot rule in `bench/performance-pr-requirements.md`. Keep interpretation and final claim checks in the agent workflow; do not hand-edit generated tables.

Final PR prose checks: follow the narrative-consistency section in `bench/performance-pr-requirements.md`; match every quoted number to its exact run/scenario, qualify improvement/no-regression claims, and keep detailed methodology/comparison prose inside the default-collapsed method block with only compact per-table legends outside.
