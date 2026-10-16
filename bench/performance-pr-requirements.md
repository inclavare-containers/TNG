# Performance optimization PR message requirements

This policy is mandatory when an agent creates or updates a PR claiming performance improvements. Read it before drafting the title/body and repeat its checks after the final code, commit, configuration, or benchmark change. It governs PR communication; existing benchmark execution rules still apply. PR titles and bodies are in English.

## Required structure

Use these sections in order: Summary; Changes and configuration; Benchmark setup; Results and tradeoffs; Validation and remaining work; Full benchmark comparison. Keep the narrative concise and self-contained. Each scenario requires an expanded classification-count table before its collapsed full data table. Additional highlight tables or charts are optional and MUST NOT replace the complete data tables.

- Summary: explain the concrete workload/problem, what changes, and the measured outcome in 2-4 sentences. Name the protocol/mode, attestation setting, connection behavior, and concurrency for numeric claims. State remaining gaps and important costs alongside improvements.
- Changes and configuration: describe the mechanism and why it addresses the bottleneck. Verify defaults, unset behavior, units, bounds, validation, scope, and examples against source. Distinguish streams per connection from number of connections, soft limits from hard limits, and opt-in behavior from default behavior. Do not organize the body around an obsolete commit count or the agent's work history.
- Benchmark setup: identify exact baseline and experimental source revisions, dirty patches if any, binary/build identity, configuration values, dependency PRs/commits, run IDs, hardware/network topology, tool versions, warmup, duration, repetitions, aggregation, workload sizes and concurrency matrix. A release version alone is insufficient. Missing identity must be labeled unverified; never invent a SHA or present `git unknown` as reproducible. Unchanged metadata can be stated once or linked to a retained complete manifest; difference-only tables do not replace the metadata needed to reproduce the run. Use portable host labels and commands; do not publish private addresses, credentials, or internal SSH aliases.
- Results and tradeoffs: distinguish improvement against the previous TNG version from standing relative to raw/HAProxy/stunnel. State the exact concurrency range behind ranges; do not generalize a high-concurrency benefit to single-connection behavior. Summarize regressions and CPU/memory costs, including unaffected control modes. All summary numbers must match the full report.
- Validation and remaining work: list checks actually run and their outcomes; separate passed, failed, and not run. Separate measured observations, profiling-supported explanations, and hypotheses. Do not claim a specific bottleneck or that a future change will eliminate the gap without evidence. Use `Closes` only when the issue's acceptance criteria are met; otherwise use `Related to` and state outstanding criteria.

## Full tables are mandatory evidence

Include the complete script-generated comparison report for every experiment, covering every measured scenario, workload/control mode, concurrency and metric, including latency percentiles, success/errors, CPU and memory when collected. Do not prune bad rows or replace full tables with selected examples. Full reports live as PR COMMENTS, not in the body (GitHub's body size limit cannot hold them): each report is one whole-report `<details>` block generated with `--fold`, maintained in place by `bench/pr-report-comments.sh` (matched by its summary line, patched, never duplicated). The PR body links to each comment with a compact hash-range line: `Full benchmark: [<base>...<head>](url)` for the main report and `Ablation step N: [<a>...<b>](url) (short natural-language description of the change)` per ablation step. Inside a report, each complete scenario data table stays inside its own clearly labeled `<details>` block, collapsed by default, with the classification-count table visible outside it. Preserve the generated Markdown artifact and underlying run data under the benchmark artifact policy.

Generate tables using `bench/gen-report.sh --compare`; never retype measured tables by hand. If formatting needs to change, update the generator and verify it against retained input data instead of editing its output. Do not edit generated evidence by hand.

## Comparison presentation and markers

Preserve adjacent baseline/experimental rows and every measured metric. Experimental metric cells carry the five direction-aware classes below, emitted by `bench/gen-report.sh --compare`, comparing the same scenario, workload, concurrency and metric with its adjacent baseline row. Never classify against raw/HAProxy or against a rounded vs-raw percentage.

| Marker | Class | Change relative to before |
|---|---|---|
| 🟢 | Improved | Favorable change greater than 1% |
| ⚪ | Stable | Absolute change at most 1% |
| 🟡 | Mild degradation | Unfavorable change greater than 1%, at most 5% |
| 🟠 | Moderate degradation | Unfavorable change greater than 5%, at most 15% |
| 🔴 | Severe degradation | Unfavorable change greater than 15% |

The generator computes relative change from unrounded measurements as `(after-before)/before*100`. Higher throughput/RPS/success is favorable; lower latency/CPU/RSS/error rate is favorable. These are display thresholds, not measured noise bands, statistical significance, or acceptance verdicts. CPU/RSS increases are resource costs and do not automatically invalidate an optimization. Efficiency claims require throughput per CPU/core or resource use at matched work. Explain measured components, process aggregation and CPU units.

Success-rate columns use the same relative-change formula for this five-class display; distinguish percentages from percentage points in prose and explicitly call out new errors or success-rate declines even if they fall inside the stable band. Do not let classification hide correctness or reliability failures. If a metric requires a different acceptance threshold, disclose it separately rather than silently changing the classification thresholds.

Absolute values remain measurements. Existing parenthesized percentages are **vs the displayed raw reference**; explicitly identify whether raw comes from the before run or the matching run. HAProxy fractions must say `of HAProxy` or `vs HAProxy`. The colored marker means **change vs before**. If explicit before/after deltas are added, label them separately; never repurpose the vs-raw percentages.

Missing/nonfinite measurements, unmatched pairs and undefined relative changes (zero denominators) are data-completeness issues, not a sixth class. Report the precise issue and repair the comparison or disclose the incomplete evidence before publishing a complete classification summary. Never add an `N/A` classification row, fabricate a percentage, drop incomplete cells silently, or count them as stable. Metrics structurally not collected for reference-only rows are outside the comparison population.

## Mandatory per-scenario count table and default folding

For every scenario use this order: scenario heading; concise main findings; expanded classification-count table; explicit legend and counting scope; collapsed complete before/after data table. The full table is retained in the PR body, not replaced by a link or selected rows.

The count table has:

1. First column: `Change class`.
2. Second column: `Count (%)`.
3. Remaining columns: EXACT metric headers, units and order from the associated full data table. Do not merge them into groups such as latency/resources. Omit non-metric identifier columns such as Streams/Conns/Workload.
4. Exactly five class rows in this order: 🟢 Improved, ⚪ Stable, 🟡 Mild degradation, 🟠 Moderate degradation, 🔴 Severe degradation, followed by `Total`. No N/A class row.

Each metric cell contains the integer count of comparable workload × concurrency pairs in that class. Each experimental metric cell contributes exactly once; do not count baseline rows again or count reference-only raw/stunnel/HAProxy rows. Include all paired TNG/control modes present in the comparison. State the included modes and concurrency range. Supplementary paired control results should have their own clearly scoped summary if not part of the primary table.

For each class, `Count` is the sum across its metric columns. Its percentage is `Count / total comparable metric cells * 100`, formatted consistently to one decimal place. The `Total` row gives each metric's comparison count and the overall `N (100.0%)`. Individual percentages may sum to 99.9% or 100.1% after rounding; do not alter counts to force a sum. Row sums, column sums and the grand total reconcile, and every eligible pair has all required measurements; both are generator-validated. A scenario with no eligible pairs is an error, not `0 (100%)`.

Everything in this section is direct generator output: `bench/gen-report.sh --compare` emits the markers, the count tables, and the Count (%) totals from the same unrounded data in one pass, and validates the reconciliation itself. Nothing here is hand-assembled. The spec above is the contract the generator's output must keep satisfying: if the format needs to change, change the generator and its tests, never the published tables.

Example structure (placeholders are illustrative, never publish them as results):

```markdown
### Scenario B - HTTP / wrk (64 KiB body, keep-alive)

Main findings: [gains, affected concurrency, resource costs and severe anomalies].

| Change class | Count (%) | Throughput (Gbps) | RPS | Mean (us) | p50 (us) | p90 (us) | p95 (us) | p99 (us) | Success % | Server CPU % | Server Mem (MiB) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 🟢 Improved | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... |
| ⚪ Stable | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... |
| 🟡 Mild degradation | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... |
| 🟠 Moderate degradation | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... |
| 🔴 Severe degradation | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... |
| **Total** | **N (100.0%)** | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... |

Scope: [paired modes and concurrency]. Parenthesized percentages are vs [raw reference]; markers and counts are vs before, using the five thresholds above. Counts are not an overall pass/fail score.

<details>
<summary>Full Scenario B comparison</summary>

[Complete generated data table, all rows and metrics.]

</details>
```

Keep per-column units consistent. Counts do not weight metric importance: many improved latency percentiles cannot cancel a severe throughput or reliability regression. Main findings must name important adverse cases. Reference rows shown only once are context, not evidence of stability: investigate control-run drift and include paired control data when needed.

## Report boundary, structure and metadata

Each generated report has exactly two chapters: `Benchmark setup` (the numbered plain lines 1. Test Environment, 2. Test Conditions, 3. Test Tool Versions, 4. Test Methodology — bold lines, not headings, with their full metadata in default-collapsed folds) and `Results` (the per-scenario sections). A report rendered as a PR comment (`--fold`) carries no top-level title: the fold's summary line is the title. Environment rows render host, kernel, CPU, memory, TNG version and TNG source revision only; the manifest-era fields (binary checksum, source-state, dirty, build command/environment, build time, run ID) are not rendered — the source revision is the identity.

Sections `1. Test Environment`, `2. Test Conditions`, and `3. Test Tool Versions` each MUST show BOTH:

- An expanded difference table (`Item | Baseline | Experimental`) containing all changed entries. When nothing changed, show `No differences.` outside the fold; this statement never replaces the full table.
- Immediately below, a default-collapsed `<details>` block containing the COMPLETE actual metadata table (`Item | Baseline | Experimental`), including unchanged entries. Use a clear summary such as `Full test environment`, `Full test conditions`, or `Full test tool versions`. Include fields present on only one side and explicitly identify missing metadata. Render both presentations from the same collected metadata, with consistent field order and values. Do not replace the full tables with a link or difference-only view. Redact sensitive values consistently without inventing public measurements.

Keep `4. Test Methodology` as a visible heading, with its reusable methodology text inside a default-collapsed `<details><summary>Test methodology and metric definitions</summary>` block. Keep comparison legends outside this block beside the tables they explain. Use canonical script-generated methodology rather than rewriting it for each PR; verify it describes the actual run. If sampling, aggregation, topology or tooling differs from the canonical method, disclose the deviation visibly and update the actual methodology. Fixed boilerplate must not assert conditions that were not measured.

## Measured binary identity is required

`git unknown`, missing revision, or a revision guessed from the report-generation machine is an identity/collection failure, not a valid final benchmark version. Before publishing a performance claim, investigate and repair version collection or establish identity from the retained build/deployment manifest, then regenerate the report from verified metadata. Do not replace unknown with today's HEAD or change historical metadata without evidence. If historical identity cannot be recovered, preserve the original evidence and mark the run unverified; rerun with recorded identity before using it as reproducible final proof.

Record ingress and egress binary identities separately for both baseline and experimental runs. Capture the full source commit at build time, dirty-tree/patch identity when applicable, build settings and a binary checksum; verify checksums after deployment and associate them with run IDs. A Git lookup in the benchmark host's working directory is not proof of the deployed binary's source version, even if it succeeds. An explicitly supplied `TNG_GIT` value must match the deployed build manifest; a bare unvalidated environment string is not proof either. Report-generation scripts must detect missing/unknown identities and host mismatches, report actionable diagnostics, and never silently pass them off as a reproducible final comparison. Intentional mixed-version runs must explicitly identify each host's revision.

## Evidence and attribution

Combined optimizations must be labeled as combined results. If a PR contains or depends on other optimizations, list the exact tested composition. Attribute an individual benefit only with an isolating comparison (e.g. before, prerequisite only, prerequisite plus this change); otherwise explicitly say the contribution is not isolated. Recheck the final PR diff, title, dependencies and benchmark binary together after rebases or splitting PRs.

Do not write `no regressions`, `unchanged`, `within noise`, `parity`, or `target met` unless supported across the stated scope. A fixed display tolerance is not an empirically measured noise band. For anomalies, show the numbers and mark the cause unknown until investigated. Investigate or repeat relevant cases when a regression, surprising memory increase, baseline drift, or tail spike affects the conclusion. Keep preliminary results labeled preliminary when evidence is incomplete; do not erase them or fabricate certainty. Distinguish fast iteration measurements from final evaluation runs and disclose limitations.

## Multi-optimization PRs: per-step ablation reports

When a PR lands multiple separable optimizations (each commit or commit group is an independently meaningful change), per-step ablation evidence is mandatory, not optional:

- The main full comparison report (PR head vs PR baseline) remains the PR-level result and keeps its mandatory expanded structure.
- The Ablation section must additionally contain ONE full comparison report PER optimization step, produced by the same `bench/gen-report.sh --compare` pipeline and in the same format as the main report (metadata difference tables, five-class cell markers, per-scenario count tables, complete data tables): step 1 = PR baseline vs step-1 tree, step N = step-(N-1) tree vs step-N tree. Test-only and tooling-only commits get no report; the ablation summary table states them as such.
- Each per-step report is wrapped in ONE default-collapsed `<details>` block (no `open` attribute) whose summary names the step, its arm source revisions and run IDs. The whole report is collapsed, unlike the main report whose main findings and count tables stay visible.
- The body carries ONLY the compact link lines; every number lives inside the comment reports themselves. No hand-written per-step summary tables, composition statements, or cross-check paragraphs in the body: they duplicate what the comment reports already show.
- Each per-step report is a separate measurement with its own run identities and binary manifests; never mix its numbers into the main-matrix narrative. Hand-built per-step tables do not satisfy this rule; if the generator cannot yet render ablation arms, extend and verify it against retained input data first, exactly as for the main report.

## Automated implementation and remaining reviewer checks

`bench/gen-report.sh --compare` now generates the five-class cell markers, exact-header per-metric count tables and Count (%) totals from the same function/data. It also generates the report separator, expanded metadata differences plus collapsed full metadata, segmented/collapsed methodology, expanded scenario findings and compact legends, collapsed complete data, and separate reference/control drift comparisons. No hand-editing or hand-counting is needed. The generated numerical findings identify adverse measurements without inventing causes.

The renderer rejects unreadable/malformed JSON, empty/unsupported results, invalid metric ranges, missing workload/concurrency pairs, missing/nonfinite metrics and undefined percentage denominators rather than silently skipping them or adding N/A classes. It validates identities for both hosts/runs and intentional mixed-version reporting requires `--allow-mixed-versions`. Failed validation returns nonzero and does not replace an existing report. Always check the exit status before using a report; an older file left in place is not fresh evidence.

New runs require a build manifest produced by `bench/record-build.py` while executing the build. Deploy the manifest beside the executable as `<binary>.build.json` (or set `TNG_BUILD_MANIFEST`), and deploy `report_support.py` with the benchmark scripts. Client/server preflight and metadata capture verify the deployed executable checksum/version against that manifest. `TNG_GIT` no longer falls back to the benchmark host's HEAD; if explicitly set, it must equal the manifest's full source commit. Configuration checksums, warmup, mux settings and run IDs are retained in collected metadata.

See [reporting.md](reporting.md) for commands and offline tests. For historical data without verified build manifests, `--allow-unverified` deliberately emits a prominent PRELIMINARY / UNVERIFIED banner; it does not repair identity, waive result completeness or authorize using the output as final proof. Do not fabricate manifests for past binaries.

Agent/reviewer checks still required: explanation of the change and actual bottleneck, isolation of combined optimization benefits, final PR head versus the measured build, actual acceptance criteria, diagnosis/retesting of anomalies, source/configuration semantics, and accuracy of prose claims against generated metrics. In particular, never say every metric improved when success remained stable or CPU worsened; distinguish supplementary A/B measurements from the main matrix with their own run identities and values. Generated methodology is grouped into topology, workloads, latency/success, resource sampling and comparison; keep detailed methods collapsed and only a compact legend outside it.

## Narrative consistency and methodology presentation

Before publishing or updating the PR body, check the narrative against the final generated report:

1. **Scope improvement claims precisely.** `Every metric improved` is valid only if every eligible metric in the stated scope is 🟢. Stable success rates must be described as stable; resource regressions must be disclosed. Prefer explicit wording such as `RPS and latency improved; success remained stable; CPU increased at these concurrency levels`. Do not turn a favorable overall result into a claim that every cell improved.
2. **Trace each quoted example to its dataset.** Each before/after number, resource example and range must match the named scenario, workload, concurrency, metric, units and run pair in the full report. A dedicated A/B study or another rerun needs its own run IDs and an explicit label; do not silently mix its numbers with the main matrix. If the narrative and report disagree, establish the correct source and update the wording or regenerate the report from verified inputs. Never edit a measured table to fit a headline.
3. **Qualify no-regression claims.** If any displayed metric worsened, do not write an unqualified `no other metric regressed`. Name the affected scope and disclose the adverse cases, including control-mode and tail-latency regressions. A suspected noisy measurement remains an observation requiring explanation or repetition; it cannot be dismissed solely because other metrics improved.
4. **Keep the method section visually contained.** Keep the visible `4. Test Methodology` heading, with topology, workloads, latency/success definitions, resource sampling and detailed comparison rules grouped inside default-collapsed details. Use blank lines between topics and short bullets; do not insert arbitrary hard line breaks within paragraphs. Outside the fold, retain only the compact legend and counting scope beside the relevant result table. Do not follow the fold with a long repeated methodology/comparison paragraph. Verify the actual `<details>` / `</details>` structure and absence of `open`; text-only page extraction may include collapsed content and does not establish the rendered fold state.

These checks apply to the final PR narrative even when all tables are script-generated. Preserve the generated report as evidence; update prose to reflect the evidence.

## Required pre-publication checks

Before creating or updating the PR body, verify each item and fix wording or obtain missing evidence within the authorized work:

- Title describes the concrete change/purpose without unsupported performance promises.
- Configuration semantics agree with the final code and docs.
- Baseline/head identities and actual tested configuration are recorded; final head differences are disclosed.
- Dependency/combined-result attribution is explicit; issue-closing language matches acceptance criteria.
- Every numeric headline is traceable to a full-report cell and names its scope and comparator.
- Full scenario tables retain every result and are collapsed by default; main findings, exact-header count tables and legends remain expanded.
- The embedded report is the current generator's freshly generated output (a leftover older file is not evidence); reference percentages and marker comparators are unambiguous.
- CPU, memory, tail latency, errors and single-concurrency behavior are assessed where measured; anomalies are disclosed.
- Reproduction parameters and retained report/raw-data references are supplied; unknowns and skipped checks are explicit.
- Report boundary has a horizontal rule; metadata sections 1-3 show expanded differences AND collapsed full actual tables; section 4 methodology is collapsed. Both hosts' measured binary identities are verified, with no unknown revision presented as final proof.
- For multi-optimization PRs: every optimization step carries its own generator-produced before/after report in the Ablation section, each fully collapsed in one details block with arm revisions and run IDs; the main report remains the PR-level result; the isolated-delta headline table and composition statement stay visible outside the folds.
- The final body is readable on GitHub: logical heading depth, working links, valid tables, and correctly closed details blocks.

If a check cannot be satisfied, state the precise limitation and avoid the corresponding claim. These checks do not authorize publishing a PR or running an expensive benchmark beyond the user's task scope.
