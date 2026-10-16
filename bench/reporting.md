# Reproducible benchmark reports

## Build and deployment identity

From the source checkout, execute the actual build through the recorder:

```bash
python3 bench/record-build.py --source . --binary target/release/tng --build-command 'make bin-build'
```

This records the full commit, dirty source fingerprint, executed build command/settings, build time, version and binary SHA-256 in `target/release/tng.build.json`. It fails if source changes during the build. Keep build outputs/manifests in a Git-ignored directory. Retain the actual dirty patch and untracked source files with the run artifacts when the source is dirty; a fingerprint alone does not reconstruct them. The recorder cannot prove that an arbitrary supplied command genuinely rebuilt the executable; use the project's real build target and review build logs.

Deploy the binary and manifest together, renaming the manifest to match the deployed executable (`tng` plus `tng.build.json`). Set `TNG_BIN` to that executable on both hosts. `TNG_BUILD_MANIFEST` can name another manifest path. Deploy `bench/client.sh`, `bench/server.sh`, `bench/lib/common.sh`, `bench/gen-report.sh` and `bench/report_support.py` with the same relative layout. Version collection fails before running loads if the manifest is missing or the deployed checksum/version differs. An explicitly supplied `TNG_GIT` must equal the full manifest commit. Do not generate a new identity from a remote working directory or backfill an old run from today's HEAD.

Run the existing benchmark workflow; both host-info JSONs include verified build identity and run metadata. Copy the server-info JSON to the controller alongside the client-info and results. Preserve all raw logs and configuration files privately; the report displays configuration hashes and redacts host endpoint identities. Review custom build commands and any additional metadata for sensitive values before publishing.

## Generate a comparison

```bash
bash bench/gen-report.sh --compare base-server-info.json base-client-info.json base-results.json head-server-info.json head-client-info.json head-results.json comparison.md
```

The file includes a leading `---` separator. Paste the generated report below the PR narrative, leaving a blank line before the separator. Metadata differences are expanded; complete metadata, segmented methodology and full scenario tables are collapsed by default. Five-class counts use the same unrounded values/function as cell markers. Main TNG summaries and reference/control summaries have separate explicit scopes.

Validation errors leave any previous output untouched and return nonzero: check the exit status, do not publish a stale file. Missing fields, malformed inputs and incomplete matrices are errors. A zero baseline has no defined relative percentage and needs investigation; it is not classified as stable. No N/A count row is emitted. Success-rate declines are explicitly listed even inside the display tolerance. Different before/after parameters remain visibly highlighted; do not attribute a gain to code until confounding changes are resolved.

For intentional mixed-version compatibility runs, add `--allow-mixed-versions`; host identities remain visible. For retained historical inputs without verified manifests, add `--allow-unverified` only to inspect preliminary evidence. It prints an explicit unverified banner and does not relax metric completeness. Neither flag fabricates measurements or proves a final performance claim.

Compare mode takes `--metrics m1,m2` to restrict every table to the metric columns a partial or historical run actually collected (for example an ablation driver that recorded only RPS and egress CPU); a results file containing measured columns outside the subset is rejected, and a mode present in only one run still needs its full matrix. Modes absent from both runs are reported as not measured. Compare mode also takes `--deltas FILE`, writing a companion per-workload table of before/after change percentages with min/max/mean rows over concurrencies, computed from the same unrounded data as the five-class markers; headline isolated-delta tables must quote these values rather than recompute them.

Single-run reports retain the original positional arguments (`server-info client-info results [output.md]`) and show collapsed complete data without before/after count tables.

## Offline verification

```bash
python3 bench/test_report.py
bash -n bench/gen-report.sh bench/lib/common.sh bench/client.sh bench/server.sh
```

The tests use synthetic JSON and a local fixture executable. They exercise class thresholds/direction, matching count totals, collapsed structure, identity validation, bad/missing measurements, historical/mixed-version flags, and deployed-binary tampering. They do not run TNG benchmarks or contact a service.

## PR presentation: reports as comments

Full comparison reports exceed GitHub's PR body limit, so they live as PR
comments maintained in place:

```bash
# one report per comment, whole report inside a fold with a compact summary
bash bench/gen-report.sh --compare --fold "Full benchmark: <base>...<head>" \
  <inputs...> main.md
bash bench/gen-report.sh --compare --fold "Ablation step 1: <a>...<b> (change)" \
  <inputs...> step1.md
# post or patch in place (matched by the fold summary line; never duplicated)
bash bench/pr-report-comments.sh <pr-number> <owner/repo> <comment-manifest.tsv>
```

The manifest lists one comment markdown file per line. The body links to each
comment with the same compact text: `Full benchmark: [<a>...<b>](url)` and
`Ablation step N: [<a>...<b>](url) (short description)`.

The PR communication requirements are in [performance-pr-requirements.md](performance-pr-requirements.md). Interpretations and prose still require review: the script does not infer bottleneck causes, prove statistical significance, isolate combined optimization benefits or decide whether an issue is closed.
