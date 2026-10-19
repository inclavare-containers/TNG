#!/usr/bin/env python3
"""Generate the three benchmark scenario SVG charts from raw bench JSON.

Single mode (one run; every workload becomes one series):
  python3 bench/gen-svg.py <server-info.json> <client-info.json> <results.json> --out-dir DIR

Compare mode (baseline vs experimental; TNG workloads double as
baseline/experimental pairs, reference workloads appear once with baseline
values, mirroring bench/gen-report.sh compare row logic):
  python3 bench/gen-svg.py --compare \
      <base-server-info.json> <base-client-info.json> <base-results.json> \
      <exp-server-info.json> <exp-client-info.json> <exp-results.json> --out-dir DIR

Writes scenario_a.svg, scenario_b.svg, scenario_c.svg (plus PNG previews for
local inspection; only the SVGs belong in the repository). Workload keys
follow bench/gen-report.sh conventions: `iperf3+<wl>`, `http+<wl>`,
`http-shortconn+<wl>` with workloads raw, stunnel, haproxy, rats-tls,
rats-tls+mux, ohttp. Metric values of "N/A", "-", "" or missing cells render
as gaps (JSON null); any other value must parse as a finite nonnegative
number, otherwise the adapter aborts rather than dropping the series.
Charts carry no identity text: the caller embeds them next to the report that
records the binary identity. Requires matplotlib>=3.7 (local dev dependency
for SVG generation only, see bench/reporting.md).
"""
from __future__ import annotations
import argparse
import json
import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import matplotlib  # noqa: F401  preflight so a missing dependency is one clear message
except ImportError:
    raise SystemExit('matplotlib>=3.7 is required for SVG charts: python3 -m pip install matplotlib')
from svg_renderer import render_scenario

WORKLOADS = ('raw', 'stunnel', 'haproxy', 'rats-tls', 'rats-tls+mux', 'ohttp')
TNG_WORKLOADS = frozenset({'rats-tls', 'rats-tls+mux', 'ohttp'})
PROTOCOLS = ('iperf3', 'http', 'http-shortconn')
A_METRICS = (('throughput', 'Throughput (Gbps)'),
             ('cpu_pct', 'Tunnel CPU %'),
             ('mem_gb', 'Tunnel Mem (GB)'))
HTTP_METRICS = (('rps', 'RPS'),
                ('p99_us', 'p99 (us)'),
                ('srv_cpu_pct', 'Server CPU %'))
ALLOWED_KEYS = {f'{p}+{w}' for p in PROTOCOLS for w in WORKLOADS}


def load_json(path, label):
    try:
        with open(path) as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError('expected a JSON object')
        return data
    except (OSError, ValueError) as e:
        raise SystemExit(f'Invalid input {label} ({path}): {e}')


def load_results(path, label):
    data = load_json(path, label)
    if not data or not any(data.values()):
        raise SystemExit(f'{label}: empty results; no measured workload')
    for workload, points in data.items():
        if workload not in ALLOWED_KEYS or not isinstance(points, dict):
            raise SystemExit(f"{label}: unsupported/malformed workload {workload!r}; extend the adapter rather than dropping it")
        for key, metrics in points.items():
            if not str(key).isdigit() or int(key) <= 0 or str(int(key)) != key or not isinstance(metrics, dict):
                raise SystemExit(f'{label}: invalid concurrency/metrics for {workload}: {key!r}')
    return data


def parse_value(raw, label, workload, conc, metric):
    # Unparseable values abort instead of becoming a silent gap: a chart with
    # a hidden measurement error looks exactly like an unmeasured cell.
    if raw is None:
        return None
    if isinstance(raw, bool):
        raise SystemExit(f'{label}: invalid {metric} for {workload}, concurrency={conc}: {raw!r}')
    if isinstance(raw, (int, float)):
        value = float(raw)
    elif isinstance(raw, str):
        text = raw.strip()
        if text in ('', 'N/A', '-'):
            return None
        try:
            value = float(text)
        except ValueError:
            raise SystemExit(f'{label}: invalid {metric} for {workload}, concurrency={conc}: {raw!r}')
    else:
        raise SystemExit(f'{label}: invalid {metric} for {workload}, concurrency={conc}: {raw!r}')
    if not math.isfinite(value) or value < 0:
        raise SystemExit(f'{label}: invalid {metric} for {workload}, concurrency={conc}: {raw!r}')
    return value


def body_kb(srv, cli):
    p = cli.get('params') or srv.get('params') or {}
    return str(p.get('http_body_kb', '64'))


def build_scenario(sid, title, x_label, protocol, metrics, sources):
    """sources: list of (series_id, dataset, workload); one values array per metric key."""
    pts = {series_id: dataset.get(f'{protocol}+{workload}', {}) for series_id, dataset, workload in sources}
    x = sorted({int(k) for points in pts.values() for k in points})
    series = []
    for series_id, points in pts.items():
        values = {}
        for metric_key, _label in metrics:
            values[metric_key] = [
                parse_value(points.get(str(k), {}).get(metric_key), sid, series_id, k, metric_key)
                for k in x
            ]
        series.append({'id': series_id, 'values': values})
    return {
        'id': sid,
        'title': title,
        'x': x,
        'x_label': x_label,
        'metrics': [{'key': k, 'label': lb} for k, lb in metrics],
        'series': series,
        'note': 'Scenario A resources are client-side tunnel; B/C resources are the server-side proxy component. CPU 100% = one logical core. Tunnel Mem is the legacy GB column value (peak VmRSS / 1024^2).',
    }


def scenario_titles(body):
    return (
        'Scenario A | TCP / iperf3',
        f'Scenario B | HTTP / wrk | {body} KiB | keep-alive',
        f'Scenario C | HTTP / wrk | {body} KiB | no keep-alive',
    )


def single_scenarios(srv, cli, res):
    titles = scenario_titles(body_kb(srv, cli))
    specs = (('A', titles[0], 'Parallel streams', 'iperf3', A_METRICS),
             ('B', titles[1], 'Concurrent connections', 'http', HTTP_METRICS),
             ('C', titles[2], 'Concurrent connections', 'http-shortconn', HTTP_METRICS))
    return [build_scenario(sid, title, xlabel, protocol, metrics,
                           [(w, res, w) for w in WORKLOADS])
            for sid, title, xlabel, protocol, metrics in specs]


def compare_scenarios(bsrv, bcli, bres, esrv, ecli, eres):
    body_b, body_e = body_kb(bsrv, bcli), body_kb(esrv, ecli)
    body = body_b if body_b == body_e else f'before={body_b}, after={body_e}'
    titles = scenario_titles(body)
    sources = []
    for w in WORKLOADS:
        if w in TNG_WORKLOADS:
            sources.append((f'{w}:baseline', bres, w))
            sources.append((f'{w}:experimental', eres, w))
        else:
            # Reference workloads plot once, from the baseline dataset.
            sources.append((w, bres, w))
    specs = (('A', titles[0], 'Parallel streams', 'iperf3', A_METRICS),
             ('B', titles[1], 'Concurrent connections', 'http', HTTP_METRICS),
             ('C', titles[2], 'Concurrent connections', 'http-shortconn', HTTP_METRICS))
    return [build_scenario(sid, title, xlabel, protocol, metrics, sources)
            for sid, title, xlabel, protocol, metrics in specs]


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--compare', action='store_true', help='baseline vs experimental; TNG series are drawn twice')
    p.add_argument('inputs', nargs='+', type=Path, help='3 info/results files (single) or 6 (compare)')
    p.add_argument('--out-dir', type=Path, required=True)
    args = p.parse_args()

    if args.compare:
        if len(args.inputs) != 6:
            raise SystemExit('usage: gen-svg.py --compare <base-server> <base-client> <base-results> <exp-server> <exp-client> <exp-results> --out-dir DIR')
        bsrv, bcli, bres, esrv, ecli, eres = args.inputs
        scenarios = compare_scenarios(
            load_json(bsrv, 'baseline server'), load_json(bcli, 'baseline client'), load_results(bres, 'baseline'),
            load_json(esrv, 'experimental server'), load_json(ecli, 'experimental client'), load_results(eres, 'experimental'))
    else:
        if len(args.inputs) != 3:
            raise SystemExit('usage: gen-svg.py <server-info> <client-info> <results> --out-dir DIR')
        srv, cli, res = args.inputs
        scenarios = single_scenarios(
            load_json(srv, 'server'), load_json(cli, 'client'), load_results(res, 'single run'))

    for scenario in scenarios:
        print(render_scenario(scenario, args.out_dir))


if __name__ == '__main__':
    main()
