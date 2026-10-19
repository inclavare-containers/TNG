#!/usr/bin/env python3
"""Render normalized benchmark scenarios as horizontal SVGs, one panel per metric.

Usage: python3 bench/svg_renderer.py <normalized-scenarios.json> --out-dir DIR
Dependency: matplotlib>=3.7. No raw report parsing and no network access:
bench/gen-svg.py adapts raw bench results JSON into the schema below.
Public Python API: render_scenario(scenario: dict, out_dir: Path).

Data contract (schema_version=1):
  {"schema_version": 1, "scenarios": [scenario, ...]}
Each scenario:
  id: A, B or C (controls the output filename).
  title: heading text.
  x: concurrency values, e.g. [1,8,16,32,64,128].
  x_label / subtitle / note: reserved metadata; not rendered.
  metrics: two to six {"key": ..., "label": ...} entries; the figure width
    scales with the panel count.
  series: list of {"id": ..., "values": {metric_key: [values...]}}.
Each value array matches the x order and length. Missing measurements MUST be
null, never zero: a partially missing series renders with a gap, a completely
missing series is omitted from every panel without extra annotations. The
renderer never converts units; ingestion normalizes them.
"""
from __future__ import annotations
import argparse
import json
import math
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter, MaxNLocator

# Stable visual identity across scenarios, including absent series.
SINGLE_STYLES = {
    'raw': ('Raw', '#94a3b8', 'D', '--'),
    'stunnel': ('stunnel', '#ca8a04', 'v', '-'),
    'haproxy': ('HAProxy', '#2563eb', 's', '-'),
    'nginx-stream': ('nginx stream (TLS)', '#16a34a', 'h', '-'),
    'nginx-http': ('nginx http (TLS)', '#c2410c', '*', '-'),
    'rats-tls': ('TNG rats-tls', '#008577', 'o', '-'),
    'rats-tls+mux': ('TNG rats-tls+mux', '#8b5cf6', '^', '-'),
    'ohttp': ('TNG ohttp', '#e05275', 'P', '-'),
}


def _with_compare_variants(styles):
    # Compare mode draws one workload twice: the ':baseline' variant keeps the
    # color but goes dashed with a hollow marker, the ':experimental' variant
    # is the single-mode style. Reference workloads never need the pair and
    # stay on their single style.
    out = dict(styles)
    for wid, (label, color, marker, linestyle) in styles.items():
        out[f'{wid}:baseline'] = (f'{label} (baseline)', color, marker, '--', 'none')
        out[f'{wid}:experimental'] = (f'{label} (experimental)', color, marker, linestyle)
    return out


STYLES = _with_compare_variants(SINGLE_STYLES)


def validate(s):
    if not 2 <= len(s['metrics']) <= 6:
        raise ValueError('Between two and six metrics required')
    if not s['x'] or len(set(s['x'])) != len(s['x']):
        raise ValueError('x must contain unique concurrency values')
    ids = [v['id'] for v in s['series']]
    if len(set(ids)) != len(ids):
        raise ValueError('Duplicate series ids')
    for series in s['series']:
        if series['id'] not in STYLES:
            raise ValueError(f"Unknown series id: {series['id']}")
        for m in s['metrics']:
            vals = series['values'][m['key']]
            if len(vals) != len(s['x']):
                raise ValueError('Each metric array must match x length')
            if any(v is not None and (isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or v < 0) for v in vals):
                raise ValueError('Metric values must be finite nonnegative numbers or null')


def render_scenario(s: dict, out_dir: Path):
    """Render one already-normalized scenario; does not transform units."""
    validate(s)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({
        'font.family': 'DejaVu Sans', 'font.size': 11,
        'svg.fonttype': 'none', 'svg.hashsalt': 'benchmark-renderer-v1',
        'axes.spines.top': False, 'axes.spines.right': False,
        'axes.edgecolor': '#333333', 'text.color': '#111111',
        'axes.labelcolor': '#111111', 'xtick.color': '#111111',
        'ytick.color': '#111111', 'savefig.facecolor': 'white',
    })
    fig, axes = plt.subplots(1, len(s['metrics']), figsize=(6.0 * len(s['metrics']), 5.6))
    fig.suptitle(s['title'], fontsize=15)
    for ax, metric in zip(axes, s['metrics']):
        for series in s['series']:
            label, col, marker, ls = STYLES[series['id']][:4]
            fill = STYLES[series['id']][4] if len(STYLES[series['id']]) > 4 else 'full'
            vals = series['values'][metric['key']]
            if all(v is None for v in vals):
                continue
            ax.plot(range(len(s['x'])),
                    [float('nan') if v is None else v for v in vals],
                    color=col, marker=marker, linestyle=ls,
                    lw=1.5, ms=4.5, fillstyle=fill, label=label)
        ax.set_title(metric['label'], fontsize=13, weight='bold')
        ax.set_ylabel(metric['label'])
        ax.set_xticks(range(len(s['x'])), s['x'])
        ax.set_xlabel('Concurrency')
        ax.set_ylim(bottom=0)
        ax.margins(x=.04, y=.13)
        ax.yaxis.set_major_locator(MaxNLocator(nbins=6))
        ax.yaxis.set_major_formatter(FuncFormatter(
            lambda v, _: f'{v:,.0f}' if v >= 100 or v.is_integer() else f'{v:g}'))
        ax.grid(axis='y', alpha=.2)
        ax.set_axisbelow(True)
        ax.legend(fontsize=8, loc='best')
    fig.tight_layout()
    stem = out_dir / f"scenario_{s['id'].lower()}"
    fig.savefig(stem.with_suffix('.svg'), metadata={'Date': None, 'Creator': 'svg_renderer.py'})
    fig.savefig(stem.with_suffix('.png'), dpi=160)
    plt.close(fig)
    return stem.with_suffix('.svg')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('data', type=Path, help='normalized scenario JSON (schema_version=1)')
    p.add_argument('--out-dir', type=Path, required=True)
    args = p.parse_args()
    data = json.loads(args.data.read_text(encoding='utf-8'))
    if data.get('schema_version') != 1:
        raise ValueError('Expected schema_version=1')
    for scenario in data['scenarios']:
        print(render_scenario(scenario, args.out_dir))


if __name__ == '__main__':
    main()
