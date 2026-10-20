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

# Visual hierarchy: the TNG series are the protagonists (thick solid,
# high-saturation) and every reference baseline is a muted gray with its own
# dash pattern, so a reader finds the TNG lines instantly and the references
# stay readable but subordinate. Raw is the softest (upper-bound context).
STYLE_FIELDS = {
    'raw':          dict(label='Raw', color='#c8c8c8', marker='D', ls='-', lw=1.8, ms=4, alpha=1.0, zorder=1),
    'stunnel':      dict(label='stunnel', color='#adadad', marker='v', ls=':', lw=1.2, ms=4, alpha=0.9, zorder=2),
    'haproxy':      dict(label='HAProxy', color='#8f8f8f', marker='s', ls='-.', lw=1.2, ms=4, alpha=0.9, zorder=2),
    'nginx-stream': dict(label='nginx stream (TLS)', color='#808080', marker='h', ls='--', lw=1.2, ms=4, alpha=0.9, zorder=2),
    'nginx-http':   dict(label='nginx http (TLS)', color='#6f6f6f', marker='*', ls=(0, (3, 1, 1, 1)), lw=1.2, ms=4, alpha=0.9, zorder=2),
    'rats-tls':     dict(label='TNG rats-tls', color='#0072B2', marker='o', ls='-', lw=2.6, ms=7, alpha=1.0, zorder=5),
    'rats-tls+mux': dict(label='TNG rats-tls+mux', color='#56B4E9', marker='^', ls='-', lw=2.6, ms=7, alpha=1.0, zorder=5),
    'ohttp':        dict(label='TNG ohttp', color='#D55E00', marker='P', ls='-', lw=2.6, ms=8, alpha=1.0, zorder=5),
}

def _with_compare_variants(styles):
    # Compare mode draws one workload twice: the ':baseline' variant keeps the
    # color but goes thin and dashed (hollow marker), the ':experimental'
    # variant is the single-mode style. Reference workloads never need the
    # pair and stay on their single style.
    out = dict(styles)
    for wid, st in styles.items():
        base = dict(st, label=st['label'] + ' (baseline)', ls='--', lw=1.6, ms=5,
                    fillstyle='none', zorder=st['zorder'] - 1)
        out[f'{wid}:baseline'] = base
        out[f'{wid}:experimental'] = dict(st, label=st['label'] + ' (experimental)')
    return out

STYLES = _with_compare_variants(STYLE_FIELDS)


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
    n = len(s['x'])
    fig, axes = plt.subplots(1, len(s['metrics']),
                             figsize=(6.0 * len(s['metrics']) + 2.0, 5.6))
    fig.suptitle(s['title'], fontsize=15)
    for ax, metric in zip(axes, s['metrics']):
        # Plot every series, then label each line directly at its end point
        # (color-matched, deconflicted vertically): no legend boxes, the eye
        # follows the line to its name.
        plotted = []
        for series in s['series']:
            st = STYLES[series['id']]
            vals = series['values'][metric['key']]
            if all(v is None for v in vals):
                continue
            ys = [float('nan') if v is None else v for v in vals]
            ax.plot(range(n), ys, color=st['color'], marker=st['marker'],
                    linestyle=st['ls'], lw=st['lw'], ms=st['ms'],
                    alpha=st['alpha'], zorder=st['zorder'],
                    fillstyle=st.get('fillstyle', 'full'))
            last_i = max(i for i, v in enumerate(ys) if v == v)
            plotted.append((ys[last_i], st['label'], st['color']))
        ax.set_title(metric['label'], fontsize=13, weight='bold')
        ax.set_ylabel(metric['label'])
        ax.set_xticks(range(n), s['x'])
        ax.set_xlabel('Concurrency')
        ax.set_ylim(bottom=0)
        ax.set_xlim(-0.4, n - 1 + 2.6)
        ax.margins(y=.13)
        ax.yaxis.set_major_locator(MaxNLocator(nbins=6))
        ax.yaxis.set_major_formatter(FuncFormatter(
            lambda v, _: f'{v:,.0f}' if v >= 100 or v.is_integer() else f'{v:g}'))
        ax.grid(axis='y', alpha=.2)
        ax.set_axisbelow(True)
        # Direct labels at the right edge, pushed apart so they never overlap.
        y0, y1 = ax.get_ylim()
        gap = (y1 - y0) * 0.045
        plotted.sort(key=lambda t: t[0])
        placed = []
        for y, label, color in plotted:
            if placed and y - placed[-1] < gap:
                y = placed[-1] + gap
            placed.append(y)
            ax.text(n - 1 + 0.25, y, label, fontsize=9, color=color,
                    va='center', ha='left', zorder=6, clip_on=False)
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
