#!/usr/bin/env python3
"""Offline report/identity regression tests; no services, builds or network required."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from report_support import classify


def metadata(commit='a' * 40):
    build = {'schema_version': 1, 'source_commit': commit, 'binary_sha256': 'b' * 64, 'dirty': False,
             'source_state_sha256': 'c' * 64, 'build_command': 'make bin-build',
             'created_at_utc': '2026-01-01T00:00:00+00:00', 'binary_version': 'tng test'}
    return {'tng_git': commit, 'tng_binary_sha256': 'b' * 64,
            'tng_build': build, 'tng_identity_verified': True, 'tng_version': 'tng test',
            'host': 'private-host', 'ip': '192.0.2.1', 'uname': 'Linux private-host 6.0 x86_64',
            'cpu_count': 4, 'cpu_model': 'test CPU', 'mem': '123 kB', 'run_id': 'synthetic',
            'tools': {}, 'params': {'ra_mode': '1', 'http_body_kb': '64'}}


def results():
    data = {}
    for prefix in ('iperf3+', 'http+', 'http-shortconn+'):
        for mode in ('raw', 'stunnel', 'haproxy', 'rats-tls', 'rats-tls+mux', 'ohttp'):
            if prefix == 'iperf3+' and mode == 'ohttp':
                continue
            values = {k: 100 for k in ('throughput', 'cpu_pct', 'mem_gb', 'rps', 'mean_us',
                      'p50_us', 'p90_us', 'p95_us', 'p99_us', 'success_pct', 'srv_cpu_pct', 'srv_mem_mib')}
            if mode == 'raw':
                for k in ('cpu_pct', 'mem_gb', 'srv_cpu_pct', 'srv_mem_mib'):
                    values[k] = 'N/A'
            data[prefix + mode] = {'1': values}
    return data


class Reports(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.base, self.exp = results(), results()
        self.metas = [metadata(), metadata(), metadata('d' * 40), metadata('d' * 40)]

    def run_report(self, flags=(), single=False):
        inputs = [self.metas[0], self.metas[1], self.base]
        if not single:
            inputs += [self.metas[2], self.metas[3], self.exp]
        paths = []
        for i, obj in enumerate(inputs):
            path = self.path / f'{i}.json'
            path.write_text(json.dumps(obj))
            paths.append(str(path))
        self.out = self.path / 'report.md'
        self.out.write_text('previous report')
        p = subprocess.run(['bash', str(ROOT / 'gen-report.sh'), *([] if single else ['--compare']),
                            *flags, *paths, str(self.out)], universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return p, self.out.read_text()

    def test_boundary_classes_and_direction(self):
        for after, expected in [(102, 0), (101, 1), (100, 1), (99, 1), (98.999, 2), (95, 2),
                                (94.999, 3), (85, 3), (84.999, 4)]:
            self.assertEqual(classify(100, after, 'rps')[0], expected)
        self.assertEqual(classify(100, 110, 'p99_us')[0], 3)
        self.assertEqual(classify(100, 80, 'srv_mem_mib')[0], 0)
        for bad in (None, 'N/A', float('nan'), float('inf'), -1, True):
            with self.assertRaises(ValueError):
                classify(100, bad, 'rps')
        with self.assertRaises(ValueError):
            classify(0, 1, 'rps')

    def test_five_classes_counts_folds_and_metadata(self):
        self.exp['http+ohttp']['1'].update(rps=120, mean_us=100, p50_us=102, p95_us=110, p99_us=120)
        p, text = self.run_report()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertTrue(text.startswith('---\n\n#'))
        self.assertEqual(text.count('<details>'), text.count('</details>'))
        self.assertNotIn('<details open', text)
        self.assertIn('No differences.\n\n<details>\n<summary>Full test conditions', text)
        method = text.split('## 4. Test Methodology')[1].split('## 5. Results')[0]
        self.assertIn('<details>', method)
        self.assertIn("**Workloads and run parameters**\n\n- ", method)
        # Scope counts: 3 modes * 10 metrics = 30; references are separate.
        b = text.split('### Scenario B')[1].split('**Reference/control')[0]
        self.assertIn('| **Total** | **30 (100.0%)** |', b)
        self.assertIn('| Change class | Count (%) | Throughput (Gbps) | RPS | Mean (us)', b)
        for marker in ('🟢', '⚪', '🟡', '🟠', '🔴'):
            self.assertIn(marker, b)
        self.assertIn('120 (+20%)🟢', b)
        self.assertNotIn('N/A', b)
        self.assertNotIn('private-host', text)
        self.assertNotIn('192.0.2.1', text)
        self.assertIn('Client TNG source revision', text)
        self.assertIn('Server TNG source revision', text)
        # The retained baseline and experimental result rows have not been pruned.
        self.assertIn('ohttp(baseline)', b)
        self.assertIn('ohttp(experimental)', b)

    def test_counts_reconcile_with_markers(self):
        self.exp['http+ohttp']['1'].update(rps=120, mean_us=99, p50_us=103, p95_us=115, p99_us=116)
        p, text = self.run_report()
        self.assertEqual(p.returncode, 0, p.stderr)
        block = text.split('### Scenario B')[1].split('### Scenario C')[0]
        summary, full = block.split('<details>', 1)
        for symbol in ('🟢', '⚪', '🟡', '🟠', '🔴'):
            row = next(x for x in summary.splitlines() if x.startswith('| ' + symbol))
            cells = [x.strip() for x in row.strip('|').split('|')]
            total = int(cells[1].split()[0])
            self.assertEqual(total, sum(map(int, cells[2:])))
            self.assertEqual(total, full.count(symbol))

    def test_ohttp_only_subset_compares_cleanly(self):
        for res in (self.base, self.exp):
            for w in list(res):
                if not w.endswith('ohttp'):
                    del res[w]
        self.exp['http+ohttp']['1'].update(rps=120)
        p, text = self.run_report()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('Not measured in either run.', text)
        self.assertIn('| **Total** | **10 (100.0%)** |', text)
        self.assertNotIn('Reference/control', text)
        self.assertNotIn('Parenthesized percentages are vs the displayed baseline-run raw row.', text)
        self.assertNotIn('Scope:', text)

    def test_partial_data_renders_full_format(self):
        # A dataset that recorded only some metrics still renders the full
        # column set; uncollected cells are '-' and stay out of the counts.
        for res in (self.base, self.exp):
            for w in list(res):
                if not w.endswith('ohttp'):
                    del res[w]
        for res in (self.base, self.exp):
            for w in res:
                for c in res[w]:
                    res[w][c] = {'rps': res[w][c]['rps'], 'srv_cpu_pct': res[w][c]['srv_cpu_pct']}
        self.exp['http+ohttp']['1']['rps'] = 120
        p, text = self.run_report()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('| Mean (us) |', text)
        self.assertIn('| **Total** | **2 (100.0%)** |', text)
        seg = text.split('Full Scenario B')[1]
        self.assertIn('**-**', seg)

    def test_optional_ingress_cpu_metric(self):
        for res in (self.base, self.exp):
            for w in list(res):
                if not w.endswith('ohttp'):
                    del res[w]
        for res in (self.base, self.exp):
            for w in res:
                for c in res[w]:
                    res[w][c] = {'rps': res[w][c]['rps'],
                                 'srv_cpu_pct': res[w][c]['srv_cpu_pct'],
                                 'cli_cpu_pct': res[w][c]['srv_cpu_pct'] / 2}
        self.exp['http+ohttp']['1']['rps'] = 120
        self.exp['http+ohttp']['1']['cli_cpu_pct'] = 40
        p, text = self.run_report()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('| Ingress CPU % |', text)
        self.assertIn('| **Total** | **3 (100.0%)** |', text)
        for res in (self.base, self.exp):
            for w in res:
                for c in res[w]:
                    del res[w][c]['cli_cpu_pct']
        p, text = self.run_report()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('| Ingress CPU % |', text)
        self.assertIn('| **Total** | **2 (100.0%)** |', text)

    def test_missing_cell_fails_without_overwriting(self):
        del self.exp['http+ohttp']['1']['p99_us']
        p, text = self.run_report()
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('p99_us', p.stderr)
        self.assertEqual(text, 'previous report')

    def test_missing_pair_and_missing_mode_fail(self):
        del self.exp['http+ohttp']['1']
        p, _ = self.run_report()
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('concurrency', p.stderr)
        self.exp = results()
        del self.base['http+ohttp']
        p, _ = self.run_report()
        self.assertNotEqual(p.returncode, 0)

    def test_unknown_identity_strict_and_preliminary(self):
        for m in self.metas:
            m['tng_git'] = 'unknown'
        p, text = self.run_report()
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(text, 'previous report')
        p, text = self.run_report(['--allow-unverified'])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('PRELIMINARY / UNVERIFIED', text)

    def test_mixed_hosts_require_explicit_option(self):
        self.metas[0] = metadata('e' * 40)
        p, _ = self.run_report()
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('--allow-mixed-versions', p.stderr)
        p, text = self.run_report(['--allow-mixed-versions'])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('Intentional mixed-version', text)

    def test_single_run_folds_without_comparison_counts(self):
        p, text = self.run_report(single=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('<summary>Full test environment', text)
        self.assertNotIn('| Change class | Count (%) |', text)

    def test_invalid_json_fails(self):
        bad = self.path / 'bad.json'
        bad.write_text('{bad')
        p = subprocess.run(['bash', str(ROOT / 'gen-report.sh'), str(bad)] * 1 +
                           [str(bad), str(bad), str(self.path / 'out')], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('Invalid input', p.stderr)

    def test_build_manifest_and_deployed_checksum(self):
        repo = self.path / 'repo';repo.mkdir()
        (repo / '.gitignore').write_text('target/\n')
        # Tiny local executable fixture; this does not build or run TNG.
        (repo / 'version.sh').write_text('#!/bin/sh\necho "tng fixture"\n')
        def git(*args):
            return subprocess.run(['git', '-C', str(repo), *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, check=True)
        git('init');git('add', '.');git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--no-gpg-sign', '-m', 'fixture')
        p = subprocess.run([sys.executable, str(ROOT / 'record-build.py'), '--source', str(repo), '--binary', 'target/tng',
                            '--build-command', 'mkdir -p target && cp version.sh target/tng && chmod +x target/tng'], universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(p.returncode, 0, p.stderr)
        binary = repo / 'target/tng'
        command = f'source "{ROOT}/lib/common.sh"; TNG_BIN="{binary}"; verify_tng_build'
        p = subprocess.run(['bash', '-c', command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        binary.write_text('#!/bin/sh\necho "tng changed"\n')
        p = subprocess.run(['bash', '-c', command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('mismatch', p.stderr)


if __name__ == '__main__':
    unittest.main()
