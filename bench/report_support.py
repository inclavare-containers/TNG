"""Shared benchmark validation and five-class comparisons (standard library only)."""
import hashlib
import math
import re

CLASSES = [('🟢', 'Improved (>1%)'), ('⚪', 'Stable (±1%)'), ('🟡', 'Mild degradation (>1–5%)'),
           ('🟠', 'Moderate degradation (>5–15%)'), ('🔴', 'Severe degradation (>15%)')]
HIGHER_BETTER = {'throughput', 'rps', 'success_pct'}


def number(value):
    if isinstance(value, bool):
        return None
    try:
        value = float(value)
        return value if math.isfinite(value) else None
    except (TypeError, ValueError):
        return None


def classify(before, after, metric):
    b, a = number(before), number(after)
    if b is None or a is None or b <= 0 or a < 0:
        raise ValueError(f'{metric}: need finite nonnegative measurements and a positive before value; got {before!r} -> {after!r}')
    change = (a - b) / b * 100
    favorable = change if metric in HIGHER_BETTER else -change
    # Round only float arithmetic noise at threshold boundaries, not measurements.
    favorable = round(favorable, 10)
    if favorable > 1:
        return 0, change
    if favorable >= -1:
        return 1, change
    if favorable >= -5:
        return 2, change
    if favorable >= -15:
        return 3, change
    return 4, change


def sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def check_identity(meta, context):
    # The source revision (commit id) is the benchmark identity. A build
    # manifest, when present, is checked for consistency but is optional.
    build = meta.get('tng_build', {})
    if not isinstance(build, dict):
        build = {}
    errors = []
    if not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', str(meta.get('tng_git', ''))):
        errors.append('missing full source revision')
    if not meta.get('tng_version') or 'unknown' in str(meta.get('tng_version')).lower():
        errors.append('missing measured binary version')
    if build:
        if build.get('source_commit') != meta.get('tng_git'):
            errors.append('manifest/source revision mismatch')
        if build.get('binary_sha256') and build.get('binary_sha256') != meta.get('tng_binary_sha256'):
            errors.append('manifest/binary checksum mismatch')
        if build.get('binary_version') != meta.get('tng_version'):
            errors.append('manifest/binary version mismatch')
    return [f'{context}: {error}' for error in errors]
