#!/usr/bin/env python3
"""Run a build and record source state plus binary identity for deployment."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import sys
sys.dont_write_bytecode = True

from report_support import sha256


def source_state(root):
    def git(*args):
        return subprocess.check_output(['git', '-C', str(root), *args])
    commit = git('rev-parse', 'HEAD').decode().strip()
    status = git('status', '--porcelain', '-z')
    digest = hashlib.sha256(git('diff', 'HEAD', '--binary'))
    for rel in sorted(git('ls-files', '--others', '--exclude-standard', '-z').split(b'\0')):
        if rel:
            path = root / os.fsdecode(rel)
            digest.update(rel + b'\0')
            digest.update(os.readlink(path).encode() if path.is_symlink() else path.read_bytes())
    return commit, bool(status), digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', default='.', help='Git source tree used for the build')
    parser.add_argument('--binary', required=True, help='Built executable, relative to source or absolute')
    parser.add_argument('--build-command', required=True, help='Exact shell build command to execute in source')
    parser.add_argument('--output', help='Default: <binary>.build.json; deploy beside the binary')
    args = parser.parse_args()
    root = Path(args.source).resolve()
    binary = (root / args.binary).resolve()
    before = source_state(root)
    subprocess.run(args.build_command, cwd=root, shell=True, executable='/bin/bash', check=True)
    if source_state(root) != before:
        raise ValueError('Source changed during build; no manifest written. Use an isolated build or rerun with stable source.')
    version = subprocess.check_output([str(binary), '--version'], universal_newlines=True).strip().splitlines()[0]
    manifest = {
        'schema_version': 1, 'source_commit': before[0], 'dirty': before[1],
        'source_state_sha256': before[2], 'binary_sha256': sha256(binary),
        'binary_version': version, 'build_command': args.build_command,
        'build_environment': {k: os.environ[k] for k in ('RUSTFLAGS', 'CARGO_BUILD_TARGET', 'CC', 'CXX') if k in os.environ},
        'created_at_utc': datetime.now(timezone.utc).isoformat(),
    }
    output = Path(args.output) if args.output else Path(str(binary) + '.build.json')
    with tempfile.NamedTemporaryFile('w', dir=output.parent, delete=False) as f:
        json.dump(manifest, f, indent=2)
        f.write('\n')
        temp = f.name
    os.replace(temp, output)
    print(output)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as e:
        raise SystemExit(f'Build identity error: {e}')
