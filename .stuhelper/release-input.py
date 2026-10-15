#!/usr/bin/env python3
"""Derive the immutable source identity; never download or patch source at build time."""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess

root = pathlib.Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser()
parser.add_argument('--component-version', required=True)
parser.add_argument('--output', type=pathlib.Path, required=True)
args = parser.parse_args()
upstream = json.loads((root / '.stuhelper/upstream.json').read_text())
if not re.fullmatch(re.escape(upstream['version']) + r'-stuhelper\.[1-9][0-9]*', args.component_version):
    raise SystemExit('Component version must identify the pinned upstream release and a positive revision')
def git(*args):
    return subprocess.check_output(['git', *args], cwd=root, text=True).strip()
if git('status', '--porcelain', '--untracked-files=normal'):
    raise SystemExit('Release inputs require a clean committed source tree')
subprocess.run(['git', 'merge-base', '--is-ancestor', upstream['commit'], 'HEAD'], cwd=root, check=True)
inputs = {
    'schemaVersion': 1,
    'sourceRepository': 'https://github.com/StuHelper/stuhelper-sso',
    'sourceCommit': git('rev-parse', 'HEAD'),
    'sourceTree': git('rev-parse', 'HEAD^{tree}'),
    'sourceDateEpoch': int(git('show', '-s', '--format=%ct', 'HEAD')),
    'upstreamRepository': upstream['repository'],
    'upstreamCommit': upstream['commit'],
    'upstreamVersion': upstream['version'],
    'componentVersion': args.component_version,
    'databaseMajor': upstream['databaseMajor'],
    'rollbackPolicy': upstream['rollbackPolicy'],
    'toolchains': json.loads((root / '.stuhelper/toolchains.json').read_text()),
    'files': {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in (
        'go.mod', 'go.sum', 'web/package.json', 'web/yarn.lock', '.stuhelper/Dockerfile', '.stuhelper/build.sh',
    )},
}
canonical = json.dumps(inputs, sort_keys=True, separators=(',', ':')).encode()
inputs['releaseInputSHA256'] = hashlib.sha256(canonical).hexdigest()
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(json.dumps(inputs, indent=2) + '\n')
