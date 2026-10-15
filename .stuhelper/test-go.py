#!/usr/bin/env python3
"""Run every extracted StuHelper regression using synthetic, disposable data."""
import pathlib
import re
import subprocess

root = pathlib.Path(__file__).resolve().parent.parent
paths = (root / '.stuhelper/go-regression-files.txt').read_text().splitlines()
names = set()
packages = set()
for name in paths:
    source = root / name
    tests = re.findall(r'^func (Test\w+)\(t \*testing\.T\)', source.read_text(), re.M)
    if not tests:
        raise SystemExit(f'No regression tests found in {name}')
    names.update(tests)
    packages.add('./' + str(pathlib.Path(name).parent))
pattern = '^(' + '|'.join(sorted(names)) + ')$'
print(f'Running {len(names)} named regressions from {len(paths)} files', flush=True)
subprocess.run(['go', 'test', '-tags', 'skipCi', '-count=1', '-v', *sorted(packages), '-run', pattern], cwd=root, check=True)
