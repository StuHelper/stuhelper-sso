#!/usr/bin/env python3
"""Export the exact source-owned built-in API policy for migration verification.

Casdoor replaces this derived table on every boot. Identity records, organization
roles and administrator-owned permission tables are not part of this projection.
A changed upstream representation requires an explicit compatibility port.
"""
import argparse
import csv
import hashlib
import json
import pathlib
import re


def export_policy(source):
    functions = re.findall(r'func InitApi\(\) \{(.*?)\nfunc ', source, re.S)
    if len(functions) != 1:
        raise ValueError('The built-in API initializer requires compatibility review')
    initializers = re.findall(r'ruleText := `(.*?)`', functions[0], re.S)
    if len(initializers) != 1 or functions[0].count('stringadapter.NewAdapter(ruleText)') != 1:
        raise ValueError('The built-in API policy source requires compatibility review')
    rules = [[field.strip() for field in row] for row in csv.reader(initializers[0].strip().splitlines())]
    if not rules or len(rules) > 10000 or any(len(rule) != 7 or rule[0] != 'p' for rule in rules):
        raise ValueError('Unexpected built-in API policy shape')
    if len({tuple(rule) for rule in rules}) != len(rules):
        raise ValueError('Duplicate built-in API rules require compatibility review')
    return {'schemaVersion': 1, 'sourceFile': 'authz/authz.go', 'table': 'casbin_api_rule', 'rules': sorted(rules)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=pathlib.Path)
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parent.parent
    metadata = export_policy((root / 'authz/authz.go').read_text())
    raw = json.dumps(metadata, sort_keys=True, separators=(',', ':')).encode() + b'\n'
    args.output.write_bytes(raw)
    print(hashlib.sha256(raw).hexdigest())


if __name__ == '__main__':
    main()
