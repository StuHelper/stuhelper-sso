#!/usr/bin/env python3
"""Trusted stable-release controller. Never execute files from an upstream checkout.

Run this script from a copy outside the checkout (see upstream.yml). Git hooks,
external merge drivers and signing are disabled. Candidate CI has a read-only
token; only this controller can advance the protected branches through PRs.
"""
import datetime
import json
import os
import pathlib
import re
import subprocess

REPO = 'StuHelper/stuhelper-sso'
UPSTREAM = 'casdoor/casdoor'
REQUIRED_CHECKS = {'Go contracts', 'Web contracts'}
PROTECTED = ('.github', '.stuhelper', 'AGENTS.md', '.node-version')
STABLE = re.compile(r'^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$')


def stable_version(value):
    match = STABLE.fullmatch(value or '')
    return tuple(map(int, match.groups())) if match else None


def newest_stable(releases):
    candidates = [r for r in releases if not r['draft'] and not r['prerelease']
                  and stable_version(r['tag_name']) is not None]
    if not candidates:
        raise RuntimeError('No stable upstream release was found')
    return max(candidates, key=lambda r: stable_version(r['tag_name']))


def run(*args, allowed=(0,)):
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode not in allowed:
        # Never include a command's stdout/stderr: authenticated tools can include credentials.
        raise RuntimeError(f'{args[0]} failed with exit status {result.returncode}')
    return result


def git(*args, allowed=(0,)):
    return run('git', '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false',
               '-c', 'merge.renormalize=false', '-c', 'core.fsmonitor=false',
               '-c', 'filter.lfs.process=', '-c', 'filter.lfs.smudge=', '-c', 'filter.lfs.required=false',
               *args, allowed=allowed)


def api(path, method='GET', payload=None):
    command = ['gh', 'api', '--method', method, path]
    result = subprocess.run(command + (['--input', '-'] if payload is not None else []),
                            input=json.dumps(payload) if payload is not None else None,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode:
        raise RuntimeError(f'GitHub API {method} request failed: {path}')
    return json.loads(result.stdout) if result.stdout.strip() else None


def pages(path):
    for page in range(1, 101):
        values = api(f'{path}{"&" if "?" in path else "?"}per_page=100&page={page}')
        yield from values
        if len(values) < 100:
            return
    raise RuntimeError('Pagination exceeded the explicit safety bound')


def notice(key, body):
    title = f'[automation] {key}'
    if not any(i['title'] == title for i in pages(f'repos/{REPO}/issues?state=open&creator=github-actions[bot]')):
        api(f'repos/{REPO}/issues', 'POST', {'title': title, 'body': body})


def active_pr(head, base):
    pulls = api(f'repos/{REPO}/pulls?state=open&head=StuHelper:{head}&base={base}')
    if len(pulls) > 1:
        raise RuntimeError('Multiple open PRs for one automation branch')
    return pulls[0] if pulls else None


def ensure_pr(head, base, title, body):
    return active_pr(head, base) or api(f'repos/{REPO}/pulls', 'POST', {
        'head': head, 'base': base, 'title': title, 'body': body, 'maintainer_can_modify': True,
    })


def workflow_runs(name, sha):
    return api(f'repos/{REPO}/actions/workflows/{name}/runs?head_sha={sha}&per_page=100')['workflow_runs']


def advance_pr(pr):
    """Only merge an exact head validated by our CI workflow; no admin bypass."""
    pr = api(f'repos/{REPO}/pulls/{pr["number"]}')
    if pr['draft'] or pr.get('mergeable') is False:
        notice(f'PR #{pr["number"]} needs compatibility work',
               f'{pr["html_url"]}\n\nResolve the conflict or finish the draft, then push the repair to this PR. '
               'The controller will resume on the next run; no branch protection is bypassed.')
        return False
    sha = pr['head']['sha']
    runs = [r for r in workflow_runs('ci.yml', sha)
            if r['event'] in ('workflow_dispatch', 'pull_request', 'push')
            and r['head_repository']['full_name'] == REPO]
    if not runs:
        api(f'repos/{REPO}/actions/workflows/ci.yml/dispatches', 'POST', {'ref': pr['head']['ref']})
        return False
    # A GITHUB_TOKEN-created PR may await approval. Explicit dispatch works without
    # a PAT and executes the preserved read-only CI workflow on the same head.
    eligible = [r for r in runs if r['status'] != 'action_required' and r['conclusion'] != 'action_required']
    if not eligible:
        api(f'repos/{REPO}/actions/workflows/ci.yml/dispatches', 'POST', {'ref': pr['head']['ref']})
        return False
    latest = max(eligible, key=lambda r: (r['run_number'], r['run_attempt']))
    if latest['status'] != 'completed':
        return False
    jobs = api(f'repos/{REPO}/actions/runs/{latest["id"]}/jobs?per_page=100')['jobs']
    if latest['conclusion'] != 'success' or not checks_pass(jobs):
        notice(f'PR #{pr["number"]} CI needs repair',
               f'{pr["html_url"]}\n\nThe exact candidate failed required compatibility checks: '
               f'{latest["html_url"]}. Fix the candidate and push a new commit, or explicitly rerun a transient failure.')
        return False
    if pr.get('mergeable_state') == 'behind':
        api(f'repos/{REPO}/pulls/{pr["number"]}/update-branch', 'PUT', {'expected_head_sha': sha})
        return False
    if pr.get('mergeable_state') not in ('clean', 'unstable', 'has_hooks'):
        return False
    result = api(f'repos/{REPO}/pulls/{pr["number"]}/merge', 'PUT', {'sha': sha, 'merge_method': 'merge'})
    return result['merged']


def checks_pass(jobs):
    actual = {job['name']: job['conclusion'] for job in jobs}
    return all(actual.get(name) == 'success' for name in REQUIRED_CHECKS)


def restore_controls(base):
    """Remove newly introduced control files too, then restore the trusted base."""
    git('rm', '-r', '-f', '--ignore-unmatch', '--', *PROTECTED)
    tracked = [p for p in PROTECTED if git('ls-tree', base, '--', p).stdout.strip()]
    if tracked:
        git('restore', '--source', base, '--staged', '--worktree', '--', *tracked)


def prepare_candidate(version, upstream_sha, branch):
    git('checkout', '-B', branch, 'origin/develop')
    base = git('rev-parse', 'HEAD').stdout.strip()
    git('merge', '--no-ff', '--no-commit', upstream_sha, allowed=(0, 1))
    restore_controls(base)
    unresolved = git('diff', '--name-only', '--diff-filter=U').stdout.splitlines()
    if unresolved:
        git('merge', '--abort')
        notice(f'{version} upstream merge conflict',
               'Automatic integration paused before creating a candidate. Merge the pinned upstream commit '
               f'`{upstream_sha}` into a dedicated branch from `develop`, preserve the StuHelper control files, '
               'port the compatibility changes, update `.stuhelper/upstream.json`, and open a PR.\n\n'
               'Conflicting paths:\n' + '\n'.join(f'- `{p}`' for p in unresolved))
        return False
    path = pathlib.Path('.stuhelper/upstream.json')
    manifest = json.loads(path.read_text())
    manifest.update(version=version, commit=upstream_sha, databaseMajor=stable_version(version)[0],
                    verifiedAt=datetime.date.today().isoformat())
    path.write_text(json.dumps(manifest, indent=2) + '\n')
    git('add', '.stuhelper/upstream.json')
    git('commit', '-m', f'merge: integrate Casdoor {version} with StuHelper controls')
    git('push', 'origin', f'HEAD:refs/heads/{branch}')
    return True


def release_current():
    sha = git('rev-parse', 'origin/main').stdout.strip()
    manifest = json.loads(git('show', 'origin/main:.stuhelper/upstream.json').stdout)
    releases = list(pages(f'repos/{REPO}/releases'))
    pattern = re.compile(re.escape(manifest['version']) + r'-stuhelper\.([1-9][0-9]*)$')
    revisions = []
    for release in releases:
        match = pattern.fullmatch(release['tag_name'])
        if not match:
            continue
        revisions.append(int(match[1]))
        tag = git('ls-remote', 'origin', f'refs/tags/{release["tag_name"]}',
                  f'refs/tags/{release["tag_name"]}^{{}}').stdout.splitlines()
        target = next((line.split()[0] for line in tag if line.endswith('^{}')),
                      tag[0].split()[0] if tag else None)
        if target == sha and not release['draft']:
            return
    active = api(f'repos/{REPO}/actions/workflows/release.yml/runs?per_page=100')['workflow_runs']
    if any(run['status'] != 'completed' for run in active):
        return
    prior = workflow_runs('release.yml', sha)
    if prior:
        latest = max(prior, key=lambda r: (r['run_number'], r['run_attempt']))
        if latest['status'] == 'completed':
            notice(f'Release {sha[:12]} needs attention',
                   f'{latest["html_url"]}\n\nThe source has no completed immutable release receipt. '
                   'Inspect any partially published artifact before explicitly retrying; tags are never overwritten.')
        return
    component = f'{manifest["version"]}-stuhelper.{max(revisions, default=0) + 1}'
    api(f'repos/{REPO}/actions/workflows/release.yml/dispatches', 'POST',
        {'ref': 'main', 'inputs': {'component_version': component}})


def main():
    if os.environ.get('GITHUB_REPOSITORY') != REPO or os.environ.get('GITHUB_REF') != 'refs/heads/develop':
        raise RuntimeError('The controller only runs from this repository protected develop branch')
    git('config', 'user.name', 'github-actions[bot]')
    git('config', 'user.email', '41898282+github-actions[bot]@users.noreply.github.com')
    git('fetch', '--no-tags', 'origin', 'develop', 'main')
    current = json.loads(git('show', 'origin/develop:.stuhelper/upstream.json').stdout)
    latest = newest_stable(list(pages(f'repos/{UPSTREAM}/releases')))
    version = latest['tag_name']
    git('fetch', '--no-tags', f'https://github.com/{UPSTREAM}.git', f'refs/tags/{current["version"]}')
    if git('rev-parse', 'FETCH_HEAD^{commit}').stdout.strip() != current['commit']:
        raise RuntimeError('The recorded upstream stable tag moved; manual investigation is required')
    git('fetch', '--no-tags', f'https://github.com/{UPSTREAM}.git', f'refs/tags/{version}')
    upstream_sha = git('rev-parse', 'FETCH_HEAD^{commit}').stdout.strip()
    if stable_version(version) > stable_version(current['version']):
        branch = f'upstream/casdoor-{version}'
        pr = active_pr(branch, 'develop')
        if not pr:
            # A closed unmerged PR is an explicit operator decision, not permission to recreate it.
            history = api(f'repos/{REPO}/pulls?state=closed&head=StuHelper:{branch}&base=develop')
            if history:
                notice(f'{version} integration was closed', 'Reopen or replace the previous integration PR to resume this version.')
                return
            if not prepare_candidate(version, upstream_sha, branch):
                return
            pr = ensure_pr(branch, 'develop', f'merge: Casdoor {version}',
                           f'Integrate official stable `{version}` at `{upstream_sha}` while retaining StuHelper control files. '
                           'Exact-head Go and web compatibility checks must pass before the controller merges this PR. '
                           'Signed publication follows a separate develop → main PR; the consumer requires database migration '
                           'and backup restoration rehearsal before production deployment, including major upgrades.')
        if not advance_pr(pr):
            return
        git('fetch', '--no-tags', 'origin', 'develop', 'main')
    if git('rev-parse', 'origin/develop^{tree}').stdout != git('rev-parse', 'origin/main^{tree}').stdout:
        ahead = int(git('rev-list', '--count', 'origin/main..origin/develop').stdout)
        if ahead:
            pr = ensure_pr('develop', 'main', 'release: validated StuHelper SSO source',
                           'Release the validated develop source with a merge commit. Exact-head Go and web checks are '
                           'required. Publication is automatic under the owner-approved stable-version policy; production '
                           'deployment remains gated by the main repository migration and restore rehearsal.')
            if not advance_pr(pr):
                return
            git('fetch', '--no-tags', 'origin', 'main')
    release_current()
    # Carry the release merge back through a PR so the next upstream update is
    # already based on main and strict branch freshness checks remain enforceable.
    if git('merge-base', '--is-ancestor', 'origin/main', 'origin/develop', allowed=(0, 1)).returncode:
        pr = ensure_pr('main', 'develop', 'merge: synchronize released SSO history',
                       'Preserve the validated release ancestry on develop without squashing or rewriting commits.')
        advance_pr(pr)


if __name__ == '__main__':
    main()
