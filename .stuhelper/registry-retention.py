#!/usr/bin/env python3
"""Keep current/previous successful SSO images and their full OCI proof graph.

Only the two fixed SSO packages are supported. A main-signed deployment success
receipt is mandatory; failed or merely published candidates never evict rollback
images. Git tags/releases and database backups are outside this script's scope.
"""
import argparse
import base64
import concurrent.futures
import datetime
import hashlib
import json
import os
import re
import subprocess
import threading
import urllib.error
import urllib.parse
import urllib.request

SOURCE_IMAGE = 'ghcr.io/stuhelper/stuhelper-sso'
DEPLOY_IMAGE = 'ghcr.io/stuhelper/casdoor'
PREDICATE = 'https://stuhelper.com/attestations/sso-deployment-success/v1'
IDENTITY = 'https://github.com/StuHelper/StuHelper/.github/workflows/casdoor-component-update.yml@refs/heads/main'
DIGEST = re.compile(r'^sha256:[0-9a-f]{64}$')
VERSION = re.compile(r'^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-stuhelper\.([1-9][0-9]*)$')
MEDIA_TYPES = {
    'application/vnd.oci.image.index.v1+json', 'application/vnd.oci.image.manifest.v1+json',
    'application/vnd.oci.artifact.manifest.v1+json',
    'application/vnd.docker.distribution.manifest.list.v2+json', 'application/vnd.docker.distribution.manifest.v2+json',
}


class PointerAbsent(Exception):
    pass


def require(value, message):
    if not value:
        raise ValueError(message)


def version(value):
    match = VERSION.fullmatch(value or '')
    require(match, 'Invalid successful component version')
    return tuple(map(int, match.groups()))


def command(*args):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
    require(result.returncode == 0, f'{args[0]} failed; no package deletion is authorized')
    return result.stdout


def json_stream(raw):
    decoder, text, values = json.JSONDecoder(), raw.decode(), []
    while text.strip():
        value, end = decoder.raw_decode(text.lstrip())
        values.extend(value if isinstance(value, list) else [value])
        text = text.lstrip()[end:]
    return values


def deployment_receipt(digest):
    raw = command('cosign', 'verify-attestation', '--timeout', '5m', '--type', PREDICATE,
                  '--certificate-identity', IDENTITY, '--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com',
                  '--certificate-github-workflow-name', 'Casdoor Component Update',
                  '--certificate-github-workflow-ref', 'refs/heads/main',
                  '--certificate-github-workflow-repository', 'StuHelper/StuHelper',
                  '--output', 'json', SOURCE_IMAGE + '@' + digest)
    accepted = []
    for envelope in json_stream(raw):
        require(envelope.get('payloadType') == 'application/vnd.in-toto+json', 'Unexpected signed statement envelope')
        statement = json.loads(base64.b64decode(envelope['payload'], validate=True))
        if statement.get('predicateType') != PREDICATE:
            continue
        require(statement.get('_type') in ('https://in-toto.io/Statement/v1', 'https://in-toto.io/Statement/v0.1')
                and statement.get('subject') == [{'name': SOURCE_IMAGE, 'digest': {'sha256': digest[7:]}}],
                'Deployment success does not bind the selected source image digest')
        receipt = statement['predicate']
        validate_receipt(receipt, digest)
        accepted.append(receipt)
    require(accepted and all(value == accepted[0] for value in accepted), 'Missing or conflicting signed deployment successes')
    return accepted[0]


def validate_receipt(receipt, digest):
    require(receipt.get('schemaVersion') == 1 and receipt.get('retentionPolicy') == 'two-successful-generations-v1'
            and receipt.get('healthVerified') is True and receipt.get('ledgerRecorded') is True
            and receipt.get('migrationPolicy') == 'backup-restore-rehearsal-required-v1', 'Incomplete successful deployment proof')
    require(receipt['current']['imageDigest'] == digest and receipt['current'].get('sourceImageName') == SOURCE_IMAGE,
            'Successful image differs from the selected discovery pointer')
    for item in (receipt['current'], receipt['previous']):
        require(DIGEST.fullmatch(item.get('imageDigest', '')), 'Invalid successful image digest')
        version(item.get('componentVersion'))
    require(receipt['current']['imageDigest'] != receipt['previous']['imageDigest'], 'A successful upgrade cannot reuse the previous image digest')
    require(version(receipt['current']['componentVersion']) > version(receipt['previous']['componentVersion']),
            'Successful versions do not advance')
    require(version(receipt['current']['componentVersion'])[0] >= 4, 'Independent source retention requires v4 or newer')
    expected_previous_source = SOURCE_IMAGE if version(receipt['previous']['componentVersion'])[0] >= 4 else None
    require(receipt['previous'].get('sourceImageName') == expected_previous_source, 'Unexpected previous source image namespace')
    require(re.fullmatch(r'[0-9a-f]{40}', receipt.get('controlPlaneCommit', ''))
            and re.fullmatch(r'[0-9a-f]{64}', receipt.get('migrationEvidenceSHA256', ''))
            and re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', receipt.get('updateRequestId', '')), 'Deployment identity is incomplete')
    deployed = timestamp(receipt['deployedAt'])
    require(0 <= (datetime.datetime.now(datetime.timezone.utc) - deployed).total_seconds() < 366 * 86400,
            'Deployment success timestamp is invalid or too old')


def timestamp(value):
    result = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(result.tzinfo is not None, 'A registry timestamp has no timezone')
    return result.astimezone(datetime.timezone.utc)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


class Registry:
    def __init__(self, image):
        require(image in (SOURCE_IMAGE, DEPLOY_IMAGE), 'Retention is restricted to the two SSO packages')
        self.image, self.path = image, image.removeprefix('ghcr.io/')
        self.token, self.lock = None, threading.Lock()
        self.opener = urllib.request.build_opener(NoRedirect())

    def bearer(self, refresh=False):
        with self.lock:
            if self.token and not refresh:
                return self.token
            url = 'https://ghcr.io/token?' + urllib.parse.urlencode({'service': 'ghcr.io', 'scope': 'repository:' + self.path + ':pull'})
            request = urllib.request.Request(url)
            token = os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')
            if token:
                user = os.environ.get('GITHUB_ACTOR', 'github-actions[bot]')
                request.add_header('Authorization', 'Basic ' + base64.b64encode((user + ':' + token).encode()).decode())
            with self.opener.open(request, timeout=30) as response:
                self.token = json.load(response)['token']
            return self.token

    def manifest(self, reference):
        require(reference == 'deployed-current' or DIGEST.fullmatch(reference), 'Invalid bounded registry reference')
        for attempt in range(2):
            request = urllib.request.Request('https://ghcr.io/v2/' + self.path + '/manifests/' + reference,
                                            headers={'Authorization': 'Bearer ' + self.bearer(refresh=bool(attempt)),
                                                     'Accept': ', '.join(sorted(MEDIA_TYPES))})
            try:
                with self.opener.open(request, timeout=30) as response:
                    raw = response.read(5 * 1024 * 1024)
                    digest = response.headers.get('Docker-Content-Digest', '')
                require(DIGEST.fullmatch(digest) and 'sha256:' + hashlib.sha256(raw).hexdigest() == digest,
                        'Registry manifest content identity changed')
                require(reference == 'deployed-current' or digest == reference, 'Registry returned another manifest')
                value = json.loads(raw)
                require(value.get('mediaType') in MEDIA_TYPES, 'Unknown OCI manifest type; inspect before cleanup')
                return digest, value
            except urllib.error.HTTPError as error:
                if reference == 'deployed-current' and error.code == 404:
                    raise PointerAbsent() from None
                if error.code == 401 and attempt == 0:
                    continue
                raise ValueError('Registry manifest unavailable; no package deletion is authorized') from None
        raise ValueError('Registry authentication failed')


def package_versions(image):
    package = image.rsplit('/', 1)[1]
    values = []
    for page in range(1, 101):
        batch = json.loads(command('gh', 'api', f'orgs/StuHelper/packages/container/{package}/versions?per_page=100&page={page}'))
        values.extend(batch)
        if len(batch) < 100:
            break
    else:
        raise ValueError('Package pagination exceeded the explicit bound')
    require(len({value['name'] for value in values}) == len(values), 'Duplicate package content identities')
    for value in values:
        require(DIGEST.fullmatch(value['name']) and isinstance(value['id'], int) and value['id'] > 0,
                'Unexpected package version identity')
    return values


def retention_plan(image, receipt, versions, manifests):
    roots = {receipt['current']['imageDigest']}
    if image == DEPLOY_IMAGE or receipt['previous']['sourceImageName'] == SOURCE_IMAGE:
        roots.add(receipt['previous']['imageDigest'])
    known = {value['name'] for value in versions}
    require(roots <= known, 'A successful rollback image is missing; cleanup is forbidden')
    reverse = {}
    children = {}
    for digest, manifest in manifests.items():
        children[digest] = {item['digest'] for item in manifest.get('manifests', [])}
        subject = manifest.get('subject', {}).get('digest')
        if subject:
            require(DIGEST.fullmatch(subject), 'Invalid OCI proof subject')
            reverse.setdefault(subject, set()).add(digest)
        require(all(DIGEST.fullmatch(child) for child in children[digest]), 'Invalid OCI child descriptor')
    for value in versions:
        digest = value['name']
        # A newer candidate, including a partially published one, must not evict
        # the last two successful deployments or be deleted by an older receipt.
        if timestamp(value['created_at']) > timestamp(receipt['deployedAt']):
            roots.add(digest)
        for tag in value['metadata']['container']['tags']:
            if VERSION.fullmatch(tag) and version(tag) > version(receipt['current']['componentVersion']):
                roots.add(digest)
            match = re.fullmatch(r'sha256-([0-9a-f]{64})\.(?:sig|att|sbom)', tag)
            if match:
                reverse.setdefault('sha256:' + match[1], set()).add(digest)
    keep, pending = set(), list(roots)
    while pending:
        digest = pending.pop()
        if digest in keep:
            continue
        keep.add(digest)
        require(digest in manifests, 'A retained OCI child or proof is missing')
        pending.extend(children[digest] | reverse.get(digest, set()))
    return keep, [value for value in versions if value['name'] not in keep]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', choices=(SOURCE_IMAGE, DEPLOY_IMAGE), required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    source = Registry(SOURCE_IMAGE)
    try:
        digest, _ = source.manifest('deployed-current')
    except PointerAbsent:
        print('No successful deployment pointer has been published yet; registry retention made no changes')
        return
    receipt = deployment_receipt(digest)
    registry, values = Registry(args.image), package_versions(args.image)
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        manifests = dict(pool.map(lambda value: registry.manifest(value['name']), values))
    # Some GHCR image-index children have no separately listed package version.
    missing = {item['digest'] for value in manifests.values() for item in value.get('manifests', [])} - set(manifests)
    while missing:
        require(len(manifests) + len(missing) <= 20000, 'OCI graph exceeded the explicit bound')
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            manifests.update(pool.map(registry.manifest, missing))
        missing = {item['digest'] for value in manifests.values() for item in value.get('manifests', [])} - set(manifests)
    keep, remove = retention_plan(args.image, receipt, values, manifests)
    print(json.dumps({'image': args.image, 'current': receipt['current'], 'previous': receipt['previous'],
                      'retainedOCIManifests': len(keep), 'obsoletePackageVersions': len(remove),
                      'delete': [{'id': value['id'], 'digest': value['name']} for value in remove]}))
    if not args.apply:
        return
    require(source.manifest('deployed-current')[0] == digest, 'A newer deployment was committed; recompute retention')
    package = args.image.rsplit('/', 1)[1]
    for value in remove:
        command('gh', 'api', '--method', 'DELETE', f'orgs/StuHelper/packages/container/{package}/versions/{value["id"]}')
    for root in (receipt['current']['imageDigest'], receipt['previous']['imageDigest']):
        if root in keep:
            registry.manifest(root)
    print(f'Registry retention completed for {args.image}; current and previous successful generations remain readable')


if __name__ == '__main__':
    main()
