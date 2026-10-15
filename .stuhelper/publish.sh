#!/usr/bin/env bash
set -euo pipefail
[[ "${GITHUB_REPOSITORY:-}" == StuHelper/stuhelper-sso ]]
[[ "${GITHUB_REF:-}" == refs/heads/main ]]
[[ "${GITHUB_EVENT_NAME:-}" == workflow_dispatch ]]
[[ "${GITHUB_WORKFLOW_REF:-}" == StuHelper/stuhelper-sso/.github/workflows/release.yml@refs/heads/main ]]
[[ "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ ]]
[[ "${COMPONENT_VERSION:-}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-stuhelper\.[1-9][0-9]*$ ]]
metadata="${SSO_BUILD_OUTPUT:?}/release-input.json"
[[ "$(jq -r .sourceCommit "${metadata}")" == "${GITHUB_SHA}" ]]
[[ "$(jq -r .componentVersion "${metadata}")" == "${COMPONENT_VERSION}" ]]
image=ghcr.io/stuhelper/stuhelper-sso
tag="${image}:${COMPONENT_VERSION}"
probe="${RUNNER_TEMP}/sso-tag-probe.log"
# A lookup failure is not permission to overwrite an existing release.
if docker buildx imagetools inspect "${tag}" >"${probe}" 2>&1; then
  echo 'Component tag already exists; choose a new immutable revision' >&2
  exit 1
fi
grep -Eqi 'manifest unknown|manifest_unknown|not found|404' "${probe}" || {
  echo 'Unable to prove the component tag is unused' >&2; exit 1;
}
if git ls-remote --exit-code origin "refs/tags/${COMPONENT_VERSION}" >"${probe}" 2>&1; then
  echo 'Source release tag already exists' >&2
  exit 1
else
  status=$?
  [[ "${status}" == 2 ]] || { echo 'Source tag lookup failed' >&2; exit 1; }
fi
docker tag sso-candidate:local "${tag}"
docker push "${tag}"
digest="$(docker buildx imagetools inspect "${tag}" --format '{{json .Manifest}}' | jq -er .digest)"
[[ "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]]
ref="${image}@${digest}"
predicate="${SSO_BUILD_OUTPUT}/source-provenance.json"
jq --arg workflow "${GITHUB_WORKFLOW_REF}" \
  --arg invocation "https://github.com/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}/attempts/${GITHUB_RUN_ATTEMPT}" '
  {
    buildDefinition: {
      buildType: "https://stuhelper.com/buildtypes/sso-source/v1",
      externalParameters: {workflow: $workflow, upstreamVersion, componentVersion},
      internalParameters: {releaseInputSHA256, sourceTree, databaseMajor},
      resolvedDependencies: [
        {uri: .sourceRepository, digest: {gitCommit: .sourceCommit}},
        {uri: .upstreamRepository, digest: {gitCommit: .upstreamCommit}}
      ]
    },
    runDetails: {
      builder: {id: ("https://github.com/" + $workflow)},
      metadata: {invocationId: $invocation}
    }
  }' "${metadata}" >"${predicate}"
cosign sign --yes --timeout 5m --oidc-provider github-actions "${ref}"
cosign attest --yes --timeout 5m --oidc-provider github-actions --type slsaprovenance1 --predicate "${predicate}" "${ref}"
cosign attest --yes --timeout 5m --oidc-provider github-actions --type cyclonedx --predicate "${SSO_BUILD_OUTPUT}/sbom.cdx.json" "${ref}"
identity="https://github.com/StuHelper/stuhelper-sso/.github/workflows/release.yml@refs/heads/main"
cosign verify --timeout 5m --certificate-identity "${identity}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com "${ref}" >/dev/null
jq --arg imageRef "${ref}" '. + {imageRef: $imageRef}' "${metadata}" >"${SSO_BUILD_OUTPUT}/component.json"
# A public GitHub release is a discovery receipt. Consumers still verify the image's
# Sigstore identity and source predicate; this JSON is never a trust root.
gh release create "${COMPONENT_VERSION}" --repo StuHelper/stuhelper-sso --target "${GITHUB_SHA}" \
  --title "StuHelper SSO ${COMPONENT_VERSION}" \
  --notes "Casdoor source, StuHelper compatibility tests, image signature, source provenance and SBOM are bound to the immutable component digest. Production deployment is approved separately in StuHelper/StuHelper." \
  "${SSO_BUILD_OUTPUT}/component.json" "${SSO_BUILD_OUTPUT}/sbom.cdx.json"
