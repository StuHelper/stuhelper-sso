#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root}"
output="${SSO_BUILD_OUTPUT:?SSO_BUILD_OUTPUT must be a new absolute directory outside the source tree}"
[[ "${output}" == /* && ! -e "${output}" && "${output}" != "${root}/"* ]] || exit 1
[[ "$(go env GOVERSION)" == "go$(jq -r .go .stuhelper/toolchains.json)" ]]
[[ "$(node --version)" == "v$(jq -r .node .stuhelper/toolchains.json)" ]]
[[ "$(yarn --version)" == "$(jq -r .yarn .stuhelper/toolchains.json)" ]]
mkdir -p "${output}"
python3 .stuhelper/release-input.py --component-version "${COMPONENT_VERSION:?}" --output "${output}/release-input.json"
python3 .stuhelper/api-policy.py --output "${output}/api-policy.json" >"${output}/api-policy.sha256"
export SOURCE_DATE_EPOCH
SOURCE_DATE_EPOCH="$(jq -r .sourceDateEpoch "${output}/release-input.json")"
export TZ=UTC
go mod verify
python3 .stuhelper/test-go.py
(
  cd web
  CYPRESS_INSTALL_BINARY=0 yarn install --frozen-lockfile --ignore-scripts --non-interactive
  yarn typecheck
  yarn lint
  yarn test
  yarn build
)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -mod=readonly -trimpath -ldflags='-w -s' -o "${output}/server" .
cp -a swagger "${output}/swagger"
mkdir -p "${output}/web" "${output}/conf"
cp -a web/build "${output}/web/build"
cp .stuhelper/app.conf "${output}/conf/app.conf"
cp .stuhelper/Dockerfile "${output}/Dockerfile"
sha256sum "${output}/server" >"${output}/server.sha256"
git diff --exit-code
printf 'Validated SSO build staged at %s\n' "${output}"
