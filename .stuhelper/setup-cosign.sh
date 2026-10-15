#!/usr/bin/env bash
set -euo pipefail

# GitHub release assets are not a reliable bootstrap path for the self-hosted
# runners: the upstream installer downloads two ~135 MiB binaries and its curl
# calls have no total timeout. Extract the same native binary from Sigstore's
# official, immutable OCI image through the selected Buildx builder instead.
# This works with the ARC-owned remote BuildKit endpoint and never requires a
# host Docker socket. Both the image index and the extracted linux/amd64 binary
# are pinned so a registry-side tag move cannot change what is executed.
readonly COSIGN_VERSION="v3.1.3"
readonly COSIGN_GIT_COMMIT="11926fa5bbbbde47e88fc006b625a17769b743b2"
readonly COSIGN_IMAGE="ghcr.io/sigstore/cosign/cosign@sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8"
readonly COSIGN_BINARY_SHA256="a57926e24b07f02b5baf3be81f9a5988e9e45d8a1ca8ca500cdf56d10e69f887"
readonly COSIGN_EXPORT_ATTEMPTS=3
readonly COSIGN_EXPORT_TIMEOUT_SECONDS=180

for command_name in awk docker jq mktemp rm sha256sum tar timeout; do
  command -v "${command_name}" >/dev/null 2>&1 || {
    printf 'required command is unavailable: %s\n' "${command_name}" >&2
    exit 1
  }
done

runner_temp="${RUNNER_TEMP:-}"
github_path="${GITHUB_PATH:-}"
[[ -n "${runner_temp}" && -d "${runner_temp}" ]] || {
  echo 'RUNNER_TEMP must identify an existing directory' >&2
  exit 1
}
[[ -n "${github_path}" ]] || {
  echo 'GITHUB_PATH is required' >&2
  exit 1
}

install_dir="${runner_temp}/cosign-${COSIGN_VERSION}"
install_path="${install_dir}/cosign"
mkdir -p "${install_dir}"

build_context="$(mktemp -d "${runner_temp}/cosign-context.XXXXXX")"
export_tar="$(mktemp "${runner_temp}/cosign-rootfs.XXXXXX.tar")"
cleanup() {
  rm -rf -- "${build_context}"
  rm -f -- "${export_tar}"
}
trap cleanup EXIT

printf 'FROM %s\n' "${COSIGN_IMAGE}" >"${build_context}/Dockerfile"

exported=false
for ((attempt = 1; attempt <= COSIGN_EXPORT_ATTEMPTS; attempt++)); do
  : >"${export_tar}"
  if timeout --signal=TERM --kill-after=10s "${COSIGN_EXPORT_TIMEOUT_SECONDS}s" \
    docker buildx build \
      --file "${build_context}/Dockerfile" \
      --output "type=tar,dest=${export_tar}" \
      --platform linux/amd64 \
      --progress plain \
      --pull \
      "${build_context}"; then
    exported=true
    break
  fi
  printf 'Cosign OCI export attempt %d/%d failed or timed out\n' \
    "${attempt}" "${COSIGN_EXPORT_ATTEMPTS}" >&2
  if ((attempt < COSIGN_EXPORT_ATTEMPTS)); then
    sleep "$((attempt * 5))"
  fi
done
[[ "${exported}" == true ]] || {
  echo 'unable to export the pinned Cosign OCI image through BuildKit' >&2
  exit 1
}

tar --extract --file "${export_tar}" --to-stdout ko-app/cosign >"${install_path}" || {
  echo 'the pinned Cosign OCI image did not export /ko-app/cosign' >&2
  exit 1
}
[[ -f "${install_path}" && ! -L "${install_path}" ]] || {
  echo 'the exported Cosign binary is not a regular file' >&2
  exit 1
}

actual_sha256="$(sha256sum "${install_path}" | awk '{print $1}')"
[[ "${actual_sha256}" == "${COSIGN_BINARY_SHA256}" ]] || {
  printf 'Cosign binary digest mismatch: expected %s, got %s\n' \
    "${COSIGN_BINARY_SHA256}" "${actual_sha256}" >&2
  exit 1
}
chmod 0755 "${install_path}"

version_json="$("${install_path}" version --json)"
jq -e \
  --arg version "${COSIGN_VERSION}" \
  --arg commit "${COSIGN_GIT_COMMIT}" \
  '.gitVersion == $version and .gitCommit == $commit and .gitTreeState == "clean" and .platform == "linux/amd64"' \
  <<<"${version_json}" >/dev/null

printf '%s\n' "${install_dir}" >>"${github_path}"
printf 'Installed Cosign %s (%s) from pinned OCI image\n' \
  "${COSIGN_VERSION}" "${COSIGN_GIT_COMMIT}"
