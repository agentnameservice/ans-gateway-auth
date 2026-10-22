#!/usr/bin/env bash
# Download a pinned agentgateway release binary into .cache/ and verify its
# SHA-256 against the digests recorded here (not against a checksum file
# fetched alongside the binary).
set -euo pipefail

AGW_VERSION="${AGW_VERSION:-v1.6.0}"
CACHE_DIR="${CACHE_DIR:-$(cd "$(dirname "$0")/.." && pwd)/.cache}"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$arch" in
  x86_64) arch=amd64 ;;
  aarch64) arch=arm64 ;;
esac
platform="${AGW_PLATFORM:-${os}-${arch}}"

# agentgateway v1.6.0 release digests (sha256).
case "${AGW_VERSION}/${platform}" in
  v1.6.0/darwin-arm64) expected=6cebe8bd57262edce23a65a376d2f5a27b97cdfef609740642edbe75e1e9c685 ;;
  v1.6.0/linux-amd64)  expected=496ed27e6a96b55a9ad7cabe5c2be7172511f44a3cb113e533d22bf93a7f079d ;;
  v1.6.0/linux-arm64)  expected=b59ecac31103bb317d1377fd42b0cb25cd9a21f8c3f1d9ee14c3ff05f3f91abf ;;
  *) echo "no pinned digest for agentgateway ${AGW_VERSION} on ${platform}" >&2; exit 2 ;;
esac

asset="agentgateway-${platform}"
target="${CACHE_DIR}/${asset}"
mkdir -p "${CACHE_DIR}"

if [ -x "${target}" ] && printf '%s  %s\n' "${expected}" "${target}" | shasum -a 256 -c --status; then
  echo "${target} (${AGW_VERSION}) already present and verified"
  exit 0
fi

echo "downloading agentgateway ${AGW_VERSION} for ${platform}" >&2
gh release download "${AGW_VERSION}" -R agentgateway/agentgateway -p "${asset}" -D "${CACHE_DIR}" --clobber
printf '%s  %s\n' "${expected}" "${target}" | shasum -a 256 -c -
chmod +x "${target}"
echo "${target}"
