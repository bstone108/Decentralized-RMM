#!/usr/bin/env bash
# Exercise the release helper scripts without signing or publishing.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "${root}"

expect_fail() {
  local needle="$1"
  shift
  local err status
  err="$(mktemp)"
  set +e
  "$@" >"${err}" 2>&1
  status=$?
  set -e
  if [[ "${status}" -eq 0 ]]; then
    echo "expected failure: $*" >&2
    cat "${err}" >&2
    exit 1
  fi
  if ! grep -q "${needle}" "${err}"; then
    echo "expected error to mention ${needle}" >&2
    cat "${err}" >&2
    exit 1
  fi
  rm -f "${err}"
}

echo "Checking release tag resolution"
out="$(mktemp)"
env -u GITHUB_EVENT_NAME \
  EVENT_NAME=push \
  GITHUB_REF=refs/tags/v2026.10.05.01 \
  PUSH_TAG=v2026.10.05.01 \
  DISPATCH_TAG= \
  GITHUB_OUTPUT="${out}" \
  scripts/resolve-release-tag.sh
grep -qx 'tag=v2026.10.05.01' "${out}"
grep -qx 'version=2026.10.05.01' "${out}"
grep -qx 'prerelease=false' "${out}"

out="$(mktemp)"
env -u GITHUB_EVENT_NAME \
  EVENT_NAME=push \
  GITHUB_REF=refs/tags/v2026.10.04.01 \
  PUSH_TAG=v2026.10.04.01 \
  GITHUB_OUTPUT="${out}" \
  scripts/resolve-release-tag.sh
grep -qx 'version=2026.10.04.01' "${out}"
grep -qx 'prerelease=false' "${out}"

out="$(mktemp)"
env -u GITHUB_EVENT_NAME \
  EVENT_NAME=push \
  GITHUB_REF=refs/tags/v2026.10.05.01-rc1 \
  PUSH_TAG=v2026.10.05.01-rc1 \
  GITHUB_OUTPUT="${out}" \
  scripts/resolve-release-tag.sh
grep -qx 'tag=v2026.10.05.01-rc1' "${out}"
grep -qx 'version=2026.10.05.01-rc1' "${out}"
grep -qx 'prerelease=true' "${out}"

expect_fail 'pull request' \
  env EVENT_NAME=pull_request PUSH_TAG=v2026.10.05.01 \
  scripts/resolve-release-tag.sh
expect_fail 'pull request' \
  env GITHUB_EVENT_NAME=pull_request EVENT_NAME=push \
  PUSH_TAG=v2026.10.05.01 GITHUB_REF=refs/tags/v2026.10.05.01 \
  scripts/resolve-release-tag.sh
expect_fail 'zero-padded' \
  env -u GITHUB_EVENT_NAME EVENT_NAME=push \
  GITHUB_REF=refs/tags/v2026.10.5.1 PUSH_TAG=v2026.10.5.1 \
  scripts/resolve-release-tag.sh

echo "Checking publish dry-run"
fakebin="$(mktemp -d)"
cat > "${fakebin}/gh" <<'EOF'
#!/bin/sh
echo "gh should not be called during --dry-run" >&2
exit 99
EOF
chmod 755 "${fakebin}/gh"

artifacts="$(mktemp -d)"
tag="v2099.12.31.01"
version="2099.12.31.01"
for name in \
  "rmm-${tag}-linux-amd64.tar.gz" \
  "rmm-${tag}-linux-arm64.tar.gz" \
  "rmm-${tag}-windows-amd64.zip" \
  "rmm-${tag}-windows-arm64.zip" \
  "rmm-${tag}-macos-arm64.zip" \
  "rmm-${tag}-macos-x86_64.zip" \
  "rmm-${tag}-macos-universal.zip"
do
  printf 'asset %s\n' "${name}" > "${artifacts}/${name}"
done

env -u GITHUB_EVENT_NAME \
  PATH="${fakebin}:${PATH}" \
  EVENT_NAME=push \
  TAG="${tag}" \
  VERSION="${version}" \
  PRERELEASE=false \
  GITHUB_REPOSITORY="${GITHUB_REPOSITORY:-bstone108/Decentralized-RMM}" \
  ARTIFACTS_DIR="${artifacts}" \
  REPO_ROOT="${root}" \
  scripts/publish-github-release.sh --dry-run
(
  cd "${artifacts}"
  sha256sum -c SHA256SUMS
)
test "$(wc -l < "${artifacts}/SHA256SUMS" | tr -d ' ')" -eq 7
if grep -q 'SHA256SUMS' "${artifacts}/SHA256SUMS"; then
  echo "checksum file listed itself" >&2
  exit 1
fi

expect_fail 'pull request' \
  env GITHUB_EVENT_NAME=pull_request EVENT_NAME=pull_request \
  TAG="${tag}" VERSION="${version}" PRERELEASE=false \
  GITHUB_REPOSITORY=bstone108/Decentralized-RMM \
  ARTIFACTS_DIR="${artifacts}" REPO_ROOT="${root}" \
  scripts/publish-github-release.sh --dry-run
expect_fail 'full release' \
  env -u GITHUB_EVENT_NAME EVENT_NAME=push \
  TAG="${tag}" VERSION="${version}" PRERELEASE=true \
  GITHUB_REPOSITORY=bstone108/Decentralized-RMM \
  ARTIFACTS_DIR="${artifacts}" REPO_ROOT="${root}" \
  scripts/publish-github-release.sh --dry-run
expect_fail 'zero-padded' \
  env -u GITHUB_EVENT_NAME EVENT_NAME=push \
  TAG=v2026.10.5.1 VERSION=2026.10.5.1 PRERELEASE=false \
  GITHUB_REPOSITORY=bstone108/Decentralized-RMM \
  ARTIFACTS_DIR="${artifacts}" REPO_ROOT="${root}" \
  scripts/publish-github-release.sh --dry-run

rm -f "${artifacts}/rmm-${tag}-linux-arm64.tar.gz"
expect_fail 'missing release asset' \
  env -u GITHUB_EVENT_NAME EVENT_NAME=push \
  TAG="${tag}" VERSION="${version}" PRERELEASE=false \
  GITHUB_REPOSITORY=bstone108/Decentralized-RMM \
  ARTIFACTS_DIR="${artifacts}" REPO_ROOT="${root}" \
  scripts/publish-github-release.sh --dry-run

version="2026.10.05.01"
tag="v${version}"
echo "Building sample release archives for ${tag}"
scripts/build-release-binaries.sh \
  --goos linux --goarch amd64 \
  --version "${version}" --tag "${tag}" --dest dist/verify-linux
scripts/build-release-binaries.sh \
  --goos windows --goarch amd64 \
  --version "${version}" --tag "${tag}" --dest dist/verify-windows
scripts/build-release-binaries.sh \
  --goos darwin --goarch arm64 \
  --version "${version}" --tag "${tag}" --dest dist/verify-darwin-arm64
scripts/build-release-binaries.sh \
  --goos darwin --goarch amd64 \
  --version "${version}" --tag "${tag}" --dest dist/verify-darwin-amd64

linux_archive="dist/verify-linux/rmm-${tag}-linux-amd64.tar.gz"
windows_archive="dist/verify-windows/rmm-${tag}-windows-amd64.zip"
test -s "${linux_archive}"
test -s "${windows_archive}"

extract="$(mktemp -d)"
tar -xzf "${linux_archive}" -C "${extract}"
base="rmm-${tag}-linux-amd64"
for entry in README.md SECURITY.md docs/DEPLOYMENT.md rmm-agent rmm-console rmm-pack; do
  test -f "${extract}/${base}/${entry}"
done
grep -q 'Back the key file up offline' "${extract}/${base}/docs/DEPLOYMENT.md"
grep -q 'Back it' "${extract}/${base}/SECURITY.md"
if [[ -d cmd/rmm ]]; then
  test -f "${extract}/${base}/rmm"
  test "$("${extract}/${base}/rmm" version)" = "${version}"
fi
test "$("${extract}/${base}/rmm-agent" version)" = "${version}"
test "$("${extract}/${base}/rmm-console" version)" = "${version}"
test "$("${extract}/${base}/rmm-pack" version)" = "${version}"
if find "${extract}" -iname 'VERSION.txt' | grep -q .; then
  echo "linux archive contains VERSION.txt" >&2
  exit 1
fi

python3 - "${windows_archive}" "${tag}" <<'PY'
import sys
import zipfile

archive, tag = sys.argv[1], sys.argv[2]
base = f"rmm-{tag}-windows-amd64"
need = {
    f"{base}/README.md",
    f"{base}/SECURITY.md",
    f"{base}/docs/DEPLOYMENT.md",
    f"{base}/rmm-agent.exe",
    f"{base}/rmm-console.exe",
    f"{base}/rmm-pack.exe",
    f"{base}/rmm.exe",
}
with zipfile.ZipFile(archive) as zf:
    names = set(zf.namelist())
    deployment = zf.read(f"{base}/docs/DEPLOYMENT.md").decode()
    security = zf.read(f"{base}/SECURITY.md").decode()
missing = need - names
if missing:
    raise SystemExit(f"windows archive missing {sorted(missing)}")
if "Back the key file up offline" not in deployment:
    raise SystemExit("windows archive is missing at-rest key backup guidance")
if "Back it" not in security:
    raise SystemExit("windows SECURITY.md is missing key backup guidance")
if any(name.lower().endswith("version.txt") for name in names):
    raise SystemExit("windows archive contains VERSION.txt")
PY

for bin in rmm-agent rmm-console rmm-pack rmm; do
  test -f "dist/verify-darwin-arm64/${bin}"
  test -f "dist/verify-darwin-amd64/${bin}"
  file "dist/verify-darwin-arm64/${bin}" | grep -q 'Mach-O'
  file "dist/verify-darwin-arm64/${bin}" | grep -q 'arm64'
  file "dist/verify-darwin-amd64/${bin}" | grep -q 'x86_64'
done
test ! -e dist/verify-darwin-arm64/VERSION.txt
test ! -e dist/verify-darwin-arm64/README.md

echo "Release layout checks passed"
