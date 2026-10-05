#!/usr/bin/env bash
# Developer ID-sign dedicated arm64 and x86_64 Mach-O binaries, plus a
# universal binary, then notarize each zip. Bare Mach-O cannot be stapled;
# the notarized zip is the shipped artifact.
# macOS bash 3.2 compatible. Run on GitHub-hosted macos-15, never macos-latest.
set -euo pipefail

if [[ "${GITHUB_EVENT_NAME:-}" == "pull_request" || "${EVENT_NAME:-}" == "pull_request" ]]; then
  echo "Refusing to sign or notarize on a pull request." >&2
  exit 1
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "macOS signing must run on Darwin." >&2
  exit 1
fi

tag=""
arm64_dir=""
x86_dir=""
out_dir=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag) tag="${2:?}"; shift 2 ;;
    --arm64) arm64_dir="${2:?}"; shift 2 ;;
    --x86_64) x86_dir="${2:?}"; shift 2 ;;
    --out) out_dir="${2:?}"; shift 2 ;;
    *)
      echo "unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if [[ -z "${tag}" || -z "${arm64_dir}" || -z "${x86_dir}" || -z "${out_dir}" ]]; then
  echo "usage: scripts/sign-notarize-macos.sh --tag TAG --arm64 DIR --x86_64 DIR --out DIR" >&2
  exit 1
fi

for tool in codesign ditto lipo xcrun python3 grep; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "missing required tool ${tool}" >&2
    exit 1
  fi
done

: "${APPLE_ID:?APPLE_ID is required}"
: "${APPLE_APP_SPECIFIC_PASSWORD:?APPLE_APP_SPECIFIC_PASSWORD is required}"
: "${APPLE_TEAM_ID:?APPLE_TEAM_ID is required}"
: "${MACOS_SIGNING_KEYCHAIN_PATH:?import the signing certificate before signing}"

root="$(cd "$(dirname "$0")/.." && pwd)"
identity="Developer ID Application: BRANDON BROWNING STONE (K6N4J68LTY)"
entitlements="${root}/scripts/macos-entitlements.plist"
if [[ ! -f "${entitlements}" ]]; then
  echo "missing ${entitlements}" >&2
  exit 1
fi
if [[ ! -f "${root}/README.md" || ! -f "${root}/SECURITY.md" || ! -f "${root}/docs/DEPLOYMENT.md" ]]; then
  echo "README.md, SECURITY.md, and docs/DEPLOYMENT.md are required in the signed archives." >&2
  exit 1
fi

canonical="$(python3 "${root}/scripts/next-date-build-version" --from-tag "${tag}")"
if [[ "v${canonical}" != "${tag}" ]]; then
  echo "tag ${tag} does not match padded version ${canonical}" >&2
  exit 1
fi
if [[ -n "${VERSION:-}" && "${canonical}" != "${VERSION}" ]]; then
  echo "VERSION ${VERSION} does not match tag ${tag}" >&2
  exit 1
fi

# upload-artifact drops Unix permissions and may nest files under one directory.
resolve_bin_dir() {
  local dir="$1"
  if [[ -f "${dir}/rmm-agent" ]]; then
    printf '%s\n' "${dir}"
    return 0
  fi
  local matches count
  matches="$(find "${dir}" -type f -name rmm-agent)"
  if [[ -z "${matches}" ]]; then
    echo "no rmm-agent under ${dir}" >&2
    find "${dir}" -print >&2 || true
    exit 1
  fi
  count="$(printf '%s\n' "${matches}" | grep -c .)"
  if [[ "${count}" -ne 1 ]]; then
    echo "expected one rmm-agent under ${dir}" >&2
    printf '%s\n' "${matches}" >&2
    exit 1
  fi
  dirname "${matches}"
}

arm64_dir="$(resolve_bin_dir "${arm64_dir}")"
x86_dir="$(resolve_bin_dir "${x86_dir}")"

verify_arch() {
  local bin="$1"
  local expected="$2"
  local archs
  archs="$(lipo -archs "${bin}")"
  if [[ "${archs}" != "${expected}" ]]; then
    echo "${bin} has arches [${archs}], want ${expected}" >&2
    exit 1
  fi
}

verify_universal() {
  local bin="$1"
  local archs
  archs="$(lipo -archs "${bin}")"
  case " ${archs} " in
    *" arm64 "*) ;;
    *)
      echo "${bin} is missing an arm64 slice [${archs}]" >&2
      exit 1
      ;;
  esac
  case " ${archs} " in
    *" x86_64 "*) ;;
    *)
      echo "${bin} is missing an x86_64 slice [${archs}]" >&2
      exit 1
      ;;
  esac
}

sign_one() {
  local bin="$1"
  codesign --force \
    --sign "${identity}" \
    --keychain "${MACOS_SIGNING_KEYCHAIN_PATH}" \
    --options runtime \
    --timestamp \
    --entitlements "${entitlements}" \
    "${bin}"
  codesign --verify --strict --verbose=2 "${bin}"
  local info
  info="$(codesign -dv --verbose=4 "${bin}" 2>&1)"
  printf '%s\n' "${info}"
  if ! printf '%s\n' "${info}" | grep -E 'flags=.*runtime' >/dev/null; then
    echo "missing hardened runtime on ${bin}" >&2
    exit 1
  fi
  if ! printf '%s\n' "${info}" | grep -E 'Timestamp=.+' >/dev/null; then
    echo "missing secure timestamp on ${bin}" >&2
    exit 1
  fi
  if printf '%s\n' "${info}" | grep -F 'Timestamp=none' >/dev/null; then
    echo "timestamp was not applied to ${bin}" >&2
    exit 1
  fi
  if ! printf '%s\n' "${info}" | grep -F "Authority=${identity}" >/dev/null; then
    echo "unexpected signing identity on ${bin}" >&2
    exit 1
  fi
}

binaries=(rmm-agent rmm-console rmm-pack)
if [[ -f "${arm64_dir}/rmm" || -f "${x86_dir}/rmm" ]]; then
  binaries[${#binaries[@]}]=rmm
fi

for bin in "${binaries[@]}"; do
  if [[ ! -f "${arm64_dir}/${bin}" || ! -f "${x86_dir}/${bin}" ]]; then
    echo "missing ${bin} in one or both macOS architectures" >&2
    exit 1
  fi
  verify_arch "${arm64_dir}/${bin}" arm64
  verify_arch "${x86_dir}/${bin}" x86_64
  # Artifact download clears the executable bit. Restore it before codesign.
  chmod 755 "${arm64_dir}/${bin}" "${x86_dir}/${bin}"
  sign_one "${arm64_dir}/${bin}"
  sign_one "${x86_dir}/${bin}"
done

uni_dir="${out_dir}/work/universal-bins"
mkdir -p "${uni_dir}"
for bin in "${binaries[@]}"; do
  lipo -create "${arm64_dir}/${bin}" "${x86_dir}/${bin}" -output "${uni_dir}/${bin}"
  chmod 755 "${uni_dir}/${bin}"
  sign_one "${uni_dir}/${bin}"
  verify_universal "${uni_dir}/${bin}"
done

notarize_zip() {
  local zip_path="$1"
  local json submission_id
  json="$(mktemp)"
  echo "Submitting $(basename "${zip_path}") with notarytool submit --wait"
  if ! xcrun notarytool submit "${zip_path}" \
    --apple-id "${APPLE_ID}" \
    --password "${APPLE_APP_SPECIFIC_PASSWORD}" \
    --team-id "${APPLE_TEAM_ID}" \
    --wait \
    --output-format json >"${json}"; then
    echo "notarytool submit failed for ${zip_path}" >&2
    cat "${json}" >&2 || true
    submission_id="$(python3 - "${json}" <<'PY'
import json
import sys
try:
    print(json.load(open(sys.argv[1])).get("id") or "")
except Exception:
    print("")
PY
)"
    if [[ -n "${submission_id}" ]]; then
      xcrun notarytool log "${submission_id}" \
        --apple-id "${APPLE_ID}" \
        --password "${APPLE_APP_SPECIFIC_PASSWORD}" \
        --team-id "${APPLE_TEAM_ID}" || true
    fi
    rm -f "${json}"
    exit 1
  fi
  python3 - "${json}" "${zip_path}" <<'PY'
import json
import sys

doc = json.load(open(sys.argv[1]))
status = doc.get("status")
if status != "Accepted":
    raise SystemExit(f"notarization of {sys.argv[2]} returned {status!r}: {doc}")
print(f"notarized {sys.argv[2]} id={doc.get('id')} status={status}")
PY
  rm -f "${json}"
}

verify_zip() {
  local zip_path="$1"
  local name="$2"
  local check bin
  check="$(mktemp -d)"
  ditto -x -k "${zip_path}" "${check}"
  for bin in "${binaries[@]}"; do
    codesign --verify --strict --verbose=2 "${check}/${name}/${bin}"
  done
  test -f "${check}/${name}/README.md"
  test -f "${check}/${name}/SECURITY.md"
  test -f "${check}/${name}/docs/DEPLOYMENT.md"
  if ! grep -q 'Back the key file up offline' "${check}/${name}/docs/DEPLOYMENT.md"; then
    echo "docs/DEPLOYMENT.md in ${name} is missing at-rest key backup guidance" >&2
    exit 1
  fi
  test ! -e "${check}/${name}/VERSION.txt"
  rm -rf "${check}"
}

package_one() {
  local label="$1"
  local src="$2"
  local name stage zip_path bin
  name="rmm-${tag}-macos-${label}"
  stage="${out_dir}/work/${name}"
  rm -rf "${stage}"
  mkdir -p "${stage}"
  for bin in "${binaries[@]}"; do
    ditto "${src}/${bin}" "${stage}/${bin}"
  done
  ditto "${root}/README.md" "${stage}/README.md"
  ditto "${root}/SECURITY.md" "${stage}/SECURITY.md"
  mkdir -p "${stage}/docs"
  ditto "${root}/docs/DEPLOYMENT.md" "${stage}/docs/DEPLOYMENT.md"
  if [[ -e "${stage}/VERSION.txt" ]]; then
    echo "refusing to ship VERSION.txt" >&2
    exit 1
  fi
  zip_path="${out_dir}/${name}.zip"
  rm -f "${zip_path}"
  # ditto -c -k is the notarization vehicle. Do not repack after submit.
  ditto -c -k --keepParent "${stage}" "${zip_path}"
  verify_zip "${zip_path}" "${name}"
  notarize_zip "${zip_path}"
}

mkdir -p "${out_dir}"
package_one arm64 "${arm64_dir}"
package_one x86_64 "${x86_dir}"
package_one universal "${uni_dir}"

for name in \
  "rmm-${tag}-macos-arm64.zip" \
  "rmm-${tag}-macos-x86_64.zip" \
  "rmm-${tag}-macos-universal.zip"
do
  if [[ ! -s "${out_dir}/${name}" ]]; then
    echo "missing notarized archive ${name}" >&2
    exit 1
  fi
done

echo "Notarized macOS archives are in ${out_dir}"
