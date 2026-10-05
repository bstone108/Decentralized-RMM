#!/usr/bin/env bash
# Import a Developer ID Application .p12 into a temporary keychain.
# Adapted from bstone108/MatrixClient scripts/import-apple-signing-cert.sh.
# Expected env: APPLE_CERTIFICATE_BASE64, APPLE_CERTIFICATE_PASSWORD
# Optional: RUNNER_TEMP (GitHub Actions), GITHUB_ENV
set -euo pipefail

if [[ "${GITHUB_EVENT_NAME:-}" == "pull_request" || "${EVENT_NAME:-}" == "pull_request" ]]; then
  echo "Refusing to import a signing certificate on a pull request." >&2
  exit 1
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This script must run on macOS." >&2
  exit 1
fi

: "${APPLE_CERTIFICATE_BASE64:?APPLE_CERTIFICATE_BASE64 is required}"
: "${APPLE_CERTIFICATE_PASSWORD:?APPLE_CERTIFICATE_PASSWORD is required}"

umask 077
TEMP_DIR="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
CERTIFICATE_PATH="${TEMP_DIR}/build_certificate.p12"
KEYCHAIN_PATH="${TEMP_DIR}/app-signing.keychain-db"
KEYCHAIN_PASSWORD="$(openssl rand -base64 32)"

# Record paths before import so a later step can delete a partial keychain.
if [[ -n "${GITHUB_ENV:-}" ]]; then
  {
    printf 'MACOS_SIGNING_KEYCHAIN_PATH=%s\n' "${KEYCHAIN_PATH}"
    printf 'MACOS_SIGNING_CERTIFICATE_PATH=%s\n' "${CERTIFICATE_PATH}"
  } >> "${GITHUB_ENV}"
fi

python3 - "${CERTIFICATE_PATH}" <<'PY'
import base64
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
data = os.environ["APPLE_CERTIFICATE_BASE64"].strip()
path.write_bytes(base64.b64decode(data))
if path.stat().st_size == 0:
    raise SystemExit("APPLE_CERTIFICATE_BASE64 decoded to an empty certificate")
PY

rm -f "${KEYCHAIN_PATH}"
security create-keychain -p "${KEYCHAIN_PASSWORD}" "${KEYCHAIN_PATH}"
security set-keychain-settings -lut 21600 "${KEYCHAIN_PATH}"
security unlock-keychain -p "${KEYCHAIN_PASSWORD}" "${KEYCHAIN_PATH}"

security import "${CERTIFICATE_PATH}" \
  -P "${APPLE_CERTIFICATE_PASSWORD}" \
  -A \
  -t cert \
  -f pkcs12 \
  -k "${KEYCHAIN_PATH}" \
  -T /usr/bin/codesign \
  -T /usr/bin/security \
  -T /usr/bin/productbuild

security set-key-partition-list \
  -S apple-tool:,apple:,codesign: \
  -s \
  -k "${KEYCHAIN_PASSWORD}" \
  "${KEYCHAIN_PATH}" >/dev/null

INTERMEDIATE_PATH="${TEMP_DIR}/DeveloperIDG2CA.cer"
if curl -fsSL --retry 3 --retry-all-errors \
  "https://www.apple.com/certificateauthority/DeveloperIDG2CA.cer" \
  -o "${INTERMEDIATE_PATH}"; then
  security import "${INTERMEDIATE_PATH}" -k "${KEYCHAIN_PATH}" -T /usr/bin/codesign >/dev/null || true
fi

EXISTING_KEYCHAINS=()
while IFS= read -r line; do
  trimmed="${line#"${line%%[![:space:]]*}"}"
  trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
  trimmed="${trimmed#\"}"
  trimmed="${trimmed%\"}"
  if [[ -n "${trimmed}" && "${trimmed}" != "${KEYCHAIN_PATH}" ]]; then
    EXISTING_KEYCHAINS+=("${trimmed}")
  fi
done < <(security list-keychains -d user)

security list-keychains -d user -s "${KEYCHAIN_PATH}" "${EXISTING_KEYCHAINS[@]+"${EXISTING_KEYCHAINS[@]}"}"

echo "Imported signing identities:"
security find-identity -v -p codesigning "${KEYCHAIN_PATH}"

identity="Developer ID Application: BRANDON BROWNING STONE (K6N4J68LTY)"
if ! security find-identity -v -p codesigning "${KEYCHAIN_PATH}" | grep -F "${identity}" >/dev/null; then
  echo "Developer ID identity was not found in the temporary keychain." >&2
  exit 1
fi
