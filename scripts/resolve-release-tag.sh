#!/usr/bin/env bash
# Validate the release tag for a tag push or workflow_dispatch.
# Writes tag, version, and prerelease to GITHUB_OUTPUT. Does not create a tag.
set -euo pipefail

if [[ "${GITHUB_EVENT_NAME:-}" == "pull_request" || "${EVENT_NAME:-}" == "pull_request" ]]; then
  echo "Refusing to resolve a release on a pull request." >&2
  exit 1
fi

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "${root}"

case "${EVENT_NAME:-}" in
  push)
    tag="${PUSH_TAG:-}"
    ;;
  workflow_dispatch)
    tag="${DISPATCH_TAG:-}"
    ;;
  *)
    echo "Unsupported event ${EVENT_NAME:-}." >&2
    exit 1
    ;;
esac

if [[ -z "${tag}" ]]; then
  echo "Release tag is empty." >&2
  exit 1
fi

case "${tag}" in
  v*) ;;
  *)
    echo "Release tag must start with v, for example v2026.10.05.01." >&2
    exit 1
    ;;
esac

version="$(python3 "${root}/scripts/next-date-build-version" --from-tag "${tag}")"
if [[ "v${version}" != "${tag}" ]]; then
  echo "Tag ${tag} does not match padded version ${version}." >&2
  exit 1
fi

prerelease=false
case "${tag}" in
  *-*) prerelease=true ;;
esac

if [[ "${EVENT_NAME}" == "push" && "${GITHUB_REF:-}" == "refs/tags/${tag}" ]]; then
  echo "Using pushed tag ${tag} (version ${version})."
else
  if ! git ls-remote --exit-code origin "refs/tags/${tag}" >/dev/null; then
    echo "Tag ${tag} does not exist on origin. This workflow does not create tags." >&2
    exit 1
  fi
  echo "Using existing tag ${tag} (version ${version})."
fi

if [[ -z "${GITHUB_OUTPUT:-}" ]]; then
  printf 'tag=%s\n' "${tag}"
  printf 'version=%s\n' "${version}"
  printf 'prerelease=%s\n' "${prerelease}"
  exit 0
fi

{
  printf 'tag=%s\n' "${tag}"
  printf 'version=%s\n' "${version}"
  printf 'prerelease=%s\n' "${prerelease}"
} >> "${GITHUB_OUTPUT}"
