#!/usr/bin/env bash
# Attach release archives and SHA256SUMS to a GitHub Release for an existing tag.
# Does not create the tag. Does not mark the release as a draft.
set -euo pipefail

dry_run=0
if [[ "${1:-}" == "--dry-run" ]]; then
  dry_run=1
  shift
fi
if [[ $# -ne 0 ]]; then
  echo "usage: scripts/publish-github-release.sh [--dry-run]" >&2
  exit 1
fi

if [[ "${GITHUB_EVENT_NAME:-}" == "pull_request" || "${EVENT_NAME:-}" == "pull_request" ]]; then
  echo "Refusing to publish a release on a pull request." >&2
  exit 1
fi

: "${TAG:?TAG is required}"
: "${VERSION:?VERSION is required}"
: "${PRERELEASE:?PRERELEASE is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"

repo_root="${REPO_ROOT:-.}"
artifacts_dir="${ARTIFACTS_DIR:-release-artifacts}"
root="$(cd "${repo_root}" && pwd)"
artifacts_dir="$(cd "${artifacts_dir}" && pwd)"

canonical="$(python3 "${root}/scripts/next-date-build-version" --from-tag "${TAG}")"
if [[ "${VERSION}" != "${canonical}" ]]; then
  echo "VERSION ${VERSION} does not match tag ${TAG} (${canonical})." >&2
  exit 1
fi
title="v${VERSION}"
if [[ "${title}" != "${TAG}" ]]; then
  echo "Release title ${title} must match tag ${TAG}." >&2
  exit 1
fi

case "${TAG}" in
  *-*)
    if [[ "${PRERELEASE}" != "true" ]]; then
      echo "Tag ${TAG} contains a hyphen and must be a prerelease." >&2
      exit 1
    fi
    ;;
  *)
    if [[ "${PRERELEASE}" != "false" ]]; then
      echo "Tag ${TAG} has no hyphen and must be a full release." >&2
      exit 1
    fi
    ;;
esac

asset_names=(
  "rmm-${TAG}-linux-amd64.tar.gz"
  "rmm-${TAG}-linux-arm64.tar.gz"
  "rmm-${TAG}-windows-amd64.zip"
  "rmm-${TAG}-windows-arm64.zip"
  "rmm-${TAG}-macos-arm64.zip"
  "rmm-${TAG}-macos-x86_64.zip"
  "rmm-${TAG}-macos-universal.zip"
)

shopt -s nullglob
if [[ ! -f "${artifacts_dir}/rmm-${TAG}-linux-amd64.tar.gz" ]]; then
  nested=( "${artifacts_dir}"/*/* )
  if [[ ${#nested[@]} -gt 0 ]]; then
    find "${artifacts_dir}" -type f -exec mv -n {} "${artifacts_dir}/" \;
  fi
fi
shopt -u nullglob

for name in "${asset_names[@]}"; do
  if [[ ! -s "${artifacts_dir}/${name}" ]]; then
    echo "missing release asset ${name}" >&2
    find "${artifacts_dir}" -print >&2 || true
    exit 1
  fi
done

rm -f "${artifacts_dir}/SHA256SUMS"
(
  cd "${artifacts_dir}"
  sha256sum "${asset_names[@]}" | LC_ALL=C sort -k2 > SHA256SUMS
  sha256sum -c SHA256SUMS
)

if grep -q 'SHA256SUMS' "${artifacts_dir}/SHA256SUMS"; then
  echo "SHA256SUMS must list the archives only." >&2
  exit 1
fi
line_count="$(wc -l < "${artifacts_dir}/SHA256SUMS" | tr -d ' ')"
if [[ "${line_count}" -ne "${#asset_names[@]}" ]]; then
  echo "SHA256SUMS has ${line_count} lines, want ${#asset_names[@]}." >&2
  exit 1
fi

files=()
for name in "${asset_names[@]}"; do
  files+=("${artifacts_dir}/${name}")
done
files+=("${artifacts_dir}/SHA256SUMS")

notes="${root}/docs/release-notes/${TAG}.md"
echo "Release title: ${title}"
if [[ -s "${notes}" ]]; then
  echo "Release notes: ${notes}"
else
  echo "No ${notes}; GitHub will generate the notes."
fi

if [[ "${dry_run}" -eq 1 ]]; then
  echo "Dry run: not creating a GitHub Release and not creating a tag."
  printf 'asset %s\n' "${files[@]}"
  exit 0
fi

tag_on_origin=0
attempt=1
while [[ "${attempt}" -le 5 ]]; do
  if git -C "${root}" ls-remote --exit-code origin "refs/tags/${TAG}" >/dev/null; then
    tag_on_origin=1
    break
  fi
  attempt=$((attempt + 1))
  sleep 2
done
if [[ "${tag_on_origin}" -ne 1 ]]; then
  echo "Tag ${TAG} does not exist on origin. Refusing to create a tag." >&2
  exit 1
fi

if gh release view "${TAG}" --repo "${GITHUB_REPOSITORY}" >/dev/null 2>&1; then
  echo "Release ${TAG} already exists. Refusing to replace it." >&2
  exit 1
fi

# gh release create makes a tag when the tag is missing. The check above
# refuses that path. Do not pass --target, which could point a new tag at the
# workflow SHA instead of the existing tag. Do not pass --draft.
set -- gh release create "${TAG}" --repo "${GITHUB_REPOSITORY}" --title "${title}"
if [[ "${PRERELEASE}" == "true" ]]; then
  set -- "$@" --prerelease
fi
if [[ -s "${notes}" ]]; then
  set -- "$@" --notes-file "${notes}"
else
  set -- "$@" --generate-notes
fi
for file in "${files[@]}"; do
  set -- "$@" "${file}"
done

echo "Creating GitHub release ${title}"
"$@"
