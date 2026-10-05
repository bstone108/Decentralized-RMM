#!/usr/bin/env bash
# Cross-compile release binaries and, for linux/windows, pack the archive.
# Darwin binaries are left unsigned for the macOS signing job.
# Version embedded with -ldflags is the padded YYYY.MM.DD.BB value (no v prefix).
set -euo pipefail

goos=""
goarch=""
version=""
tag=""
dest=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --goos) goos="${2:?}"; shift 2 ;;
    --goarch) goarch="${2:?}"; shift 2 ;;
    --version) version="${2:?}"; shift 2 ;;
    --tag) tag="${2:?}"; shift 2 ;;
    --dest) dest="${2:?}"; shift 2 ;;
    *)
      echo "unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if [[ -z "${goos}" || -z "${goarch}" || -z "${version}" || -z "${tag}" || -z "${dest}" ]]; then
  echo "usage: scripts/build-release-binaries.sh --goos GOOS --goarch GOARCH --version YYYY.MM.DD.BB --tag vYYYY.MM.DD.BB --dest dist/..." >&2
  exit 1
fi

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "${root}"

canonical="$(python3 "${root}/scripts/next-date-build-version" --from-tag "${tag}")"
if [[ "${version}" != "${canonical}" || "v${version}" != "${tag}" ]]; then
  echo "refusing to embed ${version} for tag ${tag}; padded version is ${canonical}" >&2
  exit 1
fi

case "${goos}/${goarch}" in
  linux/amd64|linux/arm64|windows/amd64|windows/arm64|darwin/amd64|darwin/arm64) ;;
  *)
    echo "unsupported target ${goos}/${goarch}" >&2
    exit 1
    ;;
esac

case "${dest}" in
  dist/*) ;;
  *)
    echo "dest must be a directory under dist/" >&2
    exit 1
    ;;
esac
case "${dest}" in
  *..*)
    echo "dest must not contain .." >&2
    exit 1
    ;;
esac
if [[ -L "${dest}" ]]; then
  echo "dest must not be a symlink" >&2
  exit 1
fi

for required in rmm-agent rmm-console rmm-pack; do
  if [[ ! -d "${root}/cmd/${required}" ]]; then
    echo "missing cmd/${required}" >&2
    exit 1
  fi
done

bins=(rmm-agent rmm-console rmm-pack)
if [[ -d "${root}/cmd/rmm" ]]; then
  bins[${#bins[@]}]=rmm
fi

suffix=""
if [[ "${goos}" == "windows" ]]; then
  suffix=".exe"
fi

workdir=""
stage=""
cleanup() {
  if [[ -n "${workdir}" ]]; then
    rm -rf "${workdir}"
  fi
  if [[ -n "${stage}" ]]; then
    rm -rf "${stage}"
  fi
}
trap cleanup EXIT
workdir="$(mktemp -d)"
stage="$(mktemp -d)"

export CGO_ENABLED=0
export GOOS="${goos}"
export GOARCH="${goarch}"
ldflags="-s -w -X main.version=${version}"

for bin in "${bins[@]}"; do
  echo "Building ${bin} for ${goos}/${goarch} version ${version}"
  go build -trimpath -ldflags "${ldflags}" -o "${workdir}/${bin}${suffix}" "${root}/cmd/${bin}"
done

verify_buildinfo() {
  local bin_path="$1"
  local meta
  meta="$(go version -m "${bin_path}")"
  META="${meta}" VERSION="${version}" python3 - <<'PY'
import os
import sys

text = os.environ["META"]
version = os.environ["VERSION"]
needle = "-X main.version=" + version
if needle not in text:
    sys.exit(f"missing ldflags {needle}\n{text}")
end = text.find(needle) + len(needle)
if end < len(text) and text[end] not in " \n\t\"'":
    sys.exit(f"ldflags version continues past {version!r}\n{text}")
if "CGO_ENABLED=0" not in text:
    sys.exit(f"CGO_ENABLED=0 missing from build info\n{text}")
if "CGO_ENABLED=1" in text:
    sys.exit(f"CGO_ENABLED=1 present in build info\n{text}")
PY
}

for bin in "${bins[@]}"; do
  verify_buildinfo "${workdir}/${bin}${suffix}"
done

host_os="$(go env GOHOSTOS)"
host_arch="$(go env GOHOSTARCH)"
if [[ "${goos}" == "${host_os}" && "${goarch}" == "${host_arch}" ]]; then
  for bin in "${bins[@]}"; do
    got="$("${workdir}/${bin}${suffix}" version)"
    if [[ "${got}" != "${version}" ]]; then
      echo "${bin} version [${got}] != [${version}]" >&2
      exit 1
    fi
  done
fi

rm -rf "${dest}"
mkdir -p "${dest}"

if [[ "${goos}" == "darwin" ]]; then
  for bin in "${bins[@]}"; do
    cp "${workdir}/${bin}" "${dest}/${bin}"
    chmod 755 "${dest}/${bin}"
  done
  echo "Wrote unsigned darwin binaries to ${dest}"
  exit 0
fi

python3 - "${workdir}" "${stage}" "${dest}" "${tag}" "${goos}" "${goarch}" "${suffix}" "${root}" "${bins[@]}" <<'PY'
import pathlib
import stat
import sys
import tarfile
import zipfile

bin_dir = pathlib.Path(sys.argv[1])
stage_parent = pathlib.Path(sys.argv[2])
dest = pathlib.Path(sys.argv[3])
tag, goos, goarch, suffix = sys.argv[4:8]
root = pathlib.Path(sys.argv[8])
bins = sys.argv[9:]
if not bins:
    raise SystemExit("no binaries to pack")

base = f"rmm-{tag}-{goos}-{goarch}"
stage = stage_parent / base
stage.mkdir(parents=True)
filenames = []
for bin_name in bins:
    filename = f"{bin_name}{suffix}"
    src = bin_dir / filename
    if not src.is_file():
        raise SystemExit(f"missing binary {src}")
    target = stage / filename
    target.write_bytes(src.read_bytes())
    target.chmod(0o755)
    filenames.append(filename)

docs = (
    ("README.md", "README.md"),
    ("SECURITY.md", "SECURITY.md"),
    ("docs/DEPLOYMENT.md", "docs/DEPLOYMENT.md"),
)
for src_rel, dest_rel in docs:
    src = root / src_rel
    if not src.is_file():
        raise SystemExit(f"missing {src_rel}")
    target = stage / dest_rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(src.read_bytes())
    target.chmod(0o644)
    filenames.append(dest_rel)

if any(name.lower() == "version.txt" for name in filenames):
    raise SystemExit("refusing to pack VERSION.txt")

allowed = {base, base + "/", f"{base}/docs", f"{base}/docs/"}
allowed.update(f"{base}/{name}" for name in filenames)

if goos == "linux":
    out = dest / f"{base}.tar.gz"
    with tarfile.open(out, "w:gz") as tf:
        tf.add(stage, arcname=base)
    with tarfile.open(out, "r:gz") as tf:
        names = tf.getnames()
elif goos == "windows":
    out = dest / f"{base}.zip"
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        info = zipfile.ZipInfo(base + "/")
        info.external_attr = (stat.S_IFDIR | 0o755) << 16
        zf.writestr(info, b"")
        for name in filenames:
            path = stage / name
            mode = 0o755 if name.endswith(".exe") else 0o644
            info = zipfile.ZipInfo(f"{base}/{name}")
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | mode) << 16
            zf.writestr(info, path.read_bytes())
    with zipfile.ZipFile(out) as zf:
        names = zf.namelist()
else:
    raise SystemExit(f"cannot pack {goos}")

extra = [name for name in names if name not in allowed]
missing = [f"{base}/{name}" for name in filenames if f"{base}/{name}" not in names]
if extra or missing:
    raise SystemExit(f"archive members extra={extra} missing={missing} got={names}")
if any(name.lower().endswith("version.txt") for name in names):
    raise SystemExit("VERSION.txt packed")
print(out)
PY
