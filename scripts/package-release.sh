#!/usr/bin/env bash
# Packages the release binaries: one tarball per target, plus SHA256SUMS.
#
# Usage: scripts/package-release.sh VERSION ARTIFACTS OUT
#
# ARTIFACTS holds one directory per target, named bin-<os>-<arch> and
# containing the age-plugin-rypt binary, which is how actions/download-artifact
# lays out the release workflow's artifacts. Each tarball,
# age-plugin-rypt-vVERSION-<os>-<arch>.tar.gz, unpacks to a single directory
# holding the binary, the README and the licenses, including
# LICENSE-THIRD-PARTY, which scripts/third-party-licenses.sh writes.
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 VERSION ARTIFACTS OUT" >&2
  exit 2
fi
version="$1"
artifacts="$2"
out="$3"

targets=(
  darwin-arm64
  darwin-amd64
  linux-arm64
  linux-amd64
)

if [ ! -f LICENSE-THIRD-PARTY ]; then
  echo "missing LICENSE-THIRD-PARTY: run scripts/third-party-licenses.sh" >&2
  exit 1
fi

mkdir -p "$out"
staging="$(mktemp -d)"
trap 'rm -rf "$staging"' EXIT

for target in "${targets[@]}"; do
  binary="$artifacts/bin-$target/age-plugin-rypt"
  if [ ! -f "$binary" ]; then
    echo "missing $binary" >&2
    exit 1
  fi
  name="age-plugin-rypt-v$version-$target"
  mkdir "$staging/$name"
  # Artifacts lose the executable bit in transit. Copying keeps the bytes, and
  # with them any macOS signature.
  install -m 0755 "$binary" "$staging/$name/age-plugin-rypt"
  install -m 0644 README.md LICENSE-MIT LICENSE-APACHE LICENSE-THIRD-PARTY "$staging/$name/"
  tar -C "$staging" --owner=0 --group=0 --numeric-owner -czf "$out/$name.tar.gz" "$name"
done

(cd "$out" && sha256sum -- *.tar.gz > SHA256SUMS)
cat "$out/SHA256SUMS"
