#!/usr/bin/env bash
# Writes LICENSE-THIRD-PARTY: the licenses of the third-party code built into
# the age-plugin-rypt binary. That is every module, other than this one, that
# provides a package the binary links on any of the four release targets, and
# Go itself, whose runtime and standard library are linked into every binary.
#
# Usage: scripts/third-party-licenses.sh [OUTPUT]
#
# OUTPUT defaults to LICENSE-THIRD-PARTY at the root of the repository. The
# license texts come from the module cache. The script fails if a module has
# no LICENSE, LICENCE or COPYING file in its root directory. It does not judge
# whether a license is acceptable.
set -euo pipefail

if [ "$#" -gt 1 ]; then
  echo "usage: $0 [OUTPUT]" >&2
  exit 2
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${1:-$root/LICENSE-THIRD-PARTY}"
case "$out" in
  /*) ;;
  *) out="$PWD/$out" ;;
esac
cd "$root"

# The release builds: see the build job in .github/workflows/release.yml.
targets=(darwin/arm64 darwin/amd64 linux/arm64 linux/amd64)
export CGO_ENABLED=0
# Only this module's go.mod and go.sum decide the dependencies.
export GOWORK=off

goroot="$(go env GOROOT)"
goversion="$(go env GOVERSION)"
goversion="${goversion#go}"
if [ ! -f "$goroot/LICENSE" ]; then
  echo "no LICENSE in $goroot" >&2
  exit 1
fi

go mod download

# One line per module: path, version and directory, separated by tabs.
modules="$(
  for target in "${targets[@]}"; do
    GOOS="${target%/*}" GOARCH="${target#*/}" go list -mod=readonly -deps \
      -f '{{with .Module}}{{if not .Main}}{{.Path}}{{"\t"}}{{.Version}}{{with .Replace}} (replaced by {{.Path}}{{with .Version}} {{.}}{{end}}){{end}}{{"\t"}}{{.Dir}}{{end}}{{end}}' .
  done | LC_ALL=C sort -u
)"

# Prints the license files in the root of a module directory, one per line:
# LICENSE, LICENCE and COPYING, and the NOTICE and PATENTS files that some
# licenses come with, each with or without a suffix such as .md or -MIT.
license_files() {
  local file name
  for file in "$1"/*; do
    [ -f "$file" ] || continue
    name="$(basename "$file" | tr '[:upper:]' '[:lower:]')"
    case "$name" in
      *.go) ;;
      licen[cs]e | licen[cs]e[._-]* | copying | copying[._-]* | notice | notice[._-]* | patents | patents[._-]*)
        printf '%s\n' "$file"
        ;;
    esac
  done
}

# Prints a file under a heading, ending it with a newline if it lacks one.
print_file() {
  echo
  echo "== $(basename "$1") =="
  echo
  cat "$1"
  if [ -n "$(tail -c 1 "$1")" ]; then
    echo
  fi
}

rule="--------------------------------------------------------------------------------"

tmp="$(mktemp "$out.XXXXXX")"
trap 'rm -f "$tmp"' EXIT

{
  echo "Third-party software in age-plugin-rypt"
  echo "======================================="
  echo
  echo "The age-plugin-rypt binary is built with Go, whose runtime and standard"
  echo "library it contains, and from the Go modules listed below. Each section"
  echo "names a module and its version, followed by the text of its license files."
  echo
  echo "  Go $goversion"
  while IFS=$'\t' read -r path version _; do
    [ -n "$path" ] || continue
    echo "  $path $version"
  done <<< "$modules"
  echo

  echo "$rule"
  echo "Go $goversion (the Go runtime and standard library)"
  for file in "$goroot/LICENSE" "$goroot/PATENTS"; do
    if [ -f "$file" ]; then
      print_file "$file"
    fi
  done
  echo

  while IFS=$'\t' read -r path version dir; do
    [ -n "$path" ] || continue
    if [ -z "$dir" ] || [ ! -d "$dir" ]; then
      echo "$path $version is not in the module cache" >&2
      exit 1
    fi
    files="$(license_files "$dir")"
    if ! grep -Eiq '/(licen[cs]e|copying)[^/]*$' <<< "$files"; then
      echo "$path $version has no LICENSE, LICENCE or COPYING file in $dir" >&2
      exit 1
    fi
    echo "$rule"
    echo "$path $version"
    while IFS= read -r file; do
      print_file "$file"
    done <<< "$files"
    echo
  done <<< "$modules"
} > "$tmp"

chmod 0644 "$tmp"
mv "$tmp" "$out"
trap - EXIT
echo "wrote $out"
