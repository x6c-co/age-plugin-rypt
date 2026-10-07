#!/usr/bin/env bash
# Checks that a built binary runs: it prints its version, then makes an
# identity file and reads the recipient back from it, which needs no network.
#
# Usage: scripts/smoke-test.sh BINARY
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 BINARY" >&2
  exit 2
fi
binary="$1"

"$binary" --version
identity="$("$binary" new --key 3f2a9c1e-7b4d-4e2a-9f10-6c8d5a2b1e47)"
recipient="$(printf '%s\n' "$identity" | "$binary" recipient)"
expected=age1rypt18u4fc8nmf48z48csdjx452c7gu9hx89g
if [ "$recipient" != "$expected" ]; then
  echo "expected the recipient $expected, got: $recipient" >&2
  exit 1
fi
echo "ok: $recipient"
