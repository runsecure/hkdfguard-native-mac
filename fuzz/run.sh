#!/usr/bin/env bash
# Runs one fuzz target: fuzz/build/hkdfguard-fuzz with the target chosen,
# and everything after the target's name passed through -- libFuzzer's
# options and corpus folders with the libFuzzer engine, files and folders of
# inputs (and -mutate=<n>) with the standalone one. See fuzz/README.md.
#
# Usage: fuzz/run.sh <target> [arguments...]
#        fuzz/run.sh --list
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
binary=$here/build/hkdfguard-fuzz
[ -x "$binary" ] || { echo "run: no $binary; run fuzz/build.sh first" >&2; exit 2; }
if [ "${1:-}" = "--list" ]; then
    HKDFGUARD_FUZZ_LIST=1 exec "$binary"
fi
[ $# -ge 1 ] || { echo "usage: $0 <target> [arguments...]   ($0 --list names the targets)" >&2; exit 2; }
target=$1
shift
# A sanitizer report is a finding like any other: abort, so the engine
# records the input. No leak detection: macOS has none.
export ASAN_OPTIONS="${ASAN_OPTIONS:-abort_on_error=1:detect_leaks=0}"
HKDFGUARD_FUZZ_TARGET=$target exec "$binary" "$@"
