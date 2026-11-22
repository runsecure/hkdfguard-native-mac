#!/usr/bin/env bash
# Builds the fuzz harnesses: fuzz/build/hkdfguard-fuzz, one binary holding
# every target (fuzz/run.sh picks one). The library's own source files are
# compiled into it, with HKDFGUARD_FUZZING defined, rather than linked as
# the dylib: the harnesses reach its internal functions, and the sanitizer
# and the fuzzer's coverage see all of it.
#
# Usage: fuzz/build.sh [--engine standalone|libfuzzer] [--sanitizer address|thread|none]
#
#   --engine standalone   (default when fuzz/libfuzzer/libFuzzer.a is not
#                         there) Needs nothing but Xcode. Replays inputs and
#                         mutates them blindly: fuzz/replay-seeds.sh, and
#                         reproducing a finding.
#   --engine libfuzzer    (default when it is) Coverage-guided fuzzing: what
#                         fuzz/campaign.sh runs. Xcode's toolchain compiles
#                         the coverage instrumentation but ships no libFuzzer
#                         to link; fuzz/build-libfuzzer.sh builds one.
#   --sanitizer           address (default), thread (for api_threads), none.
set -euo pipefail
cd "$(dirname "$0")/.."

engine=""
sanitizer=address
while [ $# -gt 0 ]; do
    case "$1" in
        --engine) engine=$2; shift 2 ;;
        --sanitizer) sanitizer=$2; shift 2 ;;
        *) echo "usage: $0 [--engine standalone|libfuzzer] [--sanitizer address|thread|none]" >&2; exit 2 ;;
    esac
done
libfuzzer=fuzz/libfuzzer/libFuzzer.a
if [ -z "$engine" ]; then
    if [ -f "$libfuzzer" ]; then engine=libfuzzer; else engine=standalone; fi
fi

flags=(
    -O -g
    -swift-version 6
    -module-name HkdfGuardFuzz
    -target "$(uname -m)-apple-macos26.0" # the software ML-KEM KEK (FuzzKEKStore) needs macOS 26
    -D HKDFGUARD_FUZZING
    -parse-as-library
    -enforce-exclusivity=checked
)
case "$sanitizer" in
    address|thread) flags+=("-sanitize=$sanitizer") ;;
    none) ;;
    *) echo "build: unknown sanitizer \"$sanitizer\"" >&2; exit 2 ;;
esac

sources=(HkdfGuardNativeMacOS/*.swift fuzz/Sources/Support/*.swift fuzz/Sources/Targets/*.swift fuzz/Sources/Engine/Entry.swift)
case "$engine" in
    standalone)
        sources+=(fuzz/Sources/Engine/Standalone.swift)
        ;;
    libfuzzer)
        [ -f "$libfuzzer" ] || { echo "build: no $libfuzzer; run fuzz/build-libfuzzer.sh first" >&2; exit 2; }
        # What libFuzzer reads: a counter per edge, the table of them, and
        # the operands of comparisons (so it can find magic values).
        flags+=(-sanitize-coverage=edge,inline-8bit-counters,pc-table,trace-cmp)
        flags+=("$libfuzzer" -lc++)
        ;;
    *) echo "build: unknown engine \"$engine\"" >&2; exit 2 ;;
esac

mkdir -p fuzz/build
xcrun swiftc "${flags[@]}" "${sources[@]}" -o fuzz/build/hkdfguard-fuzz
printf '%s\n%s\n' "$engine" "$sanitizer" > fuzz/build/engine
echo "build: fuzz/build/hkdfguard-fuzz ($engine, sanitizer: $sanitizer)"
