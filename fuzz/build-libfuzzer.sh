#!/usr/bin/env bash
# Builds fuzz/libfuzzer/libFuzzer.a: LLVM's libFuzzer, from its source, with
# Xcode's clang. Xcode's toolchain compiles libFuzzer's coverage
# instrumentation into Swift code but does not ship the library itself, so
# coverage-guided fuzzing (fuzz/campaign.sh) needs this once per machine.
# fuzz/replay-seeds.sh does not.
#
# What is fetched is one commit of github.com/llvm/llvm-project, named by
# its full hash below -- git checks that what arrives is that commit -- and
# of it only compiler-rt/lib/fuzzer. Nothing is installed outside fuzz/.
# Bump the commit deliberately.
#
# Usage: fuzz/build-libfuzzer.sh
set -euo pipefail
cd "$(dirname "$0")"

# llvmorg-19.1.7
LLVM_COMMIT=cd708029e0b2869e80abe31ddb175f7c35361f90

work=libfuzzer
rm -rf "$work"
mkdir -p "$work/src"
git -C "$work/src" init -q
git -C "$work/src" remote add origin https://github.com/llvm/llvm-project
git -C "$work/src" sparse-checkout set compiler-rt/lib/fuzzer
git -C "$work/src" fetch -q --depth 1 --filter=blob:none origin "$LLVM_COMMIT"
git -C "$work/src" -c advice.detachedHead=false checkout -q FETCH_HEAD
[ "$(git -C "$work/src" rev-parse HEAD)" = "$LLVM_COMMIT" ] || { echo "build-libfuzzer: fetched another commit than $LLVM_COMMIT" >&2; exit 1; }

mkdir -p "$work/obj"
for source in "$work"/src/compiler-rt/lib/fuzzer/*.cpp; do
    xcrun clang++ -g -O2 -fno-omit-frame-pointer -std=c++17 -c "$source" -o "$work/obj/$(basename "$source" .cpp).o"
done
rm -f "$work/libFuzzer.a"
xcrun ar -rcs "$work/libFuzzer.a" "$work"/obj/*.o
rm -rf "$work/obj"
echo "build-libfuzzer: fuzz/libfuzzer/libFuzzer.a (llvm-project $LLVM_COMMIT)"
