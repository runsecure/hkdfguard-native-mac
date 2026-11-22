#!/usr/bin/env bash
# Writes fuzz/seeds/<target>/ for every target (or the ones named): the
# inputs each target's source lists, one file each, named for what it
# tries. The folder is ignored by git: the targets' `seeds:` are the source.
#
# Usage: fuzz/make-seeds.sh [target...]
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
binary=$here/build/hkdfguard-fuzz
[ -x "$binary" ] || { echo "make-seeds: no $binary; run fuzz/build.sh first" >&2; exit 2; }
if [ $# -eq 0 ]; then
    set -- $(HKDFGUARD_FUZZ_LIST=1 "$binary")
fi
for target in "$@"; do
    rm -rf "$here/seeds/$target"
    mkdir -p "$here/seeds/$target"
    HKDFGUARD_FUZZ_TARGET=$target HKDFGUARD_FUZZ_WRITE_SEEDS=$here/seeds/$target "$binary"
done
