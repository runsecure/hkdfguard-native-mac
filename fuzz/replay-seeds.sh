#!/usr/bin/env bash
# Runs every seed the targets list through its target, once, under
# AddressSanitizer: the buffer, NULL-pointer, truncation, header-byte and
# string-boundary attacks, as a regression suite that takes a minute or two
# rather than a fuzzing campaign. Fails on the first seed that crashes a
# target or breaks one of its checks. Needs nothing but Xcode.
#
# Usage: fuzz/replay-seeds.sh [target...]     (default: every target)
set -euo pipefail
cd "$(dirname "$0")/.."

fuzz/build.sh --engine standalone
if [ $# -eq 0 ]; then
    set -- $(fuzz/run.sh --list)
fi
fuzz/make-seeds.sh "$@" >/dev/null
# A finding's input is written to the current folder.
mkdir -p fuzz/artifacts
cd fuzz/artifacts
for target in "$@"; do
    count=$(find "../seeds/$target" -type f | wc -l | tr -d ' ')
    printf '== %s: %s seeds ==\n' "$target" "$count"
    log=$(mktemp)
    if ! ../run.sh "$target" "../seeds/$target" >"$log" 2>&1; then
        cat "$log" >&2; rm -f "$log"
        echo "replay-seeds: FAIL: $target (the offending input is fuzz/artifacts/crash-$target-<pid>)" >&2
        exit 1
    fi
    # And the run must have been of these seeds, all of them.
    ran=$(sed -n 's/^.*: ran \([0-9]*\) inputs .*/\1/p' "$log")
    rm -f "$log"
    [ "$ran" = "$count" ] || { echo "replay-seeds: FAIL: $target ran $ran of $count seeds" >&2; exit 1; }
done
echo "replay-seeds: every seed passed."
