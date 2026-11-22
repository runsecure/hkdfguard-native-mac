#!/usr/bin/env bash
# One fuzzing campaign: runs <target> for <seconds> under libFuzzer,
# starting from its corpus (fuzz/corpus/<target>, kept between runs where
# the caller keeps it) and its seeds, and reports the result as Markdown.
# Exits 1 on a finding, 2 if the harness doesn't build or the arguments are
# wrong.
#
# By hand, the report goes to stdout and says what was found. In CI
# (.github/workflows/fuzz.yml) it goes to the run's summary page, which
# anyone who can see the repository can read -- so there it says only that
# there was a finding, and the finding itself goes into
# fuzz/campaign-<target>.sarif (fuzz/finding_sarif.py), which the workflow
# uploads to code scanning: the Security tab, shown to maintainers only.
#
# The fuzzer's own output goes to fuzz/campaign-<target>.log; a finding's
# input is under fuzz/artifacts/<target>/.
#
# Needs fuzz/libfuzzer/libFuzzer.a (fuzz/build-libfuzzer.sh).
#
# Usage: fuzz/campaign.sh <target> <seconds>
set -euo pipefail
cd "$(dirname "$0")/.."

[[ $# -eq 2 && $2 =~ ^[0-9]+$ ]] || { echo "usage: $0 <target> <seconds>" >&2; exit 2; }
target=$1
seconds=$2
summary=${GITHUB_STEP_SUMMARY:-/dev/stdout}
# Set where what this prints is public (GitHub Actions): a finding's details
# then go to the SARIF file only.
public=${GITHUB_ACTIONS:-}
log=fuzz/campaign-$target.log

if ! fuzz/build.sh --engine libfuzzer >"$log" 2>&1; then
    tail -n 60 "$log" >&2
    printf '### :x: `%s`: did not build\n\nThe harness no longer compiles against the library; see the job log.\n' "$target" >> "$summary"
    exit 2
fi
fuzz/run.sh --list | grep -qx "$target" || { echo "campaign: no fuzz target \"$target\"" >&2; exit 2; }

fuzz/make-seeds.sh "$target" >/dev/null
corpus=fuzz/corpus/$target
mkdir -p "$corpus"
# The first folder is the one libFuzzer adds to.
inputs=("$corpus" "fuzz/seeds/$target")
# Findings from an earlier run are not this run's.
rm -rf "fuzz/artifacts/$target" "fuzz/campaign-$target.sarif"
mkdir -p "fuzz/artifacts/$target"
options=("-max_total_time=$seconds" -timeout=30 -max_len=4096 -print_final_stats=1 "-artifact_prefix=fuzz/artifacts/$target/")
case $target in
    policy)      options+=(-dict=fuzz/policy.dict) ;;
    api_threads) options+=(-timeout=120) ;; # up to four threads of key agreements, under a sanitizer
esac

status=0
fuzz/run.sh "$target" "${inputs[@]}" "${options[@]}" >"$log" 2>&1 || status=$?

executions=$(sed -n 's/^stat::number_of_executed_units: //p' "$log" | tail -n 1)
entries=$(find "$corpus" -type f | wc -l | tr -d ' ')
findings=$(find "fuzz/artifacts/$target" -type f | sed 's|.*/||' | sort)
found=$(printf '%s' "$findings" | grep -c . || true)

{
    if [[ $status -eq 0 ]]; then
        printf '### :white_check_mark: `%s`: no findings\n\n' "$target"
    else
        printf '### :x: `%s`: FINDING\n\n' "$target"
    fi
    printf '| executions | time budget | corpus entries | findings |\n|---|---|---|---|\n'
    printf '| %s | %ss | %s | %s |\n' "${executions:-unknown}" "$seconds" "$entries" "$found"
    if [[ $status -ne 0 && -n $public ]]; then
        printf '\nThe details -- what failed, the input, the log -- are in the Security tab, under code scanning (branch `%s`, tool `hkdfguard-fuzz`). They are not in this run.\n' "$(git rev-parse --abbrev-ref HEAD)"
    elif [[ $status -ne 0 ]]; then
        # What kind of failure, in a line: the harness's own message, or the
        # sanitizer's summary.
        reason=$(grep -m1 -E '^FUZZ FINDING|^SUMMARY: |ERROR: libFuzzer: ' "$log" || true)
        printf '\n%s\n' "${reason:-The fuzzer exited with status $status; see $log.}"
        for name in $findings; do
            printf '\nReplay: `fuzz/run.sh %s fuzz/artifacts/%s/%s`\n' "$target" "$target" "$name"
        done
    fi
    printf '\n'
} >> "$summary"

if [[ $status -ne 0 ]]; then
    sarif=fuzz/campaign-$target.sarif
    category=$(python3 -I fuzz/finding_sarif.py "$target" "$log" "fuzz/artifacts/$target" "$(git rev-parse HEAD)" "$sarif")
    if [[ -n $public ]]; then
        # For the upload step. Nothing of the finding goes to the job log.
        printf 'sarif=%s\ncategory=%s\n' "$sarif" "$category" >> "${GITHUB_OUTPUT:-/dev/null}"
        echo "campaign: finding in $target; see the Security tab (code scanning)." >&2
    else
        tail -n 80 "$log" >&2
        echo "campaign: finding in $target; SARIF for code scanning written to $sarif." >&2
    fi
    exit 1
fi
