#!/bin/bash
# Verifies production mode's machine scope end to end on this Mac -- the
# parts the unit tests can't reach, because they need root, a policy, and
# real LaunchDaemons -- once per KEK suite: ML-KEM-1024 (the default, on
# macOS 26 and later) and P-256 (the policy's KekSuite opt-in):
#
#   - provision: refused without root, refused for an admin outside
#     SecurityAdminGroup, then a machine KEK of the policy's suite created
#     by the one-off system job, in that suite's KEK file format, owned
#     root:<RunnerGroup> 0640, its folder excluded from Time Machine; a
#     second run verifies it
#   - wrap: refused for an admin outside DeploymentAdminGroup, then done in
#     the system job, --fingerprint confirmed, the payload naming the suite,
#     the key file given to the runner group by default
#   - unwrap: works for a LaunchDaemon running as a RunnerGroup member
#     (nobody); refused from this Terminal (root, via sudo) and for an
#     account outside the group
#   - RequirePostQuantum (P-256 only): the KEK is reported as refused, can't
#     be provisioned or wrap, and its payload doesn't unwrap -- but it can
#     still be retired
#   - retire: refused with the wrong fingerprint; with the right one the KEK
#     file is deleted and the payload no longer unwraps
#
# Before macOS 26 the ML-KEM pass only checks that provisioning refuses,
# rather than creating a P-256 KEK in its place.
#
# Uses this repo's builds (build them first):
#   xcodebuild -project HkdfGuardNativeMacOS.xcodeproj -target HkdfGuardNativeMacOSDylib -configuration Release build
#   (cd hkdfguard-cli && swift build -c release)
# copied to a root-owned staging folder, since machine-scoped commands run
# only root-owned code as root.
#
# Creates, and removes on exit: a local policy file, the group
# _hkdfguardverify (member: nobody), the KEK files for
# com.hkdfguard.verify.mlkem and com.hkdfguard.verify.p256, temporary
# LaunchDaemons, and its staging folder. Refuses to start if a policy, that
# group, or either KEK already exists.
#
# Run with: sudo bash scripts/verify-machine-scope.sh
set -u
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

fail_now() { echo "error: $*" >&2; exit 1; }
[[ "$(id -u)" -eq 0 ]] || fail_now "run with sudo"
[[ -n "${SUDO_USER:-}" ]] && [[ "$SUDO_USER" != root ]] || fail_now "run with sudo from your own (admin) account"

REPO="$(cd "$(dirname "$0")/.." && pwd)"
CLI_SRC="$REPO/hkdfguard-cli/.build/release/hkdfguard"
LIB_SRC="$REPO/build/Release/libhkdfguard.dylib"
for f in "$CLI_SRC" "$LIB_SRC"; do [[ -f "$f" ]] || fail_now "missing $f -- build first (see the header)"; done

HG="/Library/Application Support/HkdfGuard"
POLICY="$HG/policy.plist"
MANAGED="/Library/Managed Preferences/com.hkdfguard.plist"
KEKS="$HG/keks"
STAGE="$HG/verify"
SERVICES="com.hkdfguard.verify.mlkem com.hkdfguard.verify.p256"
GROUP=_hkdfguardverify
LABEL=com.hkdfguard.verify.consumer
JOBPLIST=/Library/LaunchDaemons/$LABEL.plist
MLKEM_AVAILABLE=0
[[ "$(sw_vers -productVersion | cut -d. -f1)" -ge 26 ]] && MLKEM_AVAILABLE=1

[[ -e "$POLICY" ]] && fail_now "$POLICY already exists; not touching a real policy"
[[ -e "$MANAGED" ]] && fail_now "$MANAGED exists (an MDM policy); run this on a Mac without one"
for s in $SERVICES; do [[ -e "$KEKS/$s.kek" ]] && fail_now "$KEKS/$s.kek already exists"; done
dscl . -read "/Groups/$GROUP" >/dev/null 2>&1 && fail_now "group $GROUP already exists"

CREATED_HG=0; CREATED_KEKS=0
[[ -d "$HG" ]] || { mkdir -m 0755 "$HG" && chown root:wheel "$HG" && CREATED_HG=1; }
[[ -d "$KEKS" ]] || CREATED_KEKS=1

cleanup() {
    launchctl bootout system/$LABEL 2>/dev/null; rm -f "$JOBPLIST"
    rm -f "$POLICY"
    for s in $SERVICES; do rm -f "$KEKS/$s.kek"; done
    [[ "$CREATED_KEKS" -eq 1 ]] && rmdir "$KEKS" 2>/dev/null
    rm -rf "$STAGE"
    [[ "$CREATED_HG" -eq 1 ]] && rmdir "$HG" 2>/dev/null
    dseditgroup -o delete -n . "$GROUP" >/dev/null 2>&1
    # The Secure Enclave prototype's watcher, if it is still installed.
    launchctl bootout system/com.hkdfguard.sepoc.watch 2>/dev/null
    rm -f /Library/LaunchDaemons/com.hkdfguard.sepoc.watch.plist
    rm -rf /private/var/tmp/hkdfguard-sepoc
}
trap cleanup EXIT

PASS=0; FAILS=0
pass() { echo "  PASS  $*"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL  $*"; FAILS=$((FAILS + 1)); }
expect() { # expect <description> <grep pattern> <output>
    if grep -q -- "$2" <<<"$3"; then pass "$1"; else fail "$1"; echo "        expected /$2/ in: $3"; fi
}
byte_at() { # byte_at <offset> <file>: that byte, as two hex digits
    xxd -s "$1" -l 1 -p "$2" 2>/dev/null
}

echo "== staging root-owned copies of this repo's builds in $STAGE"
mkdir -m 0755 "$STAGE" "$STAGE/bin" "$STAGE/keys" "$STAGE/out"
install -o root -g wheel -m 0755 "$CLI_SRC" "$STAGE/bin/hkdfguard"
install -o root -g wheel -m 0644 "$LIB_SRC" "$STAGE/bin/libhkdfguard.dylib"
# The development CLI finds its library in the repo; the staged one must
# use the root-owned copy beside it.
otool -l "$STAGE/bin/hkdfguard" | awk '/LC_RPATH/{r=1} r && /path /{print $2; r=0}' \
    | while read -r rp; do install_name_tool -delete_rpath "$rp" "$STAGE/bin/hkdfguard" 2>/dev/null; done
install_name_tool -add_rpath @executable_path "$STAGE/bin/hkdfguard"
codesign -s - --force "$STAGE/bin/hkdfguard" 2>/dev/null
cat > "$STAGE/consumer.c" <<'C'
#include "hkdfguard.h"
#include <bsm/audit.h>
#include <stdio.h>
#include <unistd.h>
/* consumer <key-file> <service>: what a service does at startup. */
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    auditinfo_addr_t a; unsigned long long flags = 0;
    if (getaudit_addr(&a, sizeof a) == 0) flags = a.ai_flags;
    uint8_t wrapped[HKDFGUARD_WRAPPED_MAX_LEN]; int wrapped_len = sizeof wrapped;
    int open_status = hkdfguard_open_file(argv[1], wrapped, &wrapped_len);
    uint8_t dek[32]; int dek_len = sizeof dek;
    int unwrap_status = open_status == 0 ? hkdfguard_unwrap_dek(argv[2], wrapped, wrapped_len, dek, &dek_len) : 999;
    printf("uid=%d session_flags=0x%llx open=%d unwrap=%d dek=", (int)getuid(), flags, open_status, unwrap_status);
    if (unwrap_status == 0) for (int i = 0; i < 32; i++) printf("%02x", dek[i]);
    printf("\n");
    return 0;
}
C
cc -I "$REPO/HkdfGuardNativeMacOS" "$STAGE/consumer.c" -L "$STAGE/bin" -lhkdfguard -Wl,-rpath,@executable_path -o "$STAGE/bin/consumer" \
    || fail_now "could not build the consumer"
chown root:wheel "$STAGE/bin/consumer"; chmod 0755 "$STAGE/bin/consumer"
CLI="$STAGE/bin/hkdfguard"

echo "== a runner group holding only the service account (nobody)"
dseditgroup -o create -n . -r "HkdfGuard verification" "$GROUP" || fail_now "could not create $GROUP"
dseditgroup -o edit -n . -a nobody -t user "$GROUP" || fail_now "could not add nobody to $GROUP"
chown nobody "$STAGE/out"

# The suite pass in progress: its service, key file, and the policy's suite
# settings (empty: the defaults).
SERVICE=""; KEYFILE=""; SUITE_KEYS=""

write_policy() { # write_policy <security group> <deployment group>
    cat > "$POLICY" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>MachineServices</key><dict>
    <key>$SERVICE</key><dict><key>RunnerGroup</key><string>$GROUP</string></dict>
  </dict>
  <key>SecurityAdminGroup</key><string>$1</string>
  <key>DeploymentAdminGroup</key><string>$2</string>
  $SUITE_KEYS
</dict></plist>
PLIST
    chown root:wheel "$POLICY"; chmod 0644 "$POLICY"
}

# Runs the consumer as a real LaunchDaemon as <user>; prints its one line.
consumer_daemon() { # consumer_daemon <user> <tag>
    local out="$STAGE/out/$2.txt"
    rm -f "$out"
    launchctl bootout system/$LABEL 2>/dev/null
    cat > "$JOBPLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>$LABEL</string>
<key>UserName</key><string>$1</string>
<key>ProgramArguments</key><array>
  <string>$STAGE/bin/consumer</string><string>$KEYFILE</string><string>$SERVICE</string>
</array>
<key>RunAtLoad</key><true/>
<key>StandardOutPath</key><string>$out</string>
</dict></plist>
PLIST
    chown root:wheel "$JOBPLIST"; chmod 0644 "$JOBPLIST"
    [[ "$1" = nobody ]] || touch "$out"
    chown "$1" "$out" 2>/dev/null
    launchctl bootstrap system "$JOBPLIST"
    for _ in $(seq 1 40); do [[ -s "$out" ]] && break; sleep 0.25; done
    launchctl bootout system/$LABEL 2>/dev/null; rm -f "$JOBPLIST"
    cat "$out" 2>/dev/null || echo "(no output)"
}

# One full pass for a suite.
verify_suite() { # verify_suite <tag> <suite name> <suite byte> <KEK file format byte> <policy suite keys>
    local tag="$1" suite="$2" suite_byte="$3" format_byte="$4"
    SERVICE="com.hkdfguard.verify.$tag"; KEYFILE="$STAGE/keys/verify-$tag.key"; SUITE_KEYS="$5"
    local OUT FP DEK_HEX WRONG

    echo "== $suite: 1. provision (security admin)"
    write_policy "$GROUP" "$GROUP"   # $SUDO_USER is in neither role yet
    OUT=$("$CLI" status -sn $SERVICE 2>&1)
    expect "status: the service is machine-scoped" "scope: machine" "$OUT"
    expect "status: no KEK yet" "kek: absent" "$OUT"
    expect "status: the policy provisions $suite" "provisions: $suite" "$OUT"
    OUT=$(sudo -u "$SUDO_USER" "$CLI" provision -sn $SERVICE 2>&1)
    expect "provision without root is refused" "only root can provision" "$OUT"
    OUT=$("$CLI" provision -sn $SERVICE 2>&1)
    expect "provision by an admin outside SecurityAdminGroup is refused" "not a member of $GROUP, the policy's SecurityAdminGroup" "$OUT"

    write_policy admin "$GROUP"      # now a security admin, still not a deployment admin
    OUT=$("$CLI" provision -sn $SERVICE 2>&1)
    expect "provision creates the machine KEK" "machine KEK provisioned" "$OUT"
    expect "of suite $suite" "suite: $suite" "$OUT"
    FP=$(sed -n 's/^fingerprint: \([0-9a-f]\{64\}\) .*/\1/p' <<<"$OUT")
    [[ ${#FP} -eq 64 ]] && pass "provision printed a fingerprint" || fail "provision printed no fingerprint: $OUT"
    expect "the KEK file is root:$GROUP 0640" "root:$GROUP 640" "$(stat -f '%Su:%Sg %Lp' "$KEKS/$SERVICE.kek" 2>&1)"
    [[ "$(byte_at 4 "$KEKS/$SERVICE.kek")" = "$format_byte" ]] && pass "the KEK file is format $format_byte" \
        || fail "the KEK file is format $(byte_at 4 "$KEKS/$SERVICE.kek"), not $format_byte"
    expect "the KEK folder is excluded from Time Machine" "\\[Excluded\\]" "$(tmutil isexcluded "$KEKS" 2>&1)"
    OUT=$("$CLI" provision -sn $SERVICE 2>&1)
    expect "a second provision verifies, not replaces" "already provisioned.*verified" "$OUT"
    expect "with the same fingerprint" "fingerprint: $FP" "$OUT"
    expect "status reports the suite" "suite: $suite" "$("$CLI" status -sn $SERVICE 2>&1)"

    echo "== $suite: 2. wrap (deployment admin)"
    DEK_HEX=$(head -c 32 /dev/urandom | xxd -p -c 32)
    ( umask 077; xxd -r -p <<<"$DEK_HEX" | base64 > "$STAGE/dek.b64" )
    OUT=$("$CLI" wrap -kf "$KEYFILE" -sn $SERVICE --dek-file "$STAGE/dek.b64" 2>&1)
    expect "wrap by an admin outside DeploymentAdminGroup is refused" "not a member of $GROUP, the policy's DeploymentAdminGroup" "$OUT"
    [[ ! -e "$KEYFILE" ]] && pass "and nothing was written" || fail "a key file was written despite the refusal"

    write_policy admin admin
    OUT=$("$CLI" wrap -kf "$KEYFILE" -sn $SERVICE --dek-file "$STAGE/dek.b64" -fp "$FP" 2>&1)
    expect "wrap succeeds in the system job" "wrapped key written" "$OUT"
    expect "under the provisioned KEK" "fingerprint: $FP (confirmed)" "$OUT"
    [[ "$(byte_at 32 "$KEYFILE")" = "$suite_byte" ]] && pass "the payload names suite $suite_byte" \
        || fail "the payload names suite $(byte_at 32 "$KEYFILE"), not $suite_byte"
    expect "the key file goes to the runner group by default" "root:$GROUP 640" "$(stat -f '%Su:%Sg %Lp' "$KEYFILE" 2>&1)"

    echo "== $suite: 3. unwrap (runtime)"
    OUT=$(consumer_daemon nobody "$tag-nobody-1")
    echo "        nobody daemon: $OUT"
    expect "a LaunchDaemon in the runner group unwraps the DEK" "unwrap=0 dek=$DEK_HEX" "$OUT"
    OUT=$("$STAGE/bin/consumer" "$KEYFILE" $SERVICE)
    echo "        root via sudo (this Terminal): $OUT"
    expect "root in a login session is refused (-18)" "unwrap=-18" "$OUT"
    OUT=$(consumer_daemon "$SUDO_USER" "$tag-$SUDO_USER")
    echo "        $SUDO_USER daemon (not in the group): $OUT"
    if grep -q 'unwrap=0' <<<"$OUT"; then fail "an account outside the runner group unwrapped"; else pass "an account outside the runner group can't unwrap"; fi

    if [[ "$tag" = p256 ]]; then
        echo "== $suite: RequirePostQuantum"
        SUITE_KEYS="<key>RequirePostQuantum</key><true/>"
        write_policy admin admin
        expect "status flags the P-256 KEK as refused" "refused by the policy's RequirePostQuantum" "$("$CLI" status -sn $SERVICE 2>&1)"
        OUT=$(consumer_daemon nobody "$tag-nobody-pq")
        echo "        nobody daemon: $OUT"
        expect "its payload doesn't unwrap (-12)" "unwrap=-12" "$OUT"
        OUT=$("$CLI" wrap -kf "$KEYFILE" -sn $SERVICE --dek-file "$STAGE/dek.b64" -fp "$FP" --force 2>&1)
        expect "it can't wrap" "RequirePostQuantum" "$OUT"
        OUT=$("$CLI" provision -sn $SERVICE 2>&1)
        expect "provision refuses it rather than verifying it" "RequirePostQuantum" "$OUT"
        [[ -e "$KEKS/$SERVICE.kek" ]] && pass "and leaves it in place" || fail "the KEK file was removed"
        # Retired with RequirePostQuantum still set: how a migration ends.
    fi

    echo "== $suite: 4. retire (security admin)"
    WRONG=$(printf '%064d' 0)
    OUT=$("$CLI" retire -sn $SERVICE -fp "$WRONG" 2>&1)
    expect "retire with the wrong fingerprint is refused" "nothing was deleted" "$OUT"
    [[ -e "$KEKS/$SERVICE.kek" ]] && pass "the KEK file is still there" || fail "the KEK file was deleted"
    OUT=$("$CLI" retire -sn $SERVICE -fp "$FP" 2>&1)
    expect "retire with the right fingerprint deletes the KEK" "retired machine KEK" "$OUT"
    [[ ! -e "$KEKS/$SERVICE.kek" ]] && pass "the KEK file is gone" || fail "the KEK file is still there"
    SUITE_KEYS="$5"
    write_policy admin admin
    OUT=$(consumer_daemon nobody "$tag-nobody-2")
    echo "        nobody daemon after retire: $OUT"
    expect "the payload no longer unwraps (-17)" "unwrap=-17" "$OUT"
    expect "status reports it absent" "kek: absent" "$("$CLI" status -sn $SERVICE 2>&1)"
}

if [[ "$MLKEM_AVAILABLE" -eq 1 ]]; then
    verify_suite mlkem ML-KEM-1024 02 02 ""
else
    echo "== ML-KEM-1024: this macOS is before 26, so provisioning must refuse"
    SERVICE=com.hkdfguard.verify.mlkem; KEYFILE="$STAGE/keys/verify-mlkem.key"; SUITE_KEYS=""
    write_policy admin admin
    OUT=$("$CLI" provision -sn $SERVICE 2>&1)
    expect "provision fails, naming the opt-in" "KekSuite P-256" "$OUT"
    [[ ! -e "$KEKS/$SERVICE.kek" ]] && pass "and creates no KEK of another suite" || fail "a KEK file was created"
fi
verify_suite p256 P-256 01 01 "<key>KekSuite</key><string>P-256</string>"

echo
echo "== $PASS passed, $FAILS failed"
[[ "$FAILS" -eq 0 ]]
