#!/usr/bin/env bash
# Installs the native library machine-wide, root-owned, into
#
#   /Library/Application Support/HkdfGuard/v1/
#
# holding libhkdfguard_v1.dylib, hkdfguard.h, hkdfguard-v1-initialize and
# SHA256SUMS from the osx-arm64 build. Apple silicon only: the library is
# not built for Intel.
#
# Usage: sudo ./install-system.sh [--from DIR] [--team-id TEAMID] [--uninstall]
#
#   --from DIR        either a build-dist.sh output folder holding
#                     osx-arm64/ (default: ./dist next to this script), or
#                     an extracted osx-arm64 release folder with SHA256SUMS
#                     at its top level
#   --team-id TEAMID  require both binaries to be signed by this Team ID
#                     (recommended for fleet installs; default: they only
#                     have to agree with each other)
#   --uninstall       remove /Library/Application Support/HkdfGuard/v1
#
# Why this location: every folder from / down is owned by root and writable
# only by root, it is outside SIP so an installer can write it, and it is
# Apple's documented place for machine-wide support files. /usr/local is
# avoided because Homebrew on Intel Macs hands its subfolders to a user.
#
# Every file is copied into a root-owned staging folder *before* it is
# verified, so a user who can write the --from folder cannot swap a file
# between the check and the install.
set -euo pipefail

# Don't let the caller's PATH choose which codesign/shasum/etc. root runs.
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DYLIB_NAME="libhkdfguard_v1.dylib"
HEADER_NAME="hkdfguard.h"
CLI_NAME="hkdfguard-v1-initialize"
PAYLOAD=("$DYLIB_NAME" "$HEADER_NAME" "$CLI_NAME" SHA256SUMS)

BASE="/Library/Application Support"
PARENT="$BASE/HkdfGuard"
TARGET="$PARENT/v1"

fail() { echo "error: $*" >&2; exit 1; }

SOURCE="$ROOT/dist"
TEAM_ID=""
UNINSTALL=0
while [ $# -gt 0 ]; do
    case "$1" in
        --from)      [ $# -ge 2 ] || fail "--from needs a folder"; SOURCE="$2"; shift 2 ;;
        --team-id)   [ $# -ge 2 ] || fail "--team-id needs a value"; TEAM_ID="$2"; shift 2 ;;
        --uninstall) UNINSTALL=1; shift ;;
        -h|--help)   sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
        *)           fail "unknown argument: $1 (see --help)" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || fail "must run as root: sudo $0 $*"
umask 022

# The hardware, not this shell: hw.optional.arm64 is 1 on Apple silicon
# even when the shell runs under Rosetta, where `uname -m` would report
# x86_64. On Intel the sysctl does not exist.
RID=osx-arm64
ARCH=arm64
[ "$(sysctl -n hw.optional.arm64 2>/dev/null || echo 0)" = 1 ] \
    || fail "this Mac is not Apple silicon; the library is built for arm64 only"

# Asserts `path` is a real folder or file (not a symlink), owned by root,
# and not writable by group or others.
assert_root_owned() {
    local path="$1" owner mode
    [ ! -L "$path" ] || fail "$path is a symlink; refusing to install through it"
    owner="$(stat -f '%u' "$path")"
    mode="$(stat -f '%Lp' "$path")"
    [ "$owner" = 0 ] || fail "$path is owned by uid $owner, not root"
    (( (8#$mode & 8#022) == 0 )) || fail "$path is writable by group or others (mode $mode)"
}

# Every ancestor of the install, so no non-root user can rename a folder
# above it and substitute their own.
for p in / /Library "$BASE"; do
    assert_root_owned "$p"
done

if [ "$UNINSTALL" = 1 ]; then
    if [ -e "$TARGET" ] || [ -L "$TARGET" ]; then
        assert_root_owned "$PARENT"
        rm -rf "$TARGET"
        rmdir "$PARENT" 2>/dev/null || true
        echo "==> Removed $TARGET"
    else
        echo "==> Nothing installed at $TARGET"
    fi
    exit 0
fi

[ -d "$SOURCE" ] || fail "source folder not found: $SOURCE (run ./build-dist.sh or pass --from)"
SOURCE="$(cd "$SOURCE" && pwd -P)"
# An extracted release folder, or build-dist.sh output with an osx-arm64/
# subfolder.
if [ ! -f "$SOURCE/SHA256SUMS" ]; then
    [ -d "$SOURCE/$RID" ] || fail "no $RID/ folder in $SOURCE"
    SOURCE="$SOURCE/$RID"
fi

if [ -e "$PARENT" ] || [ -L "$PARENT" ]; then
    assert_root_owned "$PARENT"
else
    install -d -o root -g wheel -m 0755 "$PARENT"
fi

# Stage next to the target so the final rename is on one volume.
STAGE="$(mktemp -d "$PARENT/.v1.staging.XXXXXX")"
OLD=""
cleanup() { rm -rf "$STAGE"; [ -z "$OLD" ] || rm -rf "$OLD"; }
trap cleanup EXIT

for f in "${PAYLOAD[@]}"; do
    [ -f "$SOURCE/$f" ] || fail "missing $f in $SOURCE"
    # -X: don't carry extended attributes (quarantine, ACL-like metadata).
    cp -X "$SOURCE/$f" "$STAGE/$f"
done
chown root:wheel "$STAGE" "$STAGE"/*
chmod 0644 "$STAGE/$DYLIB_NAME" "$STAGE/$HEADER_NAME" "$STAGE/SHA256SUMS"
chmod 0755 "$STAGE/$CLI_NAME" "$STAGE"

# Verify the staged (root-owned) copy, not the source.
for f in "${PAYLOAD[@]}"; do
    [ -f "$STAGE/$f" ] && [ ! -L "$STAGE/$f" ] || fail "missing $f"
done

# SHA256SUMS must cover exactly the three payload files.
listed="$(awk '{print $2}' "$STAGE/SHA256SUMS" | sort | tr '\n' ' ')"
expected="$(printf '%s\n' "$CLI_NAME" "$HEADER_NAME" "$DYLIB_NAME" | sort | tr '\n' ' ')"
[ "$listed" = "$expected" ] || fail "SHA256SUMS lists '$listed', expected '$expected'"
(cd "$STAGE" && shasum -a 256 -c -s SHA256SUMS) || fail "checksum mismatch in $SOURCE"

DEVELOPER_ID=1
for f in "$DYLIB_NAME" "$CLI_NAME"; do
    [ "$(lipo -archs "$STAGE/$f")" = "$ARCH" ] \
        || fail "$f is built for '$(lipo -archs "$STAGE/$f")', expected $ARCH"
    codesign --verify --strict "$STAGE/$f" || fail "$f: signature does not verify"
    info="$(codesign -dvv "$STAGE/$f" 2>&1)"
    team="$(sed -n 's/^TeamIdentifier=//p' <<<"$info")"
    [ -n "$team" ] && [ "$team" != "not set" ] || fail "$f: no Team ID (ad-hoc signed?)"
    [ -n "$TEAM_ID" ] || TEAM_ID="$team"
    [ "$team" = "$TEAM_ID" ] || fail "$f: signed by team $team, expected $TEAM_ID"
    grep -q '^Authority=Developer ID Application:' <<<"$info" || DEVELOPER_ID=0
done

# Swap the new tree into place; the old one is removed on exit.
if [ -e "$TARGET" ] || [ -L "$TARGET" ]; then
    OLD="$PARENT/.v1.old.$$"
    mv "$TARGET" "$OLD"
fi
mv "$STAGE" "$TARGET"

# Final check of what is actually on disk.
assert_root_owned "$TARGET"
for f in "${PAYLOAD[@]}"; do
    assert_root_owned "$TARGET/$f"
done

echo "==> Installed $RID (team $TEAM_ID): $TARGET/$DYLIB_NAME"
if [ "$DEVELOPER_ID" = 0 ]; then
    echo "warning: these binaries are not Developer ID signed (development build?)." >&2
    echo "         Use a HKDFGUARD_RELEASE=1 build for machines outside your team." >&2
fi
