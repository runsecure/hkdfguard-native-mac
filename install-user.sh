#!/usr/bin/env bash
# Installs the native library for the current user into
#
#   ~/.hkdfguard/v1/
#
# holding libhkdfguard_v1.dylib, hkdfguard.h, hkdfguard-v1-initialize and
# SHA256SUMS for this Mac's architecture only: the osx-arm64 build on Apple
# silicon, the osx-x64 build on Intel.
#
# Usage: ./install-user.sh [--from DIR] [--team-id TEAMID] [--uninstall]
#
#   --from DIR        either a build-dist.sh output folder holding
#                     osx-arm64/ and osx-x64/ (default: ./dist next to this
#                     script), or a single extracted per-architecture
#                     release folder with SHA256SUMS at its top level
#   --team-id TEAMID  require both binaries to be signed by this Team ID
#                     (default: they only have to agree with each other)
#   --uninstall       remove ~/.hkdfguard/v1
#
# A per-user install is only as trusted as the user account: anything
# running as this user can replace it. Use install-system.sh for a
# root-owned machine-wide install.
#
# The home folder is looked up in the directory service rather than taken
# from $HOME, matching what the C# resolver should do: $HOME is set by
# whoever starts the process.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DYLIB_NAME="libhkdfguard_v1.dylib"
HEADER_NAME="hkdfguard.h"
CLI_NAME="hkdfguard-v1-initialize"
PAYLOAD=("$DYLIB_NAME" "$HEADER_NAME" "$CLI_NAME" SHA256SUMS)

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

# Running under sudo would leave root-owned files in the user's profile
# that the user can then no longer update.
[ "$(id -u)" -ne 0 ] || fail "run this as the user it installs for, not as root"

# The hardware's architecture, not this shell's: hw.optional.arm64 is 1 on
# Apple silicon even when the shell runs under Rosetta, where `uname -m`
# would report x86_64. On Intel the sysctl does not exist.
if [ "$(sysctl -n hw.optional.arm64 2>/dev/null || echo 0)" = 1 ]; then
    RID=osx-arm64; ARCH=arm64
else
    RID=osx-x64; ARCH=x86_64
fi

USER_NAME="$(id -un)"
USER_UID="$(id -u)"
HOME_DIR="$(dscl /Search -read "/Users/$USER_NAME" NFSHomeDirectory 2>/dev/null \
    | awk -F': ' '/^NFSHomeDirectory:/{print $2; exit}')"
[ -n "$HOME_DIR" ] && [ -d "$HOME_DIR" ] || fail "could not look up the home folder for $USER_NAME"

PARENT="$HOME_DIR/.hkdfguard"
TARGET="$PARENT/v1"

# Asserts `path` is a real folder or file (not a symlink), owned by this
# user, and not writable by group or others.
assert_private() {
    local path="$1" owner mode
    [ ! -L "$path" ] || fail "$path is a symlink; refusing to install through it"
    owner="$(stat -f '%u' "$path")"
    mode="$(stat -f '%Lp' "$path")"
    [ "$owner" = "$USER_UID" ] || fail "$path is owned by uid $owner, not $USER_NAME"
    (( (8#$mode & 8#022) == 0 )) || fail "$path is writable by group or others (mode $mode)"
}

assert_private "$HOME_DIR"

if [ "$UNINSTALL" = 1 ]; then
    if [ -e "$TARGET" ] || [ -L "$TARGET" ]; then
        assert_private "$PARENT"
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
# A single extracted release folder, or build-dist.sh output with one
# subfolder per architecture.
if [ ! -f "$SOURCE/SHA256SUMS" ]; then
    [ -d "$SOURCE/$RID" ] || fail "no $RID/ folder in $SOURCE (this Mac is $ARCH)"
    SOURCE="$SOURCE/$RID"
fi

if [ -e "$PARENT" ] || [ -L "$PARENT" ]; then
    assert_private "$PARENT"
else
    mkdir -m 0755 "$PARENT"
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

# Verify the *staged* copy, not the source, so nothing can change between
# the check and the install.
for f in "${PAYLOAD[@]}"; do
    [ -f "$STAGE/$f" ] && [ ! -L "$STAGE/$f" ] || fail "missing $f"
done

# SHA256SUMS must cover exactly the three payload files.
listed="$(awk '{print $2}' "$STAGE/SHA256SUMS" | sort | tr '\n' ' ')"
expected="$(printf '%s\n' "$CLI_NAME" "$HEADER_NAME" "$DYLIB_NAME" | sort | tr '\n' ' ')"
[ "$listed" = "$expected" ] || fail "SHA256SUMS lists '$listed', expected '$expected'"
(cd "$STAGE" && shasum -a 256 -c -s SHA256SUMS) || fail "checksum mismatch in $SOURCE"

for f in "$DYLIB_NAME" "$CLI_NAME"; do
    [ "$(lipo -archs "$STAGE/$f")" = "$ARCH" ] \
        || fail "$f is built for '$(lipo -archs "$STAGE/$f")', but this Mac is $ARCH"
    codesign --verify --strict "$STAGE/$f" || fail "$f: signature does not verify"
    info="$(codesign -dvv "$STAGE/$f" 2>&1)"
    team="$(sed -n 's/^TeamIdentifier=//p' <<<"$info")"
    [ -n "$team" ] && [ "$team" != "not set" ] || fail "$f: no Team ID (ad-hoc signed?)"
    [ -n "$TEAM_ID" ] || TEAM_ID="$team"
    [ "$team" = "$TEAM_ID" ] || fail "$f: signed by team $team, expected $TEAM_ID"
done

chmod 0644 "$STAGE/$DYLIB_NAME" "$STAGE/$HEADER_NAME" "$STAGE/SHA256SUMS"
chmod 0755 "$STAGE/$CLI_NAME" "$STAGE"

# Swap the new tree into place; the old one is removed on exit.
if [ -e "$TARGET" ] || [ -L "$TARGET" ]; then
    OLD="$PARENT/.v1.old.$$"
    mv "$TARGET" "$OLD"
fi
mv "$STAGE" "$TARGET"

echo "==> Installed $RID (team $TEAM_ID): $TARGET/$DYLIB_NAME"
