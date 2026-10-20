#!/usr/bin/env bash
# Builds the signed, notarized release in one step: build-dist.sh with a
# Developer ID identity, then build-pkg.sh, ending with
#
#   dist/hkdfguard-native-macos-<version>-osx-arm64.pkg   (+ .sha256)
#
# Usage:
#   ./build-release.sh              build and package
#   ./build-release.sh --install    also remove the installed version and
#                                   install the new package (asks for sudo)
#
# Optional overrides (environment):
#   HKDFGUARD_SIGN_IDENTITY   the "Developer ID Application" identity to sign
#                             with. Default: the one identity in the keychain
#                             whose team is the project's DEVELOPMENT_TEAM.
#   HKDFGUARD_NOTARY_PROFILE  notarytool keychain profile. Default:
#                             hkdfguard-notary (create it once with
#                             `xcrun notarytool store-credentials`).
#
# Everything else -- signing checks, notarization, stapling, smoke tests --
# is build-dist.sh's and build-pkg.sh's; this only supplies their inputs.
set -euo pipefail

# Signing needs this user's login keychain, which root can't use: under sudo,
# codesign fails with errSecInternalComponent and root-owned files are left
# in the build folders. Run as yourself; --install asks for sudo itself, only for the install step.
if [ "$(/usr/bin/id -u)" -eq 0 ]; then
    echo "error: don't run $(basename "$0") with sudo -- run it as yourself; --install asks for sudo itself, only for the install step" >&2
    exit 1
fi

# This script drives the release signing (through build-dist.sh and
# build-pkg.sh) and runs sudo; don't let the caller's environment decide
# which security/sudo/installer it runs. PATH is pinned to the system
# folders and TOOLCHAINS cleared, as in build-dist.sh, which also prints
# the developer tools folder in use.
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
unset TOOLCHAINS
cd "$(dirname "$0")"

fail() { echo "error: $*" >&2; exit 1; }

INSTALL=0
case "${1:-}" in
    "") ;;
    --install) INSTALL=1 ;;
    -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) fail "unknown argument: $1 (expected --install or nothing)" ;;
esac

TEAM_ID="$(grep -o 'DEVELOPMENT_TEAM = [A-Z0-9]*' HkdfGuardNativeMacOS.xcodeproj/project.pbxproj | head -n 1 | awk '{print $3}')"
[ -n "$TEAM_ID" ] || fail "could not read DEVELOPMENT_TEAM from the Xcode project"

if [ -z "${HKDFGUARD_SIGN_IDENTITY:-}" ]; then
    # Exactly one Developer ID Application identity for this team, or stop:
    # never guess between two.
    matches="$(security find-identity -v -p codesigning \
        | sed -n "s/.*\"\(Developer ID Application: .* ($TEAM_ID)\)\".*/\1/p" | sort -u)"
    count="$(printf '%s' "$matches" | grep -c . || true)"
    [ "$count" -eq 1 ] || fail "found $count \"Developer ID Application\" identities for team $TEAM_ID; set HKDFGUARD_SIGN_IDENTITY to the one to use"
    HKDFGUARD_SIGN_IDENTITY="$matches"
fi
export HKDFGUARD_RELEASE=1
export HKDFGUARD_SIGN_IDENTITY
export HKDFGUARD_NOTARY_PROFILE="${HKDFGUARD_NOTARY_PROFILE:-hkdfguard-notary}"

echo "==> Release build"
echo "    identity: $HKDFGUARD_SIGN_IDENTITY"
echo "    notary:   $HKDFGUARD_NOTARY_PROFILE"
echo

./build-dist.sh
./build-pkg.sh

# The package build-pkg.sh just wrote: the newest signed (not -UNSIGNED) one,
# never an old-style "-macos-v1-" package left in dist/ by an earlier build.
PKG="$(ls -t dist/hkdfguard-native-macos-*-osx-arm64.pkg 2>/dev/null | grep -v -e '-UNSIGNED' -e '-macos-v1-' | head -n 1 || true)"
[ -n "$PKG" ] || fail "build-pkg.sh finished but no package was found in dist/"

echo
echo "==> Built $PKG"
cat "$PKG.sha256"
pkgutil --check-signature "$PKG" | sed -n '1,4p'

[ "$INSTALL" -eq 1 ] || exit 0

UNINSTALLER="/Library/Application Support/HkdfGuard/v1/uninstall.sh"
echo
if [ -x "$UNINSTALLER" ]; then
    installed="$(pkgutil --pkg-info com.hkdfguard.native 2>/dev/null || true)"
    echo "==> Removing the installed version ($(printf '%s\n' "$installed" | sed -n 's/^version: //p'))"
    sudo "$UNINSTALLER"
else
    echo "==> No installed version to remove"
fi

echo "==> Installing $PKG"
sudo installer -pkg "$PKG" -target /

echo
echo "==> Installed"
pkgutil --pkg-info com.hkdfguard.native | sed -n 's/^version: /    version: /p'
ls "/Library/Application Support/HkdfGuard/v1/"
"/Library/Application Support/HkdfGuard/v1/hkdfguard" --help >/dev/null 2>&1 \
    && echo "    hkdfguard starts (hardening passed)" \
    || fail "the installed hkdfguard did not start; run it by hand to see why"
