#!/usr/bin/env bash
# Builds the signed, notarized installer package from build-dist.sh's output:
#
#   dist/hkdfguard-native-macos-v1-<version>-osx-arm64.pkg   (+ .sha256)
#
# The package installs, root:wheel, into /Library/Application Support/HkdfGuard/v1/:
#
#   libhkdfguard_v1.dylib          the library
#   hkdfguard.h                    its C header
#   hkdfguard        the CLI, legacy keychain mode
#   hkdfguard.app    the CLI, data-protection keychain mode
#   SHA256SUMS                     checksums of the first three
#   uninstall.sh                   removes all of it (sudo)
#
# and its postinstall script adds a root-owned symlink
# /usr/local/bin/hkdfguard -> v1/hkdfguard.
# It installs only on Apple silicon running macOS 14 or later, only to a
# system volume (never a user's home), with no customization.
#
# Usage, after a release build (HKDFGUARD_RELEASE=1 ./build-dist.sh):
#
#   HKDFGUARD_NOTARY_PROFILE=hkdfguard-notary ./build-pkg.sh
#
#   HKDFGUARD_PKG_VERSION       optional; defaults to the built app's version,
#                               which is MARKETING_VERSION in the Xcode project,
#                               and must equal it if given. MAJOR.MINOR.PATCH;
#                               installers and MDM compare it to decide whether
#                               this is an upgrade.
#   HKDFGUARD_NOTARY_PROFILE    required for a signed build; the same notarytool
#                               keychain profile build-dist.sh uses.
#   HKDFGUARD_INSTALLER_IDENTITY  optional; defaults to the "Developer ID
#                               Installer" identity for the project's Team.
#   HKDFGUARD_TEAM_ID           optional; defaults to the project's DEVELOPMENT_TEAM.
#   HKDFGUARD_PKG_UNSIGNED=1    local layout testing only: skips signing and
#                               notarization and names the output -UNSIGNED.
#                               Gatekeeper and MDM tools refuse such a package.
#
# A signed build requires the dist/ input to be a release build: the dylib,
# CLI, and app Developer ID signed by the same Team and notarized, the app
# stapled. Everything is staged in a temporary directory and only moved into
# dist/ once every check has passed.
set -euo pipefail

# This script signs what every machine will trust; don't let the caller's
# PATH decide which codesign/productbuild/security/curl it runs.
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST="$ROOT/dist"
LIB_DIR="$DIST/osx-arm64"
APP_SRC="$DIST/osx-arm64-app/hkdfguard.app"
PKG_RES="$ROOT/pkg"

DYLIB_NAME="libhkdfguard_v1.dylib"
HEADER_NAME="hkdfguard.h"
CLI_NAME="hkdfguard"
APP_NAME="hkdfguard.app"
PKG_ID="com.hkdfguard.native.v1"
INSTALL_LOCATION="/Library/Application Support/HkdfGuard"

fail() { echo "error: $*" >&2; exit 1; }

# The release version lives in one place: MARKETING_VERSION in the Xcode
# project, which build-dist.sh bakes into the app as CFBundleShortVersionString.
[ -f "$APP_SRC/Contents/Info.plist" ] || fail "missing $APP_SRC -- run build-dist.sh first"
APP_VERSION="$(plutil -extract CFBundleShortVersionString raw -o - "$APP_SRC/Contents/Info.plist" 2>/dev/null)" \
    || fail "$APP_SRC has no CFBundleShortVersionString"
VERSION="${HKDFGUARD_PKG_VERSION:-$APP_VERSION}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
    || fail "the package version must be MAJOR.MINOR.PATCH (got '${VERSION}')"
[ "$VERSION" = "$APP_VERSION" ] \
    || fail "HKDFGUARD_PKG_VERSION=$VERSION does not match the built app's version $APP_VERSION (MARKETING_VERSION); rebuild dist/ or drop the override"

UNSIGNED="${HKDFGUARD_PKG_UNSIGNED:-}"
NOTARY_PROFILE="${HKDFGUARD_NOTARY_PROFILE:-}"

TEAM_ID="${HKDFGUARD_TEAM_ID:-}"
if [ -z "$TEAM_ID" ]; then
    TEAM_ID="$(grep -o 'DEVELOPMENT_TEAM = [A-Z0-9]*;' "$ROOT/HkdfGuardNativeMacOS.xcodeproj/project.pbxproj" \
        | sort -u | sed 's/DEVELOPMENT_TEAM = //; s/;//')"
    [ "$(wc -l <<<"$TEAM_ID" | tr -d ' ')" = 1 ] && [ -n "$TEAM_ID" ] \
        || fail "could not determine a single DEVELOPMENT_TEAM from the project; set HKDFGUARD_TEAM_ID"
fi

if [ "$UNSIGNED" = 1 ]; then
    OUT_NAME="hkdfguard-native-macos-v1-$VERSION-osx-arm64-UNSIGNED.pkg"
    echo "note: HKDFGUARD_PKG_UNSIGNED=1 -- unsigned, unnotarized; for local layout testing only" >&2
else
    OUT_NAME="hkdfguard-native-macos-v1-$VERSION-osx-arm64.pkg"
    [ -n "$NOTARY_PROFILE" ] || fail "set HKDFGUARD_NOTARY_PROFILE (or HKDFGUARD_PKG_UNSIGNED=1 for a local test build)"
    IDENTITY="${HKDFGUARD_INSTALLER_IDENTITY:-}"
    identities="$(security find-identity -v)"
    if [ -z "$IDENTITY" ]; then
        IDENTITY="$(grep -o "\"Developer ID Installer: [^\"]*($TEAM_ID)\"" <<<"$identities" | head -1 | tr -d '"')" || true
    fi
    [ -n "$IDENTITY" ] && grep -qF "\"$IDENTITY\"" <<<"$identities" || fail "$(cat <<EOF
no "Developer ID Installer" certificate for team $TEAM_ID in your keychain.
Create one in Xcode > Settings > Accounts > (your team) > Manage Certificates
> + > Developer ID Installer, then check with: security find-identity -v
EOF
)"
    [[ "$IDENTITY" == "Developer ID Installer:"* ]] \
        || fail "HKDFGUARD_INSTALLER_IDENTITY must be a \"Developer ID Installer\" identity (got '$IDENTITY')"
fi

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/hkdfguard-pkg.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT

# ---------------------------------------------------------------------------
# Input: the dist/ build
# ---------------------------------------------------------------------------

echo "==> Checking dist/ input"
for f in "$DYLIB_NAME" "$HEADER_NAME" "$CLI_NAME" SHA256SUMS; do
    [ -f "$LIB_DIR/$f" ] || fail "missing $LIB_DIR/$f -- run build-dist.sh first"
done
[ -d "$APP_SRC" ] || fail "missing $APP_SRC -- run build-dist.sh first"
(cd "$LIB_DIR" && shasum -a 256 -c -s SHA256SUMS) || fail "$LIB_DIR does not match its SHA256SUMS"

for f in "$LIB_DIR/$DYLIB_NAME" "$LIB_DIR/$CLI_NAME" "$APP_SRC"; do
    codesign --verify --strict --deep "$f" || fail "$f: signature does not verify"
    [ "$(lipo -archs "$( [ -d "$f" ] && echo "$f/Contents/MacOS/$CLI_NAME" || echo "$f")")" = arm64 ] \
        || fail "$f is not an arm64 build"
    info="$(codesign -dvv "$f" 2>&1)"
    grep -q "^TeamIdentifier=$TEAM_ID\$" <<<"$info" || fail "$f: not signed by team $TEAM_ID"
    # Hardened runtime: library validation and no DYLD_* overrides, as
    # build-dist.sh signed it. Re-checked here in case dist/ was touched.
    grep -q 'flags=0x10000(runtime)' <<<"$info" || fail "$f: hardened runtime flag missing"
    if [ "$UNSIGNED" != 1 ]; then
        grep -q '^Authority=Developer ID Application:' <<<"$info" \
            || fail "$f: not Developer ID signed -- package only a HKDFGUARD_RELEASE=1 build"
    fi
done
if [ "$UNSIGNED" != 1 ]; then
    # The bare dylib and CLI can't carry a stapled ticket; check that Apple's
    # ticket service publishes theirs, as build-dist.sh does, rather than
    # trust this Mac's Gatekeeper, which caches lookups by cdhash.
    ticket_url="https://api.apple-cloudkit.com/database/1/com.apple.gk.ticket-delivery/production/public/records/lookup"
    for f in "$LIB_DIR/$DYLIB_NAME" "$LIB_DIR/$CLI_NAME"; do
        cdhash="$(codesign -dvvv "$f" 2>&1 | sed -n 's/^CDHash=//p')"
        [ -n "$cdhash" ] || fail "$f: could not read its cdhash"
        response="$STAGE/ticket-$cdhash.json"
        curl -fsS -m 20 -X POST -H 'Content-Type: application/json' \
            -d "{\"records\":[{\"recordName\":\"2/2/$cdhash\"}]}" "$ticket_url" -o "$response" \
            || fail "could not reach Apple's ticket service to check $f"
        [ "$(plutil -extract records.0.recordType raw -o - "$response" 2>/dev/null)" = DeveloperIDTicket ] \
            && [ -n "$(plutil -extract records.0.fields.signedTicket.value raw -o - "$response" 2>/dev/null)" ] \
            || fail "$f (cdhash $cdhash) is not notarized -- package only a HKDFGUARD_RELEASE=1 build"
    done
    xcrun stapler validate "$APP_SRC" >/dev/null || fail "$APP_SRC has no valid stapled ticket"
fi

# ---------------------------------------------------------------------------
# Payload: <INSTALL_LOCATION>/v1/...
# ---------------------------------------------------------------------------

# The payload root maps to INSTALL_LOCATION, not to /, so the package never
# carries -- and Installer never re-permissions -- /Library or
# /Library/Application Support.
PAYLOAD="$STAGE/payload"
V1="$PAYLOAD/v1"
echo "==> Staging payload"
mkdir -p "$V1"
for f in "$DYLIB_NAME" "$HEADER_NAME" "$CLI_NAME" SHA256SUMS; do
    cp -X "$LIB_DIR/$f" "$V1/$f"
done
ditto "$APP_SRC" "$V1/$APP_NAME"
cp -X "$PKG_RES/uninstall.sh" "$V1/uninstall.sh"

# Modes are carried into the package; owners become root:wheel through
# --ownership recommended.
chmod 0755 "$PAYLOAD" "$V1"
chmod 0644 "$V1/$DYLIB_NAME" "$V1/$HEADER_NAME" "$V1/SHA256SUMS"
chmod 0755 "$V1/$CLI_NAME" "$V1/uninstall.sh"
find "$V1/$APP_NAME" -type d -exec chmod 0755 {} +
find "$V1/$APP_NAME" -type f -exec chmod go-w {} +
codesign --verify --strict --deep "$V1/$APP_NAME" || fail "staged app no longer verifies"

SCRIPTS="$STAGE/scripts"
mkdir -p "$SCRIPTS"
cp -X "$PKG_RES/scripts/postinstall" "$SCRIPTS/postinstall"
chmod 0755 "$SCRIPTS/postinstall"

# Component plist: the app bundle must install where the payload puts it.
# Without BundleIsRelocatable=false, Installer looks for another copy of the
# same bundle ID anywhere on disk (dist/, a download folder) and "upgrades"
# that copy in place instead.
COMPONENT_PLIST="$STAGE/component.plist"
pkgbuild --analyze --root "$PAYLOAD" "$COMPONENT_PLIST" >/dev/null
count=0
while plutil -extract "$count" xml1 -o /dev/null "$COMPONENT_PLIST" 2>/dev/null; do
    count=$((count + 1))
done
[ "$count" -ge 1 ] || fail "pkgbuild --analyze found no bundle in the payload"
for ((i = 0; i < count; i++)); do
    plutil -replace "$i.BundleIsRelocatable" -bool NO "$COMPONENT_PLIST"
    plutil -replace "$i.BundleIsVersionChecked" -bool NO "$COMPONENT_PLIST"
    plutil -replace "$i.BundleOverwriteAction" -string upgrade "$COMPONENT_PLIST"
done

echo "==> Building component package $PKG_ID $VERSION"
mkdir -p "$STAGE/component"
pkgbuild \
    --root "$PAYLOAD" \
    --install-location "$INSTALL_LOCATION" \
    --component-plist "$COMPONENT_PLIST" \
    --scripts "$SCRIPTS" \
    --identifier "$PKG_ID" \
    --version "$VERSION" \
    --ownership recommended \
    "$STAGE/component/component.pkg" >/dev/null

# Distribution: Apple silicon, macOS 14+, system domain only, no choices.
DIST_XML="$STAGE/distribution.xml"
cat >"$DIST_XML" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>HkdfGuard Native v1</title>
    <options customize="never" require-scripts="true" hostArchitectures="arm64"/>
    <domains enable_anywhere="false" enable_currentUserHome="false" enable_localSystem="true"/>
    <allowed-os-versions>
        <os-version min="14.0"/>
    </allowed-os-versions>
    <choices-outline>
        <line choice="default">
            <line choice="$PKG_ID"/>
        </line>
    </choices-outline>
    <choice id="default"/>
    <choice id="$PKG_ID" visible="false">
        <pkg-ref id="$PKG_ID"/>
    </choice>
    <pkg-ref id="$PKG_ID" version="$VERSION" onConclusion="none">component.pkg</pkg-ref>
</installer-gui-script>
EOF

OUT="$STAGE/$OUT_NAME"
echo "==> Building product archive"
if [ "$UNSIGNED" = 1 ]; then
    productbuild --distribution "$DIST_XML" --package-path "$STAGE/component" "$OUT" >/dev/null
else
    productbuild --distribution "$DIST_XML" --package-path "$STAGE/component" \
        --sign "$IDENTITY" --timestamp "$OUT" >/dev/null
fi

# ---------------------------------------------------------------------------
# Notarize and staple
# ---------------------------------------------------------------------------

if [ "$UNSIGNED" != 1 ]; then
    echo "==> Notarizing with keychain profile \"$NOTARY_PROFILE\""
    result="$STAGE/notary-result.json"
    xcrun notarytool submit "$OUT" --keychain-profile "$NOTARY_PROFILE" \
        --wait --output-format json >"$result" \
        || fail "notarytool submit failed: $(cat "$result")"
    [ "$(plutil -extract status raw -o - "$result" 2>/dev/null)" = Accepted ] \
        || fail "notarization not accepted: $(cat "$result") -- run 'xcrun notarytool log <id> --keychain-profile $NOTARY_PROFILE'"
    xcrun stapler staple "$OUT" >/dev/null || fail "stapling the package failed"
fi

# ---------------------------------------------------------------------------
# Verify the finished package
# ---------------------------------------------------------------------------

echo "==> Verifying $OUT_NAME"
if [ "$UNSIGNED" != 1 ]; then
    sig="$(pkgutil --check-signature "$OUT" 2>&1)" || fail "pkgutil --check-signature failed: $sig"
    grep -q 'Status: signed by a developer certificate issued by Apple for distribution' <<<"$sig" \
        || fail "package is not signed with a Developer ID certificate: $sig"
    grep -q "Developer ID Installer: .*($TEAM_ID)" <<<"$sig" \
        || fail "package is not signed by team $TEAM_ID's Developer ID Installer certificate: $sig"
    grep -q 'Notarization: trusted by the Apple notary service' <<<"$sig" \
        || fail "package is not notarized: $sig"
    xcrun stapler validate "$OUT" >/dev/null || fail "stapled ticket does not validate"
    assessment="$(spctl --assess --type install -vv "$OUT" 2>&1)" \
        || fail "Gatekeeper rejects the package: $assessment"
    grep -q 'source=Notarized Developer ID' <<<"$assessment" \
        || fail "Gatekeeper does not report the package as notarized: $assessment"
fi

EXPANDED="$STAGE/expanded"
pkgutil --expand-full "$OUT" "$EXPANDED" >/dev/null
CPKG="$EXPANDED/component.pkg"
[ -d "$CPKG/Payload" ] || fail "expanded package has no component payload"

# Exactly the expected top-level files, nothing more.
expected="$(printf '%s\n' v1 "v1/$APP_NAME" "v1/$CLI_NAME" "v1/$DYLIB_NAME" "v1/$HEADER_NAME" v1/SHA256SUMS v1/uninstall.sh | sort)"
actual="$(cd "$CPKG/Payload" && find . -mindepth 1 -not -path "./v1/$APP_NAME/*" | sed 's|^\./||' | sort)"
[ "$expected" = "$actual" ] || fail "unexpected payload contents:
$actual"

# The bytes that ship are the bytes build-dist.sh verified.
for f in "$DYLIB_NAME" "$HEADER_NAME" "$CLI_NAME"; do
    cmp -s "$LIB_DIR/$f" "$CPKG/Payload/v1/$f" || fail "packaged $f differs from $LIB_DIR/$f"
done
codesign --verify --strict --deep "$CPKG/Payload/v1/$APP_NAME" || fail "packaged app does not verify"
if [ "$UNSIGNED" != 1 ]; then
    xcrun stapler validate "$CPKG/Payload/v1/$APP_NAME" >/dev/null \
        || fail "packaged app lost its stapled notarization ticket"
fi

# Every payload entry root:wheel (uid 0, gid 0); nothing group/other-writable;
# no setuid/setgid/sticky bits (lsbom prints st_mode in octal, e.g. 100755;
# the fourth digit from the right holds those bits).
bom="$(lsbom -p fugm "$CPKG/Bom")"
bad_owner="$(awk -F'\t' '$2 != 0 || $3 != 0' <<<"$bom")"
[ -z "$bad_owner" ] || fail "payload entries not owned by root:wheel:
$bad_owner"
bad_mode="$(awk -F'\t' '{ m = substr($4, length($4) - 2); g = substr(m, 2, 1); o = substr(m, 3, 1); if (g ~ /[2367]/ || o ~ /[2367]/) print }' <<<"$bom")"
[ -z "$bad_mode" ] || fail "payload entries writable by group or others:
$bad_mode"
bad_special="$(awk -F'\t' '{ if (length($4) >= 4 && substr($4, length($4) - 3, 1) != "0") print }' <<<"$bom")"
[ -z "$bad_special" ] || fail "payload entries with setuid, setgid, or sticky bits:
$bad_special"
grep -q "\./v1/$CLI_NAME	0	0	100755" <<<"$bom" || fail "CLI is not root:wheel 0755 in the payload"

[ -x "$CPKG/Scripts/postinstall" ] || fail "postinstall missing from the package"
grep -q 'hostArchitectures="arm64"' "$EXPANDED/Distribution" || fail "Distribution lacks the arm64 restriction"

# ---------------------------------------------------------------------------

mkdir -p "$DIST"
mv "$OUT" "$DIST/$OUT_NAME"
(cd "$DIST" && shasum -a 256 "$OUT_NAME" > "$OUT_NAME.sha256")
echo "==> Done: dist/$OUT_NAME"
cat "$DIST/$OUT_NAME.sha256"
