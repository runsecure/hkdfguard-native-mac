#!/usr/bin/env bash
# Builds the Release dylib and the hkdfguard-v1-initialize CLI for arm64
# (Apple silicon) -- the only supported architecture -- signs both with the
# hardened runtime, verifies them, and collects what a downstream consumer
# needs (dylib, C header, CLI, SHA256SUMS) into dist/osx-arm64/, named for
# the .NET runtime identifier. It must run on an Apple silicon Mac.
#
# It also builds the bundled CLI, dist/osx-arm64-app/hkdfguard-v1-initialize.app:
# the same CLI as an arm64 app bundle carrying the shared
# com.hkdfguard.keys keychain access group and an embedded provisioning
# profile, which is what lets it run in data-protection keychain mode. It is
# archived and exported by Xcode, because only an export embeds the profile
# that entitlement requires.
#
# Usage: ./build-dist.sh
#
# For a release, set HKDFGUARD_RELEASE=1. It refuses to run unless every
# artifact will be signed with a "Developer ID Application" identity and
# notarized -- the bare CLI and dylib in dist/osx-arm64/ as well as
# the app bundle -- so a development-signed build, which Gatekeeper rejects on
# any other Mac, can never be mistaken for a release:
#
#   HKDFGUARD_RELEASE=1 \
#   HKDFGUARD_SIGN_IDENTITY="Developer ID Application: <Name> (<TEAMID>)" \
#   HKDFGUARD_NOTARY_PROFILE=<notarytool profile> \
#   ./build-dist.sh
#
# HKDFGUARD_APP_EXPORT selects how the bundled CLI is exported:
#   developer-id  for distribution; needs a "Developer ID Application"
#                 certificate on this Mac. The default when
#                 HKDFGUARD_SIGN_IDENTITY is a Developer ID identity.
#   debugging     development signing for testing only: the bundle launches
#                 only on Macs registered to the developer account. The
#                 default otherwise.
#
# Everything is assembled in a temporary staging directory and only moved
# into place as dist/ once every build, signature, and check has passed, so
# a failure part-way through never leaves an empty or half-populated dist/.
#
# Signing uses a secure timestamp (--timestamp), which contacts Apple's
# timestamp server: this script needs network access to complete.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST="$ROOT/dist"
CLI_PKG="$ROOT/hkdfguard-v1-initialize"
DYLIB_NAME="libhkdfguard_v1.dylib"
HEADER="$ROOT/HkdfGuardNativeMacOS/hkdfguard.h"

# Signing identity for every artifact below. Override with
# HKDFGUARD_SIGN_IDENTITY=... (e.g. a "Developer ID Application" identity for
# distribution outside your own team) without editing this script.
SIGN_IDENTITY="${HKDFGUARD_SIGN_IDENTITY:-Apple Development}"

# --options runtime: hardened runtime. For the CLI this disables the DYLD_*
# environment variables (DYLD_LIBRARY_PATH was demonstrated to silently
# redirect which dylib the CLI loads) and turns on library validation, so
# it will only load dylibs signed by the same Team ID or by Apple -- which
# is why the dylib next to it is signed with the same identity, here, by
# this script, rather than relying on whatever the Xcode target's own
# signing step happened to do (ENABLE_HARDENED_RUNTIME is off in the
# project, and a plain `codesign --sign` does not add it).
CODESIGN_FLAGS=(--force --options runtime --timestamp --sign "$SIGN_IDENTITY")

case "${HKDFGUARD_APP_EXPORT:-}" in
    "")
        if [[ "$SIGN_IDENTITY" == "Developer ID Application"* ]]; then
            APP_EXPORT="developer-id"
        else
            APP_EXPORT="debugging"
        fi
        ;;
    developer-id|debugging)
        APP_EXPORT="$HKDFGUARD_APP_EXPORT"
        ;;
    *)
        echo "error: HKDFGUARD_APP_EXPORT must be developer-id or debugging, got '$HKDFGUARD_APP_EXPORT'" >&2
        exit 2
        ;;
esac

APP_SCHEME="hkdfguard-v1-initialize-app"
APP_NAME="hkdfguard-v1-initialize.app"
APP_EXECUTABLE="hkdfguard-v1-initialize"
ACCESS_GROUP_SUFFIX="com.hkdfguard.keys"

# Credentials. None are stored in this script or the repository; each input
# below only *names* a credential kept elsewhere:
#
#   HKDFGUARD_SIGN_IDENTITY  (above) names a signing certificate in your
#                            login keychain, e.g. "Developer ID Application:
#                            Your Name (TEAMID)".
#   HKDFGUARD_TEAM_ID        the Team ID to sign the bundled CLI for. Not a
#                            secret; defaults to the project's DEVELOPMENT_TEAM.
#   HKDFGUARD_ASC_KEY_PATH, HKDFGUARD_ASC_KEY_ID, HKDFGUARD_ASC_ISSUER_ID
#                            optional App Store Connect API key, passed to
#                            xcodebuild so it can create or download
#                            provisioning profiles without an Apple ID signed
#                            in to Xcode. KEY_PATH is the path to the .p8 file;
#                            keep that file outside the repository. When
#                            unset, xcodebuild uses the account signed in to
#                            Xcode (Settings > Accounts).
#   HKDFGUARD_NOTARY_PROFILE optional name of a notarytool keychain profile.
#                            Create it once with
#                              xcrun notarytool store-credentials <name>
#                            which prompts for your Apple ID and an
#                            app-specific password (or an API key) and stores
#                            them in your keychain. When set, the bundled CLI
#                            is notarized and stapled; requires developer-id.
TEAM_ID="${HKDFGUARD_TEAM_ID:-}"
NOTARY_PROFILE="${HKDFGUARD_NOTARY_PROFILE:-}"

XCODE_AUTH_ARGS=()
if [ -n "${HKDFGUARD_ASC_KEY_PATH:-}" ]; then
    if [ -z "${HKDFGUARD_ASC_KEY_ID:-}" ] || [ -z "${HKDFGUARD_ASC_ISSUER_ID:-}" ]; then
        echo "error: HKDFGUARD_ASC_KEY_PATH requires HKDFGUARD_ASC_KEY_ID and HKDFGUARD_ASC_ISSUER_ID" >&2
        exit 2
    fi
    [ -f "$HKDFGUARD_ASC_KEY_PATH" ] || { echo "error: HKDFGUARD_ASC_KEY_PATH does not exist: $HKDFGUARD_ASC_KEY_PATH" >&2; exit 2; }
    XCODE_AUTH_ARGS=(
        -authenticationKeyPath "$HKDFGUARD_ASC_KEY_PATH"
        -authenticationKeyID "$HKDFGUARD_ASC_KEY_ID"
        -authenticationKeyIssuerID "$HKDFGUARD_ASC_ISSUER_ID"
    )
fi

if [ -n "$NOTARY_PROFILE" ] && [ "$APP_EXPORT" != "developer-id" ]; then
    echo "error: HKDFGUARD_NOTARY_PROFILE is set, but notarization requires HKDFGUARD_APP_EXPORT=developer-id (got $APP_EXPORT)" >&2
    exit 2
fi

# True when the dylib and bare CLI are signed with Developer
# ID -- the only certificate Gatekeeper accepts outside your own Macs, and the
# only one notarization accepts.
is_developer_id() { [[ "$SIGN_IDENTITY" == "Developer ID Application"* ]]; }

# Notarization covers the dylib and bare CLI as well as the app bundle, so it
# needs Developer ID on them too, not only on the app export.
if [ -n "$NOTARY_PROFILE" ] && ! is_developer_id; then
    echo "error: HKDFGUARD_NOTARY_PROFILE is set, but HKDFGUARD_SIGN_IDENTITY is '$SIGN_IDENTITY'; notarization requires a \"Developer ID Application\" identity" >&2
    exit 2
fi

if [ "${HKDFGUARD_RELEASE:-}" = "1" ]; then
    is_developer_id \
        || { echo "error: HKDFGUARD_RELEASE=1 requires HKDFGUARD_SIGN_IDENTITY to be a \"Developer ID Application\" identity (got '$SIGN_IDENTITY')" >&2; exit 2; }
    [ "$APP_EXPORT" = "developer-id" ] \
        || { echo "error: HKDFGUARD_RELEASE=1 requires HKDFGUARD_APP_EXPORT=developer-id (got $APP_EXPORT)" >&2; exit 2; }
    [ -n "$NOTARY_PROFILE" ] \
        || { echo "error: HKDFGUARD_RELEASE=1 requires HKDFGUARD_NOTARY_PROFILE: an unnotarized dylib or CLI is blocked by Gatekeeper once downloaded" >&2; exit 2; }
elif ! is_developer_id || [ -z "$NOTARY_PROFILE" ]; then
    echo "note: this is NOT a release build (signing: $SIGN_IDENTITY; notarization: ${NOTARY_PROFILE:-off})." >&2
    echo "      Gatekeeper will reject its dylib and CLI on other Macs. Use HKDFGUARD_RELEASE=1 for releases." >&2
fi

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/hkdfguard-dist.XXXXXX")"
# Archive/export scratch space, kept out of STAGE so only finished artifacts
# are ever moved into dist/.
WORK="$(mktemp -d "${TMPDIR:-/tmp}/hkdfguard-dist-work.XXXXXX")"
trap 'rm -rf "$STAGE" "$WORK"' EXIT

fail() { echo "error: $*" >&2; exit 1; }

# Asserts that a Mach-O file is a thin binary for exactly one architecture.
assert_arch() {
    local file="$1" expected="$2" actual
    actual="$(lipo -archs "$file")"
    [ "$actual" = "$expected" ] || fail "$file is built for '$actual', expected '$expected'"
}

# Asserts a signature verifies strictly and carries the hardened-runtime
# flag and a secure timestamp.
#
# Tool output is captured into a variable before grepping, here and in
# every check below: piping a tool straight into `grep -q` lets grep exit
# on its first match, the tool then dies of SIGPIPE writing the rest of its
# output, and `set -o pipefail` reports that as a failed pipeline -- a
# false failure (or, for a negated check, a false pass).
assert_signed() {
    local file="$1" info
    codesign --verify --strict --verbose=1 "$file" \
        || fail "$file: signature does not verify"
    info="$(codesign -dv "$file" 2>&1)"
    grep -q 'flags=0x10000(runtime)' <<<"$info" \
        || fail "$file: hardened runtime flag missing"
    grep -q '^Timestamp=' <<<"$info" \
        || fail "$file: secure timestamp missing"
}

# Asserts `file` is signed for this build's Team -- always, since library
# validation only lets the CLI load a same-Team dylib -- and, when a
# Developer ID identity was requested, with a Developer ID certificate. The
# keychain identifies the CLI by this signature: a Developer ID binary is
# remembered by its Team, so certificate renewals don't invalidate the access
# an operator granted to the CLI that provisioned a legacy-mode KEK.
assert_identity() {
    local file="$1" info
    info="$(codesign -dvv "$file" 2>&1)"
    grep -q "^TeamIdentifier=$TEAM_ID\$" <<<"$info" \
        || fail "$file: not signed by team $TEAM_ID"
    if is_developer_id; then
        grep -q '^Authority=Developer ID Application:' <<<"$info" \
            || fail "$file: not signed with a Developer ID Application certificate"
    fi
}

# Asserts Apple's notarization log `log` lists `file`'s cdhash among the
# ticket contents -- the authoritative answer, straight from the notary
# service, with no local caching in between.
assert_in_ticket() {
    local file="$1" log="$2" cdhash i entry
    cdhash="$(codesign -dvvv "$file" 2>&1 | sed -n 's/^CDHash=//p')"
    [ -n "$cdhash" ] || fail "$file: could not read its cdhash"
    for ((i = 0; ; i++)); do
        entry="$(plist_value "$log" "ticketContents.$i.cdhash")"
        [ -n "$entry" ] || break
        [ "$entry" = "$cdhash" ] && return 0
    done
    fail "$file (cdhash $cdhash) is not in the notarization ticket: $(cat "$log")"
}

# Asserts Gatekeeper accepts `file` as notarized. A bare dylib or executable
# cannot carry a stapled ticket, so Gatekeeper looks the ticket up online.
# Both are assessed by their own signature (--type open with the
# primary-signature context): `--type execute` on a bare executable only
# says "does not seem to be an app" and never reports a source. Gatekeeper
# caches lookups by cdhash, so one that was assessed before it was notarized
# can keep reporting "Unnotarized" for a while -- hence the long retry.
assert_notarized() {
    local file="$1" assessment attempt
    for attempt in $(seq 1 12); do
        assessment="$(spctl --assess --type open --context context:primary-signature -vv "$file" 2>&1)" || true
        grep -q 'source=Notarized Developer ID' <<<"$assessment" && return 0
        sleep 15
    done
    fail "$(cat <<EOF
Gatekeeper does not report $file as notarized after 3 minutes:
$assessment
Apple's ticket does list it (checked above), so this Mac's Gatekeeper is
likely answering from a cached lookup made before notarization, or cannot
reach Apple. Re-run later, or check by hand with:
  spctl --assess --type open --context context:primary-signature -vv <file>
EOF
)"
}

# Notarizes the dylib and bare CLI in dist/<rid>/. Nothing is
# modified on disk -- no ticket can be stapled to a bare Mach-O -- so the
# signatures checked above and the SHA256SUMS written afterward stay valid.
notarize_arch() {
    local rid="$1" out="$2"
    local bundle="$WORK/notarize-$rid" submission="$WORK/notarize-$rid.zip" result="$WORK/notary-$rid.json"
    local log="$WORK/notary-log-$rid.json" id
    echo "==> Notarizing $rid ($DYLIB_NAME, hkdfguard-v1-initialize) with keychain profile \"$NOTARY_PROFILE\""
    mkdir -p "$bundle"
    cp "$out/$DYLIB_NAME" "$out/hkdfguard-v1-initialize" "$bundle/"
    ditto -c -k --keepParent "$bundle" "$submission"
    xcrun notarytool submit "$submission" --keychain-profile "$NOTARY_PROFILE" \
        --wait --output-format json >"$result" \
        || fail "notarytool submit failed for $rid: $(cat "$result")"
    [ "$(plist_value "$result" status)" = "Accepted" ] \
        || fail "notarization of $rid not accepted: $(cat "$result") -- run 'xcrun notarytool log <id> --keychain-profile $NOTARY_PROFILE' for details"
    id="$(plist_value "$result" id)"
    xcrun notarytool log "$id" --keychain-profile "$NOTARY_PROFILE" "$log" >/dev/null \
        || fail "could not fetch the notarization log for $rid (submission $id)"
    assert_in_ticket "$out/$DYLIB_NAME" "$log"
    assert_in_ticket "$out/hkdfguard-v1-initialize" "$log"
    assert_notarized "$out/$DYLIB_NAME"
    assert_notarized "$out/hkdfguard-v1-initialize"
}

# build_arch <xcode-arch> <rid>
#   xcode-arch: value for xcodebuild ARCHS / swift build --arch (arm64)
#   rid:        dist/ subfolder name (osx-arm64)
build_arch() {
    local arch="$1" rid="$2"
    local build_dir="$ROOT/build-$arch"
    local dylib_dir="$build_dir/Release"
    local out="$STAGE/$rid"
    local scratch="$CLI_PKG/.build-$arch"

    echo
    echo "==================== $rid ($arch) ===================="
    mkdir -p "$out"

    echo "==> Building $DYLIB_NAME for $arch (Release) into $build_dir"
    xcodebuild -project "$ROOT/HkdfGuardNativeMacOS.xcodeproj" \
        -target HkdfGuardNativeMacOSDylib \
        -configuration Release \
        ARCHS="$arch" ONLY_ACTIVE_ARCH=NO \
        BUILD_DIR="$build_dir" \
        build
    [ -f "$dylib_dir/$DYLIB_NAME" ] || fail "expected $dylib_dir/$DYLIB_NAME after the xcodebuild above"

    echo "==> Building hkdfguard-v1-initialize for $arch (release)"
    # A dedicated --scratch-path: SwiftPM caches the evaluated manifest (and
    # therefore the linker flags derived from HKDFGUARD_DYLIB_DIR) per
    # scratch directory, so a plain `swift build` can't bleed into this one.
    HKDFGUARD_DYLIB_DIR="$dylib_dir" swift build -c release \
        --arch "$arch" \
        --package-path "$CLI_PKG" \
        --scratch-path "$scratch"
    local cli_bin_dir
    cli_bin_dir="$(HKDFGUARD_DYLIB_DIR="$dylib_dir" swift build -c release \
        --arch "$arch" \
        --package-path "$CLI_PKG" \
        --scratch-path "$scratch" \
        --show-bin-path)"
    [ -f "$cli_bin_dir/hkdfguard-v1-initialize" ] || fail "expected CLI at $cli_bin_dir/hkdfguard-v1-initialize"

    echo "==> Assembling $out"
    cp "$dylib_dir/$DYLIB_NAME" "$out/"
    cp "$HEADER" "$out/"
    cp "$cli_bin_dir/hkdfguard-v1-initialize" "$out/"

    echo "==> Making $rid/hkdfguard-v1-initialize self-contained"
    # As linked (see Package.swift), the CLI finds the dylib via an -rpath
    # baked in as this machine's absolute build directory -- fine
    # locally, useless once dist/ is copied anywhere else. The dylib's own
    # install_name is the relocatable "@rpath/<name>.dylib", so the CLI
    # only needs an rpath that resolves relative to itself:
    # @executable_path, i.e. "the directory this binary lives in".
    local cli="$out/hkdfguard-v1-initialize"
    install_name_tool -delete_rpath "$dylib_dir" "$cli"
    install_name_tool -add_rpath "@executable_path" "$cli"
    local rpaths
    rpaths="$(otool -l "$cli" | grep -A2 LC_RPATH || true)"
    if grep -q "path $dylib_dir" <<<"$rpaths"; then
        fail "$cli still carries the absolute build rpath $dylib_dir"
    fi
    grep -q 'path @executable_path' <<<"$rpaths" \
        || fail "$cli lacks the @executable_path rpath"

    echo "==> Signing (hardened runtime, timestamped) with: $SIGN_IDENTITY"
    # install_name_tool invalidated the CLI's linker signature; and the
    # dylib is re-signed here too so both carry identical options and
    # identity regardless of the Xcode target's own signing settings.
    codesign "${CODESIGN_FLAGS[@]}" "$out/$DYLIB_NAME"
    codesign "${CODESIGN_FLAGS[@]}" "$cli"

    echo "==> Verifying $rid"
    assert_arch "$out/$DYLIB_NAME" "$arch"
    assert_arch "$cli" "$arch"
    assert_signed "$out/$DYLIB_NAME"
    assert_signed "$cli"
    assert_identity "$out/$DYLIB_NAME"
    assert_identity "$cli"
    local links
    links="$(otool -L "$cli")"
    grep -q "@rpath/$DYLIB_NAME" <<<"$links" \
        || fail "$cli does not reference @rpath/$DYLIB_NAME"

    # Smoke test: --help must launch, which means dyld resolved the dylib
    # next to the binary via @executable_path AND library validation
    # (hardened runtime) accepted its signature.
    echo "==> Smoke test: $cli --help"
    local help
    help="$("$cli" --help 2>&1)" || fail "$cli --help exited non-zero: $help"
    grep -qi usage <<<"$help" || fail "$cli --help did not print usage"

    if [ -n "$NOTARY_PROFILE" ]; then
        notarize_arch "$rid" "$out"
    fi

    echo "==> Writing $rid/SHA256SUMS"
    (cd "$out" && shasum -a 256 "$DYLIB_NAME" "$(basename "$HEADER")" hkdfguard-v1-initialize > SHA256SUMS)
}

# Prints `key`'s raw value from a plist, or nothing if it is absent.
plist_value() {
    plutil -extract "$2" raw -o - "$1" 2>/dev/null || true
}

# build_app: archives the bundled CLI (arm64), exports it with the
# embedded provisioning profile its keychain-access-groups entitlement
# requires, verifies it, optionally notarizes and staples it, and stages it
# as osx-arm64-app/hkdfguard-v1-initialize.app.
build_app() {
    local out="$STAGE/osx-arm64-app"
    local archive="$WORK/app.xcarchive"
    local export_dir="$WORK/export"
    local options="$WORK/ExportOptions.plist"

    local expected_group="$TEAM_ID.$ACCESS_GROUP_SUFFIX"

    echo
    echo "==================== osx-arm64-app ($APP_NAME, export: $APP_EXPORT) ===================="

    echo "==> Archiving $APP_SCHEME (Release, arm64, team $TEAM_ID)"
    xcodebuild archive \
        -project "$ROOT/HkdfGuardNativeMacOS.xcodeproj" \
        -scheme "$APP_SCHEME" \
        -configuration Release \
        -destination "generic/platform=macOS" \
        -archivePath "$archive" \
        -allowProvisioningUpdates \
        ${XCODE_AUTH_ARGS[@]+"${XCODE_AUTH_ARGS[@]}"} \
        ARCHS=arm64 ONLY_ACTIVE_ARCH=NO \
        DEVELOPMENT_TEAM="$TEAM_ID"

    echo "==> Exporting ($APP_EXPORT)"
    plutil -create xml1 "$options"
    plutil -insert method -string "$APP_EXPORT" "$options"
    plutil -insert teamID -string "$TEAM_ID" "$options"
    plutil -insert signingStyle -string automatic "$options"
    xcodebuild -exportArchive \
        -archivePath "$archive" \
        -exportPath "$export_dir" \
        -exportOptionsPlist "$options" \
        -allowProvisioningUpdates \
        ${XCODE_AUTH_ARGS[@]+"${XCODE_AUTH_ARGS[@]}"}

    local app="$export_dir/$APP_NAME"
    local exe="$app/Contents/MacOS/$APP_EXECUTABLE"
    local embedded_dylib="$app/Contents/Frameworks/$DYLIB_NAME"
    [ -x "$exe" ] || fail "expected $exe after export"
    [ -f "$embedded_dylib" ] || fail "expected the dylib embedded at $embedded_dylib"

    echo "==> Verifying $APP_NAME"
    codesign --verify --strict --deep --verbose=1 "$app" \
        || fail "$app: signature does not verify"

    # -dvv, not -dv: only the second level of verbosity prints the
    # Authority= (certificate chain) lines checked below.
    local info
    info="$(codesign -dvv "$app" 2>&1)"
    grep -q 'flags=0x10000(runtime)' <<<"$info" || fail "$app: hardened runtime flag missing"
    grep -q "^TeamIdentifier=$TEAM_ID\$" <<<"$info" || fail "$app: not signed by team $TEAM_ID"
    if [ "$APP_EXPORT" = "developer-id" ]; then
        grep -q '^Timestamp=' <<<"$info" || fail "$app: secure timestamp missing"
        grep -q '^Authority=Developer ID Application:' <<<"$info" || fail "$app: not signed with a Developer ID Application certificate"
    fi

    # Library validation (hardened runtime) only loads a dylib signed by the
    # same team, so the embedded copy must carry the app's Team ID.
    info="$(codesign -dv "$embedded_dylib" 2>&1)"
    grep -q "^TeamIdentifier=$TEAM_ID\$" <<<"$info" || fail "$embedded_dylib: not signed by team $TEAM_ID"

    assert_arch "$exe" arm64
    assert_arch "$embedded_dylib" arm64

    # The library stores KEKs under the FIRST listed access group.
    local entitlements="$WORK/entitlements.plist"
    codesign -d --entitlements - --xml "$app" >"$entitlements" 2>/dev/null \
        || fail "$app: could not read entitlements"
    local first_group
    first_group="$(plist_value "$entitlements" keychain-access-groups.0)"
    [ "$first_group" = "$expected_group" ] \
        || fail "$app: first keychain-access-groups entry is '$first_group', expected '$expected_group'"
    # The test-only group belongs to the unhardened test host and the Debug
    # builds; a shipped bundle carrying it would share KEKs with them.
    if grep -q 'com\.hkdfguard\.tests\.keys' "$entitlements"; then
        fail "$app: carries the test-only com.hkdfguard.tests.keys access group"
    fi

    local profile="$app/Contents/embedded.provisionprofile"
    [ -f "$profile" ] || fail "$app: no embedded provisioning profile (the access-group entitlement requires one)"
    local profile_plist="$WORK/profile.plist"
    security cms -D -i "$profile" >"$profile_plist" 2>/dev/null || fail "$profile: could not decode"
    [ "$(plist_value "$profile_plist" TeamIdentifier.0)" = "$TEAM_ID" ] \
        || fail "$profile: not issued for team $TEAM_ID"
    local profile_group
    profile_group="$(plist_value "$profile_plist" Entitlements.keychain-access-groups.0)"
    [ "$profile_group" = "$expected_group" ] || [ "$profile_group" = "$TEAM_ID.*" ] \
        || fail "$profile: does not grant '$expected_group' (grants '$profile_group')"
    if [ "$APP_EXPORT" = "developer-id" ]; then
        [ "$(plist_value "$profile_plist" ProvisionsAllDevices)" = "true" ] \
            || fail "$profile: not a Developer ID profile (it does not provision all devices)"
    else
        [ -n "$(plist_value "$profile_plist" ProvisionedDevices.0)" ] \
            || fail "$profile: expected a development profile with registered devices"
        echo "    note: development-signed; launches only on Macs registered in this profile"
    fi

    if [ -n "$NOTARY_PROFILE" ]; then
        echo "==> Notarizing with keychain profile \"$NOTARY_PROFILE\""
        local submission="$WORK/notarize.zip" result="$WORK/notary-result.json"
        ditto -c -k --keepParent "$app" "$submission"
        xcrun notarytool submit "$submission" --keychain-profile "$NOTARY_PROFILE" \
            --wait --output-format json >"$result" \
            || fail "notarytool submit failed: $(cat "$result")"
        [ "$(plist_value "$result" status)" = "Accepted" ] \
            || fail "notarization not accepted: $(cat "$result") -- run 'xcrun notarytool log <id> --keychain-profile $NOTARY_PROFILE' for details"
        xcrun stapler staple "$app" || fail "stapling the notarization ticket failed"
        xcrun stapler validate "$app" || fail "stapled ticket does not validate"
        local assessment
        assessment="$(spctl --assess --type execute --verbose=2 "$app" 2>&1)" \
            || fail "Gatekeeper rejects $app: $assessment"
        grep -q 'source=Notarized Developer ID' <<<"$assessment" \
            || fail "Gatekeeper does not report $app as notarized: $assessment"
    elif [ "$APP_EXPORT" = "developer-id" ]; then
        echo "    note: not notarized (HKDFGUARD_NOTARY_PROFILE unset); Gatekeeper will block it on other Macs"
    fi

    mkdir -p "$out"
    ditto "$app" "$out/$APP_NAME"

    # Read-only smoke test on this Mac, run only now -- after stapling, and on
    # the work copy rather than the one staged for dist/. Once a notarized
    # app has been launched, macOS App Management protection blocks writes
    # into the bundle, so stapler would fail ("Error 73", can't create
    # output). The code is reproducible, so even a fresh export can already
    # be notarized from an earlier run. The bundle launches (AMFI accepted the
    # profile, library validation accepted the embedded dylib) and the
    # library reports data-protection mode. `status` never creates a key.
    echo "==> Smoke test: $APP_EXECUTABLE --help, status"
    local output
    output="$("$exe" --help 2>&1)" || fail "$exe --help exited non-zero: $output"
    grep -qi usage <<<"$output" || fail "$exe --help did not print usage"
    output="$("$exe" status --service-name com.hkdfguard.builddist.smoketest 2>&1)" \
        || fail "$exe status exited non-zero: $output"
    grep -q '^keychain: data-protection$' <<<"$output" \
        || fail "$exe does not run in data-protection keychain mode: $output"
}

# Resolves the Team ID and checks signing prerequisites up front, so a
# missing certificate fails in seconds rather than after the builds.
preflight_app() {
    # The hardware, not this shell: hw.optional.arm64 is 1 on Apple silicon
    # even under Rosetta, and does not exist on Intel. The arm64 smoke tests
    # below have to launch what was just built.
    [ "$(sysctl -n hw.optional.arm64 2>/dev/null || echo 0)" = 1 ] \
        || fail "build-dist.sh builds arm64 only and must run on an Apple silicon Mac"

    if [ -z "$TEAM_ID" ]; then
        TEAM_ID="$(xcodebuild -project "$ROOT/HkdfGuardNativeMacOS.xcodeproj" \
            -scheme "$APP_SCHEME" -configuration Release -showBuildSettings 2>/dev/null \
            | awk -F' = ' '/ DEVELOPMENT_TEAM /{print $2; exit}')"
    fi
    [ -n "$TEAM_ID" ] || fail "could not determine the Team ID; set HKDFGUARD_TEAM_ID"

    if [ "$APP_EXPORT" = "developer-id" ]; then
        local identities
        identities="$(security find-identity -v -p codesigning)"
        grep -q "\"Developer ID Application: .*($TEAM_ID)\"" <<<"$identities" || fail "$(cat <<EOF
no "Developer ID Application" certificate for team $TEAM_ID in your keychain.
Create one in Xcode > Settings > Accounts > (your team) > Manage Certificates
> + > Developer ID Application (requires the Account Holder role), or set
HKDFGUARD_APP_EXPORT=debugging to build a development-signed bundle for
testing on registered Macs only.
EOF
)"
    fi
}

preflight_app
build_arch arm64 osx-arm64
build_app

echo
echo "==> All builds and checks passed; installing into $DIST"
rm -rf "$DIST"
mv "$STAGE" "$DIST"
rm -rf "$WORK"
trap - EXIT

echo "==> Done:"
find "$DIST" -type f | sort | while read -r f; do
    printf '%-70s %s\n' "${f#"$ROOT"/}" "$(lipo -archs "$f" 2>/dev/null || echo '-')"
done
echo
cat "$DIST"/osx-arm64/SHA256SUMS
