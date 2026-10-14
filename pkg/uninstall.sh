#!/bin/sh
# Removes what the com.hkdfguard.native.v1 package installed:
#
#   /Library/Application Support/HkdfGuard/v1/
#   /usr/local/bin/hkdfguard-v1-initialize   (only if it is still our symlink)
#   the package receipt                      (pkgutil --forget)
#
# Usage: sudo "/Library/Application Support/HkdfGuard/v1/uninstall.sh"
#
# KEKs are NOT touched: they live in each user's keychain, not here. Retire
# any that should go *before* uninstalling, while the CLI still exists:
#   hkdfguard-v1-initialize retire --service-name <name> --fingerprint <hex>
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

[ "$(id -u)" -eq 0 ] || { echo "error: must run as root: sudo $0" >&2; exit 1; }

root_dir="/Library/Application Support/HkdfGuard"
cli="$root_dir/v1/hkdfguard-v1-initialize"
link="/usr/local/bin/hkdfguard-v1-initialize"

if [ -L "$link" ] && [ "$(readlink "$link")" = "$cli" ]; then
    rm -f "$link"
    echo "==> Removed $link"
fi

if [ -d "$root_dir/v1" ] && [ ! -L "$root_dir/v1" ]; then
    rm -rf "$root_dir/v1"
    echo "==> Removed $root_dir/v1"
fi
rmdir "$root_dir" 2>/dev/null || true

pkgutil --forget com.hkdfguard.native.v1 >/dev/null 2>&1 \
    && echo "==> Forgot package receipt com.hkdfguard.native.v1" || true
