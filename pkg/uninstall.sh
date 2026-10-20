#!/bin/sh
# Removes what the com.hkdfguard.native package installed:
#
#   /Library/Application Support/HkdfGuard/v1/
#   /usr/local/bin/hkdfguard   (only if it is still our symlink)
#   the package receipt                      (pkgutil --forget)
#
# Usage: sudo "/Library/Application Support/HkdfGuard/v1/uninstall.sh"
#
# KEKs are NOT touched: they live in each user's keychain, not here. Retire
# any that should go *before* uninstalling, while the CLI still exists:
#   hkdfguard retire --service-name <name> --fingerprint <hex>
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

[ "$(id -u)" -eq 0 ] || { echo "error: must run as root: sudo $0" >&2; exit 1; }

root_dir="/Library/Application Support/HkdfGuard"
cli="$root_dir/v1/hkdfguard"
link="/usr/local/bin/hkdfguard"

if [ -L "$link" ] && [ "$(readlink "$link")" = "$cli" ]; then
    rm -f "$link"
    echo "==> Removed $link"
fi

# Delete only through a real, root-owned HkdfGuard folder: were it a symlink
# or someone else's, `rm -rf .../v1` would resolve into wherever it pointed.
if [ -e "$root_dir" ] || [ -L "$root_dir" ]; then
    if [ -L "$root_dir" ] || [ ! -d "$root_dir" ] || [ "$(stat -f '%u' "$root_dir")" != 0 ]; then
        echo "error: $root_dir is not a root-owned folder; refusing to remove anything under it" >&2
        exit 1
    fi
    if [ -d "$root_dir/v1" ] && [ ! -L "$root_dir/v1" ]; then
        rm -rf "$root_dir/v1"
        echo "==> Removed $root_dir/v1"
    fi
    rmdir "$root_dir" 2>/dev/null || true
fi

pkgutil --forget com.hkdfguard.native >/dev/null 2>&1 \
    && echo "==> Forgot package receipt com.hkdfguard.native" || true
