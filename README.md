# hkdfguard-native-macos

Core key and key-material protection for macOS, for interop across the
HkdfGuard libraries. Sibling of `hkdfguard-native-linux` and the Windows
native library; the three share one payload format and one CLI contract.

`HkdfGuardNativeMacOS` wraps and unwraps 32-byte Data Encryption
Keys (DEKs) under a per-service Key Encryption Key (KEK) that lives in the
device's Secure Enclave, exposed as a plain C ABI so it can be called from
Swift, Objective-C, C/C++, or any language that can load a Mach-O dylib
(Python `ctypes`, Go `cgo`, .NET P/Invoke, Java JNA, …). A companion
command-line tool, `hkdfguard-v1-initialize`, provisions KEKs and wraps DEKs
for pipelines.

## What it does

Each calling application identifies itself with a **service name** (see
below). A service's KEK is a P-256 key-agreement key generated inside the
Secure Enclave; its private half never leaves the enclave and can only be
*used*, never extracted. What the library persists in the keychain is the
enclave's opaque, device-bound reference to that key.

Provisioning is explicit. `hkdfguard_create_kek` is the only function that
creates a KEK; every wrap/unwrap function requires one to already exist and
fails with `kekNotFound` (-10) otherwise. Nothing is ever created "on first
use".

To wrap a DEK:

1. Generate a fresh ephemeral P-256 key pair (discarded after the call).
2. ECDH between the ephemeral private key and the service's KEK public key.
3. Derive an AES-256 key via HKDF-SHA512, salted with the ephemeral public
   key and bound to the scheme label, both public keys, and the service.
4. AES-256-GCM-encrypt the DEK under a random nonce, with the service name
   and the KEK fingerprint as additional authenticated data.

Unwrapping reverses this, with the enclave performing its side of the ECDH.
Because each wrap uses a fresh ephemeral key *and* a fresh nonce, the
derived key is single-use — two wraps of the same DEK never produce the
same bytes — and a payload wrapped under one service can never be opened
under another.

## Wrapped payload format

Always exactly **156 bytes**:

```
[ 32-byte KEK fingerprint — SHA-256 of the KEK's public key ]
[ 64-byte ephemeral P-256 public key, raw x || y             ]
[ 12-byte AES-GCM nonce || 32-byte ciphertext || 16-byte tag ]
```

The fingerprint identifies *which* KEK a payload was wrapped under. On
unwrap it is compared to the current KEK's public key **before** any ECDH
or decryption is attempted, so "wrong or rotated KEK" is reported as
`fingerprintMismatch` (-16) rather than as a generic decryption failure.
It is also folded into the AES-GCM authenticated data, so tampering with it
fails the tag check as well.

There is no in-band format version. **A change of payload format is
signalled by adopting a new service name** (and therefore a new KEK).

## Service names

1–128 bytes, each an ASCII letter, digit, or `.` — typically reverse-DNS.
Matched **case-insensitively**: every entry point validates the name as
ASCII first and then lowercases it, and that lowercased form is what is
stored, looked up, and bound into the AES-GCM AAD and HKDF info. Validation
comes first on purpose: Unicode case-folding can map non-ASCII input onto
ASCII (KELVIN SIGN → `k`), so lowercasing first would let such names
through. Anything else (empty, over-length, any non-ASCII byte, `-`, `_`,
…) is `invalidServiceIdentifier` (-8). The rule is enforced on bytes,
identically in the library, the CLI, and the Linux and Windows tools.

## C ABI

Declared in
[`hkdfguard.h`](HkdfGuardNativeMacOS/hkdfguard.h)
(plain C; `extern "C"`-guarded; nullability-annotated). All pointers are
required — a NULL is reported, never dereferenced.

```c
int32_t hkdfguard_keychain_mode(int32_t* out_mode);          // 0 legacy, 1 data-protection
int32_t hkdfguard_kek_exists(const char* service, int32_t* out_exists);
int32_t hkdfguard_kek_fingerprint(const char* service, uint8_t* out, int32_t* out_len); // 32 bytes, public
int32_t hkdfguard_create_kek(const char* service);            // the only function that creates a KEK
int32_t hkdfguard_wrap_dek(const char* service, const uint8_t* dek, int32_t dek_len,
                           uint8_t* out, int32_t* out_len);
int32_t hkdfguard_unwrap_dek(const char* service, const uint8_t* wrapped, int32_t wrapped_len,
                             uint8_t* out, int32_t* out_len);
int32_t hkdfguard_generate_and_wrap_dek(const char* service, uint8_t* out, int32_t* out_len);
```

`*out_len` is the buffer capacity on entry and, on return, either the bytes
written or — on `outputBufferTooSmall` — the required size (156 for wrap,
32 for unwrap). Both wrap and unwrap check the capacity, and unwrap checks
`wrapped_len == 156`, **before** touching the keychain or the enclave, so a
sizing call costs nothing and a DEK is never decrypted for a caller who
cannot receive it.

### Status codes

| Value | Meaning |
|------:|---------|
| `0`   | success |
| `-1`  | `invalidInputLength` — `dek_len != 32`, `wrapped_len != 156`, or a NULL buffer/length pointer |
| `-2`  | `outputBufferTooSmall` — `*out_len` set to the required size |
| `-3`  | `keyUnavailable` — reserved, no longer returned |
| `-4`  | `publicKeyUnavailable` — reserved, never returned |
| `-5`  | `encryptionFailed` |
| `-6`  | `decryptionFailed` — AES-GCM authentication failed (altered payload, or wrapped for a different service under the same KEK) |
| `-7`  | `unexpectedOutputLength` |
| `-8`  | `invalidServiceIdentifier` |
| `-9`  | `enclaveUnavailable` — no Secure Enclave on this machine |
| `-10` | `kekNotFound` — no KEK for this service in this process's keychain mode; call `hkdfguard_create_kek` |
| `-11` | `kekCorrupted` — an item exists but can't be reconstructed into a key; never auto-replaced |
| `-12` | `accessControlCreationFailed` |
| `-13` | `keyGenerationFailed` — the enclave refused to generate a key |
| `-14` | `keychainWriteFailed` |
| `-15` | `kekVerificationFailed` — stored, but couldn't be reloaded immediately after |
| `-16` | `fingerprintMismatch` — payload was wrapped under a different KEK |
| `-17` | `keychainAccessDenied` — locked keychain / no UI session / ACL denial / declined prompt / missing entitlement. **A key likely exists**; don't create or delete anything |
| `-18` | `keychainReadFailed` |

## Keychain modes (hybrid)

The KEK's keychain item lives in one of two keychains, chosen once per
process from the process's **own code-signing entitlements** — never from
configuration:

| Mode | When | Where the item lives | Cross-process access |
|---|---|---|---|
| **data-protection** (1) | the process has a `keychain-access-groups` entitlement — on macOS that means a Team-signed **app bundle with an embedded provisioning profile** | the data-protection keychain, under the first listed access group | decided by securityd from the caller's signed identity: no prompts, no ACLs; any Team-signed bundle listing the same group shares it |
| **legacy** (0) | no such entitlement — a bare executable (the CLI as a plain Mach-O, a .NET/Python/Go host that `dlopen`s the dylib, the `xctest` agent) | the login keychain | login-keychain lock plus a per-item ACL keyed to the creating binary; other identities get an interactive prompt, or, headless, `-17` |

The two keychains are disjoint: **the process that provisions a service's
KEK and every process that unwraps under it must run in the same mode**, or
consumers see `kekNotFound`. `hkdfguard_keychain_mode` reports the mode and
the CLI prints it on every command. Both modes set
`kSecAttrSynchronizable = false`; iCloud Keychain never sees these items.

`kSecUseDataProtectionKeychain` is set explicitly for both modes —
`true` for data-protection, `false` for legacy — never omitted. On the
current SDK an omitted key can default to the data-protection keychain for
a process that also carries `keychain-access-groups`, which would silently
defeat this disjointness for any call made with `mode: .legacy` from inside
an entitled process. Covered by `dataProtectionModeStoresItemsOnlyInTheDataProtectionKeychain`
(see Tests), which asserts a data-protection item is invisible to an
explicit legacy-mode query from the same process.

## Access policy and headless use

Every KEK is created with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and
`privateKeyUsage` only — no user-presence or biometric requirement, so
using the key never triggers a Touch ID/password prompt. Consequences:

- The key can never leave this device; no backup or restore carries it.
- "Unlocked" means the login user's keybag. A LaunchDaemon or SSH session on
  a Mac with no unlocked GUI session may find the key unavailable
  (`keyGenerationFailed`/`decryptionFailed` from the enclave, or
  `keychainAccessDenied` from a locked keychain). Run headless consumers as
  a LaunchAgent in a logged-in session, or ensure the login keychain is
  unlocked.
- The protection boundary is *which processes may read the keychain item*
  (the keychain mode's job), not *a human approved this use*.
- **Everything runs as one macOS user.** Both keychains are per-user, so a
  KEK provisioned by one account is invisible to every other account —
  administrator or not. `provision`, `wrap`, and the application that
  unwraps must all run as the same user, in the same keychain mode. A
  different user gets `kekNotFound` (`-10`), and running `provision` there
  would silently create a second, unrelated KEK under the same name. `sudo`
  does not bridge users; it runs in a different keychain context. No
  administrator rights are needed for any of these operations.

The policy is fixed; there is no per-service override. The library has no
delete or rotate API — a service that needs a new KEK adopts a new service
name — and deletion exists only as the CLI's fingerprint-confirmed
`retire` command (below), so no process that merely loads the dylib gets a
one-call wipe.

### If a KEK is compromised

Retiring the KEK does not undo a compromise: assume anyone who could use it
has already unwrapped every DEK they could reach. Recover in this order:

1. `provision` a **new service name** and record its fingerprint.
2. Generate **new DEKs**, re-encrypt the data, and `wrap` them under the new
   service.
3. Only then `retire` the old service's KEK. Anything still wrapped under it
   becomes permanently unrecoverable.

A legacy-mode KEK item can come back if a backup of the login keychain
taken before retirement is restored onto the same Mac; account for backups
if the goal is a true crypto-shred.

## Command-line tool: `hkdfguard-v1-initialize`

Provisions, wraps, and retires KEKs for pipelines. Provisioning and
wrapping go through the C ABI above only; `retire` additionally deletes the
keychain item itself, since the library deliberately exports no delete.
Four commands:

```
hkdfguard-v1-initialize provision --service-name|-sn <name>

hkdfguard-v1-initialize status --service-name|-sn <name>

hkdfguard-v1-initialize wrap --key-file-path|-kf <path> \
                             --service-name|-sn <name> \
                             ( --dek-stdin | --dek-file <path> ) \
                             [--fingerprint|-fp <64 hex chars>] [--force|-f]

hkdfguard-v1-initialize retire --service-name|-sn <name> \
                               ( --fingerprint|-fp <64 hex chars> | --corrupt )
```

- **`provision`** creates the KEK for `<name>` if it doesn't exist. The only
  command that creates keys; idempotent (a second run reports "already
  exists" and exits 0). Prints the keychain mode it used and the KEK's
  **fingerprint** (SHA-256 of its public key) — record it. On "already
  exists", compare it with the recorded value: a mismatch means the KEK
  under that name is not the one you provisioned.
- **`status`** reports the keychain mode, whether a KEK exists for `<name>`
  (`present`, `absent`, or `corrupt`), and its fingerprint. Read-only: it
  never creates or deletes anything, so it is the safe way to check a
  service's KEK against its recorded fingerprint, or which keychain mode a
  build of the CLI runs in. Exits `0` when the keychain gave a definite
  answer and `1` when it could not (`-17`, `-18`, no enclave).
- **`retire`** deletes the KEK for `<name>`, but only if its current
  fingerprint equals `<hex>` exactly; a mismatch, a KEK that can't be read
  (`-17`, `-11`, `-18`), or no KEK at all deletes nothing. The only command
  that deletes keys, and the only supported way to remove a
  data-protection-mode KEK, which Keychain Access and `security` cannot see.
  It must run in the same keychain mode as the KEK (the bundled CLI for
  data-protection) and refuses if the library's mode and the executable's
  entitlements disagree. It deletes exactly one item: it lists every
  matching item and refuses if there is more than one (in legacy mode the
  search list can span several keychains), re-reads that item by its
  persistent reference, re-checks the fingerprint from the item's own stored
  blob, and deletes by that reference, so an item swapped in after the check
  cannot be the one removed. In **legacy** mode it can only delete an item
  the CLI binary itself created: the login keychain lets only an item's
  creator change or delete it, so a KEK that a `dlopen`/FFI host created
  through `hkdfguard_create_kek` is refused (`errSecInvalidOwnerEdit`,
  nothing deleted). Retire such a KEK from the creating application, or
  confirm its fingerprint with `status` and then remove it with
  `security delete-generic-password -s <name> -a kek-v1`; that command has
  no fingerprint check of its own, so run `status` first. See "If a KEK is
  compromised" above for when to retire at all.
- **`retire --corrupt`** removes an item the library reports as
  `kekCorrupted` (`-11`) — present but not reconstructable into a key, so
  it has no fingerprint to confirm. It deletes only when the status is
  exactly `-11`, and only after proving the Secure Enclave works in this
  session: it creates a throwaway, never-stored enclave key under the same
  access policy, reconstructs it from its data representation as the
  library does, and uses it once. Otherwise a healthy KEK that merely
  failed to load (locked session, SSH without a GUI login) could look
  corrupt and be deleted. A valid KEK, a missing one, or one the keychain
  won't let it read (`-17`, `-18`) is never deleted. Like `retire`, it
  acts on exactly one item, by persistent reference, after confirming that
  item's own blob is the unreconstructable one. Afterwards the service can
  be provisioned again. `--fingerprint` and `--corrupt` are mutually
  exclusive.
- **`wrap`** wraps the pipeline's existing 32-byte DEK — base64, read from
  **stdin** (`--dek-stdin`) or a **file** (`--dek-file`), exactly one of the
  two — under the already-provisioned KEK and writes the 156-byte payload to
  `<path>`. It never creates a KEK (an unprovisioned service is an error
  naming the `provision` command) and never generates a DEK. There is
  deliberately no `--dek <base64>` argument: an argv value is visible to
  every process via `ps` and lands in shell history. `--dek` and
  `--generate` are refused with an explanation.
  - *Input handling.* The DEK text is read into one fixed-size buffer of at
    most 1024 bytes (surrounding whitespace, including CRLF, is allowed;
    anything larger is refused before it is read in full), decoded in
    place, and zeroed on every exit path; it is never held as a string.
  - *Output file.* Created with POSIX `0600` permissions set at creation
    (owner read/write, nothing for anyone else), then the file and its
    directory entry are flushed to the storage device (`F_FULLFSYNC`)
    before `wrap` exits `0`, so a pipeline may safely discard its plaintext
    DEK at that point. On any failure after creation the partial file is
    removed. `0600` fits the one-user model (see "Everything runs as one
    macOS user" above): the user who wraps owns the file and is the same
    user whose application unwraps it. If a deploy step later copies or
    `chown`s the file to another account, that account must also be the one
    holding the KEK.
- **`wrap --fingerprint`** pins the KEK. `wrap` is the one operation that
  commits a secret to a KEK, so it always prints the fingerprint of the KEK
  the payload was actually sealed to (bytes 0–31 of the payload), and with
  `--fingerprint <hex>` it refuses to write the file unless that value
  equals the one recorded at `provision` time. Without the pin, a keychain
  item swapped for a different enclave key before the wrap would be noticed
  only at unwrap (`-16`), after the DEK had already been sealed to the wrong
  key. The check is made on the returned payload, not through a separate
  fingerprint call, so there is no window between "which KEK?" and "wrap
  under it". Use it in every scripted pipeline. ABI consumers get the same
  guarantee by comparing the first 32 bytes of the payload
  `hkdfguard_wrap_dek` returns against their recorded fingerprint before
  storing it.
- **`--force`** securely overwrites an existing `<path>` (eight alternating
  zero/random passes, streamed through one 1 MiB buffer so memory use does
  not grow with the file, each pass flushed with `F_FULLFSYNC`) before
  replacing it. A `--fingerprint` mismatch is detected before the overwrite
  starts, so the existing file is left intact. It only ever
  touches a **regular file with a single link**: a symlink at `<path>` is
  refused rather than followed (`O_NOFOLLOW` + `fstat`), and so is a file
  with more than one hard link, since overwriting it would also destroy
  whatever other file shares its contents. A FIFO, device, or directory is
  refused too.

Exit codes: `0` success, `1` runtime failure, `2` argument error (usage
printed). Nothing persistent is touched until every argument is validated.

The CLI ships in two builds of the same source, and the build decides the
keychain mode:

| Build | Keychain mode | Use it to |
|---|---|---|
| `hkdfguard-v1-initialize` (plain executable) | legacy | provision and wrap for consumers that run in legacy mode — any `dlopen`/FFI host |
| `hkdfguard-v1-initialize.app` (app bundle) | data-protection | provision, wrap, and retire for consumers that are Team-signed app bundles in the same `com.hkdfguard.keys` access group |

Run the bundled build by its executable inside the bundle; a symlink onto
your `PATH` works:

```sh
cp -R hkdfguard-v1-initialize.app /Applications/
ln -s /Applications/hkdfguard-v1-initialize.app/Contents/MacOS/hkdfguard-v1-initialize \
      /usr/local/bin/hkdfguard-v1-initialize-dp
hkdfguard-v1-initialize-dp status -sn com.example.ingest   # prints "keychain: data-protection"
```

Its access group is prefixed with the signing Team ID
(`<TeamID>.com.hkdfguard.keys`), so only apps signed by that same Team can
share the KEKs it provisions. An app signed by a different Team uses its own
group, and provisions either from inside that app through
`hkdfguard_create_kek`, or with a bundled CLI built from this source under
its own Team.

Example pipeline use:

```sh
hkdfguard-v1-initialize provision -sn com.example.ingest      # prints "fingerprint: <hex>" -- record it
printf '%s' "$DEK_B64" | hkdfguard-v1-initialize wrap -kf /etc/example/ingest.key -sn com.example.ingest \
    --dek-stdin -fp <recorded fingerprint>                     # refuses if the KEK is not that one

# Later, after migrating everything to a new service name:
hkdfguard-v1-initialize retire -sn com.example.ingest -fp <fingerprint printed by provision>
```

## Project layout

| Target / package | Product | Purpose |
|---|---|---|
| `HkdfGuardNativeMacOS` | `HkdfGuardNativeMacOS.framework` | Embed in a signed macOS app; carries the public header and an app-sandbox entitlement |
| `HkdfGuardNativeMacOSDylib` | `libhkdfguard_v1.dylib` | Flat shared library for `dlopen`-based FFI from arbitrary, often unsandboxed, host processes |
| `HkdfGuardNativeMacOSTests` | `.xctest` | Swift Testing suites for the C entry points and for the CLI as a real subprocess |
| `hkdfguard-v1-initialize/` | `hkdfguard-v1-initialize` | SwiftPM package for the CLI; links the dylib through its C ABI only. Bare Mach-O → legacy keychain mode |
| `hkdfguard-v1-initialize-app` | `hkdfguard-v1-initialize.app` | The same `main.swift` as an app bundle with the `com.hkdfguard.keys` access group in Release (`com.hkdfguard.tests.keys` in Debug/DebugHosted) and hardened runtime, embedding the dylib — the build of the CLI that runs in data-protection mode |
| `HkdfGuardNativeMacOSTestHost` | `HkdfGuardNativeMacOSTestHost.app` | Minimal entitled host app for the test bundle, so the suite can run in data-protection mode (see Tests) |

All library targets build from the single `HkdfGuardNativeMacOS.swift`.
Requires a **Swift 6.2+** toolchain (compile-time `#error` guard). The
dylib and both CLI builds target **macOS 13.0+**; the test bundle and test
host target 14.0; the framework target uses the SDK's recommended
deployment target.

Supporting scripts: `build-dist.sh` (release artifacts, below),
`install-user.sh` / `install-system.sh` (put a build at a fixed path on a
Mac for other applications to load; see
[Installing on a machine](#installing-on-a-machine)), and
`setup-hosted-test-kek.sh` (a one-time, per-developer provisioning of a
data-protection KEK in the test-only access group, under
`com.hkdfguard.fixture.hostedtests`; see Tests).

## Building

```sh
# Framework, embeddable in a signed app:
xcodebuild -project HkdfGuardNativeMacOS.xcodeproj \
  -scheme HkdfGuardNativeMacOS -configuration Release build

# Standalone dylib for FFI:
xcodebuild -project HkdfGuardNativeMacOS.xcodeproj \
  -target HkdfGuardNativeMacOSDylib -configuration Release build

# CLI (links against build/Release by default; override with HKDFGUARD_DYLIB_DIR):
swift build -c release --package-path hkdfguard-v1-initialize

# Tests (real Secure Enclave required — see Tests):
xcodebuild test -scheme HkdfGuardNativeMacOSTests
```

### Distribution: `build-dist.sh`

Builds everything a downstream consumer needs into `dist/osx-arm64/`
(dylib, header, CLI, `SHA256SUMS`), named for the .NET runtime identifier.
**arm64 (Apple silicon) is the only supported architecture**: there is no
Intel build, and the script refuses to run on an Intel Mac. It builds the
dylib and the CLI, rewrites the CLI's rpath to `@executable_path` so it finds the
dylib next to itself, signs both with the **hardened runtime and a secure
timestamp**, then verifies: strict signature check, runtime flag, timestamp,
`lipo` architecture, rpath, `@rpath` reference, and a `--help` launch smoke
test. Everything is assembled in a staging
directory and only moved into `dist/` once every check passes.

```sh
./build-dist.sh        # local testing only: "Apple Development", not notarized

HKDFGUARD_RELEASE=1 \
HKDFGUARD_SIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)" \
HKDFGUARD_NOTARY_PROFILE=hkdfguard-notary \
./build-dist.sh        # a release: Developer ID everywhere, everything notarized
```

**Only a Developer ID, notarized build can be released.** Gatekeeper rejects
a development-signed dylib or CLI on any Mac but your own, and blocks an
unnotarized one once it has been downloaded. That includes the bare CLI,
which is the tool operators provision KEKs with. `HKDFGUARD_RELEASE=1`
refuses to start unless the signing identity is Developer ID, the app is
exported as Developer ID, and a notary profile is set. Without it, the
script prints that the build is not a release.

The script then checks that the dylib and
the CLI are signed by the build's Team (library validation requires it) and,
for a Developer ID build, by a Developer ID certificate. With a notary
profile it notarizes both files, confirms that each file's cdhash is in
the ticket Apple issued (from `notarytool log`), and then requires
Gatekeeper to report `source=Notarized Developer ID` for each, assessing
both by their own signature (`spctl --assess --type open --context
context:primary-signature`; `--type execute` never reports a source for a
bare executable). A bare dylib or executable cannot
carry a stapled ticket, so Gatekeeper looks the ticket up online the first
time a downloaded copy runs. Nothing is modified on disk, so the
signatures and `SHA256SUMS` stay valid.

Developer ID also gives the CLI a stable keychain identity. In legacy mode a
KEK's access approval is bound to the signature of the binary that
provisioned it. A Developer ID binary is identified by its Team, so
renewing the certificate does not invalidate that approval. A
development-signed binary is tied to one certificate, so every renewal
re-prompts, and a KEK provisioned by a development-signed CLI prompts once
for the Developer ID CLI and cannot be `retire`d by it.

Needs network access (timestamp server). The hardened runtime matters: it
disables `DYLD_*` environment overrides (which can otherwise redirect which
dylib a process loads) and enforces library validation, so the CLI only
loads dylibs signed by the same Team or by Apple.

It also builds the bundled CLI into `dist/osx-arm64-app/hkdfguard-v1-initialize.app`
— an arm64 bundle with the dylib embedded. Xcode
archives and exports it, because only an export embeds the provisioning
profile that the `keychain-access-groups` entitlement requires. Before
anything reaches `dist/`, the script verifies:

- the signature, strictly and including the embedded dylib, with the
  hardened runtime;
- the Team ID on both the bundle and the embedded dylib (library validation
  only loads a same-Team dylib);
- that the executable and the embedded dylib are arm64;
- that the first `keychain-access-groups` entry is `<TeamID>.com.hkdfguard.keys`
  (the library stores KEKs under the first), and that the test-only
  `com.hkdfguard.tests.keys` group is absent;
- the embedded profile: issued for that Team, granting that group, and of
  the expected type;
- a read-only smoke test on this Mac: `--help` launches, and `status`
  reports `keychain: data-protection`.

`HKDFGUARD_APP_EXPORT` picks how the bundle is signed:

| Value | Signing | Runs on |
|---|---|---|
| `developer-id` | Developer ID, secure timestamp; default when `HKDFGUARD_SIGN_IDENTITY` is a Developer ID identity | any Mac, once notarized |
| `debugging` | development; the default otherwise | only Macs registered to your developer account |

**Credentials are never stored in the script or the repository.** Each
input only names something kept in your keychain or Xcode:

| Variable | What it names |
|---|---|
| `HKDFGUARD_SIGN_IDENTITY` | a signing certificate in your login keychain |
| `HKDFGUARD_TEAM_ID` | the Team to sign the bundle for (not secret; defaults to the project's `DEVELOPMENT_TEAM`) |
| `HKDFGUARD_ASC_KEY_PATH`, `HKDFGUARD_ASC_KEY_ID`, `HKDFGUARD_ASC_ISSUER_ID` | optional App Store Connect API key (path to the `.p8`, kept outside the repo) so `xcodebuild` can manage provisioning profiles without an Apple ID signed in to Xcode; otherwise it uses the account in Xcode → Settings → Accounts |
| `HKDFGUARD_NOTARY_PROFILE` | optional `notarytool` keychain profile; when set, the dylib and CLI are notarized and checked with Gatekeeper, and the bundle is notarized, stapled, and checked (Developer ID only) |
| `HKDFGUARD_RELEASE` | `1` for a release: refuses to run without a Developer ID identity, a Developer ID app export, and a notary profile |

One-time setup for a distributable build:

1. Create a **Developer ID Application** certificate: Xcode → Settings →
   Accounts → your team → Manage Certificates → + → Developer ID
   Application (Account Holder role required). Its private key stays in
   your login keychain.
2. Store notarization credentials in your keychain under a profile name:
   `xcrun notarytool store-credentials hkdfguard-notary`. It prompts for
   your Apple ID, Team ID, and an **app-specific password** (created at
   account.apple.com), or accepts an App Store Connect API key instead.

Then:

```sh
HKDFGUARD_SIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)" \
HKDFGUARD_NOTARY_PROFILE=hkdfguard-notary \
./build-dist.sh
```

The script checks for the Developer ID certificate before building
anything, so a missing one fails in seconds. The Developer ID provisioning
profile is created by `xcodebuild` during export (automatic signing,
`-allowProvisioningUpdates`); this path has not yet been run end to end,
since it needs the certificate above.

## Publishing a release

Distribution is a tagged GitHub Release carrying the `dist/` output as
assets — not a package published to PyPI/npm/Maven/NuGet. That keeps a
single, manually-signed artifact as the only thing every consumer trusts,
which matches how this project is built (no CI; a person runs
`build-dist.sh` and signs locally).

```sh
VERSION=v1.2.0

HKDFGUARD_RELEASE=1 \
HKDFGUARD_SIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)" \
HKDFGUARD_NOTARY_PROFILE=hkdfguard-notary \
./build-dist.sh

(cd dist/osx-arm64 && zip -r "../hkdfguard-native-macos-v1-$VERSION-osx-arm64.zip" .)
# ditto, not zip, for the app bundle: it preserves the bundle's signature.
ditto -c -k --keepParent dist/osx-arm64-app/hkdfguard-v1-initialize.app \
  "dist/hkdfguard-v1-initialize-$VERSION-osx-arm64.app.zip"

# Checksums of the release assets themselves, published in the release
# notes -- outside the assets, so replacing an asset cannot also replace
# the value it is checked against.
(cd dist && shasum -a 256 \
  "hkdfguard-native-macos-v1-$VERSION-osx-arm64.zip" \
  "hkdfguard-v1-initialize-$VERSION-osx-arm64.app.zip" > RELEASE-SHA256SUMS)
{
  echo "See README for the C ABI and per-language consumption notes."
  echo
  echo "SHA-256 of each asset (verify with \`shasum -a 256 -c\`):"
  echo '```'
  cat dist/RELEASE-SHA256SUMS
  echo '```'
} > dist/release-notes.md

git tag -s "$VERSION" -m "$VERSION"   # signed tag; -a if you have no signing key
git push origin "$VERSION"

gh release create "$VERSION" \
  dist/hkdfguard-native-macos-v1-$VERSION-osx-arm64.zip \
  "dist/hkdfguard-v1-initialize-$VERSION-osx-arm64.app.zip" \
  --title "$VERSION" \
  --notes-file dist/release-notes.md
```

Publish only a `HKDFGUARD_RELEASE=1` build. A development-signed or
unnotarized build runs only on your own Macs; elsewhere Gatekeeper blocks
the dylib, the CLI, and the bundle.

Each zip also contains its own `SHA256SUMS` (written by `build-dist.sh`).
That file detects corruption only: anyone able to replace a zip can replace
the `SHA256SUMS` inside it too. Integrity comes from the checksums in the
release notes, which live outside the assets. Consumers should check a
downloaded zip against those first, then its contents against the inner
`SHA256SUMS`. The app bundle is additionally covered by its own Developer ID
signature and notarization (`spctl --assess`). Confirm the tag before pushing it or
running `gh release create` — a release, unlike a local build, is visible
and hard to fully retract once someone has pulled it.

## Installing on a machine

Applications should load the dylib from a fixed, absolute path rather than
from their working directory or a search path, so nothing earlier on that
path can substitute a different library. Two scripts put a build at one of
two such paths:

| Script | Installs to | Owned by | Use it for |
|---|---|---|---|
| `install-user.sh` | `~/.hkdfguard/v1/` | the current user | a developer's own Mac |
| `sudo ./install-system.sh` | `/Library/Application Support/HkdfGuard/v1/` | root | shared, build, and team machines; MDM rollout |

Either one installs the four files of the `osx-arm64` build directly into
`v1/`:

```
v1/libhkdfguard_v1.dylib
v1/hkdfguard.h
v1/hkdfguard-v1-initialize
v1/SHA256SUMS
```

Both refuse to run on an Intel Mac. They check the hardware (`sysctl
hw.optional.arm64`), not the shell, so a script run under Rosetta still
installs. Consumers must run on a native arm64 runtime: an x64 .NET,
Python, or Java runtime under Rosetta cannot load the arm64 dylib.

### Pushing a build

From a local build, after `./build-dist.sh`:

```sh
./install-user.sh                 # installs dist/osx-arm64
sudo ./install-system.sh
```

From a published release, verify the zip against the release notes first
(see [Publishing a release](#publishing-a-release)), then point `--from` at
the extracted folder:

```sh
VERSION=v1.2.0
ZIP="hkdfguard-native-macos-v1-$VERSION-osx-arm64.zip"
gh release download "$VERSION" --pattern "$ZIP"
shasum -a 256 "$ZIP"              # must match the value in the release notes
mkdir hkdfguard-$VERSION && ditto -x -k "$ZIP" hkdfguard-$VERSION

sudo ./install-system.sh --from hkdfguard-$VERSION
```

`--from` accepts either a `build-dist.sh`-style folder holding `osx-arm64/`
or the extracted `osx-arm64` release folder itself.

For a fleet, have your MDM (Jamf, Intune, Kandji, ...) run
`install-system.sh --from <folder>` as root, with the release zip
extracted into `<folder>`, and scope the policy to Apple silicon Macs.

`install-system.sh` only installs binaries signed by the Team pinned in
the script (`PINNED_TEAM_ID`, which must match `DEVELOPMENT_TEAM` in the
Xcode project); a build signed by anyone else is refused. The pin lives in
the script rather than in the payload, so tampering with the files being
installed cannot change it. `--team-id <TEAMID>` overrides it, for a build
signed by a different team such as a fork.

To remove an install: `./install-user.sh --uninstall` or
`sudo ./install-system.sh --uninstall`.

### What the scripts check

Before anything at the destination changes, each script copies the files
into a staging folder next to `v1/` and verifies **the staged copy** — so a
file in the `--from` folder cannot be swapped between the check and the
install:

- `SHA256SUMS` lists exactly the three payload files, and they match it.
- The dylib and CLI are thin arm64 binaries.
- Both signatures verify (`codesign --verify --strict`) and carry a Team
  ID (not ad-hoc). `install-system.sh` requires that Team ID to be the
  pinned one (or `--team-id`); `install-user.sh` requires both to share
  one Team ID, and match `--team-id` when given.

Only then is the old `v1/` swapped out for the new one; a failed run leaves
an existing install untouched. Extended attributes, including quarantine,
are not copied, as with a `.pkg` installer: the checks above stand in for
Gatekeeper's.

Each script also refuses to install through a symlink, or under a folder
that the wrong owner or another user could write:

- `install-user.sh` refuses to run as root, takes the home folder from the
  directory service (`dscl`) rather than `$HOME`, and requires the home
  folder, `~/.hkdfguard`, and `v1/` to be owned by the user and not group-
  or world-writable. Files are mode 644, the CLI and folders 755.
- `install-system.sh` requires root, runs with a fixed `PATH`, and requires
  `/`, `/Library`, `/Library/Application Support`, `HkdfGuard/`, and
  everything it installs to be root-owned and writable only by root (files
  `root:wheel` 644, the CLI and folders 755). It warns when the binaries are
  not Developer ID signed.

`/Library/Application Support` is used rather than `/usr/local/lib`
because Homebrew on Intel Macs makes `/usr/local`'s subfolders writable by
a user; `/usr/lib` is protected by SIP; and `/Users/Shared` or `/tmp` are
writable by everyone.

A per-user install is only as trusted as that user's account: anything
running as the user can replace it. It is meant for development. Use the
system install anywhere the library protects production data.

### Loading the installed library

Consumers should look in the system location first and fall back to the
per-user one, so an administrator's install cannot be overridden by a
per-user copy:

1. `/Library/Application Support/HkdfGuard/v1/libhkdfguard_v1.dylib`
2. `<home>/.hkdfguard/v1/libhkdfguard_v1.dylib`, with `<home>` looked up
   from the user database (`getpwuid(getuid())`), not `$HOME`

Load the chosen file by its absolute path. Do not take extra search folders
from an environment variable or config file. A hardened consumer also
re-checks what the scripts enforce before loading: resolve the path with
`realpath` and confirm it is still one of the two above, then check that
every folder from the install root down and the dylib itself are owned by
root (system) or the current user (per-user) and not group- or
world-writable.

For C#, route the `DllImport` name to that path with a resolver, so the
existing `[DllImport("hkdfguard_v1")]` declarations stay unchanged:

```csharp
NativeLibrary.SetDllImportResolver(typeof(HkdfGuardInterop).Assembly, (name, assembly, searchPath) =>
    name == "hkdfguard_v1"
        ? NativeLibrary.Load(HkdfGuardInstall.ResolveVerifiedPath()) // system, then per-user; checks above
        : IntPtr.Zero);
```

Other languages load the same absolute path in place of the
`./libhkdfguard_v1.dylib` used in the examples below.

## Consuming this library

Every consumer needs three files from a release's zip:
`libhkdfguard_v1.dylib`, `hkdfguard.h` (for the
exact signatures — see [C ABI](#c-abi)), and, if provisioning from that
process, `hkdfguard-v1-initialize`. Before loading anything, check the
zip's SHA-256 against the value in the release notes, then the files inside
against the zip's own `SHA256SUMS` (see "Publishing a release").

A `dlopen`/FFI host in any of these languages runs in **legacy keychain
mode** (see [Keychain modes](#keychain-modes-hybrid)) unless the host
process is itself a Team-signed app bundle carrying the
`keychain-access-groups` entitlement — which a stock `python`, `node`,
`java`, or `dotnet` binary is not. In legacy mode its KEKs live in the login
keychain, gated by the login session being unlocked, not by an access group
shared with a signed app bundle.

**Legacy mode trusts the runtime, not your code.** The login keychain's ACL
identifies the *executable* that asks for the item. For an interpreted or
managed consumer that executable is the interpreter or runtime (`python3`,
`node`, `java`, `dotnet`), so the operator's "Always Allow" is granted to
that runtime as a whole. From then on, **any** script or program run by
that runtime, as that user, can unwrap every DEK under that service with no
prompt. For production, package the consumer as a Team-signed app bundle
entitled for the shared access group so it runs in data-protection mode,
where access is granted to your signed identity alone.

**Python** (`ctypes`, standard library):

```python
import ctypes

lib = ctypes.CDLL("./libhkdfguard_v1.dylib")
lib.hkdfguard_create_kek.argtypes = [ctypes.c_char_p]
lib.hkdfguard_create_kek.restype = ctypes.c_int32

status = lib.hkdfguard_create_kek(b"com.example.ingest")
```

**Node** (`koffi`):

```js
const koffi = require("koffi");
const lib = koffi.load("./libhkdfguard_v1.dylib");
const hkdfguard_create_kek = lib.func("int32_t hkdfguard_create_kek(const char *service)");

const status = hkdfguard_create_kek("com.example.ingest");
```

**Java** (JNA):

```java
public interface HkdfGuard extends Library {
    HkdfGuard INSTANCE = Native.load("./libhkdfguard_v1.dylib", HkdfGuard.class);
    int hkdfguard_create_kek(String service);
}

int status = HkdfGuard.INSTANCE.hkdfguard_create_kek("com.example.ingest");
```

**Go** (`cgo`, needs the header at build time):

```go
/*
#cgo LDFLAGS: -L${SRCDIR} -lhkdfguard_v1
#include "hkdfguard.h"
*/
import "C"

status := C.hkdfguard_create_kek(C.CString("com.example.ingest"))
```

(A `cgo`-free option exists too: [`purego`](https://github.com/ebitengine/purego)
`dlopen`s the dylib and calls it by symbol name, like the other
non-`cgo` bindings above.)

**C#** (P/Invoke):

```csharp
[DllImport("hkdfguard_v1", CallingConvention = CallingConvention.Cdecl)]
static extern int hkdfguard_create_kek(string service);

int status = hkdfguard_create_kek("com.example.ingest");
```

`hkdfguard_v1` is the platform-neutral library name: .NET resolves it to
`libhkdfguard_v1.dylib` here by adding the platform's `lib` prefix and
extension, so the same `DllImport` works wherever the library follows the
standard naming.

The `dist/osx-arm64` folder name is already a .NET runtime identifier, so a
C# consumer can drop it straight into a NuGet package's
`runtimes/{rid}/native/` layout instead of loading the zip by hand.

## Signing and entitlements

- The **framework** target has `com.apple.security.app-sandbox`. It does not
  declare `keychain-access-groups`: that capability is enforced against a
  process's main executable, not the frameworks it loads. It belongs on the
  app that embeds the framework.
- The **dylib** target has no entitlements, on purpose: it loads into
  arbitrary host processes.
- The **bundled CLI** has two entitlement files: the Release build (what
  `build-dist.sh` ships) carries the production `com.hkdfguard.keys` group;
  Debug and DebugHosted carry the test-only `com.hkdfguard.tests.keys`
  group. The **test host** carries only the test group, and has no hardened
  runtime (see Tests).
- **Data-protection mode** requires the *consuming process* to be a
  Team-signed app bundle with an embedded provisioning profile carrying
  `keychain-access-groups` (Xcode: Signing & Capabilities → Keychain
  Sharing). A bare executable cannot carry that entitlement — AMFI kills it
  at launch — which is why bare consumers run in legacy mode.
- The project carries a specific `DEVELOPMENT_TEAM` and bundle identifiers;
  replace them with your own before building under your account.

## Concurrency

- `hkdfguard_create_kek` is safe under concurrent first use: the keychain's
  unique index on (service, account) lets exactly one creation win and the
  others load the winner's key.
- The Secure Enclave / `securityd` IPC layer has limited real concurrency.
  A handful of simultaneous enclave operations from one process is fine;
  dozens cause severe contention (observed while building the test suite,
  which runs serialized for that reason).

## Tests

Two Swift Testing suites, both `.serialized`:

- **`HkdfGuardNativeMacOSWrapUnwrapTests`** exercises every C entry
  point in-process: provisioning, idempotence and the first-use race,
  service-name rules (ASCII bytes, case-insensitivity, length), round trips,
  payload length, nonce/ephemeral uniqueness, per-service isolation,
  fingerprint and ciphertext tamper detection, buffer sizing before any
  enclave work, NULL-pointer handling, corrupt-item reporting, and the
  keychain-mode decision (including that data-protection mode from an
  unentitled process is reported as `-17`, never as "no key").
- **`HkdfGuardCommandLineToolTests`** builds and runs the real CLI as a
  subprocess: `provision`/`wrap`/`status`/`retire` semantics, DEK sources
  and their bounds (whitespace, oversized, non-ASCII, missing file),
  rejected arguments, `wrap --fingerprint` (match, mismatch leaves an
  existing file untouched, malformed), `retire` by fingerprint and
  `--corrupt`, `--force` symlink/hard-link/FIFO refusal and the chunked
  overwrite of a multi-megabyte file, file permissions, exit codes, and —
  hosted — the bundled CLI's data-protection provision/wrap/retire with
  this host unwrapping.

The library suite needs a real Secure Enclave and is skipped as a whole on
CI/VM runners; in the CLI suite only the tests that reach the enclave are
skipped there, so its argument-handling tests still run. Every test that
provisions a key deletes its keychain item afterward — in whichever keychain
the host process's mode uses — so a run leaves the keychain clean. No test
reads the persistent fixture KEK that `setup-hosted-test-kek.sh`
provisions; it exists for ad-hoc experiments in the hosted configuration.

### Two ways to run the suite

**Unhosted (legacy mode) — the default.** `xcodebuild test -scheme
HkdfGuardNativeMacOSTests` runs the bundle in the plain `xctest`
agent, which has no keychain entitlement, so the library runs in legacy mode
and the data-protection-only tests are skipped. Needs no provisioning
profile. The legacy cross-process round trips (this process reading an item
the bare CLI created) trigger a one-time interactive keychain prompt and are
opt-in. From the command line, `xcodebuild` only forwards variables with a
`TEST_RUNNER_` prefix to the test process, so run
`TEST_RUNNER_HKDFGUARD_RUN_INTERACTIVE_KEYCHAIN_TESTS=1 xcodebuild test -scheme
HkdfGuardNativeMacOSTests` (a bare `HKDFGUARD_RUN_INTERACTIVE_KEYCHAIN_TESTS=1`
is silently dropped and the tests stay skipped). In Xcode, enable the
pre-defined but disabled `HKDFGUARD_RUN_INTERACTIVE_KEYCHAIN_TESTS` variable
in the scheme's Test action. Be present to click Allow.

**Hosted (data-protection mode).** `xcodebuild test -scheme
HkdfGuardNativeMacOSTests-Hosted -allowProvisioningUpdates` uses
the `DebugHosted` configuration, which sets `TEST_HOST` to
`HkdfGuardNativeMacOSTestHost.app` — a Team-signed app entitled for the
**test-only** `com.hkdfguard.tests.keys` access group — so the whole suite
runs in data-protection mode, and additionally builds the bundled CLI
(`hkdfguard-v1-initialize.app`, same test group). That enables the test
that matters most: the bundled CLI provisions a KEK and wraps a DEK, and
this differently-signed host unwraps it through the library **with no
interactive prompt** — the production topology, with access granted by
securityd from the two signed identities alone.

The test host runs without the hardened runtime, because Xcode's test
injection relies on `DYLD_*` variables, so any code can be injected into it.
That is why it never gets the production group. The bundled CLI uses the
test group in its Debug and DebugHosted builds and the production
`com.hkdfguard.keys` group only in Release, the configuration `build-dist.sh`
ships. `build-dist.sh` fails if a shipped bundle carries the test group, and
`setup-hosted-test-kek.sh` refuses `--configuration Release`. KEKs in the two
groups are disjoint: a fixture provisioned for tests is invisible to
production builds, and the reverse.

Last full pass: **84 tests, both suites, no failures**, on real Secure
Enclave hardware, in each of three runs:

- unhosted (legacy mode): nine skipped by design — the four
  data-protection-only tests and the five interactive legacy tests;
- hosted (data-protection mode, test group): including
  `dataProtectionModeStoresItemsOnlyInTheDataProtectionKeychain`,
  `bundledCliProvisionsAndWrapsInDataProtectionModeAndEntitledHostUnwraps`
  (the end-to-end cross-process round trip), `bundledCliRetiresDataProtectionKek`,
  and `bundledCliRetiresCorruptDataProtectionItem`; six skipped — the five
  interactive legacy tests (legacy-only by construction) and the one test
  that only makes sense in an unentitled host;
- unhosted with the interactive opt-in: only the four data-protection
  tests skipped; all five legacy cross-process tests ran (including `cliRetireCorruptDeletesOnlyACorruptItem`, which plants a
  corrupt item from another process). The first of them waited on the
  keychain prompt; once approved, the rest completed in seconds.

Every test that provisions a key is paired with a `defer` that deletes it,
so a failing assertion still leaves the keychain clean; this was confirmed
by inspecting the login keychain after the runs.

The CLI suite runs an incremental build of the dylib and the CLI once per
test run, so it always tests the current source rather than whatever
binary happens to be on disk.

Both app targets need a **Mac App Development provisioning profile**, which
Xcode's automatic signing creates once this Mac is registered as a device in
your developer account (Certificates, Identifiers & Profiles → Devices →
macOS, using the Provisioning UDID from *About This Mac → System Report →
Hardware*; or open the project in Xcode, select `HkdfGuardNativeMacOSTestHost`, and let
Signing & Capabilities register it). Until then the hosted scheme fails at
provisioning and the unhosted scheme is unaffected.

## Differences from the Linux tool

Deliberate divergences from `hkdfguard-v1-initialize.rs`: separate
`provision`, `wrap`, and `retire` commands; the key file path is
`--key-file-path`, not positional; no `--dek <base64>` argument (stdin or
file only); output file permissions `0600`; `wrap` prints the KEK
fingerprint it used and accepts `--fingerprint` to pin it.
