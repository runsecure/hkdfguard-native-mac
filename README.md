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
int32_t hkdfguard_open_file(const char* path, uint8_t* out, int32_t* out_len); // reads a 156-byte payload file
```

`*out_len` is the buffer capacity on entry and, on return, either the bytes
written or — on `outputBufferTooSmall` — the required size (156 for wrap,
32 for unwrap). Both wrap and unwrap check the capacity, and unwrap checks
`wrapped_len == 156`, **before** touching the keychain or the enclave, so a
sizing call costs nothing and a DEK is never decrypted for a caller who
cannot receive it.

### Reading a wrapped key file: `hkdfguard_open_file`

Reads the 156-byte payload that the CLI's `wrap` writes, validates it, and
copies it to `out`, ready for `hkdfguard_unwrap_dek`. It never touches the
keychain or the Secure Enclave and never unwraps, so the plaintext DEK does
not pass through it:

```c
uint8_t wrapped[156];
int32_t wrapped_len = sizeof wrapped;
int32_t status = hkdfguard_open_file("/etc/example/ingest.key", wrapped, &wrapped_len);
if (status == 0)
    status = hkdfguard_unwrap_dek("com.example.ingest", wrapped, wrapped_len, dek, &dek_len);
```

`*out_len` is the capacity on entry (at least 156) and is always written:
156 — the bytes read — on success, 156 on `outputBufferTooSmall` (checked
before the file is opened), and 0 on every other failure. `out` is written
only on success.

- **Safe opening.** The path must name a regular file. A symbolic link as
  its last component is refused, not followed (`O_NOFOLLOW`); symlinks in
  directory components resolve as usual, so `/etc/...` works. A FIFO,
  socket, directory, or device is refused without blocking. Every check is
  made on the opened descriptor (`fstat`), so it describes the file that is
  actually read. At most 157 bytes are read, and a file larger than a
  payload is rejected from its size before any read.
- **Ownership.** The file must be owned by the process's effective user
  **or by root**, writable by no one but its owner, and have a single hard
  link, or it is `fileInsecure` (-27). The CLI's `wrap` output (0600, one
  link) always passes. Root is accepted so an administrator or MDM can
  deploy key files that a service account reads; root can already alter
  anything on the machine, so this adds no new party who could tamper with
  the file. A file owned by any *other* user is refused, because that user
  could swap in a different payload or hard-link an older one into place,
  and that would otherwise be a silent rollback rather than a loud error.
  Group- or world-*readable* is allowed, since the payload is ciphertext. A
  root-owned file must still be readable by the reading account: `0644`, or
  `0640` with a group the account belongs to. Otherwise it is
  `fileAccessDenied` (-20).
- **Pass a trusted, absolute path.** The function opens what it is told.
  Don't hand it paths from untrusted input (its status codes say whether a
  file exists, is readable, and its size class — a small oracle if a
  privileged process is pointed at arbitrary files), and don't use relative
  paths, which resolve against a working directory the caller may not
  control. Keep the file in a directory only its owner can write.
- **Length.** Anything other than exactly 156 bytes is `fileTooShort`
  (-23) or `fileTooLong` (-24).
- **Unprotected key.** A file holding a bare 32-byte DEK instead of a
  payload — raw bytes, or base64 (padded or not, standard or URL alphabet)
  or hex text, with optional surrounding whitespace — is reported as
  `fileUnprotectedKey` (-26), not merely as too short. The key was stored
  unprotected: treat it as exposed and rotate it, rather than wrapping it
  now. Its bytes never reach the caller's buffer, and the library zeroes
  its own read buffer on every return.
- **Malformed.** A 156-byte file whose ephemeral public key is not a valid
  P-256 point, or whose KEK fingerprint is all zeros, is `fileMalformed`
  (-25). These are structural checks only: whether the payload is genuine,
  unaltered, and for this service is decided by `hkdfguard_unwrap_dek`
  (`-16`, `-6`). Reading the file proves nothing about it — pin the KEK by
  comparing bytes 0–31 with the recorded fingerprint before unwrapping, as
  with any payload.

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
| `-19` | `fileNotFound` — no file at the path, or a path component is not a directory (`hkdfguard_open_file` only, as are `-20` to `-26`) |
| `-20` | `fileAccessDenied` — this process may not read the file or a directory on its path |
| `-21` | `fileNotRegular` — a symbolic link (refused, never followed), directory, FIFO, socket, or device |
| `-22` | `fileReadFailed` — `open`/`fstat`/`read` failed for any other reason |
| `-23` | `fileTooShort` — fewer than 156 bytes, and not a plaintext DEK |
| `-24` | `fileTooLong` — more than 156 bytes |
| `-25` | `fileMalformed` — 156 bytes, but the ephemeral key is not a P-256 point or the fingerprint is all zeros |
| `-26` | `fileUnprotectedKey` — the file appears to hold a bare, unwrapped DEK (any 32-byte value as raw/base64/hex matches). **Treat the key as exposed** and rotate it |
| `-27` | `fileInsecure` — owned by someone other than this user or root, writable by group or others, or more than one hard link |

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

The installer package installs both (see
[Installing on a machine](#installing-on-a-machine)). The legacy-mode CLI is
on `PATH` as `/usr/local/bin/hkdfguard-v1-initialize`; run the
data-protection build by the executable inside its bundle:

```sh
"/Library/Application Support/HkdfGuard/v1/hkdfguard-v1-initialize.app/Contents/MacOS/hkdfguard-v1-initialize" \
    status -sn com.example.ingest   # prints "keychain: data-protection"
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

Supporting scripts: `build-dist.sh` (signed, notarized build artifacts,
below), `build-pkg.sh` with `pkg/` (the installer package — the only way the
library is installed; see [Installing on a machine](#installing-on-a-machine)),
and `setup-hosted-test-kek.sh` (a one-time, per-developer provisioning of a
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

Builds the signed artifacts the installer package is made from (see
[`build-pkg.sh`](#the-installer-package-build-pkgsh)) into `dist/osx-arm64/`
(dylib, header, CLI, `SHA256SUMS`) and `dist/osx-arm64-app/` (the
data-protection CLI app).
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
`-allowProvisioningUpdates`).

## Publishing a release

The only distribution is a signed, notarized **installer package** attached
to a tagged GitHub Release. There are no zips, no NuGet package, and no
install scripts: a Mac gets the library by installing the package, and
nothing else puts it in place. That keeps one manually signed artifact —
built by a person on one Mac, with no CI — as the only thing every machine
trusts.

```sh
VERSION=v0.9.0   # must equal MARKETING_VERSION in the Xcode project

HKDFGUARD_RELEASE=1 \
HKDFGUARD_SIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)" \
HKDFGUARD_NOTARY_PROFILE=hkdfguard-notary \
./build-dist.sh

HKDFGUARD_NOTARY_PROFILE=hkdfguard-notary ./build-pkg.sh
PKG="hkdfguard-native-macos-v1-${VERSION#v}-osx-arm64.pkg"

# The checksum goes in the release notes -- outside the asset, so replacing
# the package cannot also replace the value it is checked against.
{
  echo "Install with: sudo installer -pkg $PKG -target /"
  echo
  echo "SHA-256 (verify with \`shasum -a 256 -c\`):"
  echo '```'
  cat "dist/$PKG.sha256"
  echo '```'
} > dist/release-notes.md

git tag -s "$VERSION" -m "$VERSION"   # signed tag; -a if you have no signing key
git push origin "$VERSION"

gh release create "$VERSION" "dist/$PKG" \
  --title "$VERSION" \
  --notes-file dist/release-notes.md
```

`build-pkg.sh` refuses anything but a `HKDFGUARD_RELEASE=1` build. Beyond
the checksum, every machine checks the package's own Developer ID Installer
signature and stapled notarization ticket when it installs. Confirm the tag
before pushing it or running `gh release create` — a release, unlike a
local build, is visible and hard to fully retract once someone has pulled
it.

### The installer package: `build-pkg.sh`

Builds `dist/hkdfguard-native-macos-v1-<version>-osx-arm64.pkg` and its
`.sha256` from `build-dist.sh`'s output. The version is the app's
`CFBundleShortVersionString`, i.e. `MARKETING_VERSION` in the Xcode project —
the one place it is set.

Signing a package needs a **Developer ID Installer** certificate, separate
from the Developer ID Application certificate that signs the code: Xcode →
Settings → Accounts → your team → Manage Certificates → **+** → Developer ID
Installer (Account Holder role). Check with `security find-identity -v`
(without `-p codesigning`, which hides installer identities). Notarization
uses the same `notarytool` profile as `build-dist.sh`.

Before anything reaches `dist/`, the script checks:

- **its input**: the dylib, CLI, and app Developer ID signed by the
  project's Team, arm64, matching `SHA256SUMS`; the bare dylib and CLI
  notarized (checked against Apple's ticket service, like `build-dist.sh`);
  the app stapled;
- **the package**: signed with Developer ID Installer by that Team,
  timestamped, notarized, stapled, and accepted by Gatekeeper
  (`spctl --assess --type install`);
- **its contents**: exactly the expected files, byte-for-byte identical to
  `dist/`, the app's signature intact, every entry `root:wheel` and writable
  only by its owner, the CLI `0755`, the `postinstall` script present, and
  the arm64 restriction in the distribution.

The app bundle is marked non-relocatable. Without that, Installer looks for
another copy of the same bundle ID anywhere on disk — the one in `dist/`, a
download folder — and "upgrades" that copy in place instead of installing
to the target path.

| Variable | Meaning |
|---|---|
| `HKDFGUARD_NOTARY_PROFILE` | required: the `notarytool` keychain profile |
| `HKDFGUARD_PKG_VERSION` | optional: must equal the built app's version if given |
| `HKDFGUARD_INSTALLER_IDENTITY` | optional: defaults to the "Developer ID Installer" identity for the project's Team |
| `HKDFGUARD_TEAM_ID` | optional: defaults to the project's `DEVELOPMENT_TEAM` |
| `HKDFGUARD_PKG_UNSIGNED` | `1` for a local layout test only: no signing or notarization, output named `-UNSIGNED`; Gatekeeper and MDM tools refuse it |

## Installing on a machine

The installer package is the **only** supported way to install the library.
It installs, all `root:wheel`, into
`/Library/Application Support/HkdfGuard/v1/`:

```
libhkdfguard_v1.dylib          0644   the library
hkdfguard.h                    0644   its C header
hkdfguard-v1-initialize        0755   the CLI, legacy keychain mode
hkdfguard-v1-initialize.app           the CLI, data-protection keychain mode
SHA256SUMS                     0644   checksums of the first three
uninstall.sh                   0755   removes all of it
```

and a root-owned symlink `/usr/local/bin/hkdfguard-v1-initialize` → the
legacy-mode CLI. It installs only on **Apple silicon** running **macOS 13 or
later**, only to a system volume (never a user's home folder), with no
customization. Consumers must run on a native arm64 runtime: an x64 .NET,
Python, or Java runtime under Rosetta cannot load the arm64 dylib.

### Installing

Check the package against the release notes, then install it:

```sh
VERSION=v0.9.0
PKG="hkdfguard-native-macos-v1-${VERSION#v}-osx-arm64.pkg"
gh release download "$VERSION" --pattern "$PKG"
shasum -a 256 "$PKG"                      # must match the release notes
pkgutil --check-signature "$PKG"          # Developer ID Installer: <Name> (<TEAMID>); notarized
sudo installer -pkg "$PKG" -target /
pkgutil --pkg-info com.hkdfguard.native.v1   # the receipt, with the installed version
```

Double-clicking the package in Finder works too. For a fleet, upload the
package to your MDM (Jamf, Intune, Kandji, …) and scope the policy to Apple
silicon Macs; MDM tools verify the Developer ID Installer signature
themselves. Installing a newer package over an older one upgrades `v1/` in
place.

### The `PATH` symlink

The package's `postinstall` script creates
`/usr/local/bin/hkdfguard-v1-initialize`, rather than shipping it in the
payload: a payload containing `/usr/local/bin` would let Installer reset the
owner and mode of a folder that already exists (Homebrew on Intel Macs owns
it). The script creates `/usr/local` and `/usr/local/bin` only if missing
(`root:wheel 0755`), never changes an existing folder, never overwrites a
real file at that path, and never fails the install. It logs what it did
to `/var/log/install.log` — including a warning when `/usr/local/bin` is
writable by anyone but root, because then anyone who can write it can
replace the symlink with their own program. In that case, call the CLI by
its full path when provisioning keys. The data-protection build is not on
`PATH`; call it by its full path (see the CLI section above).

### Uninstalling

```sh
sudo "/Library/Application Support/HkdfGuard/v1/uninstall.sh"
```

Removes `v1/`, the `PATH` symlink (only if it still points at this CLI), and
the package receipt. **KEKs are not touched**: they live in each user's
keychain, not in the install folder. Retire any that should go *before*
uninstalling, while the CLI still exists (see `retire` above).

### Why this location

Every folder from `/` down to `/Library/Application Support` is owned by
root and writable only by root, so no other user can substitute a library or
a folder above it. It is outside SIP, so a package can write it, and it is
Apple's documented place for machine-wide support files.
`/usr/local/lib` is avoided because Homebrew on Intel Macs makes
`/usr/local`'s subfolders writable by a user; `/usr/lib` is protected by
SIP; `/Users/Shared` and `/tmp` are writable by everyone.

### Loading the installed library

There is exactly one place to load the library from:

```
/Library/Application Support/HkdfGuard/v1/libhkdfguard_v1.dylib
```

Load it by that absolute path. Do not search other folders, and do not take
a path or search folder from an environment variable or config file. A
hardened consumer also re-checks what the package guarantees before loading:
resolve the path with `realpath` and confirm it is still exactly the path
above, then check that every folder from `/` down and the dylib itself are
owned by root and not group- or world-writable. It can also verify the
dylib's code signature against the expected Team ID
(`SecStaticCodeCreateWithPath` + `SecStaticCodeCheckValidity`): a `dotnet`,
`python`, or `java` host has no library validation of its own.

For C#, route the `DllImport` name to that path with a resolver, so the
existing `[DllImport("hkdfguard_v1")]` declarations stay unchanged:

```csharp
NativeLibrary.SetDllImportResolver(typeof(HkdfGuardInterop).Assembly, (name, assembly, searchPath) =>
    name == "hkdfguard_v1"
        ? NativeLibrary.Load(HkdfGuardInstall.ResolveVerifiedPath()) // the fixed path; checks above
        : IntPtr.Zero);
```

Other languages load the same absolute path in place of the
`./libhkdfguard_v1.dylib` used in the examples below.

## Consuming this library

Every consumer uses the files the installer package puts in
`/Library/Application Support/HkdfGuard/v1/`: `libhkdfguard_v1.dylib`,
loaded by that absolute path (see
[Loading the installed library](#loading-the-installed-library));
`hkdfguard.h`, for the exact signatures (see [C ABI](#c-abi)); and, for
provisioning, the `hkdfguard-v1-initialize` CLI.

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

Three Swift Testing suites:

- **`HkdfGuardNativeMacOSWrapUnwrapTests`** (`.serialized`) exercises
  every C entry point in-process: provisioning, idempotence and the first-use race,
  service-name rules (ASCII bytes, case-insensitivity, length), round trips,
  payload length, nonce/ephemeral uniqueness, per-service isolation,
  fingerprint and ciphertext tamper detection, buffer sizing before any
  enclave work, NULL-pointer handling, corrupt-item reporting, and the
  keychain-mode decision (including that data-protection mode from an
  unentitled process is reported as `-17`, never as "no key"), and a
  wrap → write file → `hkdfguard_open_file` → unwrap round trip.
- **`HkdfGuardOpenFileTests`** covers `hkdfguard_open_file` without the
  enclave: exact-length success, too short/too long, plaintext DEKs in
  every accepted encoding (`-26`, never copied out) versus short text that
  is not a key, malformed payloads (off-curve ephemeral key, zero
  fingerprint), missing and unreadable files, symlink/directory/FIFO
  refusal, ownership rules (group/world-writable and multiply-linked files
  refused; 0600/0644/0400 and root-owned files accepted), buffer sizing
  before the file is
  opened, and NULL pointers.
- **`HkdfGuardCommandLineToolTests`** (`.serialized`) builds and runs the real CLI as a
  subprocess: `provision`/`wrap`/`status`/`retire` semantics, DEK sources
  and their bounds (whitespace, oversized, non-ASCII, missing file),
  rejected arguments, `wrap --fingerprint` (match, mismatch leaves an
  existing file untouched, malformed), `retire` by fingerprint and
  `--corrupt`, `--force` symlink/hard-link/FIFO refusal and the chunked
  overwrite of a multi-megabyte file, file permissions, exit codes, and —
  hosted — the bundled CLI's data-protection provision/wrap/retire with
  this host unwrapping.

The wrap/unwrap suite needs a real Secure Enclave and is skipped as a whole on
CI/VM runners; `HkdfGuardOpenFileTests` runs everywhere; in the CLI suite only the tests that reach the enclave are
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
