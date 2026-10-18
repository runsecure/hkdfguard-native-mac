# hkdfguard-native-macos

Core key and key-material protection for macOS. Sibling of
`hkdfguard-native-linux` and the Windows native library: the three share
the C ABI, the status codes, the service-name rules, and the CLI contract,
so one consumer and one pipeline work on every platform. They do **not**
share payload bytes, and nothing requires them to: a KEK is bound to the
Secure Enclave of the machine that created it and never leaves it, so a
wrapped key file is only ever read on the machine that wrote it. The macOS
payload is HPKE (RFC 9180), described below.

`HkdfGuardNativeMacOS` wraps and unwraps 32-byte Data Encryption
Keys (DEKs) under a per-service Key Encryption Key (KEK) that lives in the
device's Secure Enclave, exposed as a plain C ABI so it can be called from
Swift, Objective-C, C/C++, or any language that can load a Mach-O dylib
(Python `ctypes`, Go `cgo`, .NET P/Invoke, Java JNA, …). A companion
command-line tool, `hkdfguard`, provisions KEKs and wraps DEKs
for pipelines.

## What it does

Each calling application identifies itself with a **service name** (see
below). A service's KEK is a P-256 key-agreement key generated inside the
Secure Enclave; its private half never leaves the enclave and can only be
*used*, never extracted. What the library persists in the keychain is the
enclave's opaque, device-bound reference to that key.

Provisioning is explicit. `hkdfguard_create_kek` is the only function that
creates a KEK; every wrap/unwrap function requires one to already exist and
fails with `kekNotFound` (-17) otherwise. Nothing is ever created "on first
use".

Wrapping is **HPKE** (RFC 9180, base mode) with the ciphersuite
DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM, as implemented by
CryptoKit:

1. HPKE generates a fresh ephemeral P-256 key pair and encapsulates a shared
   secret to the service's KEK public key (discarding the ephemeral private
   key after the call).
2. The HPKE key schedule derives the AEAD key and nonce from that secret and
   an `info` string of the scheme label and the service name
   (`com.hkdfguard.hpke.v1` ‖ `0x00` ‖ service).
3. AES-256-GCM seals the DEK, with the payload header — KEK fingerprint ‖
   suite id — as additional authenticated data.

Unwrapping reverses this, with the Secure Enclave performing its side of the
key agreement. Each wrap uses a fresh ephemeral key, so the derived key is
single-use — two wraps of the same DEK never produce the same bytes — and a
payload wrapped for one service can never be opened under another. The
library holds no KDF or nonce handling of its own; the construction is the
RFC's as implemented by CryptoKit. (RFC 9180's Appendix A publishes vectors
for DHKEM(P-256) with AES-128-GCM and for AES-256-GCM with P-521, but not
for this exact P-256 + AES-256-GCM suite; the suite's security rests on the
RFC's analysis and Apple's implementation, not on a vector check here.)

## Wrapped payload format

Always exactly **146 bytes**:

```
[ 32-byte KEK fingerprint — SHA-256 of the KEK's public key          ]
[  1-byte ciphersuite id — 0x01                                       ]
[ 65-byte HPKE encapsulated key — X9.63 P-256 point, 0x04 || x || y   ]
[ 32-byte AES-256-GCM ciphertext || 16-byte tag                       ]
```

The fingerprint identifies *which* KEK a payload was wrapped under. On
unwrap it is compared to the current KEK's public key **before** any key
agreement or decryption is attempted, so "wrong or rotated KEK" is reported
as `fingerprintMismatch` (-16) rather than as a generic decryption failure.
It is also in the AEAD's additional authenticated data (the whole header,
fingerprint ‖ suite id, is), so tampering with it — or with the suite
byte — fails the tag check as well. Pipelines and consumers pin a KEK by comparing
these 32 bytes with the fingerprint recorded at provisioning.

The **suite id** names the HPKE ciphersuite the rest of the payload was
sealed with. This build implements exactly one, `0x01`; any other value is
`unsupportedCiphersuite` (-12), reported before the keychain is consulted.
The byte exists so a future suite — a post-quantum hybrid KEM, once the
Secure Enclave can hold its key — is a parse-time dispatch, not a new file
format: the key schedule, AEAD, `info`, AAD, and parser stay as they are
and only the KEM changes.

### Sender authentication — the trust boundary

Base-mode HPKE, like any public-key encryption, authenticates nothing about
*who* wrapped a payload: anyone holding a KEK's public key can produce one
that unwraps. **This is a deliberate decision, not a gap.** The deployment
model is that the pipeline hands the plaintext DEK to the CLI *on the
machine*, which wraps it as the same user who will later unwrap it. In that
model a sender key would live on the same machine as the same user, so
HPKE's Auth mode (sender-authenticated encryption, which CryptoKit supports
with the Secure Enclave recipient key) would add a check the file's owner
could always pass themselves. It is therefore not used.

What this design defends against, and what it leaves to the account:

- A key file can be **read** by anyone, safely: it is ciphertext under a
  key that never leaves this Mac's Secure Enclave.
- A key file can be **swapped or forged** only by someone who can write it
  as its owner (or root). `hkdfguard_open_file` refuses files owned by
  anyone else, writable by anyone else, hard-linked, or in a folder someone
  else can write (`-39`); the AEAD
  rejects any alteration of a genuine file; `wrap --fingerprint` and the
  fingerprint check at unwrap reject a payload for the wrong KEK.
- Whoever **is** the owning user — or has code running as them — can wrap a
  DEK of their choosing, or put back an older genuine file. That is the
  user account's boundary, the same one the login keychain already draws,
  and it is where the protection stops.

Were the deployment model ever to change so the pipeline wrapped off the
machine with a key of its own, Auth mode plus a pinned sender key is the
mechanism, and the suite byte leaves room for it; nothing in the current
format precludes it.

There is no in-band format version. **A change of payload format is
signalled by adopting a new service name** (and therefore a new KEK).

### Payload formats are per-platform

The macOS, Linux, and Windows libraries share one C ABI: the function names
and signatures, the status codes, the `HKDFGUARD_*` flags, and what every
call does. The wrapped payload is not shared. Each platform has its own
format and size: here, the 146-byte HPKE layout above; on Linux, ECDH
against a per-payload hashed point, HKDF-SHA512, and AES-256-GCM, with a
version byte, 132–276 bytes. That's why `HKDFGUARD_WRAPPED_MAX_LEN` has the
same name everywhere but a per-platform value (146 here). A payload is only
opened on the Mac whose Secure Enclave KEK wrapped it, so the formats never
need to interoperate:

- Treat a payload as opaque bytes. Size buffers with
  `HKDFGUARD_WRAPPED_MAX_LEN` or a size probe, and never parse one.
- Moving a service to another platform means re-wrapping its DEKs there,
  under that host's KEK. A payload never moves between platforms.
- The platforms also differ in **who can create a payload**. Here, as
  described above, anyone holding the KEK's public key can, and the
  boundary is the key file's ownership. Linux deliberately uses a scheme
  where only the KEK holder can (see its README).

## Service names

1–128 bytes, each an ASCII letter, digit, or `.`, not starting with `.` and
with no two consecutive dots (`..`) — typically reverse-DNS.
Matched **case-insensitively**: every entry point validates the name as
ASCII first and then lowercases it, and that lowercased form is what is
stored, looked up, and bound into the AES-GCM AAD and HKDF info. Validation
comes first on purpose: Unicode case-folding can map non-ASCII input onto
ASCII (KELVIN SIGN → `k`), so lowercasing first would let such names
through. Anything else (empty, over-length, any non-ASCII byte, `-`, `_`,
a leading `.`, `..`, …) is `invalidServiceIdentifier` (-8). The rule is enforced on bytes,
identically in the library, the CLI, and the Linux and Windows tools.

## C ABI

Declared in
[`hkdfguard.h`](HkdfGuardNativeMacOS/hkdfguard.h)
(plain C; `extern "C"`-guarded; nullability-annotated). All pointers are
required — a NULL is reported, never dereferenced — except `out` in a size
probe (`out = NULL`, `*out_len = 0`), as on Linux. `hkdfguard_keychain_mode`
and `hkdfguard_kek_fingerprint` are macOS-only; everything else is the C ABI
shared with Linux and Windows.

```c
int32_t hkdfguard_keychain_mode(int32_t* out_mode);          // macOS-only: 0 legacy, 1 data-protection
int32_t hkdfguard_kek_exists(const char* service, int32_t* out_exists);
int32_t hkdfguard_kek_fingerprint(const char* service, uint8_t* out, int32_t* out_len); // macOS-only: 32 bytes, public
int32_t hkdfguard_create_kek(const char* service);            // the only function that creates a KEK
int32_t hkdfguard_wrap_dek(const char* service, const uint8_t* dek, int32_t dek_len,
                           uint8_t* out, int32_t* out_len);
int32_t hkdfguard_unwrap_dek(const char* service, const uint8_t* wrapped, int32_t wrapped_len,
                             uint8_t* out, int32_t* out_len);
int32_t hkdfguard_generate_and_wrap_dek(const char* service, uint8_t* out, int32_t* out_len);
int32_t hkdfguard_open_file(const char* path, uint8_t* out, int32_t* out_len); // reads a 146-byte payload file
int hkdfguard_harden_process(void);                           // opt-in; see below
int hkdfguard_harden_process_with_flags(unsigned int flags);
```

`*out_len` is the buffer capacity on entry and, on return, either the bytes
written or — on `outputBufferTooSmall` — the required size (146 for wrap,
32 for unwrap). Both wrap and unwrap check the capacity, and unwrap checks
`wrapped_len == 146`, **before** touching the keychain or the enclave, so a
sizing call costs nothing and a DEK is never decrypted for a caller who
cannot receive it. If `hkdfguard_unwrap_dek` or `hkdfguard_open_file` fails
for any reason, every byte of the `out` capacity declared on entry is zeroed,
so no partial or stale key material is left behind (as on Linux).

### Hardening the host process (opt-in)

Keys and DEKs pass through your process's memory. `hkdfguard_harden_process`
makes that memory harder to recover, as on Linux. It is process-wide and
can't be undone (debuggers and crash reporters stop working for your
process), so it is opt-in: call it once, early in startup.

1. **Core dumps off:** `RLIMIT_CORE` set to 0, hard limit included.
2. **Debugger attachment denied:** `ptrace(PT_DENY_ATTACH)`. If a debugger
   is *already* attached -- running under Xcode's debugger, say -- it
   returns `HKDFGUARD_ERR_PROCESS_HARDENING_FAILED` (-20) instead, because
   the kernel would otherwise terminate the process.
3. **Code signature checked.** On macOS, what really stops another process
   of the same user from reading yours (through its task port) is the
   *host executable's* signature: the Hardened Runtime (`codesign --options
   runtime`) without `com.apple.security.get-task-allow` (which Xcode adds
   to Debug builds), `cs.allow-dyld-environment-variables`, or
   `cs.disable-library-validation`. A library can check that but not change
   it, so by default a weak signature is only **logged** (os_log, subsystem
   `com.hkdfguard`, category `hardening`) and the call still succeeds. That
   keeps the library usable from python, dotnet, Go, and Xcode Debug builds
   during development.

To make a weak signature a startup failure -- a release build of a signed
app -- pass `HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE`:

```swift
#if DEBUG
let rc = hkdfguard_harden_process()
#else
let rc = hkdfguard_harden_process_with_flags(HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE)
#endif
guard rc == 0 else { fatalError("could not harden the process: \(rc)") }
```

Steps 1 and 2 are applied even when strict mode fails. The flag is part of
the shared C ABI: Linux accepts it and changes nothing (`PR_SET_DUMPABLE`
already gives that guarantee there), so a cross-platform binding can pass
it everywhere. Unknown flag bits return -1 before anything changes.

The `hkdfguard` CLI calls `hkdfguard_harden_process()` at startup and
refuses to run if it fails, like the Linux tool.

### Audit trail

The library writes one record per security-relevant event to the macOS
unified log, whatever the host does about logging: subsystem
`com.hkdfguard`, category `audit`. These are the Linux build's syslog records
and the Windows build's Event Log events, with the same IDs, meanings and
fields, so one set of alerts covers all three. To read them:

```sh
/usr/bin/log show --last 1h --info \
    --predicate 'subsystem == "com.hkdfguard" AND category == "audit"'
```

(Use the full path: in zsh, `log` is a shell builtin that shadows the tool.)
Console.app shows the same records live.

| ID | Level | When |
|---|---|---|
| 1000 | default | A KEK was created (not merely found). |
| 1002 | default | A DEK was wrapped (`hkdfguard_wrap_dek` or `hkdfguard_generate_and_wrap_dek`). |
| 1003 | default | A DEK was unwrapped. |
| 2000 | error | `KEK_ACCESS_DENIED`. |
| 2002 | fault | `KEK_INVALID`. |
| 2003 | error | Unwrap rejected a tampered, corrupted, misdirected or unknown-suite payload: `PAYLOAD_AUTH_FAILED`, `KEK_FINGERPRINT_MISMATCH`, `PAYLOAD_MALFORMED`, `PAYLOAD_UNSUPPORTED`. |
| 2005 | fault | `PROVIDER_UNAVAILABLE`, `CRYPTO_ERROR`, `INTERNAL_ERROR`, or one of the macOS refinements of `PROVIDER_ERROR` (-96..-100). |
| 2006 | fault | `hkdfguard_open_file` refused a file that looks like an unwrapped DEK; names the file. |
| 2007 | warning | A process made more than 10 `hkdfguard_create_kek` / `hkdfguard_kek_exists` calls (each held to at least 1000 ms; see [Concurrency](#concurrency)). Logged once per process. |

The unified log has no "warning" level, so Linux's info / warning / error
are `default` / `error` / `fault` here. `default` is the level the log keeps
on disk by default. Linux's 1001 (a KEK created on a fallback provider) and
2004 (`POLICY_INVALID`) never occur on macOS: there is one provider, the
Secure Enclave, and no policy file.

Each record is `key=value` fields followed by a sentence:

```text
event=1002 op=hkdfguard_wrap_dek result=OK service="com.example.ingest" provider=SECURE_ENCLAVE
  kek_fingerprint=d7a1... payload_sha256=7fbd... uid=501 euid=501 pid=4242 exe="/usr/local/bin/ingest" msg="DEK wrapped"
```

The fields identify the caller (`uid`, `euid`, `pid`, `exe`) and the service
by name, and every field is logged public, so nothing appears as
`<private>`. Wrap and unwrap records also carry the KEK's fingerprint and a
SHA-256 of the 146-byte payload. Both are public, and the same payload hashes
the same in its wrap record and in every unwrap record, which ties each
unwrap back to the wrap that made it (`shasum -a 256 <file>` hashes a key
file for comparison). The creation record (1000) also names the keychain
mode.

The records never contain DEKs, KEKs, shared secrets, derived keys or
plaintext. Caller mistakes (`INVALID_ARGUMENT`, `BUFFER_TOO_SMALL`,
`INVALID_SERVICE_NAME`) and `KEK_NOT_FOUND` aren't recorded. Unlike Linux,
the unwrap-success record (1003) can't be turned off: Linux does that in its
policy file, and this library takes no configuration. Any process can write
to the unified log, so these records are an audit aid, not tamper-proof
evidence.

### Reading a wrapped key file: `hkdfguard_open_file`

Reads the 146-byte payload that the CLI's `wrap` writes, validates it, and
copies it to `out`, ready for `hkdfguard_unwrap_dek`. It never touches the
keychain or the Secure Enclave and never unwraps, so the plaintext DEK does
not pass through it:

```c
uint8_t wrapped[HKDFGUARD_WRAPPED_MAX_LEN];
int32_t wrapped_len = sizeof wrapped;
int32_t status = hkdfguard_open_file("/etc/example/ingest.key", wrapped, &wrapped_len);
if (status == 0)
    status = hkdfguard_unwrap_dek("com.example.ingest", wrapped, wrapped_len, dek, &dek_len);
```

`*out_len` is the capacity on entry (at least 146). It is set to 146 — the
bytes read — on success, and to 146 on `outputBufferTooSmall` (checked
before the file is opened). Every other failure leaves it as the caller set
it, as on Linux and as wrap and unwrap do. The file's bytes
reach `out` only on success; on any failure the whole declared capacity of
`out` is zeroed, as on Linux.

- **Safe opening.** The path must name a regular file. A symbolic link as
  its last component is refused, not followed (`O_NOFOLLOW`); symlinks in
  directory components resolve as usual, so `/etc/...` works. A FIFO,
  socket, directory, or device is refused without blocking. Every check is
  made on the opened descriptor (`fstat`), so it describes the file that is
  actually read. At most 147 bytes are read, and a file larger than a
  payload is rejected from its size before any read.
- **Ownership.** The file must be owned by the process's effective user
  **or by root**, writable by no one but its owner, and have a single hard
  link, or it is `fileInsecure` (-39). The CLI's `wrap` output (0600, one
  link) always passes. Root is accepted so an administrator or MDM can
  deploy key files that a service account reads; root can already alter
  anything on the machine, so this adds no new party who could tamper with
  the file. A file owned by any *other* user is refused, because that user
  could swap in a different payload or hard-link an older one into place,
  and that would otherwise be a silent rollback rather than a loud error.
  Group- or world-*readable* is allowed, since the payload is ciphertext. A
  root-owned file must still be readable by the reading account: `0644`, or
  `0640` with a group the account belongs to. Otherwise it is
  `fileAccessDenied` (-33).
- **Folders.** The same holds for every folder above the file, up to `/`,
  as on Linux: each must be owned by root or the process's effective user,
  and not writable by group or others unless it is sticky (`/tmp`-style,
  where only an entry's owner can rename or remove it). Write bits are
  ignored on a read-only volume. Otherwise someone else could rename a file
  of their choosing over the key, and it is `fileInsecure` (-39). The folder
  is the one the opened file actually sits in. A folder the `admin` group
  can write, such as `/Applications`, is refused: every administrator could
  replace the key there without root. Keep key files under a root-owned
  folder such as `/Library/Application Support/<app>` (`0755`), or in the
  service account's home folder.
- **Pass a trusted, absolute path.** The function opens what it is told.
  Don't hand it paths from untrusted input (its status codes say whether a
  file exists, is readable, and its size class — a small oracle if a
  privileged process is pointed at arbitrary files), and don't use relative
  paths, which resolve against a working directory the caller may not
  control. Keep the file in a directory only its owner can write.
- **Length.** Anything other than exactly 146 bytes is `fileTooShort`
  (-35) or `fileTooLong` (-36).
- **Unprotected key.** A file holding a bare 32-byte DEK instead of a
  payload — raw bytes, or base64 (padded or not, standard or URL alphabet)
  or hex text, with optional surrounding whitespace — is reported as
  `fileUnprotectedKey` (-37), not merely as too short. The key was stored
  unprotected: treat it as exposed and rotate it, rather than wrapping it
  now. Its bytes never reach the caller's buffer, and the library zeroes
  its own read buffer on every return.
- **Malformed.** A 146-byte file whose KEK fingerprint is all zeros, or
  whose encapsulated key is not a valid P-256 point, is `fileMalformed`
  (-38); one whose suite byte is not `0x01` is `unsupportedCiphersuite`
  (-12). These are structural checks only: whether the payload is genuine,
  unaltered, and for this service is decided by `hkdfguard_unwrap_dek`
  (`-16`, `-11`). Reading the file proves nothing about it — pin the KEK by
  comparing bytes 0–31 with the recorded fingerprint before unwrapping, as
  with any payload.

### Status codes

The numbering is the shared HkdfGuard status table, the same on every
platform; `hkdfguard.h` defines each as an `HKDFGUARD_*` constant. The source
of record is `hkdfguard-native-linux/include/hkdfguard.h`. Codes not listed
here are defined there but never returned on macOS.

| Value | Constant (`HKDFGUARD_…`) | Swift case | Meaning on macOS |
|------:|---------|---------|---------|
| `0`   | `OK` | `success` | success |
| `-1`  | `ERR_INVALID_ARGUMENT` | `invalidInputLength` | `dek_len != 32`, a NULL buffer/length pointer, or a NULL or empty `path` |
| `-2`  | `ERR_BUFFER_TOO_SMALL` | `outputBufferTooSmall` | `*out_len` set to the required size |
| `-3`  | `ERR_PROVIDER_UNAVAILABLE` | `enclaveUnavailable` | no Secure Enclave on this machine |
| `-5`  | `ERR_CRYPTO_ERROR` | `encryptionFailed` | the RNG or HPKE sealing failed |
| `-6`  | `ERR_INTERNAL_ERROR` | `unexpectedOutputLength` | the library produced output of an impossible length (a bug) |
| `-8`  | `ERR_INVALID_SERVICE_NAME` | `invalidServiceIdentifier` | see `service` above |
| `-10` | `ERR_PAYLOAD_MALFORMED` | `payloadMalformed` | `wrapped_len != 146` |
| `-11` | `ERR_PAYLOAD_AUTH_FAILED` | `decryptionFailed` | the HPKE open failed: altered payload or encapsulated key, or wrapped for a different service under the same KEK |
| `-12` | `ERR_PAYLOAD_UNSUPPORTED` | `unsupportedCiphersuite` | the payload's suite byte is not one this build implements; a newer or different build wrote it. Not tampering |
| `-16` | `ERR_KEK_FINGERPRINT_MISMATCH` | `fingerprintMismatch` | payload was wrapped under a different KEK |
| `-17` | `ERR_KEK_NOT_FOUND` | `kekNotFound` | no KEK for this service in this process's keychain mode; call `hkdfguard_create_kek` |
| `-18` | `ERR_KEK_ACCESS_DENIED` | `keychainAccessDenied` | locked keychain / no UI session / ACL denial / declined prompt / missing entitlement. **A key likely exists**; don't create or delete anything |
| `-19` | `ERR_KEK_INVALID` | `kekCorrupted` | an item exists but can't be reconstructed into a key; never auto-replaced |
| `-32` | `ERR_FILE_NOT_FOUND` | `fileNotFound` | no file at the path, or a path component is not a directory (`hkdfguard_open_file` only, as are `-33` to `-39`) |
| `-33` | `ERR_FILE_ACCESS_DENIED` | `fileAccessDenied` | this process may not read the file or a directory on its path |
| `-34` | `ERR_FILE_IO` | `fileIO` | a symbolic link (refused, never followed), directory, FIFO, socket, or device; or `open`/`fstat`/`read` failed |
| `-35` | `ERR_FILE_TOO_SHORT` | `fileTooShort` | fewer than 146 bytes, and not a plaintext DEK |
| `-36` | `ERR_FILE_TOO_LONG` | `fileTooLong` | more than 146 bytes |
| `-37` | `ERR_FILE_PLAINTEXT_KEY` | `fileUnprotectedKey` | the file appears to hold a bare, unwrapped DEK (any 32-byte value as raw/base64/hex matches). **Treat the key as exposed** and rotate it |
| `-38` | `ERR_FILE_MALFORMED` | `fileMalformed` | 146 bytes, but the fingerprint is all zeros or the encapsulated key is not a P-256 point |
| `-39` | `ERR_FILE_UNTRUSTED` | `fileInsecure` | owned by someone other than this user or root, writable by group or others, or more than one hard link; or a folder above it is owned by someone else or writable by group or others without being sticky |
| `-96` | `ERR_MAC_ACCESS_CONTROL_CREATION_FAILED` | `accessControlCreationFailed` | refines `ERR_PROVIDER_ERROR` (-4) |
| `-97` | `ERR_MAC_KEY_GENERATION_FAILED` | `keyGenerationFailed` | the enclave refused to generate a key; refines -4 |
| `-98` | `ERR_MAC_KEYCHAIN_WRITE_FAILED` | `keychainWriteFailed` | refines -4 |
| `-99` | `ERR_MAC_KEK_VERIFICATION_FAILED` | `kekVerificationFailed` | stored, but couldn't be reloaded immediately after; refines -4 |
| `-100` | `ERR_MAC_KEYCHAIN_READ_FAILED` | `keychainReadFailed` | refines -4 |

## Keychain modes (hybrid)

The KEK's keychain item lives in one of two keychains, chosen once per
process from the process's **own code-signing entitlements** — never from
configuration:

| Mode | When | Where the item lives | Cross-process access |
|---|---|---|---|
| **data-protection** (1) | the process has a `keychain-access-groups` entitlement — on macOS that means a Team-signed **app bundle with an embedded provisioning profile** | the data-protection keychain, under the first listed access group | decided by securityd from the caller's signed identity: no prompts, no ACLs; any Team-signed bundle listing the same group shares it |
| **legacy** (0) | no such entitlement — a bare executable (the CLI as a plain Mach-O, a .NET/Python/Go host that `dlopen`s the dylib, the `xctest` agent) | the login keychain | login-keychain lock plus a per-item ACL keyed to the creating binary; other identities get an interactive prompt, or, headless, `-18` |

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
  different user gets `kekNotFound` (`-17`), and running `provision` there
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

## Command-line tool: `hkdfguard`

Provisions, wraps, and retires KEKs for pipelines. Provisioning and
wrapping go through the C ABI above only; `retire` additionally deletes the
keychain item itself, since the library deliberately exports no delete.
Four commands:

```
hkdfguard provision --service-name|-sn <name>

hkdfguard status --service-name|-sn <name>

hkdfguard wrap --key-file-path|-kf <path> \
                             --service-name|-sn <name> \
                             ( --dek-stdin | --dek-file <path> ) \
                             [--fingerprint|-fp <64 hex chars>] [--force|-f]

hkdfguard retire --service-name|-sn <name> \
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
  answer and `1` when it could not (`-18`, `-100`, no enclave).
- **`retire`** deletes the KEK for `<name>`, but only if its current
  fingerprint equals `<hex>` exactly; a mismatch, a KEK that can't be read
  (`-18`, `-19`, `-100`), or no KEK at all deletes nothing. The only command
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
  `kekCorrupted` (`-19`) — present but not reconstructable into a key, so
  it has no fingerprint to confirm. It deletes only when the status is
  exactly `-19`, and only after proving the Secure Enclave works in this
  session: it creates a throwaway, never-stored enclave key under the same
  access policy, reconstructs it from its data representation as the
  library does, and uses it once. Otherwise a healthy KEK that merely
  failed to load (locked session, SSH without a GUI login) could look
  corrupt and be deleted. A valid KEK, a missing one, or one the keychain
  won't let it read (`-18`, `-100`) is never deleted. Like `retire`, it
  acts on exactly one item, by persistent reference, after confirming that
  item's own blob is the unreconstructable one. Afterwards the service can
  be provisioned again. `--fingerprint` and `--corrupt` are mutually
  exclusive.
- **`wrap`** wraps the pipeline's existing 32-byte DEK — base64, read from
  **stdin** (`--dek-stdin`) or a **file** (`--dek-file`), exactly one of the
  two — under the already-provisioned KEK and writes the 146-byte payload to
  `<path>`. It never creates a KEK (an unprovisioned service is an error
  naming the `provision` command) and never generates a DEK. There is
  deliberately no `--dek <base64>` argument: an argv value is visible to
  every process via `ps` and lands in shell history. `--dek` and
  `--generate` are refused with an explanation.
  - *`--dek-file` rules (same as the Linux tool).* The file must be a
    regular file -- a symbolic link is refused, never followed, and a FIFO
    or device is refused without blocking -- owned by root or by the user
    running the CLI, and grant no access to group or others (mode `0400` or
    `0600`). Every check is made on the opened descriptor, so it describes
    the file that is read.
  - *Input handling (same as the Linux tool).* At most 64 bytes are
    accepted -- base64 of a 32-byte DEK is 44 characters -- and anything
    longer is refused before it is read in full. One trailing newline (or
    CRLF) is ignored and nothing else: leading spaces, trailing spaces, or a
    second newline make the input invalid base64. Decoding is strict,
    padded standard base64. The text and the decoded DEK live in one
    fixed-size buffer locked into memory with `mlock` (a warning is printed
    if the lock is refused), are never held as a string, and are zeroed on
    every exit path.
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
| `hkdfguard` (plain executable) | legacy | provision and wrap for consumers that run in legacy mode — any `dlopen`/FFI host |
| `hkdfguard.app` (app bundle) | data-protection | provision, wrap, and retire for consumers that are Team-signed app bundles in the same `com.hkdfguard.keys` access group |

The installer package installs both (see
[Installing on a machine](#installing-on-a-machine)). The legacy-mode CLI is
on `PATH` as `/usr/local/bin/hkdfguard`; run the
data-protection build by the executable inside its bundle:

```sh
"/Library/Application Support/HkdfGuard/v1/hkdfguard.app/Contents/MacOS/hkdfguard" \
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
hkdfguard provision -sn com.example.ingest      # prints "fingerprint: <hex>" -- record it
printf '%s' "$DEK_B64" | hkdfguard wrap -kf /etc/example/ingest.key -sn com.example.ingest \
    --dek-stdin -fp <recorded fingerprint>                     # refuses if the KEK is not that one

# Later, after migrating everything to a new service name:
hkdfguard retire -sn com.example.ingest -fp <fingerprint printed by provision>
```

## Project layout

| Target / package | Product | Purpose |
|---|---|---|
| `HkdfGuardNativeMacOS` | `HkdfGuardNativeMacOS.framework` | Embed in a signed macOS app; carries the public header and an app-sandbox entitlement |
| `HkdfGuardNativeMacOSDylib` | `libhkdfguard.dylib` | Flat shared library for `dlopen`-based FFI from arbitrary, often unsandboxed, host processes |
| `HkdfGuardNativeMacOSTests` | `.xctest` | Swift Testing suites for the C entry points and for the CLI as a real subprocess |
| `hkdfguard-cli/` | `hkdfguard` | SwiftPM package for the CLI; links the dylib through its C ABI only. Bare Mach-O → legacy keychain mode |
| `hkdfguard-app` | `hkdfguard.app` | The same `main.swift` as an app bundle with the `com.hkdfguard.keys` access group in Release (`com.hkdfguard.tests.keys` in Debug/DebugHosted) and hardened runtime, embedding the dylib — the build of the CLI that runs in data-protection mode |
| `HkdfGuardNativeMacOSTestHost` | `HkdfGuardNativeMacOSTestHost.app` | Minimal entitled host app for the test bundle, so the suite can run in data-protection mode (see Tests) |

All library targets build from the single `HkdfGuardNativeMacOS.swift`.
Requires a **Swift 6.2+** toolchain (compile-time `#error` guard). The
dylib, both CLI builds, the test bundle, and the test host target
**macOS 14.0+** (HPKE in CryptoKit needs 14); the framework target uses the
SDK's recommended deployment target.

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
swift build -c release --package-path hkdfguard

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

It also builds the bundled CLI into `dist/osx-arm64-app/hkdfguard.app`
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
PKG="hkdfguard-native-macos-${VERSION#v}-osx-arm64.pkg"

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

Builds `dist/hkdfguard-native-macos-<version>-osx-arm64.pkg` and its
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
libhkdfguard.dylib          0644   the library
hkdfguard.h                    0644   its C header
hkdfguard        0755   the CLI, legacy keychain mode
hkdfguard.app           the CLI, data-protection keychain mode
SHA256SUMS                     0644   checksums of the first three
uninstall.sh                   0755   removes all of it
```

and a root-owned symlink `/usr/local/bin/hkdfguard` → the
legacy-mode CLI. It installs only on **Apple silicon** running **macOS 14 or
later**, only to a system volume (never a user's home folder), with no
customization. Consumers must run on a native arm64 runtime: an x64 .NET,
Python, or Java runtime under Rosetta cannot load the arm64 dylib.

### Installing

Check the package against the release notes, then install it:

```sh
VERSION=v0.9.0
PKG="hkdfguard-native-macos-${VERSION#v}-osx-arm64.pkg"
gh release download "$VERSION" --pattern "$PKG"
shasum -a 256 "$PKG"                      # must match the release notes
pkgutil --check-signature "$PKG"          # Developer ID Installer: <Name> (<TEAMID>); notarized
sudo installer -pkg "$PKG" -target /
pkgutil --pkg-info com.hkdfguard.native      # the receipt, with the installed version
```

Double-clicking the package in Finder works too. For a fleet, upload the
package to your MDM (Jamf, Intune, Kandji, …) and scope the policy to Apple
silicon Macs; MDM tools verify the Developer ID Installer signature
themselves. Installing a newer package over an older one upgrades `v1/` in
place. Installer does not refuse an *older* package over a newer one — it
replaces `v1/` as a whole, so the result is a consistent downgrade, not a
mix — so have the MDM policy or the operator compare
`pkgutil --pkg-info com.hkdfguard.native` first.

Earlier packages used the package ID `com.hkdfguard.native.v1`. The current
package installs over one of those normally and forgets the old receipt, so
afterwards `pkgutil` lists only `com.hkdfguard.native`. MDM policies that
check the installed version should look for the new ID, or for either.

### The `PATH` symlink

The package's `postinstall` script creates
`/usr/local/bin/hkdfguard`, rather than shipping it in the
payload: a payload containing `/usr/local/bin` would let Installer reset the
owner and mode of a folder that already exists (Homebrew on Intel Macs owns
it). The script creates `/usr/local` and `/usr/local/bin` only if missing
(`root:wheel 0755`), never changes an existing folder, never overwrites a
real file at that path, and never fails the install. It creates the symlink
**only when `/usr/local/bin` is a real folder owned by root and writable by
root alone**: anyone else who could write that folder could repoint the
symlink at their own program, which an operator would then run while
provisioning keys. Otherwise it logs a warning to `/var/log/install.log`
and links nothing; call the CLI by its full path in that case. The
data-protection build is never on `PATH`; call it by its full path (see the
CLI section above).

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
/Library/Application Support/HkdfGuard/v1/libhkdfguard.dylib
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
existing `[DllImport("hkdfguard")]` declarations stay unchanged:

```csharp
NativeLibrary.SetDllImportResolver(typeof(HkdfGuardInterop).Assembly, (name, assembly, searchPath) =>
    name == "hkdfguard"
        ? NativeLibrary.Load(HkdfGuardInstall.ResolveVerifiedPath()) // the fixed path; checks above
        : IntPtr.Zero);
```

Other languages load the same absolute path in place of the
`./libhkdfguard.dylib` used in the examples below.

## Consuming this library

Every consumer uses the files the installer package puts in
`/Library/Application Support/HkdfGuard/v1/`: `libhkdfguard.dylib`,
loaded by that absolute path (see
[Loading the installed library](#loading-the-installed-library));
`hkdfguard.h`, for the exact signatures (see [C ABI](#c-abi)); and, for
provisioning, the `hkdfguard` CLI.

A `dlopen`/FFI host in any of these languages runs in **legacy keychain
mode** (see [Keychain modes](#keychain-modes-hybrid)) unless the host
process is itself a Team-signed app bundle carrying the
`keychain-access-groups` entitlement — which a stock `python`, `node`,
`java`, or `dotnet` binary is not. In legacy mode its KEKs live in the login
keychain, gated by the login session being unlocked, not by an access group
shared with a signed app bundle.

**Legacy mode is the production mode for these consumers**, and its
boundary is the user account plus the login keychain's per-item ACL. That
ACL identifies the *main executable* that asks for the item, so what the
operator's one-time "Always Allow" is granted to depends on how the
consumer is launched:

- Run as `dotnet MyApp.dll`, `python3 app.py`, `java -jar …`, the
  executable is the shared runtime. The approval then covers **every**
  program that runtime runs as that user, with no further prompt.
- Run as **its own executable** — a .NET apphost (`./MyApp`, the default
  `UseAppHost=true` build, or a self-contained single-file publish), a
  PyInstaller/Nuitka binary, a Go binary — the approval covers that program
  alone.

So ship the consumer as its own executable and **sign it with your
Developer ID** (a .NET apphost needs the `com.apple.security.cs.allow-jit`
entitlement if you also enable the hardened runtime). A Developer ID
signature is identified by its Team, so rebuilds and certificate renewals
keep the approval; an ad-hoc signature is identified by the binary's hash,
so every rebuild re-prompts — the same rule the CLI section gives for the
CLI. The first unwrap on a machine is interactive (the "Always Allow"
prompt) and needs the login keychain unlocked; run headless consumers as a
LaunchAgent in a logged-in session (see "Access policy and headless use").

Data-protection mode remains available for a consumer that *is* a
Team-signed app bundle: there, access follows the signed identity with no
prompt at all. It is not required.

**Python** (`ctypes`, standard library):

```python
import ctypes

lib = ctypes.CDLL("./libhkdfguard.dylib")
lib.hkdfguard_create_kek.argtypes = [ctypes.c_char_p]
lib.hkdfguard_create_kek.restype = ctypes.c_int32

status = lib.hkdfguard_create_kek(b"com.example.ingest")
```

**Node** (`koffi`):

```js
const koffi = require("koffi");
const lib = koffi.load("./libhkdfguard.dylib");
const hkdfguard_create_kek = lib.func("int32_t hkdfguard_create_kek(const char *service)");

const status = hkdfguard_create_kek("com.example.ingest");
```

**Java** (JNA):

```java
public interface HkdfGuard extends Library {
    HkdfGuard INSTANCE = Native.load("./libhkdfguard.dylib", HkdfGuard.class);
    int hkdfguard_create_kek(String service);
}

int status = HkdfGuard.INSTANCE.hkdfguard_create_kek("com.example.ingest");
```

**Go** (`cgo`, needs the header at build time):

```go
/*
#cgo LDFLAGS: -L${SRCDIR} -lhkdfguard
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
[DllImport("hkdfguard", CallingConvention = CallingConvention.Cdecl)]
static extern int hkdfguard_create_kek(string service);

int status = hkdfguard_create_kek("com.example.ingest");
```

`hkdfguard` is the platform-neutral library name: .NET resolves it to
`libhkdfguard.dylib` here by adding the platform's `lib` prefix and
extension, so the same `DllImport` works wherever the library follows the
standard naming -- including Linux, where the same name resolves to
`libhkdfguard.so`. (Both libraries dropped an earlier `_v1` suffix from the
name; the ABI's major version is carried by the install folder
`HkdfGuard/v1/` here and by the `libhkdfguard.so.1` SONAME on Linux.)

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

- `hkdfguard_create_kek` and `hkdfguard_kek_exists` are setup calls, meant
  to run once per application startup. Each takes at least 1000 ms of
  wall-clock time whatever its outcome, and they are serialized with each
  other across threads, so a process can make at most about one per
  second -- the same floor as the Linux and Windows builds. On macOS it is
  fixed (Linux reads `startup_behavior.setup_min_delay_ms` from its policy
  file, Windows `HKLM\Software\Policies\HkdfGuard\SetupMinDelayMs`).
  A NULL pointer or an invalid service name returns immediately. Call them
  once at startup, then use `hkdfguard_wrap_dek` / `hkdfguard_unwrap_dek`,
  which are not gated.
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
  unentitled process is reported as `-18`, never as "no key"), and a
  wrap → write file → `hkdfguard_open_file` → unwrap round trip.
- **`HkdfGuardOpenFileTests`** covers `hkdfguard_open_file` without the
  enclave: exact-length success, too short/too long, plaintext DEKs in
  every accepted encoding (`-37`, never copied out) versus short text that
  is not a key, malformed payloads (off-curve encapsulated key, zero
  fingerprint), unknown suite bytes (-12), missing and unreadable files, symlink/directory/FIFO
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
(`hkdfguard.app`, same test group). That enables the test
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

Shared with the Linux tool (`hkdfguard-native-linux/src/bin/hkdfguard.rs`):
the `provision` and `wrap` commands, `--key-file-path`, DEK input from stdin
or a file only, `0600` output, and process hardening at startup. Mac-only:
the `retire` and `status` commands, and `wrap` printing the KEK fingerprint
it used and accepting `--fingerprint` to pin it.
