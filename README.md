# hkdfguard-native-macos

Core key and key-material protection for macOS. Sibling of
`hkdfguard-native-linux` and the Windows native library: the three share
the C ABI, the status codes, the service-name rules, and the CLI contract,
so one consumer and one pipeline work on every platform. They do **not**
share payload bytes, and nothing requires them to: a KEK is bound to the
Secure Enclave of the machine that created it and never leaves it, so a
wrapped key file is only ever read on the machine that wrote it. The macOS
payload construction is the same as theirs, described below.

`HkdfGuardNativeMacOS` wraps and unwraps 32-byte Data Encryption
Keys (DEKs) under a per-service Key Encryption Key (KEK) that lives in the
device's Secure Enclave, exposed as a plain C ABI so it can be called from
Swift, Objective-C, C/C++, or any language that can load a Mach-O dylib
(Python `ctypes`, Go `cgo`, .NET P/Invoke, Java JNA, …). A companion
command-line tool, `hkdfguard`, provisions KEKs and wraps DEKs
for pipelines.

## What it does

Each calling application identifies itself with a **service name** (see
below). A service's KEK is a key generated inside the Secure Enclave: an
ML-KEM-1024 key by default, or a P-256 key-agreement key where the policy
opts in to one (see [KEK suites](#kek-suites)). Its private half never
leaves the enclave and can only be *used*, never extracted. What the
library persists, in the keychain or a machine KEK file, is the enclave's
opaque, device-bound reference to that key.

Provisioning is explicit. `hkdfguard_create_kek` is the only function that
creates a KEK; every wrap/unwrap function requires one to already exist and
fails with `kekNotFound` (-17) otherwise. Nothing is ever created "on first
use".

Every payload is sealed the same way: **a secret only the Secure Enclave
can compute, HKDF-SHA512, AES-256-GCM**, with CryptoKit doing every
primitive. The KEK's suite decides where the secret comes from:

1. A fresh random 32-byte **salt** and 12-byte **nonce** are drawn.
2. The **Secure Enclave** computes the secret:
   - **ML-KEM-1024** (suite `0x02`): it decapsulates the ciphertext stored
     with the KEK, which was encapsulated to it once, at provisioning, and
     gets back the 32-byte secret `K`.
   - **P-256** (suite `0x01`), the Linux and Windows libraries'
     construction: the salt is hashed to a P-256 point `H` with RFC 9380
     hash-to-curve, suite `P256_XMD:SHA-256_SSWU_RO_`, under the DST
     `"HkdfGuard-payload-ECDH-point-V01-CS01-with-P256_XMD:SHA-256_SSWU_RO_"`
     (the Linux library's hash, byte for byte), and the enclave computes
     `Z = ECDH(KEK_priv, H)`.
3. **HKDF-SHA512** turns the secret into the 32-byte AES key, with the salt
   as HKDF's salt and an `info` of `"hkdfguard-wrap-v1:"` ‖ the service
   name's length (u16, little-endian) ‖ the service name ‖ the payload
   header. The header holds the suite byte, so the two suites never derive
   the same key.
4. **AES-256-GCM** seals the DEK under the nonce, with the payload header
   as additional authenticated data.

Unwrapping reverses this: the payload names the suite, the Secure Enclave
computes the same secret. Every wrap draws a new salt and nonce, so two
wraps of the same DEK never produce the same bytes, and a payload wrapped
for one service can never be opened under another.

### KEK suites

| | ML-KEM-1024 (`0x02`) | P-256 (`0x01`) |
|---|---|---|
| Provisioned | by default, on macOS 26 and later | only with `KekSuite` `P-256` in the [policy](#the-policy) |
| The secret | `K`: one per KEK | `Z`: one per payload |
| A quantum computer that sees the public key | learns nothing that gives `K` | recovers the private key, and with it every payload |
| Fingerprint | SHA-256 of the 1568-byte ML-KEM public key | SHA-256 of `0x04 ‖ x ‖ y` |
| Same construction on Linux and Windows | not yet | yes |

Both keep the payload at 125 bytes, and with both only this Mac can create
a payload, not merely open one. A KEK has exactly one suite, fixed when it
is provisioned: changing a service's suite means retiring its KEK and
provisioning a new one (see [Moving to post-quantum KEKs](#moving-to-post-quantum-keks)).

### Why only this Mac can create a payload

For **P-256**, nobody knows the private key of a point that came out of a
hash, so `Z` can only be computed with the KEK's private key, which never
leaves the Secure Enclave. Creating a payload therefore needs the enclave
as much as opening one does. Knowing the KEK's **public** key is not enough.

That is the difference from ordinary public-key encryption (ECIES, HPKE base
mode), where the sender picks an ephemeral key `e` and computes `e · KEK_pub`.
Anyone holding the public key can do that, and could therefore write a key
file carrying a DEK of their choosing that `unwrap` accepts. The public key
isn't secret, and once it has been seen it can't be made secret again, so
with that design the key file's permissions would be the only thing standing
in the way.

For **ML-KEM-1024**, `K` came out of one encapsulation, made at
provisioning and then dropped; from then on only decapsulating the stored
ciphertext gives it back, and that takes the enclave. The public key lets
anyone encapsulate a secret of their own, not recover `K`, so it can't be
used to forge a payload either. Neither the public key nor the stored
ciphertext needs to stay secret.

### What each suite gives up

**P-256** gives each payload its own point, so `Z` is unique to the
payload: if one `Z` is ever captured (from memory, say), it opens that one
payload, not the service's history, and still lets nobody create a new one.
What it can't survive is a quantum computer that has seen the KEK's public
key: Shor's algorithm turns the public key into the private key, and that
opens every payload ever wrapped under the KEK, offline, without this Mac.
No payload or fingerprint carries the public key, but a P-256 machine KEK
file does, in the clear, and so does every copy of that file a backup or
snapshot keeps.

**ML-KEM-1024** has one secret per KEK, not one per payload. `K` passes
through the process on every wrap and unwrap, as `Z` does; captured once,
it opens every payload under that KEK, and lets its holder create new ones,
until the KEK is retired. That is the price of keeping the payload at 125
bytes. The alternative, a fresh encapsulation per payload with an ML-DSA
signature to keep payloads unforgeable, has P-256's one-secret-per-payload
property but makes every payload about 4.5 KB.

## Wrapped payload format

Always exactly **125 bytes**:

```
[ 32-byte KEK fingerprint — SHA-256 of the KEK's public key                 ]
[  1-byte suite id — 0x01 (P-256) or 0x02 (ML-KEM-1024), the KEK's suite    ]
[ 32-byte random salt                                                       ]
[ 12-byte random AES-GCM nonce                                              ]
[ 32-byte AES-256-GCM ciphertext || 16-byte tag                             ]
```

The **header** is every byte before the ciphertext. It is bound twice, as on
Linux: into the derived key (HKDF `info`, with the service name) and into
the tag (AES-GCM additional data). No header byte can be changed without the
open failing.

The fingerprint identifies *which* KEK a payload was wrapped under. For a
P-256 KEK it hashes the uncompressed public key (`0x04 || x || y`), as Linux
does; Windows hashes the raw `x || y`, without the `0x04` prefix, so the same
key would fingerprint differently there. That is harmless, since a payload
is only ever opened on the machine that wrapped it, but a fingerprint is
only meaningful on the platform that produced it. For an ML-KEM-1024 KEK it
hashes the raw 1568-byte public key. On unwrap it is compared to the current
KEK's **before** any key agreement, decapsulation or decryption is
attempted, so "wrong or rotated KEK" is reported as `fingerprintMismatch`
(-16) rather than as a generic decryption failure. That includes a payload
of the other suite: no KEK of one suite has the other's fingerprint.
Pipelines and consumers pin a KEK by comparing these 32 bytes with the
fingerprint recorded at provisioning.

The **suite id** names the construction above: `0x01` or `0x02`, the suite
of the KEK that wrapped it. Any other value is `unsupportedCiphersuite`
(-12) from unwrap, reported before the keychain is consulted (`fileMalformed`,
-38, from `hkdfguard_open_file`, as on Linux and Windows), so a future
construction is a parse-time dispatch rather than a new file format. The
right fingerprint with the other suite's byte can only be an alteration, and
is `decryptionFailed` (-11). With the policy's `RequirePostQuantum`, a `0x01`
payload is `unsupportedCiphersuite` (-12) too, before the keychain is
consulted.

Unwrap failures are kept apart: the Secure Enclave refusing the key
agreement or the decapsulation (locked, unavailable) is `encryptionFailed`
(-5, CRYPTO_ERROR), a fact about this machine; only a tag that doesn't
verify is `decryptionFailed` (-11, PAYLOAD_AUTH_FAILED): the payload was
altered, or sealed for a different service.

### The trust boundary

- A key file can be **read** by anyone, safely: it is ciphertext under a
  key that never leaves this Mac's Secure Enclave.
- A key file can be **created** only by code that can use the KEK — the
  service's account, through the Secure Enclave. Someone who can merely
  write files (a configuration push, a backup restore, a process that once
  saw the public key) cannot forge one.
- A key file can be **swapped** for another genuine one only by someone who
  can write it as its owner (or root). `hkdfguard_open_file` refuses files
  owned by anyone else, writable by anyone else, reached through a
  symbolic link, or in a folder someone else can write (`-39`); the AEAD rejects any alteration of a
  genuine file; `wrap --fingerprint` and the fingerprint check at unwrap
  reject a payload for the wrong KEK.
- Whoever **is** the owning user — or has code running as them — can wrap a
  DEK of their choosing, or put back an older genuine file. That is the
  user account's boundary, the same one the login keychain already draws,
  and it is where the protection stops.

### Payload formats are per-platform

The macOS, Linux, and Windows libraries share one C ABI: the function names
and signatures, the status codes, the `HKDFGUARD_*` flags, and what every
call does. They also share the P-256 construction above; the ML-KEM-1024
suite is this library's alone for now. The payload **layout**
is not shared: Linux adds a version byte, a provider tag and a key id
(132–276 bytes), and this library's is the fixed 125 bytes above. That's why
`HKDFGUARD_WRAPPED_MAX_LEN` has the same name everywhere but a per-platform
value (125 here). A payload is only opened on the Mac whose Secure Enclave
KEK wrapped it, so the layouts never need to interoperate:

- Treat a payload as opaque bytes. Size buffers with
  `HKDFGUARD_WRAPPED_MAX_LEN` or a size probe, and never parse one.
- Moving a service to another platform means re-wrapping its DEKs there,
  under that host's KEK. A payload never moves between platforms.

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
probe (`out = NULL`, `*out_len = 0`), as on Linux. `hkdfguard_keychain_mode`,
`hkdfguard_kek_fingerprint`, `hkdfguard_kek_suite` and `hkdfguard_machine_policy`
(the KEK policy in effect, as JSON; the CLI uses it to enforce the admin
roles and to show the suite settings) are macOS-only; everything else is the
C ABI shared with Linux and Windows.

```c
int hkdfguard_keychain_mode(int* out_mode);          // macOS-only: 0 legacy, 1 data-protection
int hkdfguard_kek_exists(const char* service, int* out_exists);
int hkdfguard_kek_fingerprint(const char* service, uint8_t* out, int* out_len); // macOS-only: 32 bytes, public
int hkdfguard_kek_suite(const char* service, int* out_suite); // macOS-only: HKDFGUARD_KEK_SUITE_P256 (1) or _MLKEM1024 (2)
int hkdfguard_create_kek(const char* service);        // the only function that creates a KEK
int hkdfguard_wrap_dek(const char* service, const uint8_t* dek, int dek_len,
                       uint8_t* out, int* out_len);
int hkdfguard_unwrap_dek(const char* service, const uint8_t* wrapped, int wrapped_len,
                         uint8_t* out, int* out_len);
int hkdfguard_generate_and_wrap_dek(const char* service, uint8_t* out, int* out_len);
int hkdfguard_open_file(const char* path, uint8_t* out, int* out_len); // reads a 125-byte payload file
int hkdfguard_harden_process(void);                           // opt-in; see below
int hkdfguard_harden_process_with_flags(unsigned int flags);
int hkdfguard_machine_policy(uint8_t* out, int* out_len); // macOS-only: the policy in effect, as JSON
```

`*out_len` is the buffer capacity on entry and, on return, either the bytes
written or — on `outputBufferTooSmall` — the required size (125 for wrap,
32 for unwrap). Both wrap and unwrap check the capacity, and unwrap checks
`wrapped_len == 125`, **before** touching the keychain or the enclave, so a
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
| 1004 | error | A KEK was retired by the CLI's `retire` (written by the CLI, category `audit`); names its fingerprint, scope and the admin behind `sudo`. |
| 2000 | error | `KEK_ACCESS_DENIED`. |
| 2002 | fault | `KEK_INVALID`. |
| 2003 | error | Unwrap rejected a tampered, corrupted, misdirected or unknown-suite payload: `PAYLOAD_AUTH_FAILED`, `KEK_FINGERPRINT_MISMATCH`, `PAYLOAD_MALFORMED`, `PAYLOAD_UNSUPPORTED`. |
| 2004 | fault | `POLICY_INVALID`: the production policy can't be used; every call fails closed until it is fixed (see [Production mode](#production-mode-machine-scoped-keks)). |
| 2005 | fault | `PROVIDER_UNAVAILABLE`, `CRYPTO_ERROR`, `INTERNAL_ERROR`, or one of the macOS refinements of `PROVIDER_ERROR` (-96..-100). |
| 2006 | fault | `hkdfguard_open_file` refused a file that looks like an unwrapped DEK; names the file. |
| 2007 | warning | A process made more than 10 `hkdfguard_create_kek` / `hkdfguard_kek_exists` / `hkdfguard_kek_fingerprint` calls (each held to at least 1000 ms; see [Concurrency](#concurrency)). Logged once per process. |

The unified log has no "warning" level, so Linux's info / warning / error
are `default` / `error` / `fault` here. `default` is the level the log keeps
on disk by default. Linux's 1001 (a KEK created on a fallback provider)
never occurs on macOS: there is one provider, the Secure Enclave. 2004
occurs only with a production policy.

Each record is `key=value` fields followed by a sentence:

```text
event=1002 op=hkdfguard_wrap_dek result=OK service="com.example.ingest" provider=SECURE_ENCLAVE
  kek_fingerprint=d7a1... payload_sha256=7fbd... uid=501 euid=501 pid=4242 exe="/usr/local/bin/ingest" msg="DEK wrapped"
```

The fields identify the caller (`uid`, `euid`, `pid`, `exe`) and the service
by name, and every field is logged public, so nothing appears as
`<private>`. Wrap and unwrap records also carry the KEK's fingerprint and a
SHA-256 of the 125-byte payload. Both are public, and the same payload hashes
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

Reads the 125-byte payload that the CLI's `wrap` writes, validates it, and
copies it to `out`, ready for `hkdfguard_unwrap_dek`. It never touches the
keychain or the Secure Enclave and never unwraps, so the plaintext DEK does
not pass through it:

```c
uint8_t wrapped[HKDFGUARD_WRAPPED_MAX_LEN];
int wrapped_len = sizeof wrapped;
int status = hkdfguard_open_file("/etc/example/ingest.key", wrapped, &wrapped_len);
if (status == 0)
    status = hkdfguard_unwrap_dek("com.example.ingest", wrapped, wrapped_len, dek, &dek_len);
```

`*out_len` is the capacity on entry (at least 125). It is set to 125 — the
bytes read — on success, and to 125 on `outputBufferTooSmall` (checked
before the file is opened). Every other failure leaves it as the caller set
it, as on Linux and as wrap and unwrap do. The file's bytes
reach `out` only on success; on any failure the whole declared capacity of
`out` is zeroed, as on Linux.

- **Safe opening.** The path must name a regular file. A symbolic link as
  its last component is refused, not followed (`O_NOFOLLOW`), as
  `fileInsecure` (-39); symlinks in
  directory components resolve as usual, so `/etc/...` works. A FIFO,
  socket, directory, or device is refused without blocking. Every check is
  made on the opened descriptor (`fstat`), so it describes the file that is
  actually read. At most 126 bytes are read, and a file larger than a
  payload is rejected from its size before any read.
- **Ownership.** The file must be owned by the process's effective user
  **or by root**, and writable by no one but its owner, or it is
  `fileInsecure` (-39). The CLI's `wrap` output (0600) always passes. Root is accepted so an administrator or MDM can
  deploy key files that a service account reads; root can already alter
  anything on the machine, so this adds no new party who could tamper with
  the file. A file owned by any *other* user is refused, because that user
  could swap in a different payload, and that would otherwise be a silent
  rollback rather than a loud error. A file with more than one hard link is
  accepted, as on Linux and Windows: putting a second name for an older
  payload where the service looks means creating an entry in the key's
  folder, which the folder checks below limit to the owner and root.
  Group- or world-*readable* is allowed, since the payload is ciphertext. A
  root-owned file must still be readable by the reading account: `0644`, or
  `0640` with a group the account belongs to. Otherwise it is
  `fileAccessDenied` (-33).
- **Folders.** The same holds for every folder above the file, up to `/`,
  as on Linux: each must be owned by root or the process's effective user,
  and not writable by group or others unless it is sticky (`/tmp`-style,
  where only an entry's owner can rename or remove it). Write bits are
  ignored only on the sealed system volume, which nothing can change; any
  other read-only volume, such as a mounted disk image, is checked like the
  rest. Otherwise someone else could rename a file of their choosing over
  the key, and it is `fileInsecure` (-39). The folders are walked from the
  one the opened file actually sits in, by descriptor through each `..`,
  never by re-reading the path's spelling.
- **Access control lists.** Mode bits are not the whole story on macOS: an
  ACL entry can grant write to anyone, whatever the mode. The file is
  `fileInsecure` (-39) if its ACL allows anyone but this user or root to
  write, append, delete it, or change its attributes, permissions, owner or
  ACL; a folder in the chain is, if its ACL allows anyone else to add,
  remove or rename entries in it, or change its permissions, owner or ACL.
  Deny entries, such as the `everyone deny delete` on every home folder,
  and entries that grant only reading or listing, are fine.
- **Volumes.** A file or folder on a volume mounted with ownership ignored
  (`noowners`, the default for disk images and removable media a user
  mounts) is `fileInsecure` (-39): there every item reports whoever asks as
  its owner, so the owner checks above would prove nothing. A folder the `admin` group
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
- **Symbolic links to folders in the path.** A link to a folder
  partway along the path is followed, and is not itself checked: the
  checks above apply to the folders the file really sits in. So whoever
  can change that link — anyone who can write the folder holding it —
  decides which folder the path names. If they point it at another folder
  that passes the checks (one of this user's own, say), they choose which
  of this user's genuine key files is read: an older one for the same
  service (see **Replay**), or another service's, which unwrap refuses as
  a fingerprint mismatch (-16). Use a path whose only symbolic links are
  the root-owned system ones (`/tmp`, `/var`, `/etc`).
- **Replay.** A genuine payload is genuine forever. Nothing in it records
  when it was made or whether it is the latest, so someone who can write
  the key file as its owner (or as root) can put back an *older* payload
  wrapped under the same KEK, and it opens and unwraps normally, giving
  the older DEK. Neither this function nor unwrap can tell. Wrapping a new
  DEK doesn't revoke the old payload: only retiring the KEK does
  (`hkdfguard retire`, then provision a new KEK and wrap again), since
  every payload under the old KEK then fails to unwrap. If an older DEK
  being reused would matter, record which payload is current somewhere
  the file's writer can't change, such as its SHA-256.
- **Length.** Anything other than exactly 125 bytes is `fileTooShort`
  (-35) or `fileTooLong` (-36).
- **Unprotected key.** A file holding a bare 32-byte DEK instead of a
  payload — raw bytes, or base64 (padded or not, standard or URL alphabet)
  or hex text, with optional surrounding whitespace, 96 bytes at most — is
  reported as `fileUnprotectedKey` (-37), not merely as too short. The
  check is the Linux and Windows one, and like theirs it runs in constant
  time in the file's contents and never decodes them. The key was stored
  unprotected: treat it as exposed and rotate it, rather than wrapping it
  now. Its bytes never reach the caller's buffer, and the library zeroes
  its own read buffer on every return.
- **Malformed.** A 125-byte file whose KEK fingerprint is all zeros is
  `fileMalformed` (-38), and so is one whose suite byte is neither `0x01`
  nor `0x02`: as
  on Linux and Windows, every format problem in a key file is this one code
  (unwrap, given the same bytes, reports the suite as -12). These are structural checks only: whether the payload is genuine,
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
| `-3`  | `ERR_PROVIDER_UNAVAILABLE` | `enclaveUnavailable` | no Secure Enclave on this machine; or, from `hkdfguard_create_kek`, one that can't create the KEK suite the policy asks for (ML-KEM-1024 needs macOS 26 or later). Never answered by creating a P-256 KEK instead: `KekSuite` `P-256` is the opt-in |
| `-5`  | `ERR_CRYPTO_ERROR` | `encryptionFailed` | the RNG failed, the Secure Enclave refused the key agreement (wrap or unwrap), or AES-GCM sealing failed |
| `-6`  | `ERR_INTERNAL_ERROR` | `unexpectedOutputLength` | an internal failure the library detected: output of an impossible length, or a buffer that should exist not existing (a bug). Linux also returns it for a caught panic; a Swift runtime trap can't be caught, so this library has no force-unwrap, `try!`, `fatalError` or `precondition` on its export paths (a test enforces it), and returns -6 where Linux would have caught one |
| `-8`  | `ERR_INVALID_SERVICE_NAME` | `invalidServiceIdentifier` | see `service` above |
| `-9`  | `ERR_POLICY_INVALID` | `policyInvalid` | the production policy can't be used (an unknown setting, a wrong type, not root's, or a runner group that doesn't exist or is too broad); **every** call fails until it is fixed |
| `-10` | `ERR_PAYLOAD_MALFORMED` | `payloadMalformed` | `wrapped_len != 125` |
| `-11` | `ERR_PAYLOAD_AUTH_FAILED` | `decryptionFailed` | the AES-GCM tag did not verify: an altered payload, or one wrapped for a different service under the same KEK |
| `-12` | `ERR_PAYLOAD_UNSUPPORTED` | `unsupportedCiphersuite` | the payload's suite byte is not one this build implements; a newer or different build wrote it. Not tampering. Also a P-256 (`0x01`) payload under the policy's `RequirePostQuantum`: wrap the DEK again under the service's new KEK |
| `-16` | `ERR_KEK_FINGERPRINT_MISMATCH` | `fingerprintMismatch` | payload was wrapped under a different KEK |
| `-17` | `ERR_KEK_NOT_FOUND` | `kekNotFound` | no KEK for this service in this process's keychain mode; call `hkdfguard_create_kek` |
| `-18` | `ERR_KEK_ACCESS_DENIED` | `keychainAccessDenied` | locked keychain / no UI session / ACL denial / declined prompt / missing entitlement / Secure Enclave won't load keys in this session (keybag locked, e.g. SSH after `security unlock-keychain`) / an ML-KEM KEK on a macOS before 26. **A key likely exists**; don't create or delete anything. Also, from wrap and provision, a P-256 KEK under the policy's `RequirePostQuantum`: `hkdfguard status` says so; retire it and provision again |
| `-19` | `ERR_KEK_INVALID` | `kekCorrupted` | an item exists but can't be reconstructed into a key, and a throwaway probe key shows the enclave works in this session; never auto-replaced |
| `-20` | `ERR_PROCESS_HARDENING_FAILED` | `processHardeningFailed` | `hkdfguard_harden_process` couldn't disable core dumps or debugger attachment, or (with `HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE`) the process can still be debugged by its own user |
| `-32` | `ERR_FILE_NOT_FOUND` | `fileNotFound` | no file at the path, or a path component is not a directory (`hkdfguard_open_file` only, as are `-33` to `-39`) |
| `-33` | `ERR_FILE_ACCESS_DENIED` | `fileAccessDenied` | this process may not read the file or a directory on its path |
| `-34` | `ERR_FILE_IO` | `fileIO` | a directory, FIFO, socket, or device; or `open`/`fstat`/`read` failed |
| `-35` | `ERR_FILE_TOO_SHORT` | `fileTooShort` | fewer than 125 bytes, and not a plaintext DEK |
| `-36` | `ERR_FILE_TOO_LONG` | `fileTooLong` | more than 125 bytes |
| `-37` | `ERR_FILE_PLAINTEXT_KEY` | `fileUnprotectedKey` | the file appears to hold a bare, unwrapped DEK (any 32-byte value as raw/base64/hex matches). **Treat the key as exposed** and rotate it |
| `-38` | `ERR_FILE_MALFORMED` | `fileMalformed` | 125 bytes, but the fingerprint is all zeros |
| `-39` | `ERR_FILE_UNTRUSTED` | `fileInsecure` | a symbolic link (refused, never followed); owned by someone other than this user or root, or writable by group or others; or an ACL lets someone else change it; or it is on a volume that ignores ownership; or a folder above it is owned by someone else, writable by group or others without being sticky, or has an ACL letting someone else add or remove entries |
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

### What the legacy-mode ACL checks, and what it doesn't

A legacy-mode item's ACL lists the programs allowed to use it without a
prompt: the one that created it, plus any an operator approved with
"Always Allow". "Program" means the **main executable of the process**
that asks, identified by its code signature. That has three consequences:

- **The library and the calling code are never checked.** The ACL sees the
  process's executable, not `libhkdfguard.dylib` and not whatever script,
  assembly or jar made the call.
- **An interpreter is one program, whatever it runs.** For a consumer
  launched as `python3 app.py`, `node app.js`, `java -jar app.jar` or
  `dotnet App.dll`, the approved program is the shared interpreter. Every
  other script that interpreter runs as the same user then passes the same
  ACL, with no prompt, including one someone else dropped into that
  user's home folder. The approval amounts to "this user, through this
  interpreter", not "this application".
- **What identifies the program is its signature.** A Developer ID
  signed executable is matched by its Team and identifier, so rebuilds and
  updates keep the approval; an ad-hoc or unsigned one by its hash, so
  every rebuild prompts again.

So for a service written in an interpreted or managed language:

- **Prefer data-protection mode**: package the service as a Team-signed
  app bundle carrying the `keychain-access-groups` entitlement and a
  provisioning profile (an interpreter embedded in a signed bundle
  qualifies). There, securityd decides from that bundle's signed identity,
  and a script run by a stock interpreter can't present it.
- **Otherwise, ship it as its own signed executable** (a .NET apphost or
  single-file publish, a PyInstaller or Nuitka binary), so the approval
  covers that program alone. See [Consuming this library](#consuming-this-library).
- **Never approve a shared interpreter** (`/usr/bin/python3`, a Homebrew
  `node`, `dotnet`) for a production KEK unless every program that
  interpreter may run as that user is equally trusted.

Either way the user account remains the boundary (see
[The trust boundary](#the-trust-boundary)): code running as the service's
user can also read its files and, unless the process runs with the
hardened runtime, attach a debugger to it.

### A KEK item can be planted ahead of time

The ACL protects an item **after** it exists, but it does not control who
creates it. In legacy mode, any process running as the same user can create
the service's KEK item in the login keychain before HkdfGuard does. It can
store a Secure Enclave key of its own there, under its own ACL. `provision`
then finds an item already present. It reports "already provisioned"
and prints that key's fingerprint, and every DEK wrapped afterwards is
sealed to a key the other process controls. **Legacy mode trusts every
process running as that user**, not just the ones the ACL lists.

Data-protection mode narrows this to apps signed by the same Team that list
the same access group. A stock interpreter or a dropped-in script running as
the user can't write there. **Prefer data-protection mode** (the bundled
`hkdfguard.app` CLI and Team-signed consumers) for production KEKs.

In either mode, the fingerprint is how a planted or swapped item is
caught:

- On `provision`, "already provisioned" for a service you have never
  provisioned means someone else created the item. Don't use it.
  Retire it, then provision again.
- `wrap --fingerprint <recorded value>` refuses to write a payload sealed
  to any other KEK. Make it the normal way to wrap, and especially the
  **first** wrap, which has nothing else to compare with; `wrap` warns when
  neither check applies.
- `wrap --force` over an existing wrapped key, without `--fingerprint`, is
  pinned to the KEK that file was wrapped under. It refuses a different
  one and leaves the old file intact.

The C ABI does none of this for you. `hkdfguard_wrap_dek` wraps under
whatever item the service name resolves to. A consumer that wraps should
compare the first 32 bytes of the payload with its recorded fingerprint
before storing it (see `wrap --fingerprint` below). 

## Access policy and headless use

This section describes **user-scoped** KEKs: every KEK with no policy, and
any service a production policy doesn't list. Machine-scoped KEKs differ;
see [Production mode](#production-mode-machine-scoped-keks).

Every user-scoped KEK is created with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and
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

The access policy of a user-scoped KEK is fixed. The library has no
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
   stops unwrapping.

`retire` is not a crypto-shred. It deletes the KEK's keychain item or key
file, which holds the Secure Enclave key in the only form it is stored in.
A copy taken before the retire still holds it: a Time Machine or other
backup of the login keychain or of `/Library/Application Support`, or a
local APFS snapshot. Restored onto the same Mac, that copy unwraps every
payload under the KEK again. (On another Mac it is useless: only this Mac's
Secure Enclave can use it.) The machine KEK folder is excluded from Time
Machine, but local snapshots and backup tools that ignore Time Machine's
exclusions still keep it. If a retire must hold, delete the local snapshots
taken before it (`tmutil listlocalsnapshots /`, then
`sudo tmutil deletelocalsnapshots <date>`) and any backups that hold the
KEK.

## Production mode: machine-scoped KEKs

With no policy, every KEK is user-scoped, as above: one person may
provision, wrap and unwrap. That is **development mode**. A **production
policy** can make chosen services machine-scoped instead, which separates
the roles:

| Role | Does | As | Allowed by the policy's |
|---|---|---|---|
| Security admin | `provision`, `retire` | `sudo` | `SecurityAdminGroup` |
| Deployment admin | `wrap` | `sudo` | `DeploymentAdminGroup` |
| Application runtime | `hkdfguard_open_file` + `hkdfguard_unwrap_dek` | a LaunchDaemon running as a member of the service's `RunnerGroup` | `MachineServices` |

A machine KEK suits a service that runs as a LaunchDaemon: it works logged
out, at the login window, and after an unattended restart
(`sudo fdesetup authrestart`), and survives password resets and account
changes, which a user's keychain does not.

### The policy

On a managed Mac, deliver it as a configuration profile for the preference
domain **`com.hkdfguard`** (Jamf "Application & Custom Settings", an Intune
custom profile, and so on), scoped to the device. macOS writes it to
`/Library/Managed Preferences/com.hkdfguard.plist`. On a Mac without MDM,
put the same keys in `/Library/Application Support/HkdfGuard/policy.plist`
(`root:wheel 0644`). The managed one wins when both exist. Either must be
root's and writable only by root, as must every folder above it.

```xml
<dict>
  <key>MachineServices</key>
  <dict>
    <key>com.example.orders</key>
    <dict><key>RunnerGroup</key><string>_orders</string></dict>
  </dict>
  <key>SecurityAdminGroup</key><string>secadmins</string>
  <key>DeploymentAdminGroup</key><string>deployers</string>
</dict>
```

The library reads the policy as a file and checks every setting. An
unknown key (a misspelling, say) or a wrong type makes the policy
**invalid**, and then every call, for every service, fails with `-9`
(`POLICY_INVALID`) until it is fixed: a misspelt `MachineServices` must not
quietly leave a production service user-scoped. `hkdfguard status` prints
why. Services the policy doesn't list stay user-scoped. Leaving out
`SecurityAdminGroup` or `DeploymentAdminGroup` lets any admin who can
`sudo` act in that role.

### KEK suites in the policy

Two more settings choose the [KEK suite](#kek-suites). They apply to every
service, user-scoped and machine-scoped alike, and a policy may hold only
them: it then leaves every service user-scoped, as no policy does.

| Setting | Values | Without it |
|---|---|---|
| `KekSuite` | `ML-KEM-1024` or `P-256` | `ML-KEM-1024`, also with no policy at all |
| `RequirePostQuantum` | a boolean (`<true/>`, `<false/>`; not `<integer>`) | `false` |

```xml
<dict>
  <!-- The opt-in to classical KEKs, e.g. for Macs before macOS 26: -->
  <key>KekSuite</key><string>P-256</string>
</dict>
```

- **`KekSuite`** is what `hkdfguard_create_kek` (and `hkdfguard provision`)
  creates. A Mac that can't create that suite -- ML-KEM-1024 needs macOS 26
  or later -- fails with `-3` (`PROVIDER_UNAVAILABLE`) and logs why; it
  never quietly creates a P-256 KEK instead, so the default can't silently
  mean nothing. It doesn't touch existing KEKs: a KEK keeps the suite it was
  provisioned with, and provisioning never replaces one.
- **`RequirePostQuantum`** refuses what is left of P-256: a P-256 KEK can't
  wrap or be provisioned (`-18`), and a `0x01` payload can't be unwrapped
  (`-12`). Its existence, fingerprint and suite can still be read, so
  `hkdfguard status` shows it, flagged, and `hkdfguard retire` removes it.
  `KekSuite` `P-256` with `RequirePostQuantum` `true` contradict each other,
  and make the policy invalid.

`hkdfguard status` prints what the policy provisions and each KEK's suite;
an application can read a KEK's with `hkdfguard_kek_suite`.

### Moving to post-quantum KEKs

A KEK's suite can't change, so a P-256 service moves by rotation:

1. Make sure the policy provisions ML-KEM-1024 (no `KekSuite`, or
   `ML-KEM-1024`), on macOS 26 or later.
2. `hkdfguard retire` the old KEK, `hkdfguard provision` a new one, and
   wrap the service's DEKs again under it -- or, to keep the old payloads
   readable while the new ones go out, provision under a new service name
   and retire the old one last (see [If a KEK is compromised](#if-a-kek-is-compromised)).
3. Once no service has a P-256 KEK left (`hkdfguard status`), set
   `RequirePostQuantum` so none can come back.

### The service account and its runner group

Run the service's LaunchDaemon as a dedicated account that cannot log in,
and make it the only member of the `RunnerGroup`. People must never be
members: the group is what can read the KEK file.

```sh
sudo dseditgroup -o create -r "Orders service" _orders
sudo dscl . -create /Users/_orders UserShell /usr/bin/false   # plus UniqueID, PrimaryGroupID, IsHidden 1, NFSHomeDirectory /var/empty
sudo dseditgroup -o edit -a _orders -t user _orders
```

The library refuses a `RunnerGroup` that covers too many accounts (`staff`,
`everyone`, `localaccounts`, `admin`, `com.apple.access_ssh`, …).

### Provisioning, wrapping and retiring

```sh
sudo hkdfguard provision -sn com.example.orders            # security admin
# machine KEK provisioned for service "com.example.orders" at
#   /Library/Application Support/HkdfGuard/keks/com.example.orders.kek (runner group: _orders)
# fingerprint: 3f1c…e09a -- record this; retire requires it

printf '%s' "$DEK_B64" | sudo hkdfguard wrap \
    -kf /Library/Application\ Support/Orders/dek.key -sn com.example.orders \
    --dek-stdin -fp 3f1c…e09a                               # deployment admin

sudo hkdfguard retire -sn com.example.orders -fp 3f1c…e09a # security admin
```

- **The role is checked against the admin behind `sudo`**: the account that
  logged in to the session, which `sudo` doesn't change. `sudo` alone isn't
  enough. A root login is trusted.
- **The Secure Enclave work runs in a one-off LaunchDaemon job.** The
  Secure Enclave binds a key to the context it was created in, so a key
  made from Terminal, `sudo` included, would be unusable by the service's
  daemons. `provision` and `wrap` hand that step to a short-lived system job
  running the same `hkdfguard` executable. The DEK goes to it through a FIFO
  in a root-only folder, so it never touches disk. That folder is made in
  `/Library/Application Support/HkdfGuard/v1/jobs`, and the job runs only if
  it and every folder above it are owned and writable by root alone, so no
  other account can swap the job's definition, its DEK channel or its answer.
  If the CLI dies before sending the DEK, the job gives up after 30 seconds
  and removes its folder; a folder left by a crashed run is removed on the
  next one. The job runs only if the
  `hkdfguard` executable and the library it loaded are root's and writable
  only by root, which the installed package's are; a build run from a
  source tree is refused.
- **`wrap` gives the key file to the `RunnerGroup`** (`0640`) unless
  `--group` says otherwise, so the daemons can read it.
- **`retire` deletes the KEK file** after confirming the fingerprint, and
  writes audit event 1004. Every payload wrapped under it stops unwrapping,
  unless the file comes back from a snapshot or backup (see "If a KEK is
  compromised").

### What the runtime can and can't do

The application calls the same functions as for a user-scoped KEK. For a
machine-scoped service:

- **Only LaunchDaemons can unwrap.** A process in a login session
  (Terminal, `sudo` from it, a GUI app, SSH) gets `-18`
  (`KEK_ACCESS_DENIED`). The library refuses those sessions itself, and the
  Secure Enclave would refuse them anyway: a key created by a daemon can't
  be used from a login session.
- **Only root and `RunnerGroup` members can read the KEK file**; anyone else
  gets `-18`.
- **The KEK file** is `/Library/Application Support/HkdfGuard/keks/<service>.kek`,
  `root:<RunnerGroup>` `0640` (`0600` with no `RunnerGroup`). A P-256 KEK's
  (format 1) holds the public key and the Secure Enclave key blob; an
  ML-KEM-1024 KEK's (format 2) holds the suite, the 32-byte fingerprint,
  the blob and the stored ciphertext, and no public key. Either way
  `status` and `retire` read the fingerprint from the file, without the
  Secure Enclave. The blob is usable only by this
  Mac's Secure Enclave, in the system context, after the first unlock since
  boot (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`). `provision`
  excludes the `keks` folder from Time Machine; local APFS snapshots still
  hold it. A file that
  isn't root's, that anyone else can write, that others can read, or that
  this library didn't write is `-19` (`KEK_INVALID`).
- **Root is trusted.** Root can read the file and install a LaunchDaemon, so
  an admin who can `sudo` can ultimately use the key, as with every secret
  store on macOS. If admins reaching a Mac over SSH is a concern, turn off
  Remote Login through MDM, and forward the `com.hkdfguard` log to your SIEM.

### Verifying it on a Mac

`scripts/verify-machine-scope.sh` runs the whole flow against this repo's
builds, as root, once per KEK suite (ML-KEM-1024 by default, then P-256
through `KekSuite`):
- provisioning, with both role refusals, and the KEK file in its suite's
  format;
- wrapping in the system job, the payload naming the suite;
- a `nobody` LaunchDaemon unwrapping, while root in Terminal and an account
  outside the group are refused;
- for P-256, `RequirePostQuantum`: the KEK flagged by `status`, refused for
  wrap, provision and unwrap, and still retirable;
- `retire`.

Before macOS 26 the ML-KEM pass only checks that provisioning refuses
rather than creating a P-256 KEK.

It cleans up after itself, and refuses to run where a real policy exists.

```sh
sudo bash scripts/verify-machine-scope.sh
```

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
                             [--group|-g <name>] [--fingerprint|-fp <64 hex chars>] [--force|-f]

hkdfguard retire --service-name|-sn <name> \
                               ( --fingerprint|-fp <64 hex chars> | --corrupt )
```

- **`provision`** creates the KEK for `<name>` if it doesn't exist. The only
  command that creates keys; idempotent. As on Linux and Windows it always
  calls `hkdfguard_create_kek`, which for an existing KEK loads the keychain
  item and rebuilds the Secure Enclave key from it, so a KEK that exists but
  can't be used fails here, at deployment, not at the first wrap; a second
  run reports "already provisioned …; verified" and exits 0. Prints the
  keychain mode it used, the KEK's suite (`ML-KEM-1024`, or `P-256` where
  the policy's `KekSuite` opts in; see [KEK suites in the policy](#kek-suites-in-the-policy)),
  and its **fingerprint** (SHA-256 of its public key) — record it. On "already provisioned", compare it with the
  recorded value: a mismatch means the KEK under that name is not the one
  you provisioned.
- **`status`** reports the keychain mode, the suite the policy provisions,
  whether a KEK exists for `<name>` (`present`, `absent`, or `corrupt`), and
  its fingerprint and suite -- flagging a P-256 KEK the policy's
  `RequirePostQuantum` refuses. Read-only: it
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
  two — under the already-provisioned KEK and writes the 125-byte payload to
  `<path>`. It never creates a KEK (an unprovisioned service is an error
  naming the `provision` command) and never generates a DEK. There is
  deliberately no `--dek <base64>` argument: an argv value is visible to
  every process via `ps` and lands in shell history. `--dek` is refused
  with an explanation.
  - *`--group|-g <name>` (as on Linux and Windows).* The file is written
    `0600` (owner read/write) by default. With `--group` it is `0640` and
    given that group, so the group's members can read it too. The group is
    set on the open file before a byte is written. Name a dedicated group
    for the service that unwraps the key, one you belong to (or run as
    root); a group name or a numeric gid both work. Groups that cover
    essentially every account or the administrators -- `staff`,
    `everyone`, `localaccounts`, `netaccounts`, `admin`, `wheel`, `nobody`,
    `nogroup`, and gid 0 -- are refused, by resolved gid, before the DEK is
    read.
  - *`--dek-file` rules (same as the Linux tool).* The file must be a
    regular file -- a symbolic link is refused, never followed, and a FIFO
    or device is refused without blocking -- owned by root or by the user
    running the CLI, and grant no access to group or others (for example
    mode `0400` or `0600`; the owner's bits aren't checked). This is
    stricter than what `hkdfguard_open_file` asks of a key file, which may
    be group- or world-readable: the DEK file holds the plaintext key, the
    key file only ciphertext. Every check is made on the opened descriptor,
    so it describes the file that is read. A file carrying an access
    control list is refused too, whatever its mode bits: an ACL can grant
    read to anyone.
  - *No symbolic link above a path (same as the Linux tool).* Neither
    `--key-file-path` nor `--dek-file` may be reached through a symlinked
    folder: whoever could plant one where the operator writes could redirect
    a `wrap --force` into overwriting a file elsewhere, or make `wrap` read a
    DEK they put somewhere else. `..` is resolved as text first, and the
    opened file is confirmed to be the one at the checked path. macOS's own
    root-owned links -- `/tmp`, `/var`, `/etc` into `/private` -- are
    accepted: a link owned by root in a root-owned folder no one else can
    write is followed to its real folder; any other link is refused.
  - *Input handling (same as the Linux tool).* At most 64 bytes are
    accepted -- base64 of a 32-byte DEK is 44 characters -- and anything
    longer is refused before it is read in full. One trailing newline (or
    CRLF) is ignored and nothing else: leading spaces, trailing spaces, or a
    second newline make the input invalid base64. A leading UTF-8
    byte-order mark (PowerShell, .NET) is skipped; UTF-16 input is refused
    with a message saying how to send UTF-8. `--dek-stdin` refuses an
    interactive terminal, where a typed or pasted DEK would be echoed and
    kept in the scrollback. Decoding is strict, padded standard base64, in
    constant time with respect to the text, and every malformed input gets
    the same fixed message, which quotes none of it. The text and the decoded DEK live in one
    fixed-size buffer locked into memory with `mlock` (a warning is printed
    if the lock is refused), are never held as a string, and are zeroed on
    every exit path.
  - *Output file.* Created with POSIX `0600` permissions set at creation
    (owner read/write, nothing for anyone else). Any access control list the
    folder would pass on to a new file is stripped before the payload is
    written -- a folder's inheritable ACE would otherwise make the file
    readable by principals the mode doesn't show -- and if it can't be
    stripped nothing is written. Then the file and its
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
  under it". It is the normal way to wrap: use it in every scripted
  pipeline, and always on a service's first wrap, which nothing else can
  check (see [A KEK item can be planted ahead of time](#a-kek-item-can-be-planted-ahead-of-time)).
  When a wrap has neither `--fingerprint` nor an existing key file to pin
  to, `wrap` prints a warning on stderr; it still exits `0`. ABI consumers
  get the same guarantee by comparing the first 32 bytes of the payload
  `hkdfguard_wrap_dek` returns against their recorded fingerprint before
  storing it.
- **`--force`** securely overwrites an existing `<path>` (eight alternating
  zero/random passes, each flushed with `F_FULLFSYNC`) before replacing it.
  It refuses a file over 64 KiB, as the Linux tool does: a wrapped key is
  125 bytes, so anything far bigger at the key path isn't one. When the
  existing file is a wrapped key and `--fingerprint` is not given, the KEK
  that file was wrapped under is the pin. A wrap under a different KEK is
  refused, with both fingerprints named. To move a service to a deliberately
  replaced KEK (re-provisioned after `retire`), name the new KEK with
  `--fingerprint`. Either mismatch is detected before the overwrite
  starts, so the existing file is left intact. It only ever
  touches a **regular file with a single link**: a symlink at `<path>` is
  refused rather than followed (`O_NOFOLLOW` + `fstat`), and so is a file
  with more than one hard link, since overwriting it would also destroy
  whatever other file shares its contents. A FIFO, device, or directory is
  refused too.

Exit codes: `0` success, `1` runtime failure, `2` argument error (usage
printed). Nothing persistent is touched until every argument is validated.
Each flag may be given once, and a flag's value may not start with `-`:
`wrap -kf --force ...` is an argument error, not a key file named
`--force`. Write a path that starts with `-` as `./-name`.

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
Requires a **Swift 6.2+** toolchain (compile-time `#error` guard). Every
target -- the framework, the dylib, both CLI builds, the test bundle, and
the test host -- targets **macOS 14.0+**, set explicitly rather than left
to Xcode's recommended value, which differs between Xcode versions (Xcode
26 recommends 11.0, too old for the library's `OSAllocatedUnfairLock` and
`Duration`).

Supporting scripts: `build-dist.sh` (signed, notarized build artifacts,
below), `build-pkg.sh` with `pkg/` (the installer package — the only way the
library is installed; see [Installing on a machine](#installing-on-a-machine)),
and `setup-hosted-test-kek.sh` (a one-time, per-developer provisioning of a
data-protection KEK in the test-only access group, under
`com.hkdfguard.fixture.hostedtests`; see Tests). `.github/` holds the CI
and release workflows (see [Continuous integration](#continuous-integration)).

## Building

```sh
# Framework, embeddable in a signed app:
xcodebuild -project HkdfGuardNativeMacOS.xcodeproj \
  -scheme HkdfGuardNativeMacOS -configuration Release build

# Standalone dylib for FFI:
xcodebuild -project HkdfGuardNativeMacOS.xcodeproj \
  -target HkdfGuardNativeMacOSDylib -configuration Release build

# CLI (links against build/Release by default; override with HKDFGUARD_DYLIB_DIR):
swift build -c release --package-path hkdfguard-cli

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
| `HKDFGUARD_ASC_KEY_PATH`, `HKDFGUARD_ASC_KEY_ID`, `HKDFGUARD_ASC_ISSUER_ID` | optional App Store Connect API key (path to the `.p8`, kept outside the repo) so `xcodebuild` can manage provisioning profiles without an Apple ID signed in to Xcode; otherwise it uses the account in Xcode → Settings → Accounts. Not used with `HKDFGUARD_APP_PROFILE` |
| `HKDFGUARD_APP_PROFILE` | optional name of an installed **Developer ID provisioning profile** for `com.hkdfguard.cli`. When set, `hkdfguard.app` is archived and exported with manual signing — the `HKDFGUARD_SIGN_IDENTITY` certificate and this profile — and `xcodebuild` never contacts Apple for a certificate or profile. Requires a Developer ID identity. Checked before building: exactly one installed, Developer ID, this team and bundle ID, the `com.hkdfguard.keys` access group, not expired |
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
anything, so a missing one fails in seconds. By default the Developer ID
provisioning profile is created by `xcodebuild` during export (automatic
signing, `-allowProvisioningUpdates`). To sign with a profile you made in
the developer portal instead — as `release.yml` does, with
`hkdfguard_app_profile` — install it with Xcode → Settings → Accounts →
Download Manual Profiles (double-clicking the file does not put it where
Xcode looks) and add
`HKDFGUARD_APP_PROFILE=hkdfguard_app_profile`.

## Continuous integration

Two GitHub Actions workflows, in `.github/workflows/`, both on
GitHub-hosted Apple silicon runners (`macos-26`, Xcode 26.6, and for one
job `macos-15`):

| Workflow | Runs on | Does | Credentials |
|---|---|---|---|
| `ci.yml` | every push to `main`, every pull request, by hand, and as the first job of `release.yml` | the unhosted test suite and the shipped Release configurations, all ad-hoc signed; then, on macOS 15, those Release binaries run and the test suite | none |
| `release.yml` | a pushed `vX.Y.Z` tag, or by hand | `ci.yml`, then `build-release.sh` — signed, notarized, stapled — and, for a tag, the GitHub Release | the `release` environment's secrets |

**macOS 15.** The library's deployment target is macOS 14, but ML-KEM is
macOS 26 only. An ML-KEM API reached without an availability check would
break the library on every older Mac, for P-256 too. The `test-macos-15`
job, on `macos-15` (the oldest macOS GitHub hosts), checks that in two ways:

- It loads the `macos-26` job's Release dylib and runs its CLI, the
  binaries a release ships. A missing symbol kills them at load. The
  unsigned strict-hardening CLI then refuses to go on, which is expected.
- It builds and runs the test suite with the newest Xcode 26 on that image.
  The tests can't be built on `macos-26` and moved, because a test bundle
  only loads under the Xcode that built it.

The job checks out the repositories in the same layout as the `macos-26`
job, because the CLI finds the dylib by an absolute path.

What a macOS 15 VM can't show is the Secure Enclave side: provisioning
failing with `-3` instead of creating a P-256 KEK, and a stored ML-KEM KEK
being refused with `-18`, never reported corrupt. On real hardware, the
`withoutMLKEM` tests act that out on macOS 26: a test-only switch,
`MachineScopeTestOverrides.withoutMLKEM`, makes the Secure Enclave neither
create nor load ML-KEM keys. Production never sets it.

**What CI can't test.** A macOS VM has no Secure Enclave, so every test
that wraps or unwraps skips itself there (see [Tests](#tests)), and the
hosted suite and `scripts/verify-machine-scope.sh` need a registered Mac,
root and LaunchDaemons. A green CI run proves the build, the argument
handling, the key file checks and the cross-platform ABI. It does not prove
the cryptography. Before tagging a release, run the full suite on real
Apple silicon:

```sh
xcodebuild test -scheme HkdfGuardNativeMacOSTests
xcodebuild test -scheme HkdfGuardNativeMacOSTests-Hosted -allowProvisioningUpdates
sudo bash scripts/verify-machine-scope.sh
```

**Unsigned builds.** `ci.yml` sets `XCODE_XCCONFIG_FILE` to
`.github/ci/unsigned.xcconfig` (ad-hoc signing, no team, no profile). It
passes the same file as `TEST_RUNNER_XCODE_XCCONFIG_FILE`, so the
`xcodebuild` that `HkdfGuardCommandLineToolTests` runs inside the test
process builds unsigned too. To reproduce a CI run locally:

```sh
X="$PWD/.github/ci/unsigned.xcconfig"
XCODE_XCCONFIG_FILE="$X" TEST_RUNNER_XCODE_XCCONFIG_FILE="$X" \
  xcodebuild test -scheme HkdfGuardNativeMacOSTests -destination 'platform=macOS,arch=arm64'
```

`HkdfGuardCrossPlatformABITests` needs `hkdfguard-native-linux` checked
out beside this repository; `ci.yml` checks it out there. If that
repository is private, give the workflow a repository secret
`LINUX_REPO_TOKEN`: a fine-grained token with read-only *Contents* access to
`runsecure/hkdfguard-native-linux` and nothing else. Without one the
checkout fails, the run shows a warning, and those tests skip themselves.

### Setting up `release.yml`

The signing credentials are **environment** secrets, not repository
secrets, so no other workflow or job can read them. Once, under
*Settings > Environments*, create an environment named `release`:

- **Required reviewers:** the people who hold the Developer ID
  certificates. Every run waits for one of them to approve it.
- **Deployment branches and tags:** *Selected branches and tags*: the tag
  pattern `v*`, and the branch `main` for manual dry runs.

Then, under *Settings > Rules > Rulesets*, add a tag ruleset for `v*` that
only administrators can bypass, so not everyone with write access can
create a release tag.

Its secrets:

| Secret | Value |
|---|---|
| `DEVELOPER_ID_APPLICATION_P12` | base64 of the *Developer ID Application* certificate and private key, exported from Keychain Access as `.p12` |
| `DEVELOPER_ID_INSTALLER_P12` | the same for the *Developer ID Installer* certificate |
| `SIGNING_P12_PASSWORD` | the password both `.p12` files were exported with |
| `DEVELOPER_ID_PROVISIONING_PROFILE` | base64 of the `hkdfguard_app_profile` Developer ID provisioning profile for `com.hkdfguard.cli`, downloaded from *Certificates, Identifiers & Profiles > Profiles*. The workflow refuses a profile with any other name (`HKDFGUARD_APP_PROFILE` in `release.yml`) |
| `ASC_KEY_P8` | the contents of an App Store Connect API key's `AuthKey_<id>.p8` (*Users and Access > Integrations > Team Keys*), used only to notarize. The **Developer** role is enough: `xcodebuild` signs with the installed profile and is never given the key |
| `ASC_KEY_ID` | that key's ID |
| `ASC_ISSUER_ID` | the team's issuer ID, shown above the keys list |

```sh
base64 -i DeveloperIDApplication.p12 | pbcopy   # paste as DEVELOPER_ID_APPLICATION_P12
base64 -i DeveloperIDInstaller.p12 | pbcopy     # paste as DEVELOPER_ID_INSTALLER_P12
base64 -i hkdfguard_app_profile.provisionprofile | pbcopy   # paste as DEVELOPER_ID_PROVISIONING_PROFILE
```

The installing step prints the profile's expiration date. Regenerating or
renewing it in the portal gives a new file, so update the secret then too;
`build-dist.sh` refuses an expired profile before anything is built.

The workflow imports the certificates into a throwaway keychain, which it
makes the default for the job, and installs the provisioning profile. It
stores the API key in that keychain as the `hkdfguard-notary` notarytool
profile, runs `build-release.sh` with
`HKDFGUARD_APP_PROFILE=hkdfguard_app_profile`, and deletes the keychain,
key and profile whether or not the build succeeded. Run it by hand from `main`
first: that run does everything except publish, and uploads the `.pkg` as a
workflow artifact, so you can test the signing setup without making a
release.

## Publishing a release

The only distribution is a signed, notarized **installer package** attached
to a tagged GitHub Release. There are no zips, no NuGet package, and no
install scripts: a Mac gets the library by installing the package, and
nothing else puts it in place. Every machine trusts exactly one signed
artifact, built by `release.yml` from a `vX.Y.Z` tag on `main`. The signing
keys live only in the protected `release` environment (see
[Setting up `release.yml`](#setting-up-releaseyml)).

That moves the trust boundary from one Mac to GitHub. Anyone who can
approve a run in the `release` environment, or change `release.yml` or the
build scripts on `main`, can ship code that every installed Mac trusts.
Keep its reviewers to the people who hold the Developer ID certificates,
and require reviews on `main`.

To release, make sure `MARKETING_VERSION` in the Xcode project is the new
version, run the full suite on real hardware (see
[Continuous integration](#continuous-integration)), then push a signed tag:

```sh
git tag -s v0.9.1 -m v0.9.1   # must equal v<MARKETING_VERSION>
git push origin v0.9.1
```

The workflow checks that the tag matches `MARKETING_VERSION` and is on
`main`. After a reviewer approves, it builds, notarizes and publishes the
Release, with the package's SHA-256 in the release notes.

To build and publish one by hand instead (the workflow runs the same
steps):

```sh
VERSION=v0.9.1   # must equal MARKETING_VERSION in the Xcode project

HKDFGUARD_RELEASE=1 \
HKDFGUARD_SIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)" \
HKDFGUARD_NOTARY_PROFILE=hkdfguard-notary \
./build-dist.sh

HKDFGUARD_NOTARY_PROFILE=hkdfguard-notary ./build-pkg.sh
PKG="hkdfguard-native-macos-${VERSION#v}-osx-arm64.pkg"

# The checksum goes in the release notes -- outside the asset, so replacing
# the package cannot also replace the value it is checked against.
{
  echo "Install with the checks in the README's \"Installing\" section."
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

`build-pkg.sh` refuses anything but a `HKDFGUARD_RELEASE=1` build. The
package carries a Developer ID Installer signature and a stapled
notarization ticket, but nothing forces a machine to check them: Finder
and MDM tools do, while `sudo installer -pkg` installs an unsigned or
re-signed package without a word. That is why the
[install commands](#installing) check the checksum, the signing Team and
Gatekeeper's verdict themselves, and stop on any failure. Confirm the tag
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

`sudo installer -pkg` checks nothing on its own: it installs an unsigned
package, or one re-signed by anyone, without a warning. So check the
package first, and install only if every check passes:

```sh
set -e
VERSION=v0.9.1
TEAM_ID=MFW3T8R8J3                        # the Team that signs this project's releases
EXPECTED=<the SHA-256 from the release notes>
PKG="hkdfguard-native-macos-${VERSION#v}-osx-arm64.pkg"

gh release download "$VERSION" --pattern "$PKG"
echo "$EXPECTED  $PKG" | shasum -a 256 -c                             # the bytes released
pkgutil --check-signature "$PKG" | grep -q "Developer ID Installer: .* ($TEAM_ID)$"  # signed by that Team
spctl --assess --type install -v "$PKG"                               # Gatekeeper: notarized, not revoked
sudo installer -pkg "$PKG" -target /
pkgutil --pkg-info com.hkdfguard.native   # the receipt, with the installed version
```

Each check exits non-zero on failure, and `set -e` stops before
`installer` runs. Take `EXPECTED` from the release notes, not from a
`.sha256` file downloaded beside the package: whoever could replace the
package could replace that too.

Double-clicking the package in Finder works too. For a fleet, upload the
package to your MDM (Jamf, Intune, Kandji, …) and scope the policy to Apple
silicon Macs; MDM tools verify the Developer ID Installer signature
themselves. Installing a newer package over an older one upgrades `v1/` in
place. Installer does not refuse an *older* package over a newer one — it
replaces `v1/` as a whole, so the result is a consistent downgrade, not a
mix — so have the MDM policy or the operator compare
`pkgutil --pkg-info com.hkdfguard.native` first.

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
the package receipt. **KEKs are not touched**: user-scoped ones live in each
user's keychain, and machine-scoped ones in
`/Library/Application Support/HkdfGuard/keks`, outside `v1/`, as does a local
`policy.plist`. Retire any that should go *before*
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
owned by root and not group- or world-writable, and that the dylib's code
signature satisfies this requirement:

```
identifier "libhkdfguard" and anchor apple generic
  and certificate 1[field.1.2.840.113635.100.6.2.6] exists
  and certificate leaf[field.1.2.840.113635.100.6.1.13] exists
  and certificate leaf[subject.OU] = "MFW3T8R8J3"
```

That is: Apple-issued Developer ID Application signature, from the Team
that signs this project's releases, on the library itself. A fork signs
with its own Team ID. Checking validity with no requirement proves only
that *someone's* valid signature is there, which anyone with any Apple
certificate could supply. A `dotnet`, `python`, or `java` host has no
library validation of its own, so this check is the only one that runs.

**C#.** Route the `DllImport` name to the checked path with a resolver, so
the existing `[DllImport("hkdfguard")]` declarations stay unchanged:

```csharp
NativeLibrary.SetDllImportResolver(typeof(HkdfGuardInterop).Assembly, (name, assembly, searchPath) =>
    name == "hkdfguard"
        ? NativeLibrary.Load(HkdfGuardInstall.ResolveVerifiedPath())
        : IntPtr.Zero);
```

`HkdfGuardInstall` makes the three checks above and throws if any fails;
it never falls back to another location:

```csharp
using System;
using System.IO;
using System.Runtime.InteropServices;

public static class HkdfGuardInstall
{
    public const string LibraryPath = "/Library/Application Support/HkdfGuard/v1/libhkdfguard.dylib";

    public const string CodeRequirement =
        "identifier \"libhkdfguard\" and anchor apple generic" +
        " and certificate 1[field.1.2.840.113635.100.6.2.6] exists" +     // Developer ID CA
        " and certificate leaf[field.1.2.840.113635.100.6.1.13] exists" + // Developer ID Application
        " and certificate leaf[subject.OU] = \"MFW3T8R8J3\"";            // the publisher's Team ID

    public static string ResolveVerifiedPath()
    {
        // 1. No symlink anywhere in the path: it resolves to itself.
        var resolved = RealPath(LibraryPath);
        if (resolved != LibraryPath)
            throw new InvalidOperationException($"{LibraryPath} resolves to {resolved}; refusing to load it");

        // 2. The dylib and every folder above it: root-owned, not a
        //    symlink, not group- or world-writable.
        for (var p = LibraryPath; ; p = Path.GetDirectoryName(p)!)
        {
            var (uid, mode) = LStat(p);
            if (uid != 0 || (mode & 0x12) != 0 || (mode & 0xF000) == 0xA000) // S_IWGRP|S_IWOTH, S_IFLNK
                throw new InvalidOperationException($"{p} is not root-owned and writable by root alone; refusing to load the library");
            if (p == "/") break;
        }

        // 3. The code signature, against the requirement above.
        CheckSignature(LibraryPath, CodeRequirement);
        return LibraryPath;
    }

    [DllImport("libc", SetLastError = true)] private static extern IntPtr realpath(string path, IntPtr resolved);
    [DllImport("libc")] private static extern void free(IntPtr p);
    [DllImport("libc", SetLastError = true)] private static extern int lstat(string path, byte[] buf);

    private static string RealPath(string path)
    {
        var p = realpath(path, IntPtr.Zero);
        if (p == IntPtr.Zero)
            throw new FileNotFoundException($"{path}: errno {Marshal.GetLastPInvokeError()}");
        try { return Marshal.PtrToStringUTF8(p)!; } finally { free(p); }
    }

    // macOS arm64 struct stat: 144 bytes; st_mode is a uint16 at offset 4,
    // st_uid a uint32 at offset 16.
    private static (uint uid, int mode) LStat(string path)
    {
        var buf = new byte[144];
        if (lstat(path, buf) != 0)
            throw new IOException($"{path}: errno {Marshal.GetLastPInvokeError()}");
        return (BitConverter.ToUInt32(buf, 16), BitConverter.ToUInt16(buf, 4));
    }

    private const string CF = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";
    private const string Sec = "/System/Library/Frameworks/Security.framework/Security";
    private const uint kCFStringEncodingUTF8 = 0x08000100;
    private const uint kSecCSCheckAllArchitectures = 1 << 0;
    private const uint kSecCSCheckNestedCode = 1 << 3;
    private const uint kSecCSStrictValidate = 1 << 4;

    [DllImport(CF)] private static extern IntPtr CFStringCreateWithCString(IntPtr alloc, string s, uint encoding);
    [DllImport(CF)] private static extern IntPtr CFURLCreateWithFileSystemPath(IntPtr alloc, IntPtr path, long style, byte isDir);
    [DllImport(CF)] private static extern void CFRelease(IntPtr cf);
    [DllImport(Sec)] private static extern int SecStaticCodeCreateWithPath(IntPtr url, uint flags, out IntPtr code);
    [DllImport(Sec)] private static extern int SecRequirementCreateWithString(IntPtr text, uint flags, out IntPtr req);
    [DllImport(Sec)] private static extern int SecStaticCodeCheckValidity(IntPtr code, uint flags, IntPtr req);

    private static void CheckSignature(string path, string requirement)
    {
        IntPtr cfPath = IntPtr.Zero, url = IntPtr.Zero, cfReq = IntPtr.Zero, code = IntPtr.Zero, req = IntPtr.Zero;
        try
        {
            cfPath = CFStringCreateWithCString(IntPtr.Zero, path, kCFStringEncodingUTF8);
            url = CFURLCreateWithFileSystemPath(IntPtr.Zero, cfPath, 0 /* POSIX */, 0);
            cfReq = CFStringCreateWithCString(IntPtr.Zero, requirement, kCFStringEncodingUTF8);
            int status = SecStaticCodeCreateWithPath(url, 0, out code);
            if (status == 0) status = SecRequirementCreateWithString(cfReq, 0, out req);
            if (status == 0) status = SecStaticCodeCheckValidity(code,
                kSecCSCheckAllArchitectures | kSecCSStrictValidate | kSecCSCheckNestedCode, req);
            if (status != 0)
                throw new InvalidOperationException($"{path} failed its code-signature check (OSStatus {status}); refusing to load it");
        }
        finally
        {
            foreach (var cf in new[] { req, code, cfReq, url, cfPath })
                if (cf != IntPtr.Zero) CFRelease(cf);
        }
    }
}
```

**Other languages.** Python, Node and Java make the same checks before
loading; the signature check can run `/usr/bin/codesign` with the
requirement (it exits non-zero if the requirement isn't met):

```sh
/usr/bin/codesign --verify --strict -R='=identifier "libhkdfguard" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "MFW3T8R8J3"' \
    "/Library/Application Support/HkdfGuard/v1/libhkdfguard.dylib"
```

The Python example below shows all three checks; the Node and Java
examples load the same absolute path, after the same checks.

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
import ctypes, os, stat, subprocess

HKDFGUARD_DYLIB = "/Library/Application Support/HkdfGuard/v1/libhkdfguard.dylib"
HKDFGUARD_REQUIREMENT = (
    'identifier "libhkdfguard" and anchor apple generic'
    ' and certificate 1[field.1.2.840.113635.100.6.2.6] exists'
    ' and certificate leaf[field.1.2.840.113635.100.6.1.13] exists'
    ' and certificate leaf[subject.OU] = "MFW3T8R8J3"'
)

def load_hkdfguard():
    """Loads the installed library after re-checking what the package guarantees."""
    if os.path.realpath(HKDFGUARD_DYLIB) != HKDFGUARD_DYLIB:
        raise RuntimeError(f"{HKDFGUARD_DYLIB} is reached through a symlink")
    p = HKDFGUARD_DYLIB
    while True:
        st = os.lstat(p)
        if st.st_uid != 0 or st.st_mode & 0o022 or stat.S_ISLNK(st.st_mode):
            raise RuntimeError(f"{p} is not root-owned and writable by root alone")
        if p == "/":
            break
        p = os.path.dirname(p)
    subprocess.run(["/usr/bin/codesign", "--verify", "--strict",
                    "-R", "=" + HKDFGUARD_REQUIREMENT, HKDFGUARD_DYLIB],
                   check=True, capture_output=True)
    return ctypes.CDLL(HKDFGUARD_DYLIB)

lib = load_hkdfguard()
lib.hkdfguard_create_kek.argtypes = [ctypes.c_char_p]
lib.hkdfguard_create_kek.restype = ctypes.c_int

status = lib.hkdfguard_create_kek(b"com.example.ingest")
```

**Node** (`koffi`):

```js
const koffi = require("koffi");
// After the path, owner and signature checks above:
const lib = koffi.load("/Library/Application Support/HkdfGuard/v1/libhkdfguard.dylib");
const hkdfguard_create_kek = lib.func("int hkdfguard_create_kek(const char *service)");

const status = hkdfguard_create_kek("com.example.ingest");
```

**Java** (JNA):

```java
public interface HkdfGuard extends Library {
    // After the path, owner and signature checks above:
    HkdfGuard INSTANCE = Native.load("/Library/Application Support/HkdfGuard/v1/libhkdfguard.dylib", HkdfGuard.class);
    int hkdfguard_create_kek(String service);
}

int status = HkdfGuard.INSTANCE.hkdfguard_create_kek("com.example.ingest");
```

**Go** (`cgo`, built against the installed header and library):

```go
/*
#cgo CFLAGS: "-I/Library/Application Support/HkdfGuard/v1"
#cgo LDFLAGS: "-L/Library/Application Support/HkdfGuard/v1" -lhkdfguard "-Wl,-rpath,/Library/Application Support/HkdfGuard/v1"
#include "hkdfguard.h"
*/
import "C"

status := C.hkdfguard_create_kek(C.CString("com.example.ingest"))
```

The binary's only search path for the library is then the root-owned
install folder (check with `otool -l`: one `LC_RPATH`). dyld loads the
library at launch, before any of the program's code runs, so the program
can't check the signature first; the root-owned folder chain is what
protects it. Run the `codesign` check above when deploying, or load the
library with `dlopen` after the checks instead of linking it.

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
`libhkdfguard.so`. (The name carries no version; the ABI's major version is
carried by the install folder `HkdfGuard/v1/` here and by the
`libhkdfguard.so.1` SONAME on Linux.)

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

- `hkdfguard_create_kek`, `hkdfguard_kek_exists` and (macOS-only)
  `hkdfguard_kek_fingerprint` are setup calls, meant to run once per
  application startup. Each takes at least 1000 ms of
  wall-clock time whatever its outcome, and they are serialized with each
  other across threads, so a process can make at most about one per
  second -- the same floor as the Linux and Windows builds. On macOS it is
  fixed (Linux reads `startup_behavior.setup_min_delay_ms` from its policy
  file, Windows `HKLM\Software\Policies\HkdfGuard\SetupMinDelayMs`).
  A NULL pointer, an invalid service name, or `kek_fingerprint`'s size
  probe returns immediately. `kek_fingerprint` is gated because "found" and
  "not found" tell a caller which services have a KEK, the same thing
  `kek_exists` does. Call them
  once at startup, then use `hkdfguard_wrap_dek` / `hkdfguard_unwrap_dek`,
  which are not gated.
- `hkdfguard_create_kek` is safe under concurrent first use: the keychain's
  unique index on (service, account) lets exactly one creation win and the
  others load the winner's key.
- The Secure Enclave / `securityd` IPC layer has limited real concurrency.
  A handful of simultaneous enclave operations from one process is fine;
  dozens cause severe contention (the test suite runs serialized for that
  reason).

## Tests

Ten Swift Testing suites. The three largest:

- **`HkdfGuardNativeMacOSWrapUnwrapTests`** (`.serialized`) exercises
  every C entry point in-process: provisioning, idempotence and the first-use race,
  service-name rules (ASCII bytes, case-insensitivity, length), round trips,
  payload length, nonce/ephemeral uniqueness, per-service isolation,
  fingerprint and ciphertext tamper detection, buffer sizing before any
  enclave work, NULL-pointer handling, corrupt-item reporting, and the
  keychain-mode decision (including that data-protection mode from an
  unentitled process is reported as `-18`, never as "no key"), a
  wrap → write file → `hkdfguard_open_file` → unwrap round trip, and the KEK
  suites: ML-KEM-1024 provisioned by default and stored in its keychain item
  format, the `KekSuite` P-256 opt-in, `hkdfguard_kek_suite`, and
  `RequirePostQuantum` refusing a P-256 KEK while still letting it be found.
- **`HkdfGuardOpenFileTests`** covers `hkdfguard_open_file` without the
  enclave: exact-length success, too short/too long, plaintext DEKs in
  every accepted encoding (`-37`, never copied out) versus short text that
  is not a key, malformed payloads (zero
  fingerprint, unknown suite bytes: -38), missing and unreadable files, symlink (-39)
  and directory/FIFO refusal, ownership rules (group/world-writable files
  refused; 0600/0644/0400, root-owned and hard-linked files accepted), buffer sizing
  before the file is
  opened, and NULL pointers.
- **`HkdfGuardCommandLineToolTests`** (`.serialized`) builds and runs the real CLI as a
  subprocess: `provision`/`wrap`/`status`/`retire` semantics, DEK sources
  and their bounds (whitespace, oversized, non-ASCII, missing file),
  rejected arguments, `wrap --fingerprint` (match, mismatch leaves an
  existing file untouched, malformed, the unpinned-wrap warning), `wrap
  --force` pinned to the replaced key file's KEK, `retire` by fingerprint and
  `--corrupt`, `--force` symlink/hard-link/FIFO refusal, the 64 KiB size cap
  and a full overwrite at that cap, file permissions, exit codes, and —
  hosted — the bundled CLI's data-protection provision/wrap/retire with
  this host unwrapping.

Smaller suites cover the audit records (`HkdfGuardAuditTests`), process
hardening (`HkdfGuardHardenProcessTests`), the setup gate
(`HkdfGuardSetupGateTests`), the salt-to-point hash
(`HkdfGuardPayloadPointTests`), the ML-KEM-1024 suite's payload crypto, its
refusals and its keychain item format, with software ML-KEM keys so they run
on CI too (`HkdfGuardMLKEMKEKTests`), the production policy, its suite
settings and both machine KEK file formats (`HkdfGuardMachineScopeTests`),
and the shared C ABI against the Linux header (`HkdfGuardCrossPlatformABITests`).

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

On real Secure Enclave hardware, each way of running skips some tests by
design:

- unhosted (legacy mode): the four data-protection-only tests and the five
  interactive legacy tests;
- hosted (data-protection mode, test group): the five interactive legacy
  tests (legacy-only by construction) and the one test that only makes
  sense in an unentitled host. This run includes
  `dataProtectionModeStoresItemsOnlyInTheDataProtectionKeychain`,
  `bundledCliProvisionsAndWrapsInDataProtectionModeAndEntitledHostUnwraps`
  (the end-to-end cross-process round trip), `bundledCliRetiresDataProtectionKek`,
  and `bundledCliRetiresCorruptDataProtectionItem`;
- unhosted with the interactive opt-in: only the four data-protection
  tests. All five legacy cross-process tests run (including `cliRetireCorruptDeletesOnlyACorruptItem`, which plants a
  corrupt item from another process). The first of them waits on the
  keychain prompt; once approved, the rest complete in seconds.

Every test that provisions a key is paired with a `defer` that deletes it,
so a failing assertion still leaves the keychain clean.

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
the `retire` and `status` commands, `wrap` printing the KEK fingerprint
it used and accepting `--fingerprint` to pin it, and, for now, the
ML-KEM-1024 KEK suite with the policy's `KekSuite` and `RequirePostQuantum`
(the Linux and Windows tools provision only the P-256 construction).
