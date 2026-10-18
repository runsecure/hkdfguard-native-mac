//
//  hkdfguard.h
//  HkdfGuardNativeMacOS
//
//  Public C ABI of the HkdfGuard macOS key-protection library: wraps and
//  unwraps 32-byte Data Encryption Keys (DEKs) under a per-service Key
//  Encryption Key (KEK) held in the Secure Enclave, using the Linux and
//  Windows construction: ECDH(KEK, a P-256 point hashed from a per-payload
//  salt) in the Secure Enclave, HKDF-SHA512, and AES-256-GCM.
//
//  Plain C. Includable from C, C++, Objective-C, and any FFI layer
//  (P/Invoke, ctypes, cgo, JNA) without Foundation; the Objective-C-only
//  framework version symbols are guarded below so they never get in a C
//  consumer's way.
//

#ifndef HKDFGUARD_MACOS_H
#define HKDFGUARD_MACOS_H

#ifdef __OBJC__
#import <Foundation/Foundation.h>

//! Project version number for HkdfGuardNativeMacOS.
FOUNDATION_EXPORT double HkdfGuardNativeMacOSVersionNumber;

//! Project version string for HkdfGuardNativeMacOS.
FOUNDATION_EXPORT const unsigned char HkdfGuardNativeMacOSVersionString[];
#endif

#include <stdint.h>

// Every pointer parameter marked HKDFGUARD_NONNULL is required. Under clang
// that is checked at the call site; elsewhere these macros are
// documentation. At run time a NULL is never dereferenced: it is reported
// as HKDFGUARD_ERR_INVALID_ARGUMENT, or as HKDFGUARD_ERR_INVALID_SERVICE_NAME
// when it is `service`. A NULL or empty `path` is
// HKDFGUARD_ERR_INVALID_ARGUMENT.
//
// The one HKDFGUARD_NULLABLE pointer is `out` on hkdfguard_wrap_dek,
// hkdfguard_unwrap_dek, hkdfguard_generate_and_wrap_dek, and
// hkdfguard_open_file, as on Linux: a size probe passes `out = NULL` with
// `*out_len = 0` and gets HKDFGUARD_ERR_BUFFER_TOO_SMALL with the size to
// allocate in `*out_len` (125 for a payload, 32 for a DEK), without the
// keychain, the Secure Enclave, or the file being touched. A NULL `out` with
// a positive `*out_len` is HKDFGUARD_ERR_INVALID_ARGUMENT, and so is a
// negative `*out_len` on any of the four.
#if defined(__clang__)
#  define HKDFGUARD_NONNULL _Nonnull
#  define HKDFGUARD_NULLABLE _Nullable
#else
#  define HKDFGUARD_NONNULL
#  define HKDFGUARD_NULLABLE
#endif

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// Constants and status codes
// ---------------------------------------------------------------------------

/* Required length of a DEK, in bytes. */
#define HKDFGUARD_DEK_LEN 32

/* Largest wrapped payload hkdfguard_wrap_dek / hkdfguard_generate_and_wrap_dek
 * can produce, for any valid service name. A buffer of this size never needs
 * a retry. Shared name with every platform's header; the value is
 * per-platform (Linux: 276). On macOS every payload is exactly this long
 * (see "Buffer contract" below). */
#define HKDFGUARD_WRAPPED_MAX_LEN 125

/*
 * Status codes returned by every hkdfguard_* function.
 *
 * This table is shared by all three platform implementations of this C ABI
 * (Linux, Windows, macOS): a name always has the same number everywhere, and
 * every platform's header defines every code, including ones that platform
 * never returns (marked below). Codes are grouped in bands:
 *
 *      0 ..   -8   general
 *     -9           policy
 *    -10 ..  -15   wrapped payload
 *    -16 ..  -31   KEK
 *    -32 ..  -63   key file (hkdfguard_open_file); -40..-63 reserved
 *    -64 ..  -79   Windows-specific
 *    -80 ..  -95   Linux-specific (none defined yet)
 *    -96 .. -111   macOS-specific
 *
 * Every code in a platform band refines one common code, named in its
 * comment: a caller that doesn't care about the detail can treat it as that
 * common code. Numbers not listed are reserved: a number is never reused
 * for a different meaning.
 */

/* General */
#define HKDFGUARD_OK 0
#define HKDFGUARD_ERR_INVALID_ARGUMENT (-1)     /* null pointer, wrong DEK length, negative capacity, etc. -- never a service-string problem, see HKDFGUARD_ERR_INVALID_SERVICE_NAME */
#define HKDFGUARD_ERR_BUFFER_TOO_SMALL (-2)     /* `out` is too small; *out_len says what to retry with */
#define HKDFGUARD_ERR_PROVIDER_UNAVAILABLE (-3) /* no KEK provider could be reached at all */
#define HKDFGUARD_ERR_PROVIDER_ERROR (-4)       /* a provider was reachable but failed to create, load, or use the KEK */
#define HKDFGUARD_ERR_CRYPTO_ERROR (-5)         /* a cryptographic operation failed for a reason other than authentication: RNG, hash-to-curve, HKDF, or encryption */
#define HKDFGUARD_ERR_INTERNAL_ERROR (-6)       /* an internal failure the library detected (see below) */
/* -7 is reserved and never returned. A `service` string that isn't valid
 * UTF-8 is one more way for it to be invalid, reported as
 * HKDFGUARD_ERR_INVALID_SERVICE_NAME below. */
#define HKDFGUARD_ERR_INVALID_SERVICE_NAME (-8) /* service is null, empty, not valid UTF-8, over 128 bytes, contains a character other than an ASCII letter, digit, or '.', starts with '.', or contains ".." */

/* Policy */
#define HKDFGUARD_ERR_POLICY_INVALID (-9)       /* the policy file can't be used: unparsable, an invalid or contradictory setting, insecure ownership/permissions of it or its directory, or it requires a provider this build lacks */

/* Wrapped payload */
#define HKDFGUARD_ERR_PAYLOAD_MALFORMED (-10)   /* structurally invalid: truncated, trailing bytes, unknown provider type, or a field length no wrap produces */
#define HKDFGUARD_ERR_PAYLOAD_AUTH_FAILED (-11) /* AES-GCM authentication failed: tampered, wrong service, or wrong KEK */
#define HKDFGUARD_ERR_PAYLOAD_UNSUPPORTED (-12) /* unknown payload version */
/* -13..-15 reserved. */

/* KEK */
#define HKDFGUARD_ERR_KEK_FINGERPRINT_MISMATCH (-16) /* the payload was wrapped under a different KEK than `service` resolves to now */
#define HKDFGUARD_ERR_KEK_NOT_FOUND (-17)       /* no KEK exists yet for this service; call hkdfguard_create_kek first */
#define HKDFGUARD_ERR_KEK_ACCESS_DENIED (-18)   /* the keychain would not say whether the KEK exists: locked, no UI session to prompt in, ACL denial or declined prompt, or a missing entitlement. A KEK very likely DOES exist: do not create a replacement or delete anything */
#define HKDFGUARD_ERR_KEK_INVALID (-19)         /* a keychain item exists for this service but can't be reconstructed into a usable key -- a corrupt or foreign entry; never "healed" by generating a replacement */
#define HKDFGUARD_ERR_PROCESS_HARDENING_FAILED (-20) /* hkdfguard_harden_process could not disable core dumps or ptrace access, or (with HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE) the process can still be debugged by its own user */
/* -21..-31 reserved. */

/* Key file: hkdfguard_open_file's refusals. */
#define HKDFGUARD_ERR_FILE_NOT_FOUND (-32)      /* key file, or a directory in its path, does not exist */
#define HKDFGUARD_ERR_FILE_ACCESS_DENIED (-33)  /* the OS refused to let this process open the key file (e.g. EACCES) */
#define HKDFGUARD_ERR_FILE_IO (-34)             /* key file is not a regular file, or reading it failed */
#define HKDFGUARD_ERR_FILE_TOO_SHORT (-35)      /* key file is shorter than a wrapped DEK, or than its own header declares */
#define HKDFGUARD_ERR_FILE_TOO_LONG (-36)       /* key file is longer than a wrapped DEK, or than its own header declares */
#define HKDFGUARD_ERR_FILE_PLAINTEXT_KEY (-37)  /* key file looks like an UNWRAPPED DEK (32 raw bytes, or its base64 or hex): treat as a key exposure */
#define HKDFGUARD_ERR_FILE_MALFORMED (-38)      /* key file is the right length but not a well-formed wrapped DEK */
#define HKDFGUARD_ERR_FILE_UNTRUSTED (-39)      /* key file, or a directory deciding what its path names, is owned by another user or writable by group/others: someone else could have replaced it */
/* -40..-63 reserved for future common codes. */

/* Windows-specific (-64..-79). Not returned on macOS. */
#define HKDFGUARD_ERR_WIN_GROUP_INVALID (-64)   /* refines HKDFGUARD_ERR_POLICY_INVALID; Windows only */

/* Linux-specific (-80..-95): none defined yet. Not returned on macOS. */

/* macOS-specific (-96..-111). Each refines HKDFGUARD_ERR_PROVIDER_ERROR. */
#define HKDFGUARD_ERR_MAC_ACCESS_CONTROL_CREATION_FAILED (-96) /* failed to set up the access policy for a new KEK, before any Secure Enclave key was requested */
#define HKDFGUARD_ERR_MAC_KEY_GENERATION_FAILED (-97)          /* the Secure Enclave refused to generate a new key */
#define HKDFGUARD_ERR_MAC_KEYCHAIN_WRITE_FAILED (-98)          /* SecItemAdd failed persisting a new KEK, other than a concurrent creator winning the race or an access denial */
#define HKDFGUARD_ERR_MAC_KEK_VERIFICATION_FAILED (-99)        /* a new KEK was stored but could not be reloaded immediately afterward; should not happen */
#define HKDFGUARD_ERR_MAC_KEYCHAIN_READ_FAILED (-100)          /* SecItemCopyMatching failed other than not-found or an access denial */

/*
 * How macOS reports the common codes:
 *   PROVIDER_UNAVAILABLE (-3)  no Secure Enclave on this machine.
 *   CRYPTO_ERROR (-5)          the RNG failed, the Secure Enclave refused the
 *                              key agreement, or AES-GCM sealing failed.
 *   INTERNAL_ERROR (-6)        an internal failure the library detected: output
 *                              of an impossible length, or a buffer that should
 *                              exist not existing (a bug here, not a caller
 *                              error). Unlike Linux, never "a caught panic": a
 *                              Swift runtime trap can't be caught, so the
 *                              library has none on its export paths, and a
 *                              failure that "can't happen" is returned as -6
 *                              rather than ending the host process.
 *   PAYLOAD_MALFORMED (-10)    wrapped_len is not 125.
 *   PAYLOAD_AUTH_FAILED (-11)  AES-GCM authentication failed: the payload or
 *                              its fingerprint was altered, or it was wrapped
 *                              for a different service under the same KEK.
 *   PAYLOAD_UNSUPPORTED (-12)  the payload's suite byte names a ciphersuite
 *                              this build does not implement (unwrap; the
 *                              same file read by hkdfguard_open_file is
 *                              FILE_MALFORMED, as on Linux and Windows).
 *   KEK_NOT_FOUND (-17)        no keychain item for this service in this
 *                              process's keychain mode -- including a
 *                              provisioner/consumer keychain-mode mismatch.
 *   FILE_IO (-34)              also: the path names a directory, FIFO,
 *                              socket, or device.
 *   FILE_UNTRUSTED (-39)       also: the path's last component is a symbolic
 *                              link (refused, never followed).
 * PROVIDER_ERROR (-4) itself is never returned: macOS always reports one of
 * its refinements (-96..-100) instead.
 */

// ---------------------------------------------------------------------------
// `service`
// ---------------------------------------------------------------------------
// A null-terminated string of 1-128 bytes, each an ASCII letter, digit, or
// '.', not starting with '.' and with no two consecutive dots (".."),
// identifying the calling application -- typically reverse-DNS. So a name
// can never be ".", "..", or a hidden dot-name. At most 129 bytes are read
// looking for the terminator. It is matched case-insensitively: every
// function validates it and then lowercases it before storage or lookup, so "Com.Example.App" and "com.example.app"
// refer to the same KEK. Each distinct service gets its own, independent
// Secure Enclave key; wrapping under one service and unwrapping under
// another fails by design.
//
// The payload format below is macOS's own. Like the Linux and Windows
// libraries, this one shares the function names and signatures, status
// codes, flags, and call semantics. Two functions here are macOS-only, with
// no Linux or Windows counterpart, so a cross-platform caller must not rely
// on them: hkdfguard_keychain_mode and hkdfguard_kek_fingerprint. Not shared
// either: the payload layout, which is per-platform (Linux's carries a
// version byte, a provider tag and a key id, 132..276 bytes). The
// construction is the same on all three -- ECDH against a hashed
// per-payload point, HKDF-SHA512, AES-256-GCM -- so on every platform only
// the KEK's holder can CREATE a payload, not merely open one: knowing the
// KEK's public key is not enough. HKDFGUARD_WRAPPED_MAX_LEN has the same
// name everywhere and a per-platform value. A payload is only ever opened
// on the Mac whose Secure Enclave KEK wrapped it, so treat it as opaque
// bytes and never parse it; moving a service to another platform means
// re-wrapping its DEKs there.

// ---------------------------------------------------------------------------
// Buffer contract
// ---------------------------------------------------------------------------
// Lengths are trusted: `dek_len`, `wrapped_len`, and `*out_len` on entry
// must describe real, readable/writable memory of exactly that size. A
// wrapped payload is always exactly 125 bytes:
//
//   [ 32-byte KEK fingerprint (SHA-256 of the KEK's public key, 0x04||x||y) ]
//   [  1-byte suite id: 0x01                                                ]
//   [ 32-byte random salt                                                   ]
//   [ 12-byte random AES-GCM nonce                                          ]
//   [ 32-byte AES-256-GCM ciphertext || 16-byte tag                         ]
//
// The Secure Enclave computes ECDH(KEK, H(salt)), where H hashes the salt
// to a P-256 point; HKDF-SHA512 (salt = the salt) derives the AES-256 key.
// The suite id names that construction; 0x01 is the only one this library
// implements (see HKDFGUARD_ERR_PAYLOAD_UNSUPPORTED). The header -- every
// byte before the ciphertext -- is bound into both the derived key (HKDF
// `info`, with the service name) and the tag (AES-GCM additional data), so a
// payload is bound to its KEK, its suite, and its service.
//
// On return, `*out_len` is always set: to the bytes written on success, or
// to the required size on outputBufferTooSmall.

// ---------------------------------------------------------------------------
// Keychain mode (hybrid)
// ---------------------------------------------------------------------------
// The KEK's keychain item lives in one of two keychains, chosen once per
// process from that process's own code-signing entitlements -- never from
// configuration:
//
//   data-protection (mode 1): the process carries a `keychain-access-groups`
//       entitlement, which on macOS requires a Team-signed app bundle with
//       an embedded provisioning profile. Items are stored under the FIRST
//       listed access group, and access is decided by securityd from the
//       caller's signed identity: no prompts, no per-item ACLs, and any
//       Team-signed bundle listing the same group shares the item. This is
//       the hardened mode -- put the shared HkdfGuard group first (or make
//       it the only one) in every participating bundle's entitlement.
//   legacy (mode 0): no such entitlement -- a bare executable (the
//       hkdfguard CLI as a plain Mach-O, a .NET/Python/Go
//       host that dlopens this library). Items are stored in the login
//       keychain, protected by its lock and a per-item ACL keyed to the
//       creating binary's signature; other identities get an interactive
//       prompt, or, headless, HKDFGUARD_ERR_KEK_ACCESS_DENIED (-18).
//
// The two keychains are disjoint, so the process that provisions a
// service's KEK and every process that unwraps under it MUST run in the
// same mode; a mismatch surfaces as HKDFGUARD_ERR_KEK_NOT_FOUND (-17). Query the mode with
// hkdfguard_keychain_mode and surface it wherever KEKs are provisioned
// (the CLI prints it).

// ---------------------------------------------------------------------------
// Access policy (fixed) and headless use
// ---------------------------------------------------------------------------
// Every KEK is created with kSecAttrAccessibleWhenUnlockedThisDeviceOnly and
// privateKeyUsage only -- no user-presence or biometric requirement, so no
// Touch ID/password prompt is ever needed to use it (this library serves
// unattended services). Consequences:
//
//   - The key can never leave this device: no backup or restore carries it.
//   - "Unlocked" is the login user's keybag. A LaunchDaemon or SSH session
//     on a Mac with no unlocked GUI session may find the key unavailable,
//     surfacing as keyGenerationFailed/decryptionFailed from the enclave or
//     keychainAccessDenied from a locked keychain. Run headless consumers
//     as a LaunchAgent inside a logged-in session, or otherwise ensure the
//     login keychain is unlocked.
//   - The protection boundary is "which processes may read the keychain
//     item" (the keychain mode's job), not "a human approved this use".
//
// There is no per-service policy override.

// ---------------------------------------------------------------------------
// Functions
// ---------------------------------------------------------------------------

// Opt-in hardening of the *calling process* against memory disclosure, so
// keys and DEKs that pass through this library can't be recovered from a
// crash dump or by a debugger running as the same user. Process-wide and
// irreversible -- debuggers and crash reporters stop working for the
// process -- hence opt-in. Call once, early in startup. Idempotent.
//
//   1. Core dumps off: RLIMIT_CORE = 0, soft and hard.
//   2. ptrace(PT_DENY_ATTACH): later debugger attaches fail. If a debugger
//      is already attached this returns HKDFGUARD_ERR_PROCESS_HARDENING_FAILED
//      instead (the kernel would otherwise terminate the process) -- so a
//      process run under Xcode's debugger gets -20 here.
//   3. The host executable's code signature is checked. On macOS, what
//      stops a same-user process from reading this one's memory through its
//      task port is the signature -- the Hardened Runtime, without the
//      get-task-allow entitlement (which Xcode adds to Debug builds) or
//      ones that allow DYLD_* injection or unsigned libraries -- and only
//      whoever signs the host can change it. A weak signature is logged
//      (os_log, subsystem com.hkdfguard) and the call still succeeds, so
//      python, dotnet, and Xcode Debug hosts can use it during development.
//
// Same as hkdfguard_harden_process_with_flags(0).
//
// Returns HKDFGUARD_OK, or HKDFGUARD_ERR_PROCESS_HARDENING_FAILED.
int hkdfguard_harden_process(void);

// Flags for hkdfguard_harden_process_with_flags. Shared by every platform:
// a flag has the same bit everywhere, and every platform accepts every flag
// defined here.
//
// HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE: make step 3's weak
//     signature a failure (HKDFGUARD_ERR_PROCESS_HARDENING_FAILED) instead
//     of a warning. Pass it in release builds of a signed app, e.g.
//         #if DEBUG
//         hkdfguard_harden_process();
//         #else
//         hkdfguard_harden_process_with_flags(HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE);
//         #endif
//     Steps 1 and 2 are still applied when it fails. On Linux the flag is
//     accepted and adds nothing (PR_SET_DUMPABLE already guarantees it), so
//     a cross-platform caller can pass it everywhere.
#define HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE 0x1u

// hkdfguard_harden_process, with `flags` -- a bitwise OR of HKDFGUARD_HARDEN_*
// flags, or 0 -- choosing how strict it is.
//
// Returns HKDFGUARD_OK; HKDFGUARD_ERR_INVALID_ARGUMENT if `flags` has a bit
// this library doesn't know (checked before anything is changed, so a newer
// flag is never silently ignored); or HKDFGUARD_ERR_PROCESS_HARDENING_FAILED.
int hkdfguard_harden_process_with_flags(unsigned int flags);

// macOS-only. Writes 0 (legacy login keychain) or 1 (data-protection keychain) to
// `*out_mode` -- see "Keychain mode" above.
int hkdfguard_keychain_mode(
    int* HKDFGUARD_NONNULL out_mode);

// Reports whether a Secure Enclave KEK already exists for `service`,
// without creating one. `*out_exists` is written on every return path --
// 1 if a valid KEK exists, 0 otherwise (including whenever the return
// status isn't 0, in which case existence couldn't be determined).
//
// HKDFGUARD_ERR_KEK_INVALID (-19) here means an item exists under this service but
// could not be reconstructed into a usable key -- distinct from "no key
// yet" (0, *out_exists = 0). Treat it as an error to investigate, not as
// "safe to create a new one". HKDFGUARD_ERR_KEK_ACCESS_DENIED (-18) means the
// keychain would not answer; a key may well exist.
//
// Subject to the same latency floor and serialization as
// hkdfguard_create_kek below; "exists" and "doesn't exist" take the same
// time.
int hkdfguard_kek_exists(
    const char* HKDFGUARD_NONNULL service,
    int* HKDFGUARD_NONNULL out_exists);

// macOS-only. Writes the 32-byte fingerprint (SHA-256 of the KEK's public key, uncompressed 0x04 || x || y) of
// the KEK for `service` to `out` -- the same value embedded at the front of
// every payload wrapped under it. Public-key material, not a secret. Lets an
// operator record which KEK a service uses after provisioning, and confirm
// it before retiring it. `*out_len` must be at least 32 on entry. Never
// creates a KEK: HKDFGUARD_ERR_KEK_NOT_FOUND (-17) if none exists.
int hkdfguard_kek_fingerprint(
    const char* HKDFGUARD_NONNULL service,
    uint8_t* HKDFGUARD_NONNULL out,
    int* HKDFGUARD_NONNULL out_len);

// Creates a Secure Enclave KEK for `service` if one doesn't already exist.
// Idempotent, and safe under concurrent first use by several threads or
// processes: whoever wins the race creates it, everyone else finds it, and
// all return 0 provided the resulting key can be reconstructed. The only
// function in this library that creates a key.
//
// Deliberately slow: this and hkdfguard_kek_exists are setup calls, meant
// to run once per application startup, and each takes at least 1000 ms of
// wall-clock time whatever its outcome (fixed on macOS; the Linux and
// Windows builds default to the same and let an administrator tune it),
// and they are serialized with each other across threads. Do not call them
// per request; call once at startup and then use hkdfguard_wrap_dek /
// hkdfguard_unwrap_dek. Argument errors (NULL pointer or invalid service
// name) return immediately.
int hkdfguard_create_kek(
    const char* HKDFGUARD_NONNULL service);

// Wraps the 32-byte DEK at `dek` under the KEK for `service` and writes the
// 125-byte payload to `out`. Never creates a KEK: expects HKDFGUARD_ERR_KEK_NOT_FOUND (-17)
// if hkdfguard_create_kek has not been called for this service in this
// process's keychain mode.
int hkdfguard_wrap_dek(
    const char* HKDFGUARD_NONNULL service,
    const uint8_t* HKDFGUARD_NONNULL dek,
    int dek_len,
    uint8_t* HKDFGUARD_NULLABLE out,
    int* HKDFGUARD_NONNULL out_len
);

// Unwraps a 125-byte payload produced by hkdfguard_wrap_dek or
// hkdfguard_generate_and_wrap_dek, writing the 32-byte DEK to `out`. Checks
// the suite byte (HKDFGUARD_ERR_PAYLOAD_UNSUPPORTED if unsupported) and then the payload's embedded KEK
// fingerprint against the KEK `service` resolves to, before attempting any
// key agreement or decryption, failing with HKDFGUARD_ERR_KEK_FINGERPRINT_MISMATCH (-16) on a
// different KEK. Never creates a KEK.
//
// On ANY failure, every byte of the capacity declared in `*out_len` on entry
// is zeroed before returning, so no partial or stale key material is ever
// left in `out` -- as on Linux. (With a NULL `out_len` there is no declared
// capacity, so nothing is written.)
int hkdfguard_unwrap_dek(
    const char* HKDFGUARD_NONNULL service,
    const uint8_t* HKDFGUARD_NONNULL wrapped,
    int wrapped_len,
    uint8_t* HKDFGUARD_NULLABLE out,
    int* HKDFGUARD_NONNULL out_len
);

// Generates a fresh, cryptographically random 32-byte DEK from the OS
// CSPRNG and immediately wraps it under the KEK for `service`, in one call
// -- the caller only ever sees the wrapped form, and the library zeroes its
// own copy before returning. For callers that want a brand-new DEK without
// sourcing their own randomness. Never creates a KEK.
int hkdfguard_generate_and_wrap_dek(
    const char* HKDFGUARD_NONNULL service,
    uint8_t* HKDFGUARD_NULLABLE out,
    int* HKDFGUARD_NONNULL out_len
);

// Reads the wrapped payload stored at `path` -- the 125-byte file the CLI's
// `wrap` command writes -- validates it, and copies it to `out`, ready to
// pass to hkdfguard_unwrap_dek. Never touches the keychain or the Secure
// Enclave, and never unwraps: the plaintext DEK does not pass through this
// function.
//
// `path` is a null-terminated filesystem path, at most PATH_MAX (1024) bytes
// including the terminator: a path with no terminator within that is
// HKDFGUARD_ERR_INVALID_ARGUMENT, and nothing past it is read. It must name a regular file
// owned by this process's effective user or by root, writable by no one but
// its owner, in folders that are each -- up to / --
// owned by root or this user and not writable by group or others unless
// sticky (/tmp-style); write bits are ignored on a read-only volume
// (HKDFGUARD_ERR_FILE_UNTRUSTED otherwise, as on Linux; the CLI's `wrap`
// writes such a file). A folder the admin group can write, such as
// /Applications, is refused. A root-owned file deployed by an administrator must
// still be readable by the caller -- 0644, or 0640 with a shared group --
// or it is HKDFGUARD_ERR_FILE_ACCESS_DENIED. A
// symbolic link as its last component is refused (HKDFGUARD_ERR_FILE_UNTRUSTED), not followed;
// symlinks in directory components resolve as usual (/etc, /tmp). A FIFO,
// socket, directory, or device is refused (HKDFGUARD_ERR_FILE_IO) without blocking. Every
// check is made on the opened descriptor, so it describes the file that is
// read.
//
// Pass an absolute path your application controls -- not one taken from an
// untrusted source, and not relative (it would resolve against the current
// directory, which the caller may not control). The status codes describe
// the file (exists, readable, size class), so a privileged process that
// opened attacker-chosen paths would leak that much about them. Store the
// file in a directory only its owner can write.
//
// `*out_len` is the capacity of `out` on entry (at least 125). It is
// written with 125 -- the number of bytes read -- on success, and with 125
// on HKDFGUARD_ERR_BUFFER_TOO_SMALL (reported before the file is opened).
// Every other failure leaves it as the caller set it, as on Linux and as
// with hkdfguard_wrap_dek and hkdfguard_unwrap_dek. The file's bytes are copied to `out` only on
// success; on any failure every byte of the capacity declared in `*out_len`
// on entry is zeroed instead, as on Linux.
//
// Reading the file proves nothing about it: whether the payload is genuine,
// unaltered, and for this service is decided by hkdfguard_unwrap_dek (-16,
// -11). Pin the KEK by comparing bytes 0-31 with the fingerprint recorded at
// provisioning before unwrapping.
int hkdfguard_open_file(
    const char* HKDFGUARD_NONNULL path,
    uint8_t* HKDFGUARD_NULLABLE out,
    int* HKDFGUARD_NONNULL out_len
);

#ifdef __cplusplus
}
#endif

#endif
