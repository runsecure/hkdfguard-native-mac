//
//  hkdfguard.h
//  HkdfGuardNativeMacOS
//
//  Public C ABI of the HkdfGuard macOS key-protection library: wraps and
//  unwraps 32-byte Data Encryption Keys (DEKs) under a per-service Key
//  Encryption Key (KEK) held in the Secure Enclave, using HPKE (RFC 9180,
//  base mode) with DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, and AES-256-GCM.
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

// Every pointer parameter below is required. Under clang that is checked
// at the call site; elsewhere this macro is documentation. At run time a
// NULL is never dereferenced: it is reported as invalidInputLength (-1),
// or as invalidServiceIdentifier (-8) when it is `service`. A NULL `path`
// is invalidInputLength (-1).
#if defined(__clang__)
#  define HKDFGUARD_NONNULL _Nonnull
#else
#  define HKDFGUARD_NONNULL
#endif

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// Status codes returned by every function below
// ---------------------------------------------------------------------------
//    0  success
//   -1  invalidInputLength     (dek_len != 32, wrapped_len != 146, or a NULL
//                               buffer/length pointer)
//   -2  outputBufferTooSmall   (*out_len has been set to the required size:
//                               146 for wrap, 32 for unwrap. Reported before
//                               any keychain or Secure Enclave work, so a
//                               caller can size a buffer with a first call
//                               that costs nothing)
//   -3  keyUnavailable         (reserved; no longer returned -- see -10 and
//                               lower for the specific failures this used
//                               to lump together)
//   -4  publicKeyUnavailable   (reserved; never returned -- a KEK's public key
//                               is derived from the reconstructed key itself,
//                               so a key that loads always has one)
//   -5  encryptionFailed
//   -6  decryptionFailed       (AES-GCM authentication failed: the payload
//                               or its embedded fingerprint was altered, or
//                               it was wrapped for a different service under
//                               the same KEK. A different service's KEK is
//                               caught earlier, as fingerprintMismatch)
//   -7  unexpectedOutputLength
//   -8  invalidServiceIdentifier (service was NULL, empty, longer than 128
//                                 bytes, or contained a byte other than an
//                                 ASCII letter, digit, or '.')
//   -9  enclaveUnavailable       (no Secure Enclave on this machine)
//  -10  kekNotFound              (no keychain item exists for this service
//                                 in this process's keychain mode -- the
//                                 ordinary state before hkdfguard_create_kek
//                                 has been called. Returned by every wrap/
//                                 unwrap function, which never create one)
//  -11  kekCorrupted             (a keychain item exists under this service
//                                 but could not be reconstructed into a
//                                 usable key -- a corrupt or foreign entry;
//                                 never "healed" by generating a replacement)
//  -12  accessControlCreationFailed (failed to set up the access policy for
//                                    a new KEK, before any Secure Enclave key
//                                    was requested)
//  -13  keyGenerationFailed      (the Secure Enclave refused to generate a
//                                 new key)
//  -14  keychainWriteFailed      (SecItemAdd failed persisting a newly
//                                 generated KEK, for a reason other than a
//                                 concurrent creator winning the race or an
//                                 access denial)
//  -15  kekVerificationFailed    (a KEK was generated and stored, but could
//                                 not be reloaded immediately afterward;
//                                 should not happen)
//  -16  fingerprintMismatch      (the payload's embedded KEK fingerprint
//                                 doesn't match the public key of the KEK
//                                 this service currently resolves to: it was
//                                 not wrapped under the key hkdfguard_unwrap_dek
//                                 is about to use. Detected before any ECDH
//                                 or AES-GCM is attempted -- "wrong KEK",
//                                 as distinct from decryptionFailed's "right
//                                 KEK, altered data")
//  -17  keychainAccessDenied     (the keychain would not say whether an item
//                                 exists: it is locked or there is no UI
//                                 session to prompt in, the item's ACL
//                                 denied this process or the user declined
//                                 the access prompt, or a required
//                                 entitlement is missing. A key very likely
//                                 DOES exist -- do not treat this as
//                                 kekNotFound and create a replacement, and
//                                 do not treat it as kekCorrupted and delete
//                                 anything)
//  -18  keychainReadFailed       (SecItemCopyMatching failed for a reason
//                                 other than not-found or the access-denial
//                                 conditions above)
//
//  -19 to -26 are returned only by hkdfguard_open_file:
//  -19  fileNotFound             (no file at the path, or a path component
//                                 is not a directory)
//  -20  fileAccessDenied         (this process may not read the file or a
//                                 directory on its path)
//  -21  fileNotRegular           (a symbolic link -- refused, never
//                                 followed -- directory, FIFO, socket, or
//                                 device)
//  -22  fileReadFailed           (open/fstat/read failed for any other
//                                 reason)
//  -23  fileTooShort             (fewer than 146 bytes, and not a
//                                 plaintext DEK -- see -26)
//  -24  fileTooLong              (more than 146 bytes; detected from the
//                                 file's size before anything is read)
//  -25  fileMalformed            (146 bytes, but not a payload: the
//                                 encapsulated key is not a valid P-256
//                                 point, or the KEK fingerprint is all
//                                 zeros)
//  -26  fileUnprotectedKey       (the file appears to hold a bare, unwrapped
//                                 32-byte DEK -- raw, or as base64 or hex
//                                 text -- instead of a wrapped payload.
//                                 Judged on length and alphabet only, so
//                                 any 32-byte value stored that way matches,
//                                 a fingerprint saved as 64 hex characters
//                                 included. If it is a key, it was stored
//                                 unprotected: treat it as exposed and
//                                 rotate it. Its bytes are never copied to
//                                 the caller's buffer)
//  -27  fileInsecure             (the file is owned by someone other than
//                                 this process's effective user or root, is
//                                 writable by group or others, or has more
//                                 than one hard link, so someone other than
//                                 its owner could have replaced or replayed
//                                 its contents. The CLI's `wrap` writes 0600
//                                 with one link; keep it that way)
//  -28  unsupportedCiphersuite   (the payload's suite byte names a
//                                 ciphersuite this build does not
//                                 implement -- written by a newer or
//                                 different build. Not tampering. Returned
//                                 by hkdfguard_unwrap_dek and
//                                 hkdfguard_open_file before any keychain
//                                 or Secure Enclave work)

// ---------------------------------------------------------------------------
// `service`
// ---------------------------------------------------------------------------
// A null-terminated string of 1-128 bytes, each an ASCII letter, digit, or
// '.', identifying the calling application -- typically reverse-DNS. It is
// matched case-insensitively: every function lowercases it before
// validation, storage, or lookup, so "Com.Example.App" and "com.example.app"
// refer to the same KEK. Each distinct service gets its own, independent
// Secure Enclave key; wrapping under one service and unwrapping under
// another fails by design.
//
// The service name is also how payload-format versions are distinguished:
// a consumer that changes format adopts a new service name (and therefore
// a new KEK) rather than relying on an in-band version field.

// ---------------------------------------------------------------------------
// Buffer contract
// ---------------------------------------------------------------------------
// Lengths are trusted: `dek_len`, `wrapped_len`, and `*out_len` on entry
// must describe real, readable/writable memory of exactly that size. A
// wrapped payload is always exactly 146 bytes:
//
//   [ 32-byte KEK fingerprint (SHA-256 of the KEK's public key)        ]
//   [  1-byte ciphersuite id: 0x01                                     ]
//   [ 65-byte HPKE encapsulated key: X9.63 P-256 point, 0x04 || x || y ]
//   [ 32-byte AES-256-GCM ciphertext || 16-byte tag                    ]
//
// The suite id names the HPKE ciphersuite the rest of the payload was
// sealed with; 0x01 is the only one this library implements (see -28). The
// header (fingerprint || suite id) is the AEAD's additional authenticated
// data and the service name is in the HPKE `info`
// ("com.hkdfguard.hpke.v1" || 0x00 || service), so a payload is bound to
// its KEK, its suite, and its service.
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
//       hkdfguard-v1-initialize CLI as a plain Mach-O, a .NET/Python/Go
//       host that dlopens this library). Items are stored in the login
//       keychain, protected by its lock and a per-item ACL keyed to the
//       creating binary's signature; other identities get an interactive
//       prompt, or, headless, keychainAccessDenied (-17).
//
// The two keychains are disjoint, so the process that provisions a
// service's KEK and every process that unwraps under it MUST run in the
// same mode; a mismatch surfaces as kekNotFound (-10). Query the mode with
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

// Writes 0 (legacy login keychain) or 1 (data-protection keychain) to
// `*out_mode` -- see "Keychain mode" above.
int32_t hkdfguard_keychain_mode(
    int32_t* HKDFGUARD_NONNULL out_mode);

// Reports whether a Secure Enclave KEK already exists for `service`,
// without creating one. `*out_exists` is written on every return path --
// 1 if a valid KEK exists, 0 otherwise (including whenever the return
// status isn't 0, in which case existence couldn't be determined).
//
// kekCorrupted (-11) here means an item exists under this service but
// could not be reconstructed into a usable key -- distinct from "no key
// yet" (0, *out_exists = 0). Treat it as an error to investigate, not as
// "safe to create a new one". keychainAccessDenied (-17) means the
// keychain would not answer; a key may well exist.
int32_t hkdfguard_kek_exists(
    const char* HKDFGUARD_NONNULL service,
    int32_t* HKDFGUARD_NONNULL out_exists);

// Writes the 32-byte fingerprint (SHA-256 of the KEK's raw public key) of
// the KEK for `service` to `out` -- the same value embedded at the front of
// every payload wrapped under it. Public-key material, not a secret. Lets an
// operator record which KEK a service uses after provisioning, and confirm
// it before retiring it. `*out_len` must be at least 32 on entry. Never
// creates a KEK: kekNotFound (-10) if none exists.
int32_t hkdfguard_kek_fingerprint(
    const char* HKDFGUARD_NONNULL service,
    uint8_t* HKDFGUARD_NONNULL out,
    int32_t* HKDFGUARD_NONNULL out_len);

// Creates a Secure Enclave KEK for `service` if one doesn't already exist.
// Idempotent, and safe under concurrent first use by several threads or
// processes: whoever wins the race creates it, everyone else finds it, and
// all return 0 provided the resulting key can be reconstructed. The only
// function in this library that creates a key.
int32_t hkdfguard_create_kek(
    const char* HKDFGUARD_NONNULL service);

// Wraps the 32-byte DEK at `dek` under the KEK for `service` and writes the
// 146-byte payload to `out`. Never creates a KEK: expects kekNotFound (-10)
// if hkdfguard_create_kek has not been called for this service in this
// process's keychain mode.
int32_t hkdfguard_wrap_dek(
    const char* HKDFGUARD_NONNULL service,
    const uint8_t* HKDFGUARD_NONNULL dek,
    int32_t dek_len,
    uint8_t* HKDFGUARD_NONNULL out,
    int32_t* HKDFGUARD_NONNULL out_len
);

// Unwraps a 146-byte payload produced by hkdfguard_wrap_dek or
// hkdfguard_generate_and_wrap_dek, writing the 32-byte DEK to `out`. Checks
// the suite byte (-28 if unsupported) and then the payload's embedded KEK
// fingerprint against the KEK `service` resolves to, before attempting any
// key agreement or decryption, failing with fingerprintMismatch (-16) on a
// different KEK. Never creates a KEK.
int32_t hkdfguard_unwrap_dek(
    const char* HKDFGUARD_NONNULL service,
    const uint8_t* HKDFGUARD_NONNULL wrapped,
    int32_t wrapped_len,
    uint8_t* HKDFGUARD_NONNULL out,
    int32_t* HKDFGUARD_NONNULL out_len
);

// Generates a fresh, cryptographically random 32-byte DEK from the OS
// CSPRNG and immediately wraps it under the KEK for `service`, in one call
// -- the caller only ever sees the wrapped form, and the library zeroes its
// own copy before returning. For callers that want a brand-new DEK without
// sourcing their own randomness. Never creates a KEK.
int32_t hkdfguard_generate_and_wrap_dek(
    const char* HKDFGUARD_NONNULL service,
    uint8_t* HKDFGUARD_NONNULL out,
    int32_t* HKDFGUARD_NONNULL out_len
);

// Reads the wrapped payload stored at `path` -- the 146-byte file the CLI's
// `wrap` command writes -- validates it, and copies it to `out`, ready to
// pass to hkdfguard_unwrap_dek. Never touches the keychain or the Secure
// Enclave, and never unwraps: the plaintext DEK does not pass through this
// function.
//
// `path` is a null-terminated filesystem path. It must name a regular file
// owned by this process's effective user or by root, writable by no one but
// its owner, with a single hard link (-27 otherwise; the CLI's `wrap`
// writes such a file). A root-owned file deployed by an administrator must
// still be readable by the caller -- 0644, or 0640 with a shared group --
// or it is fileAccessDenied (-20). A
// symbolic link as its last component is refused (-21), not followed;
// symlinks in directory components resolve as usual (/etc, /tmp). A FIFO,
// socket, directory, or device is refused (-21) without blocking. Every
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
// `*out_len` is the capacity of `out` on entry (at least 146) and is
// written on every return: 146 -- the number of bytes read -- on success,
// 146 on outputBufferTooSmall (-2, reported before the file is opened), and
// 0 on every other failure. `out` is written only on success.
//
// Reading the file proves nothing about it: whether the payload is genuine,
// unaltered, and for this service is decided by hkdfguard_unwrap_dek (-16,
// -6). Pin the KEK by comparing bytes 0-31 with the fingerprint recorded at
// provisioning before unwrapping.
int32_t hkdfguard_open_file(
    const char* HKDFGUARD_NONNULL path,
    uint8_t* HKDFGUARD_NONNULL out,
    int32_t* HKDFGUARD_NONNULL out_len
);

#ifdef __cplusplus
}
#endif

#endif
