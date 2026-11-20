//
//  HkdfGuardStatus.swift
//  HkdfGuardNativeMacOS
//
//  The status codes returned across the C boundary.
//

import Foundation

// MARK: - Status codes returned across the C boundary

/// The numbering is the shared HkdfGuard status table defined by
/// hkdfguard-native-linux's include/hkdfguard.h, the source of record: a
/// name has the same number on every platform. Common codes keep their
/// common number; macOS-only refinements live in the -96..-111 band and each
/// refines `HKDFGUARD_ERR_PROVIDER_ERROR` (-4). Numbers not listed here are
/// reserved by that table. Case names stay macOS-flavored; the comment on
/// each gives the shared `HKDFGUARD_*` name.
enum HKDFGuardStatus: Int32, CaseIterable { // internal, not private: the cross-platform ABI test checks every case against the Linux header
    /// HKDFGUARD_OK
    case success = 0
    /// HKDFGUARD_ERR_INVALID_ARGUMENT: a NULL pointer, a DEK that isn't 32
    /// bytes, or an empty `path`.
    case invalidInputLength = -1
    /// HKDFGUARD_ERR_BUFFER_TOO_SMALL
    case outputBufferTooSmall = -2
    /// HKDFGUARD_ERR_PROVIDER_UNAVAILABLE: no Secure Enclave on this machine.
    case enclaveUnavailable = -3
    /// HKDFGUARD_ERR_CRYPTO_ERROR: the RNG failed, the Secure Enclave refused
    /// the key agreement (wrap or unwrap), or AES-GCM sealing failed.
    case encryptionFailed = -5
    /// HKDFGUARD_ERR_INTERNAL_ERROR: an internal failure the library
    /// detected itself -- output of a length it never should produce, or a
    /// buffer that should exist not existing. Points at a bug here, not at
    /// the caller's input. (Linux also returns it for a caught panic; a
    /// Swift runtime trap can't be caught, so this library is written to
    /// have none on its export paths -- see `copyOut`.)
    case unexpectedOutputLength = -6
    /// HKDFGUARD_ERR_INVALID_SERVICE_NAME
    case invalidServiceIdentifier = -8
    /// HKDFGUARD_ERR_POLICY_INVALID: the production policy (a managed
    /// `com.hkdfguard` profile, or the local policy file) can't be used --
    /// an unknown setting, a wrong type, insecure ownership, or a runner
    /// group that doesn't exist or is too broad. Every call fails closed
    /// until it is fixed, as on Linux.
    case policyInvalid = -9

    // MARK: Wrapped payload

    /// HKDFGUARD_ERR_PAYLOAD_MALFORMED: `wrapped_len` is not the length every
    /// payload this library produces has.
    case payloadMalformed = -10

    /// HKDFGUARD_ERR_PAYLOAD_AUTH_FAILED: AES-GCM authentication failed: the
    /// payload or its embedded fingerprint was altered, or it was wrapped for
    /// a different service under the same KEK. A different KEK is caught
    /// earlier, as `fingerprintMismatch`.
    case decryptionFailed = -11

    /// HKDFGUARD_ERR_PAYLOAD_UNSUPPORTED: the payload's suite byte names a
    /// ciphersuite this build does not implement — a payload written by a
    /// newer or different build, not a tampered one. Returned by
    /// hkdfguard_unwrap_dek before any keychain or Secure Enclave work
    /// (hkdfguard_open_file reports the same file as `fileMalformed`, -38).
    case unsupportedCiphersuite = -12

    // MARK: KEK

    /// HKDFGUARD_ERR_KEK_FINGERPRINT_MISMATCH: the wrapped payload's embedded
    /// KEK fingerprint (see `kekFingerprint`) doesn't match the public
    /// key of the KEK this service currently resolves to — this payload was
    /// not wrapped under the key `hkdfguard_unwrap_dek` is about to use.
    /// Detected and returned before any key agreement or AES-GCM is
    /// attempted: unlike `decryptionFailed`, this specifically means "wrong
    /// KEK," not "right KEK, but tampered/mismatched data."
    case fingerprintMismatch = -16

    /// HKDFGUARD_ERR_KEK_NOT_FOUND: no keychain item exists yet for this
    /// service — the ordinary, expected state before the first
    /// `hkdfguard_create_kek` call for a given service. Wrap and unwrap never
    /// create one.
    case kekNotFound = -17

    /// HKDFGUARD_ERR_KEK_ACCESS_DENIED: the keychain refused to say whether
    /// an item exists for this service: the keychain is locked or there is no
    /// UI session to prompt in (`errSecInteractionNotAllowed` — the
    /// headless-daemon case), the item's ACL denied this process or the user
    /// declined the access prompt (`errSecAuthFailed`, `errSecUserCanceled`),
    /// or this process lacks a required entitlement
    /// (`errSecMissingEntitlement`). Also: the keychain handed the item over
    /// but the Secure Enclave won't load keys in this session (keybag
    /// locked, e.g. SSH after `security unlock-keychain`), proven by a
    /// throwaway probe key failing too. Deliberately distinct from
    /// `kekNotFound`/`kekCorrupted`: a key very likely *does* exist, and
    /// treating this as "no key" or "corrupt key" would invite a caller to
    /// create a replacement or an operator to delete a healthy one.
    case keychainAccessDenied = -18

    /// HKDFGUARD_ERR_KEK_INVALID: a keychain item exists under this service,
    /// but its stored data representation could not be reconstructed into a
    /// usable Secure Enclave key — a corrupt or foreign entry — while the
    /// enclave demonstrably works in this session. Deliberately
    /// never "healed" by generating a replacement: that would silently
    /// orphan whatever the original key protected.
    case kekCorrupted = -19

    /// HKDFGUARD_ERR_PROCESS_HARDENING_FAILED: `hkdfguard_harden_process`
    /// could not disable core dumps or deny debugger attachment, or -- with
    /// HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE -- the host executable's
    /// code signature still lets same-user processes debug or inject into it.
    case processHardeningFailed = -20

    // MARK: Key file — returned only by `hkdfguard_open_file`, which reads
    // a payload from disk and never touches the keychain or the Secure
    // Enclave.

    /// HKDFGUARD_ERR_FILE_NOT_FOUND: no file at the path, or a component of
    /// the path is not a directory (`ENOENT`, `ENOTDIR`).
    case fileNotFound = -32

    /// HKDFGUARD_ERR_FILE_ACCESS_DENIED: the file or a directory on its path
    /// can't be read by this process (`EACCES`, `EPERM`).
    case fileAccessDenied = -33

    /// HKDFGUARD_ERR_FILE_IO: the path names a directory, FIFO, socket, or
    /// device rather than a regular file, or `open`, `fstat`, or `read`
    /// failed for any other reason. A FIFO is opened non-blocking so it
    /// can't hang the caller. (A symbolic link is `fileInsecure`.)
    case fileIO = -34

    /// HKDFGUARD_ERR_FILE_TOO_SHORT: fewer bytes than a wrapped payload —
    /// truncated, or not a payload — and not recognizable as a plaintext DEK
    /// (that is `fileUnprotectedKey`).
    case fileTooShort = -35

    /// HKDFGUARD_ERR_FILE_TOO_LONG: more bytes than a wrapped payload.
    /// Detected from the file's size before anything is read, so an
    /// arbitrarily large file costs nothing.
    case fileTooLong = -36

    /// HKDFGUARD_ERR_FILE_PLAINTEXT_KEY: the file appears to hold a bare,
    /// unwrapped 32-byte DEK — raw, or as base64 or hex text — instead of a
    /// wrapped payload. Judged on length and alphabet alone, so any 32-byte
    /// value stored that way matches (a fingerprint saved as 64 hex
    /// characters, for one). If it is a key, it was stored without
    /// protection: treat it as exposed and rotate it. Its bytes are never
    /// copied to the caller's buffer.
    case fileUnprotectedKey = -37

    /// HKDFGUARD_ERR_FILE_MALFORMED: exactly the payload's length, but not a
    /// payload this build can read: its KEK fingerprint is all zeros, or its
    /// suite byte names a construction this build does not implement. As on
    /// Linux and Windows, every format problem in a key file is this one
    /// code; hkdfguard_unwrap_dek, given the same bytes, reports the suite
    /// as `unsupportedCiphersuite` (-12).
    case fileMalformed = -38

    /// HKDFGUARD_ERR_FILE_UNTRUSTED: the path's last component is a symbolic
    /// link (refused, never followed: `O_NOFOLLOW`), or the file is owned by
    /// someone other than this process's effective user or root, or is
    /// writable by group or others; or a folder above it, up to `/`, is
    /// owned by someone else or writable by group or others — unless
    /// sticky, which excuses a folder further up but never the one the file
    /// is in (see `keyFileFoldersAreTrusted`) — so a party other than its
    /// owner could have replaced its contents or renamed another file over
    /// it. Root is accepted so an administrator or MDM can deploy key files
    /// a service account reads; root can already alter anything on the
    /// machine, so this adds no new party who could tamper with the file.
    /// The CLI's `wrap` writes owner-only, 0600, which always passes.
    case fileInsecure = -39

    // MARK: macOS-specific — each refines HKDFGUARD_ERR_PROVIDER_ERROR (-4).

    /// HKDFGUARD_ERR_MAC_ACCESS_CONTROL_CREATION_FAILED:
    /// `SecAccessControlCreateWithFlags` failed while provisioning a new
    /// KEK, before any Secure Enclave key was even requested.
    case accessControlCreationFailed = -96

    /// HKDFGUARD_ERR_MAC_KEY_GENERATION_FAILED: the Secure Enclave refused
    /// to generate a new P-256 key-agreement key for this service (distinct
    /// from the enclave being entirely unavailable, `enclaveUnavailable`).
    case keyGenerationFailed = -97

    /// HKDFGUARD_ERR_MAC_KEYCHAIN_WRITE_FAILED: `SecItemAdd` failed while
    /// persisting a newly generated KEK, with an `OSStatus` other than
    /// success or "another caller already won the race"
    /// (`errSecDuplicateItem`, which is not an error — see `createKEK`'s
    /// handling of it).
    case keychainWriteFailed = -98

    /// HKDFGUARD_ERR_MAC_KEK_VERIFICATION_FAILED: a KEK was just generated
    /// and successfully stored, but immediately reloading and reconstructing
    /// it afterward failed. Should not happen in practice; kept distinct
    /// from `kekCorrupted` because it points at a different moment
    /// (verification of a write this process just made, not a pre-existing
    /// item found on lookup).
    case kekVerificationFailed = -99

    /// HKDFGUARD_ERR_MAC_KEYCHAIN_READ_FAILED: `SecItemCopyMatching` failed
    /// with an `OSStatus` other than not-found or one of the access-denial
    /// codes above — e.g. no keychain available at all, or an unexpected
    /// item shape.
    case keychainReadFailed = -100
}

extension HKDFGuardStatus {
    /// The shared name of this status, without the `HKDFGUARD_` prefix (e.g.
    /// `KEK_INVALID`) -- the `result=` value in audit records, as on Linux.
    /// The cross-platform ABI test checks each against the header.
    var sharedName: String {
        switch self {
        case .success: return "OK"
        case .invalidInputLength: return "ERR_INVALID_ARGUMENT"
        case .outputBufferTooSmall: return "ERR_BUFFER_TOO_SMALL"
        case .enclaveUnavailable: return "ERR_PROVIDER_UNAVAILABLE"
        case .encryptionFailed: return "ERR_CRYPTO_ERROR"
        case .unexpectedOutputLength: return "ERR_INTERNAL_ERROR"
        case .invalidServiceIdentifier: return "ERR_INVALID_SERVICE_NAME"
        case .policyInvalid: return "ERR_POLICY_INVALID"
        case .payloadMalformed: return "ERR_PAYLOAD_MALFORMED"
        case .decryptionFailed: return "ERR_PAYLOAD_AUTH_FAILED"
        case .unsupportedCiphersuite: return "ERR_PAYLOAD_UNSUPPORTED"
        case .fingerprintMismatch: return "ERR_KEK_FINGERPRINT_MISMATCH"
        case .kekNotFound: return "ERR_KEK_NOT_FOUND"
        case .keychainAccessDenied: return "ERR_KEK_ACCESS_DENIED"
        case .kekCorrupted: return "ERR_KEK_INVALID"
        case .processHardeningFailed: return "ERR_PROCESS_HARDENING_FAILED"
        case .fileNotFound: return "ERR_FILE_NOT_FOUND"
        case .fileAccessDenied: return "ERR_FILE_ACCESS_DENIED"
        case .fileIO: return "ERR_FILE_IO"
        case .fileTooShort: return "ERR_FILE_TOO_SHORT"
        case .fileTooLong: return "ERR_FILE_TOO_LONG"
        case .fileUnprotectedKey: return "ERR_FILE_PLAINTEXT_KEY"
        case .fileMalformed: return "ERR_FILE_MALFORMED"
        case .fileInsecure: return "ERR_FILE_UNTRUSTED"
        case .accessControlCreationFailed: return "ERR_MAC_ACCESS_CONTROL_CREATION_FAILED"
        case .keyGenerationFailed: return "ERR_MAC_KEY_GENERATION_FAILED"
        case .keychainWriteFailed: return "ERR_MAC_KEYCHAIN_WRITE_FAILED"
        case .kekVerificationFailed: return "ERR_MAC_KEK_VERIFICATION_FAILED"
        case .keychainReadFailed: return "ERR_MAC_KEYCHAIN_READ_FAILED"
        }
    }

    /// The name an audit record shows: Linux's (no `ERR_` prefix), e.g.
    /// `PAYLOAD_AUTH_FAILED`.
    var auditName: String {
        sharedName.hasPrefix("ERR_") ? String(sharedName.dropFirst(4)) : sharedName
    }
}
