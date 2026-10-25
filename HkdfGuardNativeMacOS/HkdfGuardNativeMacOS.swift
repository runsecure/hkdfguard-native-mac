import Foundation
import CryptoKit
import Security
import os // Logger: hkdfguard_harden_process's advisory signature warning
import Darwin.membership // mbr_uuid_to_id, ID_TYPE_UID: not re-exported by Foundation in every SDK

#if compiler(<6.2)
#error("HkdfGuardNativeMacOS requires a Swift 6.2 or later toolchain.")
#endif

// MARK: - Configuration

let hkdfguardKeychainAccount = "kek-v1" // internal (not private) so @testable-import test code can clean up keychain items it creates

/// Expected length of the Data Encryption Key being wrapped/unwrapped.
private let hkdfguardDekLength = 32

/// Length, in bytes, of the SHA-256 "fingerprint" at the front of every
/// wrapped payload — see `kekFingerprint` below.
private let hkdfguardFingerprintLength = 32

/// The one byte that names the payload's construction (see "Wrap" below):
/// ECDH(KEK, hashed per-payload point) -> HKDF-SHA512 -> AES-256-GCM, the
/// Linux and Windows libraries' construction. The hook for a future one to
/// be recognised at parse time; this build implements exactly one.
private let hkdfguardSuiteId: UInt8 = 0x01
private let hkdfguardSuiteIdLength = 1

/// The per-payload random salt: it selects the payload's ECDH point (see
/// `payloadECDHPoint`) and is HKDF's salt. Linux's SALT_LEN.
private let hkdfguardSaltLength = 32

/// The AES-GCM nonce, random per payload. Linux's NONCE_LEN.
private let hkdfguardNonceLength = 12

/// AES-GCM tag length.
private let hkdfguardGCMTagLength = 16

/// The exact length of every wrapped payload:
///   fingerprint || suite id || salt || nonce || ciphertext (DEK length) || tag
/// = 32 + 1 + 32 + 12 + 32 + 16 = 125 bytes. Known up front, so both wrap and
/// unwrap can reject a wrong-sized buffer before any keychain or Secure
/// Enclave work.
private let hkdfguardWrappedLength =
    hkdfguardFingerprintLength + hkdfguardSuiteIdLength + hkdfguardSaltLength + hkdfguardNonceLength
    + hkdfguardDekLength + hkdfguardGCMTagLength

/// Offsets of each field within a payload. Everything before the
/// ciphertext is the header, authenticated as a whole (see `wrapDekCore`).
private let hkdfguardSuiteIdOffset = hkdfguardFingerprintLength
private let hkdfguardSaltOffset = hkdfguardSuiteIdOffset + hkdfguardSuiteIdLength
private let hkdfguardNonceOffset = hkdfguardSaltOffset + hkdfguardSaltLength
private let hkdfguardCiphertextOffset = hkdfguardNonceOffset + hkdfguardNonceLength
private let hkdfguardHeaderLength = hkdfguardCiphertextOffset
private let hkdfguardCiphertextLength = hkdfguardDekLength + hkdfguardGCMTagLength

/// HKDF `info` prefix and the salt-to-point hash's domain, byte for byte
/// the Linux library's (HKDF_INFO_PREFIX, PAYLOAD_POINT_DOMAIN). Payloads
/// are host-only, so nothing requires the labels to match; matching keeps
/// the three implementations reviewable as one design.
private let hkdfguardHKDFInfoPrefix = Data("hkdfguard-wrap-v1:".utf8)
private let hkdfguardPayloadPointDomain = Data("HkdfGuard-P256-payload-ECDH-point-v1:".utf8)

/// HKDF `info` for one payload: prefix || len(service) as u16 little-endian
/// || service || header. The length prefix keeps the concatenation
/// unambiguous, so no two distinct (service, header) pairs give the same
/// `info`; the header binds the fingerprint, suite, salt and nonce into the
/// key itself. Linux's `derive_wrapping_key`.
func wrappingKeyInfo(service: String, header: Data) -> Data { // internal: the forgery tests rebuild payloads with it
    let serviceBytes = Data(service.utf8) // validated ASCII, at most 128 bytes
    var info = hkdfguardHKDFInfoPrefix
    info.append(UInt8(truncatingIfNeeded: serviceBytes.count))
    info.append(UInt8(truncatingIfNeeded: serviceBytes.count >> 8))
    info.append(serviceBytes)
    info.append(header)
    return info
}

/// Hashes `salt` to a P-256 point: the first `X = SHA-256(domain || salt ||
/// counter)` that is a valid x-coordinate, with the even-Y point (compressed
/// 0x02 || X). Linux's `payload_ecdh_point`, byte for byte.
///
/// Why: the wrapping key comes from `ECDH(KEK_priv, H)`. Nobody knows the
/// discrete log of a hash output, so computing it takes the KEK's private
/// key, which never leaves the Secure Enclave -- only this host can create
/// a payload, as well as open one. An ephemeral sender key (HPKE base mode,
/// ECIES) would let anyone holding the KEK's *public* key derive the same
/// secret and mint a payload carrying a DEK of their choosing. One point
/// per payload, rather than one fixed point, makes the shared secret unique
/// to the payload: capturing it once opens that payload, not the service's
/// whole history.
///
/// Roughly half of all candidates are on the curve, so 255 failures has
/// probability 2^-255. Not constant-time, and need not be: the salt is
/// public. P-256 has cofactor 1, so any point that decompresses is in the
/// prime-order group. CryptoKit validates the point while decompressing.
func payloadECDHPoint(salt: Data) -> P256.KeyAgreement.PublicKey? {
    for counter in UInt8(0)..<UInt8.max {
        var hasher = SHA256()
        hasher.update(data: hkdfguardPayloadPointDomain)
        hasher.update(data: salt)
        hasher.update(data: [counter])
        var compressed = Data([0x02])
        compressed.append(contentsOf: hasher.finalize())
        if let point = try? P256.KeyAgreement.PublicKey(compressedRepresentation: compressed) {
            return point
        }
    }
    return nil
}

/// The AES-256 wrapping key for one payload: the Secure Enclave computes
/// `ECDH(KEK_priv, payloadECDHPoint(salt))`, and HKDF-SHA512 (salt = the
/// payload salt, `info` = `wrappingKeyInfo`) turns it into 32 bytes. The raw
/// shared secret stays inside CryptoKit's `SharedSecret` and never becomes
/// a buffer here. Throws if the enclave refuses (CRYPTO_ERROR); nil only if
/// no point exists for the salt.
private func deriveWrappingKey(
    enclaveKey: SecureEnclave.P256.KeyAgreement.PrivateKey,
    service: String,
    header: Data
) throws -> SymmetricKey? {
    let salt = header[hkdfguardSaltOffset..<hkdfguardNonceOffset]
    guard let point = payloadECDHPoint(salt: Data(salt)) else {
        return nil
    }
    let shared = try enclaveKey.sharedSecretFromKeyAgreement(with: point)
    return shared.hkdfDerivedSymmetricKey(
        using: SHA512.self,
        salt: salt,
        sharedInfo: wrappingKeyInfo(service: service, header: header),
        outputByteCount: 32
    )
}

private func randomBytes(_ count: Int) -> Data? {
    var bytes = Data(count: count)
    let status = bytes.withUnsafeMutableBytes { raw -> OSStatus in
        guard let base = raw.baseAddress else { return errSecParam }
        return SecRandomCopyBytes(kSecRandomDefault, count, base)
    }
    return status == errSecSuccess ? bytes : nil
}

// MARK: - Keychain mode (hybrid)

/// Which keychain the KEK's keychain item lives in. Decided once per
/// process, from the process's own code-signing entitlements — see
/// `detectKeychainMode` — never from configuration or the environment.
///
/// - `dataProtection`: the process carries a `keychain-access-groups`
///   entitlement (which on macOS requires a Team-signed app bundle with an
///   embedded provisioning profile). Items go in the data-protection
///   keychain under `accessGroup`, where access is decided by securityd
///   from the caller's signed identity: no ACL prompts, no per-item ACLs,
///   `kSecAttrAccessible` is honored, and any Team-signed bundle listing
///   the same group shares the item deterministically. The hardened mode.
/// - `legacy`: no such entitlement (a bare executable: this CLI as a
///   plain Mach-O, a .NET/Python/Go host that `dlopen`s this dylib, the
///   `xctest` agent). Items go in the login keychain, protected by its
///   lock and a per-item ACL keyed to the creating binary's signature;
///   other identities hit an interactive prompt, or headless,
///   `keychainAccessDenied`.
///
/// This is not a silent downgrade: an unentitled process cannot see
/// data-protection items at all, and the mode is derived from a signature
/// an attacker cannot alter without invalidating it. It does create one
/// deployment invariant — **the process that provisions a service's KEK and
/// every process that unwraps under it must run in the same mode** — which
/// is why `hkdfguard_keychain_mode` exposes the decision and the CLI prints
/// it.
enum KeychainMode: Equatable {
    case legacy
    case dataProtection(accessGroup: String)
}

let hkdfguardKeychainMode: KeychainMode = detectKeychainMode()

private func detectKeychainMode() -> KeychainMode {
    guard let task = SecTaskCreateFromSelf(nil) else {
        return .legacy
    }
    guard let value = SecTaskCopyValueForEntitlement(task, "keychain-access-groups" as CFString, nil),
          let groups = value as? [String],
          let first = groups.first(where: { !$0.isEmpty }) else {
        return .legacy
    }
    return .dataProtection(accessGroup: first)
}

/// The attributes every keychain query/add for a service's KEK item shares,
/// including the ones that select the keychain `mode` puts it in.
private func keychainItemAttributes(service: String, mode: KeychainMode) -> [String: Any] {
    var attributes: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: hkdfguardKeychainAccount,
        // Explicit in both modes so a query can never match an iCloud-synced
        // item, and so the intent is visible rather than a default.
        kSecAttrSynchronizable as String: false,
    ]
    switch mode {
    case .legacy:
        // Explicit false, not omitted: on newer SDKs an omitted key can
        // default to the data-protection keychain rather than the legacy
        // file-based one for a process that also carries
        // keychain-access-groups, which would silently defeat the two
        // keychains' disjointness.
        attributes[kSecUseDataProtectionKeychain as String] = false
    case .dataProtection(let accessGroup):
        attributes[kSecUseDataProtectionKeychain as String] = true
        attributes[kSecAttrAccessGroup as String] = accessGroup
    }
    return attributes
}

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
    /// KEK fingerprint (see `kekFingerprint` below) doesn't match the public
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
    /// owned by someone else or writable by group or others without being
    /// sticky (see `keyFileFoldersAreTrusted`) — so a party other than its
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

// MARK: - Zeroing secrets

/// Zeroes `bytes` with `memset_s`, which the C standard forbids the compiler
/// from eliding as a dead store — unlike a plain memset/`initializeMemory`
/// right before the buffer is freed. Best effort still: it covers only the
/// copy it is handed.
private func secureZero(_ bytes: inout Data) {
    bytes.withUnsafeMutableBytes { raw in
        guard let base = raw.baseAddress, raw.count > 0 else { return }
        _ = memset_s(base, raw.count, 0, raw.count)
    }
}

/// Copies the first `count` bytes of `bytes` to `out`, or reports that it
/// couldn't. Never traps: Swift can't catch a runtime trap the way the
/// Linux build catches a panic at every export (and Windows an exception),
/// so a trap here would end the host process instead of returning a status.
/// The library therefore has no force-unwrap, `try!`, `fatalError` or
/// `precondition` on any path an export can reach (the
/// `theLibraryHasNoTrapsOnItsExportPaths` test enforces it); a failure
/// that "can't happen" becomes INTERNAL_ERROR (-6) instead.
private func copyOut<Bytes: ContiguousBytes>(_ bytes: Bytes, to out: UnsafeMutablePointer<UInt8>, count: Int) -> Bool {
    bytes.withUnsafeBytes { raw in
        guard count > 0, count <= raw.count, let source = raw.baseAddress else {
            return false
        }
        memcpy(out, source, count)
        return true
    }
}

private func secureZero(_ bytes: inout [UInt8]) {
    bytes.withUnsafeMutableBytes { raw in
        guard let base = raw.baseAddress, raw.count > 0 else { return }
        _ = memset_s(base, raw.count, 0, raw.count)
    }
}

// MARK: - Secure Enclave KEK lookup / provisioning

/// The access policy baked into every KEK at creation — what the Secure
/// Enclave enforces on each use of the key, independent of which keychain
/// (see `KeychainMode`) the key's item lives in. Fixed; there is no
/// per-service override.
///
/// - `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`: usable only while the
///   device is unlocked, and never migrated to another device (no backup or
///   restore can carry it). "Unlocked" means the login user's keybag: a
///   LaunchDaemon or SSH session on a Mac with no unlocked GUI session may
///   find the key unavailable — surfacing as `keyGenerationFailed`/
///   `decryptionFailed` from the enclave, or `keychainAccessDenied` from a
///   locked keychain. Headless consumers should run as a LaunchAgent inside
///   a logged-in session, or otherwise ensure the login keychain is
///   unlocked.
/// - `.privateKeyUsage` alone — no `.userPresence`/`.biometryAny`, so no
///   Touch ID or password prompt is ever required to *use* the key. That is
///   deliberate: this library serves unattended services. It means the
///   protection boundary is "which processes may read the keychain item"
///   (the keychain mode's job), not "a human approved this use".
private func makeAccessControl() -> SecAccessControl? {
    var error: Unmanaged<CFError>?
    return SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage],
        &error
    )
}

/// Maximum accepted length of a service name, in UTF-8 bytes (which, for
/// the ASCII-only charset below, is also its character count).
private let hkdfguardMaxServiceLength = 128

/// ASCII letters, digits, and '.' — nothing else. Checked on raw UTF-8
/// bytes rather than `Character` properties on purpose: `Character.isLetter`
/// / `isNumber` are Unicode-aware and would accept `é`, CJK, Arabic-Indic
/// digits, `½`, and so on, while `String.count` counts grapheme clusters
/// rather than bytes. The C header, the CLI, and this project's Linux
/// tool all promise (and enforce) ASCII bytes, so this must too.
private func isValidServiceByte(_ byte: UInt8) -> Bool {
    (0x30...0x39).contains(byte)      // '0'-'9'
        || (0x41...0x5A).contains(byte) // 'A'-'Z'
        || (0x61...0x7A).contains(byte) // 'a'-'z'
        || byte == 0x2E                 // '.'
}

/// The shared HkdfGuard service-name rule (hkdfguard-native-linux's
/// `cstr_to_service` is the source of record): 1-128 bytes, ASCII letters,
/// digits, and '.' only, not starting with '.', and with no two consecutive
/// dots. So a name can never be ".", "..", or a hidden dot-name, and never
/// has an empty label between dots -- the same names are valid on every
/// platform.
private func validServiceName(service: String) -> Bool {
    let bytes = service.utf8
    guard !bytes.isEmpty, bytes.count <= hkdfguardMaxServiceLength else {
        return false
    }
    guard bytes.allSatisfy(isValidServiceByte) else {
        return false
    }
    guard bytes.first != 0x2E else { // leading '.'
        return false
    }
    return !zip(bytes, bytes.dropFirst()).contains { $0 == 0x2E && $1 == 0x2E } // ".."
}

/// Every C ABI entry point below calls this immediately after receiving
/// the raw C string, before any keychain/crypto use. It validates first
/// and lowercases second — in that order, because Unicode case-folding
/// can change byte length and map non-ASCII input onto ASCII (KELVIN SIGN
/// U+212A lowercases to plain `k`), so lowercasing before validation
/// would let such input through. After `validServiceName` has confirmed
/// pure ASCII, an ASCII-only lowercase is exact and length-preserving.
///
/// Service names are case-insensitive (`"Com.Example.App"` and
/// `"com.example.app"` resolve to the same KEK); the returned string is
/// the one normalized form that `validServiceName` re-checks downstream,
/// the keychain query/store calls use, and the HKDF `info` is built from. Returns `nil` when the name is invalid — the
/// caller maps that to `invalidServiceIdentifier`.
///
/// The terminator is looked for in at most 129 bytes (`strnlen`), as on
/// Linux, rather than with `String(cString:)`, which reads until it finds a
/// NUL however far away: an unterminated or over-long string is rejected
/// without reading past the longest name that could be valid.
private func normalizedService(from servicePtr: UnsafePointer<CChar>) -> String? {
    let length = strnlen(servicePtr, hkdfguardMaxServiceLength + 1)
    guard length <= hkdfguardMaxServiceLength else { return nil }
    let raw = String(decoding: UnsafeRawBufferPointer(start: servicePtr, count: length), as: UTF8.self)
    guard validServiceName(service: raw) else { return nil }
    let lowered = raw.utf8.map { byte in
        (0x41...0x5A).contains(byte) ? byte + 0x20 : byte
    }
    return String(decoding: lowered, as: UTF8.self)
}

/// Outcome of looking up a service's keychain item. `notFound` is the only
/// case that means "no key exists"; the other two failure cases mean the
/// keychain would not or could not answer, and a key may well exist — the
/// callers below must never treat those as a clean slate.
private enum KEKLookup {
    case found(Data)
    case notFound
    /// Locked keychain / no UI session, ACL denial, user declined the
    /// prompt, or missing entitlement — see `HKDFGuardStatus.keychainAccessDenied`.
    case accessDenied
    case failed(OSStatus)
}

/// Looks up the persisted Secure Enclave key's opaque data representation
/// in the keychain, under the caller-supplied service identifier.
private func loadKEKDataRepresentation(service: String, mode: KeychainMode) -> KEKLookup {
    var query = keychainItemAttributes(service: service, mode: mode)
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne

    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    switch status {
    case errSecSuccess:
        guard let data = item as? Data else { return .failed(errSecInternalError) }
        return .found(data)
    case errSecItemNotFound:
        return .notFound
    case errSecInteractionNotAllowed, errSecAuthFailed, errSecUserCanceled, errSecMissingEntitlement:
        return .accessDenied
    default:
        return .failed(status)
    }
}

/// What a stored KEK blob turned out to be.
enum KEKReconstruction {
    case key(SecureEnclave.P256.KeyAgreement.PrivateKey)
    /// Not a usable key for this device, though the enclave works:
    /// `HKDFGuardStatus.kekCorrupted`.
    case corrupt
    /// The enclave would not load even a key made just now under the same
    /// policy, so this blob's failure says nothing about the blob: reported
    /// as `HKDFGuardStatus.keychainAccessDenied` (a KEK very likely exists).
    case enclaveRefused
}

/// Reconstructs a Secure Enclave key from a keychain item's stored data.
///
/// A blob can fail to load for two very different reasons: it is not (or
/// no longer) a key for this device, or this session's keybag is locked --
/// an SSH login after `security unlock-keychain`, say, where the keychain
/// hands the item over but the enclave refuses keys bound to "when
/// unlocked". Reporting the second as corrupt would point an operator at
/// deleting a healthy KEK, and every DEK under it with it. So on failure
/// the enclave is probed, and only a failure the probe survives is corrupt.
func reconstructKEK(
    _ data: Data,
    enclaveIsUsable: () -> Bool = secureEnclaveIsUsableNow
) -> KEKReconstruction {
    if let key = try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: data) {
        return .key(key)
    }
    return enclaveIsUsable() ? .corrupt : .enclaveRefused
}

/// Whether the Secure Enclave and this user's keybag can use keys in this
/// session: a throwaway key is created under the KEK's own access policy,
/// reconstructed from its data representation exactly as a stored KEK is,
/// and used once. Nothing is stored. Only run when a stored blob has
/// already failed to load, so a healthy KEK never pays for it.
func secureEnclaveIsUsableNow() -> Bool {
    enclaveProbeSucceeds(makeAccessControl())
}

/// The probe itself, under `access` -- the user-scoped KEKs' policy above,
/// or the machine KEKs'.
private func enclaveProbeSucceeds(_ access: SecAccessControl?) -> Bool {
    guard SecureEnclave.isAvailable,
          let access,
          let probe = try? SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access) else {
        return false
    }
    var blob = probe.dataRepresentation
    defer { secureZero(&blob) }
    guard let reloaded = try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob) else {
        return false
    }
    let peer = P256.KeyAgreement.PrivateKey().publicKey
    return (try? reloaded.sharedSecretFromKeyAgreement(with: peer)) != nil
}

@discardableResult
private func storeKEKDataRepresentation(_ data: Data, service: String, mode: KeychainMode) -> OSStatus {
    var attributes = keychainItemAttributes(service: service, mode: mode)
    attributes[kSecValueData as String] = data
    // Honored by the data-protection keychain; accepted but ignored by the
    // legacy keychain, where the login keychain's own lock applies instead.
    attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    return SecItemAdd(attributes as CFDictionary, nil)
}

/// Reports whether a valid, reconstructable KEK already exists for
/// `service`, without creating one. Distinguishes "no key yet" (`success`,
/// `false`) from "a keychain item is present but can't be reconstructed"
/// (`kekCorrupted`, `false`) — a caller that only looked at the boolean
/// would otherwise treat a corrupt/foreign entry the same as a clean slate.
func kekExists(service: String, mode: KeychainMode = hkdfguardKeychainMode) -> (status: Int32, exists: Bool) {
    guard validServiceName(service: service) else {
        return (HKDFGuardStatus.invalidServiceIdentifier.rawValue, false)
    }

    guard SecureEnclave.isAvailable else {
        return (HKDFGuardStatus.enclaveUnavailable.rawValue, false)
    }

    switch kekScope(service: service) {
    case .policyInvalid:
        return (HKDFGuardStatus.policyInvalid.rawValue, false)
    case .machine:
        return machineKekExists(service: service)
    case .user:
        break
    }

    switch loadKEKDataRepresentation(service: service, mode: mode) {
    case .notFound:
        return (HKDFGuardStatus.success.rawValue, false)
    case .accessDenied:
        return (HKDFGuardStatus.keychainAccessDenied.rawValue, false)
    case .failed:
        return (HKDFGuardStatus.keychainReadFailed.rawValue, false)
    case .found(var existing):
        defer { secureZero(&existing) } // the SEP-wrapped blob is the credential: don't leave this copy behind
        switch reconstructKEK(existing) {
        case .key:
            return (HKDFGuardStatus.success.rawValue, true)
        case .corrupt:
            return (HKDFGuardStatus.kekCorrupted.rawValue, false)
        case .enclaveRefused:
            return (HKDFGuardStatus.keychainAccessDenied.rawValue, false)
        }
    }
}

/// Creates a KEK for `service` if one doesn't already exist. Idempotent
/// and safe under concurrent first-use — see the duplicate-item handling
/// below — so a caller that already checked `kekExists` and got `false`
/// doesn't need to treat a race against another creator as its own error.
func createKEK(service: String, mode: KeychainMode = hkdfguardKeychainMode) -> Int32 {

    // Validate service identifier.
    guard validServiceName(service: service) else {
        return HKDFGuardStatus.invalidServiceIdentifier.rawValue
    }

    // Secure Enclave must exist.
    guard SecureEnclave.isAvailable else {
        return HKDFGuardStatus.enclaveUnavailable.rawValue
    }

    switch kekScope(service: service) {
    case .policyInvalid:
        return HKDFGuardStatus.policyInvalid.rawValue
    case .machine(let settings):
        return createMachineKEK(service: service, settings: settings)
    case .user:
        break
    }

    // Existing key? Only a definite "not found" may proceed to create one:
    // a denied or failed lookup means a key may already exist that this
    // process simply can't see, and generating a replacement on top of it
    // would orphan whatever that key protects.
    switch loadKEKDataRepresentation(service: service, mode: mode) {
    case .found(var existing):
        defer { secureZero(&existing) } // the SEP-wrapped blob is the credential: don't leave this copy behind
        // An item that can't be reconstructed is never replaced, whichever
        // the reason.
        switch reconstructKEK(existing) {
        case .key:
            return HKDFGuardStatus.success.rawValue
        case .corrupt:
            return HKDFGuardStatus.kekCorrupted.rawValue
        case .enclaveRefused:
            return HKDFGuardStatus.keychainAccessDenied.rawValue
        }
    case .accessDenied:
        return HKDFGuardStatus.keychainAccessDenied.rawValue
    case .failed:
        return HKDFGuardStatus.keychainReadFailed.rawValue
    case .notFound:
        break
    }

    // No key exists. Create one.
    guard let access = makeAccessControl() else {
        return HKDFGuardStatus.accessControlCreationFailed.rawValue
    }

    guard let newKey =
        try? SecureEnclave.P256.KeyAgreement.PrivateKey(
            accessControl: access
        )
    else {
        return HKDFGuardStatus.keyGenerationFailed.rawValue
    }

    // The SEP-wrapped key blob is the very credential the keychain item
    // exists to protect: usable by any process on this device that holds
    // it, while unlocked. This zeroes the one copy this function owns, on
    // every exit path -- including the race-loser path below, where it is
    // never stored at all. It is best-effort, not a guarantee: `newKey`
    // keeps its own internal copy of the blob, which CryptoKit offers no way
    // to zero and which is freed, unzeroed, when `newKey` goes out of scope
    // at the end of this function.
    var representation = newKey.dataRepresentation
    defer { secureZero(&representation) }

    let status = storeKEKDataRepresentation(
        representation,
        service: service,
        mode: mode
    )

    switch status {

    case errSecSuccess:

        // Verify store/reload/reconstruct succeeds.
        switch loadKEKDataRepresentation(service: service, mode: mode) {
        case .found(var stored):
            defer { secureZero(&stored) }
            switch reconstructKEK(stored) {
            case .key:
                auditKekCreated(service: service, mode: mode)
                return HKDFGuardStatus.success.rawValue
            case .corrupt:
                return HKDFGuardStatus.kekVerificationFailed.rawValue
            case .enclaveRefused:
                return HKDFGuardStatus.keychainAccessDenied.rawValue
            }
        case .accessDenied:
            return HKDFGuardStatus.keychainAccessDenied.rawValue
        case .notFound, .failed:
            return HKDFGuardStatus.kekVerificationFailed.rawValue
        }

    case errSecDuplicateItem:

        // Another thread/process won the race. Validate the winner's key
        // before declaring success. If the winner was a differently-signed
        // process, its item's ACL may deny this one — that is
        // keychainAccessDenied, not a corrupt item.
        switch loadKEKDataRepresentation(service: service, mode: mode) {
        case .found(var existing):
            defer { secureZero(&existing) }
            switch reconstructKEK(existing) {
            case .key:
                return HKDFGuardStatus.success.rawValue
            case .corrupt:
                return HKDFGuardStatus.kekCorrupted.rawValue
            case .enclaveRefused:
                return HKDFGuardStatus.keychainAccessDenied.rawValue
            }
        case .accessDenied:
            return HKDFGuardStatus.keychainAccessDenied.rawValue
        case .notFound, .failed:
            return HKDFGuardStatus.keychainReadFailed.rawValue
        }

    case errSecMissingEntitlement, errSecInteractionNotAllowed, errSecAuthFailed, errSecUserCanceled:
        // Normally caught by the lookup above; kept so a write that is
        // refused for access reasons is never reported as a generic write
        // failure.
        return HKDFGuardStatus.keychainAccessDenied.rawValue

    default:
        return HKDFGuardStatus.keychainWriteFailed.rawValue
    }
}

/// Looks up the KEK for `service` — never creates one. Returns the
/// specific reason it couldn't, when it couldn't, rather than a plain
/// `nil`: `wrapDekCore`/`hkdfguard_unwrap_dek` below propagate this
/// `status` directly on failure, so a caller finds out whether there's
/// simply no key yet (`kekNotFound` — the ordinary state before
/// `hkdfguard_create_kek` has been called), the enclave itself is
/// unavailable, the service name is malformed, or an existing item is
/// corrupt, instead of one indistinguishable failure.
func getKEK(service: String, mode: KeychainMode = hkdfguardKeychainMode) -> (status: Int32, key: SecureEnclave.P256.KeyAgreement.PrivateKey?) {
    guard validServiceName(service: service) else {
        return (HKDFGuardStatus.invalidServiceIdentifier.rawValue, nil)
    }

    guard SecureEnclave.isAvailable else {
        return (HKDFGuardStatus.enclaveUnavailable.rawValue, nil)
    }

    switch kekScope(service: service) {
    case .policyInvalid:
        return (HKDFGuardStatus.policyInvalid.rawValue, nil)
    case .machine:
        return getMachineKEK(service: service)
    case .user:
        break
    }

    switch loadKEKDataRepresentation(service: service, mode: mode) {
    case .notFound:
        return (HKDFGuardStatus.kekNotFound.rawValue, nil)
    case .accessDenied:
        return (HKDFGuardStatus.keychainAccessDenied.rawValue, nil)
    case .failed:
        return (HKDFGuardStatus.keychainReadFailed.rawValue, nil)
    case .found(var existing):
        defer { secureZero(&existing) } // best effort: `key` keeps CryptoKit's own copy
        switch reconstructKEK(existing) {
        case .key(let key):
            return (HKDFGuardStatus.success.rawValue, key)
        case .corrupt:
            return (HKDFGuardStatus.kekCorrupted.rawValue, nil)
        case .enclaveRefused:
            return (HKDFGuardStatus.keychainAccessDenied.rawValue, nil)
        }
    }
}

/// Computes the "fingerprint" embedded at the front of every wrapped
/// payload: a SHA-256 hash of the KEK's public key, uncompressed X9.63
/// (0x04 || x || y) -- the encoding Linux and Windows hash.
/// Not a secret value — the public key it hashes isn't secret either —
/// so the explicit equality check against it in `hkdfguard_unwrap_dek`
/// exists purely to fail fast, cheaply, on "this payload wasn't wrapped
/// under the KEK I just resolved for this service" *before* spending any
/// effort on ECDH/AES-GCM. It is also in the authenticated header (see
/// `wrapDekCore`), so the derived key and the tag commit to it too.
func kekFingerprint(_ publicKey: P256.KeyAgreement.PublicKey) -> Data {
    Data(SHA256.hash(data: publicKey.x963Representation))
}

// MARK: - Machine scope (production mode)
//
// With no policy -- development mode -- every KEK is user-scoped, as above.
// A production policy can name services whose KEK is machine-scoped
// instead: created by root in the system context (a LaunchDaemon, never a
// login session), kept as a root-owned file its service's runner group may
// read, and usable only by LaunchDaemons. The Secure Enclave binds a key to
// the context it was created in: one created from Terminal -- `sudo`
// included -- is unusable by daemons, and one created by a daemon is
// unusable from any login session. So a machine KEK serves services that
// run as LaunchDaemons, survives logouts, password resets and reboots
// (AfterFirstUnlock), and can't be used from Terminal or over SSH.

private let machineLog = Logger(subsystem: "com.hkdfguard", category: "machine")

/// The device-level managed preferences macOS writes for an MDM
/// configuration profile with the `com.hkdfguard` preference domain.
let managedPolicyFilePath = "/Library/Managed Preferences/com.hkdfguard.plist"
/// The policy on a Mac without MDM. Ignored when a managed one exists.
let localPolicyFilePath = "/Library/Application Support/HkdfGuard/policy.plist"
/// One file per machine-scoped service: `<service>.kek`.
let machineKeyFolderPath = "/Library/Application Support/HkdfGuard/keks"
private let machinePolicyMaxSize = 64 * 1024

/// A machine-scoped service's settings.
struct MachineServiceSettings: Equatable {
    /// The group whose members -- the service accounts its LaunchDaemons
    /// run as -- may read its KEK file. nil: root only.
    var runnerGroup: String?
}

struct MachinePolicy: Equatable {
    var source: String
    /// Who may provision and retire machine KEKs (the CLI checks it).
    var securityAdminGroup: String?
    /// Who may wrap DEKs under them (the CLI checks it).
    var deploymentAdminGroup: String?
    /// Normalized (lowercase) service name -> its settings.
    var machineServices: [String: MachineServiceSettings]
}

enum PolicyLoad: Equatable {
    case none                  // development mode
    case loaded(MachinePolicy) // production mode
    case invalid(String)       // every call fails closed with POLICY_INVALID
}

/// Test-only overrides of where the policy and the machine KEKs come
/// from. `nil` (the default, and always in production) reads the real
/// ones. Task-local, so a test's override applies to its own calls only,
/// never to a suite running alongside it; internal, so only `@testable
/// import` can reach them -- never part of the C ABI.
enum MachineScopeTestOverrides {
    @TaskLocal static var policy: PolicyLoad?
    @TaskLocal static var keyFolder: String?
}

private struct PolicyError: Error {
    let reason: String
}

/// A local or directory group name: ASCII letters, digits, `_`, `-`, `.`.
func validGroupName(_ name: String) -> Bool {
    let bytes = Array(name.utf8)
    guard !bytes.isEmpty, bytes.count <= 255, bytes.first != UInt8(ascii: "-") else {
        return false
    }
    return bytes.allSatisfy { byte in
        (0x30...0x39).contains(byte) || (0x41...0x5A).contains(byte) || (0x61...0x7A).contains(byte)
            || byte == UInt8(ascii: "_") || byte == UInt8(ascii: "-") || byte == UInt8(ascii: ".")
    }
}

/// Validates and parses a policy's settings. Strict: an unknown setting or
/// a wrong type makes the whole policy invalid, never ignored -- a
/// misspelt `MachineServices` would otherwise leave a production service
/// quietly user-scoped.
func parseMachinePolicy(_ values: [String: Any], source: String) -> PolicyLoad {
    func group(_ value: Any?, _ setting: String) throws -> String? {
        guard let value else {
            return nil
        }
        guard let name = value as? String, validGroupName(name) else {
            throw PolicyError(reason: "\(setting) must be a group name")
        }
        return name
    }
    do {
        let known: Set<String> = ["MachineServices", "SecurityAdminGroup", "DeploymentAdminGroup"]
        if let unknown = Set(values.keys).subtracting(known).sorted().first {
            throw PolicyError(reason: "unknown setting \"\(unknown)\"")
        }
        var services: [String: MachineServiceSettings] = [:]
        if let raw = values["MachineServices"] {
            guard let table = raw as? [String: Any] else {
                throw PolicyError(reason: "MachineServices must be a dictionary keyed by service name")
            }
            for name in table.keys.sorted() {
                guard validServiceName(service: name) else {
                    throw PolicyError(reason: "MachineServices: \"\(name)\" is not a valid service name")
                }
                let service = String(decoding: name.utf8.map { (0x41...0x5A).contains($0) ? $0 + 0x20 : $0 }, as: UTF8.self)
                guard let settings = table[name] as? [String: Any] else {
                    throw PolicyError(reason: "MachineServices.\(name) must be a dictionary")
                }
                if let unknown = Set(settings.keys).subtracting(["RunnerGroup"]).sorted().first {
                    throw PolicyError(reason: "MachineServices.\(name): unknown setting \"\(unknown)\"")
                }
                guard services[service] == nil else {
                    throw PolicyError(reason: "MachineServices names \"\(service)\" twice (service names are case-insensitive)")
                }
                services[service] = MachineServiceSettings(
                    runnerGroup: try group(settings["RunnerGroup"], "MachineServices.\(name).RunnerGroup"))
            }
        }
        return .loaded(MachinePolicy(
            source: source,
            securityAdminGroup: try group(values["SecurityAdminGroup"], "SecurityAdminGroup"),
            deploymentAdminGroup: try group(values["DeploymentAdminGroup"], "DeploymentAdminGroup"),
            machineServices: services))
    } catch let error as PolicyError {
        return .invalid("\(source): \(error.reason)")
    } catch {
        return .invalid("\(source): \(error)")
    }
}

/// Reads all of `fd`, refusing more than `limit` bytes. nil on a read
/// error or an oversized file.
private func readAll(fd: Int32, limit: Int) -> Data? {
    var data = Data()
    var buffer = [UInt8](repeating: 0, count: 4096)
    defer { secureZero(&buffer) }
    while data.count <= limit {
        let count = buffer.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
        if count < 0 {
            if errno == EINTR {
                continue
            }
            return nil
        }
        if count == 0 {
            return data
        }
        data.append(contentsOf: buffer[0..<count])
    }
    return nil
}

/// The policy at `path`, read as a file rather than through CFPreferences
/// so that every setting in it is seen and validated. nil when there is
/// no such file. It, and every folder above it, must be root's and
/// writable by root alone -- as Linux requires of its policy.
func loadPolicyFile(atPath path: String) -> PolicyLoad? {
    let url = URL(fileURLWithPath: path)
    let folderFd = open(url.deletingLastPathComponent().path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    guard folderFd >= 0 else {
        let code = errno
        return code == ENOENT ? nil : .invalid("\(path): its folder can't be opened (\(String(cString: strerror(code))))")
    }
    defer { close(folderFd) }
    let fd = openat(folderFd, url.lastPathComponent, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
    guard fd >= 0 else {
        let code = errno
        return code == ENOENT ? nil : .invalid("\(path) can't be opened (\(String(cString: strerror(code))))")
    }
    defer { close(fd) }
    guard keyFileFoldersAreTrusted(folderFd: folderFd, rootOnly: true) else {
        return .invalid("\(path): a folder above it is not root's, or others can write it")
    }
    var info = stat()
    guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG else {
        return .invalid("\(path) is not a regular file")
    }
    guard info.st_uid == 0, info.st_mode & (S_IWGRP | S_IWOTH) == 0,
          !onVolumeIgnoringOwnership(fd),
          !aclGrantsOthersAChange(fd: fd, isFolder: false, rootOnly: true) else {
        return .invalid("\(path) must be owned by root and writable by root alone")
    }
    guard info.st_size <= off_t(machinePolicyMaxSize), let data = readAll(fd: fd, limit: machinePolicyMaxSize) else {
        return .invalid("\(path) is larger than \(machinePolicyMaxSize) bytes, or can't be read")
    }
    guard let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
          let values = plist as? [String: Any] else {
        return .invalid("\(path) is not a property list dictionary")
    }
    return parseMachinePolicy(values, source: path)
}

/// The policy in effect: the managed one if MDM delivered it, else the
/// local file, else none (development mode). Read on every call, so a
/// changed profile takes effect without restarting anything.
func currentMachinePolicy() -> PolicyLoad {
    if let forced = MachineScopeTestOverrides.policy {
        return forced
    }
    if let managed = loadPolicyFile(atPath: managedPolicyFilePath) {
        return managed
    }
    return loadPolicyFile(atPath: localPolicyFilePath) ?? .none
}

/// Where a service's KEK lives.
enum KEKScope: Equatable {
    case user
    case machine(MachineServiceSettings)
    /// The policy can't be used: every call fails closed, whatever the
    /// service, until it is fixed -- as on Linux.
    case policyInvalid
}

func kekScope(service: String) -> KEKScope {
    switch currentMachinePolicy() {
    case .none:
        return .user
    case .invalid(let reason):
        machineLog.error("hkdfguard policy invalid, every call fails closed until it is fixed: \(reason, privacy: .public)")
        return .policyInvalid
    case .loaded(let policy):
        return policy.machineServices[service].map { .machine($0) } ?? .user
    }
}

/// Whether this process runs outside every login session: a LaunchDaemon,
/// or a process one started -- not Terminal, `sudo` from it, SSH, or a GUI
/// app. Judged from the process's audit session, which every process of a
/// login session shares and none can leave: one with graphic, terminal,
/// remote or console access is a login session. The Secure Enclave binds a
/// key to the context it was created in, so a machine KEK must be created
/// here to be usable by daemons, and is refused here first anywhere else.
func runningInSystemContext() -> Bool {
    var info = auditinfo_addr_t()
    guard getaudit_addr(&info, Int32(MemoryLayout<auditinfo_addr_t>.size)) == 0 else {
        return false
    }
    // AU_SESSION_FLAG_HAS_GRAPHIC_ACCESS | _HAS_TTY | _IS_REMOTE | _HAS_CONSOLE_ACCESS
    let loginSessionFlags: UInt64 = 0x0010 | 0x0020 | 0x1000 | 0x2000
    return UInt64(info.ai_flags) & loginSessionFlags == 0
}

// The machine KEK file: magic "HKGK", format 1, the KEK's public key
// (uncompressed x963, 65 bytes) -- so its fingerprint can be read without
// the Secure Enclave, by `status` and `retire` -- then the Secure Enclave
// blob, length-prefixed (big-endian u16). The blob is usable only by this
// Mac's Secure Enclave, in the system context.
private let machineKeyMagic = Data("HKGK".utf8)
private let machineKeyFormatVersion: UInt8 = 1
private let machineKeyPublicKeyLength = 65
private let machineKeyHeaderLength = 4 + 1 + 65 + 2
private let machineKeyMaxSize = 4096

struct MachineKeyFile: Equatable {
    var publicKey: Data
    var blob: Data
}

func encodeMachineKeyFile(_ file: MachineKeyFile) -> Data? {
    guard file.publicKey.count == machineKeyPublicKeyLength, !file.blob.isEmpty,
          machineKeyHeaderLength + file.blob.count <= machineKeyMaxSize else {
        return nil
    }
    var out = machineKeyMagic
    out.append(machineKeyFormatVersion)
    out.append(file.publicKey)
    out.append(UInt8(file.blob.count >> 8))
    out.append(UInt8(file.blob.count & 0xFF))
    out.append(file.blob)
    return out
}

func decodeMachineKeyFile(_ data: Data) -> MachineKeyFile? {
    var bytes = [UInt8](data)
    defer { secureZero(&bytes) }
    guard bytes.count > machineKeyHeaderLength, bytes.count <= machineKeyMaxSize,
          Data(bytes[0..<4]) == machineKeyMagic, bytes[4] == machineKeyFormatVersion else {
        return nil
    }
    let publicKey = Data(bytes[5..<(5 + machineKeyPublicKeyLength)])
    let length = Int(bytes[70]) << 8 | Int(bytes[71])
    guard length > 0, bytes.count == machineKeyHeaderLength + length,
          (try? P256.KeyAgreement.PublicKey(x963Representation: publicKey)) != nil else {
        return nil
    }
    return MachineKeyFile(publicKey: publicKey, blob: Data(bytes[machineKeyHeaderLength...]))
}

enum MachineKeyRead {
    case found(MachineKeyFile)
    case notFound
    case accessDenied(String)
    case untrusted(String)
}

private func machineKeyFolder() -> String {
    MachineScopeTestOverrides.keyFolder ?? machineKeyFolderPath
}

/// Reads a machine KEK file. It must be root's, writable by root alone,
/// with no access at all for others (its runner group may read it), in
/// folders only root controls; the reasons are for the log only.
func readMachineKeyFile(service: String) -> MachineKeyRead {
    let folder = machineKeyFolder()
    let folderFd = open(folder, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    guard folderFd >= 0 else {
        let code = errno
        if code == ENOENT {
            return .notFound
        }
        if code == EACCES {
            return .accessDenied("\(folder) can't be opened by this account")
        }
        return .untrusted("\(folder) can't be opened (\(String(cString: strerror(code))))")
    }
    defer { close(folderFd) }
    guard keyFileFoldersAreTrusted(folderFd: folderFd, rootOnly: true) else {
        return .untrusted("\(folder), or a folder above it, is not root's or can be written by others")
    }
    let fd = openat(folderFd, "\(service).kek", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
    guard fd >= 0 else {
        let code = errno
        if code == ENOENT {
            return .notFound
        }
        if code == EACCES {
            return .accessDenied("this account may not read the machine KEK for \(service): it is neither root nor in the service's runner group")
        }
        return .untrusted("the machine KEK file for \(service) can't be opened (\(String(cString: strerror(code))))")
    }
    defer { close(fd) }
    var info = stat()
    guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_uid == 0,
          info.st_mode & (S_IWGRP | S_IROTH | S_IWOTH | S_IXOTH) == 0,
          !onVolumeIgnoringOwnership(fd),
          !aclGrantsOthersAChange(fd: fd, isFolder: false, rootOnly: true) else {
        return .untrusted("the machine KEK file for \(service) is not a root-owned file that only root can change and only its runner group can read")
    }
    guard info.st_size <= off_t(machineKeyMaxSize), var bytes = readAll(fd: fd, limit: machineKeyMaxSize) else {
        return .untrusted("the machine KEK file for \(service) is too large, or can't be read")
    }
    defer { secureZero(&bytes) }
    guard let file = decodeMachineKeyFile(bytes) else {
        return .untrusted("the machine KEK file for \(service) is not one this library wrote")
    }
    return .found(file)
}

/// Machine KEKs stay usable after the first unlock following a boot --
/// logged out, at the login window, after an unattended restart -- unlike
/// the user-scoped KEKs' WhenUnlocked, which fails as soon as the last user
/// logs out.
private func makeMachineAccessControl() -> SecAccessControl? {
    var error: Unmanaged<CFError>?
    return SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        [.privateKeyUsage],
        &error
    )
}

/// Whether `key` can do a key agreement now, and gets the answer its
/// public key predicts.
private func keyAgreementWorks(_ key: SecureEnclave.P256.KeyAgreement.PrivateKey) -> Bool {
    let peer = P256.KeyAgreement.PrivateKey()
    guard let ours = try? key.sharedSecretFromKeyAgreement(with: peer.publicKey),
          let theirs = try? peer.sharedSecretFromKeyAgreement(with: key.publicKey) else {
        return false
    }
    return ours == theirs
}

private func logMachineRefusal(_ service: String, _ reason: String) {
    machineLog.error("\(service, privacy: .public): \(reason, privacy: .public)")
}

/// Whether the machine KEK file for `service` exists. File-level only --
/// no Secure Enclave use -- so root can ask from Terminal (`status`).
func machineKekExists(service: String) -> (status: Int32, exists: Bool) {
    switch readMachineKeyFile(service: service) {
    case .found(var file):
        secureZero(&file.blob)
        return (HKDFGuardStatus.success.rawValue, true)
    case .notFound:
        return (HKDFGuardStatus.success.rawValue, false)
    case .accessDenied(let reason):
        logMachineRefusal(service, reason)
        return (HKDFGuardStatus.keychainAccessDenied.rawValue, false)
    case .untrusted(let reason):
        logMachineRefusal(service, reason)
        return (HKDFGuardStatus.kekCorrupted.rawValue, false)
    }
}

/// The machine KEK's public key, from its file -- no Secure Enclave use,
/// so it can be read from anywhere the file can (the fingerprint).
func machinePublicKey(service: String) -> (status: Int32, key: P256.KeyAgreement.PublicKey?) {
    switch readMachineKeyFile(service: service) {
    case .found(var file):
        defer { secureZero(&file.blob) }
        guard let key = try? P256.KeyAgreement.PublicKey(x963Representation: file.publicKey) else {
            return (HKDFGuardStatus.kekCorrupted.rawValue, nil)
        }
        return (HKDFGuardStatus.success.rawValue, key)
    case .notFound:
        return (HKDFGuardStatus.kekNotFound.rawValue, nil)
    case .accessDenied(let reason):
        logMachineRefusal(service, reason)
        return (HKDFGuardStatus.keychainAccessDenied.rawValue, nil)
    case .untrusted(let reason):
        logMachineRefusal(service, reason)
        return (HKDFGuardStatus.kekCorrupted.rawValue, nil)
    }
}

/// Loads the machine KEK for wrap and unwrap: only in the system context,
/// and only if it is the key its file says.
func getMachineKEK(service: String) -> (status: Int32, key: SecureEnclave.P256.KeyAgreement.PrivateKey?) {
    guard runningInSystemContext() else {
        logMachineRefusal(service, "machine KEKs can only be used by a LaunchDaemon -- not from Terminal, sudo, SSH or a login session")
        return (HKDFGuardStatus.keychainAccessDenied.rawValue, nil)
    }
    switch readMachineKeyFile(service: service) {
    case .notFound:
        return (HKDFGuardStatus.kekNotFound.rawValue, nil)
    case .accessDenied(let reason):
        logMachineRefusal(service, reason)
        return (HKDFGuardStatus.keychainAccessDenied.rawValue, nil)
    case .untrusted(let reason):
        logMachineRefusal(service, reason)
        return (HKDFGuardStatus.kekCorrupted.rawValue, nil)
    case .found(var file):
        defer { secureZero(&file.blob) }
        switch reconstructKEK(file.blob, enclaveIsUsable: { enclaveProbeSucceeds(makeMachineAccessControl()) }) {
        case .key(let key):
            guard key.publicKey.x963Representation == file.publicKey else {
                logMachineRefusal(service, "the machine KEK file's key does not match the public key it records")
                return (HKDFGuardStatus.kekCorrupted.rawValue, nil)
            }
            return (HKDFGuardStatus.success.rawValue, key)
        case .corrupt:
            return (HKDFGuardStatus.kekCorrupted.rawValue, nil)
        case .enclaveRefused:
            return (HKDFGuardStatus.keychainAccessDenied.rawValue, nil)
        }
    }
}

/// Groups too broad to read a machine KEK: each covers essentially every
/// account, every administrator, or everyone allowed to log in remotely.
private let overBroadRunnerGroups: Set<String> = [
    "staff", "everyone", "localaccounts", "netaccounts", "authedusers",
    "interactusers", "consoleusers", "admin", "com.apple.access_ssh",
]

/// Opens the machine KEK folder, creating it (root:wheel 0755) if it is
/// missing. Its parent must already exist -- the package installs it.
private func openMachineKeyFolderCreatingIt(service: String) -> Int32? {
    let url = URL(fileURLWithPath: machineKeyFolder())
    let parentFd = open(url.deletingLastPathComponent().path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    guard parentFd >= 0 else {
        logMachineRefusal(service, "\(url.deletingLastPathComponent().path) is missing: install the hkdfguard package")
        return nil
    }
    defer { close(parentFd) }
    let leaf = url.lastPathComponent
    let created = mkdirat(parentFd, leaf, 0o755) == 0
    guard created || errno == EEXIST else {
        logMachineRefusal(service, "\(url.path) can't be created (\(String(cString: strerror(errno))))")
        return nil
    }
    let fd = openat(parentFd, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard fd >= 0 else {
        return nil
    }
    if created && (fchown(fd, 0, 0) != 0 || fchmod(fd, 0o755) != 0) {
        close(fd)
        return nil
    }
    guard keyFileFoldersAreTrusted(folderFd: fd, rootOnly: true) else {
        logMachineRefusal(service, "\(url.path), or a folder above it, is not root's or can be written by others")
        close(fd)
        return nil
    }
    // On every provision, not just the first, so a folder made by an older
    // build is excluded too. Not fatal: the KEK is no less usable for it.
    if !excludeFromBackup(url.path) {
        logMachineRefusal(service, "\(url.path) could not be excluded from Time Machine; a backup of it would let a retired KEK be restored")
    }
    return fd
}

/// Excludes the folder at `path` from Time Machine, so a retired machine
/// KEK can't come back from a backup. A sticky exclusion: it stays with the
/// folder if it moves. Backup tools that ignore it, and local APFS
/// snapshots, still keep copies; deleting the KEK file can't reach those.
func excludeFromBackup(_ path: String) -> Bool {
    var url = URL(fileURLWithPath: path, isDirectory: true)
    var values = URLResourceValues()
    values.isExcludedFromBackup = true
    return (try? url.setResourceValues(values)) != nil
}

private enum MachineKeyWrite {
    case written
    case alreadyExists // another provisioner won the race
    case failed
}

/// Writes the KEK file under a temporary name, owned root:`gid`, mode 0640
/// (0600 for root only), synced, then renames it into place -- only if no
/// file has that name yet, so an existing KEK is never replaced.
private func writeMachineKeyFile(_ bytes: Data, service: String, folderFd: Int32, gid: gid_t) -> MachineKeyWrite {
    let finalName = "\(service).kek"
    let tempName = ".\(service).\(UInt64.random(in: .min ... .max)).tmp"
    let fd = openat(folderFd, tempName, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
    guard fd >= 0 else {
        logMachineRefusal(service, "the machine KEK file can't be created (\(String(cString: strerror(errno))))")
        return .failed
    }
    var written = bytes.withUnsafeBytes { raw -> Bool in
        var offset = 0
        while offset < raw.count {
            let count = write(fd, raw.baseAddress?.advanced(by: offset), raw.count - offset)
            if count < 0 {
                if errno == EINTR {
                    continue
                }
                return false
            }
            offset += count
        }
        return true
    }
    let mode: mode_t = gid == 0 ? 0o600 : 0o640
    written = written && fchown(fd, 0, gid) == 0 && fchmod(fd, mode) == 0 && fsync(fd) == 0
    close(fd)
    guard written else {
        unlinkat(folderFd, tempName, 0)
        logMachineRefusal(service, "the machine KEK file can't be written")
        return .failed
    }
    if renameatx_np(folderFd, tempName, folderFd, finalName, UInt32(RENAME_EXCL)) != 0 {
        let code = errno
        unlinkat(folderFd, tempName, 0)
        return code == EEXIST ? .alreadyExists : .failed
    }
    _ = fsync(folderFd)
    return .written
}

/// Verifies an existing machine KEK, never replacing one: usable, and the
/// key its file records.
private func verifyExistingMachineKEK(service: String) -> Int32 {
    switch readMachineKeyFile(service: service) {
    case .found(var file):
        defer { secureZero(&file.blob) }
        guard let key = try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: file.blob),
              key.publicKey.x963Representation == file.publicKey,
              keyAgreementWorks(key) else {
            logMachineRefusal(service, "the existing machine KEK can't be used, or is not the key its file records; it was left untouched")
            return HKDFGuardStatus.kekCorrupted.rawValue
        }
        return HKDFGuardStatus.success.rawValue
    case .notFound:
        return HKDFGuardStatus.kekNotFound.rawValue
    case .accessDenied(let reason):
        logMachineRefusal(service, reason)
        return HKDFGuardStatus.keychainAccessDenied.rawValue
    case .untrusted(let reason):
        logMachineRefusal(service, reason)
        return HKDFGuardStatus.kekCorrupted.rawValue
    }
}

/// Creates the machine KEK for `service` if it has none: root only, in
/// the system context only (the CLI's `provision` runs this as a one-off
/// LaunchDaemon job). Idempotent; an existing KEK is verified, never
/// replaced.
func createMachineKEK(service: String, settings: MachineServiceSettings) -> Int32 {
    guard geteuid() == 0 else {
        logMachineRefusal(service, "only root can create a machine KEK")
        return HKDFGuardStatus.keychainAccessDenied.rawValue
    }
    guard runningInSystemContext() else {
        logMachineRefusal(service, "a machine KEK must be created by a LaunchDaemon (`sudo hkdfguard provision` does this for you); one created from Terminal would be unusable by the daemons it is for")
        return HKDFGuardStatus.keychainAccessDenied.rawValue
    }
    var gid: gid_t = 0
    if let name = settings.runnerGroup {
        guard !overBroadRunnerGroups.contains(name.lowercased()) else {
            logMachineRefusal(service, "RunnerGroup \(name) is too broad: name a group that holds only this service's accounts")
            return HKDFGuardStatus.policyInvalid.rawValue
        }
        guard let group = getgrnam(name) else {
            logMachineRefusal(service, "RunnerGroup \(name) does not name a group on this Mac")
            return HKDFGuardStatus.policyInvalid.rawValue
        }
        gid = group.pointee.gr_gid
    }

    let existing = verifyExistingMachineKEK(service: service)
    guard existing == HKDFGuardStatus.kekNotFound.rawValue else {
        return existing
    }

    guard let folderFd = openMachineKeyFolderCreatingIt(service: service) else {
        return HKDFGuardStatus.keychainWriteFailed.rawValue
    }
    defer { close(folderFd) }
    guard let access = makeMachineAccessControl() else {
        return HKDFGuardStatus.accessControlCreationFailed.rawValue
    }
    guard let key = try? SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access) else {
        return HKDFGuardStatus.keyGenerationFailed.rawValue
    }
    var blob = key.dataRepresentation
    defer { secureZero(&blob) }
    guard keyAgreementWorks(key),
          let reloaded = try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob),
          keyAgreementWorks(reloaded) else {
        return HKDFGuardStatus.kekVerificationFailed.rawValue
    }
    guard var encoded = encodeMachineKeyFile(MachineKeyFile(publicKey: key.publicKey.x963Representation, blob: blob)) else {
        return HKDFGuardStatus.unexpectedOutputLength.rawValue
    }
    defer { secureZero(&encoded) }
    switch writeMachineKeyFile(encoded, service: service, folderFd: folderFd, gid: gid) {
    case .written:
        auditMachineKekCreated(service: service, runnerGroup: settings.runnerGroup)
        return HKDFGuardStatus.success.rawValue
    case .alreadyExists:
        return verifyExistingMachineKEK(service: service)
    case .failed:
        return HKDFGuardStatus.keychainWriteFailed.rawValue
    }
}

/// The policy in effect, as JSON, for `hkdfguard_machine_policy`.
func machinePolicyJSON() -> Data? {
    var object: [String: Any] = [
        "machineKeyFolder": machineKeyFolder(),
        "systemContext": runningInSystemContext(),
    ]
    switch currentMachinePolicy() {
    case .none:
        object["mode"] = "development"
    case .invalid(let reason):
        object["mode"] = "invalid"
        object["reason"] = reason
    case .loaded(let policy):
        object["mode"] = "production"
        object["source"] = policy.source
        if let group = policy.securityAdminGroup {
            object["securityAdminGroup"] = group
        }
        if let group = policy.deploymentAdminGroup {
            object["deploymentAdminGroup"] = group
        }
        var services: [String: [String: String]] = [:]
        for (service, settings) in policy.machineServices {
            services[service] = settings.runnerGroup.map { ["runnerGroup": $0] } ?? [:]
        }
        object["machineServices"] = services
    }
    return try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
}

// MARK: - Wrap (seal) a DEK under the Secure Enclave KEK
//
// Wrapped format: [KEK fingerprint, 32-byte SHA-256 of the KEK's public key]
//                  [suite id, 1 byte: 0x01]
//                  [salt, 32 random bytes]
//                  [nonce, 12 random bytes]
//                  [AES-256-GCM ciphertext || 16-byte tag, 48 bytes]
//
// The Linux and Windows construction: the Secure Enclave computes
// Z = ECDH(KEK_priv, H(salt)), where H hashes the salt to a P-256 point
// (`payloadECDHPoint`); HKDF-SHA512 turns Z into the AES-256 key
// (`deriveWrappingKey`); AES-256-GCM seals the DEK. Wrapping needs the
// KEK's private key as much as unwrapping does, so only this host -- not
// anyone who has seen the public key -- can create a payload.
//
// The header (fingerprint || suite id || salt || nonce: every byte before
// the ciphertext) is bound twice, as on Linux: into the key, through HKDF's
// `info` with the service name, and into the tag, as the AEAD's additional
// authenticated data. Neither the fingerprint nor the suite byte can be
// rewritten, and a payload sealed for one service cannot be opened under
// another even when (by misuse) both resolve to the same KEK.
//
// The fingerprint identifies *which* KEK this payload was wrapped under —
// checked against the current KEK's own public key by hkdfguard_unwrap_dek
// before any key agreement is attempted (see `kekFingerprint`).

/// `@_cdecl` entry points below.
private func wrapDekCore(
    service: String,
    dekPtr: UnsafePointer<UInt8>,
    dekLen: Int32,
    outPtr: UnsafeMutablePointer<UInt8>,
    outLen: UnsafeMutablePointer<Int32>
) -> Int32 {
    let (getStatus, maybeEnclaveKey) = getKEK(service: service)
    guard let enclaveKey = maybeEnclaveKey else {
        return getStatus
    }

    guard let salt = randomBytes(hkdfguardSaltLength),
          let nonceBytes = randomBytes(hkdfguardNonceLength),
          let nonce = try? AES.GCM.Nonce(data: nonceBytes) else {
        return HKDFGuardStatus.encryptionFailed.rawValue // the RNG failed
    }

    var header = kekFingerprint(enclaveKey.publicKey)
    header.append(hkdfguardSuiteId)
    header.append(salt)
    header.append(nonceBytes)
    guard header.count == hkdfguardHeaderLength else {
        return HKDFGuardStatus.unexpectedOutputLength.rawValue
    }

    let sealed: AES.GCM.SealedBox
    do {
        guard let key = try deriveWrappingKey(enclaveKey: enclaveKey, service: service, header: header) else {
            return HKDFGuardStatus.encryptionFailed.rawValue // no point for this salt (probability 2^-255)
        }
        // Sealed straight from the caller's buffer: no copy of the DEK is made.
        sealed = try AES.GCM.seal(
            UnsafeRawBufferPointer(start: dekPtr, count: Int(dekLen)),
            using: key,
            nonce: nonce,
            authenticating: header
        )
    } catch {
        return HKDFGuardStatus.encryptionFailed.rawValue // the enclave refused the key agreement, or sealing failed
    }

    guard sealed.ciphertext.count == hkdfguardDekLength,
          sealed.tag.count == hkdfguardGCMTagLength else {
        return HKDFGuardStatus.unexpectedOutputLength.rawValue
    }

    var payload = header
    payload.append(sealed.ciphertext)
    payload.append(sealed.tag)
    guard payload.count == hkdfguardWrappedLength else {
        return HKDFGuardStatus.unexpectedOutputLength.rawValue
    }

    guard copyOut(payload, to: outPtr, count: hkdfguardWrappedLength) else {
        return HKDFGuardStatus.unexpectedOutputLength.rawValue
    }
    outLen.pointee = Int32(hkdfguardWrappedLength)

    return HKDFGuardStatus.success.rawValue
}

// MARK: - Audit trail

// One system-log record per security-relevant event, written whatever the
// host does about logging -- the macOS counterpart of the Linux build's
// syslog records (src/audit.rs) and the Windows build's Event Log events:
// the same event IDs, meanings, fields and sentences, so one set of alerts
// reads all three.
//
// - Where. The unified log, subsystem `com.hkdfguard`, category `audit`:
//   `log show --predicate 'subsystem == "com.hkdfguard" AND category ==
//   "audit"'`, or Console. Every field is logged public (service names,
//   paths, fingerprints and payload hashes are not secrets), so nothing is
//   redacted as `<private>`.
// - Severity. The unified log has no "warning" level: info events are
//   `default` (notice), the level the log keeps on disk by default; warnings
//   are `error`; errors are `fault`.
// - What. `key=value` fields, then a sentence: the event, the C function,
//   the normalized service name, the result, and who called -- `uid`,
//   `euid`, `pid` and `exe`. Wrap and unwrap records also carry the KEK's
//   fingerprint and a SHA-256 of the wrapped payload, both public; the same
//   payload has the same hash in its wrap record and in every unwrap record.
// - Never. DEKs, KEKs, shared secrets, derived keys or plaintext. Caller
//   mistakes (INVALID_ARGUMENT, BUFFER_TOO_SMALL, INVALID_SERVICE_NAME) and
//   KEK_NOT_FOUND aren't audited either, as on Linux and Windows.
// - Differences from Linux. 1001 (KEK created off the policy's first choice)
//   and 2004 (POLICY_INVALID) never occur: there is one provider, the Secure
//   Enclave, and no policy file. For the same reason the unwrap-success
//   record (1003) is always written -- Linux's `[audit] unwrap_success`
//   switch has nowhere to live here. The macOS-only refinements of
//   PROVIDER_ERROR (-96..-100) are audited as 2005, like PROVIDER_ERROR.
//
// Any process can write to the unified log, so these records are an audit
// aid, not tamper-proof evidence -- as with syslog and the Event Log.

/// The C function an audit event belongs to.
enum AuditOp: String {
    case createKek = "hkdfguard_create_kek"
    case kekExists = "hkdfguard_kek_exists"
    case kekFingerprint = "hkdfguard_kek_fingerprint"
    case wrap = "hkdfguard_wrap_dek"
    case generateAndWrap = "hkdfguard_generate_and_wrap_dek"
    case unwrap = "hkdfguard_unwrap_dek"
    case openFile = "hkdfguard_open_file"
}

/// Event IDs: the Windows build's, number for number, as on Linux.
enum AuditEvent: Int {
    case kekCreated = 1000
    case kekCreatedFallback = 1001 // never on macOS: one provider
    case dekWrapped = 1002
    case dekUnwrapped = 1003
    case accessDenied = 2000
    case kekInvalid = 2002
    case integrityFailure = 2003
    case policyInvalid = 2004
    case operationFailed = 2005
    case plaintextKeyFile = 2006
    case setupCallsExceeded = 2007
}

enum AuditSeverity {
    case info, warning, error

    var logType: OSLogType {
        switch self {
        case .info: return .default
        case .warning: return .error
        case .error: return .fault
        }
    }
}

private let auditLog = Logger(subsystem: "com.hkdfguard", category: "audit")

/// When non-nil, every record is also appended here, prefixed with its
/// severity (`[info] `, `[warning] `, `[error] `) -- for the tests, which
/// filter by their own service names or paths (they run in parallel). Nil,
/// and so free, in normal use.
let auditCapture = OSAllocatedUnfairLock<[String]?>(initialState: nil)

/// The provider, as Linux's `provider=` field names its own.
private let auditProvider = "SECURE_ENCLAVE"

private let auditExecutable: String = {
    var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
    let length = proc_pidpath(getpid(), &buffer, UInt32(buffer.count))
    guard length > 0 else { return auditQuote(Array("(unknown)".utf8)) }
    return auditQuote(buffer[0..<min(Int(length), buffer.count)].map { UInt8(bitPattern: $0) })
}()

/// A double-quoted field value, exactly as Linux quotes one: printable ASCII
/// other than `"` and `\` is kept; everything else -- quotes, backslashes,
/// control characters (so no value can forge a second record) and any
/// non-ASCII byte -- is written as \xNN.
func auditQuote(_ bytes: [UInt8]) -> String {
    var out = "\""
    for byte in bytes {
        if (0x20..<0x7F).contains(byte) && byte != 0x22 && byte != 0x5C {
            out.unicodeScalars.append(Unicode.Scalar(byte))
        } else {
            out += String(format: "\\x%02x", byte)
        }
    }
    return out + "\""
}

private func auditHex<Bytes: Sequence>(_ bytes: Bytes) -> String where Bytes.Element == UInt8 {
    bytes.map { String(format: "%02x", $0) }.joined()
}

private func auditKeychainName(_ mode: KeychainMode) -> String {
    switch mode {
    case .legacy: return "legacy"
    case .dataProtection: return "data-protection"
    }
}

/// One record: the event's own fields, who called, then the sentence.
func auditEmit(_ severity: AuditSeverity, _ event: AuditEvent, fields: String, message: String) {
    let line = "event=\(event.rawValue) \(fields) uid=\(getuid()) euid=\(geteuid()) pid=\(getpid()) exe=\(auditExecutable) msg=\(auditQuote(Array(message.utf8)))"
    auditLog.log(level: severity.logType, "\(line, privacy: .public)")
    auditCapture.withLock { $0?.append("[\(severity)] " + line) }
}

/// A KEK was created (not merely found).
func auditKekCreated(service: String, mode: KeychainMode) {
    auditEmit(
        .info, .kekCreated,
        fields: "op=\(AuditOp.createKek.rawValue) service=\(auditQuote(Array(service.utf8))) provider=\(auditProvider) keychain=\(auditKeychainName(mode))",
        message: "KEK created on \(auditProvider)"
    )
}

/// A machine-scoped KEK was created (not merely found).
func auditMachineKekCreated(service: String, runnerGroup: String?) {
    auditEmit(
        .info, .kekCreated,
        fields: "op=\(AuditOp.createKek.rawValue) service=\(auditQuote(Array(service.utf8))) provider=\(auditProvider) keychain=machine runner_group=\(auditQuote(Array((runnerGroup ?? "(root only)").utf8)))",
        message: "machine KEK created on \(auditProvider)"
    )
}

/// A DEK was wrapped (`op` is wrap or generateAndWrap) or unwrapped
/// (`unwrap`). `payload` is the 125-byte payload produced or consumed:
/// public bytes, the first 32 of which are the KEK fingerprint.
func auditDekOperation(_ op: AuditOp, service: String, payload: UnsafeBufferPointer<UInt8>) {
    let unwrap = op == .unwrap
    let fingerprint = payload.count >= hkdfguardFingerprintLength
        ? auditHex(payload[0..<hkdfguardFingerprintLength]) : "(unavailable)"
    auditEmit(
        .info, unwrap ? .dekUnwrapped : .dekWrapped,
        fields: "op=\(op.rawValue) result=OK service=\(auditQuote(Array(service.utf8))) provider=\(auditProvider) kek_fingerprint=\(fingerprint) payload_sha256=\(auditHex(SHA256.hash(data: Data(payload))))",
        message: unwrap ? "DEK unwrapped" : "DEK wrapped"
    )
}

/// `op` failed with `code`, for `service`. Only the failures worth an
/// administrator's attention are written -- Linux's and Windows' list.
func auditOperationFailed(_ op: AuditOp, service: String, code: Int32) {
    guard let status = HKDFGuardStatus(rawValue: code) else { return }
    let event: AuditEvent
    let severity: AuditSeverity
    let meaning: String
    switch status {
    case .keychainAccessDenied:
        (event, severity, meaning) = (.accessDenied, .warning, "the caller is not authorized to use this KEK")
    case .policyInvalid:
        (event, severity, meaning) = (.policyInvalid, .error, "the policy can't be trusted or used; every call fails closed until it is fixed")
    case .kekCorrupted:
        (event, severity, meaning) = (.kekInvalid, .error, "a KEK exists under this service name but is corrupt or not one this library would create; it was left untouched")
    case .decryptionFailed, .fingerprintMismatch, .payloadMalformed, .unsupportedCiphersuite:
        guard op == .unwrap else { return }
        switch status {
        case .decryptionFailed: meaning = "the payload failed authentication: tampered with, or presented for the wrong service"
        case .fingerprintMismatch: meaning = "the payload was not wrapped under this service's current KEK"
        case .unsupportedCiphersuite: meaning = "the payload's format version is not one this build understands (corrupted, tampered with, or from a newer version)"
        default: meaning = "the payload is not a valid wrapped DEK (truncated, corrupted, or tampered with)"
        }
        (event, severity) = (.integrityFailure, .warning)
    case .enclaveUnavailable, .encryptionFailed, .unexpectedOutputLength,
         .accessControlCreationFailed, .keyGenerationFailed, .keychainWriteFailed, .kekVerificationFailed, .keychainReadFailed:
        (event, severity, meaning) = (.operationFailed, .error, "the key provider or a cryptographic operation failed")
    default:
        return // caller mistakes, "not provisioned yet", and everything else
    }
    auditEmit(
        severity, event,
        fields: "op=\(op.rawValue) result=\(status.auditName)(\(code)) service=\(auditQuote(Array(service.utf8)))",
        message: "\(op.rawValue) failed: \(meaning)"
    )
}

/// hkdfguard_open_file refused `path` as FILE_PLAINTEXT_KEY: it looks like
/// an unwrapped DEK. Names the file; none of its contents are logged.
func auditPlaintextKeyFile(path: [UInt8]) {
    auditEmit(
        .error, .plaintextKeyFile,
        fields: "op=\(AuditOp.openFile.rawValue) result=\(HKDFGuardStatus.fileUnprotectedKey.auditName)(\(HKDFGuardStatus.fileUnprotectedKey.rawValue)) path=\(auditQuote(path))",
        message: "the file looks like an unwrapped DEK (32 raw bytes, or its base64 or hex), so it may be a plaintext key written to disk by mistake; none of its contents were returned. Treat that key as exposed: find out how the file was written, remove it, and re-mint the DEK"
    )
}

/// More than this many setup calls in one process is the signature of a
/// caller looping on them -- Linux's threshold.
let auditSetupCallsWarnAt = 10

/// Counts setup calls (hkdfguard_create_kek / hkdfguard_kek_exists) and
/// reports, once per counter, when they pass `auditSetupCallsWarnAt`.
struct SetupCallCounter {
    private(set) var calls = 0
    private(set) var warned = false

    /// Records one call; true exactly once, on the call that passes the
    /// threshold.
    mutating func record() -> Bool {
        calls += 1
        guard !warned, calls > auditSetupCallsWarnAt else { return false }
        warned = true
        return true
    }
}

private let setupCalls = OSAllocatedUnfairLock(initialState: SetupCallCounter())

/// Called on every setup call that names a valid service, inside the
/// setup gate (see `gatedSetup`).
func auditNoteSetupCall(floor: Duration) {
    if setupCalls.withLock({ $0.record() }) {
        auditSetupCallsExceeded(floorMs: floor.wholeMilliseconds)
    }
}

func auditSetupCallsExceeded(floorMs: Int64) {
    let calls = auditSetupCallsWarnAt
    auditEmit(
        .warning, .setupCallsExceeded,
        fields: "calls=\(calls) setup_min_delay_ms=\(floorMs)",
        message: "more than \(calls) hkdfguard_create_kek / hkdfguard_kek_exists / hkdfguard_kek_fingerprint calls in this process; these are meant to run once per application startup, and each costs a Secure Enclave round trip plus at least \(floorMs) ms -- call them once at startup, then use hkdfguard_wrap_dek / hkdfguard_unwrap_dek"
    )
}

// MARK: - Setup gate

/// The least wall-clock time each setup call (`hkdfguard_create_kek`,
/// `hkdfguard_kek_exists`, `hkdfguard_kek_fingerprint`) takes, whatever its outcome -- the Linux and
/// Windows default. Fixed on macOS: there is no policy file or
/// administrator setting to tune it (Linux reads
/// `startup_behavior.setup_min_delay_ms`, Windows
/// `HKLM\Software\Policies\HkdfGuard\SetupMinDelayMs`).
///
/// Setup calls are meant to run once per application startup. Holding
/// each to a floor, serialized across threads, caps how fast a caller --
/// a bug looping on them, or code probing which services have a KEK --
/// can drive the Secure Enclave and keychain through them: at most one
/// per second per process. And "exists" and "doesn't exist" take the same
/// time.
let setupMinDelay: Duration = .milliseconds(1_000)

/// Test-only override of `setupMinDelay`: `nil` (the default, and always
/// in production) uses `setupMinDelay`. The test suites that make setup
/// calls set it to zero so their many calls don't each cost a second;
/// the tests of the floor itself set it explicitly. Internal, so only
/// `@testable import` can reach it -- never part of the C ABI.
let setupMinDelayOverrideForTests = OSAllocatedUnfairLock<Duration?>(initialState: nil)

func effectiveSetupMinDelay() -> Duration {
    setupMinDelayOverrideForTests.withLock { $0 } ?? setupMinDelay
}

/// Serializes every setup call, so that together with the floor their
/// aggregate rate is capped regardless of how many threads call in. A
/// blocking lock rather than an unfair lock: it is held across a keychain
/// round trip and a sleep.
private let setupGate = NSLock()

/// Runs `body` (the keychain-touching part of a setup call) under the
/// setup gate: serialized against every other setup call, and not
/// returning until at least `effectiveSetupMinDelay()` has passed since
/// entry -- whatever `body` returned, and however quickly. Argument
/// validation happens before callers reach this, so a NULL pointer or an
/// invalid service name still fails immediately; only calls that would
/// reach the keychain pay the floor. The counterpart of Linux's
/// `gated_setup` and Windows' `GatedSetup`.
/// `floor` is a parameter only so the tests of the gate itself can pass
/// their own without racing other suites over the override.
func gatedSetup<T>(floor: Duration? = nil, _ body: () -> T) -> T {
    setupGate.lock()
    defer { setupGate.unlock() }
    let clock = ContinuousClock()
    let entered = clock.now
    let floor = floor ?? effectiveSetupMinDelay()
    // Waited out on every exit path, after `body`'s result is in hand.
    defer {
        let remaining = floor - (clock.now - entered)
        if remaining > .zero {
            Thread.sleep(forTimeInterval: remaining.secondsAsDouble)
        }
    }

    let result = body()
    auditNoteSetupCall(floor: floor)
    return result
}

extension Duration {
    /// Whole milliseconds, truncated.
    var wholeMilliseconds: Int64 {
        let (s, attos) = components
        return s * 1_000 + attos / 1_000_000_000_000_000
    }

    var secondsAsDouble: Double {
        let (s, attos) = components
        return Double(s) + Double(attos) / 1e18
    }
}

/// The normalized service name a C caller passed, or nil when it isn't a
/// valid one (then there is nothing worth auditing: INVALID_SERVICE_NAME is
/// a caller mistake).
private func auditService(_ servicePtr: UnsafePointer<CChar>?) -> String? {
    servicePtr.flatMap { normalizedService(from: $0) }
}

/// Audits a finished wrap, generate-and-wrap or unwrap: the success record
/// with the payload's fingerprint and hash, or the failure record when the
/// failure is one worth auditing.
private func auditDekCall(_ op: AuditOp, _ servicePtr: UnsafePointer<CChar>?, status: Int32, payload: UnsafeBufferPointer<UInt8>?) {
    guard let service = auditService(servicePtr) else { return }
    if status == HKDFGuardStatus.success.rawValue {
        if let payload { auditDekOperation(op, service: service, payload: payload) }
    } else {
        auditOperationFailed(op, service: service, code: status)
    }
}

// MARK: - Process hardening (opt-in)

/// HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE: make a weak code signature
/// a failure instead of a logged warning. Same bit on every platform.
private let hkdfguardHardenRequireProtectedSignature: UInt32 = 0x1

/// Every hardening flag this build knows; any other bit is refused.
private let hkdfguardHardenAllFlags: UInt32 = hkdfguardHardenRequireProtectedSignature

private let hardeningLog = Logger(subsystem: "com.hkdfguard", category: "hardening")

/// Entitlements that let another process of the same user debug this one
/// (get-task-allow, which Xcode adds to Debug builds) or load code into it.
private let debuggableEntitlements = [
    "com.apple.security.get-task-allow",
    "com.apple.security.cs.allow-dyld-environment-variables",
    "com.apple.security.cs.disable-library-validation",
]

/// Why the host executable's code signature still lets same-user processes
/// debug or inject into this process -- empty when it doesn't. On macOS that
/// protection comes from the signature (Hardened Runtime, none of
/// `debuggableEntitlements`), which a library can read but not change.
/// Internal, not private, so tests can check it against a known signature.
func codeSignatureWeaknesses() -> [String] {
    var code: SecCode?
    var staticCode: SecStaticCode?
    var info: CFDictionary?
    guard SecCodeCopySelf(SecCSFlags(), &code) == errSecSuccess, let code,
          SecCodeCopyStaticCode(code, SecCSFlags(), &staticCode) == errSecSuccess, let staticCode,
          SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
          let signing = info as? [String: Any]
    else {
        return ["its code signature could not be read"]
    }

    var weaknesses: [String] = []
    let flags = (signing[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
    if flags & SecCodeSignatureFlags.runtime.rawValue == 0 {
        weaknesses.append("it is not signed with the Hardened Runtime (codesign --options runtime)")
    }
    let entitlements = signing[kSecCodeInfoEntitlementsDict as String] as? [String: Any] ?? [:]
    for key in debuggableEntitlements where (entitlements[key] as? Bool) == true {
        weaknesses.append("it has the \(key) entitlement")
    }
    return weaknesses
}

/// `ptrace(2)` isn't imported into Swift's Darwin module, so it is bound to
/// the libc symbol directly, with <sys/ptrace.h>'s signature and request.
@_silgen_name("ptrace")
private func sys_ptrace(_ request: Int32, _ pid: pid_t, _ addr: UnsafeMutablePointer<CChar>?, _ data: Int32) -> Int32
private let PT_DENY_ATTACH: Int32 = 31

/// Whether a debugger is attached right now (`P_TRACED`), or nil if that
/// can't be determined. `PT_DENY_ATTACH` on a traced process terminates it
/// instead of returning, so it is only ever called after this says "no".
private func isBeingTraced() -> Bool? {
    var info = kinfo_proc()
    var size = MemoryLayout<kinfo_proc>.stride
    var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
    guard sysctl(&mib, u_int(mib.count), &info, &size, nil, 0) == 0 else {
        return nil
    }
    return info.kp_proc.p_flag & P_TRACED != 0
}

/// Same as `hkdfguard_harden_process_with_flags(0)`: core dumps off, debugger
/// attachment denied, and a weak code signature logged but not fatal.
@_cdecl("hkdfguard_harden_process")
public func hkdfguard_harden_process() -> Int32 {
    hkdfguard_harden_process_with_flags(flags: 0)
}

/// Opt-in hardening of the calling process against memory disclosure, in
/// the same steps as on Linux where macOS has them:
///
/// 1. `RLIMIT_CORE` = 0, soft and hard, so it can't be raised again.
/// 2. `ptrace(PT_DENY_ATTACH)`: later ptrace attaches fail. Refused (-20)
///    rather than attempted if a debugger is already attached, because
///    then the kernel would terminate the process.
/// 3. The host executable's code signature is checked
///    (`codeSignatureWeaknesses`). That is what stops a same-user process
///    from taking this process's task port to read its memory, and only
///    the host's signer can change it. A weakness is logged as a warning
///    and the call still succeeds, so development hosts (python, dotnet,
///    Xcode Debug builds) work -- unless `flags` includes
///    HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE, which makes it -20.
///
/// Steps 1 and 2 are applied before step 3 is judged, so a strict-mode
/// failure still leaves the process as hardened as it could be made.
/// Unknown flag bits are -1, before anything changes. Idempotent.
@_cdecl("hkdfguard_harden_process_with_flags")
public func hkdfguard_harden_process_with_flags(flags: UInt32) -> Int32 {
    guard flags & ~hkdfguardHardenAllFlags == 0 else {
        hardeningLog.error("hkdfguard_harden_process_with_flags: unknown flag bits \(flags & ~hkdfguardHardenAllFlags, format: .hex)")
        return HKDFGuardStatus.invalidInputLength.rawValue
    }

    var noCore = rlimit(rlim_cur: 0, rlim_max: 0)
    guard setrlimit(RLIMIT_CORE, &noCore) == 0 else {
        hardeningLog.error("hkdfguard: could not disable core dumps (setrlimit RLIMIT_CORE): \(String(cString: strerror(errno)), privacy: .public)")
        return HKDFGuardStatus.processHardeningFailed.rawValue
    }

    switch isBeingTraced() {
    case .some(false):
        guard sys_ptrace(PT_DENY_ATTACH, 0, nil, 0) == 0 else {
            hardeningLog.error("hkdfguard: could not deny debugger attachment (ptrace PT_DENY_ATTACH): \(String(cString: strerror(errno)), privacy: .public)")
            return HKDFGuardStatus.processHardeningFailed.rawValue
        }
    case .some(true):
        hardeningLog.error("hkdfguard: a debugger is attached to this process; it can't be hardened against one")
        return HKDFGuardStatus.processHardeningFailed.rawValue
    case .none:
        hardeningLog.error("hkdfguard: could not tell whether a debugger is attached (sysctl KERN_PROC_PID): \(String(cString: strerror(errno)), privacy: .public)")
        return HKDFGuardStatus.processHardeningFailed.rawValue
    }

    let weaknesses = codeSignatureWeaknesses()
    if !weaknesses.isEmpty {
        let why = weaknesses.joined(separator: "; ")
        if flags & hkdfguardHardenRequireProtectedSignature != 0 {
            hardeningLog.error("hkdfguard: other processes of this user can still debug or inject code into this process: \(why, privacy: .public). Sign the host executable with the Hardened Runtime and without those entitlements.")
            return HKDFGuardStatus.processHardeningFailed.rawValue
        }
        hardeningLog.warning("hkdfguard: process hardened, but other processes of this user can still debug or inject code into it: \(why, privacy: .public). Fine for development; for production, sign the host executable with the Hardened Runtime and without those entitlements, and pass HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE.")
    }
    return HKDFGuardStatus.success.rawValue
}

/// Reports which keychain this process's KEK items live in — see
/// `KeychainMode`. `*outMode` is 0 for the legacy login keychain and 1 for
/// the data-protection keychain, and is written on every return path.
/// Callers should surface this (the CLI prints it) because a service's
/// provisioner and its consumers must agree on it.
@_cdecl("hkdfguard_keychain_mode")
public func hkdfguard_keychain_mode(
    outMode: UnsafeMutablePointer<Int32>?
) -> Int32 {
    guard let outMode else {
        return HKDFGuardStatus.invalidInputLength.rawValue
    }
    switch hkdfguardKeychainMode {
    case .legacy:
        outMode.pointee = 0
    case .dataProtection:
        outMode.pointee = 1
    }
    return HKDFGuardStatus.success.rawValue
}

/// macOS-only. Reports the KEK policy in effect, as UTF-8 JSON (not
/// NUL-terminated): `mode` is "development" (no policy: every KEK is
/// user-scoped), "production" (with `source`, the role groups, and
/// `machineServices`: service -> `runnerGroup`), or "invalid" (with
/// `reason`; every other call then fails with POLICY_INVALID). Also
/// `machineKeyFolder`, and `systemContext`: whether this process may use
/// machine KEKs at all. The hkdfguard CLI uses it to enforce the roles.
/// Buffer contract as the other functions': a capacity too small is
/// BUFFER_TOO_SMALL with `*outLen` set to the length needed.
@_cdecl("hkdfguard_machine_policy")
public func hkdfguard_machine_policy(
    outPtr: UnsafeMutablePointer<UInt8>?,
    outLen: UnsafeMutablePointer<Int32>?
) -> Int32 {
    guard let outLen, outLen.pointee >= 0 else {
        return HKDFGuardStatus.invalidInputLength.rawValue
    }
    guard let json = machinePolicyJSON(), !json.isEmpty, json.count <= Int(Int32.max) else {
        return HKDFGuardStatus.unexpectedOutputLength.rawValue
    }
    guard Int(outLen.pointee) >= json.count else {
        outLen.pointee = Int32(json.count)
        return HKDFGuardStatus.outputBufferTooSmall.rawValue
    }
    guard let outPtr else {
        return HKDFGuardStatus.invalidInputLength.rawValue
    }
    guard copyOut(json, to: outPtr, count: json.count) else {
        return HKDFGuardStatus.unexpectedOutputLength.rawValue
    }
    outLen.pointee = Int32(json.count)
    return HKDFGuardStatus.success.rawValue
}

/// Reports whether a Secure Enclave KEK already exists for `service`,
/// without creating one — `*outExists` is always written, on every return
/// path (1 if a valid KEK exists, 0 otherwise, including when the status
/// isn't `success`, in which case existence couldn't be determined), so
/// the caller's variable is never left in an undefined state. A setup
/// call: held to `setupMinDelay` and serialized (see `gatedSetup`).
@_cdecl("hkdfguard_kek_exists")
public func hkdfguard_kek_exists(
    servicePtr: UnsafePointer<CChar>?,
    outExists: UnsafeMutablePointer<Int32>?
) -> Int32 {
    // NULL from a C caller is a contract violation, reported rather than
    // dereferenced -- here and in every entry point below.
    guard let outExists else {
        return HKDFGuardStatus.invalidInputLength.rawValue
    }
    outExists.pointee = 0

    guard let servicePtr, let service = normalizedService(from: servicePtr) else {
        return HKDFGuardStatus.invalidServiceIdentifier.rawValue
    }

    let (status, exists) = gatedSetup { kekExists(service: service) }
    outExists.pointee = exists ? 1 : 0
    if status != HKDFGuardStatus.success.rawValue {
        auditOperationFailed(.kekExists, service: service, code: status)
    }
    return status
}

/// Writes the 32-byte fingerprint (SHA-256 of the public key) of the KEK
/// `service` currently resolves to -- the same value embedded at the front
/// of every payload wrapped under it. Public-key material only, so safe to
/// expose; lets an operator pin which KEK a service uses and confirm it
/// before retiring it. Never creates a KEK. A setup call: held to
/// `setupMinDelay` and serialized (see `gatedSetup`) like
/// `hkdfguard_kek_exists`, since "found" vs `kekNotFound` answers the same
/// question -- which services have a KEK -- and would otherwise let it be
/// asked as fast as the keychain answers.
@_cdecl("hkdfguard_kek_fingerprint")
public func hkdfguard_kek_fingerprint(
    servicePtr: UnsafePointer<CChar>?,
    outPtr: UnsafeMutablePointer<UInt8>?,
    outLen: UnsafeMutablePointer<Int32>?
) -> Int32 {
    guard let outPtr, let outLen else {
        return HKDFGuardStatus.invalidInputLength.rawValue
    }
    guard Int(outLen.pointee) >= hkdfguardFingerprintLength else {
        outLen.pointee = Int32(hkdfguardFingerprintLength)
        return HKDFGuardStatus.outputBufferTooSmall.rawValue
    }
    guard let servicePtr, let service = normalizedService(from: servicePtr) else {
        return HKDFGuardStatus.invalidServiceIdentifier.rawValue
    }

    // The key itself stays inside the gate; only its public fingerprint
    // leaves it.
    // For a machine KEK, from its file's public key: no Secure Enclave use,
    // so root can read it from Terminal (`status`, `provision`, `retire`).
    let (status, maybeFingerprint) = gatedSetup { () -> (Int32, Data?) in
        switch kekScope(service: service) {
        case .policyInvalid:
            return (HKDFGuardStatus.policyInvalid.rawValue, nil)
        case .machine:
            let (status, maybeKey) = machinePublicKey(service: service)
            return (status, maybeKey.map(kekFingerprint))
        case .user:
            let (status, maybeKey) = getKEK(service: service)
            return (status, maybeKey.map { kekFingerprint($0.publicKey) })
        }
    }
    guard let fingerprint = maybeFingerprint else {
        auditOperationFailed(.kekFingerprint, service: service, code: status)
        return status
    }

    guard copyOut(fingerprint, to: outPtr, count: hkdfguardFingerprintLength) else {
        return HKDFGuardStatus.unexpectedOutputLength.rawValue
    }
    outLen.pointee = Int32(hkdfguardFingerprintLength)
    return HKDFGuardStatus.success.rawValue
}

/// Creates a Secure Enclave KEK for `service` if one doesn't already
/// exist. Paired with `hkdfguard_kek_exists` above so a caller can decide
/// for itself whether creation is needed — e.g. prompting for user
/// consent, or provisioning on a schedule — rather than have that decision
/// made implicitly inside a single combined "ensure" call. A setup call:
/// held to `setupMinDelay` and serialized (see `gatedSetup`).
@_cdecl("hkdfguard_create_kek")
public func hkdfguard_create_kek(
    servicePtr: UnsafePointer<CChar>?
) -> Int32 {
    guard let servicePtr, let service = normalizedService(from: servicePtr) else {
        return HKDFGuardStatus.invalidServiceIdentifier.rawValue
    }

    let status = gatedSetup { createKEK(service: service) }
    if status != HKDFGuardStatus.success.rawValue {
        auditOperationFailed(.createKek, service: service, code: status)
    }
    return status
}

@_cdecl("hkdfguard_wrap_dek")
public func hkdfguard_wrap_dek(
    servicePtr: UnsafePointer<CChar>?,
    dekPtr: UnsafePointer<UInt8>?,
    dekLen: Int32,
    outPtr: UnsafeMutablePointer<UInt8>?,
    outLen: UnsafeMutablePointer<Int32>?
) -> Int32 {
    let status = wrapDekChecked(servicePtr: servicePtr, dekPtr: dekPtr, dekLen: dekLen, outPtr: outPtr, outLen: outLen)
    auditDekCall(.wrap, servicePtr, status: status, payload: writtenPayload(status, outPtr, outLen))
    return status
}

/// The payload a successful wrap wrote to `out`, for its audit record.
private func writtenPayload(_ status: Int32, _ outPtr: UnsafeMutablePointer<UInt8>?, _ outLen: UnsafeMutablePointer<Int32>?) -> UnsafeBufferPointer<UInt8>? {
    guard status == HKDFGuardStatus.success.rawValue, let outPtr, let outLen, outLen.pointee >= 0 else { return nil }
    return UnsafeBufferPointer(start: outPtr, count: Int(outLen.pointee))
}

/// The argument checks shared by `hkdfguard_wrap_dek` and
/// `hkdfguard_generate_and_wrap_dek`, in Linux's `wrap_impl` order, then the
/// wrap itself. Everything here is answered before any keychain lookup or
/// Secure Enclave operation:
///
/// - NULL `dek` or `out_len`, a `dek_len` other than 32, or a negative
///   capacity: -1.
/// - An invalid service: -8.
/// - NULL `out` with a positive capacity (somewhere declared, nowhere to
///   write): -1.
/// - A capacity under 125 -- including the 0 of a size probe, which may pass
///   a NULL `out`: -2 with `*out_len` = 125. The payload size is a constant,
///   so no ciphertext is ever produced for a caller who can't receive it.
private func wrapDekChecked(
    servicePtr: UnsafePointer<CChar>?,
    dekPtr: UnsafePointer<UInt8>?,
    dekLen: Int32,
    outPtr: UnsafeMutablePointer<UInt8>?,
    outLen: UnsafeMutablePointer<Int32>?
) -> Int32 {
    guard let dekPtr, let outLen, dekLen == Int32(hkdfguardDekLength) else {
        return HKDFGuardStatus.invalidInputLength.rawValue
    }
    let capacity = outLen.pointee
    guard capacity >= 0 else {
        return HKDFGuardStatus.invalidInputLength.rawValue
    }
    guard let servicePtr, let service = normalizedService(from: servicePtr) else {
        return HKDFGuardStatus.invalidServiceIdentifier.rawValue
    }
    guard outPtr != nil || capacity == 0 else {
        return HKDFGuardStatus.invalidInputLength.rawValue
    }
    guard Int(capacity) >= hkdfguardWrappedLength, let outPtr else {
        outLen.pointee = Int32(hkdfguardWrappedLength)
        return HKDFGuardStatus.outputBufferTooSmall.rawValue
    }

    return wrapDekCore(service: service, dekPtr: dekPtr, dekLen: dekLen, outPtr: outPtr, outLen: outLen)
}

// MARK: - Generate a new random DEK and wrap it, in one call

private func generateRandomDek() -> Data? {
    var bytes = Data(count: hkdfguardDekLength)
    let status = bytes.withUnsafeMutableBytes { raw -> OSStatus in
        guard raw.count == hkdfguardDekLength, let base = raw.baseAddress else { return errSecParam }
        return SecRandomCopyBytes(kSecRandomDefault, hkdfguardDekLength, base)
    }
    guard status == errSecSuccess else { return nil }
    return bytes
}

@_cdecl("hkdfguard_generate_and_wrap_dek")
public func hkdfguard_generate_and_wrap_dek(
    servicePtr: UnsafePointer<CChar>?,
    outPtr: UnsafeMutablePointer<UInt8>?,
    outLen: UnsafeMutablePointer<Int32>?
) -> Int32 {
    let status = generateAndWrapCore(servicePtr: servicePtr, outPtr: outPtr, outLen: outLen)
    auditDekCall(.generateAndWrap, servicePtr, status: status, payload: writtenPayload(status, outPtr, outLen))
    return status
}

private func generateAndWrapCore(
    servicePtr: UnsafePointer<CChar>?,
    outPtr: UnsafeMutablePointer<UInt8>?,
    outLen: UnsafeMutablePointer<Int32>?
) -> Int32 {
    // As on Linux: the DEK is generated first, then every argument is
    // checked exactly as hkdfguard_wrap_dek checks it.
    guard var dek = generateRandomDek() else {
        return HKDFGuardStatus.encryptionFailed.rawValue
    }

    defer { secureZero(&dek) }

    return dek.withUnsafeBytes { raw -> Int32 in
        guard let dekPtr = raw.bindMemory(to: UInt8.self).baseAddress, raw.count == hkdfguardDekLength else {
            return HKDFGuardStatus.unexpectedOutputLength.rawValue
        }
        return wrapDekChecked(
            servicePtr: servicePtr,
            dekPtr: dekPtr,
            dekLen: Int32(hkdfguardDekLength),
            outPtr: outPtr,
            outLen: outLen
        )
    }
}

// MARK: - Unwrap (decrypt) a DEK using the Secure Enclave KEK

/// Runs `body` -- an entry point that writes into the caller's `out` -- and,
/// on any non-success status, zeroes every byte of the capacity the caller
/// declared in `*outLen` on entry, as on Linux: no partial or stale key
/// material is ever left in `out`. With a NULL `out` or `outLen` there is no
/// declared buffer that can safely be written, so nothing is.
private func zeroingOutOnFailure(
    _ outPtr: UnsafeMutablePointer<UInt8>?,
    _ outLen: UnsafeMutablePointer<Int32>?,
    _ body: () -> Int32
) -> Int32 {
    let declaredCapacity = outLen.map { Int($0.pointee) } ?? 0
    let status = body()
    if status != HKDFGuardStatus.success.rawValue, let outPtr, declaredCapacity > 0 {
        _ = memset_s(outPtr, declaredCapacity, 0, declaredCapacity)
    }
    return status
}

/// On any failure, every byte of the caller's declared `out` capacity is
/// zeroed (see `zeroingOutOnFailure`).
@_cdecl("hkdfguard_unwrap_dek")
public func hkdfguard_unwrap_dek(
    servicePtr: UnsafePointer<CChar>?,
    wrappedPtr: UnsafePointer<UInt8>?,
    wrappedLen: Int32,
    outPtr: UnsafeMutablePointer<UInt8>?,
    outLen: UnsafeMutablePointer<Int32>?
) -> Int32 {
    let status = zeroingOutOnFailure(outPtr, outLen) {
        unwrapDekCore(servicePtr: servicePtr, wrappedPtr: wrappedPtr, wrappedLen: wrappedLen, outPtr: outPtr, outLen: outLen)
    }
    let consumed = status == HKDFGuardStatus.success.rawValue
        ? wrappedPtr.map { UnsafeBufferPointer(start: $0, count: Int(wrappedLen)) } : nil
    auditDekCall(.unwrap, servicePtr, status: status, payload: consumed)
    return status
}

private func unwrapDekCore(
    servicePtr: UnsafePointer<CChar>?,
    wrappedPtr: UnsafePointer<UInt8>?,
    wrappedLen: Int32,
    outPtr: UnsafeMutablePointer<UInt8>?,
    outLen: UnsafeMutablePointer<Int32>?
) -> Int32 {
    // Argument checks in Linux's unwrap_impl order, all before any keychain
    // lookup or Secure Enclave operation.
    guard let outLen, let wrappedPtr else {
        return HKDFGuardStatus.invalidInputLength.rawValue
    }
    let capacity = outLen.pointee
    guard wrappedLen >= 0, capacity >= 0 else {
        return HKDFGuardStatus.invalidInputLength.rawValue
    }
    guard let servicePtr, let service = normalizedService(from: servicePtr) else {
        return HKDFGuardStatus.invalidServiceIdentifier.rawValue
    }

    // The plaintext size is a constant: a too-small buffer -- including the
    // 0 of a size probe, which may pass a NULL `out` -- is reported before
    // the payload is even looked at, so a DEK is never decrypted into memory
    // for a caller who cannot receive it.
    guard Int(capacity) >= hkdfguardDekLength else {
        outLen.pointee = Int32(hkdfguardDekLength)
        return HKDFGuardStatus.outputBufferTooSmall.rawValue
    }
    guard let outPtr else {
        return HKDFGuardStatus.invalidInputLength.rawValue // a declared capacity with nowhere to write
    }

    // Every payload this library produces is exactly hkdfguardWrappedLength
    // bytes, so anything else is malformed and rejected before it is read.
    guard wrappedLen == Int32(hkdfguardWrappedLength) else {
        return HKDFGuardStatus.payloadMalformed.rawValue
    }

    let header = Data(bytes: wrappedPtr, count: hkdfguardHeaderLength)
    let storedFingerprint = header.prefix(hkdfguardFingerprintLength)
    let suiteId = wrappedPtr[hkdfguardSuiteIdOffset]
    let nonceBytes = Data(bytes: wrappedPtr + hkdfguardNonceOffset, count: hkdfguardNonceLength)
    let ciphertext = Data(bytes: wrappedPtr + hkdfguardCiphertextOffset, count: hkdfguardDekLength)
    let tag = Data(bytes: wrappedPtr + hkdfguardCiphertextOffset + hkdfguardDekLength, count: hkdfguardGCMTagLength)

    // A payload of a suite this build does not implement is reported as
    // such, before the keychain is consulted: it is a version or build
    // mismatch, not tampering.
    guard suiteId == hkdfguardSuiteId else {
        return HKDFGuardStatus.unsupportedCiphersuite.rawValue
    }

    var plaintext: Data
    do {
        let (getStatus, maybeEnclaveKey) = getKEK(service: service)
        guard let enclaveKey = maybeEnclaveKey else {
            return getStatus
        }

        // Checked against the *current* KEK's own public key before any key
        // agreement is attempted — a plain equality comparison is fine here
        // since neither side is secret (both are public-key material); this
        // is a fast, specific "wrong/stale KEK" signal that fails ahead of
        // the AEAD tag check below, which also covers this same fingerprint
        // (it is in the AAD) and would catch a tampered one anyway.
        let currentFingerprint = kekFingerprint(enclaveKey.publicKey)
        guard currentFingerprint == storedFingerprint else {
            return HKDFGuardStatus.fingerprintMismatch.rawValue
        }

        // The fixed-length fields always form a box; failing that is a bug.
        guard let nonce = try? AES.GCM.Nonce(data: nonceBytes),
              let box = try? AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag) else {
            return HKDFGuardStatus.unexpectedOutputLength.rawValue
        }

        // Re-derive the payload's key -- the Secure Enclave's ECDH against
        // the point its salt hashes to, then HKDF over the same header and
        // service -- and open. The two failures are kept apart, as on Linux:
        // the enclave refusing the key agreement (locked, unavailable) is a
        // CRYPTO_ERROR about this machine, not a verdict on the payload;
        // only a tag that doesn't verify is PAYLOAD_AUTH_FAILED (tampered,
        // or sealed for a different service).
        let key: SymmetricKey
        do {
            guard let derived = try deriveWrappingKey(enclaveKey: enclaveKey, service: service, header: header) else {
                return HKDFGuardStatus.encryptionFailed.rawValue // no point for this salt (probability 2^-255)
            }
            key = derived
        } catch {
            return HKDFGuardStatus.encryptionFailed.rawValue
        }
        do {
            plaintext = try AES.GCM.open(box, using: key, authenticating: header)
        } catch {
            return HKDFGuardStatus.decryptionFailed.rawValue
        }
    }

    defer { secureZero(&plaintext) }

    guard plaintext.count == hkdfguardDekLength else {
        return HKDFGuardStatus.unexpectedOutputLength.rawValue
    }

    guard Int(capacity) >= plaintext.count else {
        outLen.pointee = Int32(plaintext.count)
        return HKDFGuardStatus.outputBufferTooSmall.rawValue
    }

    guard copyOut(plaintext, to: outPtr, count: hkdfguardDekLength) else {
        return HKDFGuardStatus.unexpectedOutputLength.rawValue
    }
    outLen.pointee = Int32(hkdfguardDekLength)

    return HKDFGuardStatus.success.rawValue
}

// MARK: - Read a wrapped payload from a file

/// Maps an `open(2)` failure to the status `hkdfguard_open_file` reports.
private func fileOpenStatus(errno code: Int32) -> HKDFGuardStatus {
    switch code {
    case ENOENT, ENOTDIR:
        return .fileNotFound
    case EACCES, EPERM:
        return .fileAccessDenied
    case ELOOP:
        // O_NOFOLLOW found a symbolic link as the final component (or the
        // path loops through links): a link is refused as untrusted, as the
        // Windows build refuses any reparse point -- not as an I/O failure.
        return .fileInsecure
    default:
        // Including EOPNOTSUPP (the path names a socket): HKDFGUARD_ERR_FILE_IO
        // covers "not a regular file" and "could not be read" alike.
        return .fileIO
    }
}

/// Whether the key file's folder, open as `folderFd`, and every folder above
/// it up to `/` are ones nobody untrusted can rename, replace or
/// delete entries in: a directory owned by root or this process's
/// effective user, and not writable by group or others unless sticky
/// (`/tmp`-style: the kernel then lets only an entry's owner, or the
/// folder's, rename or remove it, and the file's own owner has just been
/// checked). Write bits are ignored on a read-only volume. Linux's
/// `check_dir_chain_for_existing_file`, with the same rules.
///
/// The folder is the one the path names the file in, opened by
/// `readWrappedFile` before the file, which is then opened *within* it
/// (`openat`): so the file read is that folder's entry, whatever other
/// names (hard links) it has elsewhere, and the folder checked is where it
/// was found -- Linux's "folder the path names it in". (Working back from
/// the open file instead, with F_GETPATH, fails for a hard-linked file:
/// macOS reports whichever of its names was looked up last.) As on Linux,
/// folders that symlinks inside the path live in are not walked: someone
/// able to retarget one could at most send the path to a different file
/// that itself passes every check here.
///
/// A folder writable by the `admin` group (`/Applications`, say) fails,
/// as a group-writable folder does on Linux: every administrator could
/// replace the key there without root.
///
/// `rootOnly` (the policy file's and machine keys' folders): every folder
/// must be root's, not this user's, and no group or other write bit is
/// excused by the sticky bit either -- as Linux judges its policy folder.
func keyFileFoldersAreTrusted(folderFd: Int32, rootOnly: Bool = false) -> Bool {
    // Walked by descriptor, from the key file's own folder up through
    // openat(fd, "..") until a folder is its own parent (/): no path string
    // is decoded, split or looked up again, so neither an odd folder name
    // (one starting with a combining mark fuses with the "/" before it in a
    // Swift String, and its parent would be skipped) nor a folder renamed
    // mid-walk can make a folder be skipped or judged in its stead.
    var current = dup(folderFd)
    guard current >= 0 else {
        return false
    }
    defer { close(current) }

    let uid = geteuid()
    for _ in 0..<Int(MAXPATHLEN) { // a path has at most this many folders
        var info = stat()
        guard fstat(current, &info) == 0,
              info.st_mode & S_IFMT == S_IFDIR,
              info.st_uid == 0 || (!rootOnly && info.st_uid == uid),
              !onVolumeIgnoringOwnership(current),
              !aclGrantsOthersAChange(fd: current, isFolder: true, rootOnly: rootOnly) else {
            return false
        }
        let writable = info.st_mode & (S_IWGRP | S_IWOTH) != 0
        let sticky = info.st_mode & S_ISVTX != 0
        if writable && (rootOnly || !sticky) && !onSealedSystemVolume(current) {
            return false
        }

        let parent = openat(current, "..", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard parent >= 0 else {
            return false
        }
        var parentInfo = stat()
        guard fstat(parent, &parentInfo) == 0 else {
            close(parent)
            return false
        }
        if parentInfo.st_dev == info.st_dev && parentInfo.st_ino == info.st_ino {
            close(parent) // "/" is its own parent: the whole chain passed
            return true
        }
        close(current)
        current = parent
    }
    return false
}

/// Whether `fd` is on a volume mounted with ownership ignored (the default
/// for disk images and removable media a user mounts). There the kernel
/// reports every file and folder as owned by whoever asks, so the owner
/// checks above would pass for anything on it, whoever wrote it.
private func onVolumeIgnoringOwnership(_ fd: Int32) -> Bool {
    var fs = statfs()
    guard fstatfs(fd, &fs) == 0 else {
        return true // can't tell: treat as untrusted
    }
    return fs.f_flags & UInt32(MNT_IGNORE_OWNERSHIP) != 0
}

/// Whether `fd` is on the sealed, read-only system volume, the one place
/// write bits on a folder can be ignored: nothing on it can change. Any
/// other read-only volume -- a disk image someone built and mounted, say --
/// gets no exemption, since whoever built it chose its contents.
private func onSealedSystemVolume(_ fd: Int32) -> Bool {
    var fs = statfs()
    guard fstatfs(fd, &fs) == 0 else {
        return false
    }
    let required = UInt32(MNT_RDONLY) | UInt32(MNT_ROOTFS)
    return fs.f_flags & required == required
}

/// Whether the access control list on `fd` grants anyone other than root or
/// this user a right that could change what the key path reads. Mode bits
/// alone miss this: on macOS an ACL can grant write to anyone regardless of
/// a 0600 or 0755 mode.
///
/// For a file: writing or appending its data, deleting it, or changing its
/// permissions, owner, ACL or attributes. For a folder: adding, removing or
/// renaming entries (add_file, add_subdirectory, delete_child), and changing
/// its permissions, owner or ACL. Deny entries only take rights away, so
/// only allow entries count -- the standard "everyone deny delete" on home
/// folders passes. Entries for root or this user are harmless. An ACL that
/// can't be read, or an entry whose principal can't be resolved, counts as
/// granting (fail closed).
///
/// `rootOnly`: an entry for this user counts as granting too -- for files
/// only root may control (the policy, machine keys), whoever reads them.
private func aclGrantsOthersAChange(fd: Int32, isFolder: Bool, rootOnly: Bool = false) -> Bool {
    guard let acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED) else {
        return errno != ENOENT // no ACL at all; any other failure fails closed
    }
    defer { acl_free(UnsafeMutableRawPointer(acl)) }

    let risky: [acl_perm_t] = isFolder
        ? [ACL_ADD_FILE, ACL_ADD_SUBDIRECTORY, ACL_DELETE_CHILD, ACL_DELETE,
           ACL_WRITE_SECURITY, ACL_CHANGE_OWNER]
        : [ACL_WRITE_DATA, ACL_APPEND_DATA, ACL_DELETE, ACL_WRITE_ATTRIBUTES,
           ACL_WRITE_EXTATTRIBUTES, ACL_WRITE_SECURITY, ACL_CHANGE_OWNER]
    let uid = geteuid()

    var entry: acl_entry_t?
    var which = ACL_FIRST_ENTRY.rawValue
    while acl_get_entry(acl, Int32(which), &entry) == 0, let current = entry {
        which = ACL_NEXT_ENTRY.rawValue
        var tag = ACL_UNDEFINED_TAG
        guard acl_get_tag_type(current, &tag) == 0 else {
            return true
        }
        guard tag == ACL_EXTENDED_ALLOW else {
            continue // deny entries can only take rights away
        }
        var permset: acl_permset_t?
        guard acl_get_permset(current, &permset) == 0, let perms = permset else {
            return true
        }
        guard risky.contains(where: { acl_get_perm_np(perms, $0) == 1 }) else {
            continue // grants only reading or listing
        }
        // Who is granted it: harmless if root or this user, else refuse.
        guard let qualifier = acl_get_qualifier(current) else {
            return true
        }
        defer { acl_free(qualifier) }
        var id: id_t = 0
        var type: Int32 = 0
        let resolved = qualifier.withMemoryRebound(to: UInt8.self, capacity: 16) {
            mbr_uuid_to_id($0, &id, &type) == 0
        }
        guard resolved, type == ID_TYPE_UID, id == 0 || (!rootOnly && id == uid) else {
            return true
        }
    }
    return false
}

/// Reads at most `buffer.count` bytes of the regular file at `path` into
/// `buffer`, returning how many were read. A file whose size already
/// exceeds a wrapped payload is rejected from `fstat` alone, before any
/// read. The caller zeroes `buffer`, which may end up holding a plaintext
/// DEK.
private func readWrappedFile(
    path: UnsafePointer<CChar>,
    length: Int, // the path's length, already bounded by openFileCore
    into buffer: inout [UInt8]
) -> (status: HKDFGuardStatus, count: Int) {
    // The path is split, as bytes, into the folder it names and its last
    // component. The folder is opened first and the file then opened within
    // it (openat), so the file read is exactly that folder's entry and the
    // folder is the one checked below -- never inferred back from the file,
    // which a hard link makes ambiguous (see keyFileFoldersAreTrusted).
    var lastSlash = -1
    for i in 0..<length where path[i] == 0x2F { // '/'
        lastSlash = i
    }
    guard lastSlash + 1 < length else {
        return (.fileIO, 0) // ends in '/': names a folder, not a file
    }
    let folderPath: [CChar] = lastSlash < 0
        ? [0x2E, 0] // "." -- a bare file name is in the current folder
        : lastSlash == 0 ? [0x2F, 0] : Array(UnsafeBufferPointer(start: path, count: lastSlash)) + [0]

    // Symlinks in the folder part resolve as usual, so /etc and /tmp --
    // themselves symlinks into /private -- work.
    var folderFd: Int32
    repeat {
        folderFd = open(folderPath, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    } while folderFd < 0 && errno == EINTR
    guard folderFd >= 0 else {
        return (fileOpenStatus(errno: errno), 0)
    }
    defer { close(folderFd) }

    // O_NOFOLLOW: a symlink as the final component is refused, not followed.
    // O_NONBLOCK: a FIFO with no writer would otherwise block here; it has
    // no effect on the regular files actually accepted. O_CLOEXEC: never
    // inherited by a child.
    var fd: Int32
    repeat {
        fd = openat(folderFd, path + lastSlash + 1, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
    } while fd < 0 && errno == EINTR
    guard fd >= 0 else {
        return (fileOpenStatus(errno: errno), 0)
    }
    defer { close(fd) }

    // Everything below is judged on the open descriptor, so it describes the
    // file that will be read, not whatever the path names by now.
    var info = stat()
    guard fstat(fd, &info) == 0 else {
        return (.fileIO, 0)
    }
    guard info.st_mode & S_IFMT == S_IFREG else {
        return (.fileIO, 0)
    }
    // Same rules the CLI's `wrap` writes to (0600) and the install scripts
    // apply to the library itself: nobody but the owner can have put these
    // bytes here, and the owner is either this user or root (an admin- or
    // MDM-deployed file; root can alter anything anyway).
    //
    // A file with more than one hard link is accepted, as on Linux and
    // Windows. Another name for the file only matters if someone could use
    // it to put an older payload where the service looks -- and that takes
    // creating an entry in the key's own folder: the folder the file was
    // just opened within, which `keyFileFoldersAreTrusted` below limits to
    // the owner and root.
    guard info.st_uid == geteuid() || info.st_uid == 0,
          info.st_mode & (S_IWGRP | S_IWOTH) == 0,
          // On a volume ignoring ownership, st_uid above is whoever asked.
          !onVolumeIgnoringOwnership(fd),
          // Nor may an ACL let anyone else rewrite, replace or re-permission it.
          !aclGrantsOthersAChange(fd: fd, isFolder: false) else {
        return (.fileInsecure, 0)
    }
    // And the folders that decide what the path names, as on Linux --
    // otherwise someone else could rename a file of their choosing over the
    // key, and the checks above would pass on whatever they put there.
    guard keyFileFoldersAreTrusted(folderFd: folderFd) else {
        return (.fileInsecure, 0)
    }
    // Exactly a DEK's size: a plaintext key, refused from its size alone,
    // never read into this process -- as on Linux (key_file.rs). A 32-byte
    // file rewritten mid-call is still caught on its contents below.
    guard info.st_size != off_t(hkdfguardDekLength) else {
        return (.fileUnprotectedKey, 0)
    }
    guard info.st_size <= off_t(hkdfguardWrappedLength) else {
        return (.fileTooLong, 0)
    }

    // Read until EOF or the buffer is full, whatever fstat said: the file
    // may change between the two, and the bytes actually read decide.
    var count = 0
    let status: HKDFGuardStatus = buffer.withUnsafeMutableBytes { raw in
        guard let base = raw.baseAddress else {
            return .unexpectedOutputLength
        }
        while count < raw.count {
            let n = read(fd, base + count, raw.count - count)
            let readErrno = errno // captured before anything else can run
            if n > 0 {
                count += n
            } else if n == 0 {
                return .success
            } else if readErrno != EINTR {
                return .fileIO
            }
        }
        return .success
    }
    return (status, status == .success ? count : 0)
}

/// Longest text form of a DEK recognised, surrounding whitespace included --
/// the Linux and Windows limit. Every length up to it is below a payload's,
/// so no payload can be mistaken for a plaintext key.
private let hkdfguardMaxPlaintextTextLength = 96

// Branch-free byte classification for `looksLikePlaintextDek`. Every helper
// returns 0 or 1 and is straight-line arithmetic on UInt32 (`&-`, `&+`:
// wrapping, never trapping), with no data-dependent branch or table lookup.
// The Linux build's `ct` module, step for step.

/// 1 if a == b, else 0 (inputs below 2^31).
@inline(__always) private func ctEq(_ a: UInt32, _ b: UInt32) -> UInt32 {
    ((a ^ b) &- 1) >> 31
}

/// 1 if lo <= c <= hi, else 0 (inputs below 2^31): both differences wrap
/// negative exactly when c is inside.
@inline(__always) private func ctInRange(_ c: UInt32, _ lo: UInt32, _ hi: UInt32) -> UInt32 {
    (((lo &- 1) &- c) & (c &- (hi &+ 1))) >> 31 & 1
}

/// a if cond is 1, b if it is 0.
@inline(__always) private func ctSelect(_ cond: UInt32, _ a: UInt32, _ b: UInt32) -> UInt32 {
    b ^ ((a ^ b) & (0 &- cond))
}

/// What Rust's trim_ascii removes: space, tab, LF, form feed, CR.
@inline(__always) private func ctIsWhitespace(_ c: UInt32) -> UInt32 {
    ctEq(c, 0x20) | ctEq(c, 0x09) | ctEq(c, 0x0A) | ctEq(c, 0x0C) | ctEq(c, 0x0D)
}

@inline(__always) private func ctIsHex(_ c: UInt32) -> UInt32 {
    ctInRange(c, 0x30, 0x39) | ctInRange(c, 0x61, 0x66) | ctInRange(c, 0x41, 0x46) // 0-9 a-f A-F
}

/// (member, 6-bit value) of `c` in the base64 alphabet whose 62nd and 63rd
/// characters are `c62` and `c63`.
@inline(__always) private func ctBase64(_ c: UInt32, _ c62: UInt32, _ c63: UInt32) -> (member: UInt32, value: UInt32) {
    let upper = ctInRange(c, 0x41, 0x5A) // A-Z
    let lower = ctInRange(c, 0x61, 0x7A) // a-z
    let digit = ctInRange(c, 0x30, 0x39) // 0-9
    let s62 = ctEq(c, c62)
    let s63 = ctEq(c, c63)
    let value = ((c &- 0x41) & (0 &- upper)) | ((c &- (0x61 - 26)) & (0 &- lower))
        | ((c &+ (52 - 0x30)) & (0 &- digit)) | (62 & (0 &- s62)) | (63 & (0 &- s63))
    return (upper | lower | digit | s62 | s63, value)
}

/// True when `bytes` look like a bare 32-byte DEK rather than a wrapped
/// payload: exactly 32 raw bytes, or -- with any surrounding whitespace an
/// editor or `echo` adds -- the 64-digit hex (either case) or base64
/// (standard or URL-safe, with or without its one `=` of padding) of 32
/// bytes. The same set the Linux and Windows builds recognise: base64 is
/// 43 characters, or 44 ending in `=`, all in one alphabet, whose last
/// character's 2 unused bits are zero.
///
/// Constant-time in the contents, as on Linux and Windows: the only
/// branches are on the length, which the file's size already gives away.
/// Every byte is visited twice (once to find the text between the
/// surrounding whitespace, once to test it against all three alphabets at
/// once) and every decision is mask arithmetic, so how long this takes says
/// nothing about where in a would-be key the first non-matching byte sits.
/// Nothing is decoded, so the key is never reassembled.
func looksLikePlaintextDek(_ bytes: ArraySlice<UInt8>) -> Bool { // internal: tested directly
    if bytes.count == hkdfguardDekLength {
        return true
    }
    if bytes.count > hkdfguardMaxPlaintextTextLength {
        return false
    }
    let base = bytes.startIndex

    // Pass 1: the first and last non-whitespace positions.
    var seen: UInt32 = 0, start: UInt32 = 0, end: UInt32 = 0
    for offset in 0..<bytes.count {
        let i = UInt32(offset)
        let text = ctIsWhitespace(UInt32(bytes[base + offset])) ^ 1
        start = ctSelect(text & (seen ^ 1), i, start)
        end = ctSelect(text, i, end)
        seen |= text
    }
    let textLength = ((end &- start) &+ 1) & (0 &- seen)

    // Pass 2: every byte between them against every alphabet, plus the
    // values of the last two (the last may be the `=` of padding).
    var hexOK: UInt32 = 1, stdOK: UInt32 = 1, urlOK: UInt32 = 1, padded: UInt32 = 0
    var stdLast: UInt32 = 0, stdPrev: UInt32 = 0, urlLast: UInt32 = 0, urlPrev: UInt32 = 0
    for offset in 0..<bytes.count {
        let i = UInt32(offset)
        let c = UInt32(bytes[base + offset])
        let outside = (ctInRange(i, start, end) & seen) ^ 1
        let isEnd = ctEq(i, end)
        let isPrev = ctEq(i &+ 1, end)
        let pad = isEnd & ctEq(c, 0x3D) // '='
        let std = ctBase64(c, 0x2B, 0x2F) // + /
        let url = ctBase64(c, 0x2D, 0x5F) // - _
        hexOK &= ctIsHex(c) | outside
        stdOK &= std.member | pad | outside
        urlOK &= url.member | pad | outside
        padded |= pad
        stdLast = ctSelect(isEnd, std.value, stdLast)
        stdPrev = ctSelect(isPrev, std.value, stdPrev)
        urlLast = ctSelect(isEnd, url.value, urlLast)
        urlPrev = ctSelect(isPrev, url.value, urlPrev)
    }

    // 43 data characters carry 258 bits: the last one's low 2 must be 0.
    let shape = (ctEq(textLength, 43) & (padded ^ 1)) | (ctEq(textLength, 44) & padded)
    let stdCanonical = ctEq(ctSelect(padded, stdPrev, stdLast) & 3, 0)
    let urlCanonical = ctEq(ctSelect(padded, urlPrev, urlLast) & 3, 0)
    let hex = hexOK & ctEq(textLength, UInt32(hkdfguardDekLength * 2))
    let base64 = shape & ((stdOK & stdCanonical) | (urlOK & urlCanonical))
    return seen & (hex | base64) == 1
}

/// Reads the wrapped payload stored at `path` — the 125-byte file the CLI's
/// `wrap` writes — validates it, and copies it to `out`, ready for
/// `hkdfguard_unwrap_dek`. Never touches the keychain or the Secure
/// Enclave, and never unwraps anything.
///
/// `*outLen` is the capacity on entry. It is written only with 125: on
/// success, and on `outputBufferTooSmall` (the required size, reported
/// before the file is opened). Every other failure leaves it as the caller
/// set it, as on Linux and as wrap and unwrap do. File contents are
/// copied to `out` only on success, so a rejected file — in particular one
/// holding a plaintext DEK — never reaches the caller's buffer; on any
/// failure every byte of the declared capacity is zeroed instead, as on
/// Linux (see `zeroingOutOnFailure`).
@_cdecl("hkdfguard_open_file")
public func hkdfguard_open_file(
    pathPtr: UnsafePointer<CChar>?,
    outPtr: UnsafeMutablePointer<UInt8>?,
    outLen: UnsafeMutablePointer<Int32>?
) -> Int32 {
    let status = zeroingOutOnFailure(outPtr, outLen) {
        openFileCore(pathPtr: pathPtr, outPtr: outPtr, outLen: outLen)
    }
    if status == HKDFGuardStatus.fileUnprotectedKey.rawValue, let pathPtr {
        let length = strnlen(pathPtr, Int(PATH_MAX))
        auditPlaintextKeyFile(path: pathPtr.withMemoryRebound(to: UInt8.self, capacity: length) { Array(UnsafeBufferPointer(start: $0, count: length)) })
    }
    return status
}

private func openFileCore(
    pathPtr: UnsafePointer<CChar>?,
    outPtr: UnsafeMutablePointer<UInt8>?,
    outLen: UnsafeMutablePointer<Int32>?
) -> Int32 {
    // Argument checks in Linux's open_file_impl order, before the file is
    // opened. As on Linux (and as wrap and unwrap do), `*out_len` is written
    // only on success (125) and on buffer-too-small (the size to retry
    // with); every other failure leaves it as the caller set it.
    guard let outLen else {
        return HKDFGuardStatus.invalidInputLength.rawValue
    }
    let capacity = outLen.pointee
    guard capacity >= 0 else {
        return HKDFGuardStatus.invalidInputLength.rawValue
    }
    guard let pathPtr, pathPtr.pointee != 0 else {
        return HKDFGuardStatus.invalidInputLength.rawValue
    }
    // The terminator is looked for in at most PATH_MAX bytes, as on Linux
    // (cstr_to_path): no NUL in that range -- an unterminated buffer, or a
    // path no open could take -- is an argument error, and nothing past it
    // is ever read.
    let pathLength = strnlen(pathPtr, Int(PATH_MAX))
    guard pathLength < Int(PATH_MAX) else {
        return HKDFGuardStatus.invalidInputLength.rawValue
    }
    // Too small for a payload -- including the 0 of a size probe, which may
    // pass a NULL `out`: answered without opening the file.
    guard Int(capacity) >= hkdfguardWrappedLength else {
        outLen.pointee = Int32(hkdfguardWrappedLength)
        return HKDFGuardStatus.outputBufferTooSmall.rawValue
    }
    guard let outPtr else {
        return HKDFGuardStatus.invalidInputLength.rawValue // a declared capacity with nowhere to write
    }

    // One byte more than a payload, so a file that grew past the fstat
    // check is still seen as too long without reading the rest of it. Zeroed
    // on every exit: a rejected file may have been a plaintext key.
    var buffer = [UInt8](repeating: 0, count: hkdfguardWrappedLength + 1)
    defer { secureZero(&buffer) }

    let (readStatus, count) = readWrappedFile(path: pathPtr, length: pathLength, into: &buffer)
    guard readStatus == .success else {
        return readStatus.rawValue
    }

    guard count <= hkdfguardWrappedLength else {
        return HKDFGuardStatus.fileTooLong.rawValue
    }
    guard count == hkdfguardWrappedLength else {
        // A plaintext DEK is always shorter than a payload; naming it
        // matters more than "too short", because the key is now exposed.
        return looksLikePlaintextDek(buffer[0..<count])
            ? HKDFGuardStatus.fileUnprotectedKey.rawValue
            : HKDFGuardStatus.fileTooShort.rawValue
    }

    // Structural checks only -- authenticity is the AEAD's job at unwrap.
    // A SHA-256 fingerprint of all zeros does not occur in practice (checked
    // first), and the suite byte must be one this build implements. Either
    // failure is `fileMalformed`, as Linux and Windows report every format
    // problem in a key file; unwrap, given the same bytes, still names an
    // unknown suite specifically (-12). The salt, nonce and ciphertext are
    // random-looking by design; nothing more can be checked without the KEK.
    let fingerprint = buffer[0..<hkdfguardFingerprintLength]
    guard fingerprint.contains(where: { $0 != 0 }) else {
        return HKDFGuardStatus.fileMalformed.rawValue
    }
    guard buffer[hkdfguardSuiteIdOffset] == hkdfguardSuiteId else {
        return HKDFGuardStatus.fileMalformed.rawValue
    }

    guard copyOut(buffer, to: outPtr, count: hkdfguardWrappedLength) else {
        return HKDFGuardStatus.unexpectedOutputLength.rawValue
    }
    outLen.pointee = Int32(hkdfguardWrappedLength)
    return HKDFGuardStatus.success.rawValue
}
