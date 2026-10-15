import Foundation
import CryptoKit
import Security
import os // Logger: hkdfguard_harden_process's advisory signature warning

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

/// The HPKE (RFC 9180) ciphersuite every payload is sealed with, and the one
/// byte that names it in the payload: DHKEM(P-256, HKDF-SHA256),
/// HKDF-SHA256, AES-256-GCM, base mode. The byte is the hook for a future
/// suite (a post-quantum hybrid KEM, say) to be recognised at parse time
/// rather than by a new file format; this build implements exactly one.
private let hkdfguardCiphersuite = HPKE.Ciphersuite.P256_SHA256_AES_GCM_256
private let hkdfguardSuiteId: UInt8 = 0x01
private let hkdfguardSuiteIdLength = 1

/// Length of the suite's encapsulated key: an uncompressed X9.63 P-256
/// point, 0x04 || x || y.
private let hkdfguardEncapsulatedKeyLength = 65

/// AES-GCM tag length, as fixed by the suite's AEAD. HPKE derives the nonce
/// from the key schedule, so none is stored.
private let hkdfguardGCMTagLength = 16

/// The exact length of every wrapped payload:
///   fingerprint || suite id || encapsulated key || ciphertext (DEK length) || tag
/// = 32 + 1 + 65 + 32 + 16 = 146 bytes. Known up front, so both wrap and
/// unwrap can reject a wrong-sized buffer before any keychain or Secure
/// Enclave work.
private let hkdfguardWrappedLength =
    hkdfguardFingerprintLength + hkdfguardSuiteIdLength + hkdfguardEncapsulatedKeyLength
    + hkdfguardDekLength + hkdfguardGCMTagLength

/// Offsets of each field within a payload.
private let hkdfguardSuiteIdOffset = hkdfguardFingerprintLength
private let hkdfguardEncapsulatedKeyOffset = hkdfguardSuiteIdOffset + hkdfguardSuiteIdLength
private let hkdfguardCiphertextOffset = hkdfguardEncapsulatedKeyOffset + hkdfguardEncapsulatedKeyLength
private let hkdfguardCiphertextLength = hkdfguardDekLength + hkdfguardGCMTagLength

/// Label at the front of the HPKE `info` string, binding every derived key
/// to this scheme so it can never be reused as a key for anything else.
/// Platform-neutral on purpose: the sibling Linux and Windows libraries
/// share this payload format, so they must derive with the same `info`.
private let hkdfguardInfoLabel = Data("com.hkdfguard.hpke.v1".utf8)

/// The HPKE `info` for `service`: label || 0x00 || service. Folded into the
/// key schedule, so a payload sealed for one service cannot be opened under
/// another even when (by misuse) both resolve to the same KEK. The service
/// is validated ASCII (letters, digits, '.') before it gets here, so the
/// 0x00 separator is unambiguous.
private func hpkeInfo(service: String) -> Data {
    var info = hkdfguardInfoLabel
    info.append(0)
    info.append(contentsOf: service.utf8)
    return info
}

/// The AEAD's additional authenticated data: the payload's own header,
/// fingerprint || suite id -- every byte that precedes the encapsulated key.
/// The tag therefore covers the suite byte the parser dispatches on as well
/// as the fingerprint, so neither can be rewritten without failing the open.
private func hpkeAAD(fingerprint: Data) -> Data {
    var aad = fingerprint
    aad.append(hkdfguardSuiteId)
    return aad
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
private enum HKDFGuardStatus: Int32 {
    /// HKDFGUARD_OK
    case success = 0
    /// HKDFGUARD_ERR_INVALID_ARGUMENT: a NULL pointer, a DEK that isn't 32
    /// bytes, or an empty `path`.
    case invalidInputLength = -1
    /// HKDFGUARD_ERR_BUFFER_TOO_SMALL
    case outputBufferTooSmall = -2
    /// HKDFGUARD_ERR_PROVIDER_UNAVAILABLE: no Secure Enclave on this machine.
    case enclaveUnavailable = -3
    /// HKDFGUARD_ERR_CRYPTO_ERROR: the RNG or HPKE sealing failed.
    case encryptionFailed = -5
    /// HKDFGUARD_ERR_INTERNAL_ERROR: the library produced output of a length
    /// it never should. Points at a bug here, not at the caller's input.
    case unexpectedOutputLength = -6
    /// HKDFGUARD_ERR_INVALID_SERVICE_NAME
    case invalidServiceIdentifier = -8

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
    /// hkdfguard_unwrap_dek and hkdfguard_open_file before any keychain or
    /// Secure Enclave work.
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
    /// (`errSecMissingEntitlement`). Deliberately distinct from
    /// `kekNotFound`/`kekCorrupted`: a key very likely *does* exist, and
    /// treating this as "no key" or "corrupt key" would invite a caller to
    /// create a replacement or an operator to delete a healthy one.
    case keychainAccessDenied = -18

    /// HKDFGUARD_ERR_KEK_INVALID: a keychain item exists under this service,
    /// but its stored data representation could not be reconstructed into a
    /// usable Secure Enclave key — a corrupt or foreign entry. Deliberately
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

    /// HKDFGUARD_ERR_FILE_IO: the path names a symbolic link, directory,
    /// FIFO, socket, or device rather than a regular file, or `open`,
    /// `fstat`, or `read` failed for any other reason. A symlink is refused
    /// rather than followed (`O_NOFOLLOW`), and a FIFO is opened non-blocking
    /// so it can't hang the caller.
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
    /// payload: its encapsulated key is not a valid P-256 point, or its KEK
    /// fingerprint is all zeros.
    case fileMalformed = -38

    /// HKDFGUARD_ERR_FILE_UNTRUSTED: the file is owned by someone other than
    /// this process's effective user or root, is writable by group or
    /// others, or has more than one hard link — so a party other than its
    /// owner could have replaced its contents or linked an older payload
    /// into its place. Root is accepted so an administrator or MDM can
    /// deploy key files a service account reads; root can already alter
    /// anything on the machine, so this adds no new party who could tamper
    /// with the file. The CLI's `wrap` writes owner-only, 0600, one link,
    /// which always passes.
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
/// the keychain query/store calls use, and the HPKE `info` is built from. Returns `nil` when the name is invalid — the
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

/// Reconstructs a Secure Enclave key from a keychain item's stored data.
/// `nil` means the item is present but is not (or is no longer) a usable
/// key for this device — `HKDFGuardStatus.kekCorrupted`.
private func reconstructKEK(_ data: Data) -> SecureEnclave.P256.KeyAgreement.PrivateKey? {
    try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: data)
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

    switch loadKEKDataRepresentation(service: service, mode: mode) {
    case .notFound:
        return (HKDFGuardStatus.success.rawValue, false)
    case .accessDenied:
        return (HKDFGuardStatus.keychainAccessDenied.rawValue, false)
    case .failed:
        return (HKDFGuardStatus.keychainReadFailed.rawValue, false)
    case .found(let existing):
        guard reconstructKEK(existing) != nil else {
            return (HKDFGuardStatus.kekCorrupted.rawValue, false)
        }
        return (HKDFGuardStatus.success.rawValue, true)
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

    // Existing key? Only a definite "not found" may proceed to create one:
    // a denied or failed lookup means a key may already exist that this
    // process simply can't see, and generating a replacement on top of it
    // would orphan whatever that key protects.
    switch loadKEKDataRepresentation(service: service, mode: mode) {
    case .found(let existing):
        guard reconstructKEK(existing) != nil else {
            // Item exists but cannot be reconstructed.
            // Do NOT generate a replacement key.
            return HKDFGuardStatus.kekCorrupted.rawValue
        }
        return HKDFGuardStatus.success.rawValue
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
        case .found(let stored) where reconstructKEK(stored) != nil:
            return HKDFGuardStatus.success.rawValue
        case .accessDenied:
            return HKDFGuardStatus.keychainAccessDenied.rawValue
        case .found, .notFound, .failed:
            return HKDFGuardStatus.kekVerificationFailed.rawValue
        }

    case errSecDuplicateItem:

        // Another thread/process won the race. Validate the winner's key
        // before declaring success. If the winner was a differently-signed
        // process, its item's ACL may deny this one — that is
        // keychainAccessDenied, not a corrupt item.
        switch loadKEKDataRepresentation(service: service, mode: mode) {
        case .found(let existing):
            guard reconstructKEK(existing) != nil else {
                return HKDFGuardStatus.kekCorrupted.rawValue
            }
            return HKDFGuardStatus.success.rawValue
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

    switch loadKEKDataRepresentation(service: service, mode: mode) {
    case .notFound:
        return (HKDFGuardStatus.kekNotFound.rawValue, nil)
    case .accessDenied:
        return (HKDFGuardStatus.keychainAccessDenied.rawValue, nil)
    case .failed:
        return (HKDFGuardStatus.keychainReadFailed.rawValue, nil)
    case .found(let existing):
        guard let key = reconstructKEK(existing) else {
            return (HKDFGuardStatus.kekCorrupted.rawValue, nil)
        }
        return (HKDFGuardStatus.success.rawValue, key)
    }
}

/// Computes the "fingerprint" embedded at the front of every wrapped
/// payload: a SHA-256 hash of the KEK's public key raw representation.
/// Not a secret value — the public key it hashes isn't secret either —
/// so the explicit equality check against it in `hkdfguard_unwrap_dek`
/// exists purely to fail fast, cheaply, on "this payload wasn't wrapped
/// under the KEK I just resolved for this service" *before* spending any
/// effort on ECDH/AES-GCM. It is also folded into the AES-GCM AAD (see
/// `wrapDekCore`/`hkdfguard_unwrap_dek`) alongside `service`, so the tag
/// itself authenticates it too.
private func kekFingerprint(publicKeyRaw: Data) -> Data {
    Data(SHA256.hash(data: publicKeyRaw))
}

// MARK: - Wrap (seal) a DEK under the Secure Enclave KEK
//
// Wrapped format: [KEK fingerprint, 32-byte SHA-256 of the KEK's public key]
//                  [suite id, 1 byte: 0x01]
//                  [HPKE encapsulated key, 65 bytes: X9.63 P-256 point]
//                  [AES-256-GCM ciphertext || 16-byte tag, 48 bytes]
//
// Sealing is HPKE (RFC 9180) in base mode, one message per context: CryptoKit
// generates the ephemeral key pair, runs the key schedule (DHKEM(P-256),
// HKDF-SHA256) and the AEAD, and derives the nonce, so this file holds no
// KDF or nonce handling of its own. `info` binds the scheme label and the
// service; the payload header (fingerprint || suite id) is the AEAD's
// additional authenticated data.
// Base mode authenticates nothing about the sender: anyone holding the KEK's
// public key can produce a valid payload (see "Sender authentication" in the
// README for the Auth-mode design that would change that).
//
// The fingerprint identifies *which* KEK this payload was wrapped under —
// checked against the current KEK's own public key by hkdfguard_unwrap_dek
// before any key agreement is attempted (see `kekFingerprint`), and covered
// by the AEAD tag too, so tampering with it fails both checks independently.

/// `@_cdecl` entry points below.
private func wrapDekCore(
    service: String,
    dekPtr: UnsafePointer<UInt8>,
    dekLen: Int32,
    outPtr: UnsafeMutablePointer<UInt8>,
    outLen: UnsafeMutablePointer<Int32>
) -> Int32 {
    guard dekLen == Int32(hkdfguardDekLength) else {
        return HKDFGuardStatus.invalidInputLength.rawValue
    }

    // The output size is a constant, so a too-small buffer is reported here
    // -- before any keychain lookup or Secure Enclave operation, and without
    // ever producing a ciphertext the caller cannot receive.
    guard Int(outLen.pointee) >= hkdfguardWrappedLength else {
        outLen.pointee = Int32(hkdfguardWrappedLength)
        return HKDFGuardStatus.outputBufferTooSmall.rawValue
    }

    let (getStatus, maybeEnclaveKey) = getKEK(service: service)
    guard let enclaveKey = maybeEnclaveKey else {
        return getStatus
    }

    let fingerprint = kekFingerprint(publicKeyRaw: enclaveKey.publicKey.rawRepresentation)

    let encapsulated: Data
    let ciphertext: Data
    do {
        var sender = try HPKE.Sender(
            recipientKey: enclaveKey.publicKey,
            ciphersuite: hkdfguardCiphersuite,
            info: hpkeInfo(service: service)
        )
        ciphertext = try sender.seal(
            UnsafeRawBufferPointer(start: dekPtr, count: Int(dekLen)),
            authenticating: hpkeAAD(fingerprint: fingerprint)
        )
        encapsulated = sender.encapsulatedKey
    } catch {
        return HKDFGuardStatus.encryptionFailed.rawValue
    }

    guard encapsulated.count == hkdfguardEncapsulatedKeyLength,
          ciphertext.count == hkdfguardCiphertextLength else {
        return HKDFGuardStatus.unexpectedOutputLength.rawValue
    }

    var payload = Data(capacity: hkdfguardWrappedLength)
    payload.append(fingerprint)
    payload.append(hkdfguardSuiteId)
    payload.append(encapsulated)
    payload.append(ciphertext)
    guard payload.count == hkdfguardWrappedLength else {
        return HKDFGuardStatus.unexpectedOutputLength.rawValue
    }

    _ = payload.withUnsafeBytes { raw in
        memcpy(outPtr, raw.baseAddress!, payload.count)
    }
    outLen.pointee = Int32(payload.count)

    return HKDFGuardStatus.success.rawValue
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

/// Reports whether a Secure Enclave KEK already exists for `service`,
/// without creating one — `*outExists` is always written, on every return
/// path (1 if a valid KEK exists, 0 otherwise, including when the status
/// isn't `success`, in which case existence couldn't be determined), so
/// the caller's variable is never left in an undefined state.
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

    let (status, exists) = kekExists(service: service)
    outExists.pointee = exists ? 1 : 0
    return status
}

/// Writes the 32-byte fingerprint (SHA-256 of the public key) of the KEK
/// `service` currently resolves to -- the same value embedded at the front
/// of every payload wrapped under it. Public-key material only, so safe to
/// expose; lets an operator pin which KEK a service uses and confirm it
/// before retiring it. Never creates a KEK.
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

    let (status, maybeKey) = getKEK(service: service)
    guard let key = maybeKey else {
        return status
    }

    let fingerprint = kekFingerprint(publicKeyRaw: key.publicKey.rawRepresentation)
    _ = fingerprint.withUnsafeBytes { raw in
        memcpy(outPtr, raw.baseAddress!, fingerprint.count)
    }
    outLen.pointee = Int32(fingerprint.count)
    return HKDFGuardStatus.success.rawValue
}

/// Creates a Secure Enclave KEK for `service` if one doesn't already
/// exist. Paired with `hkdfguard_kek_exists` above so a caller can decide
/// for itself whether creation is needed — e.g. prompting for user
/// consent, or provisioning on a schedule — rather than have that decision
/// made implicitly inside a single combined "ensure" call.
@_cdecl("hkdfguard_create_kek")
public func hkdfguard_create_kek(
    servicePtr: UnsafePointer<CChar>?
) -> Int32 {
    guard let servicePtr, let service = normalizedService(from: servicePtr) else {
        return HKDFGuardStatus.invalidServiceIdentifier.rawValue
    }

    return createKEK(service: service)
}

@_cdecl("hkdfguard_wrap_dek")
public func hkdfguard_wrap_dek(
    servicePtr: UnsafePointer<CChar>?,
    dekPtr: UnsafePointer<UInt8>?,
    dekLen: Int32,
    outPtr: UnsafeMutablePointer<UInt8>?,
    outLen: UnsafeMutablePointer<Int32>?
) -> Int32 {
    guard let dekPtr, let outPtr, let outLen else {
        return HKDFGuardStatus.invalidInputLength.rawValue
    }
    guard let servicePtr, let service = normalizedService(from: servicePtr) else {
        return HKDFGuardStatus.invalidServiceIdentifier.rawValue
    }

    return wrapDekCore(service: service, dekPtr: dekPtr, dekLen: dekLen, outPtr: outPtr, outLen: outLen)
}

// MARK: - Generate a new random DEK and wrap it, in one call

private func generateRandomDek() -> Data? {
    var bytes = Data(count: hkdfguardDekLength)
    let status = bytes.withUnsafeMutableBytes { raw in
        SecRandomCopyBytes(kSecRandomDefault, hkdfguardDekLength, raw.baseAddress!)
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
    guard let outPtr, let outLen else {
        return HKDFGuardStatus.invalidInputLength.rawValue
    }
    guard let servicePtr, let service = normalizedService(from: servicePtr) else {
        return HKDFGuardStatus.invalidServiceIdentifier.rawValue
    }
    
    guard var dek = generateRandomDek() else {
        return HKDFGuardStatus.encryptionFailed.rawValue
    }

    defer { secureZero(&dek) }

    return dek.withUnsafeBytes { raw -> Int32 in
        wrapDekCore(
            service: service,
            dekPtr: raw.bindMemory(to: UInt8.self).baseAddress!,
            dekLen: Int32(dek.count),
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
    zeroingOutOnFailure(outPtr, outLen) {
        unwrapDekCore(servicePtr: servicePtr, wrappedPtr: wrappedPtr, wrappedLen: wrappedLen, outPtr: outPtr, outLen: outLen)
    }
}

private func unwrapDekCore(
    servicePtr: UnsafePointer<CChar>?,
    wrappedPtr: UnsafePointer<UInt8>?,
    wrappedLen: Int32,
    outPtr: UnsafeMutablePointer<UInt8>?,
    outLen: UnsafeMutablePointer<Int32>?
) -> Int32 {
    guard let wrappedPtr, let outPtr, let outLen else {
        return HKDFGuardStatus.invalidInputLength.rawValue
    }

    // The plaintext size is a constant: a too-small buffer is reported
    // before the payload is even looked at, and so before any keychain
    // lookup or Secure Enclave operation -- a DEK is never decrypted into
    // memory for a caller who cannot receive it.
    guard Int(outLen.pointee) >= hkdfguardDekLength else {
        outLen.pointee = Int32(hkdfguardDekLength)
        return HKDFGuardStatus.outputBufferTooSmall.rawValue
    }

    // Every payload this library produces is exactly hkdfguardWrappedLength
    // bytes, so anything else is malformed and rejected before it is read.
    guard wrappedLen == Int32(hkdfguardWrappedLength) else {
        return HKDFGuardStatus.payloadMalformed.rawValue
    }

    guard let servicePtr, let service = normalizedService(from: servicePtr) else {
        return HKDFGuardStatus.invalidServiceIdentifier.rawValue
    }

    let storedFingerprint = Data(bytes: wrappedPtr, count: hkdfguardFingerprintLength)
    let suiteId = wrappedPtr[hkdfguardSuiteIdOffset]
    let encapsulated = Data(bytes: wrappedPtr + hkdfguardEncapsulatedKeyOffset, count: hkdfguardEncapsulatedKeyLength)
    let ciphertext = Data(bytes: wrappedPtr + hkdfguardCiphertextOffset, count: hkdfguardCiphertextLength)

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
        let currentFingerprint = kekFingerprint(publicKeyRaw: enclaveKey.publicKey.rawRepresentation)
        guard currentFingerprint == storedFingerprint else {
            return HKDFGuardStatus.fingerprintMismatch.rawValue
        }

        // HPKE base mode: the Secure Enclave performs its half of the key
        // agreement inside Recipient.init; the key schedule and AEAD open
        // follow. Any failure -- an encapsulated key that is not a point on
        // the curve, a locked enclave, a tag that does not verify -- is one
        // outcome: the payload cannot be opened under this KEK.
        do {
            var recipient = try HPKE.Recipient(
                privateKey: enclaveKey,
                ciphersuite: hkdfguardCiphersuite,
                info: hpkeInfo(service: service),
                encapsulatedKey: encapsulated
            )
            plaintext = try recipient.open(ciphertext, authenticating: hpkeAAD(fingerprint: currentFingerprint))
        } catch {
            return HKDFGuardStatus.decryptionFailed.rawValue
        }
    }

    defer { secureZero(&plaintext) }

    guard plaintext.count == hkdfguardDekLength else {
        return HKDFGuardStatus.unexpectedOutputLength.rawValue
    }

    let capacity = Int(outLen.pointee)
    guard capacity >= plaintext.count else {
        outLen.pointee = Int32(plaintext.count)
        return HKDFGuardStatus.outputBufferTooSmall.rawValue
    }

    _ = plaintext.withUnsafeBytes { raw in
        memcpy(outPtr, raw.baseAddress!, plaintext.count)
    }
    outLen.pointee = Int32(plaintext.count)

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
    default:
        // Including ELOOP (O_NOFOLLOW found a symbolic link as the final
        // component, or the path loops) and EOPNOTSUPP (the path names a
        // socket): HKDFGUARD_ERR_FILE_IO covers "not a regular file" and
        // "could not be read" alike.
        return .fileIO
    }
}

/// Reads at most `buffer.count` bytes of the regular file at `path` into
/// `buffer`, returning how many were read. A file whose size already
/// exceeds a wrapped payload is rejected from `fstat` alone, before any
/// read. The caller zeroes `buffer`, which may end up holding a plaintext
/// DEK.
private func readWrappedFile(
    path: UnsafePointer<CChar>,
    into buffer: inout [UInt8]
) -> (status: HKDFGuardStatus, count: Int) {
    // O_NOFOLLOW: a symlink as the final component is refused, not followed
    // (symlinks in directory components still resolve, so /etc and /tmp --
    // themselves symlinks into /private -- work). O_NONBLOCK: a FIFO with
    // no writer would otherwise block here; it has no effect on the regular
    // files actually accepted. O_CLOEXEC: never inherited by a child.
    var fd: Int32
    repeat {
        fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
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
    // Same rules the CLI's `wrap` writes to (0600, one link) and the
    // install scripts apply to the library itself: nobody but the owner can
    // have put these bytes here, and the owner is either this user or root
    // (an admin- or MDM-deployed file; root can alter anything anyway). A
    // file linked in from elsewhere (st_nlink > 1) could be an older payload
    // replayed.
    guard info.st_uid == geteuid() || info.st_uid == 0,
          info.st_mode & (S_IWGRP | S_IWOTH) == 0,
          info.st_nlink == 1 else {
        return (.fileInsecure, 0)
    }
    guard info.st_size <= off_t(hkdfguardWrappedLength) else {
        return (.fileTooLong, 0)
    }

    // Read until EOF or the buffer is full, whatever fstat said: the file
    // may change between the two, and the bytes actually read decide.
    var count = 0
    let status: HKDFGuardStatus = buffer.withUnsafeMutableBytes { raw in
        while count < raw.count {
            let n = read(fd, raw.baseAddress! + count, raw.count - count)
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

/// True when `bytes` look like a bare 32-byte DEK rather than a wrapped
/// payload: exactly 32 raw bytes, or — ignoring surrounding ASCII
/// whitespace, as the CLI's `--dek-file` accepts — the 44-character padded
/// or 43-character unpadded base64 (standard or URL alphabet), or the
/// 64-character hex, encoding of 32 bytes. Checked on length and alphabet
/// only, so nothing is decoded and no further copy of a key is made.
private func looksLikePlaintextDek(_ bytes: ArraySlice<UInt8>) -> Bool {
    if bytes.count == hkdfguardDekLength {
        return true
    }

    func isWhitespace(_ byte: UInt8) -> Bool {
        byte == 0x20 || byte == 0x09 || byte == 0x0A || byte == 0x0D
    }
    func isHex(_ byte: UInt8) -> Bool {
        (0x30...0x39).contains(byte) || (0x41...0x46).contains(byte) || (0x61...0x66).contains(byte)
    }
    func isBase64(_ byte: UInt8) -> Bool {
        (0x30...0x39).contains(byte) || (0x41...0x5A).contains(byte) || (0x61...0x7A).contains(byte)
            || byte == 0x2B || byte == 0x2F || byte == 0x2D || byte == 0x5F // + / - _
    }

    guard let first = bytes.firstIndex(where: { !isWhitespace($0) }),
          let last = bytes.lastIndex(where: { !isWhitespace($0) }) else {
        return false
    }
    let text = bytes[first...last]

    switch text.count {
    case hkdfguardDekLength * 2:
        return text.allSatisfy(isHex)
    case 44:
        return text.last == 0x3D && text.dropLast().allSatisfy(isBase64) // trailing '='
    case 43:
        return text.allSatisfy(isBase64)
    default:
        return false
    }
}

/// Reads the wrapped payload stored at `path` — the 146-byte file the CLI's
/// `wrap` writes — validates it, and copies it to `out`, ready for
/// `hkdfguard_unwrap_dek`. Never touches the keychain or the Secure
/// Enclave, and never unwraps anything.
///
/// `*outLen` is the capacity on entry and is written on every return path:
/// 146 on success or `outputBufferTooSmall` (the required size, reported
/// before the file is opened), 0 on every other failure. File contents are
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
    zeroingOutOnFailure(outPtr, outLen) {
        openFileCore(pathPtr: pathPtr, outPtr: outPtr, outLen: outLen)
    }
}

private func openFileCore(
    pathPtr: UnsafePointer<CChar>?,
    outPtr: UnsafeMutablePointer<UInt8>?,
    outLen: UnsafeMutablePointer<Int32>?
) -> Int32 {
    guard let outPtr, let outLen else {
        return HKDFGuardStatus.invalidInputLength.rawValue
    }
    guard Int(outLen.pointee) >= hkdfguardWrappedLength else {
        outLen.pointee = Int32(hkdfguardWrappedLength)
        return HKDFGuardStatus.outputBufferTooSmall.rawValue
    }
    outLen.pointee = 0
    guard let pathPtr, pathPtr.pointee != 0 else {
        return HKDFGuardStatus.invalidInputLength.rawValue
    }

    // One byte more than a payload, so a file that grew past the fstat
    // check is still seen as too long without reading the rest of it. Zeroed
    // on every exit: a rejected file may have been a plaintext key.
    var buffer = [UInt8](repeating: 0, count: hkdfguardWrappedLength + 1)
    defer { secureZero(&buffer) }

    let (readStatus, count) = readWrappedFile(path: pathPtr, into: &buffer)
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
    // first, so an all-zero file is "malformed", not "newer suite"); the
    // suite byte must be one this build implements; and the encapsulated
    // key must be a point on P-256 (checked in its X9.63 form, which
    // CryptoKit validates -- `PublicKey(rawRepresentation:)` would accept
    // any 64 bytes) for any unwrap to succeed.
    let fingerprint = buffer[0..<hkdfguardFingerprintLength]
    guard fingerprint.contains(where: { $0 != 0 }) else {
        return HKDFGuardStatus.fileMalformed.rawValue
    }
    guard buffer[hkdfguardSuiteIdOffset] == hkdfguardSuiteId else {
        return HKDFGuardStatus.unsupportedCiphersuite.rawValue
    }
    let encapsulated = buffer[hkdfguardEncapsulatedKeyOffset..<hkdfguardCiphertextOffset]
    guard (try? P256.KeyAgreement.PublicKey(x963Representation: encapsulated)) != nil else {
        return HKDFGuardStatus.fileMalformed.rawValue
    }

    buffer.withUnsafeBytes { raw in
        _ = memcpy(outPtr, raw.baseAddress!, hkdfguardWrappedLength)
    }
    outLen.pointee = Int32(hkdfguardWrappedLength)
    return HKDFGuardStatus.success.rawValue
}
