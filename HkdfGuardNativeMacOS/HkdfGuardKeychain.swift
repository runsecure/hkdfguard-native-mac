//
//  HkdfGuardKeychain.swift
//  HkdfGuardNativeMacOS
//
//  User-scoped KEKs: the keychain mode, the keychain item and its format,
//  service names, and looking up, reconstructing and creating a KEK.
//

import Foundation
import CryptoKit
import Security
import os

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
/// rather than bytes. The C header, the CLI, all promise (and enforce) ASCII bytes, so this must too.
/// A `switch`, not a chain of `||`: older Swift 6.2 type checkers (Xcode
/// 26.3) give up on a long chain of literal comparisons.
private func isValidServiceByte(_ byte: UInt8) -> Bool {
    switch byte {
    case 0x30...0x39, // '0'-'9'
         0x41...0x5A, // 'A'-'Z'
         0x61...0x7A, // 'a'-'z'
         0x2E:        // '.'
        return true
    default:
        return false
    }
}

/// The shared HkdfGuard service-name rule : 1-128 bytes, ASCII letters,
/// digits, and '.' only, not starting with '.', and with no two consecutive
/// dots. So a name can never be ".", "..", or a hidden dot-name, and never
/// has an empty label between dots -- the same names are valid on every
/// platform.
func validServiceName(service: String) -> Bool {
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
/// The terminator is looked for in at most 129 bytes (`strnlen`)
/// rather than with `String(cString:)`, which reads until it finds a
/// NUL however far away: an unterminated or over-long string is rejected
/// without reading past the longest name that could be valid.
func normalizedService(from servicePtr: UnsafePointer<CChar>) -> String? {
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

private let keychainLog = Logger(subsystem: "com.hkdfguard", category: "keychain")

/// Looks up the persisted Secure Enclave key's opaque data representation
/// in the keychain, under the caller-supplied service identifier.
private func loadKEKDataRepresentation(service: String, mode: KeychainMode) -> KEKLookup {
    // In legacy mode the search list spans more than one keychain (login
    // and System, plus any the user added), so the same service can have a
    // KEK item in each, and a first-match lookup would quietly take
    // whichever comes first. More than one is refused instead: nothing
    // says which is the service's KEK. (The data-protection keychain holds
    // at most one item per service and account.)
    if case .legacy = mode {
        var count = keychainItemAttributes(service: service, mode: mode)
        count[kSecMatchLimit as String] = kSecMatchLimitAll
        count[kSecReturnPersistentRef as String] = true
        var found: CFTypeRef?
        if SecItemCopyMatching(count as CFDictionary, &found) == errSecSuccess,
           let refs = found as? [Data], refs.count > 1 {
            keychainLog.error("\(service, privacy: .public): \(refs.count) keychains in the search list hold a KEK item for this service; refusing to choose one. Remove the stray ones (`security find-generic-password -s \(service, privacy: .public) -a \(hkdfguardKeychainAccount, privacy: .public)` shows each)")
            return .failed(errSecDuplicateItem)
        }
    }
    var query = keychainItemAttributes(service: service, mode: mode)
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne

    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    switch status {
    case errSecSuccess:
        guard let data = takeKeychainSecret(item) else { return .failed(errSecInternalError) }
        return .found(data)
    case errSecItemNotFound:
        return .notFound
    case errSecInteractionNotAllowed, errSecAuthFailed, errSecUserCanceled, errSecMissingEntitlement:
        return .accessDenied
    default:
        return .failed(status)
    }
}

/// Moves the bytes of a keychain result out of the object the keychain
/// returned and into memory this library owns, or returns nil if the result
/// is not data.
///
/// Casting the result to `Data` instead only wraps the keychain's object: a
/// later `secureZero` then wipes a private copy (copy-on-write) and the
/// object keeps the blob until it is freed, unzeroed. So the bytes are
/// copied out, the keychain's object is zeroed in place, and the copy is
/// zeroed when its last reference goes -- however many `Data` values came
/// to share it on the way. Copies made inside the Security framework before
/// it returned are out of reach.
func takeKeychainSecret(_ item: CFTypeRef?) -> Data? {
    guard let item, CFGetTypeID(item) == CFDataGetTypeID() else { return nil }
    let keychainData = unsafeBitCast(item, to: CFData.self)
    let count = CFDataGetLength(keychainData)
    guard count > 0, let source = CFDataGetBytePtr(keychainData) else { return Data() }
    let copy = UnsafeMutableRawPointer.allocate(byteCount: count, alignment: MemoryLayout<UInt>.alignment)
    copy.copyMemory(from: source, byteCount: count)
    _ = memset_s(UnsafeMutableRawPointer(mutating: source), count, 0, count)
    return Data(bytesNoCopy: copy, count: count, deallocator: .custom { pointer, length in
        _ = memset_s(pointer, length, 0, length)
        pointer.deallocate()
    })
}

/// A KEK as stored: its Secure Enclave blob, plus, for suite 0x02, the
/// ciphertext encapsulated to it at provisioning and its P-256 key's blob
/// (see `KEMKEK`).
enum StoredKEK: Equatable {
    case p256(blob: Data)
    case mlkem1024(blob: Data, encapsulated: Data, classicalBlob: Data)

    /// Zeroes the enclave blobs: they are the credential.
    mutating func zeroBlobs() {
        switch self {
        // `self` is emptied first in each case: until then it still refers
        // to the same bytes as the bindings, and zeroing through a shared
        // reference wipes a private copy instead (copy-on-write).
        case .p256(var blob):
            self = .p256(blob: Data())
            secureZero(&blob)
            self = .p256(blob: blob)
        case .mlkem1024(var blob, let encapsulated, var classicalBlob):
            self = .p256(blob: Data())
            secureZero(&blob)
            secureZero(&classicalBlob)
            self = .mlkem1024(blob: blob, encapsulated: encapsulated, classicalBlob: classicalBlob)
        }
    }
}

// A user-scoped KEK's keychain item data. A P-256 KEK's is its bare Secure
// Enclave blob, as it always has been. An ML-KEM KEK's is a container:
// magic "HKGQ", format 3, the suite byte (0x02), the KEK's 32-byte
// fingerprint, the ML-KEM blob length-prefixed (big-endian u16), the
// 1568-byte ciphertext, then the P-256 blob length-prefixed. Secure
// Enclave blobs begin 0x04 0x82 (a DER octet
// string), so no P-256 item starts with the magic. The CLI's `retire`
// reads this format too (`storedKEKCheck` in main.swift).
//
// The fingerprint is recorded because it covers the ciphertext (see
// `KEMKEK`), and decapsulating a damaged ciphertext doesn't fail: without
// the record, an item whose ciphertext was damaged would load as a KEK
// with another fingerprint; with it, the item is corrupt. As in a machine
// KEK file, this catches damage, not someone who can rewrite the item --
// they can record a fingerprint to match; the payloads' and the operator's
// copies of the fingerprint are what catch that.
private let keychainKEKMagic = Data("HKGQ".utf8)
private let keychainKEKFormatVersion: UInt8 = 3
private let keychainKEKHeaderLength = 4 + 1 + 1 + hkdfguardFingerprintLength + 2

/// A keychain item's KEK, and the fingerprint the item records for it (an
/// ML-KEM item always does; a P-256 item has nowhere to).
struct KeychainKEK: Equatable {
    var stored: StoredKEK
    var fingerprint: Data?
}

/// `fingerprint` is the KEK's, required for ML-KEM and unused for P-256.
func encodeKeychainKEK(_ stored: StoredKEK, fingerprint: Data? = nil) -> Data? {
    switch stored {
    case .p256(let blob):
        guard !blob.isEmpty, !blob.starts(with: keychainKEKMagic) else {
            return nil
        }
        return blob
    case .mlkem1024(let blob, let encapsulated, let classicalBlob):
        guard !blob.isEmpty, blob.count <= Int(UInt16.max),
              !classicalBlob.isEmpty, classicalBlob.count <= Int(UInt16.max),
              encapsulated.count == mlkem1024CiphertextLength,
              let fingerprint, fingerprint.count == hkdfguardFingerprintLength else {
            return nil
        }
        var out = keychainKEKMagic
        out.append(keychainKEKFormatVersion)
        out.append(KEKSuite.mlkem1024StoredCiphertext.rawValue)
        out.append(fingerprint)
        out.append(UInt8(blob.count >> 8))
        out.append(UInt8(blob.count & 0xFF))
        out.append(blob)
        out.append(encapsulated)
        out.append(UInt8(classicalBlob.count >> 8))
        out.append(UInt8(classicalBlob.count & 0xFF))
        out.append(classicalBlob)
        return out
    }
}

/// Nil only for data that has the container's magic but isn't a container
/// this build understands: corrupt, or from a newer build. Anything else is
/// taken as a P-256 blob, for the enclave to accept or refuse.
func decodeKeychainKEK(_ data: Data) -> KeychainKEK? {
    guard data.starts(with: keychainKEKMagic) else {
        return KeychainKEK(stored: .p256(blob: data), fingerprint: nil)
    }
    var bytes = [UInt8](data)
    defer { secureZero(&bytes) }
    guard bytes.count > keychainKEKHeaderLength,
          bytes[4] == keychainKEKFormatVersion,
          bytes[5] == KEKSuite.mlkem1024StoredCiphertext.rawValue else {
        return nil
    }
    let length = Int(bytes[keychainKEKHeaderLength - 2]) << 8 | Int(bytes[keychainKEKHeaderLength - 1])
    let blobEnd = keychainKEKHeaderLength + length
    let classicalStart = blobEnd + mlkem1024CiphertextLength + 2
    guard length > 0, bytes.count > classicalStart else {
        return nil
    }
    let classicalLength = Int(bytes[classicalStart - 2]) << 8 | Int(bytes[classicalStart - 1])
    guard classicalLength > 0, bytes.count == classicalStart + classicalLength else {
        return nil
    }
    return KeychainKEK(
        stored: .mlkem1024(blob: Data(bytes[keychainKEKHeaderLength..<blobEnd]),
                           encapsulated: Data(bytes[blobEnd..<(classicalStart - 2)]),
                           classicalBlob: Data(bytes[classicalStart...])),
        fingerprint: Data(bytes[6..<(6 + hkdfguardFingerprintLength)]))
}

/// What a stored KEK blob turned out to be.
enum KEKReconstruction {
    case key(KEK)
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
    guard var item = decodeKeychainKEK(data) else {
        return .corrupt // a malformed container: no keybag state explains that
    }
    // An ML-KEM item's blobs are copies of their own (a P-256 item's is
    // `data` itself, which the caller zeroes): don't leave them behind.
    defer { item.stored.zeroBlobs() }
    let result = reconstructStoredKEK(item.stored, enclaveIsUsable: enclaveIsUsable)
    // The key loaded, but is not the KEK the item records: its ciphertext
    // (or the record) was damaged. No keybag state explains that either.
    if case .key(let kek) = result, let recorded = item.fingerprint, kek.fingerprint != recorded {
        return .corrupt
    }
    return result
}

/// `reconstructKEK` for a KEK already split into its parts -- a keychain
/// item's, or a machine KEK file's.
func reconstructStoredKEK(
    _ stored: StoredKEK,
    enclaveIsUsable: () -> Bool = secureEnclaveIsUsableNow
) -> KEKReconstruction {
    switch stored {
    case .p256(let blob):
        if let key = try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob) {
            return .key(.p256(key))
        }
    case .mlkem1024(let blob, let encapsulated, let classicalBlob):
        // Before macOS 26 the enclave has no ML-KEM: the KEK is very likely
        // fine, and must never be reported as corrupt (and so deleted).
        guard !MachineScopeTestOverrides.withoutMLKEM, #available(macOS 26.0, *) else {
            return .enclaveRefused
        }
        if let kem = reconstructMLKEM1024KEK(blob: blob, encapsulated: encapsulated, classicalBlob: classicalBlob) {
            return .key(.mlkem1024(kem))
        }
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
func enclaveProbeSucceeds(_ access: SecAccessControl?) -> Bool {
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
    case .machine(let settings):
        return machineKekExists(service: service, settings: settings)
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

/// `keychainAccessDenied`, logged, when `suites` refuses `kek`'s suite
/// (RequirePostQuantum, and a P-256 KEK); nil when it permits it.
func suiteRefusal(_ kek: KEK, _ suites: SuitePolicy, service: String) -> Int32? {
    guard !suites.permits(kek.suite) else {
        return nil
    }
    machineLog.error("\(service, privacy: .public): the hkdfguard policy requires post-quantum KEKs (RequirePostQuantum) and this service's KEK is P-256; retire it and provision a new one")
    return HKDFGuardStatus.keychainAccessDenied.rawValue
}

/// Creates an ML-KEM-1024 KEK under `access`. Where this Mac's Secure
/// Enclave can't -- a macOS before 26, or an enclave that makes P-256 keys
/// under the same policy but not ML-KEM ones -- that is
/// `enclaveUnavailable`, logged: provisioning never falls back to P-256 on
/// its own, only through the policy's `KekSuite`. Any other refusal is
/// `keyGenerationFailed`.
func createMLKEMKEK(
    accessControl access: SecAccessControl,
    service: String
) -> (status: Int32, created: (kek: KEMKEK, stored: StoredKEK)?) {
    if !MachineScopeTestOverrides.withoutMLKEM, #available(macOS 26.0, *),
       let created = newMLKEM1024KEK(accessControl: access) {
        return (HKDFGuardStatus.success.rawValue, created)
    }
    guard (try? SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)) != nil else {
        return (HKDFGuardStatus.keyGenerationFailed.rawValue, nil)
    }
    machineLog.error("\(service, privacy: .public): this Mac's Secure Enclave can't create an ML-KEM-1024 KEK (that needs macOS 26 or later); to provision a classical P-256 KEK instead, set KekSuite to P-256 in the hkdfguard policy")
    return (HKDFGuardStatus.enclaveUnavailable.rawValue, nil)
}

/// Creates a KEK for `service` if one doesn't already exist. Idempotent
/// and safe under concurrent first-use — see the duplicate-item handling
/// below — so a caller that already checked `kekExists` and got `false`
/// doesn't need to treat a race against another creator as its own error.
func createKEK(service: String, mode: KeychainMode = hkdfguardKeychainMode) -> Int32 {
    withPolicySnapshot { createKEKUnderPolicy(service: service, mode: mode) }
}

private func createKEKUnderPolicy(service: String, mode: KeychainMode) -> Int32 {

    // Validate service identifier.
    guard validServiceName(service: service) else {
        return HKDFGuardStatus.invalidServiceIdentifier.rawValue
    }

    // Secure Enclave must exist.
    guard SecureEnclave.isAvailable else {
        return HKDFGuardStatus.enclaveUnavailable.rawValue
    }

    guard let suites = currentSuitePolicy() else {
        return HKDFGuardStatus.policyInvalid.rawValue
    }
    switch kekScope(service: service) {
    case .policyInvalid:
        return HKDFGuardStatus.policyInvalid.rawValue
    case .machine(let settings):
        return createMachineKEK(service: service, settings: settings, suites: suites)
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
        // the reason; nor is one of a suite the policy refuses.
        switch reconstructKEK(existing) {
        case .key(let kek):
            return suiteRefusal(kek, suites, service: service) ?? HKDFGuardStatus.success.rawValue
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

    // The SEP-wrapped key blob is the very credential the keychain item
    // exists to protect: usable by any process on this device that holds
    // it, while unlocked. This zeroes the copies this function owns, on
    // every exit path -- including the race-loser path below, where it is
    // never stored at all. It is best-effort, not a guarantee: the new key
    // keeps its own internal copy of the blob, which CryptoKit offers no way
    // to zero and which is freed, unzeroed, when the key goes out of scope.
    var representation: Data
    switch suites.provisionSuite {
    case .p256HashedPoint:
        guard let newKey = try? SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access) else {
            return HKDFGuardStatus.keyGenerationFailed.rawValue
        }
        representation = newKey.dataRepresentation
    case .mlkem1024StoredCiphertext:
        let (createStatus, maybeCreated) = createMLKEMKEK(accessControl: access, service: service)
        guard var created = maybeCreated else {
            return createStatus
        }
        defer { created.stored.zeroBlobs() }
        guard let encoded = encodeKeychainKEK(created.stored, fingerprint: created.kek.fingerprint) else {
            return HKDFGuardStatus.unexpectedOutputLength.rawValue
        }
        representation = encoded
    }
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
            case .key(let kek):
                return suiteRefusal(kek, suites, service: service) ?? HKDFGuardStatus.success.rawValue
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
func getKEK(service: String, mode: KeychainMode = hkdfguardKeychainMode) -> (status: Int32, key: KEK?) {
    guard validServiceName(service: service) else {
        return (HKDFGuardStatus.invalidServiceIdentifier.rawValue, nil)
    }

    guard SecureEnclave.isAvailable else {
        return (HKDFGuardStatus.enclaveUnavailable.rawValue, nil)
    }

    switch kekScope(service: service) {
    case .policyInvalid:
        return (HKDFGuardStatus.policyInvalid.rawValue, nil)
    case .machine(let settings):
        return getMachineKEK(service: service, settings: settings)
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
/// (0x04 || x || y).
/// Not a secret value — the public key it hashes isn't secret either —
/// so the explicit equality check against it in `hkdfguard_unwrap_dek`
/// exists purely to fail fast, cheaply, on "this payload wasn't wrapped
/// under the KEK I just resolved for this service" *before* spending any
/// effort on ECDH/AES-GCM. It is also in the authenticated header (see
/// `wrapDekCore`), so the derived key and the tag commit to it too.
func kekFingerprint(_ publicKey: P256.KeyAgreement.PublicKey) -> Data {
    Data(SHA256.hash(data: publicKey.x963Representation))
}
