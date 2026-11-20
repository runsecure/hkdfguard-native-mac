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
let hkdfguardDekLength = 32

/// Length, in bytes, of the SHA-256 "fingerprint" at the front of every
/// wrapped payload — see `kekFingerprint`.
let hkdfguardFingerprintLength = 32

/// The one byte that names the payload's construction (see "Wrap" below),
/// and so the kind of KEK that can open it: a KEK has exactly one suite.
/// Recognised at parse time, so an unknown one is reported before the
/// keychain is consulted.
enum KEKSuite: UInt8 {
    /// ECDH(P-256 KEK, hashed per-payload point) -> HKDF-SHA512 ->
    /// AES-256-GCM, the Linux and Windows libraries' construction.
    case p256HashedPoint = 0x01
    /// A hybrid: ECDH(the KEK's P-256 key, hashed per-payload point) and
    /// the ML-KEM-1024 decapsulation of the ciphertext stored with the KEK,
    /// both -> HKDF-SHA512 -> AES-256-GCM (see `KEMKEK`).
    case mlkem1024StoredCiphertext = 0x02
}
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
let hkdfguardWrappedLength =
    hkdfguardFingerprintLength + hkdfguardSuiteIdLength + hkdfguardSaltLength + hkdfguardNonceLength
    + hkdfguardDekLength + hkdfguardGCMTagLength

/// Offsets of each field within a payload. Everything before the
/// ciphertext is the header, authenticated as a whole (see `wrapDekCore`).
let hkdfguardSuiteIdOffset = hkdfguardFingerprintLength
let hkdfguardSaltOffset = hkdfguardSuiteIdOffset + hkdfguardSuiteIdLength
let hkdfguardNonceOffset = hkdfguardSaltOffset + hkdfguardSaltLength
private let hkdfguardCiphertextOffset = hkdfguardNonceOffset + hkdfguardNonceLength
private let hkdfguardHeaderLength = hkdfguardCiphertextOffset
private let hkdfguardCiphertextLength = hkdfguardDekLength + hkdfguardGCMTagLength

/// HKDF `info` prefix and the salt-to-point hash's RFC 9380 domain
/// separation tag, byte for byte the Linux library's (HKDF_INFO_PREFIX,
/// PAYLOAD_POINT_DST_PREFIX || the suite ID). Payloads are host-only, so
/// nothing requires the labels to match; matching keeps the three
/// implementations reviewable as one design.
private let hkdfguardHKDFInfoPrefix = Data("hkdfguard-wrap-v1:".utf8)
private let hkdfguardPayloadPointDST = Data("HkdfGuard-payload-ECDH-point-V01-CS01-with-P256_XMD:SHA-256_SSWU_RO_".utf8)
/// Suite 0x02's tag for the same hash: its own, so the two suites never ask
/// a key for the same point.
private let hkdfguardPayloadPointDSTSuite2 = Data("HkdfGuard-payload-ECDH-point-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_".utf8)

/// HKDF `info` for one payload: prefix || len(service) as u16 little-endian
/// || service || header. The length prefix keeps the concatenation
/// unambiguous, so no two distinct (service, header) pairs give the same
/// `info`; the header binds the fingerprint, suite, salt and nonce into the
/// key itself.
func wrappingKeyInfo(service: String, header: Data) -> Data { // internal: the forgery tests rebuild payloads with it
    let serviceBytes = Data(service.utf8) // validated ASCII, at most 128 bytes
    var info = hkdfguardHKDFInfoPrefix
    info.append(UInt8(truncatingIfNeeded: serviceBytes.count))
    info.append(UInt8(truncatingIfNeeded: serviceBytes.count >> 8))
    info.append(serviceBytes)
    info.append(header)
    return info
}

/// Hashes `salt` to a P-256 point with RFC 9380 `hash_to_curve`, suite
/// `P256_XMD:SHA-256_SSWU_RO_`, under `hkdfguardPayloadPointDST`.
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
/// Nil only if the hash lands on the point at infinity (probability about
/// 2^-256), which must never be handed to ECDH.
func payloadECDHPoint(salt: Data, suite: KEKSuite = .p256HashedPoint) -> P256.KeyAgreement.PublicKey? {
    switch suite {
    case .p256HashedPoint: return hashToCurveP256(message: salt, dst: hkdfguardPayloadPointDST)
    case .mlkem1024StoredCiphertext: return hashToCurveP256(message: salt, dst: hkdfguardPayloadPointDSTSuite2)
    }
}

// MARK: - Zeroing secrets

/// Zeroes `bytes` with `memset_s`, which the C standard forbids the compiler
/// from eliding as a dead store — unlike a plain memset/`initializeMemory`
/// right before the buffer is freed. Best effort still: it covers only the
/// copy it is handed.
func secureZero(_ bytes: inout Data) {
    bytes.withUnsafeMutableBytes { raw in
        guard let base = raw.baseAddress, raw.count > 0 else { return }
        _ = memset_s(base, raw.count, 0, raw.count)
    }
}

/// Copies the first `count` bytes of `bytes` to `out`, or reports that it
/// couldn't. Never traps: Swift can't catch a runtime trap,
/// so a trap here would end the host process instead of returning a status.
/// The library therefore has no force-unwrap, `try!`, `fatalError` or
/// `precondition` on any path an export can reach (the
/// `theLibraryHasNoTrapsOnItsExportPaths` test enforces it); a failure
/// that "can't happen" becomes INTERNAL_ERROR (-6) instead.
func copyOut<Bytes: ContiguousBytes>(_ bytes: Bytes, to out: UnsafeMutablePointer<UInt8>, count: Int) -> Bool {
    bytes.withUnsafeBytes { raw in
        guard count > 0, count <= raw.count, let source = raw.baseAddress else {
            return false
        }
        memcpy(out, source, count)
        return true
    }
}

func secureZero(_ bytes: inout [UInt8]) {
    bytes.withUnsafeMutableBytes { raw in
        guard let base = raw.baseAddress, raw.count > 0 else { return }
        _ = memset_s(base, raw.count, 0, raw.count)
    }
}

// MARK: - Wrap (seal) a DEK under the Secure Enclave KEK
//
// Wrapped format: [KEK fingerprint, 32 bytes: see `KEK.fingerprint`]
//                  [suite id, 1 byte: the KEK's `KEKSuite`]
//                  [salt, 32 random bytes]
//                  [nonce, 12 random bytes]
//                  [AES-256-GCM ciphertext || 16-byte tag, 48 bytes]
//
// For suite 0x01 the Secure Enclave computes
// Z = ECDH(KEK_priv, H(salt)), where H hashes the salt to a P-256 point
// (`payloadECDHPoint`); for suite 0x02 it does that with the KEK's P-256
// key and also decapsulates the ciphertext stored with the KEK (`KEMKEK`).
// HKDF-SHA512 turns that secret (suite 0x02: both, chained) into the
// AES-256 key (`KEK.wrappingKey`); AES-256-GCM seals the DEK. Wrapping
// needs the KEK's private key as much as unwrapping does, so only this
// host -- not anyone who has seen the public key -- can create a payload.
//
// The header (fingerprint || suite id || salt || nonce: every byte before
// the ciphertext) is bound twice: into the key, through HKDF's
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
    withPolicySnapshot {
        wrapDekUnderPolicy(service: service, dekPtr: dekPtr, dekLen: dekLen, outPtr: outPtr, outLen: outLen)
    }
}

private func wrapDekUnderPolicy(
    service: String,
    dekPtr: UnsafePointer<UInt8>,
    dekLen: Int32,
    outPtr: UnsafeMutablePointer<UInt8>,
    outLen: UnsafeMutablePointer<Int32>
) -> Int32 {
    let (getStatus, maybeKEK) = getKEK(service: service)
    guard let kek = maybeKEK else {
        return getStatus
    }
    guard let suites = currentSuitePolicy() else {
        return HKDFGuardStatus.policyInvalid.rawValue
    }
    if let refusal = suiteRefusal(kek, suites, service: service) {
        return refusal
    }

    let (sealStatus, maybePayload) = sealDek(
        UnsafeRawBufferPointer(start: dekPtr, count: Int(dekLen)), kek: kek, service: service)
    guard let payload = maybePayload else {
        return sealStatus
    }

    guard copyOut(payload, to: outPtr, count: hkdfguardWrappedLength) else {
        return HKDFGuardStatus.unexpectedOutputLength.rawValue
    }
    outLen.pointee = Int32(hkdfguardWrappedLength)

    return HKDFGuardStatus.success.rawValue
}

/// Seals `dek` into a payload under `kek`, in `kek`'s suite. Internal so
/// the tests can seal under a KEK that isn't in a keychain.
func sealDek(_ dek: UnsafeRawBufferPointer, kek: KEK, service: String) -> (status: Int32, payload: Data?) {
    guard let salt = randomBytes(hkdfguardSaltLength),
          let nonceBytes = randomBytes(hkdfguardNonceLength),
          let nonce = try? AES.GCM.Nonce(data: nonceBytes) else {
        return (HKDFGuardStatus.encryptionFailed.rawValue, nil) // the RNG failed
    }

    var header = kek.fingerprint
    header.append(kek.suite.rawValue)
    header.append(salt)
    header.append(nonceBytes)
    guard header.count == hkdfguardHeaderLength else {
        return (HKDFGuardStatus.unexpectedOutputLength.rawValue, nil)
    }

    let sealed: AES.GCM.SealedBox
    do {
        guard let key = try kek.wrappingKey(service: service, header: header) else {
            return (HKDFGuardStatus.encryptionFailed.rawValue, nil) // the salt hashed to the point at infinity (probability about 2^-256)
        }
        // Sealed straight from the caller's buffer: no copy of the DEK is made.
        sealed = try AES.GCM.seal(dek, using: key, nonce: nonce, authenticating: header)
    } catch {
        return (HKDFGuardStatus.encryptionFailed.rawValue, nil) // the enclave refused the key agreement or decapsulation, or sealing failed
    }

    guard sealed.ciphertext.count == hkdfguardDekLength,
          sealed.tag.count == hkdfguardGCMTagLength else {
        return (HKDFGuardStatus.unexpectedOutputLength.rawValue, nil)
    }

    var payload = header
    payload.append(sealed.ciphertext)
    payload.append(sealed.tag)
    guard payload.count == hkdfguardWrappedLength else {
        return (HKDFGuardStatus.unexpectedOutputLength.rawValue, nil)
    }
    return (HKDFGuardStatus.success.rawValue, payload)
}

// MARK: - Setup gate

/// The least wall-clock time each setup call (`hkdfguard_create_kek`,
/// `hkdfguard_kek_exists`, `hkdfguard_kek_fingerprint`) takes, whatever its outcome
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
/// reach the keychain pay the floor.
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

/// Writes the 32-byte fingerprint (SHA-256 of the public key and, for
/// ML-KEM, the stored ciphertext) of the KEK
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
    let (status, maybeFingerprint) = gatedSetup { () -> (Int32, Data?) in withPolicySnapshot {
        switch kekScope(service: service) {
        case .policyInvalid:
            return (HKDFGuardStatus.policyInvalid.rawValue, nil)
        case .machine(let settings):
            let (status, summary) = machineKeySummary(service: service, settings: settings)
            return (status, summary?.fingerprint)
        case .user:
            let (status, maybeKey) = getKEK(service: service)
            return (status, maybeKey?.fingerprint)
        }
    } }
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

/// Writes the suite of the KEK `service` currently resolves to -- the
/// suite byte every payload wrapped under it names: 1 for P-256, 2 for
/// ML-KEM-1024. macOS-only. Answered the way `hkdfguard_kek_fingerprint`
/// answers (for a machine KEK from its file, without the Secure Enclave),
/// and gated like it, being the same kind of question. A KEK the policy
/// refuses (RequirePostQuantum) is still reported, so it can be found.
@_cdecl("hkdfguard_kek_suite")
public func hkdfguard_kek_suite(
    servicePtr: UnsafePointer<CChar>?,
    outSuite: UnsafeMutablePointer<Int32>?
) -> Int32 {
    guard let outSuite else {
        return HKDFGuardStatus.invalidInputLength.rawValue
    }
    outSuite.pointee = 0
    guard let servicePtr, let service = normalizedService(from: servicePtr) else {
        return HKDFGuardStatus.invalidServiceIdentifier.rawValue
    }

    let (status, maybeSuite) = gatedSetup { () -> (Int32, KEKSuite?) in withPolicySnapshot {
        switch kekScope(service: service) {
        case .policyInvalid:
            return (HKDFGuardStatus.policyInvalid.rawValue, nil)
        case .machine(let settings):
            let (status, summary) = machineKeySummary(service: service, settings: settings)
            return (status, summary?.suite)
        case .user:
            let (status, maybeKey) = getKEK(service: service)
            return (status, maybeKey?.suite)
        }
    } }
    guard let suite = maybeSuite else {
        auditOperationFailed(.kekSuite, service: service, code: status)
        return status
    }
    outSuite.pointee = Int32(suite.rawValue)
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
/// `hkdfguard_generate_and_wrap_dek`, then the
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
    // the DEK is generated first, then every argument is
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
func zeroingOutOnFailure(
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
    withPolicySnapshot {
        unwrapDekUnderPolicy(servicePtr: servicePtr, wrappedPtr: wrappedPtr, wrappedLen: wrappedLen, outPtr: outPtr, outLen: outLen)
    }
}

private func unwrapDekUnderPolicy(
    servicePtr: UnsafePointer<CChar>?,
    wrappedPtr: UnsafePointer<UInt8>?,
    wrappedLen: Int32,
    outPtr: UnsafeMutablePointer<UInt8>?,
    outLen: UnsafeMutablePointer<Int32>?
) -> Int32 {
    // Argument checks, all before any keychain
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

    // A payload of a suite this build does not implement is reported as
    // such, before the keychain is consulted: it is a version or build
    // mismatch, not tampering.
    // The payload is copied once, here, and only the copy is looked at from
    // now on: what the policy is asked about is what gets opened, whatever
    // the caller does to its buffer meanwhile.
    let payload = Data(bytes: wrappedPtr, count: hkdfguardWrappedLength)
    guard let suite = KEKSuite(rawValue: payload[hkdfguardSuiteIdOffset]) else {
        return HKDFGuardStatus.unsupportedCiphersuite.rawValue
    }
    // So is one of a suite the policy refuses (RequirePostQuantum, and a
    // P-256 payload).
    guard let suites = currentSuitePolicy() else {
        return HKDFGuardStatus.policyInvalid.rawValue
    }
    guard suites.permits(suite) else {
        machineLog.error("\(service, privacy: .public): the hkdfguard policy requires post-quantum KEKs (RequirePostQuantum) and this payload was wrapped under a P-256 KEK; wrap the DEK again under the service's new KEK")
        return HKDFGuardStatus.unsupportedCiphersuite.rawValue
    }

    let (getStatus, maybeKEK) = getKEK(service: service)
    guard let kek = maybeKEK else {
        return getStatus
    }
    // Decrypted straight into the caller's buffer (its capacity was checked
    // above): the library keeps no copy of the DEK of its own to clean up.
    let openStatus = openPayload(payload, kek: kek, service: service, into: outPtr)
    guard openStatus == HKDFGuardStatus.success.rawValue else {
        return openStatus
    }
    outLen.pointee = Int32(hkdfguardDekLength)

    return HKDFGuardStatus.success.rawValue
}

/// Opens a payload under `kek` and returns the DEK as a value. For the
/// tests, which open under KEKs that aren't in a keychain;
/// `hkdfguard_unwrap_dek` uses the `into:` form below, so that no copy of
/// the DEK outlives the call.
func openPayload(_ payload: Data, kek: KEK, service: String) -> (status: Int32, plaintext: Data?) {
    var dek = [UInt8](repeating: 0, count: hkdfguardDekLength)
    defer { secureZero(&dek) }
    let status = dek.withUnsafeMutableBufferPointer { buffer -> Int32 in
        guard let out = buffer.baseAddress else {
            return HKDFGuardStatus.unexpectedOutputLength.rawValue
        }
        return openPayload(payload, kek: kek, service: service, into: out)
    }
    return (status, status == HKDFGuardStatus.success.rawValue ? Data(dek) : nil)
}

/// Opens a `hkdfguardWrappedLength`-byte payload under `kek`, writing the
/// `hkdfguardDekLength`-byte DEK to `out` -- which must have room for it --
/// only on success. Internal so the tests can open under a KEK that isn't in
/// a keychain.
///
/// The decrypted DEK is zeroed here, in the one variable CryptoKit's result
/// is ever bound to. Handing that `Data` to a caller to zero does not work:
/// a second binding shares its storage, so zeroing through either one makes
/// a private copy (copy-on-write), wipes that, and leaves the original bytes
/// to be freed intact.
func openPayload(_ payload: Data, kek: KEK, service: String, into out: UnsafeMutablePointer<UInt8>) -> Int32 {
    guard payload.count == hkdfguardWrappedLength else {
        return HKDFGuardStatus.payloadMalformed.rawValue
    }
    let bytes = [UInt8](payload)
    let header = Data(bytes[0..<hkdfguardHeaderLength])
    let storedFingerprint = header.prefix(hkdfguardFingerprintLength)
    let nonceBytes = Data(bytes[hkdfguardNonceOffset..<hkdfguardCiphertextOffset])
    let ciphertext = Data(bytes[hkdfguardCiphertextOffset..<(hkdfguardCiphertextOffset + hkdfguardDekLength)])
    let tag = Data(bytes[(hkdfguardCiphertextOffset + hkdfguardDekLength)...])

    // Checked against the *current* KEK's own public key before any key
    // agreement is attempted — a plain equality comparison is fine here
    // since neither side is secret (both are public-key material); this
    // is a fast, specific "wrong/stale KEK" signal that fails ahead of
    // the AEAD tag check below, which also covers this same fingerprint
    // (it is in the AAD) and would catch a tampered one anyway.
    guard kek.fingerprint == storedFingerprint else {
        return HKDFGuardStatus.fingerprintMismatch.rawValue
    }

    // The right fingerprint with the other suite's byte: no KEK of that
    // suite has this fingerprint, so the byte was altered.
    guard bytes[hkdfguardSuiteIdOffset] == kek.suite.rawValue else {
        return HKDFGuardStatus.decryptionFailed.rawValue
    }

    // The fixed-length fields always form a box; failing that is a bug.
    guard let nonce = try? AES.GCM.Nonce(data: nonceBytes),
          let box = try? AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag) else {
        return HKDFGuardStatus.unexpectedOutputLength.rawValue
    }

    // Re-derive the payload's key -- the Secure Enclave's ECDH against
    // the point its salt hashes to, or its decapsulation of the KEK's
    // ciphertext, then HKDF over the same header and service -- and open.
    // The two failures are kept apart, as on Linux: the enclave refusing
    // (locked, unavailable) is a CRYPTO_ERROR about this machine, not a
    // verdict on the payload; only a tag that doesn't verify is
    // PAYLOAD_AUTH_FAILED (tampered, or sealed for a different service).
    let key: SymmetricKey
    do {
        guard let derived = try kek.wrappingKey(service: service, header: header) else {
            return HKDFGuardStatus.encryptionFailed.rawValue // the salt hashed to the point at infinity (probability about 2^-256)
        }
        key = derived
    } catch {
        return HKDFGuardStatus.encryptionFailed.rawValue
    }
    var plaintext: Data
    do {
        plaintext = try AES.GCM.open(box, using: key, authenticating: header)
    } catch {
        return HKDFGuardStatus.decryptionFailed.rawValue
    }
    defer { secureZero(&plaintext) } // in place: `plaintext` is the only reference to these bytes

    guard plaintext.count == hkdfguardDekLength,
          copyOut(plaintext, to: out, count: hkdfguardDekLength) else {
        return HKDFGuardStatus.unexpectedOutputLength.rawValue
    }
    return HKDFGuardStatus.success.rawValue
}
