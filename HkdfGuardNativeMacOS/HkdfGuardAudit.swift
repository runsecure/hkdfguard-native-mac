//
//  HkdfGuardAudit.swift
//  HkdfGuardNativeMacOS
//
//  The audit trail: one unified-log record per security-relevant event.
//

import Foundation
import CryptoKit
import os

// MARK: - Audit trail

// One system-log record per security-relevant event, written whatever the
// host does about logging :
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
//   never occurs: there is one provider, the Secure Enclave. The
//   unwrap-success record (1003) is always written: the macOS policy has no
//   counterpart of Linux's `[audit] unwrap_success` switch. The macOS-only refinements of
//   PROVIDER_ERROR (-96..-100) are audited as 2005, like PROVIDER_ERROR.
//
// Any process can write to the unified log, so these records are an audit
// aid, not tamper-proof evidence -- as with syslog and the Event Log.

/// The C function an audit event belongs to.
enum AuditOp: String {
    case createKek = "hkdfguard_create_kek"
    case kekExists = "hkdfguard_kek_exists"
    case kekFingerprint = "hkdfguard_kek_fingerprint"
    case kekSuite = "hkdfguard_kek_suite"
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

private let auditProvider = "SECURE_ENCLAVE"

private let auditExecutable: String = {
    var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
    let length = proc_pidpath(getpid(), &buffer, UInt32(buffer.count))
    guard length > 0 else { return auditQuote(Array("(unknown)".utf8)) }
    return auditQuote(buffer[0..<min(Int(length), buffer.count)].map { UInt8(bitPattern: $0) })
}()

/// A double-quoted field value: printable ASCII
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
/// administrator's attention are written
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
/// caller looping on them.
let auditSetupCallsWarnAt = 10

/// Counts setup calls (hkdfguard_create_kek / hkdfguard_kek_exists /
/// hkdfguard_kek_fingerprint) and
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
