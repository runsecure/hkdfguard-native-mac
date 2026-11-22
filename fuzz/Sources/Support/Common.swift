//
//  Common.swift
//  hkdfguard fuzz build only
//
//  Shared by every harness: the one-time setup, the helpers that make a C
//  ABI call the way a C caller would, the contract every call must keep
//  whatever it returns, and independent restatements of the library's rules
//  (what a valid service name is, what a plaintext key looks like) for the
//  harnesses to judge the library's answers against.
//

import Foundation

// MARK: - Findings

/// A finding: says what, and aborts so the fuzzer records the input.
func finding(_ message: @autoclosure () -> String, file: StaticString = #fileID, line: UInt = #line) -> Never {
    fputs("FUZZ FINDING (aborting so the fuzzer records the input): \(message()) [\(file):\(line)]\n", stderr)
    abort()
}

func check(_ condition: Bool, _ message: @autoclosure () -> String, file: StaticString = #fileID, line: UInt = #line) {
    if !condition {
        finding(message(), file: file, line: line)
    }
}

/// The shared name of a status, for messages.
func statusName(_ code: Int32) -> String {
    HKDFGuardStatus(rawValue: code).map { "\($0) (\(code))" } ?? "unknown status \(code)"
}

let OK = HKDFGuardStatus.success.rawValue
let INVALID_ARGUMENT = HKDFGuardStatus.invalidInputLength.rawValue
let BUFFER_TOO_SMALL = HKDFGuardStatus.outputBufferTooSmall.rawValue
let INTERNAL_ERROR = HKDFGuardStatus.unexpectedOutputLength.rawValue
let INVALID_SERVICE_NAME = HKDFGuardStatus.invalidServiceIdentifier.rawValue
let POLICY_INVALID = HKDFGuardStatus.policyInvalid.rawValue
let PAYLOAD_MALFORMED = HKDFGuardStatus.payloadMalformed.rawValue
let PAYLOAD_AUTH_FAILED = HKDFGuardStatus.decryptionFailed.rawValue
let PAYLOAD_UNSUPPORTED = HKDFGuardStatus.unsupportedCiphersuite.rawValue
let KEK_FINGERPRINT_MISMATCH = HKDFGuardStatus.fingerprintMismatch.rawValue
let KEK_NOT_FOUND = HKDFGuardStatus.kekNotFound.rawValue
let FILE_NOT_FOUND = HKDFGuardStatus.fileNotFound.rawValue
let FILE_ACCESS_DENIED = HKDFGuardStatus.fileAccessDenied.rawValue
let FILE_IO = HKDFGuardStatus.fileIO.rawValue
let FILE_TOO_SHORT = HKDFGuardStatus.fileTooShort.rawValue
let FILE_TOO_LONG = HKDFGuardStatus.fileTooLong.rawValue
let FILE_PLAINTEXT_KEY = HKDFGuardStatus.fileUnprotectedKey.rawValue
let FILE_MALFORMED = HKDFGuardStatus.fileMalformed.rawValue
let FILE_UNTRUSTED = HKDFGuardStatus.fileInsecure.rawValue

// MARK: - Setup

/// The service whose KEK every harness creates at startup.
let SERVICE = "com.hkdfguard.fuzz"
/// The same name, as the C ABI must treat it: case-insensitively.
let SERVICE_UPPER = "COM.HKDFGUARD.Fuzz"
/// A valid service name no KEK is ever created for.
let OTHER_SERVICE = "com.hkdfguard.other"

/// hkdfguard.h's constants, restated: a harness must not learn them from
/// the code it is checking.
let DEK_LEN = 32
let WRAPPED_LEN = 125
let FINGERPRINT_LEN = 32
let SUITE_OFFSET = 32
let KNOWN_SUITES: Set<UInt8> = [1, 2]
/// The suite of the fuzz build's KEKs (see `FuzzKEKStore`).
let FUZZ_KEK_SUITE: UInt8 = 2

let knownDek: [UInt8] = (0..<32).map { 0x40 + UInt8($0) }

/// A private directory of this process's own, for the files the harnesses
/// make. The library refuses a key file under any folder others can write,
/// so `HKDFGUARD_FUZZ_DIR` (default: ~/Library/Caches/hkdfguard-fuzz) must
/// be one whose every ancestor is root's or this user's and writable by
/// nobody else.
let fuzzDirectory: String = {
    let base = ProcessInfo.processInfo.environment["HKDFGUARD_FUZZ_DIR"].flatMap { $0.isEmpty ? nil : $0 }
        ?? NSHomeDirectory() + "/Library/Caches/hkdfguard-fuzz"
    // What a process that ended in a finding left behind.
    for entry in (try? FileManager.default.contentsOfDirectory(atPath: base)) ?? [] {
        if entry.hasPrefix("p"), let pid = pid_t(entry.dropFirst()), kill(pid, 0) != 0, errno == ESRCH {
            removeTree(base + "/" + entry)
        }
    }
    let path = base + "/p\(getpid())"
    do {
        try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    } catch {
        finding("fuzz setup: can't create \(path): \(error)")
    }
    guard chmod(base, 0o700) == 0, chmod(path, 0o700) == 0 else {
        finding("fuzz setup: can't make \(path) private")
    }
    return path
}()

/// Removes this process's directory. Called when a run ends normally; one
/// that ends in a finding leaves its directory -- nothing but the harness's
/// own scratch files -- for the next run to remove.
func removeFuzzDirectory() {
    removeTree(fuzzDirectory)
}

/// Removes `path` and everything under it, whatever modes a harness left.
func removeTree(_ path: String) {
    var info = stat()
    guard lstat(path, &info) == 0 else { return }
    guard info.st_mode & S_IFMT == S_IFDIR else {
        _ = unlink(path) // a link is removed, never followed
        return
    }
    _ = lchmod(path, 0o700)
    if let walker = FileManager.default.enumerator(atPath: path) {
        for case let entry as String in walker {
            _ = lchmod(path + "/" + entry, 0o700)
        }
    }
    try? FileManager.default.removeItem(atPath: path)
}

private let setupOnce: Void = {
    // A Swift runtime trap is SIGTRAP, which libFuzzer does not handle: turn
    // it into the abort it does, so the input is recorded.
    signal(SIGTRAP) { _ in
        let message: StaticString = "FUZZ FINDING: a Swift runtime trap (SIGTRAP) -- in the library, a crash of the host process; run the input under lldb to see where\n"
        _ = write(2, message.utf8Start, message.utf8CodeUnitCount)
        abort()
    }
    // The setup calls' one-second floor is for production; see
    // `setupMinDelayOverrideForTests`.
    setupMinDelayOverrideForTests.withLock { $0 = .zero }
    _ = fuzzDirectory
    let rc = SERVICE.withCString { hkdfguard_create_kek(servicePtr: $0) }
    check(rc == OK, "fuzz setup: hkdfguard_create_kek: \(statusName(rc))")
}()

/// Once per process: the KEK for `SERVICE`, the private directory, no
/// setup-call delay.
func setup() {
    _ = setupOnce
}

/// A genuine payload for `SERVICE` and `knownDek`, wrapped once.
let genuinePayload: [UInt8] = {
    setup()
    let ret = wrap(.fuzz, dek: knownDek, call: .full)
    check(ret.rc == OK && ret.written.count == WRAPPED_LEN, "fuzz setup: hkdfguard_wrap_dek: \(statusName(ret.rc))")
    return ret.written
}()

/// The fingerprint of `SERVICE`'s KEK, read once.
let genuineFingerprint: [UInt8] = {
    setup()
    let ret = withBuffer(.dek) { out, outLen in
        SERVICE.withCString { hkdfguard_kek_fingerprint(servicePtr: $0, outPtr: out, outLen: outLen) }
    }
    check(ret.rc == OK && ret.written.count == FINGERPRINT_LEN, "fuzz setup: hkdfguard_kek_fingerprint: \(statusName(ret.rc))")
    return ret.written
}()

// MARK: - The service string

/// hkdfguard.h's rule for `service`, restated independently: 1 to 128
/// bytes, each an ASCII letter, digit or '.', not starting with '.', and
/// with no "..".
func serviceNameIsValid(_ name: [UInt8]) -> Bool {
    guard (1...128).contains(name.count), name[0] != UInt8(ascii: ".") else { return false }
    var previous: UInt8 = 0
    for byte in name {
        let letter = (byte >= 0x41 && byte <= 0x5A) || (byte >= 0x61 && byte <= 0x7A)
        let digit = byte >= 0x30 && byte <= 0x39
        guard letter || digit || byte == 0x2E else { return false }
        if byte == 0x2E && previous == 0x2E { return false }
        previous = byte
    }
    return true
}

func asciiLowercased(_ bytes: [UInt8]) -> [UInt8] {
    bytes.map { $0 >= 0x41 && $0 <= 0x5A ? $0 + 0x20 : $0 }
}

enum Service {
    case fuzz
    case fuzzUpper
    case other
    case raw([UInt8])
    case null

    static func decode(_ input: inout FuzzInput) -> Service {
        switch input.choice(5) {
        case 0: return .fuzz
        case 1: return .fuzzUpper
        case 2: return .other
        case 3: return .raw(input.blob(max: 300))
        default: return .null
        }
    }

    func encode(_ seed: Seed) {
        switch self {
        case .fuzz: seed.choice(0)
        case .fuzzUpper: seed.choice(1)
        case .other: seed.choice(2)
        case .raw(let bytes): seed.choice(3).blob(bytes)
        case .null: seed.choice(4)
        }
    }

    /// The name as C sees it: up to the first NUL. Nil is a NULL pointer.
    var name: [UInt8]? {
        switch self {
        case .fuzz: return Array(SERVICE.utf8)
        case .fuzzUpper: return Array(SERVICE_UPPER.utf8)
        case .other: return Array(OTHER_SERVICE.utf8)
        case .raw(let bytes): return Array(bytes.prefix { $0 != 0 })
        case .null: return nil
        }
    }

    var isValid: Bool {
        name.map(serviceNameIsValid) ?? false
    }

    /// Whether it names the service that has a KEK, in any spelling.
    var isFuzz: Bool {
        name.map { asciiLowercased($0) == Array(SERVICE.utf8) } ?? false
    }

    /// Calls `body` with the C string, or NULL.
    func withCString<T>(_ body: (UnsafePointer<CChar>?) -> T) -> T {
        guard let name else { return body(nil) }
        return (name + [0]).withUnsafeBufferPointer { buffer in
            buffer.withMemoryRebound(to: CChar.self) { body($0.baseAddress) }
        }
    }
}

// MARK: - The output buffer

/// How the caller's output buffer is presented: its declared capacity
/// (negative included), and whether `out` or `out_len` is NULL.
struct Call {
    var cap: Int16
    var outNull = false
    var outLenNull = false

    /// More than any output needs.
    static let full = Call(cap: 1024)
    /// Exactly a DEK, or a fingerprint.
    static let dek = Call(cap: 32)

    static func decode(_ input: inout FuzzInput) -> Call {
        let cap = input.i16()
        let shape = input.u8()
        return Call(cap: cap, outNull: shape == 1 || shape == 3, outLenNull: shape == 2 || shape == 3)
    }

    func encode(_ seed: Seed) {
        seed.i16(cap).u8((outNull ? 1 : 0) | (outLenNull ? 2 : 0))
    }

    var capacity: Int32 { Int32(cap) }

    /// Pointers valid, capacity non-negative: a call the contract promises
    /// an answer to.
    var wellFormed: Bool { !outNull && !outLenNull && cap >= 0 }
}

let FILL: UInt8 = 0xAA
/// Bytes kept past the declared capacity: a write there is an overflow,
/// whatever sanitizer the build has or hasn't.
private let canaryLength = 64

struct Ret {
    let rc: Int32
    /// `*out_len` after the call, when `out_len` was not NULL.
    let outLen: Int32?
    /// The caller's buffer: `max(cap, 0)` bytes, `FILL` before the call.
    let buffer: [UInt8]
    let canaryIntact: Bool

    var untouched: Bool { buffer.allSatisfy { $0 == FILL } }
    var zeroed: Bool { buffer.allSatisfy { $0 == 0 } }
    /// The first `*out_len` bytes.
    var written: [UInt8] {
        let count = min(max(Int(outLen ?? 0), 0), buffer.count)
        return Array(buffer[0..<count])
    }
}

/// Runs `body(out, out_len)` with the buffer `call` describes.
func withBuffer(_ call: Call, _ body: (UnsafeMutablePointer<UInt8>?, UnsafeMutablePointer<Int32>?) -> Int32) -> Ret {
    let declared = max(Int(call.cap), 0)
    let storage = UnsafeMutablePointer<UInt8>.allocate(capacity: declared + canaryLength)
    defer { storage.deallocate() }
    storage.initialize(repeating: FILL, count: declared + canaryLength)
    var outLen = call.capacity
    let rc = withUnsafeMutablePointer(to: &outLen) { outLenPointer in
        body(call.outNull ? nil : storage, call.outLenNull ? nil : outLenPointer)
    }
    let all = Array(UnsafeBufferPointer(start: storage, count: declared + canaryLength))
    return Ret(rc: rc, outLen: call.outLenNull ? nil : outLen,
               buffer: Array(all[0..<declared]), canaryIntact: all[declared...].allSatisfy { $0 == FILL })
}

/// What a failure does to the caller's buffer.
enum OnFailure {
    /// hkdfguard_unwrap_dek, hkdfguard_open_file: every byte of the
    /// declared capacity is zeroed.
    case zeroed
    /// Every other function: nothing is written.
    case untouched
}

/// What every call must satisfy, whatever it returned.
func checkContract(_ ret: Ret, _ call: Call, _ onFailure: OnFailure, _ what: String, file: StaticString = #fileID, line: UInt = #line) {
    func require(_ condition: Bool, _ message: @autoclosure () -> String) {
        check(condition, "\(what): \(message())", file: file, line: line)
    }
    require(HKDFGuardStatus(rawValue: ret.rc) != nil, "returned \(ret.rc), which hkdfguard.h does not define")
    require(ret.rc != INTERNAL_ERROR, "INTERNAL_ERROR: the library detected a failure that can't happen")
    require(ret.canaryIntact, "wrote past the declared capacity \(call.cap) (rc \(statusName(ret.rc)))")
    if call.outLenNull {
        require(ret.untouched, "out_len NULL, but the buffer was written (rc \(statusName(ret.rc)))")
    }
    if call.outLenNull || call.cap < 0 {
        require(ret.rc == INVALID_ARGUMENT, "a NULL out_len or a negative capacity must be INVALID_ARGUMENT, not \(statusName(ret.rc))")
    }
    guard let outLen = ret.outLen else { return }
    if ret.rc == OK {
        require(outLen >= 0 && outLen <= max(call.capacity, 0), "OK but *out_len \(outLen) exceeds the capacity \(call.cap)")
        require(!call.outNull, "OK with a NULL out")
    } else if ret.rc == BUFFER_TOO_SMALL {
        require(outLen > call.capacity, "BUFFER_TOO_SMALL asks for \(outLen), not more than the capacity \(call.cap)")
    } else {
        require(outLen == call.capacity, "\(statusName(ret.rc)) changed *out_len from \(call.cap) to \(outLen)")
    }
    if ret.rc != OK {
        switch onFailure {
        case .zeroed where !call.outNull:
            require(ret.zeroed, "failure (\(statusName(ret.rc))) left bytes in the caller's buffer")
        case .zeroed, .untouched:
            require(ret.untouched, "failure (\(statusName(ret.rc))) wrote to the caller's buffer")
        }
    }
}

// MARK: - Calls

func unwrap(_ service: Service, _ payload: [UInt8], _ call: Call, payloadNull: Bool = false, lengthOverride: Int32? = nil) -> Ret {
    service.withCString { servicePointer in
        // One spare byte, so an empty payload still has an address.
        (payload + [0]).withUnsafeBufferPointer { bytes in
            withBuffer(call) { out, outLen in
                hkdfguard_unwrap_dek(servicePtr: servicePointer, wrappedPtr: payloadNull ? nil : bytes.baseAddress,
                                     wrappedLen: lengthOverride ?? Int32(payload.count), outPtr: out, outLen: outLen)
            }
        }
    }
}

func wrap(_ service: Service, dek: [UInt8], call: Call, dekNull: Bool = false, lengthOverride: Int32? = nil) -> Ret {
    service.withCString { servicePointer in
        (dek + [0]).withUnsafeBufferPointer { bytes in
            withBuffer(call) { out, outLen in
                hkdfguard_wrap_dek(servicePtr: servicePointer, dekPtr: dekNull ? nil : bytes.baseAddress,
                                   dekLen: lengthOverride ?? Int32(dek.count), outPtr: out, outLen: outLen)
            }
        }
    }
}

func openFile(path: [UInt8]?, _ call: Call) -> Ret {
    guard let path else {
        return withBuffer(call) { out, outLen in hkdfguard_open_file(pathPtr: nil, outPtr: out, outLen: outLen) }
    }
    return (path + [0]).withUnsafeBufferPointer { buffer in
        buffer.withMemoryRebound(to: CChar.self) { pointer in
            withBuffer(call) { out, outLen in hkdfguard_open_file(pathPtr: pointer.baseAddress, outPtr: out, outLen: outLen) }
        }
    }
}

func openFile(path: String, _ call: Call) -> Ret {
    openFile(path: Array(path.utf8), call)
}

/// What `hkdfguard_unwrap_dek` must return for these arguments: hkdfguard.h's
/// order of checks, restated. `genuine`: the one payload that opens.
func expectedUnwrapStatus(service: Service, payload: [UInt8], call: Call) -> Int32 {
    if call.outLenNull || call.cap < 0 { return INVALID_ARGUMENT }
    guard service.isValid else { return INVALID_SERVICE_NAME }
    if call.cap < DEK_LEN { return BUFFER_TOO_SMALL }
    if call.outNull { return INVALID_ARGUMENT }
    guard payload.count == WRAPPED_LEN else { return PAYLOAD_MALFORMED }
    guard KNOWN_SUITES.contains(payload[SUITE_OFFSET]) else { return PAYLOAD_UNSUPPORTED }
    guard service.isFuzz else { return KEK_NOT_FOUND }
    guard Array(payload[0..<FINGERPRINT_LEN]) == genuineFingerprint else { return KEK_FINGERPRINT_MISMATCH }
    return payload == genuinePayload ? OK : PAYLOAD_AUTH_FAILED
}

// MARK: - Key files

/// Whether `bytes` are what hkdfguard.h calls a plaintext DEK: 32 raw
/// bytes, or -- inside any surrounding ASCII whitespace, in at most 96
/// bytes -- its 64-digit hex or its base64 (standard or URL-safe, 43
/// characters or 44 with the `=`). Written the obvious way, to be compared
/// with the library's constant-time version.
func looksLikePlaintextKey(_ bytes: [UInt8]) -> Bool {
    if bytes.count == DEK_LEN { return true }
    if bytes.count > 96 { return false }
    let whitespace: Set<UInt8> = [0x20, 0x09, 0x0A, 0x0C, 0x0D]
    guard let first = bytes.firstIndex(where: { !whitespace.contains($0) }),
          let last = bytes.lastIndex(where: { !whitespace.contains($0) }) else { return false }
    let text = Array(bytes[first...last])

    func isHex(_ c: UInt8) -> Bool {
        (c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x66) || (c >= 0x41 && c <= 0x46)
    }
    if text.count == 64 && text.allSatisfy(isHex) { return true }

    var data = text
    if data.count == 44 {
        guard data.last == UInt8(ascii: "=") else { return false }
        data.removeLast()
    }
    guard data.count == 43 else { return false }
    for alphabet in ["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
                     "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"] {
        let symbols = Array(alphabet.utf8)
        let values = data.map { symbols.firstIndex(of: $0) }
        // 43 characters carry 258 bits: the last one's low two are unused.
        if !values.contains(nil), let lastValue = values[42], lastValue & 3 == 0 {
            return true
        }
    }
    return false
}

/// What `hkdfguard_open_file` must say of a trusted, readable regular file
/// holding `bytes`.
func expectedKeyFileStatus(_ bytes: [UInt8]) -> Int32 {
    if bytes.count == DEK_LEN { return FILE_PLAINTEXT_KEY }
    if bytes.count > WRAPPED_LEN { return FILE_TOO_LONG }
    if bytes.count < WRAPPED_LEN {
        return looksLikePlaintextKey(bytes) ? FILE_PLAINTEXT_KEY : FILE_TOO_SHORT
    }
    if bytes[0..<FINGERPRINT_LEN].allSatisfy({ $0 == 0 }) { return FILE_MALFORMED }
    return KNOWN_SUITES.contains(bytes[SUITE_OFFSET]) ? OK : FILE_MALFORMED
}

/// Writes `bytes` to `path` with `mode`, replacing whatever is there.
func writeFile(_ path: String, _ bytes: [UInt8], mode: mode_t) {
    _ = chmod(path, 0o600) // the last iteration's may be read-only
    _ = unlink(path)
    let fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0o600)
    check(fd >= 0, "harness: can't create \(path): \(String(cString: strerror(errno)))")
    let written = bytes.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
    check(written == bytes.count, "harness: short write to \(path)")
    check(fchmod(fd, mode) == 0, "harness: fchmod \(path)")
    close(fd)
}

/// The bytes of the file at `path` (C bytes, no terminator), or nil.
func readFile(_ path: [UInt8], limit: Int = 4096) -> [UInt8]? {
    let fd = (path + [0]).withUnsafeBufferPointer { buffer in
        buffer.withMemoryRebound(to: CChar.self) { cPath -> Int32 in
            guard let base = cPath.baseAddress else { return -1 }
            return open(base, O_RDONLY | O_NONBLOCK | O_CLOEXEC)
        }
    }
    guard fd >= 0 else { return nil }
    defer { close(fd) }
    var bytes = [UInt8](repeating: 0, count: limit)
    let count = bytes.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
    return count >= 0 ? Array(bytes.prefix(count)) : nil
}

// MARK: - Strings at the edge of readable memory

/// A byte string placed so that its last byte is the last readable byte
/// before an inaccessible page: reading one byte past it is a fault, in any
/// build, with or without a sanitizer. What a C caller's string looks like
/// when it ends at the end of a mapping -- and what an unterminated one
/// must be treated as.
final class Guarded {
    private let base: UnsafeMutableRawPointer
    private let mapLength: Int
    private let pointer: UnsafePointer<CChar>

    init(_ bytes: [UInt8]) {
        let page = Int(getpagesize())
        let dataLength = max((bytes.count + page - 1) / page, 1) * page
        mapLength = dataLength + page
        guard let mapped = mmap(nil, mapLength, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0),
              mapped != MAP_FAILED else {
            finding("harness: mmap of a guarded string")
        }
        base = mapped
        check(mprotect(base + dataLength, page, PROT_NONE) == 0, "harness: mprotect of the guard page")
        let start = base + (dataLength - bytes.count)
        bytes.withUnsafeBytes { start.copyMemory(from: $0.baseAddress ?? UnsafeRawPointer(start), byteCount: $0.count) }
        pointer = UnsafePointer(start.assumingMemoryBound(to: CChar.self))
    }

    /// Calls `body` with the string. The mapping lasts exactly as long as
    /// this object, so the pointer is only ever handed out inside a call.
    func use<T>(_ body: (UnsafePointer<CChar>) -> T) -> T {
        withExtendedLifetime(self) { body(pointer) }
    }

    deinit {
        munmap(base, mapLength)
    }
}
