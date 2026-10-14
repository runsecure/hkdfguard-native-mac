//
//  HkdfGuardOpenFileTests.swift
//  HkdfGuardNativeMacOSTests
//

import Testing
import Foundation
import CryptoKit
@testable import HkdfGuardNativeMacOS

/// Exercises `hkdfguard_open_file`: reading a wrapped payload from disk and
/// every way a file can fail to be one.
///
/// Status codes mirrored from the module's private `HKDFGuardStatus`:
///   0 = success, -1 = invalidInputLength, -2 = outputBufferTooSmall,
///   -19 = fileNotFound, -20 = fileAccessDenied, -21 = fileNotRegular,
///   -22 = fileReadFailed, -23 = fileTooShort, -24 = fileTooLong,
///   -25 = fileMalformed, -26 = fileUnprotectedKey, -27 = fileInsecure.
///
/// `hkdfguard_open_file` never touches the keychain or the Secure Enclave,
/// so unlike `HkdfGuardNativeMacOSWrapUnwrapTests` this suite runs anywhere,
/// CI and VMs included. The round trip through a real KEK
/// (`wrapWriteOpenFileThenUnwrapRecoversOriginalDEK`) lives in that suite.
@Suite
struct HkdfGuardOpenFileTests {

    private static let wrappedLength = 156

    /// A fresh, empty directory for one test; removed by the caller's defer.
    private static func makeTempDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("hkdfguard.openfile.\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
        return url
    }

    private static func write(_ bytes: [UInt8], to url: URL) throws {
        try Data(bytes).write(to: url)
    }

    /// A 156-byte payload that passes every structural check: a non-zero
    /// fingerprint, a real P-256 ephemeral public key, and random
    /// nonce/ciphertext/tag bytes. It would fail AES-GCM at unwrap, which is
    /// not `hkdfguard_open_file`'s concern.
    private static func structurallyValidPayload() -> [UInt8] {
        var payload = (0..<32).map { _ in UInt8.random(in: 1 ... .max) }
        payload += Array(P256.KeyAgreement.PrivateKey().publicKey.rawRepresentation)
        payload += (0..<(12 + 32 + 16)).map { _ in UInt8.random(in: .min ... .max) }
        return payload
    }

    private static func openFile(
        _ path: String,
        bufferCapacity: Int32 = 1024
    ) -> (status: Int32, bytes: [UInt8], outLen: Int32, untouched: Bool) {
        var out = [UInt8](repeating: 0xA5, count: Int(bufferCapacity))
        var outLen = bufferCapacity
        let status = path.withCString { pathCStr in
            out.withUnsafeMutableBufferPointer { outBuf in
                hkdfguard_open_file(pathPtr: pathCStr, outPtr: outBuf.baseAddress!, outLen: &outLen)
            }
        }
        return (status, Array(out.prefix(Int(max(outLen, 0)))), outLen, out.allSatisfy { $0 == 0xA5 })
    }

    // MARK: - Success

    @Test func readsAWrappedPayloadFile() throws {
        let dir = try Self.makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("ingest.key")
        let payload = Self.structurallyValidPayload()
        try Self.write(payload, to: file)

        let result = Self.openFile(file.path)
        #expect(result.status == 0)
        #expect(result.outLen == Int32(Self.wrappedLength))
        #expect(result.bytes == payload)
    }

    @Test func acceptsABufferOfExactlyThePayloadLength() throws {
        let dir = try Self.makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("ingest.key")
        let payload = Self.structurallyValidPayload()
        try Self.write(payload, to: file)

        let result = Self.openFile(file.path, bufferCapacity: Int32(Self.wrappedLength))
        #expect(result.status == 0)
        #expect(result.bytes == payload)
    }

    // MARK: - Length

    @Test func rejectsFilesShorterThanAPayload() throws {
        let dir = try Self.makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let payload = Self.structurallyValidPayload()

        for length in [0, 1, 31, 33, 100, Self.wrappedLength - 1] {
            let file = dir.appendingPathComponent("short.\(length)")
            try Self.write(Array(payload.prefix(length)), to: file)
            let result = Self.openFile(file.path)
            #expect(result.status == -23, "length \(length)")
            #expect(result.outLen == 0, "length \(length)")
            #expect(result.untouched, "length \(length): nothing may be written to out")
        }
    }

    @Test func rejectsFilesLongerThanAPayload() throws {
        let dir = try Self.makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let payload = Self.structurallyValidPayload()

        for extra in [1, 2, 156, 1 << 20] {
            let file = dir.appendingPathComponent("long.\(extra)")
            try Self.write(payload + [UInt8](repeating: 0x41, count: extra), to: file)
            let result = Self.openFile(file.path)
            #expect(result.status == -24, "extra \(extra)")
            #expect(result.outLen == 0, "extra \(extra)")
            #expect(result.untouched, "extra \(extra)")
        }
    }

    // MARK: - Unprotected (plaintext) keys

    @Test func reportsAPlaintextDEKAsUnprotectedRatherThanTooShort() throws {
        let dir = try Self.makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let dek = (0..<32).map { _ in UInt8.random(in: .min ... .max) }
        let base64 = Data(dek).base64EncodedString()
        let base64URLUnpadded = base64
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        let hex = dek.map { String(format: "%02x", $0) }.joined()

        let cases: [(String, [UInt8])] = [
            ("raw 32 bytes", dek),
            ("base64", Array(base64.utf8)),
            ("base64 + LF", Array((base64 + "\n").utf8)),
            ("base64 + CRLF, leading spaces", Array(("  " + base64 + "\r\n").utf8)),
            ("base64url unpadded", Array(base64URLUnpadded.utf8)),
            ("hex lowercase + LF", Array((hex + "\n").utf8)),
            ("hex uppercase", Array(hex.uppercased().utf8)),
        ]
        for (name, bytes) in cases {
            let file = dir.appendingPathComponent(name.replacingOccurrences(of: " ", with: "."))
            try Self.write(bytes, to: file)
            let result = Self.openFile(file.path)
            #expect(result.status == -26, "\(name)")
            #expect(result.outLen == 0, "\(name)")
            #expect(result.untouched, "\(name): a plaintext key must never reach the caller's buffer")
        }
    }

    @Test func shortTextThatIsNotAKeyIsTooShortNotUnprotected() throws {
        let dir = try Self.makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }

        let cases: [(String, String)] = [
            ("hex of 31 bytes", String(repeating: "ab", count: 31)),
            ("hex with a non-hex char", String(repeating: "ab", count: 31) + "zz"),
            ("44 chars without padding", String(repeating: "A", count: 44)),
            ("base64 with a space inside", String(repeating: "A", count: 21) + " " + String(repeating: "A", count: 21) + "="),
            ("plain words", "this is not a key"),
        ]
        for (name, text) in cases {
            let file = dir.appendingPathComponent(name.replacingOccurrences(of: " ", with: "."))
            try Self.write(Array(text.utf8), to: file)
            #expect(Self.openFile(file.path).status == -23, "\(name)")
        }
    }

    // MARK: - Malformed payloads

    @Test func rejectsAPayloadLengthFileWithAnAllZeroFingerprint() throws {
        let dir = try Self.makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("zero.fingerprint")
        var payload = Self.structurallyValidPayload()
        payload.replaceSubrange(0..<32, with: [UInt8](repeating: 0, count: 32))
        try Self.write(payload, to: file)

        let result = Self.openFile(file.path)
        #expect(result.status == -25)
        #expect(result.untouched)
    }

    @Test func rejectsAPayloadLengthFileWhoseEphemeralKeyIsNotOnTheCurve() throws {
        let dir = try Self.makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("bad.point")
        var payload = Self.structurallyValidPayload()
        payload.replaceSubrange(32..<96, with: [UInt8](repeating: 0xFF, count: 64))
        try Self.write(payload, to: file)

        #expect(Self.openFile(file.path).status == -25)
    }

    @Test func rejectsAnAllZeroPayloadLengthFile() throws {
        let dir = try Self.makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("zeros")
        try Self.write([UInt8](repeating: 0, count: Self.wrappedLength), to: file)

        #expect(Self.openFile(file.path).status == -25)
    }

    // MARK: - Path and file type

    @Test func reportsAMissingFileAsNotFound() throws {
        let dir = try Self.makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }

        #expect(Self.openFile(dir.appendingPathComponent("absent.key").path).status == -19)
        #expect(Self.openFile("").status == -19)

        // A path that runs *through* a regular file: ENOTDIR.
        let file = dir.appendingPathComponent("ingest.key")
        try Self.write(Self.structurallyValidPayload(), to: file)
        #expect(Self.openFile(file.path + "/inner").status == -19)
    }

    @Test(.enabled(if: geteuid() != 0, "root bypasses file permissions"))
    func reportsAnUnreadableFileAsAccessDenied() throws {
        let dir = try Self.makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("ingest.key")
        try Self.write(Self.structurallyValidPayload(), to: file)
        try FileManager.default.setAttributes([.posixPermissions: 0o000], ofItemAtPath: file.path)

        #expect(Self.openFile(file.path).status == -20)
    }

    @Test func refusesASymlinkEvenToAValidPayload() throws {
        let dir = try Self.makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let target = dir.appendingPathComponent("ingest.key")
        try Self.write(Self.structurallyValidPayload(), to: target)
        let link = dir.appendingPathComponent("link.key")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)

        let result = Self.openFile(link.path)
        #expect(result.status == -21)
        #expect(result.untouched)
    }

    @Test func refusesADirectory() throws {
        let dir = try Self.makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }

        #expect(Self.openFile(dir.path).status == -21)
    }

    // MARK: - Ownership, permissions, links

    @Test func acceptsOwnerOnlyAndOwnerWritableFiles() throws {
        // 0600 is what the CLI writes; 0644 (the test helper's default) is
        // readable by others but writable by no one else, so it passes too.
        let dir = try Self.makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        for mode in [0o600, 0o644, 0o400] {
            let file = dir.appendingPathComponent("mode.\(String(mode, radix: 8))")
            try Self.write(Self.structurallyValidPayload(), to: file)
            try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: file.path)
            #expect(Self.openFile(file.path).status == 0, "mode \(String(mode, radix: 8))")
        }
    }

    @Test func refusesAFileWritableByGroupOrOthers() throws {
        let dir = try Self.makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        for mode in [0o620, 0o602, 0o666, 0o777] {
            let file = dir.appendingPathComponent("mode.\(String(mode, radix: 8))")
            try Self.write(Self.structurallyValidPayload(), to: file)
            try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: file.path)
            let result = Self.openFile(file.path)
            #expect(result.status == -27, "mode \(String(mode, radix: 8))")
            #expect(result.untouched, "mode \(String(mode, radix: 8))")
        }
    }

    @Test func acceptsARootOwnedFileForAnAdministratorDeployment() throws {
        // A test can't create a root-owned file without sudo, so this uses
        // one the OS ships: root-owned, 0444, one link. It isn't a payload,
        // so it can't succeed -- but it must get past the ownership check
        // and fail on its size (-24), never as fileInsecure (-27).
        let path = "/System/Library/CoreServices/SystemVersion.plist"
        var info = stat()
        try #require(stat(path, &info) == 0, "\(path) missing")
        try #require(info.st_uid == 0 && info.st_mode & (S_IWGRP | S_IWOTH) == 0 && info.st_nlink == 1,
                     "\(path) is no longer root-owned, owner-writable only, single-link")
        try #require(info.st_size > off_t(Self.wrappedLength), "\(path) is no longer larger than a payload")

        #expect(Self.openFile(path).status == -24)
    }

    @Test func refusesAFileWithMoreThanOneHardLink() throws {
        // A second name for the same inode could have been created by anyone
        // with write access to some directory and read access to an older
        // payload -- the replay the check exists to catch. The link is
        // refused through either name.
        let dir = try Self.makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let original = dir.appendingPathComponent("ingest.key")
        try Self.write(Self.structurallyValidPayload(), to: original)
        #expect(Self.openFile(original.path).status == 0)

        let alias = dir.appendingPathComponent("alias.key")
        try FileManager.default.linkItem(at: original, to: alias)
        #expect(Self.openFile(original.path).status == -27)
        #expect(Self.openFile(alias.path).status == -27)

        // Removing the extra link restores the file.
        try FileManager.default.removeItem(at: alias)
        #expect(Self.openFile(original.path).status == 0)
    }

    @Test(.timeLimit(.minutes(1)))
    func refusesAFIFOWithoutBlocking() throws {
        let dir = try Self.makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let fifo = dir.appendingPathComponent("ingest.fifo")
        #expect(mkfifo(fifo.path, 0o600) == 0)

        // No writer ever opens the FIFO: a blocking open would hang here.
        #expect(Self.openFile(fifo.path).status == -21)
    }

    // MARK: - Arguments and buffer sizing

    @Test func reportsRequiredCapacityBeforeOpeningTheFile() {
        // The path does not exist, yet the answer is -2, not -19: sizing is
        // checked first, so a sizing call never touches the filesystem.
        let result = Self.openFile("/nonexistent/hkdfguard/ingest.key", bufferCapacity: Int32(Self.wrappedLength - 1))
        #expect(result.status == -2)
        #expect(result.outLen == Int32(Self.wrappedLength))
    }

    @Test func nullPointersAreReportedNotDereferenced() {
        var out = [UInt8](repeating: 0, count: 1024)
        var outLen: Int32 = 1024

        out.withUnsafeMutableBufferPointer { outBuf in
            #expect(hkdfguard_open_file(pathPtr: nil, outPtr: outBuf.baseAddress, outLen: &outLen) == -1)
            #expect(outLen == 0, "outLen must still be written")
            outLen = 1024
            #expect(hkdfguard_open_file(pathPtr: "/tmp/x", outPtr: nil, outLen: &outLen) == -1)
            #expect(hkdfguard_open_file(pathPtr: "/tmp/x", outPtr: outBuf.baseAddress, outLen: nil) == -1)
        }
    }
}
