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
///   -32 = fileNotFound, -33 = fileAccessDenied,
///   -34 = fileIO, -35 = fileTooShort, -36 = fileTooLong,
///   -37 = fileUnprotectedKey, -38 = fileMalformed, -39 = fileInsecure
///   (the shared HkdfGuard status table; see hkdfguard.h).
///
/// `hkdfguard_open_file` never touches the keychain or the Secure Enclave,
/// so unlike `HkdfGuardNativeMacOSWrapUnwrapTests` this suite runs anywhere,
/// CI and VMs included. The round trip through a real KEK
/// (`wrapWriteOpenFileThenUnwrapRecoversOriginalDEK`) lives in that suite.
@Suite
struct HkdfGuardOpenFileTests {

    private static let wrappedLength = 125 // 32 fingerprint + 1 suite + 32 salt + 12 nonce + 32 ct + 16 tag

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

    /// A payload that passes every structural check: a non-zero fingerprint,
    /// the supported suite byte, and random salt, nonce, ciphertext and tag.
    /// It would fail the AEAD at unwrap, which is not `hkdfguard_open_file`'s
    /// concern.
    private static func structurallyValidPayload() -> [UInt8] {
        var payload = (0..<32).map { _ in UInt8.random(in: 1 ... .max) }
        payload.append(0x01) // suite id
        payload += (0..<(32 + 12 + 32 + 16)).map { _ in UInt8.random(in: .min ... .max) }
        return payload
    }

    private static func openFile(
        _ path: String,
        bufferCapacity: Int32 = 1024
    ) -> (status: Int32, bytes: [UInt8], outLen: Int32, zeroed: Bool) {
        var out = [UInt8](repeating: 0xA5, count: Int(bufferCapacity))
        var outLen = bufferCapacity
        let status = path.withCString { pathCStr in
            out.withUnsafeMutableBufferPointer { outBuf in
                hkdfguard_open_file(pathPtr: pathCStr, outPtr: outBuf.baseAddress!, outLen: &outLen)
            }
        }
        // `zeroed`: on failure the whole declared capacity is cleared (as on
        // Linux), so no byte of a rejected file -- or the marker -- remains.
        return (status, Array(out.prefix(Int(max(outLen, 0)))), outLen, out.allSatisfy { $0 == 0 })
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
            #expect(result.status == -35, "length \(length)")
            #expect(result.outLen == 1024, "length \(length): *out_len left as the caller set it")
            #expect(result.zeroed, "length \(length): out must be zeroed")
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
            #expect(result.status == -36, "extra \(extra)")
            #expect(result.outLen == 1024, "extra \(extra): *out_len left as the caller set it")
            #expect(result.zeroed, "extra \(extra)")
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
            #expect(result.status == -37, "\(name)")
            #expect(result.outLen == 1024, "\(name): *out_len left as the caller set it")
            #expect(result.zeroed, "\(name): a plaintext key must never reach the caller's buffer")
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
            #expect(Self.openFile(file.path).status == -35, "\(name)")
        }
    }

    @Test func theDetectorsEdgeCasesMatchLinuxAndWindows() {
        // The same cases as the Linux build's
        // the_detector_s_edge_cases_match_the_windows_build and the Windows
        // build's "detector:" checks, so all three agree on every one.
        let b64 = Data(repeating: 0, count: 32).base64EncodedString() // "AAAA...A="
        let prefix42 = String(b64.prefix(42))
        func plain(_ s: String) -> Bool { looksLikePlaintextDek(ArraySlice(Array(s.utf8))) }
        #expect(plain(String(repeating: " ", count: 30) + b64 + String(repeating: "\n", count: 22)), "96 bytes in all")
        #expect(!plain(String(repeating: " ", count: 31) + b64 + String(repeating: "\n", count: 22)), "nothing over 96 bytes")
        #expect(!plain(prefix42 + "B="), "unused trailing bits set")
        #expect(plain(prefix42 + "E="), "trailing bits zero")
        #expect(plain("+" + String(b64.dropFirst().prefix(41)) + "A"), "43 characters, standard alphabet")
        #expect(!plain("+" + String(b64.dropFirst().prefix(40)) + "-A"), "mixed alphabets")
        #expect(!plain(prefix42 + "=="), "\"==\"")
        #expect(!plain(b64 + "="), "an extra '='")
        #expect(!plain("\u{0B}" + b64), "vertical tab is not trimmed")
        #expect(plain("\u{0C}" + b64 + "\u{0C}"), "form feed is")
        #expect(!plain(""), "empty")
        #expect(!plain(String(repeating: " ", count: 50)), "only whitespace")
        #expect(plain(String(repeating: "F", count: 64)), "64 uppercase hex digits")
        #expect(!plain(String(repeating: "a", count: 63) + "g"), "one character not hex")
        #expect(!plain(String(repeating: "a", count: 32) + "\n" + String(repeating: "a", count: 32)), "whitespace inside")
        #expect(plain(String(repeating: "_", count: 42) + "w"), "URL-safe, unpadded, canonical")
        #expect(looksLikePlaintextDek(ArraySlice([UInt8](repeating: 0, count: 32))), "any 32 raw bytes")
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
        #expect(result.status == -38)
        #expect(result.zeroed)
    }

    @Test func acceptsAnyBytesAfterTheHeader() throws {
        // Salt, nonce and ciphertext are random by design: with a good
        // fingerprint and suite byte, all-zero or all-0xFF bodies are
        // structurally fine. Only unwrap, with the KEK, can judge them.
        let dir = try Self.makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        for fill: UInt8 in [0x00, 0xFF] {
            let file = dir.appendingPathComponent("body.\(fill)")
            var payload = Self.structurallyValidPayload()
            payload.replaceSubrange(33..<Self.wrappedLength, with: [UInt8](repeating: fill, count: Self.wrappedLength - 33))
            try Self.write(payload, to: file)
            #expect(Self.openFile(file.path).status == 0, "fill \(fill)")
        }
    }

    @Test func reportsAnUnknownSuiteByteAsMalformedAsOnLinuxAndWindows() throws {
        // A plausible payload (non-zero fingerprint) with a suite this build
        // doesn't implement. In a key file every format problem is -38, the
        // Linux and Windows answer; unwrap names the suite itself (-12).
        let dir = try Self.makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        for suite: UInt8 in [0x00, 0x02, 0xFF] {
            let file = dir.appendingPathComponent("suite.\(suite)")
            var payload = Self.structurallyValidPayload()
            payload[32] = suite
            try Self.write(payload, to: file)
            let result = Self.openFile(file.path)
            #expect(result.status == -38, "suite \(suite)")
            #expect(result.zeroed, "suite \(suite)")
        }
    }

    @Test func rejectsAnAllZeroPayloadLengthFile() throws {
        let dir = try Self.makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("zeros")
        try Self.write([UInt8](repeating: 0, count: Self.wrappedLength), to: file)

        #expect(Self.openFile(file.path).status == -38)
    }

    // MARK: - Path and file type

    @Test func aSizeProbeWithANullOutReportsTheSizeWithoutOpeningTheFile() {
        // As on Linux: `out = NULL, *out_len = 0` is -2 with 125, answered
        // before the path is opened -- so even a missing file gives the size.
        var len: Int32 = 0
        #expect(hkdfguard_open_file(pathPtr: "/nonexistent/hkdfguard/probe.key", outPtr: nil, outLen: &len) == -2)
        #expect(len == Int32(Self.wrappedLength))

        len = 200
        #expect(hkdfguard_open_file(pathPtr: "/nonexistent/hkdfguard/probe.key", outPtr: nil, outLen: &len) == -1, "NULL out with a positive capacity")
        #expect(len == 200, "*out_len left as the caller set it")

        var out = [UInt8](repeating: 0, count: 256)
        len = -1
        let rc = out.withUnsafeMutableBufferPointer { hkdfguard_open_file(pathPtr: "/nonexistent/hkdfguard/probe.key", outPtr: $0.baseAddress, outLen: &len) }
        #expect(rc == -1, "negative capacity")
        #expect(len == -1, "*out_len left as the caller set it")
    }

    @Test func zeroesTheDeclaredOutCapacityOnFailure() throws {
        // A missing file (-32) and a too-small buffer (-2): either way the
        // declared capacity is zeroed and nothing past it is touched.
        let dir = try Self.makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let missing = dir.appendingPathComponent("absent.key").path

        for (declared, status) in [(Int32(200), Int32(-32)), (Int32(100), Int32(-2))] {
            var out = [UInt8](repeating: 0xAA, count: 256)
            var outLen = declared
            let rc = out.withUnsafeMutableBufferPointer { buf in
                hkdfguard_open_file(pathPtr: missing, outPtr: buf.baseAddress, outLen: &outLen)
            }
            #expect(rc == status)
            #expect(out[0..<Int(declared)].allSatisfy { $0 == 0 }, "declared \(declared)")
            #expect(out[Int(declared)...].allSatisfy { $0 == 0xAA }, "declared \(declared)")
        }
    }

    @Test func reportsAMissingFileAsNotFound() throws {
        let dir = try Self.makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }

        #expect(Self.openFile(dir.appendingPathComponent("absent.key").path).status == -32)
        // An empty path names nothing to look for: an argument error, as on
        // Linux, not a missing file.
        #expect(Self.openFile("").status == -1)

        // A path that runs *through* a regular file: ENOTDIR.
        let file = dir.appendingPathComponent("ingest.key")
        try Self.write(Self.structurallyValidPayload(), to: file)
        #expect(Self.openFile(file.path + "/inner").status == -32)
    }

    @Test(.enabled(if: geteuid() != 0, "root bypasses file permissions"))
    func reportsAnUnreadableFileAsAccessDenied() throws {
        let dir = try Self.makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("ingest.key")
        try Self.write(Self.structurallyValidPayload(), to: file)
        try FileManager.default.setAttributes([.posixPermissions: 0o000], ofItemAtPath: file.path)

        #expect(Self.openFile(file.path).status == -33)
    }

    @Test func refusesASymlinkEvenToAValidPayload() throws {
        let dir = try Self.makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let target = dir.appendingPathComponent("ingest.key")
        try Self.write(Self.structurallyValidPayload(), to: target)
        let link = dir.appendingPathComponent("link.key")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)

        // Untrusted (-39), as Windows reports any link -- not an I/O error.
        let result = Self.openFile(link.path)
        #expect(result.status == -39)
        #expect(result.zeroed)
    }

    @Test func refusesADirectory() throws {
        let dir = try Self.makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }

        #expect(Self.openFile(dir.path).status == -34)
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
            #expect(result.status == -39, "mode \(String(mode, radix: 8))")
            #expect(result.zeroed, "mode \(String(mode, radix: 8))")
        }
    }

    @Test func acceptsARootOwnedFileForAnAdministratorDeployment() throws {
        // A test can't create a root-owned file without sudo, so this uses
        // one the OS ships: root-owned, 0444, one link. It isn't a payload,
        // so it can't succeed -- but it must get past the ownership check
        // and fail on its size (-36), never as fileInsecure (-39).
        let path = "/System/Library/CoreServices/SystemVersion.plist"
        var info = stat()
        try #require(stat(path, &info) == 0, "\(path) missing")
        try #require(info.st_uid == 0 && info.st_mode & (S_IWGRP | S_IWOTH) == 0 && info.st_nlink == 1,
                     "\(path) is no longer root-owned, owner-writable only, single-link")
        try #require(info.st_size > off_t(Self.wrappedLength), "\(path) is no longer larger than a payload")

        #expect(Self.openFile(path).status == -36)
    }

    // MARK: - Folders above the file (as on Linux)

    @Test func refusesAFileInAFolderGroupOrOthersCanWrite() throws {
        // Someone who can write the folder can rename a file of their choosing
        // over the key, whatever the key's own mode.
        let dir = try Self.makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("ingest.key")
        try Self.write(Self.structurallyValidPayload(), to: file)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        #expect(Self.openFile(file.path).status == 0)

        for mode in [0o775, 0o757, 0o777] {
            try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: dir.path)
            let result = Self.openFile(file.path)
            #expect(result.status == -39, "folder mode \(String(mode, radix: 8))")
            #expect(result.zeroed, "folder mode \(String(mode, radix: 8))")
        }
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: dir.path)
        #expect(Self.openFile(file.path).status == 0, "a 0755 folder is trusted again")
    }

    @Test func acceptsAFileInAStickyWorldWritableFolder() throws {
        // /tmp-style: only an entry's owner (or the folder's) can rename or
        // remove it, and the file's owner is checked.
        let dir = try Self.makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("ingest.key")
        try Self.write(Self.structurallyValidPayload(), to: file)
        try FileManager.default.setAttributes([.posixPermissions: 0o1777], ofItemAtPath: dir.path)
        #expect(Self.openFile(file.path).status == 0)
    }

    @Test func refusesAFileBelowAWritableAncestorFolder() throws {
        // Not just the file's own folder: anyone who can write an ancestor
        // can rename the whole subtree aside and put their own in its place.
        let dir = try Self.makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let sub = dir.appendingPathComponent("sub", isDirectory: true)
        try FileManager.default.createDirectory(at: sub, withIntermediateDirectories: false)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: sub.path)
        let file = sub.appendingPathComponent("ingest.key")
        try Self.write(Self.structurallyValidPayload(), to: file)
        #expect(Self.openFile(file.path).status == 0)

        try FileManager.default.setAttributes([.posixPermissions: 0o777], ofItemAtPath: dir.path)
        #expect(Self.openFile(file.path).status == -39)
        try FileManager.default.setAttributes([.posixPermissions: 0o1777], ofItemAtPath: dir.path)
        #expect(Self.openFile(file.path).status == 0, "a sticky ancestor protects the subtree beneath it")
    }

    @Test func checksTheFolderTheFileIsIn_notTheSpellingOfThePath() throws {
        // A symlinked folder in the path resolves (as /tmp and /etc do); the
        // folders checked are the ones the opened file really sits in.
        let dir = try Self.makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let real = dir.appendingPathComponent("real", isDirectory: true)
        try FileManager.default.createDirectory(at: real, withIntermediateDirectories: false)
        let file = real.appendingPathComponent("ingest.key")
        try Self.write(Self.structurallyValidPayload(), to: file)
        let alias = dir.appendingPathComponent("alias")
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: real)
        let viaAlias = alias.appendingPathComponent("ingest.key").path

        #expect(Self.openFile(viaAlias).status == 0)
        try FileManager.default.setAttributes([.posixPermissions: 0o777], ofItemAtPath: real.path)
        #expect(Self.openFile(viaAlias).status == -39, "the real folder is writable, whatever the path says")
    }

    @Test func acceptsAFileWithMoreThanOneHardLinkAsOnLinuxAndWindows() throws {
        // A second name only matters if it could put an older payload where
        // the service looks, and that takes an entry in the key's own folder
        // -- which the folder checks limit to the owner and root. Accepted
        // through either name, as on the other platforms.
        let dir = try Self.makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let original = dir.appendingPathComponent("ingest.key")
        let payload = Self.structurallyValidPayload()
        try Self.write(payload, to: original)

        let alias = dir.appendingPathComponent("alias.key")
        try FileManager.default.linkItem(at: original, to: alias)
        for path in [original.path, alias.path] {
            let result = Self.openFile(path)
            #expect(result.status == 0, "\(path)")
            #expect(result.bytes == payload, "\(path)")
        }

        // But a link name in a folder others can write is still refused,
        // by the folder rule.
        try FileManager.default.setAttributes([.posixPermissions: 0o777], ofItemAtPath: dir.path)
        #expect(Self.openFile(alias.path).status == -39)
    }

    @Test(.timeLimit(.minutes(1)))
    func refusesAFIFOWithoutBlocking() throws {
        let dir = try Self.makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let fifo = dir.appendingPathComponent("ingest.fifo")
        #expect(mkfifo(fifo.path, 0o600) == 0)

        // No writer ever opens the FIFO: a blocking open would hang here.
        #expect(Self.openFile(fifo.path).status == -34)
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
            #expect(outLen == 1024, "*out_len left as the caller set it, as on Linux")
            outLen = 1024
            #expect(hkdfguard_open_file(pathPtr: "/tmp/x", outPtr: nil, outLen: &outLen) == -1)
            #expect(hkdfguard_open_file(pathPtr: "/tmp/x", outPtr: outBuf.baseAddress, outLen: nil) == -1)
        }
    }
}
