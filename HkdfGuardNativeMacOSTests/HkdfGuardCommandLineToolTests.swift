//
//  HkdfGuardCommandLineToolTests.swift
//  HkdfGuardNativeMacOSTests
//

import Testing
import Foundation
import CryptoKit
@testable import HkdfGuardNativeMacOS

/// Exercises the actual `hkdfguard` command-line tool
/// (`../hkdfguard-cli`) as a real, separate process — not the
/// `hkdfguard_wrap_dek` C ABI function it calls internally, which every
/// other test in this suite already covers directly. This is the one
/// place that answers "does the tool a real caller runs actually work,
/// end to end": argument parsing, file I/O (permissions, `--force`
/// overwrite/secure-delete), exit codes, and — the scenario this file
/// exists for — that a DEK wrapped by that separate process can be
/// recovered by *application code* (the library, called directly here the
/// same way a consuming app would) via `hkdfguard_unwrap_dek`.
///
/// That last point works correctly (byte-for-byte, proven below) but is
/// NOT free of ceremony: the CLI tool and this test host are
/// two differently-signed binaries, and the Secure Enclave key the CLI
/// creates is persisted as an ordinary keychain item with no shared
/// `kSecAttrAccessGroup` (see the comment in
/// HkdfGuardNativeMacOS.entitlements on why not). Its default ACL
/// therefore trusts exactly the creating binary's code signature, or
/// falls back to an interactive macOS keychain-access prompt for anyone
/// else, as the system log (`log show`) shows:
///
///   securityd: displaying keychain prompt for .../xctest(59175);
///   ACL: ThresholdAclSubject(1 of 2)
///     [CodeSignatureAclSubject[path: .../hkdfguard]]
///     [KeychainPromptAclSubject(desc: com.hkdfguard.tests.cli.roundtrip.1)]
///
/// The first time this test host (as a new, not-yet-approved requesting
/// identity) reads a keychain item the CLI created, that prompt appears
/// and blocks until a human clicks it, indefinitely in an unattended run.
/// Once approved, that identity stays trusted: later CLI→app round trips
/// complete in seconds. See `interactiveKeychainAccessEnabled` below for
/// how the affected tests are gated because of this.
///
/// This is not just a test-environment quirk: it's the same prompt a real
/// differently-signed consuming application would hit in production
/// unwrapping a DEK the CLI provisioned, absent a shared keychain-access-
/// group entitlement between them.
///
/// Separately: the *first* CLI subprocess launch after a freshly built
/// binary takes several seconds longer than later launches —
/// Gatekeeper's first-launch check, most likely — independent of the
/// keychain-prompt issue above. `toolsBuilt`
/// below deliberately builds the tool once, up front, outside of any
/// individual test's timing, so that one-time cost doesn't land on
/// whichever test happens to run first.
///
/// `.serialized` for the same Secure Enclave/SEP concurrency reason as
/// `HkdfGuardNativeMacOSWrapUnwrapTests`. Every test that actually
/// exercises the CLI's wrap path is additionally gated on
/// `SecureEnclave.isAvailable` — see `secureEnclaveAvailableComment` below
/// — so this suite degrades gracefully to just its pure argument-handling
/// tests (`cliRejects*`, `cliPrintsUsageOnHelp`) on a CI/VM runner with no
/// real Secure Enclave, rather than failing outright.
@Suite(.serialized)
struct HkdfGuardCommandLineToolTests {

    // MARK: - Opt-in gate for tests that cross the CLI -> application-code
    // keychain boundary

    /// Set `HKDFGUARD_RUN_INTERACTIVE_KEYCHAIN_TESTS=1` in the test host's
    /// environment to opt into the tests below gated on this. In Xcode,
    /// enable the (pre-defined, disabled) variable in the scheme's Test
    /// action. From the command line, `xcodebuild` forwards only variables
    /// prefixed `TEST_RUNNER_` to the test process, prefix stripped:
    /// `TEST_RUNNER_HKDFGUARD_RUN_INTERACTIVE_KEYCHAIN_TESTS=1 xcodebuild test ...`.
    /// A bare `HKDFGUARD_RUN_INTERACTIVE_KEYCHAIN_TESTS=1 xcodebuild test`
    /// is silently dropped and the tests stay skipped. They're excluded
    /// from the default run — rather than left enabled and just slow —
    /// because the *first* time they run against a keychain/machine that
    /// hasn't already approved this test host's identity, macOS shows a
    /// real interactive keychain-access prompt (see the suite's doc
    /// comment above) that nothing here can dismiss automatically. Be
    /// present to click "Allow" once when running these; after that
    /// approval, reruns are fast.
    private static let interactiveKeychainAccessEnabled =
        ProcessInfo.processInfo.environment["HKDFGUARD_RUN_INTERACTIVE_KEYCHAIN_TESTS"] != nil

    private static let interactiveKeychainAccessComment: Comment =
        "requires a one-time interactive keychain approval; set HKDFGUARD_RUN_INTERACTIVE_KEYCHAIN_TESTS=1 to opt in — see this suite's doc comment"

    /// The cross-process round trips below read, in *this* process, a KEK
    /// the bare SwiftPM-built CLI created. That CLI is a plain Mach-O with
    /// no entitlements, so it always runs in legacy keychain mode; the read
    /// can only succeed if this host runs in legacy mode too (the two
    /// keychains are disjoint). Hosted in the entitled HkdfGuardNativeMacOSTestHost app
    /// these are skipped, and the data-protection equivalent -- provisioned
    /// by the *bundled* CLI, no prompt involved -- runs instead (see the end
    /// of this file).
    private static let legacyCrossProcessRoundTripEnabled =
        interactiveKeychainAccessEnabled && hkdfguardKeychainMode == .legacy

    /// Every test below that actually runs the CLI's wrap path needs a
    /// real Secure Enclave — on a CI/VM runner (`SecureEnclave.isAvailable
    /// == false`), the CLI itself would fail with `enclaveUnavailable` before
    /// any of what these tests are checking even comes into play. Folded
    /// into `interactiveKeychainAccessEnabled` below for the four tests
    /// that need both gates; used alone for the one default-running test
    /// that wraps but doesn't cross the interactive-keychain boundary.
    private static let secureEnclaveAvailableComment: Comment =
        "requires a real Secure Enclave — not available on CI/VM runners; run on real Mac hardware before committing/requesting a build"

    private static let interactiveKeychainAndSecureEnclaveComment: Comment =
        "requires a real Secure Enclave and a one-time interactive keychain approval; set HKDFGUARD_RUN_INTERACTIVE_KEYCHAIN_TESTS=1 on real Mac hardware to opt in — see this suite's doc comment"

    // MARK: - Locating and building the tool this suite exercises

    private static let dekLength = 32

    // This file lives at <repo>/HkdfGuardNativeMacOSTests/…, so
    // its own path is a stable way to find the repo root regardless of
    // where/how the test bundle itself is run from — the same technique
    // hkdfguard-cli/Package.swift uses to locate the dylib it
    // links against.
    private static let repoRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent() // HkdfGuardNativeMacOSTests/
        .deletingLastPathComponent() // repo root

    private static let dylibPath = repoRoot
        .appendingPathComponent("build/Release/libhkdfguard.dylib")
        .path

    private static let cliPackageDir = repoRoot
        .appendingPathComponent("hkdfguard-cli")

    private static let cliExecutablePath = repoRoot
        .appendingPathComponent("hkdfguard-cli/.build/release/hkdfguard")
        .path

    private struct ToolBuildError: Error, CustomStringConvertible {
        let description: String
    }

    /// Starts reading `handle` to EOF on a background queue immediately and
    /// returns a closure that blocks until that read completes and hands
    /// back the bytes. Used by `run` below so both of a child's output
    /// pipes are drained *while* it runs — see the comment there.
    private static func drainInBackground(_ handle: FileHandle) -> () -> Data {
        let done = DispatchGroup()
        var data = Data()
        done.enter()
        DispatchQueue.global(qos: .utility).async {
            data = handle.readDataToEndOfFile()
            done.leave()
        }
        return {
            done.wait()
            return data
        }
    }

    /// Runs `arguments` to completion and returns its exit code plus
    /// captured stdout/stderr.
    ///
    /// Both pipes are drained concurrently, from the moment the child
    /// starts, and `waitUntilExit` is only called after that draining is
    /// under way. Reading a pipe only *after* the child exits deadlocks as
    /// soon as the child writes more than the pipe's buffer (64KB on
    /// macOS): the child blocks in `write(2)` waiting for a reader, the
    /// parent blocks in `waitUntilExit` waiting for the child. The CLI
    /// itself writes a line or two, but this same helper also launches
    /// `xcodebuild` and `swift build` (via `buildDylib`/
    /// `buildCLI`), whose logs are far larger than 64KB: read late, the
    /// nested Release-dylib build would block in `write` on a full pipe
    /// with this test host parked in `waitUntilExit`, and the CLI tests
    /// would appear to hang.
    ///
    /// `stdin`, when given, is written to the child's standard input and
    /// then closed; otherwise the child's stdin is /dev/null, so no child
    /// can ever block waiting on this test host's inherited stdin.
    @discardableResult
    private static func run(_ executableURL: URL, _ arguments: [String], currentDirectory: URL? = nil, stdin: Data? = nil) throws -> (exitCode: Int32, stdout: String, stderr: String) {
        let process = Process()
        process.executableURL = executableURL
        process.arguments = arguments
        if let currentDirectory {
            process.currentDirectoryURL = currentDirectory
        }

        // Process() inherits the parent's environment by default — here,
        // the xctest host's. Xcode points that host's DYLD_LIBRARY_PATH/
        // DYLD_FRAMEWORK_PATH at its own DerivedData Products directory so
        // the test bundle can find HkdfGuardNativeMacOS.framework;
        // dyld's DYLD_LIBRARY_PATH override resolves @rpath/<leaf-name>
        // against *any* matching filename found there first, ahead of a
        // launched executable's own embedded rpath. A stale, same-named
        // dylib in that DerivedData directory would be silently loaded by
        // the CLI subprocess launched below instead of the current one at
        // build/Release, so the test would exercise the wrong library.
        // Stripping DYLD_* here removes that whole class of environment
        // leakage regardless of what DerivedData happens to contain.
        var environment = ProcessInfo.processInfo.environment
        for key in environment.keys where key.hasPrefix("DYLD_") {
            environment.removeValue(forKey: key)
        }
        process.environment = environment
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        let stdinPipe: Pipe?
        if stdin != nil {
            stdinPipe = Pipe()
            process.standardInput = stdinPipe
        } else {
            stdinPipe = nil
            process.standardInput = FileHandle.nullDevice
        }

        try process.run()
        let stdoutBytes = drainInBackground(stdoutPipe.fileHandleForReading)
        let stderrBytes = drainInBackground(stderrPipe.fileHandleForReading)
        if let stdinPipe, let stdin {
            // Small payloads only (a base64 DEK), well under the pipe buffer,
            // so this write can't block; close signals EOF to the child.
            stdinPipe.fileHandleForWriting.write(stdin)
            try? stdinPipe.fileHandleForWriting.close()
        }
        process.waitUntilExit()

        let stdout = String(data: stdoutBytes(), encoding: .utf8) ?? ""
        let stderr = String(data: stderrBytes(), encoding: .utf8) ?? ""
        return (process.terminationStatus, stdout, stderr)
    }

    /// Builds the Release dylib and the CLI once per test run. Always
    /// invoked, not skipped when binaries already exist: both builds are
    /// incremental, and skipping them would let the suite silently test a
    /// stale CLI that doesn't match its source.
    private static let toolsBuilt: Result<Void, Error> = Result {
        try buildDylib()
        try buildCLI()
    }

    private static func buildDylib() throws {
        let result = try run(
            URL(fileURLWithPath: "/usr/bin/xcodebuild"),
            [
                "-project", repoRoot.appendingPathComponent("HkdfGuardNativeMacOS.xcodeproj").path,
                "-target", "HkdfGuardNativeMacOSDylib",
                "-configuration", "Release",
                "build"
            ],
            currentDirectory: repoRoot
        )
        guard result.exitCode == 0, FileManager.default.fileExists(atPath: dylibPath) else {
            throw ToolBuildError(description: "failed to build HkdfGuardNativeMacOSDylib (exit \(result.exitCode)):\n\(result.stdout)\n\(result.stderr)")
        }
    }

    /// Builds the `hkdfguard` executable via SwiftPM. Must run
    /// after `buildDylib()` — the tool links against the dylib's fixed path
    /// at build time (see its own Package.swift) as well as at run time via
    /// `-rpath`.
    private static func buildCLI() throws {
        let result = try run(
            URL(fileURLWithPath: "/usr/bin/env"),
            ["swift", "build", "-c", "release"],
            currentDirectory: cliPackageDir
        )
        guard result.exitCode == 0, FileManager.default.fileExists(atPath: cliExecutablePath) else {
            throw ToolBuildError(description: "failed to build hkdfguard (exit \(result.exitCode)):\n\(result.stdout)\n\(result.stderr)")
        }
    }

    /// Runs the built `hkdfguard` executable with
    /// `arguments`, building it first if needed.
    private static func runCLI(_ arguments: [String], stdin: Data? = nil) throws -> (exitCode: Int32, stdout: String, stderr: String) {
        try toolsBuilt.get()
        return try run(URL(fileURLWithPath: cliExecutablePath), arguments, stdin: stdin)
    }

    /// Runs the CLI's `provision` command for `service` and asserts it
    /// succeeded. Since `wrap` never creates a KEK, every test that expects
    /// a wrap to succeed calls this first -- exactly as a real operator must.
    private static func provision(service: String, sourceLocation: SourceLocation = #_sourceLocation) throws {
        let result = try runCLI(["provision", "--service-name", service])
        #expect(result.exitCode == 0, "provision failed: \(result.stderr)", sourceLocation: sourceLocation)
    }

    // MARK: - Helpers shared with the round-trip/tamper tests

    private static func randomDEK() -> [UInt8] {
        (0..<dekLength).map { _ in UInt8.random(in: .min ... .max) }
    }

    /// `dek` as the CLI's `--dek-stdin` input: base64 plus the trailing
    /// newline `echo`/a piped tool would send. The CLI deliberately has no
    /// way to take a DEK as an argument, so this is how every test that
    /// supplies its own DEK feeds it in.
    private static func base64Stdin(_ dek: [UInt8]) -> Data {
        Data((Data(dek).base64EncodedString() + "\n").utf8)
    }

    /// Deletes the keychain item for `service`, via the `security` CLI
    /// rather than a direct `SecItemDelete` call. This isn't stylistic:
    /// every KEK this suite needs to clean up was created by the separate,
    /// differently-signed `hkdfguard` process, and a plain
    /// `SecItemDelete` from *this* process (the test host) against such an
    /// item fails outright, returning errSecInvalidOwnerEdit (-25244, "Invalid attempt
    /// to change the owner of this item"), silently, no interactive prompt
    /// at all (unlike the *read* path — see the suite's doc comment).
    /// `/usr/bin/security`, an Apple-signed platform binary, has broader
    /// keychain trust than an arbitrary third-party process and reliably
    /// succeeds where `SecItemDelete` here does not.
    private static func deleteKEK(service: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        // Lowercased to match what the library actually stored (it
        // normalizes `service` before any keychain use).
        process.arguments = ["delete-generic-password", "-s", service.lowercased(), "-a", hkdfguardKeychainAccount]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try? process.run()
        process.waitUntilExit()
    }

    /// Whether a keychain item exists for `service`. Via the `security` CLI
    /// for the same cross-process reason as `deleteKEK` above; this is an
    /// attribute lookup only (no `-w`/`-g`, so the item's data is never
    /// read and no ACL prompt can be triggered).
    private static func kekItemExists(service: String) -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        process.arguments = ["find-generic-password", "-s", service.lowercased(), "-a", hkdfguardKeychainAccount]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try? process.run()
        process.waitUntilExit()
        return process.terminationStatus == 0
    }

    /// The "application code" side of every test below: calls
    /// `hkdfguard_unwrap_dek` directly, exactly the way any Swift/C/other
    /// consumer of this library would, on whatever bytes the CLI tool
    /// wrote to disk.
    private static func unwrapInApplicationCode(
        _ wrapped: [UInt8],
        service: String
    ) -> (status: Int32, dek: [UInt8]) {
        var out = [UInt8](repeating: 0, count: 1024)
        var outLen = Int32(out.count)
        let status = service.withCString { serviceCStr in
            wrapped.withUnsafeBufferPointer { wrappedBuf in
                out.withUnsafeMutableBufferPointer { outBuf in
                    hkdfguard_unwrap_dek(
                        servicePtr: serviceCStr,
                        wrappedPtr: wrappedBuf.baseAddress!,
                        wrappedLen: Int32(wrapped.count),
                        outPtr: outBuf.baseAddress!,
                        outLen: &outLen
                    )
                }
            }
        }
        return (status, Array(out.prefix(Int(max(outLen, 0)))))
    }

    /// Writes `contents` to `path` as a `--dek-file` the CLI accepts: a
    /// regular file owned by this user, mode 0600 (the Linux tool's rule).
    private static func writeDekFile(_ contents: Data, to path: String, mode: Int = 0o600) throws {
        try contents.write(to: URL(fileURLWithPath: path))
        try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: path)
    }

    /// A temp file path under the system temp directory, not yet created.
    private static func makeTempFilePath() -> String {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("hkdfguard-cli-test-\(UUID().uuidString).bin")
            .path
    }

    // MARK: - Round trip: CLI wraps, application code decrypts

    @Test(.enabled(if: legacyCrossProcessRoundTripEnabled && SecureEnclave.isAvailable, interactiveKeychainAndSecureEnclaveComment))
    func cliWrappedDekIsRecoveredByApplicationCode() throws {
        let service = "com.hkdfguard.tests.cli.roundtrip"
        defer { Self.deleteKEK(service: service) }

        let dek = Self.randomDEK()
        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }

        try Self.provision(service: service)
        let result = try Self.runCLI(
            ["wrap", "--key-file-path", keyFilePath, "--service-name", service, "--dek-stdin"],
            stdin: Self.base64Stdin(dek)
        )
        #expect(result.exitCode == 0, "CLI failed: \(result.stderr)")
        #expect(FileManager.default.fileExists(atPath: keyFilePath))

        let wrapped = try Array(Data(contentsOf: URL(fileURLWithPath: keyFilePath)))
        let recovered = Self.unwrapInApplicationCode(wrapped, service: service)
        #expect(recovered.status == 0)
        #expect(recovered.dek == dek)
    }

    @Test(.enabled(if: SecureEnclave.isAvailable, secureEnclaveAvailableComment))
    func cliWrappedFileHasExpectedLengthAndPermissions() throws {
        let service = "com.hkdfguard.tests.cli.file.attributes"
        defer { Self.deleteKEK(service: service) }

        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }

        try Self.provision(service: service)
        let result = try Self.runCLI(
            ["wrap", "-kf", keyFilePath, "-sn", service, "--dek-stdin"],
            stdin: Self.base64Stdin(Self.randomDEK())
        )
        #expect(result.exitCode == 0, "CLI failed: \(result.stderr)")

        let attributes = try FileManager.default.attributesOfItem(atPath: keyFilePath)
        let permissions = (attributes[.posixPermissions] as? NSNumber)?.intValue
        #expect(permissions == 0o600)

        let wrapped = try Data(contentsOf: URL(fileURLWithPath: keyFilePath))
        #expect(wrapped.count == 125) // 32-byte KEK fingerprint + 1-byte suite id + 32-byte salt + 12-byte nonce + 32-byte ciphertext + 16-byte tag
    }

    // MARK: - hkdfguard_open_file against the CLI's own files

    /// `hkdfguard_open_file` on `path`, with a 1024-byte buffer.
    private static func openFile(_ path: String) -> (status: Int32, bytes: [UInt8]) {
        var out = [UInt8](repeating: 0, count: 1024)
        var outLen: Int32 = 1024
        let status = path.withCString { pathCStr in
            out.withUnsafeMutableBufferPointer { outBuf in
                hkdfguard_open_file(pathPtr: pathCStr, outPtr: outBuf.baseAddress!, outLen: &outLen)
            }
        }
        return (status, Array(out.prefix(Int(max(outLen, 0)))))
    }

    @Test(.enabled(if: SecureEnclave.isAvailable, secureEnclaveAvailableComment))
    func cliWrappedFileIsReadByOpenFile() throws {
        // The file format contract between the CLI (writer) and the library
        // (reader): whatever `wrap` writes -- 0600, fsynced, 125 bytes --
        // hkdfguard_open_file accepts byte for byte.
        let service = "com.hkdfguard.tests.cli.openfile"
        defer { Self.deleteKEK(service: service) }

        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }

        try Self.provision(service: service)
        let result = try Self.runCLI(
            ["wrap", "-kf", keyFilePath, "-sn", service, "--dek-stdin"],
            stdin: Self.base64Stdin(Self.randomDEK())
        )
        #expect(result.exitCode == 0, "CLI failed: \(result.stderr)")

        let opened = Self.openFile(keyFilePath)
        #expect(opened.status == 0)
        #expect(opened.bytes == Array(try Data(contentsOf: URL(fileURLWithPath: keyFilePath))))
    }

    @Test func cliDekInputFileIsReportedAsUnprotectedByOpenFile() throws {
        // The mistake hkdfguard_open_file's -37 exists for: an application
        // pointed at the plaintext DEK file given to `wrap --dek-file`
        // (base64 plus a newline) instead of the wrapped key file `wrap`
        // wrote. Needs no enclave: the plaintext file is never wrapped here.
        let dekFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: dekFilePath) }
        try Self.base64Stdin(Self.randomDEK()).write(to: URL(fileURLWithPath: dekFilePath))

        let opened = Self.openFile(dekFilePath)
        #expect(opened.status == -37) // fileUnprotectedKey
        #expect(opened.bytes.allSatisfy { $0 == 0 }, "no byte of a plaintext key may reach the caller")
    }

    // MARK: - File handling: refuses to clobber, --force overwrites correctly

    @Test(.enabled(if: legacyCrossProcessRoundTripEnabled && SecureEnclave.isAvailable, interactiveKeychainAndSecureEnclaveComment))
    func cliRefusesToOverwriteWithoutForce() throws {
        let service = "com.hkdfguard.tests.cli.no.overwrite"
        defer { Self.deleteKEK(service: service) }

        let firstDek = Self.randomDEK()
        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }

        try Self.provision(service: service)
        let firstResult = try Self.runCLI(
            ["wrap", "--key-file-path", keyFilePath, "--service-name", service, "--dek-stdin"],
            stdin: Self.base64Stdin(firstDek)
        )
        #expect(firstResult.exitCode == 0, "CLI failed: \(firstResult.stderr)")

        let secondResult = try Self.runCLI(
            ["wrap", "--key-file-path", keyFilePath, "--service-name", service, "--dek-stdin"],
            stdin: Self.base64Stdin(Self.randomDEK())
        )
        #expect(secondResult.exitCode != 0)

        // The original file, and the DEK it wraps, must be untouched.
        let wrapped = try Array(Data(contentsOf: URL(fileURLWithPath: keyFilePath)))
        let recovered = Self.unwrapInApplicationCode(wrapped, service: service)
        #expect(recovered.status == 0)
        #expect(recovered.dek == firstDek)
    }

    @Test(.enabled(if: legacyCrossProcessRoundTripEnabled && SecureEnclave.isAvailable, interactiveKeychainAndSecureEnclaveComment))
    func cliForceOverwritesWithNewDek() throws {
        let service = "com.hkdfguard.tests.cli.force.overwrite"
        defer { Self.deleteKEK(service: service) }

        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }

        try Self.provision(service: service)
        let firstResult = try Self.runCLI(
            ["wrap", "--key-file-path", keyFilePath, "--service-name", service, "--dek-stdin"],
            stdin: Self.base64Stdin(Self.randomDEK())
        )
        #expect(firstResult.exitCode == 0, "CLI failed: \(firstResult.stderr)")

        let secondDek = Self.randomDEK()
        let secondResult = try Self.runCLI(
            ["wrap", "--key-file-path", keyFilePath, "--service-name", service, "--dek-stdin", "--force"],
            stdin: Self.base64Stdin(secondDek)
        )
        #expect(secondResult.exitCode == 0, "CLI --force failed: \(secondResult.stderr)")

        let wrapped = try Array(Data(contentsOf: URL(fileURLWithPath: keyFilePath)))
        let recovered = Self.unwrapInApplicationCode(wrapped, service: service)
        #expect(recovered.status == 0)
        #expect(recovered.dek == secondDek)
    }

    // MARK: - Input validation, via the real CLI's own argument handling

    @Test func cliRejectsNonBase64Dek() throws {
        let service = "com.hkdfguard.tests.cli.bad.dek"
        defer { Self.deleteKEK(service: service) } // only needed if the assertion below fails
        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }

        let result = try Self.runCLI(
            ["wrap", "--key-file-path", keyFilePath, "--service-name", service, "--dek-stdin"],
            stdin: Data("not-valid-base64!!\n".utf8)
        )
        #expect(result.exitCode == 1)
        #expect(result.stderr.contains("not valid base64"), "stderr: \(result.stderr)")
        #expect(!FileManager.default.fileExists(atPath: keyFilePath))
        // A rejected invocation must have no persistent side effects: the
        // DEK is validated before any KEK is provisioned, so a typo leaves
        // no Secure Enclave key or keychain item behind.
        #expect(!Self.kekItemExists(service: service), "a rejected --dek must not provision a KEK")
    }

    @Test func cliRejectsWrongLengthDek() throws {
        let service = "com.hkdfguard.tests.cli.short.dek"
        defer { Self.deleteKEK(service: service) }
        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }

        let result = try Self.runCLI(
            ["wrap", "--key-file-path", keyFilePath, "--service-name", service, "--dek-stdin"],
            stdin: Self.base64Stdin([UInt8](repeating: 0, count: 16))
        )
        #expect(result.exitCode == 1)
        #expect(result.stderr.contains("exactly 32 bytes"), "stderr: \(result.stderr)")
        #expect(!FileManager.default.fileExists(atPath: keyFilePath))
        #expect(!Self.kekItemExists(service: service), "a rejected --dek must not provision a KEK")
    }

    // MARK: - --force never follows symlinks or touches non-regular files

    @Test func cliForceRefusesToOverwriteThroughSymlink() throws {
        // A link planted at <key-file-path> must not redirect the
        // destructive overwrite passes onto whatever it points at. Refused
        // before any Secure Enclave/keychain work, so no KEK appears either.
        let service = "com.hkdfguard.tests.cli.force.symlink"
        defer { Self.deleteKEK(service: service) }
        let targetPath = Self.makeTempFilePath()
        let linkPath = Self.makeTempFilePath()
        defer {
            try? FileManager.default.removeItem(atPath: linkPath)
            try? FileManager.default.removeItem(atPath: targetPath)
        }
        let original = Data("do not destroy me".utf8)
        try original.write(to: URL(fileURLWithPath: targetPath))
        try FileManager.default.createSymbolicLink(atPath: linkPath, withDestinationPath: targetPath)

        let result = try Self.runCLI(
            ["wrap", "--key-file-path", linkPath, "--service-name", service, "--dek-stdin", "--force"],
            stdin: Self.base64Stdin(Self.randomDEK())
        )
        #expect(result.exitCode == 1)
        #expect(result.stderr.contains("symbolic link"), "stderr: \(result.stderr)")

        let targetAfter = try Data(contentsOf: URL(fileURLWithPath: targetPath))
        #expect(targetAfter == original)
        #expect((try? FileManager.default.destinationOfSymbolicLink(atPath: linkPath)) == targetPath)
        #expect(!Self.kekItemExists(service: service))
    }

    @Test(.enabled(if: SecureEnclave.isAvailable, secureEnclaveAvailableComment))
    func cliForceRefusesToOverwriteThroughHardLink() throws {
        // The hard-link twin of the symlink case: O_NOFOLLOW can't see a
        // hard link, and it is a regular file, so only the link count
        // reveals that the overwrite passes would destroy another file.
        let service = "com.hkdfguard.tests.cli.force.hardlink"
        defer { Self.deleteKEK(service: service) }
        let targetPath = Self.makeTempFilePath()
        let linkPath = Self.makeTempFilePath()
        defer {
            try? FileManager.default.removeItem(atPath: linkPath)
            try? FileManager.default.removeItem(atPath: targetPath)
        }
        let original = Data("do not destroy me".utf8)
        try original.write(to: URL(fileURLWithPath: targetPath))
        #expect(link(targetPath, linkPath) == 0)

        // Provisioned, so the wrap itself would succeed: only the link-count
        // check stands between this command and the overwrite passes.
        try Self.provision(service: service)

        let result = try Self.runCLI(
            ["wrap", "--key-file-path", linkPath, "--service-name", service, "--dek-stdin", "--force"],
            stdin: Self.base64Stdin(Self.randomDEK())
        )
        #expect(result.exitCode == 1)
        #expect(result.stderr.contains("hard links"), "stderr: \(result.stderr)")

        #expect(try Data(contentsOf: URL(fileURLWithPath: targetPath)) == original)
        #expect(try Data(contentsOf: URL(fileURLWithPath: linkPath)) == original, "the link must not have been removed")
    }

    @Test func cliForceRefusesNonRegularFile() throws {
        let service = "com.hkdfguard.tests.cli.force.fifo"
        defer { Self.deleteKEK(service: service) }
        let fifoPath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: fifoPath) }
        #expect(mkfifo(fifoPath, 0o600) == 0)

        let result = try Self.runCLI(
            ["wrap", "--key-file-path", fifoPath, "--service-name", service, "--dek-stdin", "--force"],
            stdin: Self.base64Stdin(Self.randomDEK())
        )
        #expect(result.exitCode == 1)
        #expect(result.stderr.contains("not a regular file"), "stderr: \(result.stderr)")

        var st = stat()
        #expect(lstat(fifoPath, &st) == 0)
        #expect((st.st_mode & S_IFMT) == S_IFIFO, "the FIFO must still be there, untouched")
        #expect(!Self.kekItemExists(service: service))
    }

    @Test func cliRejectsMissingRequiredArguments() throws {
        let result = try Self.runCLI(["wrap", "--service-name", "com.hkdfguard.tests.cli.missing.args"])
        #expect(result.exitCode == 2) // argument-parsing failure, distinct from a runtime failure
        #expect(result.stderr.contains("--key-file-path"))
    }

    @Test func cliPrintsUsageOnHelp() throws {
        let result = try Self.runCLI(["--help"])
        #expect(result.exitCode == 0)
        #expect(result.stderr.localizedCaseInsensitiveContains("usage"))
        #expect(result.stderr.contains("provision"))
        #expect(result.stderr.contains("wrap"))
        #expect(result.stderr.contains("--key-file-path"))
        #expect(result.stderr.contains("--dek-stdin"))
        #expect(result.stderr.contains("--dek-file"))
        #expect(!result.stderr.contains("--dek|"), "usage must not advertise a --dek argument")
        #expect(!result.stderr.contains("--generate"), "usage must not advertise DEK generation")
        #expect(result.stderr.contains("--group|-g <name>"))
    }

    // MARK: - DEK sources: --dek-stdin, --dek-file (and the rejected --dek / --generate)

    @Test func cliTreatsGenerateAsAnUnknownArgument() throws {
        // There is no --generate: this tool wraps the pipeline's existing
        // DEK. -g is --group, as on Linux and Windows.
        let service = "com.hkdfguard.tests.cli.generate.rejected"
        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }

        let result = try Self.runCLI(["wrap", "--key-file-path", keyFilePath, "--service-name", service, "--dek-stdin", "--generate"])
        #expect(result.exitCode == 2, "exit \(result.exitCode), stderr: \(result.stderr)")
        #expect(result.stderr.contains("unrecognized argument for `wrap`: --generate"), "\(result.stderr)")
        #expect(!FileManager.default.fileExists(atPath: keyFilePath))
        #expect(!Self.kekItemExists(service: service))
    }

    // MARK: - --group (as on Linux)

    /// A group this user belongs to that --group accepts, if any: not one of
    /// the broad groups every account is in (staff, everyone, ...).
    private static func eligibleGroup() -> (gid: gid_t, name: String)? {
        let broad: Set<String> = ["wheel", "admin", "staff", "everyone", "localaccounts", "netaccounts", "nobody", "nogroup"]
        var gids = [gid_t](repeating: 0, count: 64)
        let count = getgroups(Int32(gids.count), &gids)
        guard count > 0 else { return nil }
        for gid in gids.prefix(Int(count)) where gid != 0 {
            if let entry = getgrgid(gid), let name = entry.pointee.gr_name.map({ String(cString: $0) }), !broad.contains(name) {
                return (gid, name)
            }
        }
        return nil
    }

    @Test func cliGroupRefusesBroadAndUnknownGroupsBeforeReadingTheDek() throws {
        // Refused while resolving --group, before any DEK is read or KEK
        // used: no stdin is supplied, and nothing is written.
        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }
        let service = "com.hkdfguard.tests.cli.group.refused"
        for group in ["staff", "everyone", "admin", "wheel", "0", "20"] {
            let result = try Self.runCLI(["wrap", "-kf", keyFilePath, "-sn", service, "--dek-stdin", "-g", group])
            #expect(result.exitCode == 1, "\(group): \(result.stderr)")
            #expect(result.stderr.contains("is an over-broad group"), "\(group): \(result.stderr)")
        }
        let missing = try Self.runCLI(["wrap", "-kf", keyFilePath, "-sn", service, "--dek-stdin", "--group", "hkdfguard-no-such-group"])
        #expect(missing.exitCode == 1)
        #expect(missing.stderr.contains("does not name a group on this host"), "\(missing.stderr)")
        #expect(!FileManager.default.fileExists(atPath: keyFilePath))
    }

    @Test func cliGroupParsing() throws {
        let keyFilePath = Self.makeTempFilePath()
        let service = "com.hkdfguard.tests.cli.group.parse"
        var result = try Self.runCLI(["wrap", "-kf", keyFilePath, "-sn", service, "--dek-stdin", "--group"])
        #expect(result.exitCode == 2 && result.stderr.contains("--group requires a value"), "\(result.stderr)")
        result = try Self.runCLI(["wrap", "-kf", keyFilePath, "-sn", service, "--dek-stdin", "-g", ""])
        #expect(result.exitCode == 2 && result.stderr.contains("--group must not be empty"), "\(result.stderr)")
        result = try Self.runCLI(["wrap", "-kf", keyFilePath, "-sn", service, "--dek-stdin", "-g", "a", "--group", "a"])
        #expect(result.exitCode == 2 && result.stderr.contains("give --group at most once"), "\(result.stderr)")
        result = try Self.runCLI(["provision", "-sn", service, "-g", "a"])
        #expect(result.exitCode == 2 && result.stderr.contains("-g is not valid for `provision`; it belongs to `wrap`"), "\(result.stderr)")
    }

    @Test func cliRefusesAFlagValueThatStartsWithADash() throws {
        // A forgotten value must not swallow the next flag: `-kf --force`
        // would otherwise write a key file named "--force" and drop --force.
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("hkdfguard.cli.dashvalue.\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: dir) }
        let keyFilePath = dir.appendingPathComponent("out.key").path
        let service = "com.hkdfguard.tests.cli.dash.value"
        let fp = String(repeating: "ab", count: 32)

        let cases: [[String]] = [
            ["wrap", "-kf", "--force", "-sn", service, "--dek-stdin"],
            ["wrap", "-kf", keyFilePath, "-sn", "-g", "--dek-stdin"],
            ["wrap", "-kf", keyFilePath, "-sn", service, "--dek-stdin", "-g", "-f"],
            ["wrap", "-kf", keyFilePath, "-sn", service, "--dek-file", "-fp", fp],
            ["wrap", "-kf", keyFilePath, "-sn", service, "--dek-stdin", "--fingerprint", "-f"],
            ["provision", "--service-name", "-h"],
            ["status", "-sn", "-sn"],
            ["retire", "-sn", service, "-fp", "--corrupt"],
        ]
        for argv in cases {
            let result = try Self.runCLI(argv)
            #expect(result.exitCode == 2, "\(argv): \(result.stderr)")
            #expect(result.stderr.contains("requires a value, but the next argument is"), "\(argv): \(result.stderr)")
        }
        #expect(try FileManager.default.contentsOfDirectory(atPath: dir.path).isEmpty, "nothing was written")
        #expect(!FileManager.default.fileExists(atPath: "--force"))

        // Flags themselves are unaffected, short or long, in any order.
        let ok = try Self.runCLI(["status", "-sn", service])
        #expect(!ok.stderr.contains("requires a value"), "\(ok.stderr)")
    }

    @Test(.enabled(if: SecureEnclave.isAvailable, secureEnclaveAvailableComment))
    func cliGroupWritesTheFile0640WithThatGroup() throws {
        guard let group = Self.eligibleGroup() else {
            // Every group this account is in is a broad one; nothing to grant.
            return
        }
        let service = "com.hkdfguard.tests.cli.group.write"
        defer { Self.deleteKEK(service: service) }
        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }
        try Self.provision(service: service)

        let result = try Self.runCLI(
            ["wrap", "-kf", keyFilePath, "-sn", service, "--dek-stdin", "-g", group.name],
            stdin: Self.base64Stdin(Self.randomDEK()))
        #expect(result.exitCode == 0, "\(result.stderr)")
        #expect(result.stdout.contains("owner read/write + \(group.name) read-only"), "\(result.stdout)")
        var info = stat()
        try #require(stat(keyFilePath, &info) == 0)
        #expect(info.st_mode & 0o777 == 0o640)
        #expect(info.st_gid == group.gid)
        #expect(info.st_uid == geteuid())
    }

    @Test(.enabled(if: SecureEnclave.isAvailable, secureEnclaveAvailableComment))
    func cliDekStdinWrapsTheSuppliedDek() throws {
        let service = "com.hkdfguard.tests.cli.dek.stdin"
        defer { Self.deleteKEK(service: service) }
        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }

        // Trailing newline on purpose: that's what `echo`/a piped tool sends.
        try Self.provision(service: service)
        let stdin = Data((Data(Self.randomDEK()).base64EncodedString() + "\n").utf8)
        let result = try Self.runCLI(["wrap", "--key-file-path", keyFilePath, "--service-name", service, "--dek-stdin"], stdin: stdin)
        #expect(result.exitCode == 0, "CLI failed: \(result.stderr)")
        #expect(!result.stderr.contains("could not lock"), "the DEK buffer's mlock must succeed; stderr: \(result.stderr)")
        let wrapped = try Data(contentsOf: URL(fileURLWithPath: keyFilePath))
        #expect(wrapped.count == 125)
    }

    @Test(.enabled(if: legacyCrossProcessRoundTripEnabled && SecureEnclave.isAvailable, interactiveKeychainAndSecureEnclaveComment))
    func cliDekStdinDekIsRecoveredByApplicationCode() throws {
        let service = "com.hkdfguard.tests.cli.dek.stdin.roundtrip"
        defer { Self.deleteKEK(service: service) }
        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }

        try Self.provision(service: service)
        let dek = Self.randomDEK()
        let stdin = Data((Data(dek).base64EncodedString() + "\n").utf8)
        let result = try Self.runCLI(["wrap", "--key-file-path", keyFilePath, "--service-name", service, "--dek-stdin"], stdin: stdin)
        #expect(result.exitCode == 0, "CLI failed: \(result.stderr)")

        let wrapped = try Array(Data(contentsOf: URL(fileURLWithPath: keyFilePath)))
        let recovered = Self.unwrapInApplicationCode(wrapped, service: service)
        #expect(recovered.status == 0)
        #expect(recovered.dek == dek)
    }

    @Test(.enabled(if: SecureEnclave.isAvailable, secureEnclaveAvailableComment))
    func cliDekFileWrapsTheSuppliedDek() throws {
        let service = "com.hkdfguard.tests.cli.dek.file"
        defer { Self.deleteKEK(service: service) }
        let keyFilePath = Self.makeTempFilePath()
        let dekFilePath = Self.makeTempFilePath()
        defer {
            try? FileManager.default.removeItem(atPath: keyFilePath)
            try? FileManager.default.removeItem(atPath: dekFilePath)
        }
        try Self.writeDekFile(Data((Data(Self.randomDEK()).base64EncodedString() + "\n").utf8), to: dekFilePath)

        try Self.provision(service: service)
        let result = try Self.runCLI(["wrap", "--key-file-path", keyFilePath, "--service-name", service, "--dek-file", dekFilePath])
        #expect(result.exitCode == 0, "CLI failed: \(result.stderr)")
        let wrapped = try Data(contentsOf: URL(fileURLWithPath: keyFilePath))
        #expect(wrapped.count == 125)
    }

    @Test func cliRejectsDekAsCommandLineArgument() throws {
        // There is deliberately no --dek|-d: a DEK on argv is visible via ps
        // and lands in shell history. It must be refused at argument-parsing
        // time (exit 2) with an explanation pointing at the supported
        // sources, before any Secure Enclave or keychain work.
        let service = "com.hkdfguard.tests.cli.dek.argument.rejected"
        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }

        for flag in ["--dek", "-d"] {
            let result = try Self.runCLI([
                "wrap",
                "--key-file-path", keyFilePath,
                "--service-name", service,
                flag, Data(Self.randomDEK()).base64EncodedString()
            ])
            #expect(result.exitCode == 2, "\(flag): exit \(result.exitCode), stderr: \(result.stderr)")
            #expect(result.stderr.contains("not supported"))
            #expect(result.stderr.contains("--dek-stdin"))
            #expect(!FileManager.default.fileExists(atPath: keyFilePath))
            #expect(!Self.kekItemExists(service: service))
        }
    }

    @Test func cliRejectsEmptyStdin() throws {
        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }

        let result = try Self.runCLI(["wrap", "--key-file-path", keyFilePath, "--service-name", "com.hkdfguard.tests.cli.empty.stdin", "--dek-stdin"], stdin: Data())
        #expect(result.exitCode == 1)
        #expect(result.stderr.contains("no data on standard input"))
        #expect(!FileManager.default.fileExists(atPath: keyFilePath))
        #expect(!Self.kekItemExists(service: "com.hkdfguard.tests.cli.empty.stdin"))
    }

    @Test(.enabled(if: SecureEnclave.isAvailable, secureEnclaveAvailableComment))
    func cliWrapWritesWhereThePathWasCheckedNotWhereALinkBeforeDotDotLeads() throws {
        // keys/link -> elsewhere/deep: to the kernel keys/link/.. is
        // `elsewhere`, while the folder check resolves `..` as text, to
        // `keys`. The CLI must write exactly there -- the Linux tool's
        // cli_wrap_writes_where_the_path_was_checked_not_where_a_link_before_dotdot_leads.
        let service = "com.hkdfguard.tests.cli.dotdot"
        defer { Self.deleteKEK(service: service) }
        try Self.provision(service: service)

        let base = FileManager.default.temporaryDirectory.appendingPathComponent("hkdfguard-dotdot-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: base) }
        let keys = base.appendingPathComponent("keys")
        let elsewhere = base.appendingPathComponent("elsewhere")
        try FileManager.default.createDirectory(at: elsewhere.appendingPathComponent("deep"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: keys, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: keys.appendingPathComponent("link"), withDestinationURL: elsewhere.appendingPathComponent("deep"))

        let result = try Self.runCLI(
            ["wrap", "-kf", keys.path + "/link/../wrapped.key", "-sn", service, "--dek-stdin"],
            stdin: Self.base64Stdin(Self.randomDEK())
        )
        #expect(result.exitCode == 0, "\(result.stderr)")
        #expect(FileManager.default.fileExists(atPath: keys.appendingPathComponent("wrapped.key").path), "written in the checked folder")
        #expect(!FileManager.default.fileExists(atPath: elsewhere.appendingPathComponent("wrapped.key").path), "nothing where the link leads")
    }

    @Test func cliForceRefusesAFileOverTheSizeCapAndLeavesItIntact() throws {
        // A wrapped key is 125 bytes; anything over 64 KiB at the key path
        // isn't one, and --force refuses it (as the Linux tool does) --
        // before any Secure Enclave or keychain work, so no KEK is needed.
        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }
        let original = Data(repeating: 0xAB, count: 64 * 1024 + 1)
        try original.write(to: URL(fileURLWithPath: keyFilePath))

        let result = try Self.runCLI(
            ["wrap", "-kf", keyFilePath, "-sn", "com.hkdfguard.tests.cli.force.overcap", "--dek-stdin", "--force"],
            stdin: Self.base64Stdin(Self.randomDEK())
        )
        #expect(result.exitCode == 1)
        #expect(result.stderr.contains("far larger than any wrapped key"), "stderr: \(result.stderr)")
        #expect(try Data(contentsOf: URL(fileURLWithPath: keyFilePath)) == original, "the file is left untouched")
    }

    @Test(.enabled(if: SecureEnclave.isAvailable, secureEnclaveAvailableComment))
    func cliForceOverwritesAFileUpToTheSizeCapBeforeReplacingIt() throws {
        // --force overwrites a file of up to 64 KiB (the Linux tool's cap; a
        // bigger one is refused, tested separately). A file of exactly
        // 64 KiB, the largest accepted, must be overwritten in full.
        //
        // The test holds its own descriptor on the old file before running
        // the CLI. An open descriptor is not a link (st_nlink stays 1, so
        // --force accepts the file), but it keeps the inode readable after
        // the CLI unlinks the name -- which is how the overwritten bytes are
        // inspected here.
        let service = "com.hkdfguard.tests.cli.force.atcap"
        defer { Self.deleteKEK(service: service) }
        try Self.provision(service: service)

        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }
        let size = 64 * 1024 // exactly the cap: accepted
        let original = Data(repeating: 0xAB, count: size)
        try original.write(to: URL(fileURLWithPath: keyFilePath))

        let held = open(keyFilePath, O_RDONLY)
        try #require(held >= 0)
        defer { close(held) }

        let result = try Self.runCLI(
            ["wrap", "-kf", keyFilePath, "-sn", service, "--dek-stdin", "--force"],
            stdin: Self.base64Stdin(Self.randomDEK())
        )
        #expect(result.exitCode == 0, "CLI --force failed: \(result.stderr)")

        // The replacement: a fresh 125-byte, 0600 file.
        #expect(try Data(contentsOf: URL(fileURLWithPath: keyFilePath)).count == 125)
        let attributes = try FileManager.default.attributesOfItem(atPath: keyFilePath)
        #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)

        // The old inode: unlinked, same length, every byte rewritten.
        var st = stat()
        #expect(fstat(held, &st) == 0)
        #expect(st.st_nlink == 0, "the old file must have been removed")
        #expect(Int(st.st_size) == size, "the overwrite must not grow or truncate the old file")
        let overwritten = FileHandle(fileDescriptor: held, closeOnDealloc: false)
        try overwritten.seek(toOffset: 0)
        let after = try #require(try overwritten.readToEnd())
        #expect(after.count == size)
        #expect(after.firstRange(of: Data(repeating: 0xAB, count: 64)) == nil,
                "a run of the original pattern survived the overwrite")
        // The last pass is a random one, over the whole file: its two halves
        // don't repeat each other, and its end isn't left zeroed.
        let half = size / 2
        #expect(after[0..<half] != after[half...])
        #expect(Data(after.suffix(1024)) != Data(repeating: 0, count: 1024), "the end of the file was not overwritten")
    }

    @Test func cliRejectsEmptyOrWhitespaceOnlyStdin() throws {
        // Empty, or nothing but the one tolerated trailing newline: no data.
        // Any other whitespace is input like any other (the Linux tool's
        // rule), so whitespace-only input is invalid base64.
        let cases: [(input: String, message: String)] = [
            ("", "no data on standard input"),
            ("\n", "no data on standard input"),
            ("\r\n", "no data on standard input"),
            (" \t\r\n\n", "not valid base64"),
        ]
        for (input, message) in cases {
            let keyFilePath = Self.makeTempFilePath()
            defer { try? FileManager.default.removeItem(atPath: keyFilePath) }

            let result = try Self.runCLI(
                ["wrap", "--key-file-path", keyFilePath, "--service-name", "com.hkdfguard.tests.cli.blank.stdin", "--dek-stdin"],
                stdin: Data(input.utf8)
            )
            #expect(result.exitCode == 1, "\(input.debugDescription)")
            #expect(result.stderr.contains(message), "\(input.debugDescription): \(result.stderr)")
            #expect(!FileManager.default.fileExists(atPath: keyFilePath))
        }
    }

    @Test func cliRejectsOversizedDekInputWithoutReadingItAll() throws {
        // The DEK reader uses one fixed-size buffer (so it never leaves
        // reallocated copies of the input behind); input past its limit is
        // refused outright rather than buffered.
        let keyFilePath = Self.makeTempFilePath()
        let dekFilePath = Self.makeTempFilePath()
        defer {
            try? FileManager.default.removeItem(atPath: keyFilePath)
            try? FileManager.default.removeItem(atPath: dekFilePath)
        }
        let oversized = Data(repeating: UInt8(ascii: "A"), count: 65) // the Linux tool's 64-byte limit, plus one
        try Self.writeDekFile(oversized, to: dekFilePath)

        let fromStdin = try Self.runCLI(
            ["wrap", "-kf", keyFilePath, "-sn", "com.hkdfguard.tests.cli.oversized.dek", "--dek-stdin"],
            stdin: oversized
        )
        #expect(fromStdin.exitCode == 1)
        #expect(fromStdin.stderr.contains("longer than 64 bytes"), "stderr: \(fromStdin.stderr)")

        let fromFile = try Self.runCLI(["wrap", "-kf", keyFilePath, "-sn", "com.hkdfguard.tests.cli.oversized.dek", "--dek-file", dekFilePath])
        #expect(fromFile.exitCode == 1)
        #expect(fromFile.stderr.contains("longer than 64 bytes"), "stderr: \(fromFile.stderr)")

        #expect(!FileManager.default.fileExists(atPath: keyFilePath))
        #expect(!Self.kekItemExists(service: "com.hkdfguard.tests.cli.oversized.dek"))
    }

    @Test func cliRejectsNonAsciiDekInputAsInvalidBase64() throws {
        // Not decoded as UTF-8 text first: bytes the base64 decoder cannot
        // accept are reported as invalid base64.
        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }
        let result = try Self.runCLI(
            ["wrap", "-kf", keyFilePath, "-sn", "com.hkdfguard.tests.cli.nonascii.dek", "--dek-stdin"],
            // Non-ASCII that isn't a byte-order mark: FF FE would be read as
            // UTF-16 and refused as such (tested on its own below).
            stdin: Data([0xC3, 0xA9, 0x41, 0x41, 0x0A]) // UTF-8 "é", then "AA\n"
        )
        #expect(result.exitCode == 1)
        #expect(result.stderr.contains("not valid base64"), "stderr: \(result.stderr)")
        #expect(!FileManager.default.fileExists(atPath: keyFilePath))
    }

    @Test(.enabled(if: SecureEnclave.isAvailable, secureEnclaveAvailableComment))
    func cliAcceptsDekInputWithOneTrailingCRLF() throws {
        let service = "com.hkdfguard.tests.cli.dek.crlf"
        defer { Self.deleteKEK(service: service) }
        try Self.provision(service: service)

        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }
        let padded = Data((Data(Self.randomDEK()).base64EncodedString() + "\r\n").utf8)
        let result = try Self.runCLI(["wrap", "-kf", keyFilePath, "-sn", service, "--dek-stdin"], stdin: padded)
        #expect(result.exitCode == 0, "CLI failed: \(result.stderr)")
        #expect(try Data(contentsOf: URL(fileURLWithPath: keyFilePath)).count == 125)
    }

    @Test func cliRejectsDekInputWithAnyPaddingButOneTrailingNewline() throws {
        // The Linux tool's rule: exactly one trailing "\n" or "\r\n" is
        // ignored; any other whitespace is part of the input and fails to
        // decode. Refused before the library is called, so nothing is created.
        let b64 = Data(Self.randomDEK()).base64EncodedString()
        for input in [" " + b64, "\t" + b64, b64 + " ", b64 + "\n\n", b64 + "\r\n\r\n", b64 + "\r", " " + b64 + "\n"] {
            let keyFilePath = Self.makeTempFilePath()
            defer { try? FileManager.default.removeItem(atPath: keyFilePath) }
            let result = try Self.runCLI(
                ["wrap", "-kf", keyFilePath, "-sn", "com.hkdfguard.tests.cli.dek.padding", "--dek-stdin"],
                stdin: Data(input.utf8)
            )
            #expect(result.exitCode == 1, "\(input.debugDescription)")
            #expect(result.stderr.contains("not valid base64"), "\(input.debugDescription): \(result.stderr)")
            #expect(!FileManager.default.fileExists(atPath: keyFilePath))
        }
    }

    @Test func cliAcceptsDekInputWithNoneOrOneTrailingNewline() throws {
        // Passes input parsing: whatever the wrap then reports for this
        // never-provisioned service, it is not about the DEK input.
        let b64 = Data(Self.randomDEK()).base64EncodedString()
        for input in [b64, b64 + "\n", b64 + "\r\n"] {
            let keyFilePath = Self.makeTempFilePath()
            defer { try? FileManager.default.removeItem(atPath: keyFilePath) }
            let result = try Self.runCLI(
                ["wrap", "-kf", keyFilePath, "-sn", "com.hkdfguard.tests.cli.dek.newline", "--dek-stdin"],
                stdin: Data(input.utf8)
            )
            #expect(!result.stderr.contains("--dek-stdin"), "\(input.debugDescription): \(result.stderr)")
        }
    }

    @Test func cliDekFileThatCannotBeOpenedIsReported() throws {
        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }
        let missing = Self.makeTempFilePath() // never created
        let result = try Self.runCLI(["wrap", "-kf", keyFilePath, "-sn", "com.hkdfguard.tests.cli.dek.file.missing", "--dek-file", missing])
        #expect(result.exitCode == 1)
        #expect(result.stderr.contains("--dek-file: failed to read"), "stderr: \(result.stderr)")
        #expect(!FileManager.default.fileExists(atPath: keyFilePath))
    }

    // MARK: --dek-file hardening (the Linux tool's read_dek_file rules)

    /// Runs `wrap --dek-file <dekFile>` against a never-provisioned service,
    /// so it can never write a key file or create a KEK. A refused DEK file
    /// is reported before the library is reached.
    private static func wrapWithDekFile(_ dekFile: String) throws -> (exitCode: Int32, stdout: String, stderr: String) {
        let keyFilePath = makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }
        let result = try runCLI(["wrap", "-kf", keyFilePath, "-sn", "com.hkdfguard.tests.cli.dek.file.rules", "--dek-file", dekFile])
        #expect(!FileManager.default.fileExists(atPath: keyFilePath))
        return result
    }

    // MARK: - DEK input encoding (as on Linux and Windows)

    @Test func cliSkipsAUtf8ByteOrderMarkAndRefusesUtf16() throws {
        let dek = Data(Self.randomDEK()).base64EncodedString()

        // A UTF-8 BOM (PowerShell, .NET) is skipped: the input decodes and
        // the run gets as far as the KEK lookup.
        let bomFile = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: bomFile) }
        try Self.writeDekFile(Data([0xEF, 0xBB, 0xBF]) + Data((dek + "\n").utf8), to: bomFile)
        let bom = try Self.wrapWithDekFile(bomFile)
        #expect(bom.exitCode == 1)
        #expect(!bom.stderr.contains("not valid base64") && !bom.stderr.contains("UTF-16"), "\(bom.stderr)")

        // UTF-16, either byte order: named as such, with the fix. Its text is
        // twice as long, so it is over the 64-byte limit -- the message must
        // still say UTF-16, not just "too long".
        for bomBytes in [Data([0xFF, 0xFE]), Data([0xFE, 0xFF])] {
            let utf16 = bomBytes + Data(dek.utf8.flatMap { bomBytes[0] == 0xFF ? [$0, 0] : [0, $0] })
            let file = Self.makeTempFilePath()
            defer { try? FileManager.default.removeItem(atPath: file) }
            try Self.writeDekFile(utf16, to: file)
            let result = try Self.wrapWithDekFile(file)
            #expect(result.exitCode == 1)
            #expect(result.stderr.contains("the DEK input is UTF-16 encoded"), "\(result.stderr)")

            // And a short UTF-16 input, under the limit, the same.
            let short = try Self.runCLI(
                ["wrap", "-kf", Self.makeTempFilePath(), "-sn", "com.hkdfguard.tests.cli.utf16", "--dek-stdin"],
                stdin: bomBytes + Data("AAAA".utf8))
            #expect(short.stderr.contains("the DEK input is UTF-16 encoded"), "\(short.stderr)")
        }
    }

    @Test func cliReportsMalformedBase64WithTheOneFixedMessage() throws {
        // The Linux and Windows tools' exact sentence: it names no character
        // or position, so a mistyped DEK never puts part of itself in a log.
        let dek = Data(Self.randomDEK()).base64EncodedString()
        for bad in [String(dek.dropLast()) + "*", "=" + dek.dropFirst(), String(dek.prefix(42)) + "B=", dek + "\n\n"] {
            let result = try Self.runCLI(
                ["wrap", "-kf", Self.makeTempFilePath(), "-sn", "com.hkdfguard.tests.cli.bad.base64", "--dek-stdin"],
                stdin: Data(bad.utf8))
            #expect(result.stderr.contains("the DEK input is not valid base64 (standard alphabet, padded, at most one trailing newline)"), "\(bad.debugDescription): \(result.stderr)")
            #expect(!result.stderr.contains(String(dek.prefix(8))), "the input must not be echoed")
        }
    }

    @Test func cliRefusesToReadTheDekFromATerminal() throws {
        // stdin is a pseudo-terminal: refused before anything is read.
        let master = posix_openpt(O_RDWR | O_NOCTTY)
        try #require(master >= 0)
        defer { close(master) }
        try #require(grantpt(master) == 0 && unlockpt(master) == 0)
        let slaveName = try #require(ptsname(master).map { String(cString: $0) })
        let slave = FileHandle(forUpdatingAtPath: slaveName)
        let terminal = try #require(slave)
        defer { try? terminal.close() }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: Self.cliExecutablePath)
        process.arguments = ["wrap", "-kf", Self.makeTempFilePath(), "-sn", "com.hkdfguard.tests.cli.tty", "--dek-stdin"]
        // As `run` does: no DYLD_* from the test host, so the CLI loads its
        // own library.
        process.environment = ProcessInfo.processInfo.environment.filter { !$0.key.hasPrefix("DYLD_") }
        let stderr = Pipe()
        process.standardInput = terminal
        process.standardOutput = Pipe()
        process.standardError = stderr
        try process.run()
        process.waitUntilExit()
        let message = String(decoding: stderr.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        #expect(process.terminationStatus == 1)
        #expect(message.contains("refusing to read the DEK from an interactive terminal"), "\(message)")
    }

    // MARK: - No symbolic link in the folders above a path (as on Linux)

    @Test func cliRefusesASymlinkedFolderAboveTheKeyFileOrTheDekFile() throws {
        let base = FileManager.default.temporaryDirectory.appendingPathComponent("hkdfguard-cli-link-\(UUID().uuidString)")
        let real = base.appendingPathComponent("real")
        let link = base.appendingPathComponent("link")
        try FileManager.default.createDirectory(at: real, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: base) }
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: real)

        // The key file: nothing is written through the link, and nothing in
        // the real folder.
        let viaLink = link.appendingPathComponent("out.key").path
        let wrap = try Self.runCLI(
            ["wrap", "-kf", viaLink, "-sn", "com.hkdfguard.tests.cli.folder.link", "--dek-stdin"],
            stdin: Self.base64Stdin(Self.randomDEK()))
        #expect(wrap.exitCode == 1)
        #expect(wrap.stderr.contains("is a symbolic link; the path must be a real path with no links in it"), "\(wrap.stderr)")
        #expect(!FileManager.default.fileExists(atPath: real.appendingPathComponent("out.key").path))

        // The DEK file: refused before it is opened.
        let dekFile = real.appendingPathComponent("dek.b64").path
        try Self.writeDekFile(Data(Data(Self.randomDEK()).base64EncodedString().utf8), to: dekFile)
        let viaLinkDek = try Self.wrapWithDekFile(link.appendingPathComponent("dek.b64").path)
        #expect(viaLinkDek.exitCode == 1)
        #expect(viaLinkDek.stderr.contains("is a symbolic link; the path must be a real path with no links in it"), "\(viaLinkDek.stderr)")

        // `..` after a link is resolved as text: link/../real/x is real/x,
        // which the kernel would otherwise reach through the link.
        let dotted = link.appendingPathComponent("..").appendingPathComponent("real").appendingPathComponent("dek.b64").path
        #expect(try Self.wrapWithDekFile(dotted).stderr.contains("symbolic link") == false, "a path whose folders are real after `..` is fine")
    }

    @Test func cliAcceptsMacOSsOwnRootOwnedLinksSuchAsTmp() throws {
        // /tmp -> private/tmp is root's link in a root-owned folder: allowed,
        // as is every test's temporary folder under /var.
        var st = stat()
        try #require(lstat("/tmp", &st) == 0 && st.st_mode & S_IFMT == S_IFLNK, "/tmp is no longer a link on this macOS")
        let path = "/tmp/hkdfguard-cli-tmp-\(UUID().uuidString).key"
        defer { try? FileManager.default.removeItem(atPath: path) }
        let result = try Self.runCLI(
            ["wrap", "-kf", path, "-sn", "com.hkdfguard.tests.cli.tmp.link", "--dek-stdin"],
            stdin: Self.base64Stdin(Self.randomDEK()))
        #expect(!result.stderr.contains("symbolic link"), "\(result.stderr)")
    }

    @Test func cliDekFileRefusesASymlink() throws {
        let target = Self.makeTempFilePath()
        let link = Self.makeTempFilePath()
        defer {
            try? FileManager.default.removeItem(atPath: target)
            try? FileManager.default.removeItem(atPath: link)
        }
        try Self.writeDekFile(Self.base64Stdin(Self.randomDEK()), to: target)
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: target)

        let result = try Self.wrapWithDekFile(link)
        #expect(result.exitCode == 1)
        #expect(result.stderr.contains("is a symlink; refusing to follow it"), "stderr: \(result.stderr)")
    }

    @Test func cliDekFileRefusesAFifoWithoutBlocking() throws {
        let fifo = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: fifo) }
        #expect(mkfifo(fifo, 0o600) == 0)

        // No writer ever opens the FIFO: without O_NONBLOCK the CLI would
        // hang in open(2) and this test with it.
        let result = try Self.wrapWithDekFile(fifo)
        #expect(result.exitCode == 1)
        #expect(result.stderr.contains("is not a regular file"), "stderr: \(result.stderr)")
    }

    @Test func cliDekFileRefusesADirectory() throws {
        let result = try Self.wrapWithDekFile(FileManager.default.temporaryDirectory.path)
        #expect(result.exitCode == 1)
        #expect(result.stderr.contains("is not a regular file"), "stderr: \(result.stderr)")
    }

    /// Gives `path` an access control entry with chmod(1), the way an
    /// administrator would: `chmod +a "<ace>" <path>`.
    private static func addACE(_ ace: String, to path: String) throws {
        let result = try run(URL(fileURLWithPath: "/bin/chmod"), ["+a", ace, path])
        try #require(result.exitCode == 0, "chmod +a failed: \(result.stderr)")
    }

    /// Whether `path` carries an access control list (its `ls -l` mode would
    /// end in `+`).
    private static func hasACL(_ path: String) -> Bool {
        guard let acl = acl_get_file(path, ACL_TYPE_EXTENDED) else { return false }
        acl_free(UnsafeMutableRawPointer(acl))
        return true
    }

    @Test func cliDekFileRefusesAFileWithAnAccessControlList() throws {
        // Mode 0600, but an ACL grants read to everyone: the mode-bit check
        // alone would accept it. Refused before the library is reached, so
        // no KEK is needed.
        let dekFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: dekFilePath) }
        try Self.writeDekFile(Self.base64Stdin(Self.randomDEK()), to: dekFilePath)
        try Self.addACE("group:everyone allow read", to: dekFilePath)
        try #require(Self.hasACL(dekFilePath))

        let result = try Self.wrapWithDekFile(dekFilePath)
        #expect(result.exitCode == 1)
        #expect(result.stderr.contains("has an access control list"), "stderr: \(result.stderr)")
    }

    @Test(.enabled(if: SecureEnclave.isAvailable, secureEnclaveAvailableComment))
    func cliWrapStripsAnACLInheritedFromTheKeyFilesFolder() throws {
        // A folder with an inheritable ACE passes it to every new file, and
        // neither the 0600 at creation nor fchmod removes it. The written key
        // file must carry no ACL, so "owner read/write" is true.
        let service = "com.hkdfguard.tests.cli.acl.inherit"
        defer { Self.deleteKEK(service: service) }
        try Self.provision(service: service)

        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hkdfguard-acl-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: dir) }
        try Self.addACE("group:everyone allow read,file_inherit", to: dir.path)
        let keyFilePath = dir.appendingPathComponent("wrapped.key").path

        let result = try Self.runCLI(["wrap", "-kf", keyFilePath, "-sn", service, "--dek-stdin"], stdin: Self.base64Stdin(Self.randomDEK()))
        #expect(result.exitCode == 0, "\(result.stderr)")
        #expect(!Self.hasACL(keyFilePath), "the inherited ACL must be stripped")
        let mode = (try FileManager.default.attributesOfItem(atPath: keyFilePath)[.posixPermissions] as? NSNumber)?.intValue
        #expect(mode == 0o600)
    }

    @Test func cliRefusesARelativeKeyPathWhenTheCurrentFolderIsGone() throws {
        // With the current folder deleted, FileManager's currentDirectoryPath
        // is "", which would turn "out.key" into "/out.key" -- at the root of
        // the filesystem, as root under sudo. The CLI must refuse instead.
        // The CLI is started through a shell that deletes its own cwd first.
        try Self.toolsBuilt.get() // started directly below, not through runCLI, so build it here
        let gone = FileManager.default.temporaryDirectory.appendingPathComponent("hkdfguard-gone-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: gone, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: gone) }

        let result = try Self.run(
            URL(fileURLWithPath: "/bin/sh"),
            ["-c", "cd \"$1\" && rmdir \"$1\" && exec \"$2\" wrap -kf out.key -sn com.hkdfguard.tests.cli.gone.cwd --dek-stdin", "sh", gone.path, Self.cliExecutablePath],
            stdin: Self.base64Stdin(Self.randomDEK())
        )
        #expect(result.exitCode == 1)
        #expect(result.stderr.contains("current folder can't be determined"), "stderr: \(result.stderr)")
        #expect(!FileManager.default.fileExists(atPath: "/out.key"), "nothing may be created at the filesystem root")
    }

    @Test func cliExitsNormallyWithTheStandardDescriptorsClosed() throws {
        // A daemon or job runner can start the CLI with descriptors 0-2
        // closed. Every message then has nowhere to go, but the exit code
        // must still be the ordinary one: FileHandle.standardError would
        // raise an uncatchable exception and abort (terminationStatus 6).
        try Self.toolsBuilt.get()
        for (arguments, expected) in [("--help", Int32(0)), ("status -sn 'bad!name'", 1), ("bogus", 2)] {
            let result = try Self.run(
                URL(fileURLWithPath: "/bin/sh"),
                ["-c", "exec \"$0\" \(arguments) <&- >&- 2>&-", Self.cliExecutablePath]
            )
            #expect(result.exitCode == expected, "\(arguments): exit \(result.exitCode)")
        }
    }

    @Test(.enabled(if: SecureEnclave.isAvailable, secureEnclaveAvailableComment))
    func cliLeavesNoPartialKeyFileWhenTheFileSizeLimitIsHit() throws {
        // With RLIMIT_FSIZE below a payload, the default SIGXFSZ would kill
        // the CLI mid-write and leave a truncated key file that blocks the
        // retry with EEXIST. The CLI ignores the signal, so the write fails
        // with EFBIG and the partial file is removed.
        let service = "com.hkdfguard.tests.cli.fsize.limit"
        defer { Self.deleteKEK(service: service) }
        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }
        try Self.provision(service: service)

        let result = try Self.run(
            URL(fileURLWithPath: "/bin/sh"),
            ["-c", "ulimit -f 0 && exec \"$0\" wrap -kf \"$1\" -sn \"$2\" --dek-stdin", Self.cliExecutablePath, keyFilePath, service],
            stdin: Self.base64Stdin(Self.randomDEK())
        )
        #expect(result.exitCode == 1, "exit \(result.exitCode): \(result.stderr)")
        #expect(result.stderr.contains("File too large"), "stderr: \(result.stderr)")
        #expect(!FileManager.default.fileExists(atPath: keyFilePath), "a partial key file was left behind")

        let retry = try Self.runCLI(["wrap", "-kf", keyFilePath, "-sn", service, "--dek-stdin"], stdin: Self.base64Stdin(Self.randomDEK()))
        #expect(retry.exitCode == 0, "retry after the failed write: \(retry.stderr)")
    }

    @Test func cliDekFileRefusesGroupOrOtherAccess() throws {
        for mode in [0o640, 0o604, 0o620, 0o602, 0o610, 0o644, 0o666] {
            let dekFilePath = Self.makeTempFilePath()
            defer { try? FileManager.default.removeItem(atPath: dekFilePath) }
            try Self.writeDekFile(Self.base64Stdin(Self.randomDEK()), to: dekFilePath, mode: mode)

            let result = try Self.wrapWithDekFile(dekFilePath)
            #expect(result.exitCode == 1, "mode \(String(mode, radix: 8))")
            #expect(result.stderr.contains("permissions are too broad"), "mode \(String(mode, radix: 8)): \(result.stderr)")
        }
    }

    @Test func cliDekFileAllowsRootOwnershipButStillChecksPermissions() throws {
        // /etc/hosts is root-owned and 0644. Root ownership is allowed, so it
        // must fail on its permissions, not its owner. (A file owned by some
        // other non-root user can't be made without root, so that branch is
        // not tested here, as on Linux.)
        let result = try Self.wrapWithDekFile("/etc/hosts")
        #expect(result.exitCode == 1)
        #expect(result.stderr.contains("permissions are too broad"), "stderr: \(result.stderr)")
        #expect(!result.stderr.contains("neither root nor"), "root ownership is allowed: \(result.stderr)")
    }

    @Test func cliDekFileAcceptsOwnerOnlyModes() throws {
        // 0600 and 0400 pass the file checks: whatever the wrap then reports
        // (no KEK for this never-provisioned service, or no Secure Enclave),
        // it is not about the --dek-file.
        for mode in [0o600, 0o400] {
            let dekFilePath = Self.makeTempFilePath()
            defer {
                chmod(dekFilePath, 0o600)
                try? FileManager.default.removeItem(atPath: dekFilePath)
            }
            try Self.writeDekFile(Self.base64Stdin(Self.randomDEK()), to: dekFilePath, mode: mode)

            let result = try Self.wrapWithDekFile(dekFilePath)
            #expect(!result.stderr.contains("--dek-file"), "mode \(String(mode, radix: 8)): \(result.stderr)")
        }
    }

    @Test func cliRejectsConflictingDekSources() throws {
        let keyFilePath = Self.makeTempFilePath()
        let result = try Self.runCLI([
            "wrap",
            "--key-file-path", keyFilePath,
            "--service-name", "com.hkdfguard.tests.cli.conflicting.sources",
            "--dek-stdin",
            "--dek-file", "/dev/null"
        ])
        #expect(result.exitCode == 2) // argument-parsing failure
        #expect(result.stderr.contains("give exactly one of --dek-stdin or --dek-file"), "\(result.stderr)")
        #expect(!FileManager.default.fileExists(atPath: keyFilePath))
    }

    @Test func cliRejectsMissingDekSource() throws {
        let keyFilePath = Self.makeTempFilePath()
        let result = try Self.runCLI(["wrap", "--key-file-path", keyFilePath, "--service-name", "com.hkdfguard.tests.cli.missing.source"])
        #expect(result.exitCode == 2)
        #expect(result.stderr.contains("missing required --dek-stdin or --dek-file <path>"), "\(result.stderr)")
        #expect(!FileManager.default.fileExists(atPath: keyFilePath))
    }

    // MARK: - provision / wrap

    @Test(.enabled(if: SecureEnclave.isAvailable, secureEnclaveAvailableComment))
    func cliProvisionCreatesKekAndIsIdempotent() throws {
        let service = "com.hkdfguard.tests.cli.provision.idempotent"
        defer { Self.deleteKEK(service: service) }
        #expect(!Self.kekItemExists(service: service))

        let first = try Self.runCLI(["provision", "--service-name", service])
        #expect(first.exitCode == 0, "provision failed: \(first.stderr)")
        #expect(first.stdout.contains("KEK provisioned for service \"\(service)\""), "\(first.stdout)")
        #expect(Self.kekItemExists(service: service))

        let second = try Self.runCLI(["provision", "-sn", service])
        #expect(second.exitCode == 0, "second provision failed: \(second.stderr)")
        // As on Linux and Windows: create_kek runs again and verifies the
        // existing KEK, rather than provision stopping at kek_exists.
        #expect(second.stdout.contains("KEK already provisioned for service \"\(service)\"; verified, nothing to do"), "\(second.stdout)")
        #expect(Self.kekItemExists(service: service))
    }

    @Test(.enabled(if: SecureEnclave.isAvailable, secureEnclaveAvailableComment))
    func cliWrapRefusesWithoutProvision() throws {
        // `wrap` must never create a KEK. Against a
        // never-provisioned service it fails, names the fix, and leaves
        // neither a keychain item nor an output file behind -- for every
        // DEK source.
        let service = "com.hkdfguard.tests.cli.wrap.unprovisioned"
        defer { Self.deleteKEK(service: service) }
        let dekFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: dekFilePath) }
        try Self.writeDekFile(Data((Data(Self.randomDEK()).base64EncodedString() + "\n").utf8), to: dekFilePath)

        let attempts: [(args: [String], stdin: Data?)] = [
            (["--dek-stdin"], Self.base64Stdin(Self.randomDEK())),
            (["--dek-file", dekFilePath], nil),
        ]
        for attempt in attempts {
            let keyFilePath = Self.makeTempFilePath()
            defer { try? FileManager.default.removeItem(atPath: keyFilePath) }

            let result = try Self.runCLI(
                ["wrap", "--key-file-path", keyFilePath, "--service-name", service] + attempt.args,
                stdin: attempt.stdin
            )
            #expect(result.exitCode == 1, "\(attempt.args): exit \(result.exitCode), stderr: \(result.stderr)")
            #expect(result.stderr.contains("no KEK exists"), "stderr: \(result.stderr)")
            #expect(result.stderr.contains("provision --service-name \(service)"), "stderr: \(result.stderr)")
            #expect(!FileManager.default.fileExists(atPath: keyFilePath))
            #expect(!Self.kekItemExists(service: service), "\(attempt.args): wrap must not have provisioned a KEK")
        }
    }

    @Test func cliProvisionRejectsInvalidServiceName() throws {
        let service = "com.hkdfguard.tests-provision-invalid"
        let result = try Self.runCLI(["provision", "--service-name", service])
        #expect(result.exitCode == 1)
        #expect(result.stderr.contains("alphanumeric"))
        #expect(!Self.kekItemExists(service: service))
    }

    @Test func cliRejectsLeadingAndConsecutiveDotsInServiceName() throws {
        // Same rule and messages as the Linux tool; rejected before the
        // library is called, so nothing is ever created.
        for (service, message) in [
            (".hidden", "must not start with '.'"),
            ("..", "must not start with '.'"),
            ("com..example", "must not contain consecutive dots"),
            ("com.example..", "must not contain consecutive dots"),
        ] {
            let result = try Self.runCLI(["provision", "--service-name", service])
            #expect(result.exitCode == 1, "\(service)")
            #expect(result.stderr.contains(message), "\(service): \(result.stderr)")
        }
    }

    @Test func cliRejectsMissingCommand() throws {
        let result = try Self.runCLI([])
        #expect(result.exitCode == 2)
        #expect(result.stderr.contains("missing subcommand: expected `provision`, `wrap`, `retire` or `status`"), "\(result.stderr)")
    }

    @Test func cliRejectsUnknownCommand() throws {
        let result = try Self.runCLI(["frobnicate", "--service-name", "com.hkdfguard.tests.cli.unknown.command"])
        #expect(result.exitCode == 2)
        #expect(result.stderr.contains("unknown subcommand \"frobnicate\""), "\(result.stderr)")
    }

    @Test func cliRejectsPositionalKeyFilePath() throws {
        // The key file path is not positional: a bare path is a usage
        // error that names --key-file-path, and nothing is written.
        let keyFilePath = Self.makeTempFilePath()
        let result = try Self.runCLI(["wrap", keyFilePath, "--service-name", "com.hkdfguard.tests.cli.positional.path", "--dek-stdin"])
        #expect(result.exitCode == 2)
        #expect(result.stderr.contains("--key-file-path"), "stderr: \(result.stderr)")
        #expect(!FileManager.default.fileExists(atPath: keyFilePath))
    }

    @Test func cliProvisionRejectsWrapOnlyFlags() throws {
        let result = try Self.runCLI(["provision", "--service-name", "com.hkdfguard.tests.cli.provision.extra", "--dek-stdin"])
        #expect(result.exitCode == 2)
        #expect(result.stderr.contains("--dek-stdin is not valid for `provision`; it belongs to `wrap`"), "\(result.stderr)")
    }

    @Test func cliRefusesEveryRepeatedFlag() throws {
        // A repeated flag is a usage error rather than the last value
        // winning -- the same rule and message as the Linux and Windows
        // tools. Refused while parsing, so nothing is read or written.
        let keyFilePath = Self.makeTempFilePath()
        let fp = String(repeating: "ab", count: 32)
        let svc = "com.hkdfguard.tests.cli.repeated"
        for (args, flag) in [
            (["wrap", "-kf", keyFilePath, "-kf", keyFilePath + ".b", "-sn", svc, "--dek-stdin"], "--key-file-path"),
            (["wrap", "-kf", keyFilePath, "-sn", svc, "--service-name", svc + ".b", "--dek-stdin"], "--service-name"),
            (["wrap", "-kf", keyFilePath, "-sn", svc, "--dek-stdin", "-f", "--force"], "--force"),
            (["wrap", "-kf", keyFilePath, "-sn", svc, "--dek-stdin", "-fp", fp, "--fingerprint", fp], "--fingerprint"),
            (["provision", "-sn", svc, "-sn", svc], "--service-name"),
            (["status", "-sn", svc, "-sn", svc], "--service-name"),
            (["retire", "-sn", svc, "-fp", fp, "-fp", fp], "--fingerprint"),
            (["retire", "-sn", svc, "--corrupt", "--corrupt"], "--corrupt"),
        ] {
            let result = try Self.runCLI(args)
            #expect(result.exitCode == 2, "\(args)")
            #expect(result.stderr.contains("give \(flag) at most once"), "\(args): \(result.stderr)")
        }
        #expect(!FileManager.default.fileExists(atPath: keyFilePath))
    }

    // MARK: - Data-protection mode: the bundled CLI provisions, the entitled host unwraps

    /// The bundled build of the CLI (`hkdfguard-app` target):
    /// the same main.swift inside an app bundle with an embedded provisioning
    /// profile and the test-only `com.hkdfguard.tests.keys` access group (its
    /// Debug/DebugHosted entitlements; Release ships `com.hkdfguard.keys`), which is
    /// what lets it run in data-protection mode. Built into the same
    /// products directory as the host app this bundle runs in.
    private static let bundledCLIPath = Bundle.main.bundleURL
        .deletingLastPathComponent()
        .appendingPathComponent("hkdfguard.app/Contents/MacOS/hkdfguard")
        .path

    private static let dataProtectionRoundTripEnabled =
        hkdfguardKeychainMode != .legacy && FileManager.default.fileExists(atPath: bundledCLIPath)

    /// Deletes a KEK item from the keychain *this process's mode* uses --
    /// the only way to clean up a data-protection item, which the
    /// legacy-only `security` tool used by `deleteKEK` cannot see.
    private static func deleteKEKInProcess(service: String) {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service.lowercased(),
            kSecAttrAccount as String: hkdfguardKeychainAccount,
            kSecAttrSynchronizable as String: false,
        ]
        switch hkdfguardKeychainMode {
        case .legacy:
            // Explicit false, not omitted -- see keychainItemAttributes in
            // HkdfGuardNativeMacOS.swift.
            query[kSecUseDataProtectionKeychain as String] = false
        case .dataProtection(let accessGroup):
            query[kSecUseDataProtectionKeychain as String] = true
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        SecItemDelete(query as CFDictionary)
    }

    @Test(.enabled(if: dataProtectionRoundTripEnabled && SecureEnclave.isAvailable, "requires the entitled HkdfGuardNativeMacOSTestHost and the bundled CLI (data-protection mode)"))
    func bundledCliProvisionsAndWrapsInDataProtectionModeAndEntitledHostUnwraps() throws {
        // The production topology end to end, with no interactive prompt:
        // a Team-signed, entitled provisioner (the bundled CLI) creates the
        // KEK and wraps a DEK in the shared access group; a different
        // Team-signed, entitled process (this host) unwraps it through the
        // library. securityd grants the access from the signed identities
        // alone -- the thing legacy mode can only do after a human clicks
        // Allow.
        let service = "com.hkdfguard.tests.cli.dataprotection.roundtrip"
        defer { Self.deleteKEKInProcess(service: service) }
        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }
        let cli = URL(fileURLWithPath: Self.bundledCLIPath)

        let provision = try Self.run(cli, ["provision", "--service-name", service])
        #expect(provision.exitCode == 0, "provision failed: \(provision.stderr)")
        #expect(provision.stdout.contains("keychain: data-protection"), "stdout: \(provision.stdout)")

        let dek = Self.randomDEK()
        let wrap = try Self.run(
            cli,
            ["wrap", "--key-file-path", keyFilePath, "--service-name", service, "--dek-stdin"],
            stdin: Self.base64Stdin(dek)
        )
        #expect(wrap.exitCode == 0, "wrap failed: \(wrap.stderr)")
        #expect(wrap.stdout.contains("keychain: data-protection"), "stdout: \(wrap.stdout)")

        let wrapped = try Array(Data(contentsOf: URL(fileURLWithPath: keyFilePath)))
        #expect(wrapped.count == 125)
        let recovered = Self.unwrapInApplicationCode(wrapped, service: service)
        #expect(recovered.status == 0, "unwrap in the entitled host failed with \(recovered.status)")
        #expect(recovered.dek == dek)

        // Disjoint keychains: the legacy login keychain (what the bare CLI
        // and the `security` tool see) must have no trace of this KEK.
        #expect(!Self.kekItemExists(service: service))
    }

    @Test(.enabled(if: dataProtectionRoundTripEnabled && SecureEnclave.isAvailable, "requires the entitled HkdfGuardNativeMacOSTestHost and the bundled CLI (data-protection mode)"))
    func bundledCliRetiresDataProtectionKek() throws {
        // The case retire exists for: a data-protection item is invisible to
        // Keychain Access and `security`, so only an entitled process can
        // remove it.
        let service = "com.hkdfguard.tests.cli.dataprotection.retire"
        defer { Self.deleteKEKInProcess(service: service) }
        let cli = URL(fileURLWithPath: Self.bundledCLIPath)

        let provision = try Self.run(cli, ["provision", "--service-name", service])
        #expect(provision.exitCode == 0, "provision failed: \(provision.stderr)")
        let fingerprint = try #require(Self.fingerprint(fromProvisionOutput: provision.stdout))
        #expect(Self.libraryReportsKek(service: service) == true)

        let status = try Self.run(cli, ["status", "--service-name", service])
        #expect(status.exitCode == 0, "status failed: \(status.stderr)")
        #expect(status.stdout.contains("keychain: data-protection"), "stdout: \(status.stdout)")
        #expect(Self.fingerprint(fromProvisionOutput: status.stdout) == fingerprint)

        let retire = try Self.run(cli, ["retire", "--service-name", service, "--fingerprint", fingerprint])
        #expect(retire.exitCode == 0, "retire failed: \(retire.stderr)")
        #expect(retire.stdout.contains("keychain: data-protection"), "stdout: \(retire.stdout)")
        #expect(Self.libraryReportsKek(service: service) == false)
    }

    @Test(.enabled(if: dataProtectionRoundTripEnabled && SecureEnclave.isAvailable, "requires the entitled HkdfGuardNativeMacOSTestHost and the bundled CLI (data-protection mode)"))
    func bundledCliRetiresCorruptDataProtectionItem() throws {
        // The case --corrupt exists for: a corrupt data-protection item is
        // invisible to Keychain Access and `security`, and has no
        // fingerprint for the --fingerprint path to confirm.
        let service = "com.hkdfguard.tests.cli.dataprotection.retire.corrupt"
        defer { Self.deleteKEKInProcess(service: service) }
        guard case .dataProtection(let accessGroup) = hkdfguardKeychainMode else { return }

        let item: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: hkdfguardKeychainAccount,
            kSecAttrSynchronizable as String: false,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrAccessGroup as String: accessGroup,
            kSecValueData as String: Data("not-a-key-blob".utf8),
        ]
        #expect(SecItemAdd(item as CFDictionary, nil) == errSecSuccess)
        var exists: Int32 = -1
        #expect(service.withCString { hkdfguard_kek_exists(servicePtr: $0, outExists: &exists) } == -19)

        let cli = URL(fileURLWithPath: Self.bundledCLIPath)
        let retire = try Self.run(cli, ["retire", "--service-name", service, "--corrupt"])
        #expect(retire.exitCode == 0, "retire --corrupt failed: \(retire.stderr)")
        #expect(retire.stdout.contains("keychain: data-protection"), "stdout: \(retire.stdout)")
        #expect(Self.libraryReportsKek(service: service) == false)
    }

    /// Whether the library, in this host's mode, sees a KEK for `service`.
    /// `nil` when the lookup itself failed.
    private static func libraryReportsKek(service: String) -> Bool? {
        var exists: Int32 = -1
        let status = service.withCString { hkdfguard_kek_exists(servicePtr: $0, outExists: &exists) }
        return status == 0 ? exists == 1 : nil
    }

    // MARK: - retire

    /// The 64-hex-character value from provision's "fingerprint: <hex>" line.
    private static func fingerprint(fromProvisionOutput stdout: String) -> String? {
        for line in stdout.split(separator: "\n") where line.hasPrefix("fingerprint: ") {
            let hex = line.dropFirst("fingerprint: ".count).prefix(64)
            return hex.count == 64 ? String(hex) : nil
        }
        return nil
    }

    @Test(.enabled(if: SecureEnclave.isAvailable, secureEnclaveAvailableComment))
    func cliRetireRequiresTheMatchingFingerprint() throws {
        let service = "com.hkdfguard.tests.cli.retire.roundtrip"
        defer { Self.deleteKEK(service: service) }

        let provision = try Self.runCLI(["provision", "--service-name", service])
        #expect(provision.exitCode == 0, "provision failed: \(provision.stderr)")
        let fingerprint = try #require(Self.fingerprint(fromProvisionOutput: provision.stdout), "stdout: \(provision.stdout)")

        // Re-provisioning reports the same KEK, by the same fingerprint.
        let again = try Self.runCLI(["provision", "--service-name", service])
        #expect(Self.fingerprint(fromProvisionOutput: again.stdout) == fingerprint)

        // One nibble off: refused, nothing deleted.
        let lastNibble = fingerprint.last == "0" ? "1" : "0"
        let wrong = String(fingerprint.dropLast()) + lastNibble
        let refused = try Self.runCLI(["retire", "--service-name", service, "--fingerprint", wrong])
        #expect(refused.exitCode == 1)
        #expect(refused.stderr.contains("fingerprint mismatch"), "stderr: \(refused.stderr)")
        #expect(Self.kekItemExists(service: service))

        // Exact match, supplied in uppercase: deleted.
        let retired = try Self.runCLI(["retire", "-sn", service, "-fp", fingerprint.uppercased()])
        #expect(retired.exitCode == 0, "retire failed: \(retired.stderr)")
        #expect(retired.stdout.contains("retired KEK"))
        #expect(!Self.kekItemExists(service: service))

        let secondRetire = try Self.runCLI(["retire", "--service-name", service, "--fingerprint", fingerprint])
        #expect(secondRetire.exitCode == 1)
        #expect(secondRetire.stderr.contains("nothing to retire"), "stderr: \(secondRetire.stderr)")
    }

    @Test(.enabled(if: SecureEnclave.isAvailable, secureEnclaveAvailableComment))
    func cliRetireWithoutKekReportsNothingToRetire() throws {
        let service = "com.hkdfguard.tests.cli.retire.unprovisioned"
        defer { Self.deleteKEK(service: service) }
        let result = try Self.runCLI(["retire", "--service-name", service, "--fingerprint", String(repeating: "ab", count: 32)])
        #expect(result.exitCode == 1)
        #expect(result.stderr.contains("nothing to retire"), "stderr: \(result.stderr)")
        #expect(!Self.kekItemExists(service: service))
    }

    // MARK: - wrap: prints, and can pin, the KEK fingerprint

    /// The 64-hex-character value from a "fingerprint: <hex>" line, whichever
    /// command printed it.
    private static func fingerprintLine(in stdout: String) -> String? {
        fingerprint(fromProvisionOutput: stdout)
    }

    @Test(.enabled(if: SecureEnclave.isAvailable, secureEnclaveAvailableComment))
    func cliWrapPrintsTheFingerprintOfTheKekItUsedAndAcceptsAMatchingPin() throws {
        let service = "com.hkdfguard.tests.cli.wrap.fingerprint.match"
        defer { Self.deleteKEK(service: service) }

        let provision = try Self.runCLI(["provision", "--service-name", service])
        #expect(provision.exitCode == 0, "provision failed: \(provision.stderr)")
        let fingerprint = try #require(Self.fingerprint(fromProvisionOutput: provision.stdout), "stdout: \(provision.stdout)")

        // Unpinned: the fingerprint is still printed, and it is exactly the
        // payload's own first 32 bytes.
        let unpinnedPath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: unpinnedPath) }
        let unpinned = try Self.runCLI(
            ["wrap", "-kf", unpinnedPath, "-sn", service, "--dek-stdin"],
            stdin: Self.base64Stdin(Self.randomDEK())
        )
        #expect(unpinned.exitCode == 0, "wrap failed: \(unpinned.stderr)")
        #expect(Self.fingerprintLine(in: unpinned.stdout) == fingerprint, "stdout: \(unpinned.stdout)")
        #expect(unpinned.stdout.contains("confirm it matches"), "stdout: \(unpinned.stdout)")
        #expect(unpinned.stderr.contains("not pinned to a KEK"), "a first wrap without --fingerprint warns; stderr: \(unpinned.stderr)")
        let payload = try Data(contentsOf: URL(fileURLWithPath: unpinnedPath))
        let embedded = payload.prefix(32).map { String(format: "%02x", $0) }.joined()
        #expect(embedded == fingerprint)

        // Pinned to the right KEK, supplied in uppercase: written and confirmed.
        let pinnedPath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: pinnedPath) }
        let pinned = try Self.runCLI(
            ["wrap", "-kf", pinnedPath, "-sn", service, "--dek-stdin", "-fp", fingerprint.uppercased()],
            stdin: Self.base64Stdin(Self.randomDEK())
        )
        #expect(pinned.exitCode == 0, "pinned wrap failed: \(pinned.stderr)")
        #expect(pinned.stdout.contains("fingerprint: \(fingerprint) (confirmed)"), "stdout: \(pinned.stdout)")
        #expect(!pinned.stderr.contains("not pinned"), "stderr: \(pinned.stderr)")
        #expect(FileManager.default.fileExists(atPath: pinnedPath))
    }

    @Test(.enabled(if: SecureEnclave.isAvailable, secureEnclaveAvailableComment))
    func cliForceWithoutFingerprintIsPinnedToTheReplacedKeyFilesKek() throws {
        // Two services stand in for one service whose keychain item was
        // replaced (planted ahead of provision, or swapped since): the key
        // file was wrapped under `original`'s KEK, and `swapped`'s KEK is a
        // different one.
        let original = "com.hkdfguard.tests.cli.wrap.pin.original"
        let swapped = "com.hkdfguard.tests.cli.wrap.pin.swapped"
        defer { Self.deleteKEK(service: original) }
        defer { Self.deleteKEK(service: swapped) }

        let provisionOriginal = try Self.runCLI(["provision", "-sn", original])
        #expect(provisionOriginal.exitCode == 0, "provision failed: \(provisionOriginal.stderr)")
        let originalFingerprint = try #require(Self.fingerprint(fromProvisionOutput: provisionOriginal.stdout))
        let provisionSwapped = try Self.runCLI(["provision", "-sn", swapped])
        #expect(provisionSwapped.exitCode == 0, "provision failed: \(provisionSwapped.stderr)")
        let swappedFingerprint = try #require(Self.fingerprint(fromProvisionOutput: provisionSwapped.stdout))

        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }
        let first = try Self.runCLI(
            ["wrap", "-kf", keyFilePath, "-sn", original, "--dek-stdin", "-fp", originalFingerprint],
            stdin: Self.base64Stdin(Self.randomDEK())
        )
        #expect(first.exitCode == 0, "wrap failed: \(first.stderr)")
        let existing = try Data(contentsOf: URL(fileURLWithPath: keyFilePath))

        // A different KEK, no --fingerprint: refused before the overwrite.
        let refused = try Self.runCLI(
            ["wrap", "-kf", keyFilePath, "-sn", swapped, "--dek-stdin", "--force"],
            stdin: Self.base64Stdin(Self.randomDEK())
        )
        #expect(refused.exitCode == 1)
        #expect(refused.stderr.contains("fingerprint mismatch"), "stderr: \(refused.stderr)")
        #expect(refused.stderr.contains("was wrapped under \(originalFingerprint)"), "stderr: \(refused.stderr)")
        #expect(try Data(contentsOf: URL(fileURLWithPath: keyFilePath)) == existing, "the old file is left intact")

        // The same KEK, no --fingerprint: confirmed by the file it replaces.
        let same = try Self.runCLI(
            ["wrap", "-kf", keyFilePath, "-sn", original, "--dek-stdin", "--force"],
            stdin: Self.base64Stdin(Self.randomDEK())
        )
        #expect(same.exitCode == 0, "re-wrap failed: \(same.stderr)")
        #expect(same.stdout.contains("same KEK as the key file it replaced"), "stdout: \(same.stdout)")
        #expect(!same.stderr.contains("not pinned"), "stderr: \(same.stderr)")

        // A deliberate change of KEK, named with --fingerprint: allowed.
        let moved = try Self.runCLI(
            ["wrap", "-kf", keyFilePath, "-sn", swapped, "--dek-stdin", "--force", "-fp", swappedFingerprint],
            stdin: Self.base64Stdin(Self.randomDEK())
        )
        #expect(moved.exitCode == 0, "pinned re-wrap failed: \(moved.stderr)")
        #expect(moved.stdout.contains("replaced a key file wrapped under \(originalFingerprint)"), "stdout: \(moved.stdout)")
        let embedded = try Data(contentsOf: URL(fileURLWithPath: keyFilePath)).prefix(32).map { String(format: "%02x", $0) }.joined()
        #expect(embedded == swappedFingerprint)
    }

    @Test(.enabled(if: SecureEnclave.isAvailable, secureEnclaveAvailableComment))
    func cliWrapWithTheWrongFingerprintWritesNothing() throws {
        let service = "com.hkdfguard.tests.cli.wrap.fingerprint.mismatch"
        defer { Self.deleteKEK(service: service) }

        let provision = try Self.runCLI(["provision", "--service-name", service])
        #expect(provision.exitCode == 0, "provision failed: \(provision.stderr)")
        let fingerprint = try #require(Self.fingerprint(fromProvisionOutput: provision.stdout), "stdout: \(provision.stdout)")
        let lastNibble = fingerprint.last == "0" ? "1" : "0"
        let wrong = String(fingerprint.dropLast()) + lastNibble

        // No output file may appear.
        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }
        let refused = try Self.runCLI(
            ["wrap", "--key-file-path", keyFilePath, "--service-name", service, "--dek-stdin", "--fingerprint", wrong],
            stdin: Self.base64Stdin(Self.randomDEK())
        )
        #expect(refused.exitCode == 1)
        #expect(refused.stderr.contains("fingerprint mismatch"), "stderr: \(refused.stderr)")
        #expect(refused.stderr.contains("nothing was written"), "stderr: \(refused.stderr)")
        #expect(!FileManager.default.fileExists(atPath: keyFilePath))
        #expect(Self.kekItemExists(service: service), "a refused wrap must not touch the KEK")

        // With --force against an existing file, the mismatch is detected
        // before the secure overwrite: the old file is left byte-for-byte.
        let existing = Data("do not destroy me\n".utf8)
        try existing.write(to: URL(fileURLWithPath: keyFilePath))
        let forced = try Self.runCLI(
            ["wrap", "-kf", keyFilePath, "-sn", service, "--dek-stdin", "-fp", wrong, "--force"],
            stdin: Self.base64Stdin(Self.randomDEK())
        )
        #expect(forced.exitCode == 1)
        #expect(forced.stderr.contains("fingerprint mismatch"), "stderr: \(forced.stderr)")
        #expect(try Data(contentsOf: URL(fileURLWithPath: keyFilePath)) == existing)
    }

    @Test(.enabled(if: SecureEnclave.isAvailable, secureEnclaveAvailableComment))
    func cliWrapRejectsAMalformedFingerprintBeforeTouchingAnything() throws {
        let service = "com.hkdfguard.tests.cli.wrap.fingerprint.malformed"
        defer { Self.deleteKEK(service: service) }
        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }

        for bad in ["abc", String(repeating: "zz", count: 32), String(repeating: "ab", count: 31)] {
            let result = try Self.runCLI(
                ["wrap", "-kf", keyFilePath, "-sn", service, "--dek-stdin", "--fingerprint", bad],
                stdin: Self.base64Stdin(Self.randomDEK())
            )
            #expect(result.exitCode == 2, "\(bad): \(result.stderr)")
            #expect(result.stderr.contains("--fingerprint must"), "stderr: \(result.stderr)")
        }
        let missing = try Self.runCLI(["wrap", "-kf", keyFilePath, "-sn", service, "--dek-stdin", "--fingerprint"])
        #expect(missing.exitCode == 2)
        #expect(!FileManager.default.fileExists(atPath: keyFilePath))
        #expect(!Self.kekItemExists(service: service))
    }

    // MARK: - status

    @Test(.enabled(if: SecureEnclave.isAvailable, secureEnclaveAvailableComment))
    func cliStatusReportsAbsentThenPresentWithoutCreatingAnything() throws {
        let service = "com.hkdfguard.tests.cli.status"
        defer { Self.deleteKEK(service: service) }

        let absent = try Self.runCLI(["status", "--service-name", service])
        #expect(absent.exitCode == 0, "status failed: \(absent.stderr)")
        #expect(absent.stdout.contains("kek: absent"), "stdout: \(absent.stdout)")
        #expect(absent.stdout.contains("keychain: legacy"), "stdout: \(absent.stdout)")
        #expect(!Self.kekItemExists(service: service), "status must never create a KEK")

        let provision = try Self.runCLI(["provision", "--service-name", service])
        let fingerprint = try #require(Self.fingerprint(fromProvisionOutput: provision.stdout), "stdout: \(provision.stdout)")

        let present = try Self.runCLI(["status", "-sn", service])
        #expect(present.exitCode == 0, "status failed: \(present.stderr)")
        #expect(present.stdout.contains("kek: present"), "stdout: \(present.stdout)")
        #expect(Self.fingerprint(fromProvisionOutput: present.stdout) == fingerprint)
    }

    @Test func cliStatusRejectsInvalidOrMissingServiceName() throws {
        let invalid = try Self.runCLI(["status", "--service-name", "com.hkdfguard.tests-status-invalid"])
        #expect(invalid.exitCode == 1)
        #expect(invalid.stderr.contains("alphanumeric"), "stderr: \(invalid.stderr)")

        let missing = try Self.runCLI(["status"])
        #expect(missing.exitCode == 2)
        #expect(missing.stderr.contains("missing required --service-name"), "stderr: \(missing.stderr)")
    }

    /// Plants a legacy-keychain item under `service` whose data is not a
    /// Secure Enclave key, so the library reports it as kekCorrupted (-19).
    /// The item is created by `security`, not by the CLI, so the CLI reading
    /// it is a cross-process legacy access: even with `-A`, it can raise an
    /// interactive keychain prompt. Tests using this are gated
    /// on the interactive opt-in for that reason.
    private static func plantCorruptLegacyItem(service: String) throws {
        let result = try run(
            URL(fileURLWithPath: "/usr/bin/security"),
            ["add-generic-password", "-s", service.lowercased(), "-a", hkdfguardKeychainAccount, "-w", "not-a-key-blob", "-A"]
        )
        #expect(result.exitCode == 0, "security add-generic-password failed: \(result.stderr)")
    }

    @Test(.enabled(if: legacyCrossProcessRoundTripEnabled && SecureEnclave.isAvailable, interactiveKeychainAndSecureEnclaveComment))
    func cliRetireCorruptDeletesOnlyACorruptItem() throws {
        let service = "com.hkdfguard.tests.cli.retire.corrupt"
        defer { Self.deleteKEK(service: service) }
        try Self.plantCorruptLegacyItem(service: service)

        // No fingerprint exists to confirm, so the fingerprint path refuses
        // and points at --corrupt.
        let byFingerprint = try Self.runCLI(["retire", "-sn", service, "-fp", String(repeating: "ab", count: 32)])
        #expect(byFingerprint.exitCode == 1)
        #expect(byFingerprint.stderr.contains("--corrupt"), "stderr: \(byFingerprint.stderr)")
        #expect(Self.kekItemExists(service: service))

        let retired = try Self.runCLI(["retire", "-sn", service, "--corrupt"])
        #expect(retired.exitCode == 0, "retire --corrupt failed: \(retired.stderr)")
        #expect(retired.stdout.contains("retired corrupt KEK item"), "stdout: \(retired.stdout)")
        #expect(!Self.kekItemExists(service: service))
    }

    @Test(.enabled(if: SecureEnclave.isAvailable, secureEnclaveAvailableComment))
    func cliRetireCorruptRefusesAValidKek() throws {
        let service = "com.hkdfguard.tests.cli.retire.corrupt.valid"
        defer { Self.deleteKEK(service: service) }
        try Self.provision(service: service)

        let result = try Self.runCLI(["retire", "-sn", service, "--corrupt"])
        #expect(result.exitCode == 1)
        #expect(result.stderr.contains("is valid, not corrupt"), "stderr: \(result.stderr)")
        #expect(Self.kekItemExists(service: service), "a valid KEK must never be deleted by --corrupt")
    }

    @Test(.enabled(if: SecureEnclave.isAvailable, secureEnclaveAvailableComment))
    func cliRetireCorruptWithoutItemReportsNothingToRetire() throws {
        let service = "com.hkdfguard.tests.cli.retire.corrupt.absent"
        defer { Self.deleteKEK(service: service) }
        let result = try Self.runCLI(["retire", "-sn", service, "--corrupt"])
        #expect(result.exitCode == 1)
        #expect(result.stderr.contains("nothing to retire"), "stderr: \(result.stderr)")
    }

    @Test func cliRetireRejectsMalformedOrMissingFingerprint() throws {
        let service = "com.hkdfguard.tests.cli.retire.malformed"
        let cases: [(args: [String], message: String)] = [
            ([], "missing required --fingerprint"),
            (["--fingerprint", "abc"], "exactly 64 hex characters"),
            (["--fingerprint", String(repeating: "zz", count: 32)], "only hex characters"),
            (["--fingerprint", String(repeating: "ab", count: 33)], "exactly 64 hex characters"),
            (["--fingerprint", String(repeating: "ab", count: 32), "--corrupt"], "mutually exclusive"),
        ]
        for testCase in cases {
            let result = try Self.runCLI(["retire", "--service-name", service] + testCase.args)
            #expect(result.exitCode == 2, "\(testCase.args): exit \(result.exitCode)")
            #expect(result.stderr.contains(testCase.message), "\(testCase.args): stderr: \(result.stderr)")
        }
    }
}
