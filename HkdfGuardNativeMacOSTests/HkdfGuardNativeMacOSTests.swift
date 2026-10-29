//
//  HkdfGuardNativeMacOSTests.swift
//  HkdfGuardNativeMacOSTests
//

import Testing
import Foundation
import CryptoKit
import Security
import os
@testable import HkdfGuardNativeMacOS

/// Exercises the public C-ABI entry points exposed by
/// `hkdfguard.h` — `hkdfguard_kek_exists`,
/// `hkdfguard_create_kek`, `hkdfguard_wrap_dek`, `hkdfguard_unwrap_dek`, and
/// `hkdfguard_generate_and_wrap_dek`. All are `@_cdecl` functions, but
/// they're still ordinary `public` Swift functions underneath, so they can
/// be called directly here without any C interop.
///
/// These status codes are the module's private `HKDFGuardStatus` raw
/// values, mirrored here since that enum isn't visible outside the module:
///   0 = success, -1 = invalidInputLength, -2 = outputBufferTooSmall,
///   -3 = enclaveUnavailable, -6 = unexpectedOutputLength,
///   -8 = invalidServiceIdentifier, -10 = payloadMalformed,
///   -11 = decryptionFailed, -12 = unsupportedCiphersuite,
///   -16 = fingerprintMismatch, -17 = kekNotFound,
///   -18 = keychainAccessDenied, -19 = kekCorrupted,
///   -96 = accessControlCreationFailed, -97 = keyGenerationFailed,
///   -98 = keychainWriteFailed, -99 = kekVerificationFailed,
///   -100 = keychainReadFailed
///   (the shared HkdfGuard status table; see hkdfguard.h).
///
/// `hkdfguard_wrap_dek`/`hkdfguard_unwrap_dek`/
/// `hkdfguard_generate_and_wrap_dek` never create a KEK; only
/// `hkdfguard_create_kek` does (see HkdfGuardNativeMacOS.swift's
/// `createKEK`/`kekExists`). Every test below that expects a
/// wrap/unwrap/generate-and-wrap to *succeed* therefore calls
/// `Self.createKEK(service:)` first and asserts it returns success, exactly
/// as real calling code must.
///
/// This suite runs serialized (`.serialized` below), not in parallel:
/// Swift Testing's default per-test parallelism hangs the whole run —
/// many tests simultaneously calling into the real Secure Enclave
/// Processor (threads pile up inside `TKSEPClientTokenSession`/`TKSEPKey`)
/// exceed whatever concurrency the SEP/securityd IPC layer actually
/// supports, well short of a hardware or App Sandbox limit we're
/// deliberately imposing. Each test still uses its own distinct service
/// identifier (rather than one shared default) so failures stay isolated
/// and easy to attribute to a specific test even though everything
/// runs one at a time. Every test that actually provisions a Secure
/// Enclave key registers a `defer` to delete that key's keychain item
/// immediately after declaring the service string it'll use — `defer`
/// runs on every exit path, including a failed `#expect`, so a failing
/// test still leaves the keychain clean.
///
/// Service name charset: `hkdfguard_kek_exists`/`hkdfguard_create_kek`/
/// `hkdfguard_wrap_dek`/`hkdfguard_unwrap_dek`/
/// `hkdfguard_generate_and_wrap_dek` all validate `service` via
/// `validServiceName` — ASCII letters, digits, and `.` only, 1-128
/// characters — so every service literal below deliberately uses `.` in
/// place of the `-`/`_` this suite's names might otherwise read more
/// naturally with (e.g. `wrapped.length`, not `wrapped-length`), and
/// nowhere relies on `UUID().uuidString` verbatim (its dashes would fail
/// validation too).
@Suite(
    .serialized,
    .enabled(
        if: SecureEnclave.isAvailable,
        "requires a real Secure Enclave — not available on CI/VM runners (e.g. GitHub-hosted macOS runners, where Apple's Virtualization framework doesn't pass the Secure Enclave through to the guest); run this suite on real Mac hardware before committing/requesting a build"
    )
)
struct HkdfGuardNativeMacOSWrapUnwrapTests {

    /// Every helper below provisions or probes through the exported setup
    /// calls, which production holds to a 1 s floor each; zero it so the
    /// suite doesn't spend minutes asleep. Only this suite writes the
    /// override, and it runs serialized, so the floor test in it
    /// (`theExportedSetupCallsPayTheFloor`) can set its own and restore
    /// zero without a race.
    init() {
        setupMinDelayOverrideForTests.withLock { $0 = .zero }
    }

    // MARK: - Helpers

    private static let dekLength = 32
    private static let wrappedLength = 125 // 32-byte KEK fingerprint + 1-byte suite id + 32-byte salt + 12-byte nonce + 32-byte ciphertext + 16-byte tag
    private static let saltOffset = 33
    private static let nonceOffset = 65
    private static let maxServiceNameLength = 128

    private static func randomDEK() -> [UInt8] {
        (0..<dekLength).map { _ in UInt8.random(in: .min ... .max) }
    }

    /// A payload-length blob of zeros with the one byte that is checked
    /// before the keychain -- the suite id at offset 32 -- set to the
    /// supported value, so a test gets to the keychain lookup it is about.
    private static func zeroPayloadWithValidSuite() -> [UInt8] {
        var blob = [UInt8](repeating: 0, count: wrappedLength)
        blob[32] = 0x01
        return blob
    }

    /// The attributes identifying `service`'s KEK item *in the keychain this
    /// process's mode uses* — mirroring the library's own
    /// `keychainItemAttributes`. Hosted in the entitled HkdfGuardNativeMacOSTestHost
    /// app the mode is data-protection, and a plain legacy query would
    /// silently miss every item the library creates.
    private static func keychainQuery(service: String) -> [String: Any] {
        // The library lowercases `service` before storing (see
        // `normalizedService`), and service matching is case-sensitive —
        // querying with the caller's original spelling (`appA`, an
        // uppercase UUID) would silently miss and leak the item.
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service.lowercased(),
            kSecAttrAccount as String: hkdfguardKeychainAccount,
            kSecAttrSynchronizable as String: false,
        ]
        if case .dataProtection(let accessGroup) = hkdfguardKeychainMode {
            query[kSecUseDataProtectionKeychain as String] = true
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        return query
    }

    /// Deletes the keychain item backing a service's Secure Enclave key,
    /// if one was created. There's no separate "delete this SE key" API —
    /// the SE key becomes unreferenced (and its `dataRepresentation` can
    /// never be reconstructed again) once the keychain item that stores
    /// that representation is gone, which is the actual cleanup unit here.
    private static func deleteKEK(service: String) {
        SecItemDelete(keychainQuery(service: service) as CFDictionary)
    }

    private static func kekExists(service: String) -> (status: Int32, exists: Bool) {
        var outExists: Int32 = -1
        let status = service.withCString { serviceCStr in
            hkdfguard_kek_exists(servicePtr: serviceCStr, outExists: &outExists)
        }
        return (status, outExists != 0)
    }

    @discardableResult
    private static func createKEK(service: String) -> Int32 {
        service.withCString { serviceCStr in
            hkdfguard_create_kek(servicePtr: serviceCStr)
        }
    }

    /// `createKEK` under a policy whose KekSuite is P-256: for the tests
    /// that rebuild suite 0x01 payloads from the KEK's P-256 key.
    private static func createClassicalKEK(service: String) -> Int32 {
        underSuitePolicy(SuitePolicy(provisionSuite: .p256HashedPoint)) { createKEK(service: service) }
    }

    /// Runs `body` under a policy with these suite settings and no machine
    /// services -- for this test's calls only (task-local).
    private static func underSuitePolicy<T>(_ suites: SuitePolicy, _ body: () throws -> T) rethrows -> T {
        try MachineScopeTestOverrides.$policy.withValue(.loaded(MachinePolicy(
            source: "test", securityAdminGroup: nil, deploymentAdminGroup: nil, machineServices: [:],
            suites: suites)), operation: body)
    }

    private static func kekSuite(service: String) -> (status: Int32, suite: Int32) {
        var suite: Int32 = -1
        let status = service.withCString { hkdfguard_kek_suite(servicePtr: $0, outSuite: &suite) }
        return (status, suite)
    }

    /// The service's keychain item data, as stored.
    private static func storedItem(service: String) throws -> Data {
        var query = keychainQuery(service: service)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        try #require(SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess)
        return try #require(result as? Data)
    }

    private static func wrap(
        _ dek: [UInt8],
        service: String,
        bufferCapacity: Int32 = 1024
    ) -> (status: Int32, wrapped: [UInt8], requiredLen: Int32) {
        var out = [UInt8](repeating: 0, count: Int(bufferCapacity))
        var outLen = bufferCapacity
        let status = service.withCString { serviceCStr in
            dek.withUnsafeBufferPointer { dekBuf in
                out.withUnsafeMutableBufferPointer { outBuf in
                    hkdfguard_wrap_dek(
                        servicePtr: serviceCStr,
                        dekPtr: dekBuf.baseAddress!,
                        dekLen: Int32(dek.count),
                        outPtr: outBuf.baseAddress!,
                        outLen: &outLen
                    )
                }
            }
        }
        return (status, Array(out.prefix(Int(max(outLen, 0)))), outLen)
    }

    private static func unwrap(
        _ wrapped: [UInt8],
        service: String,
        bufferCapacity: Int32 = 1024
    ) -> (status: Int32, plaintext: [UInt8], requiredLen: Int32) {
        var out = [UInt8](repeating: 0, count: Int(bufferCapacity))
        var outLen = bufferCapacity
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
        return (status, Array(out.prefix(Int(max(outLen, 0)))), outLen)
    }

    private static func generateAndWrap(
        service: String,
        bufferCapacity: Int32 = 1024
    ) -> (status: Int32, wrapped: [UInt8], requiredLen: Int32) {
        var out = [UInt8](repeating: 0, count: Int(bufferCapacity))
        var outLen = bufferCapacity
        let status = service.withCString { serviceCStr in
            out.withUnsafeMutableBufferPointer { outBuf in
                hkdfguard_generate_and_wrap_dek(
                    servicePtr: serviceCStr,
                    outPtr: outBuf.baseAddress!,
                    outLen: &outLen
                )
            }
        }
        return (status, Array(out.prefix(Int(max(outLen, 0)))), outLen)
    }

    // MARK: - hkdfguard_kek_exists / hkdfguard_create_kek

    @Test func kekExistsReportsFalseForNeverCreatedService() {
        let service = "com.hkdfguard.tests.kek.exists.never.created"
        // No defer/cleanup needed: this service is never created by this
        // test, only queried.
        let result = Self.kekExists(service: service)
        #expect(result.status == 0)
        #expect(result.exists == false)
    }

    @Test func createKekThenKekExistsReportsTrue() {
        let service = "com.hkdfguard.tests.kek.exists.after.create"
        defer { Self.deleteKEK(service: service) }

        #expect(Self.createKEK(service: service) == 0)

        let result = Self.kekExists(service: service)
        #expect(result.status == 0)
        #expect(result.exists == true)
    }

    @Test func createKekIsIdempotent() {
        // Calling create twice must succeed both times, not treat the
        // second call as an error just because a key already exists —
        // that's the whole point of it being "create if missing," not
        // "create or fail."
        let service = "com.hkdfguard.tests.kek.create.idempotent"
        defer { Self.deleteKEK(service: service) }

        #expect(Self.createKEK(service: service) == 0)
        #expect(Self.createKEK(service: service) == 0)

        let result = Self.kekExists(service: service)
        #expect(result.status == 0)
        #expect(result.exists == true)
    }

    @Test func concurrentFirstUseOfCreateKekConvergesOnOneKEK() {
        // Several callers racing to create the very first keychain item
        // for a service must all succeed. SecItemAdd's unique index on
        // service+account lets only one caller's create win; the rest must
        // fall back to loading the winner's key rather than treating that
        // as failure. Using a never-before-seen service identifier here
        // forces every task through that first-use race on every run.
        //
        // This deliberately uses GCD (real OS threads from its global
        // pool) rather than Swift's async/withTaskGroup:
        // hkdfguard_create_kek makes synchronous, blocking
        // Security-framework calls, and Swift Concurrency's cooperative
        // thread pool has a limited number of threads that assume tasks
        // suspend via `await` rather than block outright. Spawning several
        // blocking calls via withTaskGroup here — on top of Swift
        // Testing's own default per-test parallelism — is enough to
        // exhaust that pool and deadlock the entire test run (every thread
        // parked in the Testing runner's scheduler, no forward progress).
        // GCD's pool is designed for exactly this kind of blocking work.
        //
        // Service names must stay within the letters/digits/'.' charset —
        // a raw UUID's dashes would be rejected, so they are stripped.
        let service = "com.hkdfguard.tests.kek.create.concurrent.\(UUID().uuidString.filter { $0 != "-" })"
        defer { Self.deleteKEK(service: service) }

        // Sendable shared state, since the creators below run in @Sendable
        // closures on GCD.
        let statuses = OSAllocatedUnfairLock<[Int32]>(initialState: [])

        // 3 concurrent creators is enough to exercise the unique-index
        // race (needs >=2); much more simultaneous load at the real Secure
        // Enclave/securityd IPC layer causes severe contention, so this
        // stays deliberately modest rather than maximizing concurrency.
        //
        // The creators run on GCD's global pool and this thread waits with
        // a deadline rather than joining them: the SEP/securityd IPC has
        // been known to stall outright under concurrent first use, and a
        // thread blocked inside it cannot be cancelled -- `.timeLimit`
        // alone would record the failure but leave the whole run hung. On
        // a stall this records an issue and returns; the stuck threads are
        // abandoned (they hold no test state) and don't block the run.
        // A normal run completes in well under a second.
        let creators = DispatchGroup()
        for _ in 0..<3 {
            DispatchQueue.global(qos: .userInitiated).async(group: creators) {
                let status = Self.createKEK(service: service)
                statuses.withLock { $0.append(status) }
            }
        }
        guard creators.wait(timeout: .now() + 60) == .success else {
            let finished = statuses.withLock { $0.count }
            Issue.record("Secure Enclave/securityd stalled: only \(finished) of 3 concurrent hkdfguard_create_kek calls returned within 60 s")
            return
        }

        let collected = statuses.withLock { $0 }
        #expect(collected.count == 3)
        #expect(collected.allSatisfy { $0 == 0 })
    }

    @Test func kekExistsRejectsInvalidServiceIdentifier() {
        // No defer/cleanup needed: rejected before any key provisioning
        // or lookup happens.
        let result = Self.kekExists(service: "")
        #expect(result.status == -8) // invalidServiceIdentifier
        #expect(result.exists == false)
    }

    @Test func createKekRejectsInvalidServiceIdentifier() {
        // No defer/cleanup needed: rejected before any key provisioning
        // happens.
        #expect(Self.createKEK(service: "") == -8) // invalidServiceIdentifier
    }

    @Test func createKekAcceptsServiceNameAtMaxLength() {
        let service = String(repeating: "a", count: Self.maxServiceNameLength)
        defer { Self.deleteKEK(service: service) }

        #expect(Self.createKEK(service: service) == 0)
        #expect(Self.kekExists(service: service).exists == true)
    }

    @Test func createKekRejectsServiceNameOverMaxLength() {
        // No defer/cleanup needed: rejected before any key provisioning
        // happens.
        let tooLong = String(repeating: "a", count: Self.maxServiceNameLength + 1)
        #expect(Self.createKEK(service: tooLong) == -8) // invalidServiceIdentifier

        let result = Self.kekExists(service: tooLong)
        #expect(result.status == -8) // invalidServiceIdentifier
        #expect(result.exists == false)
    }

    @Test func createKekRejectsServiceNameWithDisallowedCharacters() {
        // No defer/cleanup needed: rejected before any key provisioning
        // happens. Only ASCII letters, digits, and '.' are accepted — a
        // hyphen (still a very ordinary character in a reverse-DNS-style
        // identifier) must not slip through.
        #expect(Self.createKEK(service: "com.hkdfguard.tests-invalid-charset") == -8) // invalidServiceIdentifier
    }

    @Test func serviceNameRejectsLeadingAndConsecutiveDots() {
        // The shared rule (hkdfguard-native-linux's cstr_to_service): a name
        // may not start with '.' or contain "..", so it can never be ".",
        // "..", or a hidden dot-name, or have an empty label. Same list as
        // the Linux CLI's validate_service_charset test. Rejected before any
        // keychain work, so nothing needs cleaning up.
        for name in [".", "..", "...", ".hidden", "..parent", "com..example", "com.example..", "a...b"] {
            #expect(Self.createKEK(service: name) == -8, "\(name) must be rejected")
            #expect(Self.kekExists(service: name).status == -8, "\(name)")
            #expect(Self.wrap(Self.randomDEK(), service: name).status == -8, "\(name)")
            #expect(Self.generateAndWrap(service: name).status == -8, "\(name)")
            #expect(Self.unwrap([UInt8](repeating: 0, count: Self.wrappedLength), service: name).status == -8, "\(name)")
        }
    }

    @Test func serviceNameAcceptsSingleInteriorAndTrailingDots() {
        // Only a leading dot and ".." are forbidden: single dots between
        // labels, and a trailing dot, are valid -- as on Linux. kekExists
        // never creates anything, so a valid name answers 0 with "no KEK".
        for name in ["a", "com.example", "a.b.c", "com.example."] {
            let result = Self.kekExists(service: name)
            #expect(result.status == 0, "\(name) must be accepted")
            #expect(result.exists == false, "\(name)")
        }
    }

    @Test func serviceNameIsCaseInsensitive() {
        // The library lowercases before every keychain/crypto use, so the
        // same KEK must be reached however the caller capitalizes.
        let mixed = "Com.HkdfGuard.Tests.Case.Insensitive"
        let lower = mixed.lowercased()
        defer { Self.deleteKEK(service: lower) }

        #expect(Self.createKEK(service: mixed) == 0)
        #expect(Self.kekExists(service: lower).exists == true)

        let wrapped = Self.wrap(Self.randomDEK(), service: mixed)
        #expect(wrapped.status == 0)
        #expect(Self.unwrap(wrapped.wrapped, service: lower).status == 0)
        #expect(Self.unwrap(wrapped.wrapped, service: mixed.uppercased()).status == 0)
    }

    @Test func serviceNameRejectsNonASCII() {
        // Character.isLetter/isNumber would accept every one of these; the
        // contract (header, CLI, Linux tool) is ASCII bytes only. The
        // KELVIN SIGN case matters most: Unicode-lowercased it becomes a
        // plain ASCII 'k', so validating *after* lowercasing would let it
        // through as a different spelling of an ASCII name.
        let rejected = [
            "caf\u{00E9}",                        // é
            "\u{65E5}\u{672C}",                   // 日本
            "com.hkdfguard.\u{0663}",             // Arabic-Indic digit three
            "com.hkdfguard.tests.\u{00BD}",       // ½
            "\u{212A}",                           // KELVIN SIGN
            "com.hkdfguard.tests.\u{0130}",       // İ (lowercases to i + U+0307)
        ]
        for name in rejected {
            #expect(Self.createKEK(service: name) == -8, "\(name.unicodeScalars.map { String($0.value, radix: 16) }) must be rejected")
            #expect(Self.kekExists(service: name).status == -8)
            #expect(Self.wrap(Self.randomDEK(), service: name).status == -8)
            #expect(Self.generateAndWrap(service: name).status == -8)
            #expect(Self.unwrap([UInt8](repeating: 0, count: Self.wrappedLength), service: name).status == -8)
        }
    }

    // MARK: - Keychain mode (hybrid)

    @Test func keychainModeMatchesTheHostProcessEntitlement() {
        // Whatever process hosts this bundle decides the mode: the plain
        // xctest agent carries only get-task-allow (legacy); the entitled
        // HkdfGuardNativeMacOSTestHost app carries keychain-access-groups
        // (data-protection). Read the entitlement independently here and
        // assert the library agrees -- in its internal enum and via the C
        // ABI -- so a host-configuration mistake shows up as this one
        // failure instead of as a mystery elsewhere in the suite.
        var entitledGroup: String?
        if let task = SecTaskCreateFromSelf(nil),
           let value = SecTaskCopyValueForEntitlement(task, "keychain-access-groups" as CFString, nil),
           let groups = value as? [String] {
            entitledGroup = groups.first(where: { !$0.isEmpty })
        }

        var mode: Int32 = -1
        #expect(hkdfguard_keychain_mode(outMode: &mode) == 0)
        if let entitledGroup {
            #expect(mode == 1, "entitled for \(entitledGroup); expected data-protection mode")
            #expect(hkdfguardKeychainMode == .dataProtection(accessGroup: entitledGroup))
        } else {
            #expect(mode == 0, "no keychain-access-groups entitlement; expected legacy mode")
            #expect(hkdfguardKeychainMode == .legacy)
        }
    }

    @Test(.enabled(if: hkdfguardKeychainMode != .legacy, "requires the entitled HkdfGuardNativeMacOSTestHost (data-protection mode)"))
    func dataProtectionModeStoresItemsOnlyInTheDataProtectionKeychain() {
        // Hosted in the entitled app: a provisioned KEK must be visible
        // through a data-protection query in the shared access group and
        // invisible to a legacy login-keychain query -- the two keychains
        // are disjoint, which is the whole "same mode" invariant.
        let service = "com.hkdfguard.tests.dataprotection.entitled"
        defer { Self.deleteKEK(service: service) }
        guard case .dataProtection(let accessGroup) = hkdfguardKeychainMode else { return }
        // The test-only group, never the production one -- see
        // HkdfGuardNativeMacOSTestHost.entitlements.
        #expect(accessGroup.hasSuffix(".com.hkdfguard.tests.keys"), "unexpected access group \(accessGroup)")

        #expect(Self.createKEK(service: service) == 0)
        #expect(Self.kekExists(service: service).exists == true)

        var dpQuery = Self.keychainQuery(service: service)
        dpQuery[kSecReturnAttributes as String] = true
        var dpItem: CFTypeRef?
        #expect(SecItemCopyMatching(dpQuery as CFDictionary, &dpItem) == errSecSuccess)
        #expect((dpItem as? [String: Any])?[kSecAttrAccessGroup as String] as? String == accessGroup)

        let legacyQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: hkdfguardKeychainAccount,
            kSecReturnAttributes as String: true,
            // Explicit false, not omitted -- see keychainItemAttributes.
            kSecUseDataProtectionKeychain as String: false,
        ]
        var legacyItem: CFTypeRef?
        #expect(SecItemCopyMatching(legacyQuery as CFDictionary, &legacyItem) == errSecItemNotFound)

        // The library's own view agrees: legacy mode sees no key here.
        #expect(HkdfGuardNativeMacOS.kekExists(service: service, mode: .legacy).exists == false)
    }

    @Test(.enabled(if: hkdfguardKeychainMode == .legacy, "only meaningful in an unentitled (legacy-mode) host"))
    func dataProtectionModeWithoutEntitlementIsAccessDeniedNotNotFound() {
        // Drives the internal functions in data-protection mode from this
        // unentitled process. securityd answers errSecMissingEntitlement
        // (-34018); the library must report that as keychainAccessDenied
        // (-18) on every path -- never as "no key" (which would invite
        // creating one) and never as a generic failure -- and must create
        // nothing. This is also the proof that kSecUseDataProtectionKeychain
        // actually reaches the keychain calls: in legacy mode the same
        // service would simply be created.
        let service = "com.hkdfguard.tests.dataprotection.unentitled"
        defer { Self.deleteKEK(service: service) }
        let dp = KeychainMode.dataProtection(accessGroup: "MFW3T8R8J3.com.hkdfguard.tests.keys")

        // Module-qualified: this suite's own static `kekExists`/`createKEK`
        // helpers (which go through the C ABI, in the process's real mode)
        // would otherwise shadow the library's internal functions.
        let exists = HkdfGuardNativeMacOS.kekExists(service: service, mode: dp)
        #expect(exists.status == -18)
        #expect(exists.exists == false)

        #expect(HkdfGuardNativeMacOS.createKEK(service: service, mode: dp) == -18)

        let got = HkdfGuardNativeMacOS.getKEK(service: service, mode: dp)
        #expect(got.status == -18)
        #expect(got.key == nil)

        // Nothing leaked into the legacy keychain either.
        #expect(Self.kekExists(service: service).exists == false)
    }

    @Test func corruptKeychainItemIsReportedAsKekCorruptedNotNotFound() {
        // An item exists under this service, but its data is not a Secure
        // Enclave key representation. Every entry point must report
        // kekCorrupted (-19): not "no key" (which would invite creating a
        // replacement on top of it), not success, and nothing may "heal"
        // it by replacing it. This is the case the keychain-lookup mapping
        // has to keep distinct from keychainAccessDenied (-18), which is
        // not reproducible in-process without locking the login keychain.
        let service = "com.hkdfguard.tests.kek.corrupt.item"
        defer { Self.deleteKEK(service: service) }

        let garbage = Data((0..<48).map { UInt8($0) })
        // Planted in whichever keychain this process's mode uses, so the
        // library actually finds it.
        var attributes = Self.keychainQuery(service: service)
        attributes[kSecValueData as String] = garbage
        #expect(SecItemAdd(attributes as CFDictionary, nil) == errSecSuccess)

        let exists = Self.kekExists(service: service)
        #expect(exists.status == -19) // kekCorrupted
        #expect(exists.exists == false)
        #expect(Self.createKEK(service: service) == -19)
        #expect(Self.wrap(Self.randomDEK(), service: service).status == -19)
        #expect(Self.unwrap(Self.zeroPayloadWithValidSuite(), service: service).status == -19)

        // Still corrupt, still present: createKEK above must not have
        // replaced it.
        #expect(Self.kekExists(service: service).status == -19)
    }

    @Test func anUnloadableBlobIsCorruptOnlyIfTheEnclaveProbeWorks() {
        // A locked keybag (SSH after `security unlock-keychain`) makes a
        // healthy KEK fail to load just like a corrupt one. Only a failure
        // that a throwaway probe key survives is reported as corrupt (-19);
        // otherwise it is access-denied (-18), so no one is pointed at
        // deleting a KEK that is fine. The probe is injected here, since a
        // locked keybag can't be produced in-process.
        let garbage = Data((0..<48).map { UInt8($0) })
        var probed = 0
        func probe(_ usable: Bool) -> () -> Bool { { probed += 1; return usable } }

        guard case .corrupt = HkdfGuardNativeMacOS.reconstructKEK(garbage, enclaveIsUsable: probe(true)) else {
            Issue.record("a blob the working enclave rejects is corrupt"); return
        }
        guard case .enclaveRefused = HkdfGuardNativeMacOS.reconstructKEK(garbage, enclaveIsUsable: probe(false)) else {
            Issue.record("when the probe fails too, the blob's failure proves nothing"); return
        }
        #expect(probed == 2)
    }

    @Test(.enabled(if: SecureEnclave.isAvailable, "needs a Secure Enclave"))
    func theEnclaveProbeWorksHereAndAHealthyKEKNeverRunsIt() throws {
        let usable = HkdfGuardNativeMacOS.secureEnclaveIsUsableNow()
        #expect(usable)

        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey()
        var probed = false
        guard case .key = HkdfGuardNativeMacOS.reconstructKEK(key.dataRepresentation,
                                                              enclaveIsUsable: { probed = true; return true }) else {
            Issue.record("a fresh enclave key reconstructs"); return
        }
        #expect(!probed, "the probe runs only after a blob fails to load")
    }

    // MARK: - A stored ML-KEM KEK

    /// Stores an ML-KEM-1024 KEK for `service` in the keychain item format
    /// provisioning will use, and returns its public key.
    @available(macOS 26.0, *)
    private static func plantMLKEMKEK(service: String) throws -> Data {
        let access = try #require(SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage], nil))
        let (kem, blob) = try #require(newMLKEM1024KEK(accessControl: access))
        var attributes = keychainQuery(service: service)
        let item = try #require(encodeKeychainKEK(.mlkem1024(blob: blob, encapsulated: kem.encapsulated)))
        attributes[kSecValueData as String] = item
        try #require(SecItemAdd(attributes as CFDictionary, nil) == errSecSuccess)
        return kem.publicKey
    }

    @available(macOS 26.0, *)
    @Test func aStoredMLKEMKEKWrapsAndUnwrapsInSuite2() throws {
        let service = "com.hkdfguard.tests.mlkem.stored"
        defer { Self.deleteKEK(service: service) }
        let publicKey = try Self.plantMLKEMKEK(service: service)

        #expect(Self.kekExists(service: service) == (0, true))
        #expect(Self.createKEK(service: service) == 0, "an existing ML-KEM KEK is verified, never replaced")
        let dek = Self.randomDEK()
        let wrapped = Self.wrap(dek, service: service)
        #expect(wrapped.status == 0)
        #expect(wrapped.wrapped.count == Self.wrappedLength)
        #expect(Data(wrapped.wrapped.prefix(32)) == Data(SHA256.hash(data: publicKey)))
        #expect(wrapped.wrapped[32] == 0x02)
        let unwrapped = Self.unwrap(wrapped.wrapped, service: service)
        #expect(unwrapped.status == 0)
        #expect(unwrapped.plaintext == dek)

        // The suite byte rewritten to P-256's: the fingerprint is this KEK's,
        // so the byte was altered.
        var rewritten = wrapped.wrapped
        rewritten[32] = 0x01
        #expect(Self.unwrap(rewritten, service: service).status == -11)
    }

    @available(macOS 26.0, *)
    @Test func anMLKEMItemWhoseBlobTheEnclaveRejectsIsCorrupt() throws {
        let service = "com.hkdfguard.tests.mlkem.corrupt.blob"
        defer { Self.deleteKEK(service: service) }
        let item = try #require(encodeKeychainKEK(.mlkem1024(
            blob: Data([0x04, 0x82] + (0..<200).map { UInt8($0 & 0xFF) }),
            encapsulated: Data(repeating: 0x5A, count: 1568))))
        var attributes = Self.keychainQuery(service: service)
        attributes[kSecValueData as String] = item
        #expect(SecItemAdd(attributes as CFDictionary, nil) == errSecSuccess)

        #expect(Self.kekExists(service: service) == (-19, false))
        #expect(Self.createKEK(service: service) == -19, "never replaced")
        #expect(Self.wrap(Self.randomDEK(), service: service).status == -19)
        #expect(Self.kekExists(service: service).status == -19)
    }

    // MARK: - Provisioning picks the policy's suite

    @available(macOS 26.0, *)
    @Test func provisioningCreatesAnMLKEMKEKByDefault() throws {
        let service = "com.hkdfguard.tests.provision.default.suite"
        defer { Self.deleteKEK(service: service) }
        #expect(Self.kekSuite(service: service) == (-17, 0), "no KEK yet")
        #expect(Self.createKEK(service: service) == 0)
        #expect(try Self.storedItem(service: service).starts(with: Data("HKGQ".utf8)), "stored as an ML-KEM item")
        #expect(Self.kekSuite(service: service) == (0, 2))
        #expect(Self.createKEK(service: service) == 0, "a second provision verifies it")

        let dek = Self.randomDEK()
        let wrapped = Self.wrap(dek, service: service)
        #expect(wrapped.status == 0)
        #expect(wrapped.wrapped[32] == 0x02)
        #expect(Self.unwrap(wrapped.wrapped, service: service).plaintext == dek)
    }

    @Test func kekSuiteOptsInToP256AndReportsIt() throws {
        let service = "com.hkdfguard.tests.provision.classical.suite"
        defer { Self.deleteKEK(service: service) }
        #expect(Self.createClassicalKEK(service: service) == 0)
        #expect(try !Self.storedItem(service: service).starts(with: Data("HKGQ".utf8)), "a bare P-256 blob, as always")
        #expect(Self.kekSuite(service: service) == (0, 1))
        // Once it exists, the default policy uses it as it is: provisioning
        // never replaces a KEK of the other suite.
        #expect(Self.createKEK(service: service) == 0)
        let wrapped = Self.wrap(Self.randomDEK(), service: service)
        #expect(wrapped.status == 0)
        #expect(wrapped.wrapped[32] == 0x01)

        var suite: Int32 = 7
        #expect(service.withCString { hkdfguard_kek_suite(servicePtr: $0, outSuite: nil) } == -1)
        #expect(hkdfguard_kek_suite(servicePtr: nil, outSuite: &suite) == -8)
        #expect(suite == 0, "zeroed on failure")
    }

    @Test func requirePostQuantumRefusesAP256KEKButStillLetsItBeFound() throws {
        let service = "com.hkdfguard.tests.provision.require.pq"
        defer { Self.deleteKEK(service: service) }
        #expect(Self.createClassicalKEK(service: service) == 0)
        let dek = Self.randomDEK()
        let wrapped = Self.wrap(dek, service: service)
        #expect(wrapped.status == 0)

        Self.underSuitePolicy(SuitePolicy(requirePostQuantum: true)) {
            #expect(Self.createKEK(service: service) == -18, "provision refuses it, and doesn't replace it")
            #expect(Self.wrap(Self.randomDEK(), service: service).status == -18)
            #expect(Self.unwrap(wrapped.wrapped, service: service).status == -12)
            #expect(Self.generateAndWrap(service: service).status == -18)
            // So it can be found and retired:
            #expect(Self.kekExists(service: service) == (0, true))
            #expect(Self.kekSuite(service: service) == (0, 1))
        }
        #expect(Self.unwrap(wrapped.wrapped, service: service).plaintext == dek, "without the setting it opens again")
    }

    @available(macOS 26.0, *)
    @Test func requirePostQuantumAcceptsAnMLKEMKEK() throws {
        let service = "com.hkdfguard.tests.provision.require.pq.mlkem"
        defer { Self.deleteKEK(service: service) }
        Self.underSuitePolicy(SuitePolicy(requirePostQuantum: true)) {
            #expect(Self.createKEK(service: service) == 0)
            #expect(Self.kekSuite(service: service) == (0, 2))
            let dek = Self.randomDEK()
            let wrapped = Self.wrap(dek, service: service)
            #expect(wrapped.status == 0)
            #expect(Self.unwrap(wrapped.wrapped, service: service).plaintext == dek)
            // A suite 0x01 payload is refused before the keychain is asked.
            var classical = wrapped.wrapped
            classical[32] = 0x01
            #expect(Self.unwrap(classical, service: service).status == -12)
        }
        #expect(try Self.storedItem(service: service).starts(with: Data("HKGQ".utf8)))
    }

    // MARK: - A Mac whose Secure Enclave has no ML-KEM (before macOS 26)

    /// Runs `body` as a macOS before 26 would: no ML-KEM keys created or
    /// loaded. For this test's calls only (task-local).
    private static func withoutMLKEM<T>(_ body: () throws -> T) rethrows -> T {
        try MachineScopeTestOverrides.$withoutMLKEM.withValue(true, operation: body)
    }

    @Test func withoutMLKEMProvisioningFailsRatherThanFallingBackToP256() {
        let service = "com.hkdfguard.tests.without.mlkem.provision"
        defer { Self.deleteKEK(service: service) }
        Self.withoutMLKEM {
            #expect(Self.createKEK(service: service) == -3)
            #expect(Self.underSuitePolicy(SuitePolicy(requirePostQuantum: true)) {
                Self.createKEK(service: service)
            } == -3)
        }
        let result = Self.kekExists(service: service)
        #expect(result.status == 0)
        #expect(result.exists == false, "no P-256 KEK was created in its place")
    }

    @Test func withoutMLKEMKekSuiteP256StillProvisions() {
        let service = "com.hkdfguard.tests.without.mlkem.classical"
        defer { Self.deleteKEK(service: service) }
        Self.withoutMLKEM {
            #expect(Self.createClassicalKEK(service: service) == 0)
            #expect(Self.kekSuite(service: service) == (0, 1))
            let dek = Self.randomDEK()
            let wrapped = Self.wrap(dek, service: service)
            #expect(wrapped.status == 0)
            #expect(wrapped.wrapped[32] == 0x01)
            #expect(Self.unwrap(wrapped.wrapped, service: service).plaintext == dek)
        }
    }

    /// An ML-KEM KEK this Mac can't load is refused (-18), never reported
    /// corrupt (-19), which would invite deleting it.
    @available(macOS 26.0, *)
    @Test func withoutMLKEMAStoredMLKEMKEKIsRefusedNeverCorrupt() throws {
        let service = "com.hkdfguard.tests.without.mlkem.stored"
        defer { Self.deleteKEK(service: service) }
        _ = try Self.plantMLKEMKEK(service: service)
        let dek = Self.randomDEK()
        let wrapped = Self.wrap(dek, service: service)
        #expect(wrapped.status == 0)
        let item = try Self.storedItem(service: service)

        Self.withoutMLKEM {
            #expect(Self.kekExists(service: service).status == -18)
            #expect(Self.createKEK(service: service) == -18, "never replaced")
            #expect(Self.wrap(Self.randomDEK(), service: service).status == -18)
            #expect(Self.unwrap(wrapped.wrapped, service: service).status == -18)
            #expect(Self.kekSuite(service: service).status == -18)
        }
        #expect(try Self.storedItem(service: service) == item, "the item is left as it was")
        #expect(Self.unwrap(wrapped.wrapped, service: service).plaintext == dek)
    }

    // MARK: - wrap/unwrap require an already-created KEK

    @Test func wrapFailsWithKekNotFoundWhenNoKekWasCreated() {
        // Wrap never creates a KEK. A well-formed, never-created service
        // must fail with kekNotFound, not succeed by silently provisioning
        // one.
        let service = "com.hkdfguard.tests.wrap.without.create"
        // No defer/cleanup needed: hkdfguard_wrap_dek must not create
        // anything here — that's exactly what's under test.
        let result = Self.wrap(Self.randomDEK(), service: service)
        #expect(result.status == -17) // kekNotFound
    }

    @Test func unwrapFailsWithKekNotFoundWhenNoKekWasCreated() {
        let service = "com.hkdfguard.tests.unwrap.without.create"
        // No defer/cleanup needed: hkdfguard_unwrap_dek must not create
        // anything here either.
        //
        // Only the length and the suite byte are checked before the KEK
        // lookup, so the rest of the content doesn't matter here.
        let arbitraryBlob = Self.zeroPayloadWithValidSuite()
        let result = Self.unwrap(arbitraryBlob, service: service)
        #expect(result.status == -17) // kekNotFound
    }

    // MARK: - Round trip

    @Test func wrapThenUnwrapRecoversOriginalDEK() {
        let service = "com.hkdfguard.tests.roundtrip"
        defer { Self.deleteKEK(service: service) }
        #expect(Self.createKEK(service: service) == 0)
        let dek = Self.randomDEK()

        let wrapResult = Self.wrap(dek, service: service)
        #expect(wrapResult.status == 0)

        let unwrapResult = Self.unwrap(wrapResult.wrapped, service: service)
        #expect(unwrapResult.status == 0)
        #expect(unwrapResult.plaintext == dek)
    }

    /// The real use of `hkdfguard_open_file`: a payload written to disk
    /// (as the CLI's `wrap` does), read back, and unwrapped. Its other
    /// behavior needs no enclave and is covered by `HkdfGuardOpenFileTests`.
    @Test func wrapWriteOpenFileThenUnwrapRecoversOriginalDEK() throws {
        let service = "com.hkdfguard.tests.roundtrip.file"
        defer { Self.deleteKEK(service: service) }
        #expect(Self.createKEK(service: service) == 0)
        let dek = Self.randomDEK()

        let wrapResult = Self.wrap(dek, service: service)
        #expect(wrapResult.status == 0)

        let file = FileManager.default.temporaryDirectory
            .appendingPathComponent("hkdfguard.roundtrip.\(UUID().uuidString).key")
        defer { try? FileManager.default.removeItem(at: file) }
        try Data(wrapResult.wrapped).write(to: file)

        var read = [UInt8](repeating: 0, count: Self.wrappedLength)
        var readLen = Int32(Self.wrappedLength)
        let openStatus = file.path.withCString { pathCStr in
            read.withUnsafeMutableBufferPointer { readBuf in
                hkdfguard_open_file(pathPtr: pathCStr, outPtr: readBuf.baseAddress!, outLen: &readLen)
            }
        }
        #expect(openStatus == 0)
        #expect(readLen == Int32(Self.wrappedLength))
        #expect(read == wrapResult.wrapped)

        let unwrapResult = Self.unwrap(read, service: service)
        #expect(unwrapResult.status == 0)
        #expect(unwrapResult.plaintext == dek)
    }

    @Test func wrappedOutputHasExpectedLength() {
        let service = "com.hkdfguard.tests.wrapped.length"
        defer { Self.deleteKEK(service: service) }
        #expect(Self.createKEK(service: service) == 0)

        let result = Self.wrap(Self.randomDEK(), service: service)
        #expect(result.status == 0)
        #expect(result.wrapped.count == Self.wrappedLength)
    }

    @Test func kekFingerprintMatchesTheFingerprintEmbeddedInPayloads() {
        let service = "com.hkdfguard.tests.kek.fingerprint"
        defer { Self.deleteKEK(service: service) }

        func fingerprint(_ capacity: Int32) -> (status: Int32, bytes: [UInt8], len: Int32) {
            var out = [UInt8](repeating: 0, count: max(Int(capacity), 0))
            var len = capacity
            let status = service.withCString { servicePtr in
                out.withUnsafeMutableBufferPointer { hkdfguard_kek_fingerprint(servicePtr: servicePtr, outPtr: $0.baseAddress, outLen: &len) }
            }
            return (status, out, len)
        }

        #expect(fingerprint(32).status == -17, "no KEK yet must be kekNotFound")

        #expect(Self.createKEK(service: service) == 0)
        let tooSmall = fingerprint(31)
        #expect(tooSmall.status == -2)
        #expect(tooSmall.len == 32)

        let result = fingerprint(32)
        #expect(result.status == 0)
        #expect(result.len == 32)
        let wrapped = Self.wrap(Self.randomDEK(), service: service)
        #expect(wrapped.status == 0)
        #expect(Array(wrapped.wrapped.prefix(32)) == result.bytes)

        var len: Int32 = 32
        #expect(service.withCString { hkdfguard_kek_fingerprint(servicePtr: $0, outPtr: nil, outLen: &len) } == -1)
        var out = [UInt8](repeating: 0, count: 32)
        #expect(out.withUnsafeMutableBufferPointer { hkdfguard_kek_fingerprint(servicePtr: nil, outPtr: $0.baseAddress, outLen: &len) } == -8)
    }

    @Test func twoWrapsOfSameDEKProduceDifferentCiphertext() {
        // Each wrap uses a fresh ephemeral key + random AES-GCM nonce, so
        // wrapping the same DEK twice must never produce identical output —
        // this is what makes the scheme semantically secure rather than
        // just "encrypted."
        let service = "com.hkdfguard.tests.nonce.uniqueness"
        defer { Self.deleteKEK(service: service) }
        #expect(Self.createKEK(service: service) == 0)
        let dek = Self.randomDEK()
        let first = Self.wrap(dek, service: service)
        let second = Self.wrap(dek, service: service)

        #expect(first.status == 0)
        #expect(second.status == 0)
        #expect(first.wrapped != second.wrapped)
    }

    // MARK: - Service identifier behavior

    @Test func differentServicesGetIsolatedKeys() {
        // Each service string is meant to identify a distinct calling
        // application; wrapping under one service's KEK and unwrapping
        // under a different service's KEK must fail, not silently
        // succeed against the wrong key.
        let serviceA = "com.hkdfguard.tests.appA"
        let serviceB = "com.hkdfguard.tests.appB"
        defer {
            Self.deleteKEK(service: serviceA)
            Self.deleteKEK(service: serviceB)
        }
        #expect(Self.createKEK(service: serviceA) == 0)
        #expect(Self.createKEK(service: serviceB) == 0)

        let dek = Self.randomDEK()
        let wrapResult = Self.wrap(dek, service: serviceA)
        #expect(wrapResult.status == 0)

        let crossServiceResult = Self.unwrap(wrapResult.wrapped, service: serviceB)
        #expect(crossServiceResult.status != 0)
    }

    @Test func wrapRejectsEmptyServiceIdentifier() {
        // No defer/cleanup needed: an empty service is rejected before any
        // key provisioning happens, so nothing is ever created.
        let result = Self.wrap(Self.randomDEK(), service: "")
        #expect(result.status == -8) // invalidServiceIdentifier
    }

    @Test func unwrapRejectsEmptyServiceIdentifier() {
        let setupService = "com.hkdfguard.tests.empty.service.unwrap.setup"
        defer { Self.deleteKEK(service: setupService) }
        #expect(Self.createKEK(service: setupService) == 0)

        let wrapped = Self.wrap(Self.randomDEK(), service: setupService).wrapped
        let result = Self.unwrap(wrapped, service: "")
        #expect(result.status == -8) // invalidServiceIdentifier
    }

    // MARK: - Audit trail, end to end

    @Test func auditTrailRecordsCreationWrapUnwrapAndTamperingWithMatchingHashes() throws {
        HkdfGuardAuditTests.startCapturing()
        let service = "com.hkdfguard.tests.audit.e2e"
        let quoted = "service=\"\(service)\""
        Self.deleteKEK(service: service)
        defer { Self.deleteKEK(service: service) }

        #expect(Self.createKEK(service: service) == 0)
        #expect(Self.createKEK(service: service) == 0) // found, not created
        let created = HkdfGuardAuditTests.records(containing: quoted).filter { $0.contains("event=1000 ") }
        #expect(created.count == 1, "exactly one creation record: \(created)")
        #expect(created.first?.hasPrefix("[info] event=1000 op=hkdfguard_create_kek \(quoted) provider=SECURE_ENCLAVE keychain=") == true, "\(created)")

        let wrapped = Self.wrap(Self.randomDEK(), service: service)
        #expect(wrapped.status == 0)
        let hash = SHA256.hash(data: Data(wrapped.wrapped)).map { String(format: "%02x", $0) }.joined()
        let fingerprint = wrapped.wrapped.prefix(32).map { String(format: "%02x", $0) }.joined()

        #expect(Self.unwrap(wrapped.wrapped, service: service).status == 0)
        var tampered = wrapped.wrapped
        tampered[tampered.count - 1] ^= 0x01
        #expect(Self.unwrap(tampered, service: service).status == -11)

        let byHash = HkdfGuardAuditTests.records(containing: "payload_sha256=\(hash)")
        #expect(byHash.contains { $0.contains("event=1002 op=hkdfguard_wrap_dek result=OK \(quoted)") }, "\(byHash)")
        #expect(byHash.contains { $0.contains("event=1003 op=hkdfguard_unwrap_dek result=OK \(quoted)") }, "\(byHash)")
        #expect(byHash.allSatisfy { $0.contains("kek_fingerprint=\(fingerprint) ") }, "the payload's own fingerprint: \(byHash)")

        let integrity = HkdfGuardAuditTests.records(containing: quoted).filter { $0.contains("event=2003 ") }
        #expect(integrity.count == 1, "\(integrity)")
        #expect(integrity.first?.hasPrefix("[warning] event=2003 op=hkdfguard_unwrap_dek result=PAYLOAD_AUTH_FAILED(-11) \(quoted)") == true, "\(integrity)")
    }

    // MARK: - Size probes and argument order (as on Linux)

    @Test func sizeProbesWithANullOutReportTheSizeWithoutTouchingTheKeychain() {
        // `out = NULL, *out_len = 0`: -2 with the size to allocate. The
        // service has no KEK, so reaching the keychain would be -17 instead.
        let service = "com.hkdfguard.tests.size.probe"
        let dek = Self.randomDEK()
        let blob = [UInt8](repeating: 0, count: Self.wrappedLength)
        var len: Int32 = 0

        #expect(dek.withUnsafeBufferPointer { d in service.withCString { hkdfguard_wrap_dek(servicePtr: $0, dekPtr: d.baseAddress, dekLen: 32, outPtr: nil, outLen: &len) } } == -2)
        #expect(len == Int32(Self.wrappedLength))

        len = 0
        #expect(service.withCString { hkdfguard_generate_and_wrap_dek(servicePtr: $0, outPtr: nil, outLen: &len) } == -2)
        #expect(len == Int32(Self.wrappedLength))

        len = 0
        #expect(blob.withUnsafeBufferPointer { b in service.withCString { hkdfguard_unwrap_dek(servicePtr: $0, wrappedPtr: b.baseAddress, wrappedLen: Int32(b.count), outPtr: nil, outLen: &len) } } == -2)
        #expect(len == 32)
        #expect(!Self.kekExists(service: service).exists)
    }

    @Test func nullOutWithAPositiveCapacityOrANegativeCapacityIsInvalidArgument() {
        let service = "com.hkdfguard.tests.null.out"
        let dek = Self.randomDEK()
        let blob = [UInt8](repeating: 0, count: Self.wrappedLength)
        var out = [UInt8](repeating: 0, count: 256)

        for capacity: Int32 in [10, 200] {
            var len = capacity
            #expect(dek.withUnsafeBufferPointer { d in service.withCString { hkdfguard_wrap_dek(servicePtr: $0, dekPtr: d.baseAddress, dekLen: 32, outPtr: nil, outLen: &len) } } == -1, "wrap, capacity \(capacity)")
            len = capacity
            #expect(service.withCString { hkdfguard_generate_and_wrap_dek(servicePtr: $0, outPtr: nil, outLen: &len) } == -1, "generate, capacity \(capacity)")
        }
        var len: Int32 = 64
        #expect(blob.withUnsafeBufferPointer { b in service.withCString { hkdfguard_unwrap_dek(servicePtr: $0, wrappedPtr: b.baseAddress, wrappedLen: Int32(b.count), outPtr: nil, outLen: &len) } } == -1)

        out.withUnsafeMutableBufferPointer { o in
            var negative: Int32 = -1
            #expect(dek.withUnsafeBufferPointer { d in service.withCString { hkdfguard_wrap_dek(servicePtr: $0, dekPtr: d.baseAddress, dekLen: 32, outPtr: o.baseAddress, outLen: &negative) } } == -1)
            negative = -1
            #expect(service.withCString { hkdfguard_generate_and_wrap_dek(servicePtr: $0, outPtr: o.baseAddress, outLen: &negative) } == -1)
            negative = -1
            #expect(blob.withUnsafeBufferPointer { b in service.withCString { hkdfguard_unwrap_dek(servicePtr: $0, wrappedPtr: b.baseAddress, wrappedLen: Int32(b.count), outPtr: o.baseAddress, outLen: &negative) } } == -1)
            var capacity: Int32 = 64
            #expect(blob.withUnsafeBufferPointer { b in service.withCString { hkdfguard_unwrap_dek(servicePtr: $0, wrappedPtr: b.baseAddress, wrappedLen: -1, outPtr: o.baseAddress, outLen: &capacity) } } == -1, "negative wrapped_len")
        }
    }

    @Test func unwrapChecksTheServiceBeforeTheBufferAndThePayload() {
        // Linux's order: an invalid service (-8) is reported ahead of a
        // too-small buffer (-2) and a malformed payload length (-10).
        let short = [UInt8](repeating: 0, count: 10)
        #expect(Self.unwrapIntoMarkedBuffer(short, service: "bad-service", allocated: 64, declared: 64).status == -8)
        #expect(Self.unwrapIntoMarkedBuffer(short, service: "bad-service", allocated: 64, declared: 8).status == -8)
        #expect(Self.unwrapIntoMarkedBuffer(short, service: "com.hkdfguard.tests.order", allocated: 64, declared: 8).status == -2)
    }

    // MARK: - Zeroing `out` on failure (as on Linux)

    /// Calls hkdfguard_unwrap_dek with an `out` of `allocated` bytes filled
    /// with 0xAA, declaring only `declared` of them, and returns the status
    /// and the buffer afterwards.
    static func unwrapIntoMarkedBuffer(
        _ blob: [UInt8], service: String, allocated: Int, declared: Int32
    ) -> (status: Int32, out: [UInt8]) {
        var out = [UInt8](repeating: 0xAA, count: allocated)
        var outLen = declared
        let status = blob.withUnsafeBufferPointer { blobBuf in
            out.withUnsafeMutableBufferPointer { outBuf in
                service.withCString {
                    hkdfguard_unwrap_dek(servicePtr: $0, wrappedPtr: blobBuf.baseAddress, wrappedLen: Int32(blob.count), outPtr: outBuf.baseAddress, outLen: &outLen)
                }
            }
        }
        return (status, out)
    }

    @Test func unwrapZeroesTheDeclaredOutCapacityOnEveryFailure() {
        // Each failure is reported before any keychain work, so nothing
        // needs cleaning up: a malformed length (-10), an invalid service
        // (-8), and an unsupported suite byte (-12).
        var badSuite = [UInt8](repeating: 0, count: Self.wrappedLength)
        badSuite[32] = 0xEE
        let failures: [(blob: [UInt8], service: String, status: Int32)] = [
            ([UInt8](repeating: 0, count: 10), "com.hkdfguard.tests.zero.out", -10),
            ([UInt8](repeating: 0, count: Self.wrappedLength), "bad-service", -8),
            (badSuite, "com.hkdfguard.tests.zero.out", -12),
        ]
        for failure in failures {
            let result = Self.unwrapIntoMarkedBuffer(failure.blob, service: failure.service, allocated: 64, declared: 48)
            #expect(result.status == failure.status)
            #expect(result.out[0..<48].allSatisfy { $0 == 0 }, "status \(failure.status): declared capacity must be zeroed")
            #expect(result.out[48...].allSatisfy { $0 == 0xAA }, "status \(failure.status): nothing past the declared capacity may be touched")
        }
    }

    @Test func unwrapZeroesATooSmallOutBufferToo() {
        let result = Self.unwrapIntoMarkedBuffer(
            [UInt8](repeating: 0, count: Self.wrappedLength), service: "com.hkdfguard.tests.zero.small", allocated: 32, declared: 16
        )
        #expect(result.status == -2)
        #expect(result.out[0..<16].allSatisfy { $0 == 0 })
        #expect(result.out[16...].allSatisfy { $0 == 0xAA })
    }

    // MARK: - Input validation

    @Test func wrapRejectsIncorrectDEKLength() {
        // No defer/cleanup needed: the DEK-length check runs before any
        // key provisioning (wrapDekCore checks it before ever calling
        // getKEK), so nothing is ever created even without a prior
        // hkdfguard_create_kek call here.
        let tooShort = [UInt8](repeating: 0, count: 16)
        let result = Self.wrap(tooShort, service: "com.hkdfguard.tests.bad.dek.length")
        #expect(result.status == -1) // invalidInputLength
    }

    @Test func unwrapRejectsBlobShorterThanEphemeralKey() {
        // No defer/cleanup needed: the length check runs before any key
        // provisioning, so nothing is ever created.
        let tooShort = [UInt8](repeating: 0, count: 32)
        let result = Self.unwrap(tooShort, service: "com.hkdfguard.tests.short.blob")
        #expect(result.status == -10) // payloadMalformed
    }

    @Test func unwrapRejectsAnyLengthOtherThanTheExactWrappedLength() {
        // Every payload this library produces is exactly wrappedLength
        // bytes, so one byte more or less is rejected up front -- before
        // the service is even looked at (no KEK exists for this service,
        // yet the answer is payloadMalformed -10, not kekNotFound -17).
        for length in [Self.wrappedLength - 1, Self.wrappedLength + 1, Self.wrappedLength * 2] {
            let blob = [UInt8](repeating: 0, count: length)
            let result = Self.unwrap(blob, service: "com.hkdfguard.tests.inexact.length")
            #expect(result.status == -10, "length \(length)")
        }
    }

    @Test func theExportedSetupCallsPayTheFloor() {
        // Through the C entry points, every setup call is gated -- "doesn't
        // exist" included -- while argument errors return before the gate.
        let floor = Duration.milliseconds(300)
        setupMinDelayOverrideForTests.withLock { $0 = floor }
        defer { setupMinDelayOverrideForTests.withLock { $0 = .zero } }
        let clock = ContinuousClock()
        let service = "com.hkdfguard.tests.floor.\(UInt64.random(in: .min ... .max))"
        defer { Self.deleteKEK(service: service) }

        var fp = [UInt8](repeating: 0, count: 32)
        var fpLen: Int32 = 32
        var fpStatus: Int32 = 0
        func fingerprint(_ name: String, capacity: Int32 = 32) -> Int32 {
            fpLen = capacity
            return fp.withUnsafeMutableBufferPointer {
                hkdfguard_kek_fingerprint(servicePtr: name, outPtr: $0.baseAddress, outLen: &fpLen)
            }
        }

        var probe: (status: Int32, exists: Bool) = (-1, true)
        var created: Int32 = -1
        var elapsed = clock.measure { fpStatus = fingerprint(service) }
        #expect(fpStatus == -17)
        #expect(elapsed >= floor, "kek_fingerprint for a missing KEK took \(elapsed)")
        elapsed = clock.measure { probe = Self.kekExists(service: service) }
        #expect(probe.status == 0 && !probe.exists)
        #expect(elapsed >= floor, "kek_exists for a missing KEK took \(elapsed)")
        elapsed = clock.measure { created = Self.createKEK(service: service) }
        #expect(created == 0)
        #expect(elapsed >= floor, "create_kek took \(elapsed)")
        elapsed = clock.measure { probe = Self.kekExists(service: service) }
        #expect(probe.status == 0 && probe.exists)
        #expect(elapsed >= floor, "kek_exists for an existing KEK took \(elapsed)")
        elapsed = clock.measure { fpStatus = fingerprint(service) }
        #expect(fpStatus == 0)
        #expect(elapsed >= floor, "kek_fingerprint for an existing KEK took \(elapsed)")

        var exists: Int32 = -1
        var codes: [Int32] = []
        elapsed = clock.measure {
            codes = [
                hkdfguard_kek_exists(servicePtr: "bad-name", outExists: &exists),
                hkdfguard_kek_exists(servicePtr: "com.hkdfguard.tests.floor", outExists: nil),
                hkdfguard_create_kek(servicePtr: "bad_name"),
                hkdfguard_create_kek(servicePtr: nil),
                fingerprint("bad_name"),
                fingerprint(service, capacity: 0), // the size probe
            ]
        }
        #expect(codes == [-8, -1, -8, -8, -8, -2])
        #expect(elapsed < floor, "argument errors must not pay the floor; took \(elapsed)")
    }

    @Test func nullPointersAreReportedNotDereferenced() {
        // A NULL from a C caller is a contract violation, but the library
        // must report it -- -1 for buffers/lengths, -8 for the service --
        // rather than crash the host process.
        var outLen: Int32 = 1024
        var out = [UInt8](repeating: 0, count: 1024)
        var exists: Int32 = -1
        let dek = Self.randomDEK()
        let blob = [UInt8](repeating: 0, count: Self.wrappedLength)

        #expect(hkdfguard_keychain_mode(outMode: nil) == -1)
        #expect(hkdfguard_kek_exists(servicePtr: nil, outExists: &exists) == -8)
        #expect(exists == 0, "outExists must still be written")
        #expect(hkdfguard_kek_exists(servicePtr: "com.hkdfguard.tests.null", outExists: nil) == -1)
        #expect(hkdfguard_create_kek(servicePtr: nil) == -8)

        out.withUnsafeMutableBufferPointer { outBuf in
            dek.withUnsafeBufferPointer { dekBuf in
                blob.withUnsafeBufferPointer { blobBuf in
                    #expect(hkdfguard_wrap_dek(servicePtr: nil, dekPtr: dekBuf.baseAddress, dekLen: 32, outPtr: outBuf.baseAddress, outLen: &outLen) == -8)
                    #expect(hkdfguard_wrap_dek(servicePtr: "com.hkdfguard.tests.null", dekPtr: nil, dekLen: 32, outPtr: outBuf.baseAddress, outLen: &outLen) == -1)
                    #expect(hkdfguard_wrap_dek(servicePtr: "com.hkdfguard.tests.null", dekPtr: dekBuf.baseAddress, dekLen: 32, outPtr: nil, outLen: &outLen) == -1)
                    #expect(hkdfguard_wrap_dek(servicePtr: "com.hkdfguard.tests.null", dekPtr: dekBuf.baseAddress, dekLen: 32, outPtr: outBuf.baseAddress, outLen: nil) == -1)
                    #expect(hkdfguard_generate_and_wrap_dek(servicePtr: nil, outPtr: outBuf.baseAddress, outLen: &outLen) == -8)
                    #expect(hkdfguard_generate_and_wrap_dek(servicePtr: "com.hkdfguard.tests.null", outPtr: nil, outLen: &outLen) == -1)
                    #expect(hkdfguard_unwrap_dek(servicePtr: nil, wrappedPtr: blobBuf.baseAddress, wrappedLen: Int32(Self.wrappedLength), outPtr: outBuf.baseAddress, outLen: &outLen) == -8)
                    #expect(hkdfguard_unwrap_dek(servicePtr: "com.hkdfguard.tests.null", wrappedPtr: nil, wrappedLen: Int32(Self.wrappedLength), outPtr: outBuf.baseAddress, outLen: &outLen) == -1)
                    #expect(hkdfguard_unwrap_dek(servicePtr: "com.hkdfguard.tests.null", wrappedPtr: blobBuf.baseAddress, wrappedLen: Int32(Self.wrappedLength), outPtr: outBuf.baseAddress, outLen: nil) == -1)
                }
            }
        }
        #expect(Self.kekExists(service: "com.hkdfguard.tests.null").exists == false, "nothing may have been created")
    }

    // MARK: - Output buffer sizing

    @Test func wrapReportsRequiredCapacityWhenBufferTooSmall() {
        let service = "com.hkdfguard.tests.wrap.buffer.too.small"
        defer { Self.deleteKEK(service: service) }
        #expect(Self.createKEK(service: service) == 0)

        let result = Self.wrap(Self.randomDEK(), service: service, bufferCapacity: 10)
        #expect(result.status == -2) // outputBufferTooSmall
        #expect(result.requiredLen == Int32(Self.wrappedLength))
    }

    @Test func unwrapReportsRequiredCapacityWhenBufferTooSmall() {
        let service = "com.hkdfguard.tests.unwrap.buffer.too.small"
        defer { Self.deleteKEK(service: service) }
        #expect(Self.createKEK(service: service) == 0)

        let wrapped = Self.wrap(Self.randomDEK(), service: service).wrapped
        let result = Self.unwrap(wrapped, service: service, bufferCapacity: 4)
        #expect(result.status == -2) // outputBufferTooSmall
        #expect(result.requiredLen == Int32(Self.dekLength))
    }

    @Test func bufferSizingIsReportedBeforeAnyKeychainOrEnclaveWork() {
        // Output sizes are constants, so a too-small buffer must be
        // reported first -- here, for a service that has no KEK at all, the
        // answer is outputBufferTooSmall with the required size, not
        // kekNotFound. A sizing call therefore costs nothing, and unwrap
        // never decrypts a DEK for a caller who cannot receive it.
        let service = "com.hkdfguard.tests.sizing.before.kek"
        // No defer/cleanup needed: nothing is provisioned.

        let wrap = Self.wrap(Self.randomDEK(), service: service, bufferCapacity: 10)
        #expect(wrap.status == -2)
        #expect(wrap.requiredLen == Int32(Self.wrappedLength))

        let generate = Self.generateAndWrap(service: service, bufferCapacity: 10)
        #expect(generate.status == -2)
        #expect(generate.requiredLen == Int32(Self.wrappedLength))

        let blob = [UInt8](repeating: 0, count: Self.wrappedLength)
        let unwrap = Self.unwrap(blob, service: service, bufferCapacity: 4)
        #expect(unwrap.status == -2)
        #expect(unwrap.requiredLen == Int32(Self.dekLength))

        #expect(Self.kekExists(service: service).exists == false)
    }

    // MARK: - Tamper detection

    @Test func unwrapRejectsTamperedCiphertext() {
        let service = "com.hkdfguard.tests.tamper.detection"
        defer { Self.deleteKEK(service: service) }
        #expect(Self.createKEK(service: service) == 0)

        var wrapped = Self.wrap(Self.randomDEK(), service: service).wrapped
        // Flip a bit inside the AES-GCM ciphertext/tag region (well past
        // the 77-byte header), leaving the
        // fingerprint itself untouched so this exercises the AEAD tag check
        // specifically, not the fingerprint check.
        wrapped[wrapped.count - 1] ^= 0xFF

        let result = Self.unwrap(wrapped, service: service)
        #expect(result.status == -11) // decryptionFailed — the GCM tag check must catch this
    }

    @Test func unwrapRejectsATamperedSaltOrNonce() {
        // The salt picks the ECDH point and salts HKDF; the nonce is the
        // AEAD's. Both are in the authenticated header, so a flipped bit in
        // either is an authentication failure, never a different DEK.
        let service = "com.hkdfguard.tests.tamper.salt.nonce"
        defer { Self.deleteKEK(service: service) }
        #expect(Self.createKEK(service: service) == 0)

        let wrapped = Self.wrap(Self.randomDEK(), service: service).wrapped
        for offset in [Self.saltOffset, Self.saltOffset + 31, Self.nonceOffset, Self.nonceOffset + 11] {
            var tampered = wrapped
            tampered[offset] ^= 0x01
            #expect(Self.unwrap(tampered, service: service).status == -11, "byte \(offset)")
        }
    }

    // MARK: - Only the KEK holder can create a payload

    /// The KEK's private key, rebuilt from its keychain item the way the
    /// library does -- so a test can stand in for this host (the Secure
    /// Enclave) and, with only `.publicKey`, for an attacker.
    private static func enclaveKEK(service: String) throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
        var query = keychainQuery(service: service)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        try #require(SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess)
        let blob = try #require(result as? Data)
        return try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob)
    }

    /// A payload in this library's format, sealed under the AES key HKDF
    /// derives from `sharedSecret` -- the wire format, rebuilt independently.
    private static func sealPayload(
        dek: [UInt8], service: String, kekPublicKey: P256.KeyAgreement.PublicKey,
        salt: Data, sharedSecret: SharedSecret
    ) throws -> [UInt8] {
        let nonceBytes = Data((0..<12).map { _ in UInt8.random(in: .min ... .max) })
        var header = kekFingerprint(kekPublicKey)
        header.append(0x01)
        header.append(salt)
        header.append(nonceBytes)
        let key = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA512.self, salt: salt,
            sharedInfo: wrappingKeyInfo(service: service, header: header), outputByteCount: 32)
        let box = try AES.GCM.seal(dek, using: key, nonce: AES.GCM.Nonce(data: nonceBytes), authenticating: header)
        return Array(header + box.ciphertext + box.tag)
    }

    @Test func aPayloadForgedWithOnlyThePublicKeyIsRefused() throws {
        // The reason for the hashed point: with an ECIES-style e * KEK_pub
        // secret, anyone holding the public key could seal a DEK of their
        // choosing. Here the attacker does exactly that, in
        // the real format, with the real fingerprint and service -- and is
        // refused, because ECDH(KEK_priv, H(salt)) is not something the
        // public key lets them compute.
        let service = "com.hkdfguard.tests.forgery.public.key"
        defer { Self.deleteKEK(service: service) }
        #expect(Self.createClassicalKEK(service: service) == 0)
        let kek = try Self.enclaveKEK(service: service)
        let dek = Self.randomDEK()
        let salt = Data((0..<32).map { _ in UInt8.random(in: .min ... .max) })

        // Control: the same builder with the genuine secret -- the Secure
        // Enclave's ECDH against the salt's point -- is accepted, so the
        // refusal below is about the secret, not a format mistake here.
        let point = try #require(payloadECDHPoint(salt: salt))
        let genuine = try Self.sealPayload(
            dek: dek, service: service, kekPublicKey: kek.publicKey, salt: salt,
            sharedSecret: kek.sharedSecretFromKeyAgreement(with: point))
        #expect(genuine.count == Self.wrappedLength)
        let opened = Self.unwrap(genuine, service: service)
        #expect(opened.status == 0)
        #expect(opened.plaintext == dek)

        // Attacks with nothing but the public key.
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let forged = try Self.sealPayload(
            dek: dek, service: service, kekPublicKey: kek.publicKey, salt: salt,
            sharedSecret: ephemeral.sharedSecretFromKeyAgreement(with: kek.publicKey))
        #expect(Self.unwrap(forged, service: service).status == -11, "ECIES-style e * KEK_pub")

        let pointKey = P256.KeyAgreement.PrivateKey()
        let forgedWithOwnPoint = try Self.sealPayload(
            dek: dek, service: service, kekPublicKey: kek.publicKey, salt: salt,
            sharedSecret: pointKey.sharedSecretFromKeyAgreement(with: point))
        #expect(Self.unwrap(forgedWithOwnPoint, service: service).status == -11, "a random scalar times H(salt)")
    }

    @Test func aPayloadForOneServiceDoesNotOpenUnderAnother() throws {
        // Two services that (by misuse) share a KEK: the service name is in
        // HKDF's info, so the key differs and the tag fails.
        let service = "com.hkdfguard.tests.binding.service.a"
        defer { Self.deleteKEK(service: service) }
        #expect(Self.createClassicalKEK(service: service) == 0)
        let kek = try Self.enclaveKEK(service: service)
        let salt = Data((0..<32).map { _ in UInt8.random(in: .min ... .max) })
        let point = try #require(payloadECDHPoint(salt: salt))
        let other = try Self.sealPayload(
            dek: Self.randomDEK(), service: "com.hkdfguard.tests.binding.service.b", kekPublicKey: kek.publicKey,
            salt: salt, sharedSecret: kek.sharedSecretFromKeyAgreement(with: point))
        #expect(Self.unwrap(other, service: service).status == -11)
    }

    @Test func unwrapRejectsAnUnsupportedSuiteByteBeforeTouchingTheKeychain() {
        // Byte 32 names the ciphersuite. No KEK exists for this service, yet
        // the answer is -12, not -17: the suite is checked first.
        let service = "com.hkdfguard.tests.unsupported.suite"
        var blob = [UInt8](repeating: 0x5A, count: Self.wrappedLength)
        blob[32] = 0x03 // 0x01 and 0x02 are implemented
        #expect(Self.unwrap(blob, service: service).status == -12)
        #expect(Self.kekExists(service: service).exists == false, "nothing may have been created")
    }

    @Test func unwrapRejectsTamperedFingerprint() {
        // Distinct from tamper detection on the ciphertext above: flipping
        // a bit inside the fingerprint itself (the payload's leading 32
        // bytes) must be caught by the fingerprint comparison specifically
        // — before AES-GCM is even attempted — and report
        // fingerprintMismatch, not decryptionFailed.
        let service = "com.hkdfguard.tests.tamper.fingerprint"
        defer { Self.deleteKEK(service: service) }
        #expect(Self.createKEK(service: service) == 0)

        var wrapped = Self.wrap(Self.randomDEK(), service: service).wrapped
        wrapped[0] ^= 0xFF

        let result = Self.unwrap(wrapped, service: service)
        #expect(result.status == -16) // fingerprintMismatch
    }

    @Test func unwrapRejectsGarbageInput() {
        // Unlike the length-check-only validation tests above, this blob
        // is a full wrappedLength bytes, so it passes the length/service
        // checks. No KEK is created for this service, so this is expected
        // to fail with kekNotFound rather than reach the fingerprint check
        // or decryption — either way, it must not succeed.
        let service = "com.hkdfguard.tests.garbage.input"
        defer { Self.deleteKEK(service: service) }

        let garbage = (0..<Self.wrappedLength).map { UInt8($0 & 0xFF) }
        let result = Self.unwrap(garbage, service: service)
        #expect(result.status != 0)
    }

    // MARK: - hkdfguard_generate_and_wrap_dek

    @Test func generateAndWrapProducesAnUnwrappableDEK() {
        let service = "com.hkdfguard.tests.generate.and.wrap.roundtrip"
        defer { Self.deleteKEK(service: service) }
        #expect(Self.createKEK(service: service) == 0)

        let result = Self.generateAndWrap(service: service)
        #expect(result.status == 0)
        #expect(result.wrapped.count == Self.wrappedLength)

        let unwrapResult = Self.unwrap(result.wrapped, service: service)
        #expect(unwrapResult.status == 0)
        #expect(unwrapResult.plaintext.count == Self.dekLength)
    }

    @Test func twoGenerateAndWrapCallsProduceDifferentDEKs() {
        // Each call sources its own fresh CSPRNG randomness for the DEK
        // itself, not just a fresh nonce/ephemeral key - this is the check
        // that actually distinguishes "generates a new DEK" from "wraps a
        // fixed/reused buffer."
        let service = "com.hkdfguard.tests.generate.and.wrap.uniqueness"
        defer { Self.deleteKEK(service: service) }
        #expect(Self.createKEK(service: service) == 0)

        let first = Self.generateAndWrap(service: service)
        let second = Self.generateAndWrap(service: service)
        #expect(first.status == 0)
        #expect(second.status == 0)

        let firstDEK = Self.unwrap(first.wrapped, service: service).plaintext
        let secondDEK = Self.unwrap(second.wrapped, service: service).plaintext
        #expect(firstDEK != secondDEK)
    }

    @Test func generateAndWrapRejectsEmptyServiceIdentifier() {
        // No defer/cleanup needed: an empty service is rejected before any
        // key provisioning or DEK generation happens.
        let result = Self.generateAndWrap(service: "")
        #expect(result.status == -8) // invalidServiceIdentifier
    }

    @Test func generateAndWrapReportsRequiredCapacityWhenBufferTooSmall() {
        let service = "com.hkdfguard.tests.generate.and.wrap.buffer.too.small"
        defer { Self.deleteKEK(service: service) }
        #expect(Self.createKEK(service: service) == 0)

        let result = Self.generateAndWrap(service: service, bufferCapacity: 10)
        #expect(result.status == -2) // outputBufferTooSmall
        #expect(result.requiredLen == Int32(Self.wrappedLength))
    }
}

/// `hkdfguard_harden_process(_with_flags)`. It changes process-wide,
/// irreversible state (core limit, PT_DENY_ATTACH), and doing so inside the
/// test process is deliberate: the test agent is exactly the kind of
/// development host the advisory mode exists for -- `xctest` is ad-hoc
/// signed with get-task-allow and no Hardened Runtime, and the hosted test
/// app is built without the Hardened Runtime -- so it can check both modes
/// against a known-weak signature. Under Xcode's debugger the process is
/// traced, and hardening must then refuse rather than let the kernel kill it.
@Suite(.serialized)
struct HkdfGuardHardenProcessTests {
    static let requireProtectedSignature: UInt32 = 0x1 // HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE

    static func isBeingTraced() -> Bool {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        #expect(sysctl(&mib, u_int(mib.count), &info, &size, nil, 0) == 0)
        return info.kp_proc.p_flag & P_TRACED != 0
    }

    @Test func unknownFlagBitsAreRejectedAsInvalidArgument() {
        #expect(hkdfguard_harden_process_with_flags(flags: ~Self.requireProtectedSignature) == -1)
        #expect(hkdfguard_harden_process_with_flags(flags: 0x8000_0000) == -1)
    }

    @Test func theTestHostsSignatureIsReportedAsWeak() {
        // Neither xctest nor the hosted test app is Hardened-Runtime signed
        // without get-task-allow, so there is always a reason to report.
        #expect(!codeSignatureWeaknesses().isEmpty)
    }

    @Test func advisoryModeHardensAndOnlyStrictModeFailsOnAWeakSignature() {
        guard !Self.isBeingTraced() else {
            // Under a debugger: refused (-20), never PT_DENY_ATTACH, which
            // would terminate this process.
            #expect(hkdfguard_harden_process() == -20)
            return
        }

        #expect(hkdfguard_harden_process() == 0, "advisory: a weak signature is only logged")
        #expect(hkdfguard_harden_process() == 0, "must be idempotent")
        #expect(hkdfguard_harden_process_with_flags(flags: 0) == 0)

        var limit = rlimit(rlim_cur: 1, rlim_max: 1)
        #expect(getrlimit(RLIMIT_CORE, &limit) == 0)
        #expect(limit.rlim_cur == 0 && limit.rlim_max == 0, "core dumps must be disabled, hard limit included")

        #expect(
            hkdfguard_harden_process_with_flags(flags: Self.requireProtectedSignature) == -20,
            "strict: this test host's weak signature must be a failure"
        )
        // Strict mode's failure must not undo or skip what it could apply.
        #expect(getrlimit(RLIMIT_CORE, &limit) == 0)
        #expect(limit.rlim_cur == 0 && limit.rlim_max == 0)
    }
}

/// Drift guard: the shared C ABI must not drift between this library and
/// hkdfguard-native-linux, the source of record. Checks the two headers
/// against each other, and the Swift status enums -- hand-maintained copies
/// of the table -- against the header. Pure text checks: no keychain or Secure Enclave. Skipped when the
/// Linux repository isn't checked out next to this one.
@Suite
struct HkdfGuardCrossPlatformABITests {
    static let macRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent() // HkdfGuardNativeMacOSTests
        .deletingLastPathComponent() // hkdfguard-native-mac
    static let macHeader = macRoot.appendingPathComponent("HkdfGuardNativeMacOS/hkdfguard.h")
    static let linuxHeader = macRoot
        .deletingLastPathComponent()
        .appendingPathComponent("hkdfguard-native-linux/include/hkdfguard.h")
    static let linuxPresent = FileManager.default.fileExists(atPath: linuxHeader.path)
    static let linuxMissing = Comment(rawValue: "hkdfguard-native-linux is not checked out next to this repository")

    /// The functions only this platform exports, as its header documents.
    static let macOnlyFunctions: Set<String> = ["hkdfguard_keychain_mode", "hkdfguard_machine_policy", "hkdfguard_kek_suite"]
    /// The Linux functions this platform doesn't export, as its header documents.
    static let linuxOnlyFunctions: Set<String> = ["hkdfguard_security_model", "hkdfguard_key_file_principal_trusted"]

    static func read(_ url: URL) throws -> String {
        try String(contentsOf: url, encoding: .utf8)
    }

    /// `#define HKDFGUARD_NAME value` -> value, for integer values like `0`,
    /// `(-17)`, `32`, or `0x1u`.
    static func defines(in text: String) -> [String: Int] {
        var result: [String: Int] = [:]
        let pattern = /(?m)^#define\s+(HKDFGUARD_[A-Z0-9_]+)\s+\(?(-?)(0x[0-9A-Fa-f]+|[0-9]+)u?\)?/
        for match in text.matches(of: pattern) {
            let digits = String(match.3)
            let magnitude = digits.hasPrefix("0x") ? Int(digits.dropFirst(2), radix: 16)! : Int(digits)!
            result[String(match.1)] = match.2.isEmpty ? magnitude : -magnitude
        }
        return result
    }

    /// Names of the functions a header declares (`int name(`, optionally
    /// behind an export macro such as Windows' HKDFGUARD_API).
    static func functions(in text: String) -> Set<String> {
        let pattern = /(?m)^\s*(?:[A-Z_]+\s+)?int\s+(hkdfguard_[a-z_]+)\s*\(/
        return Set(text.matches(of: pattern).map { String($0.1) })
    }

    /// The status codes: HKDFGUARD_OK and every HKDFGUARD_ERR_*.
    static func statusCodes(_ all: [String: Int]) -> [String: Int] {
        all.filter { $0.key == "HKDFGUARD_OK" || $0.key.hasPrefix("HKDFGUARD_ERR_") }
    }

    @Test func theLibraryHasNoTrapsOnItsExportPaths() throws {
        // Linux catches a panic at every export and Windows an exception,
        // returning a status either way. A Swift runtime trap can't be
        // caught: it ends the host process. So the library must contain no
        // force-unwrap, `try!`, `as!`, `fatalError`, `precondition`,
        // `preconditionFailure` or `assertionFailure` -- a failure that
        // "can't happen" returns INTERNAL_ERROR (-6) instead (see `copyOut`).
        // Comments and string literals are skipped; `!=` and prefix `!`
        // (negation) are not unwraps.
        let source = try String(
            contentsOf: Self.macRoot.appendingPathComponent("HkdfGuardNativeMacOS/HkdfGuardNativeMacOS.swift"),
            encoding: .utf8)
        let trap = try Regex(#"(?:[\w)\]]!(?!=))|\btry!|\bas!|\bfatalError\(|\bprecondition\(|\bpreconditionFailure\(|\bassertionFailure\("#)
        let stringLiteral = try Regex(#""(?:[^"\\]|\\.)*""#)
        var offenders: [String] = []
        for (number, line) in source.split(separator: "\n", omittingEmptySubsequences: false).enumerated() {
            var code = String(line).replacing(stringLiteral, with: "\"\"")
            if let comment = code.range(of: "//") {
                code = String(code[..<comment.lowerBound])
            }
            if code.contains(trap) {
                offenders.append("line \(number + 1): \(line.trimmingCharacters(in: .whitespaces))")
            }
        }
        #expect(offenders.isEmpty, "a runtime trap on an export path would crash the host process:\n\(offenders.joined(separator: "\n"))")
    }

    @Test(.enabled(if: linuxPresent, linuxMissing))
    func statusCodesAndFlagsMatchLinuxExactly() throws {
        let linux = Self.defines(in: try Self.read(Self.linuxHeader))
        let mac = Self.defines(in: try Self.read(Self.macHeader))

        let linuxShared = linux.filter { Self.isSharedConstant($0.key) }
        let macShared = mac.filter { Self.isSharedConstant($0.key) }
        #expect(!linuxShared.isEmpty, "parsed no constants from the Linux header")
        for (name, value) in linuxShared.sorted(by: { $0.key < $1.key }) {
            #expect(macShared[name] == value, "\(name): Linux \(value), macOS \(macShared[name].map(String.init) ?? "missing")")
        }
        for name in Set(macShared.keys).subtracting(linuxShared.keys).sorted() {
            Issue.record("\(name) is defined only in the macOS header: add it to Linux's (the source of record) first")
        }

        // Same name everywhere, per-platform value.
        #expect(linux["HKDFGUARD_WRAPPED_MAX_LEN"] != nil && mac["HKDFGUARD_WRAPPED_MAX_LEN"] != nil)
    }

    /// Constants whose value must be identical on every platform.
    static func isSharedConstant(_ name: String) -> Bool {
        name == "HKDFGUARD_OK" || name == "HKDFGUARD_DEK_LEN"
            || name.hasPrefix("HKDFGUARD_ERR_") || name.hasPrefix("HKDFGUARD_HARDEN_")
    }

    @Test(.enabled(if: linuxPresent, linuxMissing))
    func everySharedFunctionIsDeclaredAndOnlyTheDocumentedOnesAreMacOnly() throws {
        let linux = Self.functions(in: try Self.read(Self.linuxHeader))
        let mac = Self.functions(in: try Self.read(Self.macHeader))
        #expect(linux.count >= 8, "parsed too few functions from the Linux header: \(linux.sorted())")

        let missing = linux.subtracting(mac)
        #expect(missing == Self.linuxOnlyFunctions, "Linux-only functions are \(missing.sorted()); the headers document \(Self.linuxOnlyFunctions.sorted())")
        let extra = mac.subtracting(linux)
        #expect(extra == Self.macOnlyFunctions, "macOS-only functions are \(extra.sorted()); the headers document \(Self.macOnlyFunctions.sorted())")
    }

    @Test func theMacHeaderUsesIntLikeLinuxAndWindows() throws {
        // The shared decision: every function returns `int` and takes `int`
        // lengths and `int*` out-parameters (flags: `unsigned int`), as the
        // Linux and Windows headers declare them. `int32_t` is the same
        // 32-bit type on every macOS target, so this is about the source a
        // caller reads and copies, not the binary interface.
        let mac = try Self.read(Self.macHeader)
        #expect(!mac.contains("int32_t"), "the macOS header must declare int, not int32_t, as Linux and Windows do")
    }

    /// Pairs each `case name = value` in `enumBody` with the HKDFGUARD_*
    /// name it is labelled with -- in a `///` line above it (the library) or
    /// a `// ERR_...` comment after it (the CLI).
    static func labelledCases(in enumBody: Substring) -> [(label: String, value: Int)] {
        var result: [(String, Int)] = []
        var pendingLabel: String?
        for line in enumBody.split(separator: "\n", omittingEmptySubsequences: false) {
            // The label is the first line of a case's doc comment; later
            // lines may mention other HKDFGUARD_* names.
            if pendingLabel == nil, let doc = line.firstMatch(of: /^\s*\/\/\/\s*(HKDFGUARD_[A-Z0-9_]+)/) {
                pendingLabel = String(doc.1)
            }
            guard let match = line.firstMatch(of: /^\s*case\s+\w+\s*=\s*(-?[0-9]+)(?:\s*\/\/\s*([A-Z0-9_]+))?/) else { continue }
            let label = match.2.map { "HKDFGUARD_" + $0 } ?? pendingLabel
            if let label { result.append((label, Int(match.1)!)) }
            pendingLabel = nil
        }
        return result
    }

    static func enumBody(_ source: String, startingAt marker: String) -> Substring? {
        guard let start = source.range(of: marker),
              let end = source.range(of: "\n}\n", range: start.upperBound..<source.endIndex)
        else { return nil }
        return source[start.upperBound..<end.lowerBound]
    }

    @Test(.enabled(if: linuxPresent, linuxMissing))
    func everyStatusCaseHasItsSharedNameAndNumber() throws {
        let linux = Self.defines(in: try Self.read(Self.linuxHeader))
        for status in HKDFGuardStatus.allCases {
            let name = "HKDFGUARD_" + status.sharedName
            #expect(linux[name] == Int(status.rawValue), "\(status) is \(status.rawValue) named \(name); Linux says \(linux[name].map(String.init) ?? "no such code")")
        }
    }

    @Test(arguments: [
        ("HkdfGuardNativeMacOS/HkdfGuardNativeMacOS.swift", "enum HKDFGuardStatus: Int32, CaseIterable {"),
        ("hkdfguard-cli/Sources/hkdfguard/main.swift", "enum HKDFGuardStatus: Int32 {"),
    ])
    func swiftStatusEnumsMatchTheHeader(file: String, marker: String) throws {
        let header = Self.defines(in: try Self.read(Self.macHeader))
        let source = try Self.read(Self.macRoot.appendingPathComponent(file))
        let body = try #require(Self.enumBody(source, startingAt: marker), "no \(marker) in \(file)")

        let cases = Self.labelledCases(in: body)
        let caseCount = body.matches(of: /(?m)^\s*case\s+\w+\s*=/).count
        #expect(cases.count == caseCount, "\(file): \(caseCount - cases.count) status case(s) carry no HKDFGUARD_* label")
        for (label, value) in cases {
            #expect(header[label] == value, "\(file): case labelled \(label) is \(value), the header says \(header[label].map(String.init) ?? "it isn't defined")")
        }
    }
}


/// The audit trail's records, checked as Linux's src/audit.rs tests check
/// its: event IDs, severities, fields, and what is never recorded. Records
/// are captured in memory (`auditCapture`) and filtered by each test's own
/// service names or paths, since tests run in parallel.
@Suite
struct HkdfGuardAuditTests {
    static func startCapturing() {
        auditCapture.withLock { if $0 == nil { $0 = [] } }
    }

    static func records(containing needle: String) -> [String] {
        auditCapture.withLock { ($0 ?? []).filter { $0.contains(needle) } }
    }

    static func last(_ needle: String) -> String {
        records(containing: needle).last ?? "(no record containing \(needle))"
    }

    init() { Self.startCapturing() }

    @Test func recordsNameTheServiceAndTheCaller() {
        auditOperationFailed(.createKek, service: "audit.test.caller", code: -19)
        let record = Self.last("\"audit.test.caller\"")
        #expect(record.hasPrefix("[error] event=2002 op=hkdfguard_create_kek result=KEK_INVALID(-19) service=\"audit.test.caller\" "), "\(record)")
        #expect(record.contains(" uid=\(getuid()) euid=\(geteuid()) pid=\(getpid()) exe=\"/"), "\(record)")
        #expect(record.contains(" msg=\"hkdfguard_create_kek failed: "), "\(record)")
    }

    @Test func eachCodeGetsTheWindowsEventIdAndSeverity() {
        let cases: [(code: Int32, event: Int, severity: String)] = [
            (-18, 2000, "warning"),   // KEK_ACCESS_DENIED
            (-19, 2002, "error"),     // KEK_INVALID
            (-9, 2004, "error"),      // POLICY_INVALID
            (-3, 2005, "error"),      // PROVIDER_UNAVAILABLE
            (-5, 2005, "error"),      // CRYPTO_ERROR
            (-6, 2005, "error"),      // INTERNAL_ERROR
            (-96, 2005, "error"), (-97, 2005, "error"), (-98, 2005, "error"), (-99, 2005, "error"), (-100, 2005, "error"),
        ]
        for (code, event, severity) in cases {
            let service = "audit.test.ids\(-code)"
            auditOperationFailed(.kekExists, service: service, code: code)
            let record = Self.last("\"\(service)\"")
            #expect(record.hasPrefix("[\(severity)] event=\(event) "), "code \(code): \(record)")
        }
    }

    @Test func callerMistakesAndNotFoundAreNotAudited() {
        for code: Int32 in [-1, -2, -8, -17] {
            auditOperationFailed(.wrap, service: "audit.test.quiet", code: code)
        }
        #expect(Self.records(containing: "audit.test.quiet").isEmpty)
    }

    @Test func payloadCodesAreAuditedOnUnwrapOnly() {
        auditOperationFailed(.wrap, service: "audit.test.wraponly", code: -10)
        #expect(Self.records(containing: "audit.test.wraponly").isEmpty)
        for code: Int32 in [-11, -16, -10, -12] {
            auditOperationFailed(.unwrap, service: "audit.test.integrity", code: code)
        }
        let records = Self.records(containing: "audit.test.integrity")
        #expect(records.count == 4)
        #expect(records.allSatisfy { $0.hasPrefix("[warning] event=2003 op=hkdfguard_unwrap_dek ") }, "\(records)")
    }

    @Test func quotingKeepsEveryValueOnOneLine() {
        #expect(auditQuote(Array("plain/path.key".utf8)) == "\"plain/path.key\"")
        #expect(auditQuote(Array("a\"b\\c".utf8)) == "\"a\\x22b\\x5cc\"")
        #expect(auditQuote(Array("line\nbreak".utf8)) == "\"line\\x0abreak\"", "no forged second record")
        #expect(auditQuote([0x63, 0x61, 0x66, 0xC3, 0xA9, 0xFF]) == "\"caf\\xc3\\xa9\\xff\"")
    }

    @Test func aPlaintextKeyFileIsAuditedByPath() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hkdfguard-audit-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("plain.key")
        try Data(repeating: 0x41, count: 32).write(to: file)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)

        var out = [UInt8](repeating: 0, count: 125)
        var outLen: Int32 = 125
        let rc = out.withUnsafeMutableBufferPointer { hkdfguard_open_file(pathPtr: file.path, outPtr: $0.baseAddress, outLen: &outLen) }
        #expect(rc == -37)
        let record = Self.last(file.lastPathComponent)
        #expect(record.hasPrefix("[error] event=2006 op=hkdfguard_open_file result=FILE_PLAINTEXT_KEY(-37) path=\"\(file.path)\" "), "\(record)")
    }

    @Test func otherOpenFileFailuresAreNotAudited() {
        var out = [UInt8](repeating: 0, count: 125)
        var outLen: Int32 = 125
        let missing = "/nonexistent/hkdfguard-audit-quiet/absent.key"
        _ = out.withUnsafeMutableBufferPointer { hkdfguard_open_file(pathPtr: missing, outPtr: $0.baseAddress, outLen: &outLen) }
        #expect(Self.records(containing: "hkdfguard-audit-quiet").isEmpty)
    }

    @Test func setupCallsWarnExactlyOnceAfterTen() {
        var counter = SetupCallCounter()
        let fired = (1...25).map { _ in counter.record() }
        #expect(fired.filter { $0 }.count == 1)
        #expect(fired.firstIndex(of: true) == 10, "on the 11th call")
    }

    @Test func theSetupCallRecordIsAWarningWith2007() {
        let before = Self.records(containing: "event=2007 ").count
        auditSetupCallsExceeded(floorMs: 1000)
        let records = Self.records(containing: "event=2007 ")
        #expect(records.count == before + 1)
        #expect(records.last?.hasPrefix("[warning] event=2007 calls=10 setup_min_delay_ms=1000 ") == true, "\(records)")
        #expect(records.last?.contains("plus at least 1000 ms") == true, "\(records)")
    }
}

/// The setup gate (`gatedSetup`) on its own, without the Secure Enclave:
/// each test passes its own floor rather than touching the shared
/// override, so these run safely alongside the other suites.
// Serialized: the gate is one lock for the whole process, so these tests
// would otherwise queue behind each other. The timing tests below also
// start their clocks inside the body, so time spent waiting for the gate --
// behind another suite's setup call, say -- is never counted against them.
@Suite(.serialized)
struct HkdfGuardSetupGateTests {
    @Test func theProductionFloorIsOneSecondAsOnLinuxAndWindows() {
        #expect(setupMinDelay == .milliseconds(1_000))
    }

    @Test func aFastCallIsHeldToTheFloor() {
        let floor = Duration.milliseconds(200)
        let clock = ContinuousClock()
        var result = 0
        let elapsed = clock.measure { result = gatedSetup(floor: floor) { 42 } }
        #expect(result == 42)
        #expect(elapsed >= floor, "took \(elapsed)")
    }

    @Test func aSlowCallPaysNoMoreThanItsOwnTime() {
        let floor = Duration.milliseconds(100)
        let clock = ContinuousClock()
        var bodyStarted = clock.now
        var bodyEnded = clock.now
        gatedSetup(floor: floor) {
            bodyStarted = clock.now // once inside the gate: no queueing counted
            Thread.sleep(forTimeInterval: 0.3)
            bodyEnded = clock.now
        }
        let returned = clock.now
        #expect(returned - bodyStarted >= .milliseconds(300))
        // Only what the gate adds after the body counts: a loaded CI runner
        // can oversleep the body's own 300 ms by more than the floor.
        let added = returned - bodyEnded
        #expect(added < floor, "the floor is a minimum, not added on top; the gate added \(added)")
    }

    @Test func aZeroFloorDoesNotWait() {
        let clock = ContinuousClock()
        var bodyStarted = clock.now
        gatedSetup(floor: .zero) { bodyStarted = clock.now }
        let elapsed = clock.now - bodyStarted
        #expect(elapsed < .milliseconds(100), "took \(elapsed)")
    }

    @Test func callsAreSerializedAcrossThreads() {
        // Three concurrent callers: never two inside at once, and together
        // they take at least three floors.
        let floor = Duration.milliseconds(150)
        let inside = OSAllocatedUnfairLock(initialState: (now: 0, peak: 0))
        let clock = ContinuousClock()
        let elapsed = clock.measure {
            DispatchQueue.concurrentPerform(iterations: 3) { _ in
                gatedSetup(floor: floor) {
                    inside.withLock { $0.now += 1; $0.peak = max($0.peak, $0.now) }
                    Thread.sleep(forTimeInterval: 0.01)
                    inside.withLock { $0.now -= 1 }
                }
            }
        }
        #expect(inside.withLock { $0.peak } == 1)
        #expect(elapsed >= floor * 3, "took \(elapsed)")
    }
}

/// The salt-to-point hash on its own, without the Secure Enclave: RFC 9380
/// `P256_XMD:SHA-256_SSWU_RO_`, checked against the RFC's own vectors, then
/// under HkdfGuard's DST against values the Linux library pins too
/// (`payload_ecdh_point_known_vectors` and the `known_answer` module in
/// src/crypto.rs), so both libraries hash a salt to the same point.
@Suite
struct HkdfGuardPayloadPointTests {
    private static func hex(_ s: String) -> Data {
        var out = Data()
        var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            out.append(UInt8(s[i..<j], radix: 16)!)
            i = j
        }
        return out
    }

    @Test func matchesRFC9380AppendixJ11() throws {
        let dst = Data("QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_".utf8)
        for (msg, x, y) in [
            ("", "2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4",
             "8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415"),
            ("abc", "0bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f",
             "5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71ffd424212e"),
            ("abcdef0123456789", "65038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80",
             "cad44d40a656e7aff4002a8de287abc8ae0482b5ae825822bb870d6df9b56ca3"),
        ] {
            let point = try #require(hashToCurveP256(message: Data(msg.utf8), dst: dst))
            #expect(point.x963Representation == Data([0x04]) + Self.hex(x) + Self.hex(y), "msg \"\(msg)\"")
        }
    }

    @Test func matchesRFC9380HashToFieldIntermediates() {
        // msg "" of Appendix J.1.1: u0 and u1, to localize a failure above.
        let dst = Data("QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_".utf8)
        let uniform = [UInt8](expandMessageXMD(message: Data(), dst: dst, length: 96))
        #expect(P256Field.reduce(uniform[0..<48]).bigEndianBytes
            == [UInt8](Self.hex("ad5342c66a6dd0ff080df1da0ea1c04b96e0330dd89406465eeba11582515009")))
        #expect(P256Field.reduce(uniform[48..<96]).bigEndianBytes
            == [UInt8](Self.hex("8c0f1d43204bd6f6ea70ae8013070a1518b43873bcd850aafa0a9e220e2eea5a")))
    }

    @Test func matchesTheLinuxLibrarysVectors() throws {
        for (salt, compressed) in [
            (Data(0..<32), "03877847fb8a2cfbcf800b4191284aaba0934fd52e7e1971d30fa14b296544229e"),
            (Data(repeating: 0x00, count: 32), "02a2b51e2ca3a067bd58078749da73319c73c7e25985053d8cc6f046a3346f38f5"),
            (Data(repeating: 0xFF, count: 32), "036fecbe49be33b5a13f69f948456292aa1f60c5bb3e3d0d702736765af0f160c0"),
            (Data(repeating: 0x11, count: 32), "02b23092bba6aaf88b48a76e47eff090537c0f22de2d07f8ea53d688533a71fd78"),
        ] {
            let point = try #require(payloadECDHPoint(salt: salt))
            #expect(point.compressedRepresentation == Self.hex(compressed), "salt \(salt.map { String(format: "%02x", $0) }.joined())")
        }
    }

    @Test func matchesTheLinuxLibrarysKnownAnswer() throws {
        // The Linux library's `known_answer` inputs, end to end outside the
        // Secure Enclave (which cannot import a chosen scalar): a software
        // KEK's ECDH against the salt's point, then the HKDF and AES-GCM
        // calls `deriveWrappingKey` and `wrapDekCore` make. The header is a
        // stand-in string, as on Linux, not a real payload header.
        let kek = try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 0x2A, count: 32))
        let salt = Data(repeating: 0x11, count: 32)
        let service = "com.hkdfguard.kat"
        let header = Data("hkdfguard known-answer header".utf8)

        let shared = try kek.sharedSecretFromKeyAgreement(with: try #require(payloadECDHPoint(salt: salt)))
        #expect(shared.withUnsafeBytes { Data($0) }
            == Self.hex("c25dfa74f08cf0cfc90c09b137e1ce621163a914e04d734e5d811ee9d8012707"))

        let key = shared.hkdfDerivedSymmetricKey(
            using: SHA512.self, salt: salt,
            sharedInfo: wrappingKeyInfo(service: service, header: header), outputByteCount: 32)
        #expect(key.withUnsafeBytes { Data($0) }
            == Self.hex("513e5531a4a065f8cc55444d0642a87599525282156d338292860e7be62cfb31"))

        let sealed = try AES.GCM.seal(
            Data(repeating: 0x5A, count: 32), using: key,
            nonce: AES.GCM.Nonce(data: Data(repeating: 0x22, count: 12)), authenticating: header)
        #expect(sealed.ciphertext + sealed.tag == Self.hex(
            "c2d840acab45552dfabe45d3d2d3556d4134bd2ae71e2163e39a4a27ef53593f6591b2dc77414d94e6a0a78f236efb6d"))
    }

    @Test func pointAdditionRefusesInfinityAndDoubles() {
        // Not reachable from a salt in practice; the addition itself must
        // refuse P + (-P) rather than return garbage for ECDH.
        let g = (x: P256Field.Element(bigEndian: Self.hex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")),
                 y: P256Field.Element(bigEndian: Self.hex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")))
        #expect(P256Field.addPoints(g, (g.x, P256Field.neg(g.y))) == nil)
        let doubled = P256Field.addPoints(g, g) // 2G, from SEC 2 / NIST test data
        #expect(doubled?.x.bigEndianBytes
            == [UInt8](Self.hex("7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978")))
    }

    @Test func isDeterministicAndDiffersPerSalt() throws {
        let a = Data((0..<32).map { _ in UInt8.random(in: .min ... .max) })
        var b = a
        b[0] ^= 0x01
        let pa = try #require(payloadECDHPoint(salt: a))
        #expect(try #require(payloadECDHPoint(salt: a)).x963Representation == pa.x963Representation)
        #expect(try #require(payloadECDHPoint(salt: b)).x963Representation != pa.x963Representation)
    }

    @Test func theFingerprintHashesTheUncompressedKeyAsLinuxDoes() {
        let key = P256.KeyAgreement.PrivateKey().publicKey
        #expect(kekFingerprint(key) == Data(SHA256.hash(data: key.x963Representation)))
        #expect(key.x963Representation.count == 65 && key.x963Representation.first == 0x04)
    }
}

/// Suite 0x02: an ML-KEM-1024 KEK, through `sealDek`/`openPayload` -- the
/// payload crypto wrap and unwrap run once they have the service's KEK.
/// Software ML-KEM keys stand in for the Secure Enclave everywhere but the
/// last test, so the format and its refusals are checked on CI's VMs too.
@Suite
struct HkdfGuardMLKEMKEKTests {
    private static let service = "com.hkdfguard.tests.mlkem"

    private static func randomDEK() -> [UInt8] {
        (0..<32).map { _ in UInt8.random(in: .min ... .max) }
    }

    @available(macOS 26.0, *)
    private static func softwareKEK() throws -> (kek: KEMKEK, key: MLKEM1024.PrivateKey) {
        let key = try MLKEM1024.PrivateKey()
        let encapsulation = try key.publicKey.encapsulate()
        return (KEMKEK(key: key, publicKey: key.publicKey.rawRepresentation, encapsulated: encapsulation.encapsulated), key)
    }

    private static func seal(_ dek: [UInt8], _ kek: KEK) -> (status: Int32, payload: Data?) {
        dek.withUnsafeBytes { sealDek($0, kek: kek, service: service) }
    }

    @Test func theKeychainItemFormatKeepsP256BareAndBoxesMLKEM() throws {
        // P-256 items stay exactly what they always were, so existing KEKs
        // keep loading; ML-KEM items carry their ciphertext in a container.
        let blob = Data([0x04, 0x82] + (0..<200).map { UInt8($0 & 0xFF) })
        let ciphertext = Data(repeating: 0x5A, count: 1568)
        #expect(encodeKeychainKEK(.p256(blob: blob)) == blob)
        #expect(decodeKeychainKEK(blob) == .p256(blob: blob))

        let boxed = try #require(encodeKeychainKEK(.mlkem1024(blob: blob, encapsulated: ciphertext)))
        #expect(boxed.prefix(6) == Data("HKGQ".utf8) + [0x01, 0x02])
        #expect(boxed.count == 8 + blob.count + 1568)
        #expect(decodeKeychainKEK(boxed) == .mlkem1024(blob: blob, encapsulated: ciphertext))

        func set(_ index: Int, _ value: UInt8) -> Data {
            var bytes = [UInt8](boxed)
            bytes[index] = value
            return Data(bytes)
        }
        #expect(decodeKeychainKEK(set(4, 0x02)) == nil, "format version")
        #expect(decodeKeychainKEK(set(5, 0x01)) == nil, "suite")
        #expect(decodeKeychainKEK(set(7, 0x00)) == nil, "blob length")
        #expect(decodeKeychainKEK(boxed.dropLast()) == nil, "truncated")
        #expect(decodeKeychainKEK(boxed + Data([0])) == nil, "trailing bytes")
        #expect(decodeKeychainKEK(Data("HKGQ".utf8)) == nil, "magic alone")

        #expect(encodeKeychainKEK(.p256(blob: Data("HKGQ".utf8) + blob)) == nil, "a P-256 blob that would read as a container")
        #expect(encodeKeychainKEK(.mlkem1024(blob: blob, encapsulated: ciphertext.dropLast())) == nil)
        #expect(encodeKeychainKEK(.mlkem1024(blob: Data(), encapsulated: ciphertext)) == nil)
    }

    @Test func aMalformedContainerIsCorruptWithoutProbingTheEnclave() {
        // No keybag state explains a container this build can't parse, so the
        // probe that tells "locked" from "corrupt" isn't needed.
        var probed = false
        guard case .corrupt = reconstructKEK(Data("HKGQ".utf8) + [0x09], enclaveIsUsable: { probed = true; return false }) else {
            Issue.record("a malformed container is corrupt"); return
        }
        #expect(!probed)
    }

    /// Before macOS 26 (really, on an older runner, or acted out on this
    /// Mac), any ML-KEM KEK is refused without the probe: it is very likely
    /// fine, and must never be reported corrupt.
    @Test func anMLKEMKEKIsRefusedNeverCorruptWithoutMLKEM() throws {
        let item = try #require(encodeKeychainKEK(.mlkem1024(
            blob: Data([0x04, 0x82] + (0..<200).map { UInt8($0 & 0xFF) }),
            encapsulated: Data(repeating: 0x5A, count: mlkem1024CiphertextLength))))
        let check = {
            var probed = false
            guard case .enclaveRefused = reconstructKEK(item, enclaveIsUsable: { probed = true; return true }) else {
                Issue.record("an ML-KEM KEK is refused, not corrupt"); return
            }
            #expect(!probed)
        }
        if #available(macOS 26.0, *) {
            MachineScopeTestOverrides.$withoutMLKEM.withValue(true, operation: check)
        } else {
            check()
        }
    }

    @available(macOS 26.0, *)
    @Test func aPayloadRoundTripsAndNamesSuite2AndTheKEKsFingerprint() throws {
        let (kem, _) = try Self.softwareKEK()
        #expect(kem.publicKey.count == mlkem1024PublicKeyLength)
        #expect(kem.encapsulated.count == mlkem1024CiphertextLength)
        let kek = KEK.mlkem1024(kem)
        let dek = Self.randomDEK()

        let sealed = Self.seal(dek, kek)
        #expect(sealed.status == 0)
        let payload = try #require(sealed.payload)
        #expect(payload.count == 125)
        #expect(payload.prefix(32) == Data(SHA256.hash(data: kem.publicKey)))
        #expect(kek.fingerprint == Data(SHA256.hash(data: kem.publicKey)))
        #expect(payload[32] == 0x02)

        let opened = openPayload(payload, kek: kek, service: Self.service)
        #expect(opened.status == 0)
        #expect(opened.plaintext.map(Array.init) == dek)
    }

    @available(macOS 26.0, *)
    @Test func theWrappingKeyIsHKDFOverTheDecapsulatedSecret() throws {
        // The construction, rebuilt independently: K = decapsulate(c), then
        // HKDF-SHA512 with the payload salt and the usual `info`, then
        // AES-256-GCM over the header -- a payload sealed this way opens.
        let (kem, key) = try Self.softwareKEK()
        let dek = Self.randomDEK()
        let salt = Data((0..<32).map { _ in UInt8.random(in: .min ... .max) })
        let nonceBytes = Data((0..<12).map { _ in UInt8.random(in: .min ... .max) })
        var header = Data(SHA256.hash(data: kem.publicKey))
        header.append(0x02)
        header.append(salt)
        header.append(nonceBytes)
        let aesKey = HKDF<SHA512>.deriveKey(
            inputKeyMaterial: try key.decapsulate(kem.encapsulated), salt: salt,
            info: wrappingKeyInfo(service: Self.service, header: header), outputByteCount: 32)
        let box = try AES.GCM.seal(dek, using: aesKey, nonce: AES.GCM.Nonce(data: nonceBytes), authenticating: header)

        let kek = KEK.mlkem1024(kem)
        #expect(try kek.wrappingKey(service: Self.service, header: header) == aesKey)
        let opened = openPayload(header + box.ciphertext + box.tag, kek: kek, service: Self.service)
        #expect(opened.status == 0)
        #expect(opened.plaintext.map(Array.init) == dek)
    }

    @available(macOS 26.0, *)
    @Test func theSameKeyWithAnotherCiphertextCantOpenThePayload() throws {
        // The stored ciphertext is part of the KEK: the same enclave key with
        // a different one has the same fingerprint, but a different K.
        let (kem, key) = try Self.softwareKEK()
        let other = KEMKEK(key: key, publicKey: kem.publicKey, encapsulated: try key.publicKey.encapsulate().encapsulated)
        let payload = try #require(Self.seal(Self.randomDEK(), .mlkem1024(kem)).payload)
        #expect(openPayload(payload, kek: .mlkem1024(other), service: Self.service).status == -11)
    }

    @available(macOS 26.0, *)
    @Test func anotherKEKIsRefusedByFingerprint() throws {
        let payload = try #require(Self.seal(Self.randomDEK(), .mlkem1024(try Self.softwareKEK().kek)).payload)
        #expect(openPayload(payload, kek: .mlkem1024(try Self.softwareKEK().kek), service: Self.service).status == -16)
    }

    @available(macOS 26.0, *)
    @Test func everyAlteredByteIsRefused() throws {
        // Fingerprint bytes: -16, before any decapsulation. The suite byte,
        // rewritten to 0x01 under a suite-0x02 KEK: -11. Every other byte:
        // the tag fails, -11.
        let kek = KEK.mlkem1024(try Self.softwareKEK().kek)
        let payload = try #require(Self.seal(Self.randomDEK(), kek).payload)
        for offset in 0..<payload.count {
            var tampered = payload
            tampered[offset] ^= offset == 32 ? 0x03 : 0x01
            let expected: Int32 = offset < 32 ? -16 : -11
            #expect(openPayload(tampered, kek: kek, service: Self.service).status == expected, "byte \(offset)")
        }
        #expect(openPayload(payload, kek: kek, service: "com.hkdfguard.tests.mlkem.other").status == -11)
        #expect(openPayload(payload.prefix(124), kek: kek, service: Self.service).status == -10)
    }

    @available(macOS 26.0, *)
    @Test(.enabled(if: SecureEnclave.isAvailable, "needs a Secure Enclave"))
    func anEnclaveKEKSurvivesItsBlobAndOpensWhatItSealed() throws {
        let access = try #require(SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage], nil))
        let (kem, blob) = try #require(newMLKEM1024KEK(accessControl: access))
        let dek = Self.randomDEK()
        let payload = try #require(Self.seal(dek, .mlkem1024(kem)).payload)

        // Rebuilt the way a stored KEK will be: blob plus ciphertext.
        let reloaded = try #require(reconstructMLKEM1024KEK(blob: blob, encapsulated: kem.encapsulated))
        #expect(reloaded.publicKey == kem.publicKey)
        let opened = openPayload(payload, kek: .mlkem1024(reloaded), service: Self.service)
        #expect(opened.status == 0)
        #expect(opened.plaintext.map(Array.init) == dek)

        #expect(reconstructMLKEM1024KEK(blob: blob, encapsulated: kem.encapsulated.prefix(100)) == nil)
        #expect(reconstructMLKEM1024KEK(blob: Data((0..<48).map { UInt8($0) }), encapsulated: kem.encapsulated) == nil)
    }
}
