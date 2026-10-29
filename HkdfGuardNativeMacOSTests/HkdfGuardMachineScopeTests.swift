//
//  HkdfGuardMachineScopeTests.swift
//  HkdfGuardNativeMacOSTests
//
//  Production mode's machine scope: the policy (parsing, and the file it is
//  read from), the machine KEK file format, the system-context check, and
//  how every entry point routes a machine-scoped service.
//
//  These run in a login session (xctest), so a machine KEK can be neither
//  created nor used here -- that is the point of several tests. Creating
//  one and unwrapping with it as a LaunchDaemon is covered by the root
//  verification script (scripts/verify-machine-scope.sh).
//

import Testing
import Foundation
import CryptoKit
import os
@testable import HkdfGuardNativeMacOS

@Suite
struct HkdfGuardMachineScopeTests {

    init() {
        setupMinDelayOverrideForTests.withLock { $0 = .zero }
    }

    private static func policy(_ services: [String: MachineServiceSettings] = [:]) -> PolicyLoad {
        .loaded(MachinePolicy(source: "test", securityAdminGroup: nil, deploymentAdminGroup: nil, machineServices: services))
    }

    /// Runs `body` with `load` as the policy and machine KEKs looked for in
    /// `folder` -- for this test's calls only (task-local).
    private static func with<T>(_ load: PolicyLoad, folder: String = "/nonexistent/hkdfguard-keks", _ body: () throws -> T) rethrows -> T {
        try MachineScopeTestOverrides.$policy.withValue(load) {
            try MachineScopeTestOverrides.$keyFolder.withValue(folder, operation: body)
        }
    }

    // MARK: - Policy parsing

    @Test func parsesAFullPolicyAndNormalizesServiceNames() {
        let load = parseMachinePolicy([
            "MachineServices": [
                "Com.Example.Orders": ["RunnerGroup": "_orders"],
                "com.example.billing": [String: Any](),
            ],
            "SecurityAdminGroup": "secadmins",
            "DeploymentAdminGroup": "deployers",
        ], source: "p")
        #expect(load == .loaded(MachinePolicy(
            source: "p",
            securityAdminGroup: "secadmins",
            deploymentAdminGroup: "deployers",
            machineServices: [
                "com.example.orders": MachineServiceSettings(runnerGroup: "_orders"),
                "com.example.billing": MachineServiceSettings(runnerGroup: nil),
            ])))
        #expect(parseMachinePolicy([:], source: "p") == Self.policy().withSource("p"), "an empty policy is production mode with no machine services")
    }

    @Test func refusesAnythingItDoesNotUnderstandRatherThanIgnoringIt() {
        // A misspelt setting must not leave a production service quietly
        // user-scoped: the whole policy is invalid instead.
        let cases: [([String: Any], String)] = [
            (["MachineService": [String: Any]()], "unknown setting \"MachineService\""),
            (["MachineServices": ["svc": ["Runnergroup": "g"]]], "unknown setting \"Runnergroup\""),
            (["MachineServices": ["svc"]], "must be a dictionary"),
            (["MachineServices": ["svc": "g"]], "must be a dictionary"),
            (["MachineServices": ["bad_name": [String: Any]()]], "not a valid service name"),
            (["MachineServices": ["a.b": [String: Any](), "A.B": [String: Any]()]], "twice"),
            (["MachineServices": ["svc": ["RunnerGroup": 7]]], "must be a group name"),
            (["SecurityAdminGroup": "bad group"], "must be a group name"),
            (["DeploymentAdminGroup": "-x"], "must be a group name"),
        ]
        for (values, expected) in cases {
            guard case .invalid(let reason) = parseMachinePolicy(values, source: "p") else {
                Issue.record("accepted \(values)")
                continue
            }
            #expect(reason.contains(expected), "\(values): \(reason)")
        }
    }

    @Test func theSuiteSettingsDefaultToMLKEMAndOptInToP256() {
        func suites(_ values: [String: Any]) -> SuitePolicy? {
            guard case .loaded(let policy) = parseMachinePolicy(values, source: "p") else {
                return nil
            }
            return policy.suites
        }
        #expect(suites([:]) == SuitePolicy(provisionSuite: .mlkem1024StoredCiphertext, requirePostQuantum: false))
        #expect(suites(["KekSuite": "ML-KEM-1024"])?.provisionSuite == .mlkem1024StoredCiphertext)
        #expect(suites(["KekSuite": "P-256"])?.provisionSuite == .p256HashedPoint)
        #expect(suites(["RequirePostQuantum": true])?.requirePostQuantum == true)
        #expect(suites(["RequirePostQuantum": false, "KekSuite": "P-256"])?.provisionSuite == .p256HashedPoint)
        // Only the suite settings: every service stays user-scoped.
        let onlySuites = PolicyLoad.loaded(MachinePolicy(source: "p", securityAdminGroup: nil, deploymentAdminGroup: nil,
                                                         machineServices: [:], suites: SuitePolicy(provisionSuite: .p256HashedPoint)))
        #expect(Self.with(onlySuites) { kekScope(service: "svc") } == .user)
        #expect(Self.with(onlySuites) { currentSuitePolicy()?.provisionSuite } == .p256HashedPoint)
        #expect(Self.with(.none) { currentSuitePolicy() } == SuitePolicy(), "no policy: the defaults")
        #expect(Self.with(.invalid("bad")) { currentSuitePolicy() } == nil, "an invalid policy fails closed")

        let cases: [([String: Any], String)] = [
            (["KekSuite": "ML-KEM-768"], "KekSuite must be"),
            (["KekSuite": "p-256"], "KekSuite must be"),
            (["KekSuite": 2], "KekSuite must be"),
            (["RequirePostQuantum": "yes"], "must be a boolean"),
            (["RequirePostQuantum": 1], "must be a boolean"),
            (["KekSuite": "P-256", "RequirePostQuantum": true], "contradicts RequirePostQuantum"),
        ]
        for (values, expected) in cases {
            guard case .invalid(let reason) = parseMachinePolicy(values, source: "p") else {
                Issue.record("accepted \(values)")
                continue
            }
            #expect(reason.contains(expected), "\(values): \(reason)")
        }
    }

    @Test func thePolicyJSONReportsTheSuiteSettings() throws {
        func json(_ load: PolicyLoad) throws -> [String: Any] {
            let data = try #require(Self.with(load) { machinePolicyJSON() })
            return try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        }
        let development = try json(.none)
        #expect(development["kekSuite"] as? String == "ML-KEM-1024")
        #expect(development["requirePostQuantum"] as? Bool == false)
        let strict = try json(.loaded(MachinePolicy(source: "p", securityAdminGroup: nil, deploymentAdminGroup: nil,
                                                    machineServices: [:], suites: SuitePolicy(requirePostQuantum: true))))
        #expect(strict["kekSuite"] as? String == "ML-KEM-1024")
        #expect(strict["requirePostQuantum"] as? Bool == true)
        let classical = try json(.loaded(MachinePolicy(source: "p", securityAdminGroup: nil, deploymentAdminGroup: nil,
                                                       machineServices: [:], suites: SuitePolicy(provisionSuite: .p256HashedPoint))))
        #expect(classical["kekSuite"] as? String == "P-256")
    }

    // MARK: - The policy file

    @Test func aMissingPolicyFileIsDevelopmentMode() {
        #expect(loadPolicyFile(atPath: "/nonexistent-hkdfguard/policy.plist") == nil)
        #expect(loadPolicyFile(atPath: NSTemporaryDirectory() + "hkdfguard-no-such-policy.plist") == nil)
    }

    @Test func refusesAPolicyFileNotOwnedByRoot() throws {
        // Anyone who can write the policy decides which keys services use.
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hkdfguard.policy.\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("policy.plist")
        let data = try PropertyListSerialization.data(fromPropertyList: ["MachineServices": [String: Any]()], format: .xml, options: 0)
        try data.write(to: file)
        guard case .invalid(let reason) = loadPolicyFile(atPath: file.path) else {
            Issue.record("a user-owned policy was accepted")
            return
        }
        #expect(reason.contains("root"), "\(reason)")
    }

    // MARK: - The machine KEK file

    @Test func theKeyFileFormatRoundTripsAndRejectsAnythingElse() throws {
        let publicKey = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
        let file = MachineKeyFile.v1(publicKey: publicKey, blob: Data((0..<200).map { UInt8($0 & 0xFF) }))
        #expect(file.fingerprint == Data(SHA256.hash(data: publicKey)))
        let encoded = try #require(encodeMachineKeyFile(file))
        #expect(decodeMachineKeyFile(encoded) == file)

        func corrupt(_ index: Int) -> Data {
            var bytes = [UInt8](encoded)
            bytes[index] ^= 0xFF
            return Data(bytes)
        }
        #expect(decodeMachineKeyFile(corrupt(0)) == nil, "magic")
        #expect(decodeMachineKeyFile(corrupt(4)) == nil, "format version")
        #expect(decodeMachineKeyFile(corrupt(5)) == nil, "the public key's 0x04 prefix")
        #expect(decodeMachineKeyFile(corrupt(71)) == nil, "blob length")
        #expect(decodeMachineKeyFile(encoded.dropLast()) == nil, "truncated")
        #expect(decodeMachineKeyFile(encoded + Data([0])) == nil, "trailing bytes")
        #expect(encodeMachineKeyFile(.v1(publicKey: publicKey.dropLast(), blob: file.blob)) == nil)
        #expect(encodeMachineKeyFile(.v1(publicKey: publicKey, blob: Data())) == nil)
    }

    @Test func formatTwoRoundTripsForBothSuitesAndRejectsAnythingElse() throws {
        let fingerprint = Data((0..<32).map { UInt8($0 + 1) })
        let blob = Data((0..<1833).map { UInt8($0 & 0xFF) })
        let ciphertext = Data((0..<1568).map { UInt8(($0 * 7) & 0xFF) })
        for stored in [StoredKEK.p256(blob: blob), .mlkem1024(blob: blob, encapsulated: ciphertext)] {
            let file = MachineKeyFile.v2(stored, fingerprint: fingerprint)
            #expect(file.publicKey == nil)
            #expect(file.stored == stored)
            let encoded = try #require(encodeMachineKeyFile(file))
            #expect(encoded[4] == 2)
            #expect(decodeMachineKeyFile(encoded) == file)
            #expect(decodeMachineKeyFile(encoded.dropLast()) == nil, "truncated")
            #expect(decodeMachineKeyFile(encoded + Data([0])) == nil, "trailing bytes")
        }

        let encoded = try #require(encodeMachineKeyFile(.v2(.mlkem1024(blob: blob, encapsulated: ciphertext), fingerprint: fingerprint)))
        func set(_ index: Int, _ value: UInt8) -> Data {
            var bytes = [UInt8](encoded)
            bytes[index] = value
            return Data(bytes)
        }
        #expect(decodeMachineKeyFile(set(4, 3)) == nil, "format version")
        #expect(decodeMachineKeyFile(set(5, 0x03)) == nil, "unknown suite")
        #expect(decodeMachineKeyFile(set(5, 0x01)) == nil, "P-256 with a ciphertext")
        #expect(decodeMachineKeyFile(set(38, 0xFF)) == nil, "blob length")
        var zeroFingerprint = [UInt8](encoded)
        zeroFingerprint.replaceSubrange(6..<38, with: [UInt8](repeating: 0, count: 32))
        #expect(decodeMachineKeyFile(Data(zeroFingerprint)) == nil, "an all-zero fingerprint")

        // The encoder refuses what the decoder would.
        #expect(encodeMachineKeyFile(.v2(.mlkem1024(blob: blob, encapsulated: ciphertext.dropLast()), fingerprint: fingerprint)) == nil)
        #expect(encodeMachineKeyFile(.v2(.p256(blob: Data()), fingerprint: fingerprint)) == nil)
        #expect(encodeMachineKeyFile(.v2(.p256(blob: blob), fingerprint: fingerprint.dropLast())) == nil)
        #expect(encodeMachineKeyFile(.v2(.p256(blob: Data(count: 9000)), fingerprint: fingerprint)) == nil, "over the size limit")
    }

    @Test func refusesAKeyFolderNotOwnedByRoot() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hkdfguard.keks.\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: dir) }
        guard case .untrusted(let reason) = Self.with(Self.policy(), folder: dir.path, { readMachineKeyFile(service: "svc") }) else {
            Issue.record("a user-owned key folder was trusted")
            return
        }
        #expect(reason.contains("root"), "\(reason)")
    }

    @Test func theKeyFolderIsExcludedFromBackup() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hkdfguard.keks.\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: dir) }
        #expect(excludeFromBackup(dir.path))
        #expect(try URL(fileURLWithPath: dir.path).resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup == true)
    }

    // MARK: - System context

    @Test func aTestRunnerInALoginSessionIsNotTheSystemContext() {
        // xctest runs in this user's login session: graphic and console
        // access. Machine KEKs must be refused here, as they would be from
        // Terminal, sudo or SSH.
        #expect(!runningInSystemContext())
    }

    // MARK: - Routing

    @Test func aMachineServiceIsRefusedOutsideTheSystemContext() {
        let service = "com.hkdfguard.tests.machine.routing"
        Self.with(Self.policy([service: MachineServiceSettings(runnerGroup: nil)])) {
            // No key file yet: existence and fingerprint answer from the
            // file alone (root can ask from Terminal).
            #expect(kekExists(service: service) == (HKDFGuardStatus.success.rawValue, false))
            var fingerprint = [UInt8](repeating: 0, count: 32)
            var length: Int32 = 32
            #expect(service.withCString { hkdfguard_kek_fingerprint(servicePtr: $0, outPtr: &fingerprint, outLen: &length) } == -17)

            // Creating one needs root in the system context; using one, the
            // system context: refused here, before any file is touched.
            #expect(createKEK(service: service) == HKDFGuardStatus.keychainAccessDenied.rawValue)
            #expect(getKEK(service: service).status == HKDFGuardStatus.keychainAccessDenied.rawValue)

            let dek = [UInt8](repeating: 0x42, count: 32)
            var out = [UInt8](repeating: 0, count: 125)
            var outLen: Int32 = 125
            #expect(service.withCString { hkdfguard_wrap_dek(servicePtr: $0, dekPtr: dek, dekLen: 32, outPtr: &out, outLen: &outLen) } == -18)

            var payload = [UInt8](repeating: 0, count: 125)
            payload[32] = 0x01 // a valid suite id, so the lookup is reached
            var plain = [UInt8](repeating: 0xA5, count: 32)
            var plainLen: Int32 = 32
            #expect(service.withCString { hkdfguard_unwrap_dek(servicePtr: $0, wrappedPtr: payload, wrappedLen: 125, outPtr: &plain, outLen: &plainLen) } == -18)
            #expect(plain.allSatisfy { $0 == 0 }, "the out buffer is zeroed on failure, as always")
        }
    }

    @Test func anInvalidPolicyFailsEveryServiceClosed() {
        // Not just the services it names: with no usable policy, nothing
        // can say which services are meant to be machine-scoped.
        Self.with(.invalid("test: broken")) {
            for service in ["com.hkdfguard.tests.machine.any", "com.hkdfguard.tests.other"] {
                #expect(kekExists(service: service).status == HKDFGuardStatus.policyInvalid.rawValue)
                #expect(createKEK(service: service) == HKDFGuardStatus.policyInvalid.rawValue)
                #expect(getKEK(service: service).status == HKDFGuardStatus.policyInvalid.rawValue)
            }
        }
    }

    @Test(.enabled(if: SecureEnclave.isAvailable, "needs a Secure Enclave"))
    func servicesThePolicyDoesNotNameStayUserScoped() {
        let service = "com.hkdfguard.tests.machine.unlisted.\(UInt64.random(in: .min ... .max))"
        Self.with(Self.policy(["com.hkdfguard.tests.machine.listed": MachineServiceSettings(runnerGroup: nil)])) {
            #expect(kekExists(service: service) == (HKDFGuardStatus.success.rawValue, false), "the keychain answered, not the machine store")
        }
    }

    // MARK: - hkdfguard_machine_policy

    private static func policyJSON() throws -> [String: Any] {
        var length: Int32 = 0
        #expect(hkdfguard_machine_policy(outPtr: nil, outLen: &length) == HKDFGuardStatus.outputBufferTooSmall.rawValue)
        #expect(length > 0)
        var out = [UInt8](repeating: 0, count: Int(length))
        #expect(hkdfguard_machine_policy(outPtr: &out, outLen: &length) == HKDFGuardStatus.success.rawValue)
        return try #require(try JSONSerialization.jsonObject(with: Data(out.prefix(Int(length)))) as? [String: Any])
    }

    @Test func reportsThePolicyInEffect() throws {
        let development = try Self.with(.none) { try Self.policyJSON() }
        #expect(development["mode"] as? String == "development")
        #expect(development["systemContext"] as? Bool == false)
        #expect(development["machineKeyFolder"] as? String == "/nonexistent/hkdfguard-keks")

        let production = try Self.with(.loaded(MachinePolicy(
            source: "test", securityAdminGroup: "secadmins", deploymentAdminGroup: "deployers",
            machineServices: ["svc.a": MachineServiceSettings(runnerGroup: "_a"), "svc.b": MachineServiceSettings(runnerGroup: nil)]))) {
            try Self.policyJSON()
        }
        #expect(production["mode"] as? String == "production")
        #expect(production["securityAdminGroup"] as? String == "secadmins")
        #expect(production["deploymentAdminGroup"] as? String == "deployers")
        let services = try #require(production["machineServices"] as? [String: [String: String]])
        #expect(services == ["svc.a": ["runnerGroup": "_a"], "svc.b": [:]])

        let invalid = try Self.with(.invalid("test: broken")) { try Self.policyJSON() }
        #expect(invalid["mode"] as? String == "invalid")
        #expect(invalid["reason"] as? String == "test: broken")

        var length: Int32 = -1
        #expect(hkdfguard_machine_policy(outPtr: nil, outLen: &length) == HKDFGuardStatus.invalidInputLength.rawValue)
        #expect(hkdfguard_machine_policy(outPtr: nil, outLen: nil) == HKDFGuardStatus.invalidInputLength.rawValue)
    }
}

private extension PolicyLoad {
    func withSource(_ source: String) -> PolicyLoad {
        guard case .loaded(var policy) = self else { return self }
        policy.source = source
        return .loaded(policy)
    }
}
