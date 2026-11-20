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

    // MARK: - The production-mode marker

    private static let somePolicy = PolicyLoad.loaded(MachinePolicy(
        source: "p", securityAdminGroup: nil, deploymentAdminGroup: nil,
        machineServices: [:], suites: SuitePolicy(requirePostQuantum: true)))

    private static func withMarkerFolder(_ body: (_ marker: String) throws -> Void) throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hkdfguard.marker.\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: dir) }
        try body(dir.appendingPathComponent("production-mode").path)
    }

    @Test func aMissingPolicyFailsClosedOnceProductionModeWasRecorded() throws {
        try Self.withMarkerFolder { marker in
            // Never in production mode: no policy is development mode.
            #expect(applyProductionMarker(.none, markerPath: marker, asRoot: true, requireTrustedFolder: false) == .none)
            #expect(!FileManager.default.fileExists(atPath: marker), "no policy must never write the marker")

            // Root sees a valid policy: recorded, and the policy is unchanged.
            #expect(applyProductionMarker(Self.somePolicy, markerPath: marker, asRoot: true, requireTrustedFolder: false) == Self.somePolicy)
            let attributes = try FileManager.default.attributesOfItem(atPath: marker)
            #expect(attributes[.type] as? FileAttributeType == .typeRegular)
            #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o644)
            // Again: the existing marker is left as it is.
            #expect(applyProductionMarker(Self.somePolicy, markerPath: marker, asRoot: true, requireTrustedFolder: false) == Self.somePolicy)

            // The policy goes away: every call fails closed, for root and everyone else.
            for asRoot in [true, false] {
                guard case .invalid(let reason) = applyProductionMarker(.none, markerPath: marker, asRoot: asRoot, requireTrustedFolder: false) else {
                    Issue.record("a Mac that was in production mode fell back to development mode")
                    return
                }
                #expect(reason.contains(marker), "\(reason)")
            }
            // An invalid policy stays what it was.
            #expect(applyProductionMarker(.invalid("x"), markerPath: marker, asRoot: true, requireTrustedFolder: false) == .invalid("x"))

            // Deleting the marker is the way back to development mode.
            try FileManager.default.removeItem(atPath: marker)
            #expect(applyProductionMarker(.none, markerPath: marker, asRoot: false, requireTrustedFolder: false) == .none)
        }
    }

    @Test func onlyRootRecordsProductionModeAndOnlyInATrustedFolder() throws {
        try Self.withMarkerFolder { marker in
            // Anyone else reading a policy leaves no marker: they couldn't
            // write the real one, and must not try.
            #expect(applyProductionMarker(Self.somePolicy, markerPath: marker, asRoot: false, requireTrustedFolder: false) == Self.somePolicy)
            #expect(!FileManager.default.fileExists(atPath: marker))
            // This folder is the test user's, not root's: with the real
            // check on, nothing is written into it, and the policy still loads.
            #expect(applyProductionMarker(Self.somePolicy, markerPath: marker, asRoot: true) == Self.somePolicy)
            #expect(!FileManager.default.fileExists(atPath: marker))
        }
    }

    @Test func anythingAtTheMarkerPathCountsAsTheMarker() throws {
        try Self.withMarkerFolder { marker in
            // A dangling symlink, say: not a file, but not "absent" either.
            try FileManager.default.createSymbolicLink(atPath: marker, withDestinationPath: "/nonexistent-hkdfguard")
            guard case .invalid = applyProductionMarker(.none, markerPath: marker, asRoot: false) else {
                Issue.record("a marker that is not a regular file was ignored")
                return
            }
        }
        // No folder at all is development mode.
        #expect(applyProductionMarker(.none, markerPath: "/nonexistent-hkdfguard/production-mode", asRoot: false) == .none)
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

    @Test func formatThreeRoundTripsForBothSuitesAndRejectsAnythingElse() throws {
        let fingerprint = Data((0..<32).map { UInt8($0 + 1) })
        let blob = Data((0..<1833).map { UInt8($0 & 0xFF) })
        let ciphertext = Data((0..<1568).map { UInt8(($0 * 7) & 0xFF) })
        let classical = Data((0..<300).map { UInt8(($0 * 3) & 0xFF) })
        for stored in [StoredKEK.p256(blob: blob), .mlkem1024(blob: blob, encapsulated: ciphertext, classicalBlob: classical)] {
            let file = MachineKeyFile.v3(stored, fingerprint: fingerprint)
            #expect(file.publicKey == nil)
            #expect(file.stored == stored)
            let encoded = try #require(encodeMachineKeyFile(file))
            #expect(encoded[4] == 3)
            #expect(decodeMachineKeyFile(encoded) == file)
            #expect(decodeMachineKeyFile(encoded.dropLast()) == nil, "truncated")
            #expect(decodeMachineKeyFile(encoded + Data([0])) == nil, "trailing bytes")
        }

        let encoded = try #require(encodeMachineKeyFile(.v3(.mlkem1024(blob: blob, encapsulated: ciphertext, classicalBlob: classical), fingerprint: fingerprint)))
        func set(_ index: Int, _ value: UInt8) -> Data {
            var bytes = [UInt8](encoded)
            bytes[index] = value
            return Data(bytes)
        }
        #expect(decodeMachineKeyFile(set(4, 2)) == nil, "format 2 is no longer read")
        #expect(decodeMachineKeyFile(set(4, 4)) == nil, "format version")
        #expect(decodeMachineKeyFile(set(5, 0x03)) == nil, "unknown suite")
        #expect(decodeMachineKeyFile(set(5, 0x01)) == nil, "P-256 with a ciphertext")
        #expect(decodeMachineKeyFile(set(38, 0xFF)) == nil, "blob length")
        var zeroFingerprint = [UInt8](encoded)
        zeroFingerprint.replaceSubrange(6..<38, with: [UInt8](repeating: 0, count: 32))
        #expect(decodeMachineKeyFile(Data(zeroFingerprint)) == nil, "an all-zero fingerprint")

        // The encoder refuses what the decoder would.
        #expect(encodeMachineKeyFile(.v3(.mlkem1024(blob: blob, encapsulated: ciphertext.dropLast(), classicalBlob: classical), fingerprint: fingerprint)) == nil)
        #expect(encodeMachineKeyFile(.v3(.mlkem1024(blob: blob, encapsulated: ciphertext, classicalBlob: Data()), fingerprint: fingerprint)) == nil, "suite 0x02 needs its P-256 key")
        #expect(encodeMachineKeyFile(.v3(.p256(blob: Data()), fingerprint: fingerprint)) == nil)
        #expect(encodeMachineKeyFile(.v3(.p256(blob: blob), fingerprint: fingerprint.dropLast())) == nil)
        #expect(encodeMachineKeyFile(.v3(.p256(blob: Data(count: 9000)), fingerprint: fingerprint)) == nil, "over the size limit")
    }

    @Test func refusesAKeyFolderNotOwnedByRoot() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hkdfguard.keks.\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: dir) }
        guard case .refused(.kekCorrupted, let reason) = Self.with(Self.policy(), folder: dir.path, { readMachineKeyFile(service: "svc", settings: MachineServiceSettings(runnerGroup: nil)) }) else {
            Issue.record("a user-owned key folder was trusted")
            return
        }
        #expect(reason.contains("root"), "\(reason)")
    }

    @Test func anACLGrantingOnlyReadCountsForAMachineKEKFile() throws {
        // A machine KEK file's contents are the secret: an `everyone allow
        // read` entry leaves the 0640 mode untouched but lets every account
        // read the blobs. The change-rights check lets it through; the
        // machine KEK reader's own check must not. (The reader itself needs a
        // root-owned file; scripts/verify-machine-scope.sh exercises it.)
        let path = FileManager.default.temporaryDirectory.appendingPathComponent("hkdfguard.acl.\(UUID().uuidString)").path
        #expect(FileManager.default.createFile(atPath: path, contents: Data([1, 2, 3]), attributes: [.posixPermissions: 0o640]))
        defer { try? FileManager.default.removeItem(atPath: path) }
        func withFile<T>(_ body: (Int32) -> T) -> T {
            let fd = open(path, O_RDONLY)
            defer { close(fd) }
            return body(fd)
        }
        func chmodACL(_ arguments: [String]) throws {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/bin/chmod")
            process.arguments = arguments + [path]
            try process.run()
            process.waitUntilExit()
            #expect(process.terminationStatus == 0, "chmod \(arguments)")
        }

        #expect(!withFile { aclGrantsAnything(fd: $0) }, "no ACL")
        try chmodACL(["+a", "everyone deny write"])
        #expect(!withFile { aclGrantsAnything(fd: $0) }, "a deny entry only takes rights away")
        try chmodACL(["+a", "everyone allow read"])
        #expect(!withFile { aclGrantsOthersAChange(fd: $0, isFolder: false, rootOnly: true) }, "read alone is no change")
        #expect(withFile { aclGrantsAnything(fd: $0) }, "but it is a grant")
    }

    @Test func theKeyFolderIsExcludedFromBackup() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("hkdfguard.keks.\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: dir) }
        #expect(excludeFromBackup(dir.path))
        #expect(try URL(fileURLWithPath: dir.path).resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup == true)
    }

    // MARK: - One policy read per call

    @Test func aCallSeesOnePolicyHoweverOftenItAsks() {
        let service = "com.hkdfguard.tests.machine.snapshot"
        var strict = MachinePolicy(source: "before", securityAdminGroup: nil, deploymentAdminGroup: nil,
                                   machineServices: [service: MachineServiceSettings(runnerGroup: "_orders")])
        strict.suites.requirePostQuantum = true
        Self.with(.loaded(strict)) {
            withPolicySnapshot {
                // The policy is replaced while the call is running.
                Self.with(.none) {
                    #expect(kekScope(service: service) == .machine(MachineServiceSettings(runnerGroup: "_orders")))
                    #expect(currentSuitePolicy() == strict.suites)
                    withPolicySnapshot {
                        #expect(currentMachinePolicy() == .loaded(strict), "a nested snapshot keeps the outer read")
                    }
                }
            }
            // The next call reads it afresh.
            Self.with(.none) {
                #expect(kekScope(service: service) == .user)
                #expect(withPolicySnapshot { currentMachinePolicy() } == PolicyLoad.none)
            }
        }
    }

    // MARK: - Runner group

    @Test func aRunnerGroupIsRefusedByGidNotJustByName() {
        // By name, whatever the case.
        for name in ["staff", "Admin", "everyone", "wheel", "com.apple.access_ssh"] {
            guard case .refused(let reason) = resolveRunnerGroup(name) else {
                Issue.record("\(name) was accepted")
                continue
            }
            #expect(reason.contains("too broad"))
        }
        guard case .refused(let missing) = resolveRunnerGroup("hkdfguard-no-such-group") else {
            Issue.record("a group that doesn't exist was accepted")
            return
        }
        #expect(missing.contains("does not name a group"))
        // Not on the list, but root is a member: not a dedicated group.
        #expect(lookupGroupID("daemon") == .found(1))
        guard case .refused(let shared) = resolveRunnerGroup("daemon") else {
            Issue.record("a group root belongs to was accepted")
            return
        }
        #expect(shared.contains("root as a member"))
        // A system group root is not in resolves to its gid.
        #expect(resolveRunnerGroup("_www") == .gid(70))
    }

    @Test func aKeyFileMustBelongToThePolicysCurrentRunnerGroup() {
        // A stand-in directory: _orders is dedicated; _staffalias is another
        // name for staff's gid; root reaches _nested through a broad group
        // nested into it after provisioning.
        let groups: (String) -> GroupLookup = { name in
            switch name {
            case "_orders": return .found(501)
            case "_staffalias", "staff": return .found(20)
            case "_nested": return .found(502)
            case "_zero": return .found(0)
            case "_down": return .failed(EIO)
            default: return .missing
            }
        }
        let rootIsIn: (gid_t) -> Bool? = { gid in gid == 502 }
        func problem(_ mode: mode_t, _ gid: gid_t, _ group: String?) -> String? {
            machineKeyFileGroupProblem(mode: mode, gid: gid, runnerGroup: group,
                                       resolve: { resolveRunnerGroup($0, lookup: groups, rootIsIn: rootIsIn) })
        }
        #expect(problem(0o640, 501, "_orders") == nil)
        #expect(problem(0o600, 501, "_orders") == nil)
        // The policy moved on, or the file was re-grouped by hand.
        #expect(problem(0o640, 502, "_orders")?.contains("not the policy's RunnerGroup _orders (gid 501)") == true)
        #expect(problem(0o640, 0, "_orders") != nil)
        // The group is gone, unreachable, or too broad: refused, not assumed.
        #expect(problem(0o640, 501, "_gone")?.contains("does not name a group") == true)
        #expect(problem(0o640, 501, "_down")?.contains("could not be looked up") == true)
        #expect(problem(0o640, 20, "staff")?.contains("too broad") == true)
        #expect(problem(0o640, 0, "_zero")?.contains("too broad") == true)
        // Restrictions provisioning applies hold on every read too, even
        // with the file's gid unchanged: an alias of a broad group, and a
        // group that root -- and so a broad group -- has come to be in.
        #expect(problem(0o640, 20, "_staffalias")?.contains("too broad") == true)
        #expect(problem(0o640, 502, "_nested")?.contains("root as a member") == true)
        // No runner group: root only, so no group access at all.
        #expect(problem(0o600, 0, nil) == nil)
        #expect(problem(0o640, 501, nil)?.contains("chmod 600") == true)
        #expect(problem(0o610, 0, nil) != nil)
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
