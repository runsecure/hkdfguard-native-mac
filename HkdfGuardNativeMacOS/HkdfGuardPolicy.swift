//
//  HkdfGuardPolicy.swift
//  HkdfGuardNativeMacOS
//
//  The production policy: where it is read from, how it is validated, the
//  production-mode marker, and which scope a service's KEK has.
//

import Foundation
import os

// MARK: - Machine scope (production mode)
//
// With no policy -- development mode -- every KEK is user-scoped, as above.
// A production policy can name services whose KEK is machine-scoped
// instead: created by root in the system context (a LaunchDaemon, never a
// login session), kept as a root-owned file its service's runner group may
// read, and usable only by LaunchDaemons. The Secure Enclave binds a key to
// the context it was created in: one created from Terminal -- `sudo`
// included -- is unusable by daemons, and one created by a daemon is
// unusable from any login session. So a machine KEK serves services that
// run as LaunchDaemons, survives logouts, password resets and reboots
// (AfterFirstUnlock), and can't be used from Terminal or over SSH.

let machineLog = Logger(subsystem: "com.hkdfguard", category: "machine")

/// The device-level managed preferences macOS writes for an MDM
/// configuration profile with the `com.hkdfguard` preference domain.
let managedPolicyFilePath = "/Library/Managed Preferences/com.hkdfguard.plist"
/// The policy on a Mac without MDM. Ignored when a managed one exists.
let localPolicyFilePath = "/Library/Application Support/HkdfGuard/policy.plist"
/// Written by the library the first time a root process sees a valid
/// policy, and never removed by it: the record that this Mac has been in
/// production mode. See `applyProductionMarker`. Beside the local policy
/// and the machine KEKs, not in `/Library/Managed Preferences`: macOS owns
/// that folder and empties it of a domain when its profile is removed --
/// the very event the marker has to outlive.
let productionMarkerFilePath = "/Library/Application Support/HkdfGuard/production-mode"
/// One file per machine-scoped service: `<service>.kek`.
let machineKeyFolderPath = "/Library/Application Support/HkdfGuard/keks"
private let machinePolicyMaxSize = 64 * 1024

/// A machine-scoped service's settings.
struct MachineServiceSettings: Equatable {
    /// The group whose members -- the service accounts its LaunchDaemons
    /// run as -- may read its KEK file. nil: root only.
    var runnerGroup: String?
}

struct MachinePolicy: Equatable {
    var source: String
    /// Who may provision and retire machine KEKs (the CLI checks it).
    var securityAdminGroup: String?
    /// Who may wrap DEKs under them (the CLI checks it).
    var deploymentAdminGroup: String?
    /// Normalized (lowercase) service name -> its settings.
    var machineServices: [String: MachineServiceSettings]
    var suites = SuitePolicy()
}

/// What the policy says about KEK suites, for every service, user-scoped
/// or machine-scoped. With no policy, or no setting: provisioning creates
/// ML-KEM-1024 KEKs, and P-256 KEKs and payloads are still accepted.
struct SuitePolicy: Equatable {
    /// `KekSuite`: what provisioning creates. "P-256" is the opt-in to a
    /// classical KEK; where the enclave can't make the suite asked for,
    /// provisioning fails rather than falling back.
    var provisionSuite: KEKSuite = .mlkem1024StoredCiphertext
    /// `RequirePostQuantum`: P-256 KEKs can't wrap or be provisioned, and
    /// suite 0x01 payloads can't be unwrapped. Their fingerprint and
    /// existence can still be read, so they can be found and retired.
    var requirePostQuantum = false

    func permits(_ suite: KEKSuite) -> Bool {
        !requirePostQuantum || suite != .p256HashedPoint
    }
}

extension KEKSuite {
    /// The suite's name in the policy (`KekSuite`) and in `status`.
    var policyName: String {
        switch self {
        case .p256HashedPoint: return "P-256"
        case .mlkem1024StoredCiphertext: return "ML-KEM-1024"
        }
    }
}

/// The suite policy in effect; nil when the policy is invalid, in which
/// case every call fails closed.
func currentSuitePolicy() -> SuitePolicy? {
    switch currentMachinePolicy() {
    case .none:
        return SuitePolicy()
    case .invalid:
        return nil
    case .loaded(let policy):
        return policy.suites
    }
}

enum PolicyLoad: Equatable {
    case none                  // development mode
    case loaded(MachinePolicy) // production mode
    case invalid(String)       // every call fails closed with POLICY_INVALID
}

/// Test-only overrides of where the policy and the machine KEKs come
/// from, and of whether this Mac has ML-KEM. `nil` and `false` (the
/// defaults, and always in production) use the real ones. Task-local, so a test's override applies to its own calls only,
/// never to a suite running alongside it; internal, so only `@testable
/// import` can reach them -- never part of the C ABI.
enum MachineScopeTestOverrides {
    @TaskLocal static var policy: PolicyLoad?
    @TaskLocal static var keyFolder: String?
    /// `true` acts as a macOS before 26 does: the Secure Enclave neither
    /// creates nor loads ML-KEM keys. Lets a macOS 26 Mac test that path.
    @TaskLocal static var withoutMLKEM = false
}

private struct PolicyError: Error {
    let reason: String
}

/// A local or directory group name: ASCII letters, digits, `_`, `-`, `.`.
func validGroupName(_ name: String) -> Bool {
    let bytes = Array(name.utf8)
    guard !bytes.isEmpty, bytes.count <= 255, bytes.first != UInt8(ascii: "-") else {
        return false
    }
    return bytes.allSatisfy(isValidGroupNameByte)
}

/// A `switch` for the same reason as `isValidServiceByte`'s.
private func isValidGroupNameByte(_ byte: UInt8) -> Bool {
    switch byte {
    case 0x30...0x39, 0x41...0x5A, 0x61...0x7A,
         UInt8(ascii: "_"), UInt8(ascii: "-"), UInt8(ascii: "."):
        return true
    default:
        return false
    }
}

/// Validates and parses a policy's settings. Strict: an unknown setting or
/// a wrong type makes the whole policy invalid, never ignored -- a
/// misspelt `MachineServices` would otherwise leave a production service
/// quietly user-scoped.
func parseMachinePolicy(_ values: [String: Any], source: String) -> PolicyLoad {
    func group(_ value: Any?, _ setting: String) throws -> String? {
        guard let value else {
            return nil
        }
        guard let name = value as? String, validGroupName(name) else {
            throw PolicyError(reason: "\(setting) must be a group name")
        }
        return name
    }
    do {
        let known: Set<String> = ["MachineServices", "SecurityAdminGroup", "DeploymentAdminGroup", "KekSuite", "RequirePostQuantum"]
        if let unknown = Set(values.keys).subtracting(known).sorted().first {
            throw PolicyError(reason: "unknown setting \"\(unknown)\"")
        }
        var services: [String: MachineServiceSettings] = [:]
        if let raw = values["MachineServices"] {
            guard let table = raw as? [String: Any] else {
                throw PolicyError(reason: "MachineServices must be a dictionary keyed by service name")
            }
            for name in table.keys.sorted() {
                guard validServiceName(service: name) else {
                    throw PolicyError(reason: "MachineServices: \"\(name)\" is not a valid service name")
                }
                let service = String(decoding: name.utf8.map { (0x41...0x5A).contains($0) ? $0 + 0x20 : $0 }, as: UTF8.self)
                guard let settings = table[name] as? [String: Any] else {
                    throw PolicyError(reason: "MachineServices.\(name) must be a dictionary")
                }
                if let unknown = Set(settings.keys).subtracting(["RunnerGroup"]).sorted().first {
                    throw PolicyError(reason: "MachineServices.\(name): unknown setting \"\(unknown)\"")
                }
                guard services[service] == nil else {
                    throw PolicyError(reason: "MachineServices names \"\(service)\" twice (service names are case-insensitive)")
                }
                services[service] = MachineServiceSettings(
                    runnerGroup: try group(settings["RunnerGroup"], "MachineServices.\(name).RunnerGroup"))
            }
        }
        var suites = SuitePolicy()
        if let raw = values["KekSuite"] {
            guard let name = raw as? String,
                  let suite = [KEKSuite.mlkem1024StoredCiphertext, .p256HashedPoint].first(where: { $0.policyName == name }) else {
                throw PolicyError(reason: "KekSuite must be \"ML-KEM-1024\" or \"P-256\"")
            }
            suites.provisionSuite = suite
        }
        if let raw = values["RequirePostQuantum"] {
            // A real boolean only: NSNumber would also pass 0 and 1 as Bool.
            guard CFGetTypeID(raw as CFTypeRef) == CFBooleanGetTypeID(), let flag = raw as? Bool else {
                throw PolicyError(reason: "RequirePostQuantum must be a boolean")
            }
            suites.requirePostQuantum = flag
        }
        guard suites.permits(suites.provisionSuite) else {
            throw PolicyError(reason: "KekSuite P-256 contradicts RequirePostQuantum")
        }
        return .loaded(MachinePolicy(
            source: source,
            securityAdminGroup: try group(values["SecurityAdminGroup"], "SecurityAdminGroup"),
            deploymentAdminGroup: try group(values["DeploymentAdminGroup"], "DeploymentAdminGroup"),
            machineServices: services,
            suites: suites))
    } catch let error as PolicyError {
        return .invalid("\(source): \(error.reason)")
    } catch {
        return .invalid("\(source): \(error)")
    }
}

/// Reads all of `fd`, refusing more than `limit` bytes. nil on a read
/// error or an oversized file.
func readAll(fd: Int32, limit: Int) -> Data? {
    var data = Data()
    var buffer = [UInt8](repeating: 0, count: 4096)
    defer { secureZero(&buffer) }
    while data.count <= limit {
        let count = buffer.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
        if count < 0 {
            if errno == EINTR {
                continue
            }
            return nil
        }
        if count == 0 {
            return data
        }
        data.append(contentsOf: buffer[0..<count])
    }
    return nil
}

/// The policy at `path`, read as a file rather than through CFPreferences
/// so that every setting in it is seen and validated. nil when there is
/// no such file. It, and every folder above it, must be root's and
/// writable by root alone.
func loadPolicyFile(atPath path: String) -> PolicyLoad? {
    let url = URL(fileURLWithPath: path)
    let folderFd = open(url.deletingLastPathComponent().path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    guard folderFd >= 0 else {
        let code = errno
        return code == ENOENT ? nil : .invalid("\(path): its folder can't be opened (\(String(cString: strerror(code))))")
    }
    defer { close(folderFd) }
    let fd = openat(folderFd, url.lastPathComponent, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
    guard fd >= 0 else {
        let code = errno
        return code == ENOENT ? nil : .invalid("\(path) can't be opened (\(String(cString: strerror(code))))")
    }
    defer { close(fd) }
    guard keyFileFoldersAreTrusted(folderFd: folderFd, rootOnly: true) else {
        return .invalid("\(path): a folder above it is not root's, or others can write it")
    }
    var info = stat()
    guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG else {
        return .invalid("\(path) is not a regular file")
    }
    guard info.st_uid == 0, info.st_mode & (S_IWGRP | S_IWOTH) == 0,
          !onVolumeIgnoringOwnership(fd),
          !aclGrantsOthersAChange(fd: fd, isFolder: false, rootOnly: true) else {
        return .invalid("\(path) must be owned by root and writable by root alone")
    }
    guard info.st_size <= off_t(machinePolicyMaxSize), let data = readAll(fd: fd, limit: machinePolicyMaxSize) else {
        return .invalid("\(path) is larger than \(machinePolicyMaxSize) bytes, or can't be read")
    }
    guard let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
          let values = plist as? [String: Any] else {
        return .invalid("\(path) is not a property list dictionary")
    }
    return parseMachinePolicy(values, source: path)
}

/// The policy in effect: the managed one if MDM delivered it, else the
/// local file, else none (development mode). Read on every call, so a
/// changed profile takes effect without restarting anything -- but once
/// per call: inside `withPolicySnapshot` every read gives the same answer.
func currentMachinePolicy() -> PolicyLoad {
    if let snapshot = PolicySnapshot.current {
        return snapshot
    }
    if let forced = MachineScopeTestOverrides.policy {
        return forced
    }
    let load = loadPolicyFile(atPath: managedPolicyFilePath) ?? loadPolicyFile(atPath: localPolicyFilePath) ?? .none
    return applyProductionMarker(load, markerPath: productionMarkerFilePath, asRoot: geteuid() == 0)
}

/// Keeps a Mac that has been in production mode from sliding back to
/// development mode because its policy went away -- a removed profile, a
/// deleted `policy.plist`. Without this, "no policy" would mean what it
/// means on a developer's Mac: `RequirePostQuantum` off, and a service that
/// was machine-scoped provisioned again as a user-scoped KEK, by anyone.
///
/// - A valid policy, read by root: the marker is written if it isn't there
///   (root's own tools and daemons arm it; nobody else can).
/// - No policy, and the marker exists: the policy is reported invalid, so
///   every call fails closed (`POLICY_INVALID`) until the policy is back or
///   root deletes the marker to return to development mode on purpose.
///
/// A tripwire for a lost policy, not a defence against root: whoever can
/// delete a root-owned policy file can delete the marker with it. Nor does
/// it notice a policy replaced by a weaker one.
func applyProductionMarker(_ load: PolicyLoad, markerPath: String, asRoot: Bool,
                           requireTrustedFolder: Bool = true) -> PolicyLoad {
    switch load {
    case .invalid:
        return load
    case .loaded:
        if asRoot {
            recordProductionMode(markerPath: markerPath, requireTrustedFolder: requireTrustedFolder)
        }
        return load
    case .none:
        guard productionMarkerExists(markerPath) else {
            return .none
        }
        return .invalid("this Mac has been in production mode (\(markerPath)) but no policy is installed now: "
            + "restore the com.hkdfguard profile or \(localPolicyFilePath). "
            + "To return to development mode on purpose, delete the marker as root")
    }
}

/// Anything at all at `path` counts, whatever its type or owner; only "no
/// such file" (or no such folder) means the marker is absent, so an error
/// reading it fails closed.
private func productionMarkerExists(_ path: String) -> Bool {
    var info = stat()
    if lstat(path, &info) == 0 {
        return true
    }
    return errno != ENOENT && errno != ENOTDIR
}

private let productionMarkerFailureLogged = OSAllocatedUnfairLock(initialState: false)

/// Creates the marker if it is missing. Best effort: a failure is logged
/// (once per process) and changes nothing else -- the policy just read is
/// still in effect.
private func recordProductionMode(markerPath: String, requireTrustedFolder: Bool) {
    guard !productionMarkerExists(markerPath) else {
        return
    }
    func failed(_ what: String, _ code: Int32) {
        let first = productionMarkerFailureLogged.withLock { logged -> Bool in
            defer { logged = true }
            return !logged
        }
        if first {
            machineLog.error("could not record production mode in \(markerPath, privacy: .public): \(what, privacy: .public) (\(String(cString: strerror(code)), privacy: .public)); a removed policy would return this Mac to development mode")
        }
    }
    let url = URL(fileURLWithPath: markerPath)
    let folder = url.deletingLastPathComponent().path
    // The policy may be MDM's alone, on a Mac where nothing has made
    // hkdfguard's own folder yet.
    let created = mkdir(folder, 0o755) == 0
    if !created, errno != EEXIST {
        return failed("its folder can't be created", errno)
    }
    let folderFd = open(folder, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard folderFd >= 0 else {
        return failed("its folder can't be opened", errno)
    }
    defer { close(folderFd) }
    // mkdir applies this process's umask: a daemon running with 077 would
    // make the folder 0700, and the runner groups' daemons could never
    // reach the machine KEKs inside it. Set on the descriptor just opened,
    // as the KEK folder is (`openMachineKeyFolderCreatingIt`).
    if created {
        guard (geteuid() != 0 || fchown(folderFd, 0, 0) == 0), fchmod(folderFd, 0o755) == 0 else {
            return failed("its folder's owner and mode can't be set", errno)
        }
    }
    guard !requireTrustedFolder || keyFileFoldersAreTrusted(folderFd: folderFd, rootOnly: true) else {
        return failed("its folder, or one above it, is not root's or others can write it", EPERM)
    }
    let fd = openat(folderFd, url.lastPathComponent, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o644)
    guard fd >= 0 else {
        // Another process got there first: the marker exists, which is all
        // that was wanted.
        return errno == EEXIST ? () : failed("it can't be created", errno)
    }
    defer { close(fd) }
    let text = Array("""
        hkdfguard: this Mac has been in production mode (a com.hkdfguard policy was in effect).
        While this file exists, a missing policy makes every hkdfguard call fail with
        POLICY_INVALID (-9) instead of falling back to development mode.
        To return to development mode on purpose, delete this file as root.

        """.utf8)
    _ = text.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
    _ = fchmod(fd, 0o644)
    _ = fsync(fd)
    machineLog.notice("production mode recorded in \(markerPath, privacy: .public): from now on a missing policy fails closed instead of returning this Mac to development mode")
}

private enum PolicySnapshot {
    @TaskLocal static var current: PolicyLoad?
}

/// Runs `body` with the policy read once, now: everything `body` asks of
/// it (the service's scope, its runner group, the suites permitted) comes
/// from that one read, so a profile replaced mid-call can't leave a call
/// acting on half of each. Nested uses keep the outermost read.
func withPolicySnapshot<T>(_ body: () -> T) -> T {
    guard PolicySnapshot.current == nil else {
        return body()
    }
    return PolicySnapshot.$current.withValue(currentMachinePolicy(), operation: body)
}

/// Where a service's KEK lives.
enum KEKScope: Equatable {
    case user
    case machine(MachineServiceSettings)
    /// The policy can't be used: every call fails closed, whatever the
    /// service, until it is fixed -- as on Linux.
    case policyInvalid
}

func kekScope(service: String) -> KEKScope {
    switch currentMachinePolicy() {
    case .none:
        return .user
    case .invalid(let reason):
        machineLog.error("hkdfguard policy invalid, every call fails closed until it is fixed: \(reason, privacy: .public)")
        return .policyInvalid
    case .loaded(let policy):
        return policy.machineServices[service].map { .machine($0) } ?? .user
    }
}
