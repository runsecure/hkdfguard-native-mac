// Production mode's machine scope, as the CLI enforces it.
//
// The library decides which services are machine-scoped (its policy: an
// MDM profile for com.hkdfguard, or /Library/Application Support/HkdfGuard/
// policy.plist) and reports it through hkdfguard_machine_policy. For a
// machine-scoped service this tool adds the role separation the policy
// names, and does the one thing the library can't do from Terminal:
//
//   security admin    provision, retire     SecurityAdminGroup
//   deployment admin  wrap                  DeploymentAdminGroup
//   runtime           unwrap (a LaunchDaemon, in the service's RunnerGroup)
//
// Both admin roles act as root (`sudo`); the role is checked against the
// admin behind the session -- the audit user, which `sudo` doesn't change
// -- so `sudo` alone is not enough. Root itself (a root login) passes:
// machine scope trusts root, as every secret store on macOS does.
//
// A machine KEK must be created, and used to wrap, in the system context:
// the Secure Enclave binds a key to the context it was made in, and keys
// made from Terminal (`sudo` included) are unusable by LaunchDaemons. So
// `provision` and `wrap` hand that step to a one-off LaunchDaemon job
// running this same executable (`__system-job`), and only when both this
// executable and the library it loaded are root's: a job running as root
// must not run code anyone else can replace. The DEK reaches the job
// through a FIFO in a root-only folder -- kernel memory, never disk.

import Darwin
import Foundation
import os
import Darwin.membership // mbr_uid_to_uuid, mbr_gid_to_uuid, mbr_check_membership
import MachO // _NSGetExecutablePath

@_silgen_name("hkdfguard_machine_policy")
func hkdfguard_machine_policy(_ out: UnsafeMutablePointer<UInt8>?, _ outLen: UnsafeMutablePointer<Int32>?) -> Int32

// MARK: - The policy in effect

struct CLIPolicy {
    var production: Bool
    var source: String?
    var securityAdminGroup: String?
    var deploymentAdminGroup: String?
    /// Normalized service -> its RunnerGroup (nil: root only).
    var machineServices: [String: String?]
    var machineKeyFolder: String

    func isMachineScoped(_ service: String) -> Bool {
        machineServices[service.lowercased()] != nil
    }

    func runnerGroup(_ service: String) -> String? {
        machineServices[service.lowercased()] ?? nil
    }

    func keyFilePath(_ service: String) -> String {
        "\(machineKeyFolder)/\(service.lowercased()).kek"
    }
}

/// The policy as the library reads it. An invalid policy stops every
/// command, as it stops every library call.
func loadPolicy() throws -> CLIPolicy {
    var length: Int32 = 0
    var status = hkdfguard_machine_policy(nil, &length)
    guard status == HKDFGuardStatus.outputBufferTooSmall.rawValue, length > 0 else {
        throw CLIError("hkdfguard_machine_policy failed: \(describeStatus(status))")
    }
    var bytes = [UInt8](repeating: 0, count: Int(length))
    status = bytes.withUnsafeMutableBufferPointer { hkdfguard_machine_policy($0.baseAddress, &length) }
    guard status == HKDFGuardStatus.success.rawValue,
          let object = try? JSONSerialization.jsonObject(with: Data(bytes.prefix(Int(length)))) as? [String: Any],
          let mode = object["mode"] as? String,
          let folder = object["machineKeyFolder"] as? String else {
        throw CLIError("hkdfguard_machine_policy returned an unreadable answer (\(describeStatus(status)))")
    }
    if mode == "invalid" {
        throw CLIError("the hkdfguard policy is invalid -- \(object["reason"] as? String ?? "no reason given"); every operation fails until it is fixed")
    }
    var services: [String: String?] = [:]
    for (service, settings) in object["machineServices"] as? [String: [String: String]] ?? [:] {
        services[service] = settings["runnerGroup"]
    }
    return CLIPolicy(
        production: mode == "production",
        source: object["source"] as? String,
        securityAdminGroup: object["securityAdminGroup"] as? String,
        deploymentAdminGroup: object["deploymentAdminGroup"] as? String,
        machineServices: services,
        machineKeyFolder: folder
    )
}

// MARK: - Roles

enum AdminRole {
    case security
    case deployment

    var setting: String {
        switch self {
        case .security: return "SecurityAdminGroup"
        case .deployment: return "DeploymentAdminGroup"
        }
    }

    var duty: String {
        switch self {
        case .security: return "provision and retire machine KEKs"
        case .deployment: return "wrap DEKs under machine KEKs"
        }
    }

    func group(in policy: CLIPolicy) -> String? {
        switch self {
        case .security: return policy.securityAdminGroup
        case .deployment: return policy.deploymentAdminGroup
        }
    }
}

/// The account that logged in to start this session -- the admin behind
/// `sudo`, which `sudo` does not change. nil when unknown or root.
func sessionUser() -> (uid: uid_t, name: String)? {
    var info = auditinfo_addr_t()
    guard getaudit_addr(&info, Int32(MemoryLayout<auditinfo_addr_t>.size)) == 0 else {
        return nil
    }
    let uid = info.ai_auid
    guard uid != 0, uid != uid_t.max /* AU_DEFAUDITID: none recorded */, let entry = getpwuid(uid) else {
        return nil
    }
    return (uid, String(cString: entry.pointee.pw_name))
}

func isMember(uid: uid_t, ofGroup name: String) -> Bool {
    guard let group = getgrnam(name) else {
        return false
    }
    var userUUID = [UInt8](repeating: 0, count: 16)
    var groupUUID = [UInt8](repeating: 0, count: 16)
    var member: Int32 = 0
    guard mbr_uid_to_uuid(uid, &userUUID) == 0,
          mbr_gid_to_uuid(group.pointee.gr_gid, &groupUUID) == 0,
          mbr_check_membership(&userUUID, &groupUUID, &member) == 0 else {
        return false
    }
    return member != 0
}

/// A machine-scoped service's admin commands run as root, by a member of
/// the role's group (when the policy names one). `command` is how to
/// rerun it, for the message.
func requireAdminRole(_ role: AdminRole, policy: CLIPolicy, service: String, command: String) throws {
    guard geteuid() == 0 else {
        throw CLIError("service \"\(service)\" is machine-scoped (policy \(policy.source ?? "?")): only root can \(role.duty) -- run `sudo \(programName) \(command) ...`")
    }
    guard let group = role.group(in: policy) else {
        return // no group named: any admin who can sudo
    }
    guard let user = sessionUser() else {
        return // a root login: trusted
    }
    guard isMember(uid: user.uid, ofGroup: group) else {
        throw CLIError("\(user.name) is not a member of \(group), the policy's \(role.setting): only its members may \(role.duty)")
    }
}

// MARK: - Root's own code only

/// Whether `path` and every folder above it are root's and writable by
/// root alone. Checked without following a symbolic link at any step.
func rootControls(_ path: String) -> Bool {
    var current = path
    while true {
        var info = stat()
        guard lstat(current, &info) == 0, info.st_uid == 0, info.st_mode & (S_IWGRP | S_IWOTH) == 0,
              info.st_mode & S_IFMT != S_IFLNK else {
            return false
        }
        if current == "/" {
            return true
        }
        current = (current as NSString).deletingLastPathComponent
        if current.isEmpty {
            return false
        }
    }
}

/// This executable, if it and the libhkdfguard it loaded are root's: the
/// only code a root LaunchDaemon job may run.
func rootOwnedSelf() throws -> String {
    var size: UInt32 = 0
    _ = _NSGetExecutablePath(nil, &size)
    var raw = [CChar](repeating: 0, count: Int(size) + 1)
    guard _NSGetExecutablePath(&raw, &size) == 0, let resolved = realpath(raw, nil) else {
        throw CLIError("can't determine this executable's path")
    }
    let executable = String(cString: resolved)
    free(resolved)

    var library = "(unknown)"
    var info = Dl_info()
    if let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "hkdfguard_machine_policy"), // RTLD_DEFAULT
       dladdr(symbol, &info) != 0, let name = info.dli_fname, let real = realpath(name, nil) {
        library = String(cString: real)
        free(real)
    }
    guard rootControls(executable), rootControls(library) else {
        throw CLIError("machine-scoped operations run part of this tool as root in a LaunchDaemon job, so this executable (\(executable)) and the library it loaded (\(library)) must be owned by root and writable by root alone -- use the installed hkdfguard (/Library/Application Support/HkdfGuard/v1/hkdfguard)")
    }
    return executable
}

// MARK: - The one-off system job

enum SystemJobOperation: String {
    case provision
    case wrap
}

struct SystemJobResult {
    var status: Int32
    var payload: [UInt8]
}

private let systemJobTimeout: TimeInterval = 30

/// Where the one-off system jobs keep their folders. Every folder from / down
/// to here must be root's and writable by root alone: the root CLI creates
/// the job's definition, its DEK channel and reads its answer here by path,
/// so a folder anyone else could write -- as /private/var/run is to the
/// daemon group -- would let them swap the job folder for one of their own.
let systemJobsFolder = "/Library/Application Support/HkdfGuard/v1/jobs"

/// A job folder older than this was left by a run that died; it is removed.
private let staleJobAge: TimeInterval = 10 * 60

/// Whether `path` is a real folder (not a link), root's, and closed to
/// everyone else.
private func isRootOnlyFolder(_ path: String) -> Bool {
    var info = stat()
    return lstat(path, &info) == 0 && info.st_mode & S_IFMT == S_IFDIR && info.st_uid == 0 && info.st_mode & 0o077 == 0
}

/// Creates the jobs folder if needed and refuses to go on unless it, and
/// every folder above it, is root's alone. Removes job folders a crashed
/// run left behind.
private func prepareSystemJobsFolder() throws {
    let parent = (systemJobsFolder as NSString).deletingLastPathComponent
    if mkdir(parent, 0o755) != 0 && errno != EEXIST {
        throw CLIError("can't create \(parent): \(String(cString: strerror(errno)))")
    }
    if mkdir(systemJobsFolder, 0o700) != 0 && errno != EEXIST {
        throw CLIError("can't create \(systemJobsFolder): \(String(cString: strerror(errno)))")
    }
    guard rootControls(systemJobsFolder), isRootOnlyFolder(systemJobsFolder) else {
        throw CLIError("\(systemJobsFolder), and every folder above it, must be owned by root and writable by root alone (the folder itself mode 0700); refusing to run a system job there")
    }
    let now = Date()
    for entry in (try? FileManager.default.contentsOfDirectory(atPath: systemJobsFolder)) ?? [] where entry.hasPrefix("job.") {
        let path = "\(systemJobsFolder)/\(entry)"
        var info = stat()
        guard lstat(path, &info) == 0 else { continue }
        let modified = Date(timeIntervalSince1970: TimeInterval(info.st_mtimespec.tv_sec))
        if now.timeIntervalSince(modified) > staleJobAge {
            try? FileManager.default.removeItem(atPath: path)
        }
    }
}

private func launchctl(_ arguments: [String]) -> Int32 {
    var pid: pid_t = 0
    let argv = (["/bin/launchctl"] + arguments).map { strdup($0) } + [nil]
    defer { argv.forEach { free($0) } }
    guard posix_spawn(&pid, "/bin/launchctl", nil, nil, argv, nil) == 0 else {
        return -1
    }
    var status: Int32 = 0
    while waitpid(pid, &status, 0) < 0 && errno == EINTR {}
    return status
}

private func xmlEscaped(_ text: String) -> String {
    text.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;").replacingOccurrences(of: ">", with: "&gt;")
}

/// Runs `operation` for `service` in the system context: a one-off
/// LaunchDaemon job running this executable, removed as soon as it has
/// answered. For `wrap`, `dek` goes to it through a FIFO.
func runSystemJob(_ operation: SystemJobOperation, service: String, dek: UnsafeRawBufferPointer? = nil) throws -> SystemJobResult {
    let executable = try rootOwnedSelf()

    try prepareSystemJobsFolder()
    var template = Array("\(systemJobsFolder)/job.XXXXXX".utf8CString)
    guard let made = mkdtemp(&template) else {
        throw CLIError("can't create the system job's folder: \(String(cString: strerror(errno)))")
    }
    let folder = String(cString: made)
    guard isRootOnlyFolder(folder) else {
        throw CLIError("the system job's folder \(folder) is not a root-only folder")
    }
    let label = "com.hkdfguard.job.\(UInt64.random(in: .min ... .max))"
    defer {
        _ = launchctl(["bootout", "system/\(label)"])
        try? FileManager.default.removeItem(atPath: folder)
    }

    let request: [String: Any] = ["operation": operation.rawValue, "service": service]
    let requestData = try PropertyListSerialization.data(fromPropertyList: request, format: .xml, options: 0)
    guard FileManager.default.createFile(atPath: "\(folder)/request.plist", contents: requestData, attributes: [.posixPermissions: 0o600]) else {
        throw CLIError("can't write the system job's request")
    }
    if operation == .wrap {
        guard mkfifo("\(folder)/dek.fifo", 0o600) == 0 else {
            throw CLIError("can't create the system job's DEK channel: \(String(cString: strerror(errno)))")
        }
    }

    let plist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
        <key>Label</key><string>\(label)</string>
        <key>ProgramArguments</key><array>
          <string>\(xmlEscaped(executable))</string><string>__system-job</string><string>\(xmlEscaped(folder))</string>
        </array>
        <key>RunAtLoad</key><true/>
        <key>LaunchOnlyOnce</key><true/>
        <key>StandardOutPath</key><string>\(xmlEscaped(folder))/job.out</string>
        <key>StandardErrorPath</key><string>\(xmlEscaped(folder))/job.err</string>
        </dict></plist>
        """
    guard FileManager.default.createFile(atPath: "\(folder)/job.plist", contents: Data(plist.utf8), attributes: [.posixPermissions: 0o644]) else {
        throw CLIError("can't write the system job's definition")
    }
    guard launchctl(["bootstrap", "system", "\(folder)/job.plist"]) == 0 else {
        throw CLIError("launchctl could not start the system job")
    }

    let deadline = Date().addingTimeInterval(systemJobTimeout)
    if let dek {
        // Opening a FIFO for writing fails (ENXIO) until the job opens it
        // for reading; then the DEK goes straight into the job.
        var fd: Int32 = -1
        while fd < 0 && Date() < deadline {
            fd = open("\(folder)/dek.fifo", O_WRONLY | O_NONBLOCK | O_CLOEXEC)
            if fd < 0 {
                usleep(20_000)
            }
        }
        guard fd >= 0 else {
            throw CLIError("the system job never collected the DEK\(jobDiagnostics(folder))")
        }
        _ = fcntl(fd, F_SETFL, 0)
        let sent = dek.baseAddress.map { write(fd, $0, dek.count) } ?? -1
        close(fd)
        guard sent == dek.count else {
            throw CLIError("could not hand the DEK to the system job")
        }
    }

    let resultPath = "\(folder)/result.plist"
    while !FileManager.default.fileExists(atPath: resultPath) && Date() < deadline {
        usleep(50_000)
    }
    guard let data = FileManager.default.contents(atPath: resultPath),
          let result = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
          let status = result["status"] as? Int else {
        throw CLIError("the system job did not answer within \(Int(systemJobTimeout)) s\(jobDiagnostics(folder))")
    }
    return SystemJobResult(status: Int32(status), payload: [UInt8](result["payload"] as? Data ?? Data()))
}

private func jobDiagnostics(_ folder: String) -> String {
    let err = (try? String(contentsOfFile: "\(folder)/job.err", encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    return err.isEmpty ? "" : " (job: \(err))"
}

/// `hkdfguard __system-job <folder>`: the job's side. Root only, in a
/// root-only folder the CLI made; never listed in the usage.
func runSystemJobSide(folder: String) throws {
    guard geteuid() == 0 else {
        throw CLIError("__system-job is internal to hkdfguard and runs only as root")
    }
    // Only a folder the CLI made in the jobs folder: root's alone, as is
    // every folder above it.
    guard (folder as NSString).deletingLastPathComponent == systemJobsFolder,
          isRootOnlyFolder(folder), rootControls(folder) else {
        throw CLIError("__system-job: \(folder) is not a root-only folder in \(systemJobsFolder)")
    }
    guard let data = FileManager.default.contents(atPath: "\(folder)/request.plist"),
          let request = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
          let operation = (request["operation"] as? String).flatMap(SystemJobOperation.init(rawValue:)),
          let service = request["service"] as? String else {
        throw CLIError("__system-job: no readable request")
    }

    var result: [String: Any]
    switch operation {
    case .provision:
        result = ["status": Int(service.withCString { hkdfguard_create_kek($0) })]
    case .wrap:
        // The library's own status goes back to the CLI, which explains it.
        result = try withDekFromFifo("\(folder)/dek.fifo", timeout: systemJobTimeout, abandon: {
            // The CLI never sent the DEK, so it died or gave up: nobody will
            // read an answer, and this folder would only be left behind.
            try? FileManager.default.removeItem(atPath: folder)
        }) { dek -> [String: Any] in
            var out = [UInt8](repeating: 0, count: initialWrappedCapacity)
            var length = Int32(out.count)
            let status = service.withCString { servicePtr in
                out.withUnsafeMutableBufferPointer { buffer in
                    hkdfguard_wrap_dek(servicePtr, dek.bindMemory(to: UInt8.self).baseAddress, Int32(dek.count), buffer.baseAddress, &length)
                }
            }
            guard status == HKDFGuardStatus.success.rawValue else {
                return ["status": Int(status)]
            }
            return ["status": 0, "payload": Data(out.prefix(Int(length)))]
        }
    }
    let out = try PropertyListSerialization.data(fromPropertyList: result, format: .xml, options: 0)
    // Written whole, then renamed into place: the CLI never reads half of it.
    let temp = "\(folder)/result.tmp"
    guard FileManager.default.createFile(atPath: temp, contents: out, attributes: [.posixPermissions: 0o600]),
          rename(temp, "\(folder)/result.plist") == 0 else {
        throw CLIError("__system-job: can't write the result")
    }
}

/// Reads the 32-byte DEK from the FIFO into a locked, zeroed-after buffer,
/// waiting at most `timeout` for the CLI to send it. If the CLI died before
/// sending, the job runs `abandon` and fails instead of blocking for ever.
func withDekFromFifo<T>(_ path: String, timeout: TimeInterval, abandon: () -> Void = {},
                        _ body: (UnsafeRawBufferPointer) throws -> T) throws -> T {
    let pageSize = Int(getpagesize())
    let buffer = UnsafeMutableRawBufferPointer.allocate(byteCount: pageSize, alignment: pageSize)
    guard let base = buffer.baseAddress else {
        throw CLIError("__system-job: no buffer for the DEK")
    }
    memset(base, 0, pageSize)
    let locked = mlock(base, pageSize) == 0
    defer {
        _ = memset_s(base, pageSize, 0, pageSize)
        if locked { munlock(base, pageSize) }
        buffer.deallocate()
    }
    // Opened read-write, which never blocks on a FIFO and keeps a writer
    // (this process) attached, so a read can't see end-of-file before the
    // CLI connects; poll then bounds the wait. A blocking read-only open
    // would wait for ever if the CLI died before opening its end.
    let fd = open(path, O_RDWR | O_CLOEXEC)
    guard fd >= 0 else {
        abandon()
        throw CLIError("__system-job: can't open the DEK channel")
    }
    defer { close(fd) }
    let deadline = Date().addingTimeInterval(timeout)
    var filled = 0
    while filled < dekLen {
        let remaining = deadline.timeIntervalSinceNow
        guard remaining > 0 else { break }
        var pollFd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        let ready = poll(&pollFd, 1, Int32(min(remaining * 1000, Double(Int32.max))))
        if ready < 0 && errno == EINTR { continue }
        if ready <= 0 { break }
        let count = read(fd, base + filled, dekLen - filled)
        if count < 0 && errno == EINTR { continue }
        if count <= 0 { break }
        filled += count
    }
    guard filled == dekLen else {
        abandon()
        throw CLIError("__system-job: the DEK channel delivered \(filled) bytes, not \(dekLen), within \(Int(timeout)) s")
    }
    return try body(UnsafeRawBufferPointer(start: base, count: dekLen))
}

// MARK: - Retiring a machine KEK

/// Deletes the machine KEK file for `service`, through a folder chain
/// opened without following links, and only the regular, root-owned file
/// that was checked.
func deleteMachineKeyFile(policy: CLIPolicy, service: String) throws {
    let path = policy.keyFilePath(service)
    let folder = try openRealFolder(path, what: "the machine KEK file")
    defer { folder.close() }
    let fd = openat(folder.fd, folder.leaf, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
    guard fd >= 0 else {
        throw CLIError("can't open \(path): \(String(cString: strerror(errno)))")
    }
    defer { close(fd) }
    var info = stat()
    guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_uid == 0 else {
        throw CLIError("\(path) is not a root-owned regular file; nothing was deleted")
    }
    guard unlinkIfStillSame(folder, fd: fd) else {
        throw CLIError("\(path) changed while it was being retired; nothing was deleted")
    }
    try flushFolder(folder)
    guard !keyFileNameIsTaken(folder) else {
        throw CLIError("\(path) is still present after deletion")
    }
}

// MARK: - Audit

private let auditLog = Logger(subsystem: "com.hkdfguard", category: "audit")

/// Event 1004 (as on Linux): a KEK was retired. The library writes every
/// other record; retiring is this tool's alone.
func auditKekRetired(service: String, fingerprint: [UInt8], scope: String) {
    let actor = sessionUser()?.name ?? "root"
    let line = "event=1004 op=retire result=OK service=\"\(service)\" provider=SECURE_ENCLAVE keychain=\(scope) kek_fingerprint=\(hexString(fingerprint)) actor=\"\(actor)\" uid=\(getuid()) euid=\(geteuid()) pid=\(getpid()) msg=\"KEK retired: no DEK wrapped under it unwraps unless the KEK is restored from a backup or snapshot\""
    auditLog.error("\(line, privacy: .public)")
}
