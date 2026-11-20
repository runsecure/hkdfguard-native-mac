//
//  HkdfGuardMachineKEK.swift
//  HkdfGuardNativeMacOS
//
//  Machine-scoped KEKs: the system context, the KEK file and its format,
//  runner groups, and reading, verifying and creating a machine KEK.
//

import Foundation
import CryptoKit
import Security
import os
import Darwin.membership // mbr_uuid_to_id, mbr_check_membership: not re-exported by Foundation in every SDK

/// Whether this process runs outside every login session: a LaunchDaemon,
/// or a process one started -- not Terminal, `sudo` from it, SSH, or a GUI
/// app. Judged from the process's audit session, which every process of a
/// login session shares and none can leave: one with graphic, terminal,
/// remote or console access is a login session. The Secure Enclave binds a
/// key to the context it was created in, so a machine KEK must be created
/// here to be usable by daemons, and is refused here first anywhere else.
func runningInSystemContext() -> Bool {
    var info = auditinfo_addr_t()
    guard getaudit_addr(&info, Int32(MemoryLayout<auditinfo_addr_t>.size)) == 0 else {
        return false
    }
    // AU_SESSION_FLAG_HAS_GRAPHIC_ACCESS | _HAS_TTY | _IS_REMOTE | _HAS_CONSOLE_ACCESS
    let loginSessionFlags: UInt64 = 0x0010 | 0x0020 | 0x1000 | 0x2000
    return UInt64(info.ai_flags) & loginSessionFlags == 0
}

// The machine KEK file: magic "HKGK", then a format byte.
//
// Format 1 (P-256 only): the KEK's public key (uncompressed x963, 65 bytes)
// -- so its fingerprint can be read without the Secure Enclave, by `status`
// and `retire` -- then the Secure Enclave blob, length-prefixed (big-endian
// u16).
//
// Format 3 (either suite): the suite byte, the KEK's 32-byte fingerprint
// (all `status` and `retire` need, without keeping the public key at rest),
// then three length-prefixed fields: the blob; the stored ciphertext (1568
// bytes for suite 0x02, none for P-256); and suite 0x02's P-256 blob (none
// for P-256). Format 2, an ML-KEM-only KEK from before suite 0x02 became a
// hybrid, is no longer read.
//
// The blobs are usable only by this Mac's Secure Enclave, in the system
// context.
private let machineKeyMagic = Data("HKGK".utf8)
private let machineKeyPublicKeyLength = 65
private let machineKeyV1HeaderLength = 4 + 1 + 65 + 2
private let machineKeyV2HeaderLength = 4 + 1 + 1 + 32
private let machineKeyMaxSize = 8192 // a suite 0x02 file is about 3.7 KB

struct MachineKeyFile: Equatable {
    var suite: KEKSuite
    /// Format 1 only; format 3 keeps just the fingerprint.
    var publicKey: Data?
    var fingerprint: Data
    var blob: Data
    /// Suite 0x02: the stored ciphertext. Empty for P-256.
    var encapsulated: Data
    /// Suite 0x02: its P-256 key's blob. Empty for P-256.
    var classicalBlob = Data()

    fileprivate mutating func zeroBlobs() {
        secureZero(&blob)
        secureZero(&classicalBlob)
    }

    /// A format 1 file: a P-256 KEK and its public key.
    static func v1(publicKey: Data, blob: Data) -> MachineKeyFile {
        MachineKeyFile(suite: .p256HashedPoint, publicKey: publicKey,
                       fingerprint: Data(SHA256.hash(data: publicKey)), blob: blob, encapsulated: Data())
    }

    /// A format 3 file.
    static func v3(_ stored: StoredKEK, fingerprint: Data) -> MachineKeyFile {
        switch stored {
        case .p256(let blob):
            return MachineKeyFile(suite: .p256HashedPoint, publicKey: nil, fingerprint: fingerprint,
                                  blob: blob, encapsulated: Data())
        case .mlkem1024(let blob, let encapsulated, let classicalBlob):
            return MachineKeyFile(suite: .mlkem1024StoredCiphertext, publicKey: nil, fingerprint: fingerprint,
                                  blob: blob, encapsulated: encapsulated, classicalBlob: classicalBlob)
        }
    }

    var stored: StoredKEK {
        switch suite {
        case .p256HashedPoint: return .p256(blob: blob)
        case .mlkem1024StoredCiphertext: return .mlkem1024(blob: blob, encapsulated: encapsulated, classicalBlob: classicalBlob)
        }
    }
}

/// The stored ciphertext's length a suite requires.
private func machineKeyCiphertextLength(_ suite: KEKSuite) -> Int {
    switch suite {
    case .p256HashedPoint: return 0
    case .mlkem1024StoredCiphertext: return mlkem1024CiphertextLength
    }
}

private func appendLengthPrefixed(_ field: Data, to out: inout Data) {
    out.append(UInt8(field.count >> 8))
    out.append(UInt8(field.count & 0xFF))
    out.append(field)
}

func encodeMachineKeyFile(_ file: MachineKeyFile) -> Data? {
    guard !file.blob.isEmpty, file.blob.count <= Int(UInt16.max),
          file.encapsulated.count == machineKeyCiphertextLength(file.suite),
          file.classicalBlob.count <= Int(UInt16.max),
          file.classicalBlob.isEmpty == (file.suite == .p256HashedPoint) else {
        return nil
    }
    var out = machineKeyMagic
    if let publicKey = file.publicKey {
        guard file.suite == .p256HashedPoint, publicKey.count == machineKeyPublicKeyLength,
              file.fingerprint == Data(SHA256.hash(data: publicKey)) else {
            return nil
        }
        out.append(1)
        out.append(publicKey)
    } else {
        guard file.fingerprint.count == 32 else {
            return nil
        }
        out.append(3)
        out.append(file.suite.rawValue)
        out.append(file.fingerprint)
    }
    appendLengthPrefixed(file.blob, to: &out)
    if file.publicKey == nil {
        appendLengthPrefixed(file.encapsulated, to: &out)
        appendLengthPrefixed(file.classicalBlob, to: &out)
    }
    return out.count <= machineKeyMaxSize ? out : nil
}

func decodeMachineKeyFile(_ data: Data) -> MachineKeyFile? {
    var bytes = [UInt8](data)
    defer { secureZero(&bytes) }
    guard bytes.count > 5, bytes.count <= machineKeyMaxSize, Data(bytes[0..<4]) == machineKeyMagic else {
        return nil
    }
    switch bytes[4] {
    case 1:
        guard bytes.count > machineKeyV1HeaderLength else {
            return nil
        }
        let publicKey = Data(bytes[5..<(5 + machineKeyPublicKeyLength)])
        guard let blob = lengthPrefixedField(in: bytes, at: machineKeyV1HeaderLength - 2), !blob.isEmpty,
              blob.upperBound == bytes.count,
              (try? P256.KeyAgreement.PublicKey(x963Representation: publicKey)) != nil else {
            return nil
        }
        return .v1(publicKey: publicKey, blob: Data(bytes[blob]))
    case 3:
        guard bytes.count > machineKeyV2HeaderLength, let suite = KEKSuite(rawValue: bytes[5]) else {
            return nil
        }
        let fingerprint = Data(bytes[6..<machineKeyV2HeaderLength])
        guard fingerprint.contains(where: { $0 != 0 }),
              let blob = lengthPrefixedField(in: bytes, at: machineKeyV2HeaderLength), !blob.isEmpty,
              let encapsulated = lengthPrefixedField(in: bytes, at: blob.upperBound),
              encapsulated.count == machineKeyCiphertextLength(suite),
              let classical = lengthPrefixedField(in: bytes, at: encapsulated.upperBound),
              classical.isEmpty == (suite == .p256HashedPoint),
              classical.upperBound == bytes.count else {
            return nil
        }
        let stored: StoredKEK = suite == .p256HashedPoint
            ? .p256(blob: Data(bytes[blob]))
            : .mlkem1024(blob: Data(bytes[blob]), encapsulated: Data(bytes[encapsulated]), classicalBlob: Data(bytes[classical]))
        return .v3(stored, fingerprint: fingerprint)
    default:
        return nil
    }
}

enum MachineKeyRead {
    case found(MachineKeyFile)
    case notFound
    /// The file is there but can't be used: `keychainAccessDenied` when this
    /// account may not read it, `kekCorrupted` when it, or a folder above
    /// it, isn't one root alone controls, or isn't a file this library
    /// wrote. `reason` is for the log.
    case refused(HKDFGuardStatus, reason: String)

    static func accessDenied(_ reason: String) -> MachineKeyRead {
        .refused(.keychainAccessDenied, reason: reason)
    }

    static func untrusted(_ reason: String) -> MachineKeyRead {
        .refused(.kekCorrupted, reason: reason)
    }
}

func machineKeyFolder() -> String {
    MachineScopeTestOverrides.keyFolder ?? machineKeyFolderPath
}

/// Reads a machine KEK file. It must be root's, writable by root alone,
/// with no access at all for others, in folders only root controls. Its
/// group must be the runner group the policy names now (none: no group
/// access at all). The reasons are for the log only.
func readMachineKeyFile(service: String, settings: MachineServiceSettings) -> MachineKeyRead {
    let folder = machineKeyFolder()
    let folderFd = open(folder, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    guard folderFd >= 0 else {
        let code = errno
        if code == ENOENT {
            return .notFound
        }
        if code == EACCES {
            return .accessDenied("\(folder) can't be opened by this account")
        }
        return .untrusted("\(folder) can't be opened (\(String(cString: strerror(code))))")
    }
    defer { close(folderFd) }
    guard keyFileFoldersAreTrusted(folderFd: folderFd, rootOnly: true) else {
        return .untrusted("\(folder), or a folder above it, is not root's or can be written by others")
    }
    let fd = openat(folderFd, "\(service).kek", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
    guard fd >= 0 else {
        let code = errno
        if code == ENOENT {
            return .notFound
        }
        if code == EACCES {
            return .accessDenied("this account may not read the machine KEK for \(service): it is neither root nor in the service's runner group")
        }
        return .untrusted("the machine KEK file for \(service) can't be opened (\(String(cString: strerror(code))))")
    }
    defer { close(fd) }
    var info = stat()
    guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_uid == 0,
          info.st_mode & (S_IWGRP | S_IROTH | S_IWOTH | S_IXOTH) == 0,
          !onVolumeIgnoringOwnership(fd),
          !aclGrantsOthersAChange(fd: fd, isFolder: false, rootOnly: true) else {
        return .untrusted("the machine KEK file for \(service) is not a root-owned file that only root can change and only its runner group can read")
    }
    if let problem = machineKeyFileGroupProblem(mode: info.st_mode, gid: info.st_gid, runnerGroup: settings.runnerGroup) {
        return .untrusted("the machine KEK file for \(service) \(problem)")
    }
    guard info.st_size <= off_t(machineKeyMaxSize), var bytes = readAll(fd: fd, limit: machineKeyMaxSize) else {
        return .untrusted("the machine KEK file for \(service) is too large, or can't be read")
    }
    defer { secureZero(&bytes) }
    guard let file = decodeMachineKeyFile(bytes) else {
        return .untrusted("the machine KEK file for \(service) is not one this library wrote")
    }
    return .found(file)
}

/// Machine KEKs stay usable after the first unlock following a boot --
/// logged out, at the login window, after an unattended restart -- unlike
/// the user-scoped KEKs' WhenUnlocked, which fails as soon as the last user
/// logs out.
private func makeMachineAccessControl() -> SecAccessControl? {
    var error: Unmanaged<CFError>?
    return SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        [.privateKeyUsage],
        &error
    )
}

/// Whether `key` can do a key agreement now, and gets the answer its
/// public key predicts.
private func keyAgreementWorks(_ key: any KeyAgreementKey) -> Bool {
    let peer = P256.KeyAgreement.PrivateKey()
    guard let ours = try? key.sharedSecretFromKeyAgreement(with: peer.publicKey),
          let theirs = try? peer.sharedSecretFromKeyAgreement(with: key.publicKey) else {
        return false
    }
    return ours == theirs
}

/// Whether `kek` can do its suite's enclave operations now: a key agreement
/// for P-256; for suite 0x02, that and decapsulating its stored ciphertext.
private func kekWorks(_ kek: KEK) -> Bool {
    switch kek {
    case .p256(let key): return keyAgreementWorks(key)
    case .mlkem1024(let kem): return (try? kem.key.decapsulate(kem.encapsulated)) != nil && keyAgreementWorks(kem.classical)
    }
}

private func logMachineRefusal(_ service: String, _ reason: String) {
    machineLog.error("\(service, privacy: .public): \(reason, privacy: .public)")
}

/// Whether the machine KEK file for `service` exists. File-level only --
/// no Secure Enclave use -- so root can ask from Terminal (`status`).
func machineKekExists(service: String, settings: MachineServiceSettings) -> (status: Int32, exists: Bool) {
    switch readMachineKeyFile(service: service, settings: settings) {
    case .found(var file):
        file.zeroBlobs()
        return (HKDFGuardStatus.success.rawValue, true)
    case .notFound:
        return (HKDFGuardStatus.success.rawValue, false)
    case .refused(let status, let reason):
        logMachineRefusal(service, reason)
        return (status.rawValue, false)
    }
}

/// The machine KEK's fingerprint and suite, from its file -- no Secure
/// Enclave use, so they can be read from anywhere the file can.
func machineKeySummary(service: String, settings: MachineServiceSettings) -> (status: Int32, summary: (fingerprint: Data, suite: KEKSuite)?) {
    switch readMachineKeyFile(service: service, settings: settings) {
    case .found(var file):
        file.zeroBlobs()
        return (HKDFGuardStatus.success.rawValue, (file.fingerprint, file.suite))
    case .notFound:
        return (HKDFGuardStatus.kekNotFound.rawValue, nil)
    case .refused(let status, let reason):
        logMachineRefusal(service, reason)
        return (status.rawValue, nil)
    }
}

/// Loads the machine KEK for wrap and unwrap: only in the system context,
/// and only if it is the key its file says.
func getMachineKEK(service: String, settings: MachineServiceSettings) -> (status: Int32, key: KEK?) {
    guard runningInSystemContext() else {
        logMachineRefusal(service, "machine KEKs can only be used by a LaunchDaemon -- not from Terminal, sudo, SSH or a login session")
        return (HKDFGuardStatus.keychainAccessDenied.rawValue, nil)
    }
    switch readMachineKeyFile(service: service, settings: settings) {
    case .notFound:
        return (HKDFGuardStatus.kekNotFound.rawValue, nil)
    case .refused(let status, let reason):
        logMachineRefusal(service, reason)
        return (status.rawValue, nil)
    case .found(var file):
        defer { file.zeroBlobs() }
        switch reconstructStoredKEK(file.stored, enclaveIsUsable: { enclaveProbeSucceeds(makeMachineAccessControl()) }) {
        case .key(let kek):
            guard kek.fingerprint == file.fingerprint else {
                logMachineRefusal(service, "the machine KEK file's key does not match the fingerprint it records")
                return (HKDFGuardStatus.kekCorrupted.rawValue, nil)
            }
            return (HKDFGuardStatus.success.rawValue, kek)
        case .corrupt:
            return (HKDFGuardStatus.kekCorrupted.rawValue, nil)
        case .enclaveRefused:
            return (HKDFGuardStatus.keychainAccessDenied.rawValue, nil)
        }
    }
}

/// Groups too broad to read a machine KEK: each covers essentially every
/// account, every administrator, or everyone allowed to log in remotely.
/// Matched by name and by resolved gid, so another name for the same group
/// can't dodge the list.
private let overBroadRunnerGroups: Set<String> = [
    "wheel", "staff", "everyone", "localaccounts", "netaccounts", "authedusers",
    "interactusers", "consoleusers", "admin", "com.apple.access_ssh",
]

enum GroupLookup: Equatable {
    case found(gid_t)
    case missing
    case failed(Int32)
}

/// A group's gid by name. `getgrnam_r`, not `getgrnam`: a library can't
/// know what its host's other threads are doing with the shared buffer.
func lookupGroupID(_ name: String) -> GroupLookup {
    var size = 16 * 1024
    while size <= 1024 * 1024 {
        var entry = group()
        var result: UnsafeMutablePointer<group>?
        var buffer = [CChar](repeating: 0, count: size)
        let rc = getgrnam_r(name, &entry, &buffer, size, &result)
        if rc == ERANGE {
            size *= 2 // a large directory group's member list didn't fit
            continue
        }
        guard rc == 0 else {
            return .failed(rc)
        }
        guard let found = result else {
            return .missing
        }
        return .found(found.pointee.gr_gid)
    }
    return .failed(ERANGE)
}

/// Whether root is a member of group `gid`, nested groups included. nil
/// when the directory can't say.
private func rootIsMember(ofGroup gid: gid_t) -> Bool? {
    var userUUID = [UInt8](repeating: 0, count: 16)
    var groupUUID = [UInt8](repeating: 0, count: 16)
    var member: Int32 = 0
    guard mbr_uid_to_uuid(0, &userUUID) == 0,
          mbr_gid_to_uuid(gid, &groupUUID) == 0,
          mbr_check_membership(&userUUID, &groupUUID, &member) == 0 else {
        return nil
    }
    return member != 0
}

enum RunnerGroupResolution: Equatable {
    case gid(gid_t)
    case refused(String)
}

/// The gid a KEK file for `name` is given, or why the group is refused: it
/// doesn't exist, it is an over-broad group under any name, or it is not a
/// dedicated one. Fails closed: a group that can't be looked up, or can't
/// be told apart from an over-broad one, is refused.
func resolveRunnerGroup(_ name: String) -> RunnerGroupResolution {
    let tooBroad = "RunnerGroup \(name) is too broad: name a group that holds only this service's accounts"
    guard !overBroadRunnerGroups.contains(name.lowercased()) else {
        return .refused(tooBroad)
    }
    let gid: gid_t
    switch lookupGroupID(name) {
    case .found(let found): gid = found
    case .missing: return .refused("RunnerGroup \(name) does not name a group on this Mac")
    case .failed(let code): return .refused("RunnerGroup \(name) could not be looked up (\(String(cString: strerror(code))))")
    }
    guard gid != 0 else {
        return .refused(tooBroad)
    }
    for broad in overBroadRunnerGroups.sorted() {
        switch lookupGroupID(broad) {
        case .found(gid): return .refused(tooBroad)
        case .found, .missing: break
        case .failed(let code):
            return .refused("RunnerGroup \(name) can't be confirmed not to be the over-broad group \(broad) (\(String(cString: strerror(code))))")
        }
    }
    // Root belongs to every system-wide group (staff, everyone, admin,
    // ...) and never needs a runner group to read the file, so a group it
    // is in -- directly, or because one of those is nested inside it --
    // is not a dedicated one.
    guard let rootIsIn = rootIsMember(ofGroup: gid) else {
        return .refused("RunnerGroup \(name)'s membership could not be checked")
    }
    guard !rootIsIn else {
        return .refused("RunnerGroup \(name) has root as a member, so it is not a dedicated group -- usually because a system-wide group (staff, admin, everyone, ...) is nested in it")
    }
    return .gid(gid)
}

/// Why a KEK file with this `mode` and `gid` is not the one `runnerGroup`
/// (the policy's, now) calls for, or nil if it is. Checked on every read,
/// so a group the policy no longer names does not go on being served.
func machineKeyFileGroupProblem(mode: mode_t, gid: gid_t, runnerGroup: String?, lookup: (String) -> GroupLookup = lookupGroupID) -> String? {
    guard let name = runnerGroup else {
        return mode & S_IRWXG == 0 ? nil : "has no RunnerGroup in the policy, but its group (gid \(gid)) can read it: `chmod 600` it"
    }
    guard !overBroadRunnerGroups.contains(name.lowercased()) else {
        return "belongs to a RunnerGroup (\(name)) that is too broad"
    }
    switch lookup(name) {
    case .found(let expected):
        guard expected != 0 else {
            return "belongs to a RunnerGroup (\(name)) that is too broad"
        }
        return gid == expected ? nil : "is group gid \(gid)'s, not the policy's RunnerGroup \(name) (gid \(expected)): `chgrp \(name)` it, and rotate the KEK if the old group should never have had it"
    case .missing:
        return "can't be matched to its RunnerGroup: \(name) does not name a group on this Mac"
    case .failed(let code):
        return "can't be matched to its RunnerGroup: \(name) could not be looked up (\(String(cString: strerror(code))))"
    }
}

/// Opens the machine KEK folder, creating it (root:wheel 0755) if it is
/// missing. Its parent must already exist -- the package installs it.
private func openMachineKeyFolderCreatingIt(service: String) -> Int32? {
    let url = URL(fileURLWithPath: machineKeyFolder())
    let parentFd = open(url.deletingLastPathComponent().path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    guard parentFd >= 0 else {
        logMachineRefusal(service, "\(url.deletingLastPathComponent().path) is missing: install the hkdfguard package")
        return nil
    }
    defer { close(parentFd) }
    let leaf = url.lastPathComponent
    let created = mkdirat(parentFd, leaf, 0o755) == 0
    guard created || errno == EEXIST else {
        logMachineRefusal(service, "\(url.path) can't be created (\(String(cString: strerror(errno))))")
        return nil
    }
    let fd = openat(parentFd, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard fd >= 0 else {
        return nil
    }
    if created && (fchown(fd, 0, 0) != 0 || fchmod(fd, 0o755) != 0) {
        close(fd)
        return nil
    }
    guard keyFileFoldersAreTrusted(folderFd: fd, rootOnly: true) else {
        logMachineRefusal(service, "\(url.path), or a folder above it, is not root's or can be written by others")
        close(fd)
        return nil
    }
    // On every provision, not just the first, so an existing folder is
    // excluded too. Not fatal: the KEK is no less usable for it.
    if !excludeFromBackup(url.path) {
        logMachineRefusal(service, "\(url.path) could not be excluded from Time Machine; a backup of it would let a retired KEK be restored")
    }
    return fd
}

/// Excludes the folder at `path` from Time Machine, so a retired machine
/// KEK can't come back from a backup. A sticky exclusion: it stays with the
/// folder if it moves. Backup tools that ignore it, and local APFS
/// snapshots, still keep copies; deleting the KEK file can't reach those.
func excludeFromBackup(_ path: String) -> Bool {
    var url = URL(fileURLWithPath: path, isDirectory: true)
    var values = URLResourceValues()
    values.isExcludedFromBackup = true
    return (try? url.setResourceValues(values)) != nil
}

private enum MachineKeyWrite {
    case written
    case alreadyExists // another provisioner won the race
    case failed
}

/// Writes the KEK file under a temporary name, owned root:`gid`, mode 0640
/// (0600 for root only), synced, then renames it into place -- only if no
/// file has that name yet, so an existing KEK is never replaced.
private func writeMachineKeyFile(_ bytes: Data, service: String, folderFd: Int32, gid: gid_t) -> MachineKeyWrite {
    let finalName = "\(service).kek"
    let tempName = ".\(service).\(UInt64.random(in: .min ... .max)).tmp"
    let fd = openat(folderFd, tempName, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
    guard fd >= 0 else {
        logMachineRefusal(service, "the machine KEK file can't be created (\(String(cString: strerror(errno))))")
        return .failed
    }
    var written = bytes.withUnsafeBytes { raw -> Bool in
        var offset = 0
        while offset < raw.count {
            let count = write(fd, raw.baseAddress?.advanced(by: offset), raw.count - offset)
            if count < 0 {
                if errno == EINTR {
                    continue
                }
                return false
            }
            offset += count
        }
        return true
    }
    let mode: mode_t = gid == 0 ? 0o600 : 0o640
    written = written && fchown(fd, 0, gid) == 0 && fchmod(fd, mode) == 0 && fsync(fd) == 0
    close(fd)
    guard written else {
        unlinkat(folderFd, tempName, 0)
        logMachineRefusal(service, "the machine KEK file can't be written")
        return .failed
    }
    if renameatx_np(folderFd, tempName, folderFd, finalName, UInt32(RENAME_EXCL)) != 0 {
        let code = errno
        unlinkat(folderFd, tempName, 0)
        return code == EEXIST ? .alreadyExists : .failed
    }
    _ = fsync(folderFd)
    return .written
}

/// Verifies an existing machine KEK, never replacing one: usable, the key
/// its file records, and of a suite `suites` permits.
private func verifyExistingMachineKEK(service: String, settings: MachineServiceSettings, suites: SuitePolicy) -> Int32 {
    switch readMachineKeyFile(service: service, settings: settings) {
    case .found(var file):
        defer { file.zeroBlobs() }
        guard case .key(let kek) = reconstructStoredKEK(file.stored, enclaveIsUsable: { true }),
              kek.fingerprint == file.fingerprint,
              kekWorks(kek) else {
            logMachineRefusal(service, "the existing machine KEK can't be used, or is not the key its file records; it was left untouched")
            return HKDFGuardStatus.kekCorrupted.rawValue
        }
        return suiteRefusal(kek, suites, service: service) ?? HKDFGuardStatus.success.rawValue
    case .notFound:
        return HKDFGuardStatus.kekNotFound.rawValue
    case .refused(let status, let reason):
        logMachineRefusal(service, reason)
        return status.rawValue
    }
}

/// Creates the machine KEK for `service` if it has none: root only, in
/// the system context only (the CLI's `provision` runs this as a one-off
/// LaunchDaemon job). Idempotent; an existing KEK is verified, never
/// replaced.
func createMachineKEK(service: String, settings: MachineServiceSettings, suites: SuitePolicy) -> Int32 {
    guard geteuid() == 0 else {
        logMachineRefusal(service, "only root can create a machine KEK")
        return HKDFGuardStatus.keychainAccessDenied.rawValue
    }
    guard runningInSystemContext() else {
        logMachineRefusal(service, "a machine KEK must be created by a LaunchDaemon (`sudo hkdfguard provision` does this for you); one created from Terminal would be unusable by the daemons it is for")
        return HKDFGuardStatus.keychainAccessDenied.rawValue
    }
    var gid: gid_t = 0
    if let name = settings.runnerGroup {
        switch resolveRunnerGroup(name) {
        case .gid(let resolved):
            gid = resolved
        case .refused(let reason):
            logMachineRefusal(service, reason)
            return HKDFGuardStatus.policyInvalid.rawValue
        }
    }

    let existing = verifyExistingMachineKEK(service: service, settings: settings, suites: suites)
    guard existing == HKDFGuardStatus.kekNotFound.rawValue else {
        return existing
    }

    guard let folderFd = openMachineKeyFolderCreatingIt(service: service) else {
        return HKDFGuardStatus.keychainWriteFailed.rawValue
    }
    defer { close(folderFd) }
    guard let access = makeMachineAccessControl() else {
        return HKDFGuardStatus.accessControlCreationFailed.rawValue
    }
    // A P-256 KEK is still written in format 1, which every release reads;
    // a suite 0x02 one needs format 3.
    var maybeEncoded: Data?
    switch suites.provisionSuite {
    case .p256HashedPoint:
        guard let key = try? SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access) else {
            return HKDFGuardStatus.keyGenerationFailed.rawValue
        }
        var blob = key.dataRepresentation
        defer { secureZero(&blob) }
        guard keyAgreementWorks(key),
              let reloaded = try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob),
              keyAgreementWorks(reloaded) else {
            return HKDFGuardStatus.kekVerificationFailed.rawValue
        }
        maybeEncoded = encodeMachineKeyFile(.v1(publicKey: key.publicKey.x963Representation, blob: blob))
    case .mlkem1024StoredCiphertext:
        let (createStatus, maybeCreated) = createMLKEMKEK(accessControl: access, service: service)
        guard var created = maybeCreated else {
            return createStatus
        }
        defer { created.stored.zeroBlobs() }
        guard kekWorks(.mlkem1024(created.kek)),
              case .key(let reloaded) = reconstructStoredKEK(created.stored, enclaveIsUsable: { true }),
              reloaded.fingerprint == created.kek.fingerprint,
              kekWorks(reloaded) else {
            return HKDFGuardStatus.kekVerificationFailed.rawValue
        }
        maybeEncoded = encodeMachineKeyFile(.v3(created.stored, fingerprint: created.kek.fingerprint))
    }
    guard var encoded = maybeEncoded else {
        return HKDFGuardStatus.unexpectedOutputLength.rawValue
    }
    defer { secureZero(&encoded) }
    switch writeMachineKeyFile(encoded, service: service, folderFd: folderFd, gid: gid) {
    case .written:
        auditMachineKekCreated(service: service, runnerGroup: settings.runnerGroup)
        return HKDFGuardStatus.success.rawValue
    case .alreadyExists:
        return verifyExistingMachineKEK(service: service, settings: settings, suites: suites)
    case .failed:
        return HKDFGuardStatus.keychainWriteFailed.rawValue
    }
}

/// The policy in effect, as JSON, for `hkdfguard_machine_policy`.
func machinePolicyJSON() -> Data? {
    var object: [String: Any] = [
        "machineKeyFolder": machineKeyFolder(),
        "systemContext": runningInSystemContext(),
    ]
    switch currentMachinePolicy() {
    case .none:
        object["mode"] = "development"
        object["kekSuite"] = SuitePolicy().provisionSuite.policyName
        object["requirePostQuantum"] = false
    case .invalid(let reason):
        object["mode"] = "invalid"
        object["reason"] = reason
    case .loaded(let policy):
        object["mode"] = "production"
        object["source"] = policy.source
        if let group = policy.securityAdminGroup {
            object["securityAdminGroup"] = group
        }
        if let group = policy.deploymentAdminGroup {
            object["deploymentAdminGroup"] = group
        }
        var services: [String: [String: String]] = [:]
        for (service, settings) in policy.machineServices {
            services[service] = settings.runnerGroup.map { ["runnerGroup": $0] } ?? [:]
        }
        object["machineServices"] = services
        object["kekSuite"] = policy.suites.provisionSuite.policyName
        object["requirePostQuantum"] = policy.suites.requirePostQuantum
    }
    return try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
}
