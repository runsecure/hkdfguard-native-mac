//
//  HkdfGuardKeyFile.swift
//  HkdfGuardNativeMacOS
//
//  hkdfguard_open_file, and the file and folder trust checks it shares
//  with the policy and machine KEK readers.
//

import Foundation
import Darwin.membership // mbr_uuid_to_id, mbr_check_membership: not re-exported by Foundation in every SDK

// MARK: - Read a wrapped payload from a file

/// Maps an `open(2)` failure to the status `hkdfguard_open_file` reports.
private func fileOpenStatus(errno code: Int32) -> HKDFGuardStatus {
    switch code {
    case ENOENT, ENOTDIR:
        return .fileNotFound
    case EACCES, EPERM:
        return .fileAccessDenied
    case ELOOP:
        // O_NOFOLLOW found a symbolic link as the final component (or the
        // path loops through links): a link is refused as untrusted, as the
        // Windows build refuses any reparse point -- not as an I/O failure.
        return .fileInsecure
    default:
        // Including EOPNOTSUPP (the path names a socket): HKDFGUARD_ERR_FILE_IO
        // covers "not a regular file" and "could not be read" alike.
        return .fileIO
    }
}

/// Whether the key file's folder, open as `folderFd`, and every folder above
/// it up to `/` are ones nobody untrusted can rename, replace or
/// delete entries in: a directory owned by root or this process's
/// effective user, and not writable by group or others. The sticky bit
/// (`/tmp`-style) excuses that for the folders *above* the key's own: there
/// the kernel lets only an entry's owner, or the folder's, rename or remove
/// it, so nobody else can swap out the subtree the key is in. It does not
/// excuse the key's own folder, because sticky stops nobody *adding* an
/// entry, and macOS lets any user hard-link a file they don't own: whenever
/// the key's name is free, someone else could link an older payload -- still
/// owned by this user or root, so passing every check on the file -- to that
/// name. (Its link count can't tell: they can drop their other name for it
/// afterwards.) Write bits are ignored on the sealed system volume.
///
/// The folder is the one the path names the file in, opened by
/// `readWrappedFile` before the file, which is then opened *within* it
/// (`openat`): so the file read is that folder's entry, whatever other
/// names (hard links) it has elsewhere, and the folder checked is where it
/// was found. (Working back from
/// the open file instead, with F_GETPATH, fails for a hard-linked file:
/// macOS reports whichever of its names was looked up last.)
/// Folders that symlinks inside the path live in are not walked: someone
/// able to retarget one could at most send the path to a different file
/// that itself passes every check here.
///
/// A folder writable by the `admin` group (`/Applications`, say) fails.
/// Every administrator could replace the key there without root.
///
/// `rootOnly` (the policy file's and machine keys' folders): every folder
/// must be root's, not this user's, and no group or other write bit is
/// excused by the sticky bit either.
func keyFileFoldersAreTrusted(folderFd: Int32, rootOnly: Bool = false) -> Bool {
    // Walked by descriptor, from the key file's own folder up through
    // openat(fd, "..") until a folder is its own parent (/): no path string
    // is decoded, split or looked up again, so neither an odd folder name
    // (one starting with a combining mark fuses with the "/" before it in a
    // Swift String, and its parent would be skipped) nor a folder renamed
    // mid-walk can make a folder be skipped or judged in its stead.
    var current = dup(folderFd)
    guard current >= 0 else {
        return false
    }
    defer { close(current) }

    let uid = geteuid()
    var isKeyFolder = true
    for _ in 0..<Int(MAXPATHLEN) { // a path has at most this many folders
        var info = stat()
        guard fstat(current, &info) == 0,
              info.st_mode & S_IFMT == S_IFDIR,
              info.st_uid == 0 || (!rootOnly && info.st_uid == uid),
              !onVolumeIgnoringOwnership(current),
              !aclGrantsOthersAChange(fd: current, isFolder: true, rootOnly: rootOnly) else {
            return false
        }
        let writable = info.st_mode & (S_IWGRP | S_IWOTH) != 0
        let sticky = info.st_mode & S_ISVTX != 0
        if writable && (rootOnly || !sticky || isKeyFolder) && !onSealedSystemVolume(current) {
            return false
        }
        isKeyFolder = false

        let parent = openat(current, "..", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard parent >= 0 else {
            return false
        }
        var parentInfo = stat()
        guard fstat(parent, &parentInfo) == 0 else {
            close(parent)
            return false
        }
        if parentInfo.st_dev == info.st_dev && parentInfo.st_ino == info.st_ino {
            close(parent) // "/" is its own parent: the whole chain passed
            return true
        }
        close(current)
        current = parent
    }
    return false
}

/// Whether `fd` is on a volume mounted with ownership ignored (the default
/// for disk images and removable media a user mounts). There the kernel
/// reports every file and folder as owned by whoever asks, so the owner
/// checks above would pass for anything on it, whoever wrote it.
func onVolumeIgnoringOwnership(_ fd: Int32) -> Bool {
    var fs = statfs()
    guard fstatfs(fd, &fs) == 0 else {
        return true // can't tell: treat as untrusted
    }
    return fs.f_flags & UInt32(MNT_IGNORE_OWNERSHIP) != 0
}

/// Whether `fd` is on the sealed, read-only system volume, the one place
/// write bits on a folder can be ignored: nothing on it can change. Any
/// other read-only volume -- a disk image someone built and mounted, say --
/// gets no exemption, since whoever built it chose its contents.
private func onSealedSystemVolume(_ fd: Int32) -> Bool {
    var fs = statfs()
    guard fstatfs(fd, &fs) == 0 else {
        return false
    }
    let required = UInt32(MNT_RDONLY) | UInt32(MNT_ROOTFS)
    return fs.f_flags & required == required
}

/// Whether the access control list on `fd` grants anyone other than root or
/// this user a right that could change what the key path reads. Mode bits
/// alone miss this: on macOS an ACL can grant write to anyone regardless of
/// a 0600 or 0755 mode.
///
/// For a file: writing or appending its data, deleting it, or changing its
/// permissions, owner, ACL or attributes. For a folder: adding, removing or
/// renaming entries (add_file, add_subdirectory, delete_child), and changing
/// its permissions, owner or ACL. Deny entries only take rights away, so
/// only allow entries count -- the standard "everyone deny delete" on home
/// folders passes. Entries for root or this user are harmless. An ACL that
/// can't be read, or an entry whose principal can't be resolved, counts as
/// granting (fail closed).
///
/// `rootOnly`: an entry for this user counts as granting too -- for files
/// only root may control (the policy, machine keys), whoever reads them.
func aclGrantsOthersAChange(fd: Int32, isFolder: Bool, rootOnly: Bool = false) -> Bool {
    guard let acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED) else {
        return errno != ENOENT // no ACL at all; any other failure fails closed
    }
    defer { acl_free(UnsafeMutableRawPointer(acl)) }

    let risky: [acl_perm_t] = isFolder
        ? [ACL_ADD_FILE, ACL_ADD_SUBDIRECTORY, ACL_DELETE_CHILD, ACL_DELETE,
           ACL_WRITE_SECURITY, ACL_CHANGE_OWNER]
        : [ACL_WRITE_DATA, ACL_APPEND_DATA, ACL_DELETE, ACL_WRITE_ATTRIBUTES,
           ACL_WRITE_EXTATTRIBUTES, ACL_WRITE_SECURITY, ACL_CHANGE_OWNER]
    let uid = geteuid()

    var entry: acl_entry_t?
    var which = ACL_FIRST_ENTRY.rawValue
    while acl_get_entry(acl, Int32(which), &entry) == 0, let current = entry {
        which = ACL_NEXT_ENTRY.rawValue
        var tag = ACL_UNDEFINED_TAG
        guard acl_get_tag_type(current, &tag) == 0 else {
            return true
        }
        guard tag == ACL_EXTENDED_ALLOW else {
            continue // deny entries can only take rights away
        }
        var permset: acl_permset_t?
        guard acl_get_permset(current, &permset) == 0, let perms = permset else {
            return true
        }
        guard risky.contains(where: { acl_get_perm_np(perms, $0) == 1 }) else {
            continue // grants only reading or listing
        }
        // Who is granted it: harmless if root or this user, else refuse.
        guard let qualifier = acl_get_qualifier(current) else {
            return true
        }
        defer { acl_free(qualifier) }
        var id: id_t = 0
        var type: Int32 = 0
        let resolved = qualifier.withMemoryRebound(to: UInt8.self, capacity: 16) {
            mbr_uuid_to_id($0, &id, &type) == 0
        }
        guard resolved, type == ID_TYPE_UID, id == 0 || (!rootOnly && id == uid) else {
            return true
        }
    }
    return false
}

/// Reads at most `buffer.count` bytes of the regular file at `path` into
/// `buffer`, returning how many were read. A file whose size already
/// exceeds a wrapped payload is rejected from `fstat` alone, before any
/// read. The caller zeroes `buffer`, which may end up holding a plaintext
/// DEK.
private func readWrappedFile(
    path: UnsafePointer<CChar>,
    length: Int, // the path's length, already bounded by openFileCore
    into buffer: inout [UInt8]
) -> (status: HKDFGuardStatus, count: Int) {
    // The path is split, as bytes, into the folder it names and its last
    // component. The folder is opened first and the file then opened within
    // it (openat), so the file read is exactly that folder's entry and the
    // folder is the one checked below -- never inferred back from the file,
    // which a hard link makes ambiguous (see keyFileFoldersAreTrusted).
    var lastSlash = -1
    for i in 0..<length where path[i] == 0x2F { // '/'
        lastSlash = i
    }
    guard lastSlash + 1 < length else {
        return (.fileIO, 0) // ends in '/': names a folder, not a file
    }
    let folderPath: [CChar] = lastSlash < 0
        ? [0x2E, 0] // "." -- a bare file name is in the current folder
        : lastSlash == 0 ? [0x2F, 0] : Array(UnsafeBufferPointer(start: path, count: lastSlash)) + [0]

    // Symlinks in the folder part resolve as usual, so /etc and /tmp --
    // themselves symlinks into /private -- work.
    var folderFd: Int32
    repeat {
        folderFd = open(folderPath, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    } while folderFd < 0 && errno == EINTR
    guard folderFd >= 0 else {
        return (fileOpenStatus(errno: errno), 0)
    }
    defer { close(folderFd) }

    // O_NOFOLLOW: a symlink as the final component is refused, not followed.
    // O_NONBLOCK: a FIFO with no writer would otherwise block here; it has
    // no effect on the regular files actually accepted. O_CLOEXEC: never
    // inherited by a child.
    var fd: Int32
    repeat {
        fd = openat(folderFd, path + lastSlash + 1, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
    } while fd < 0 && errno == EINTR
    guard fd >= 0 else {
        return (fileOpenStatus(errno: errno), 0)
    }
    defer { close(fd) }

    // Everything below is judged on the open descriptor, so it describes the
    // file that will be read, not whatever the path names by now.
    var info = stat()
    guard fstat(fd, &info) == 0 else {
        return (.fileIO, 0)
    }
    guard info.st_mode & S_IFMT == S_IFREG else {
        return (.fileIO, 0)
    }
    // Same rules the CLI's `wrap` writes to (0600) and the install scripts
    // apply to the library itself: nobody but the owner can have put these
    // bytes here, and the owner is either this user or root (an admin- or
    // MDM-deployed file; root can alter anything anyway).
    //
    // A file with more than one hard link is accepted.
    // Another name for the file only matters if someone could use
    // it to put an older payload where the service looks -- and that takes
    // creating an entry in the key's own folder: the folder the file was
    // just opened within, which `keyFileFoldersAreTrusted` below limits to
    // the owner and root (it refuses that folder if group or others can
    // write it, sticky or not).
    guard info.st_uid == geteuid() || info.st_uid == 0,
          info.st_mode & (S_IWGRP | S_IWOTH) == 0,
          // On a volume ignoring ownership, st_uid above is whoever asked.
          !onVolumeIgnoringOwnership(fd),
          // Nor may an ACL let anyone else rewrite, replace or re-permission it.
          !aclGrantsOthersAChange(fd: fd, isFolder: false) else {
        return (.fileInsecure, 0)
    }
    // And the folders that decide what the path names, as on Linux --
    // otherwise someone else could rename a file of their choosing over the
    // key, and the checks above would pass on whatever they put there.
    guard keyFileFoldersAreTrusted(folderFd: folderFd) else {
        return (.fileInsecure, 0)
    }
    // Exactly a DEK's size: a plaintext key, refused from its size alone,
    // never read into this process -- as on Linux (key_file.rs). A 32-byte
    // file rewritten mid-call is still caught on its contents below.
    guard info.st_size != off_t(hkdfguardDekLength) else {
        return (.fileUnprotectedKey, 0)
    }
    guard info.st_size <= off_t(hkdfguardWrappedLength) else {
        return (.fileTooLong, 0)
    }

    // Read until EOF or the buffer is full, whatever fstat said: the file
    // may change between the two, and the bytes actually read decide.
    var count = 0
    let status: HKDFGuardStatus = buffer.withUnsafeMutableBytes { raw in
        guard let base = raw.baseAddress else {
            return .unexpectedOutputLength
        }
        while count < raw.count {
            let n = read(fd, base + count, raw.count - count)
            let readErrno = errno // captured before anything else can run
            if n > 0 {
                count += n
            } else if n == 0 {
                return .success
            } else if readErrno != EINTR {
                return .fileIO
            }
        }
        return .success
    }
    return (status, status == .success ? count : 0)
}

/// Longest text form of a DEK recognised, surrounding whitespace included.
/// Every length up to it is below a payload's,
/// so no payload can be mistaken for a plaintext key.
private let hkdfguardMaxPlaintextTextLength = 96

// Branch-free byte classification for `looksLikePlaintextDek`. Every helper
// returns 0 or 1 and is straight-line arithmetic on UInt32 (`&-`, `&+`:
// wrapping, never trapping), with no data-dependent branch or table lookup.

/// 1 if a == b, else 0 (inputs below 2^31).
@inline(__always) private func ctEq(_ a: UInt32, _ b: UInt32) -> UInt32 {
    ((a ^ b) &- 1) >> 31
}

/// 1 if lo <= c <= hi, else 0 (inputs below 2^31): both differences wrap
/// negative exactly when c is inside.
@inline(__always) private func ctInRange(_ c: UInt32, _ lo: UInt32, _ hi: UInt32) -> UInt32 {
    (((lo &- 1) &- c) & (c &- (hi &+ 1))) >> 31 & 1
}

/// a if cond is 1, b if it is 0.
@inline(__always) private func ctSelect(_ cond: UInt32, _ a: UInt32, _ b: UInt32) -> UInt32 {
    b ^ ((a ^ b) & (0 &- cond))
}

/// What trim_ascii removes: space, tab, LF, form feed, CR.
@inline(__always) private func ctIsWhitespace(_ c: UInt32) -> UInt32 {
    ctEq(c, 0x20) | ctEq(c, 0x09) | ctEq(c, 0x0A) | ctEq(c, 0x0C) | ctEq(c, 0x0D)
}

@inline(__always) private func ctIsHex(_ c: UInt32) -> UInt32 {
    ctInRange(c, 0x30, 0x39) | ctInRange(c, 0x61, 0x66) | ctInRange(c, 0x41, 0x46) // 0-9 a-f A-F
}

/// (member, 6-bit value) of `c` in the base64 alphabet whose 62nd and 63rd
/// characters are `c62` and `c63`.
@inline(__always) private func ctBase64(_ c: UInt32, _ c62: UInt32, _ c63: UInt32) -> (member: UInt32, value: UInt32) {
    let upper = ctInRange(c, 0x41, 0x5A) // A-Z
    let lower = ctInRange(c, 0x61, 0x7A) // a-z
    let digit = ctInRange(c, 0x30, 0x39) // 0-9
    let s62 = ctEq(c, c62)
    let s63 = ctEq(c, c63)
    // One typed term per class: as a single expression of untyped literals,
    // this is more than older Swift 6.2 type checkers (Xcode 26.3) finish.
    let upperValue: UInt32 = (c &- 0x41) & (0 &- upper)
    let lowerValue: UInt32 = (c &- (0x61 - 26)) & (0 &- lower)
    let digitValue: UInt32 = (c &+ (52 - 0x30)) & (0 &- digit)
    let s62Value: UInt32 = 62 & (0 &- s62)
    let s63Value: UInt32 = 63 & (0 &- s63)
    let value = upperValue | lowerValue | digitValue | s62Value | s63Value
    return (upper | lower | digit | s62 | s63, value)
}

/// True when `bytes` look like a bare 32-byte DEK rather than a wrapped
/// payload: exactly 32 raw bytes, or -- with any surrounding whitespace an
/// editor or `echo` adds -- the 64-digit hex (either case) or base64
/// (standard or URL-safe, with or without its one `=` of padding) of 32
/// bytes. The same set the Linux and Windows builds recognise: base64 is
/// 43 characters, or 44 ending in `=`, all in one alphabet, whose last
/// character's 2 unused bits are zero.
///
/// Constant-time in the contents: the only
/// branches are on the length, which the file's size already gives away.
/// Every byte is visited twice (once to find the text between the
/// surrounding whitespace, once to test it against all three alphabets at
/// once) and every decision is mask arithmetic, so how long this takes says
/// nothing about where in a would-be key the first non-matching byte sits.
/// Nothing is decoded, so the key is never reassembled.
func looksLikePlaintextDek(_ bytes: ArraySlice<UInt8>) -> Bool { // internal: tested directly
    if bytes.count == hkdfguardDekLength {
        return true
    }
    if bytes.count > hkdfguardMaxPlaintextTextLength {
        return false
    }
    let base = bytes.startIndex

    // Pass 1: the first and last non-whitespace positions.
    var seen: UInt32 = 0, start: UInt32 = 0, end: UInt32 = 0
    for offset in 0..<bytes.count {
        let i = UInt32(offset)
        let text = ctIsWhitespace(UInt32(bytes[base + offset])) ^ 1
        start = ctSelect(text & (seen ^ 1), i, start)
        end = ctSelect(text, i, end)
        seen |= text
    }
    let textLength = ((end &- start) &+ 1) & (0 &- seen)

    // Pass 2: every byte between them against every alphabet, plus the
    // values of the last two (the last may be the `=` of padding).
    var hexOK: UInt32 = 1, stdOK: UInt32 = 1, urlOK: UInt32 = 1, padded: UInt32 = 0
    var stdLast: UInt32 = 0, stdPrev: UInt32 = 0, urlLast: UInt32 = 0, urlPrev: UInt32 = 0
    for offset in 0..<bytes.count {
        let i = UInt32(offset)
        let c = UInt32(bytes[base + offset])
        let outside = (ctInRange(i, start, end) & seen) ^ 1
        let isEnd = ctEq(i, end)
        let isPrev = ctEq(i &+ 1, end)
        let pad = isEnd & ctEq(c, 0x3D) // '='
        let std = ctBase64(c, 0x2B, 0x2F) // + /
        let url = ctBase64(c, 0x2D, 0x5F) // - _
        hexOK &= ctIsHex(c) | outside
        stdOK &= std.member | pad | outside
        urlOK &= url.member | pad | outside
        padded |= pad
        stdLast = ctSelect(isEnd, std.value, stdLast)
        stdPrev = ctSelect(isPrev, std.value, stdPrev)
        urlLast = ctSelect(isEnd, url.value, urlLast)
        urlPrev = ctSelect(isPrev, url.value, urlPrev)
    }

    // 43 data characters carry 258 bits: the last one's low 2 must be 0.
    let shape = (ctEq(textLength, 43) & (padded ^ 1)) | (ctEq(textLength, 44) & padded)
    let stdCanonical = ctEq(ctSelect(padded, stdPrev, stdLast) & 3, 0)
    let urlCanonical = ctEq(ctSelect(padded, urlPrev, urlLast) & 3, 0)
    let hex = hexOK & ctEq(textLength, UInt32(hkdfguardDekLength * 2))
    let base64 = shape & ((stdOK & stdCanonical) | (urlOK & urlCanonical))
    return seen & (hex | base64) == 1
}

/// Reads the wrapped payload stored at `path` — the 125-byte file the CLI's
/// `wrap` writes — validates it, and copies it to `out`, ready for
/// `hkdfguard_unwrap_dek`. Never touches the keychain or the Secure
/// Enclave, and never unwraps anything.
///
/// `*outLen` is the capacity on entry. It is written only with 125: on
/// success, and on `outputBufferTooSmall` (the required size, reported
/// before the file is opened). Every other failure leaves it as the caller
/// set it, as on Linux and as wrap and unwrap do. File contents are
/// copied to `out` only on success, so a rejected file — in particular one
/// holding a plaintext DEK — never reaches the caller's buffer; on any
/// failure every byte of the declared capacity is zeroed instead, as on
/// Linux (see `zeroingOutOnFailure`).
@_cdecl("hkdfguard_open_file")
public func hkdfguard_open_file(
    pathPtr: UnsafePointer<CChar>?,
    outPtr: UnsafeMutablePointer<UInt8>?,
    outLen: UnsafeMutablePointer<Int32>?
) -> Int32 {
    let status = zeroingOutOnFailure(outPtr, outLen) {
        openFileCore(pathPtr: pathPtr, outPtr: outPtr, outLen: outLen)
    }
    if status == HKDFGuardStatus.fileUnprotectedKey.rawValue, let pathPtr {
        let length = strnlen(pathPtr, Int(PATH_MAX))
        auditPlaintextKeyFile(path: pathPtr.withMemoryRebound(to: UInt8.self, capacity: length) { Array(UnsafeBufferPointer(start: $0, count: length)) })
    }
    return status
}

private func openFileCore(
    pathPtr: UnsafePointer<CChar>?,
    outPtr: UnsafeMutablePointer<UInt8>?,
    outLen: UnsafeMutablePointer<Int32>?
) -> Int32 {
    // Argument checks, before the file is
    // opened. As on Linux (and as wrap and unwrap do), `*out_len` is written
    // only on success (125) and on buffer-too-small (the size to retry
    // with); every other failure leaves it as the caller set it.
    guard let outLen else {
        return HKDFGuardStatus.invalidInputLength.rawValue
    }
    let capacity = outLen.pointee
    guard capacity >= 0 else {
        return HKDFGuardStatus.invalidInputLength.rawValue
    }
    guard let pathPtr, pathPtr.pointee != 0 else {
        return HKDFGuardStatus.invalidInputLength.rawValue
    }
    // The terminator is looked for in at most PATH_MAX bytes, as on Linux
    // (cstr_to_path): no NUL in that range -- an unterminated buffer, or a
    // path no open could take -- is an argument error, and nothing past it
    // is ever read.
    let pathLength = strnlen(pathPtr, Int(PATH_MAX))
    guard pathLength < Int(PATH_MAX) else {
        return HKDFGuardStatus.invalidInputLength.rawValue
    }
    // Too small for a payload -- including the 0 of a size probe, which may
    // pass a NULL `out`: answered without opening the file.
    guard Int(capacity) >= hkdfguardWrappedLength else {
        outLen.pointee = Int32(hkdfguardWrappedLength)
        return HKDFGuardStatus.outputBufferTooSmall.rawValue
    }
    guard let outPtr else {
        return HKDFGuardStatus.invalidInputLength.rawValue // a declared capacity with nowhere to write
    }

    // One byte more than a payload, so a file that grew past the fstat
    // check is still seen as too long without reading the rest of it. Zeroed
    // on every exit: a rejected file may have been a plaintext key.
    var buffer = [UInt8](repeating: 0, count: hkdfguardWrappedLength + 1)
    defer { secureZero(&buffer) }

    let (readStatus, count) = readWrappedFile(path: pathPtr, length: pathLength, into: &buffer)
    guard readStatus == .success else {
        return readStatus.rawValue
    }

    guard count <= hkdfguardWrappedLength else {
        return HKDFGuardStatus.fileTooLong.rawValue
    }
    guard count == hkdfguardWrappedLength else {
        // A plaintext DEK is always shorter than a payload; naming it
        // matters more than "too short", because the key is now exposed.
        return looksLikePlaintextDek(buffer[0..<count])
            ? HKDFGuardStatus.fileUnprotectedKey.rawValue
            : HKDFGuardStatus.fileTooShort.rawValue
    }

    // Structural checks only -- authenticity is the AEAD's job at unwrap.
    // A SHA-256 fingerprint of all zeros does not occur in practice (checked
    // first), and the suite byte must be one this build implements. Either
    // failure is `fileMalformed`, report every format
    // problem in a key file; unwrap, given the same bytes, still names an
    // unknown suite specifically (-12). The salt, nonce and ciphertext are
    // random-looking by design; nothing more can be checked without the KEK.
    let fingerprint = buffer[0..<hkdfguardFingerprintLength]
    guard fingerprint.contains(where: { $0 != 0 }) else {
        return HKDFGuardStatus.fileMalformed.rawValue
    }
    guard KEKSuite(rawValue: buffer[hkdfguardSuiteIdOffset]) != nil else {
        return HKDFGuardStatus.fileMalformed.rawValue
    }

    guard copyOut(buffer, to: outPtr, count: hkdfguardWrappedLength) else {
        return HKDFGuardStatus.unexpectedOutputLength.rawValue
    }
    outLen.pointee = Int32(hkdfguardWrappedLength)
    return HKDFGuardStatus.success.rawValue
}
