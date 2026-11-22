//
//  OpenFile.swift -- fuzz target `open_file`
//
//  hkdfguard_open_file on arbitrary file contents under every mode a key
//  file might have, on arbitrary paths, and on the things a path can name
//  that are not a key file: a symbolic link, a hard link, a folder, a FIFO,
//  nothing.
//
//  Beyond "no crash": the status is the one hkdfguard.h gives for the
//  file's mode and bytes, judged here by an independent restatement of the
//  rules (the library's constant-time plaintext-key test against the
//  obvious one, among them); what comes back on success is the file's own
//  bytes; a refused file's bytes never reach the caller's buffer, which is
//  zeroed; a file group or others can write is refused; a symbolic link is
//  refused, never followed.
//

import Foundation

private let modes: [mode_t] = [
    0o600, // what the CLI's `wrap` writes
    0o400,
    0o640, // group read is allowed: the file is ciphertext
    0o644, // so is everyone's
    0o700,
    0o660, // group write: refused
    0o606, // others' write: refused
    0o666,
    0o200, // unreadable by its owner
    0o000,
]

private enum Special: Int, CaseIterable {
    case symlink, hardLink, folder, trailingSlash, fifo, missing, missingFolder, fileAsFolder, symlinkedFolder, relative
}

private enum Subject {
    /// A file of these bytes, in the fuzz directory.
    case content(bytes: [UInt8], mode: Int, genuinePrefix: Bool)
    /// Whatever path these bytes name.
    case path([UInt8])
    /// A genuine key file, reached some other way than by its own name.
    case special(Special)
    case nullPath

    static func decode(_ input: inout FuzzInput) -> Subject {
        switch input.choice(4) {
        case 0:
            let mode = input.choice(modes.count)
            let genuinePrefix = input.bool()
            return .content(bytes: input.blob(max: 400), mode: mode, genuinePrefix: genuinePrefix)
        case 1: return .path(input.blob(max: 1200))
        case 2: return .special(Special(rawValue: input.choice(Special.allCases.count)) ?? .symlink)
        default: return .nullPath
        }
    }

    func encode(_ seed: Seed) {
        switch self {
        case .content(let bytes, let mode, let genuinePrefix): seed.choice(0).choice(mode).bool(genuinePrefix).blob(bytes)
        case .path(let bytes): seed.choice(1).blob(bytes)
        case .special(let special): seed.choice(2).choice(special.rawValue)
        case .nullPath: seed.choice(3)
        }
    }
}

/// What the argument checks answer before the file is opened; nil when
/// they pass. `pathLength`: up to the first NUL; nil for a NULL path.
private func expectedBeforeOpening(pathLength: Int?, call: Call) -> Int32? {
    if call.outLenNull || call.cap < 0 { return INVALID_ARGUMENT }
    guard let pathLength, pathLength > 0, pathLength < Int(PATH_MAX) else { return INVALID_ARGUMENT }
    if call.cap < WRAPPED_LEN { return BUFFER_TOO_SMALL }
    if call.outNull { return INVALID_ARGUMENT }
    return nil
}

private func checkOpen(_ ret: Ret, _ call: Call, expected: Int32, content: [UInt8]?, _ what: String) {
    checkContract(ret, call, .zeroed, "open_file (\(what))")
    check(ret.rc == expected, "open_file (\(what)) returned \(statusName(ret.rc)), expected \(statusName(expected)) (call \(call))")
    if ret.rc == OK {
        check(ret.outLen == Int32(WRAPPED_LEN), "open_file: OK with *out_len \(String(describing: ret.outLen))")
        check(content == nil || ret.written == content, "open_file (\(what)) returned bytes that are not the file's")
        check(ret.buffer[WRAPPED_LEN...].allSatisfy { $0 == FILL }, "open_file wrote past the payload")
    } else if ret.rc == BUFFER_TOO_SMALL {
        check(ret.outLen == Int32(WRAPPED_LEN), "open_file: BUFFER_TOO_SMALL must report \(WRAPPED_LEN)")
    }
}

let openFileTarget = FuzzTarget(name: "open_file", run: { data in
    setup()
    var input = FuzzInput(data)
    let subject = Subject.decode(&input)
    let call = Call.decode(&input)
    let isRoot = geteuid() == 0
    let keyPath = fuzzDirectory + "/key.bin"

    switch subject {
    case .content(let bytes, let modeIndex, let genuinePrefix):
        let content = (genuinePrefix ? genuinePayload : []) + bytes
        let mode = modes[modeIndex]
        writeFile(keyPath, content, mode: mode)

        // The library's plaintext-key test and the obvious one must agree
        // on every file shorter than a payload.
        if content.count < WRAPPED_LEN {
            check(looksLikePlaintextDek(content[...]) == looksLikePlaintextKey(content),
                  "looksLikePlaintextDek disagrees with the plain restatement on \(content.count) bytes: \(content)")
        }

        var expected = expectedBeforeOpening(pathLength: keyPath.utf8.count, call: call)
        if expected == nil {
            if mode & 0o400 == 0 && !isRoot {
                expected = FILE_ACCESS_DENIED
            } else if mode & 0o022 != 0 {
                expected = FILE_UNTRUSTED
            } else {
                expected = expectedKeyFileStatus(content)
            }
        }
        let ret = openFile(path: keyPath, call)
        checkOpen(ret, call, expected: expected ?? OK, content: content, "\(content.count) bytes, mode \(String(mode, radix: 8))")
        // What the file opens as, unwrap agrees is a payload of a known
        // suite: the two never disagree about the format.
        if ret.rc == OK {
            let back = unwrap(.fuzz, ret.written, .dek)
            check(back.rc != PAYLOAD_MALFORMED && back.rc != PAYLOAD_UNSUPPORTED,
                  "open_file accepted bytes unwrap_dek calls \(statusName(back.rc))")
        }

    case .path(let bytes):
        let path = Array(bytes.prefix { $0 != 0 })
        let ret = openFile(path: path, call)
        checkContract(ret, call, .zeroed, "open_file (arbitrary path)")
        if let expected = expectedBeforeOpening(pathLength: path.count, call: call) {
            check(ret.rc == expected, "open_file (arbitrary path of \(path.count) bytes) returned \(statusName(ret.rc)), expected \(statusName(expected))")
        } else if ret.rc == OK {
            // Some real key file on this Mac: then those are its bytes, and
            // they are a payload.
            let onDisk = readFile(path)
            check(onDisk == ret.written && expectedKeyFileStatus(ret.written) == OK,
                  "open_file accepted \(String(decoding: path, as: UTF8.self)), which does not hold what it returned")
        }

    case .nullPath:
        let ret = openFile(path: nil, call)
        checkOpen(ret, call, expected: INVALID_ARGUMENT, content: nil, "NULL path")

    case .special(let special):
        writeFile(keyPath, genuinePayload, mode: 0o600)
        let other = fuzzDirectory + "/other"
        removeTree(other)
        let path: String
        var expected: Int32
        switch special {
        case .symlink:
            check(symlink(keyPath, other) == 0, "harness: symlink")
            (path, expected) = (other, FILE_UNTRUSTED)
        case .hardLink:
            check(link(keyPath, other) == 0, "harness: link")
            (path, expected) = (other, OK)
        case .folder:
            check(mkdir(other, 0o700) == 0, "harness: mkdir")
            (path, expected) = (other, FILE_IO)
        case .trailingSlash:
            (path, expected) = (keyPath + "/", FILE_IO)
        case .fifo:
            check(mkfifo(other, 0o600) == 0, "harness: mkfifo")
            (path, expected) = (other, FILE_IO)
        case .missing:
            (path, expected) = (other, FILE_NOT_FOUND)
        case .missingFolder:
            (path, expected) = (other + "/key.bin", FILE_NOT_FOUND)
        case .fileAsFolder:
            (path, expected) = (keyPath + "/key.bin", FILE_NOT_FOUND)
        case .symlinkedFolder:
            // A link to a folder partway along the path is followed.
            check(symlink(fuzzDirectory, other) == 0, "harness: symlink")
            (path, expected) = (other + "/key.bin", OK)
        case .relative:
            // "." is the folder of a bare name.
            check(chdir(fuzzDirectory) == 0, "harness: chdir")
            (path, expected) = ("key.bin", OK)
        }
        if let earlier = expectedBeforeOpening(pathLength: path.utf8.count, call: call) {
            expected = earlier
        }
        let ret = openFile(path: path, call)
        checkOpen(ret, call, expected: expected, content: genuinePayload, "\(special)")
        removeTree(other)
    }
}, seeds: {
    var seeds: [NamedSeed] = []
    func add(_ name: String, _ subject: Subject, _ call: Call = .full) {
        seeds.append(NamedSeed(name) { seed in
            subject.encode(seed)
            call.encode(seed)
        })
    }
    for (index, mode) in modes.enumerated() {
        add("genuine-mode-\(String(mode, radix: 8))", .content(bytes: [], mode: index, genuinePrefix: true))
    }
    for cap in [125, 124, 126, 0, 1, -1, Int(Int16.min), Int(Int16.max)] {
        add("genuine-cap-\(cap)", .content(bytes: [], mode: 0, genuinePrefix: true), Call(cap: Int16(cap)))
        add("genuine-cap-\(cap)-out-null", .content(bytes: [], mode: 0, genuinePrefix: true), Call(cap: Int16(cap), outNull: true))
        add("plaintext-cap-\(cap)", .content(bytes: knownDek, mode: 0, genuinePrefix: false), Call(cap: Int16(cap)))
    }
    add("genuine-out-len-null", .content(bytes: [], mode: 0, genuinePrefix: true), Call(cap: 125, outLenNull: true))
    for extra in [1, 2, 200] {
        add("genuine-then-\(extra)", .content(bytes: [UInt8](repeating: 7, count: extra), mode: 0, genuinePrefix: true))
    }
    for length in [0, 1, 31, 32, 33, 43, 44, 45, 63, 64, 65, 96, 97, 124, 125, 126, 400] {
        add("zeros-\(length)", .content(bytes: [UInt8](repeating: 0, count: length), mode: 0, genuinePrefix: false))
        add("ones-\(length)", .content(bytes: [UInt8](repeating: 0xFF, count: length), mode: 0, genuinePrefix: false))
        add("letters-\(length)", .content(bytes: [UInt8](repeating: 0x41, count: length), mode: 0, genuinePrefix: false))
    }
    // Plaintext keys, as an editor or `echo` leaves them.
    let hex = Array(knownDek.map { String(format: "%02x", $0) }.joined().utf8)
    let base64 = Array(Data(knownDek).base64EncodedString().utf8)
    let urlSafe = base64.map { $0 == 0x2B ? 0x2D : $0 == 0x2F ? 0x5F : $0 }
    let texts: [(String, [UInt8])] = [
        ("hex", hex), ("hex-upper", Array(String(decoding: hex, as: UTF8.self).uppercased().utf8)),
        ("hex-newline", hex + [0x0A]), ("hex-crlf", hex + [0x0D, 0x0A]), ("hex-padded", [0x20, 0x09] + hex + [0x0A, 0x0A]),
        ("hex-63", Array(hex.dropLast())), ("hex-65", hex + [0x30]), ("hex-with-g", Array(hex.dropLast()) + [0x67]),
        ("hex-space-inside", Array(hex.prefix(32)) + [0x20] + Array(hex.dropFirst(33))),
        ("hex-in-96", [UInt8](repeating: 0x20, count: 32) + hex), ("hex-in-97", [UInt8](repeating: 0x20, count: 33) + hex),
        ("base64", base64), ("base64-newline", base64 + [0x0A]), ("base64-unpadded", Array(base64.dropLast())),
        ("base64-url", urlSafe), ("base64-url-unpadded", Array(urlSafe.dropLast())),
        ("base64-mixed-alphabets", Array("+".utf8) + Array(urlSafe.dropFirst().dropLast()) + Array("_".utf8)),
        ("base64-noncanonical", Array(base64.dropLast(2)) + Array("B=".utf8)),
        ("base64-two-pads", Array(base64.dropLast(2)) + Array("==".utf8)),
        ("base64-pad-first", Array("=".utf8) + Array(base64.dropLast())),
        ("whitespace-only", [0x20, 0x0A, 0x09]), ("form-feed", [0x0C] + hex + [0x0C]), ("vertical-tab", [0x0B] + hex),
    ]
    for (name, bytes) in texts {
        add("plaintext-\(name)", .content(bytes: bytes, mode: 0, genuinePrefix: false))
    }
    // A payload's shape with a header no wrap produces.
    for suite: UInt8 in [0, 1, 2, 3, 0xFF] {
        add("suite-\(suite)", .content(bytes: [UInt8](repeating: 0x33, count: 32) + [suite] + [UInt8](repeating: 0x33, count: 92), mode: 0, genuinePrefix: false))
        add("zero-fingerprint-suite-\(suite)", .content(bytes: [UInt8](repeating: 0, count: 32) + [suite] + [UInt8](repeating: 0x33, count: 92), mode: 0, genuinePrefix: false))
    }
    for special in Special.allCases {
        add("special-\(special)", .special(special))
        add("special-\(special)-probe", .special(special), Call(cap: 0, outNull: true))
    }
    add("null-path", .nullPath)
    let paths: [(String, [UInt8])] = [
        ("empty", []), ("root", Array("/".utf8)), ("dot", Array(".".utf8)), ("dot-dot", Array("..".utf8)),
        ("dev-null", Array("/dev/null".utf8)), ("dev-zero", Array("/dev/zero".utf8)), ("dev-random", Array("/dev/random".utf8)),
        ("dev-fd-0", Array("/dev/fd/0".utf8)), ("dev-tty", Array("/dev/tty".utf8)), ("etc-passwd", Array("/etc/passwd".utf8)),
        ("tmp", Array("/tmp".utf8)), ("tmp-file", Array("/tmp/hkdfguard-fuzz-no-such-file".utf8)),
        ("applications", Array("/Applications/Safari.app/Contents/Info.plist".utf8)),
        ("system-file", Array("/System/Library/CoreServices/SystemVersion.plist".utf8)),
        ("traversal", Array("/tmp/../../../../etc/master.passwd".utf8)),
        ("component-255", [0x2F] + [UInt8](repeating: 0x61, count: 255)),
        ("component-256", [0x2F] + [UInt8](repeating: 0x61, count: 256)),
        ("length-1022", [0x2F] + [UInt8](repeating: 0x61, count: 1021)),
        ("length-1023", [0x2F] + [UInt8](repeating: 0x61, count: 1022)),
        ("length-1024", [0x2F] + [UInt8](repeating: 0x61, count: 1023)),
        ("length-1200", [UInt8](repeating: 0x2F, count: 1200)),
        ("slashes", [UInt8](repeating: 0x2F, count: 64)),
        ("non-utf8", [0x2F, 0xFF, 0xFE]), ("control", [0x2F, 0x01, 0x0A]),
        ("combining-mark-folder", Array("/tmp/".utf8) + [0xCC, 0x81] + Array("/key".utf8)),
        ("nul-inside", Array("/dev/null".utf8) + [0] + Array("/etc/passwd".utf8)),
        ("resource-fork", Array("/etc/passwd/..namedfork/rsrc".utf8)),
    ]
    for (name, bytes) in paths {
        add("path-\(name)", .path(bytes))
    }
    return seeds
})
