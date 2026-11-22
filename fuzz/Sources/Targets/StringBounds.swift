//
//  StringBounds.swift -- fuzz target `string_bounds`
//
//  Every C string the ABI takes -- the service, through each of the seven
//  functions that take one, and a key file path -- with no terminator at
//  all, at the longest length the rule allows, one byte over, and with a
//  NUL earlier than the bytes that follow it. Each string ends against an
//  inaccessible page.
//
//  Beyond "no crash": a read one byte past the bounded scan (129 bytes of a
//  service, PATH_MAX of a path), or past a terminator, is a fault in any
//  build, sanitizer or not; an unterminated or over-long string gets its
//  documented refusal; the longest valid one is not refused for its length;
//  bytes after the first NUL change neither the status nor the output; the
//  genuine string still works from the edge of a mapping.
//

import Foundation

private let serviceScan = 129 // strnlen's bound: the longest name and its terminator
private let pathScan = Int(PATH_MAX)

private enum Function: Int, CaseIterable {
    case exists, fingerprint, suite, create, wrap, generate, unwrap
}

/// One call with `service`, and everything it wrote.
private struct Answer: Equatable {
    var rc: Int32
    var out: [UInt8] = []
    var outLen: Int32?
    var value: Int32 = 0
}

private func call(_ function: Function, _ service: UnsafePointer<CChar>?) -> Answer {
    switch function {
    case .exists:
        var exists: Int32 = 0x5A5A
        let rc = hkdfguard_kek_exists(servicePtr: service, outExists: &exists)
        return Answer(rc: rc, value: exists)
    case .suite:
        var suite: Int32 = 0x5A5A
        let rc = hkdfguard_kek_suite(servicePtr: service, outSuite: &suite)
        return Answer(rc: rc, value: suite)
    case .create:
        return Answer(rc: hkdfguard_create_kek(servicePtr: service))
    case .fingerprint:
        let ret = withBuffer(.dek) { out, outLen in hkdfguard_kek_fingerprint(servicePtr: service, outPtr: out, outLen: outLen) }
        return Answer(rc: ret.rc, out: ret.buffer, outLen: ret.outLen)
    case .wrap:
        let ret = knownDek.withUnsafeBufferPointer { dek in
            withBuffer(.full) { out, outLen in hkdfguard_wrap_dek(servicePtr: service, dekPtr: dek.baseAddress, dekLen: 32, outPtr: out, outLen: outLen) }
        }
        checkContract(ret, .full, .untouched, "wrap_dek")
        // A payload is random: only that there is one can be compared.
        return Answer(rc: ret.rc, outLen: ret.outLen)
    case .generate:
        let ret = withBuffer(.full) { out, outLen in hkdfguard_generate_and_wrap_dek(servicePtr: service, outPtr: out, outLen: outLen) }
        checkContract(ret, .full, .untouched, "generate_and_wrap_dek")
        return Answer(rc: ret.rc, outLen: ret.outLen)
    case .unwrap:
        let ret = genuinePayload.withUnsafeBufferPointer { payload in
            withBuffer(.dek) { out, outLen in
                hkdfguard_unwrap_dek(servicePtr: service, wrappedPtr: payload.baseAddress, wrappedLen: Int32(payload.count), outPtr: out, outLen: outLen)
            }
        }
        checkContract(ret, .dek, .zeroed, "unwrap_dek")
        return Answer(rc: ret.rc, out: ret.buffer, outLen: ret.outLen)
    }
}

/// What `function` must answer for a valid name with no KEK.
private func statusWithoutKEK(_ function: Function) -> Int32 {
    switch function {
    case .exists, .create: return OK // create makes one
    default: return KEK_NOT_FOUND
    }
}

private func serviceByte(_ value: UInt8) -> UInt8 {
    // Mostly bytes a name may hold, so the long strings are valid ones.
    let alphabet = Array("abcXYZ019.".utf8)
    return value < 200 ? alphabet[Int(value) % alphabet.count] : value
}

let stringBoundsTarget = FuzzTarget(name: "string_bounds", run: { data in
    setup()
    _ = (genuinePayload, genuineFingerprint)
    defer { FuzzKEKStore.removeAll(except: SERVICE) } // create_kek under a valid name makes a KEK
    var input = FuzzInput(data)
    let shape = input.choice(6)

    if shape == 5 {
        // A path: unterminated for exactly the bounded scan, or the longest
        // that has a terminator inside it.
        let terminated = input.bool()
        let fill = input.u8() | 1 // never NUL
        let length = terminated ? pathScan - 1 - input.choice(4) : pathScan + input.choice(3)
        var bytes = [UInt8](repeating: fill, count: length)
        bytes[0] = 0x2F
        for index in stride(from: 200, to: length, by: 200) { bytes[index] = 0x2F } // components a filesystem would take
        let guarded = Guarded(terminated ? bytes + [0] : Array(bytes.prefix(pathScan)))
        let ret = guarded.use { path in withBuffer(.full) { out, outLen in hkdfguard_open_file(pathPtr: path, outPtr: out, outLen: outLen) } }
        checkContract(ret, .full, .zeroed, "open_file")
        if terminated {
            check(ret.rc != OK && ret.rc != INVALID_ARGUMENT, "open_file of a \(length)-byte path with a terminator: \(statusName(ret.rc))")
        } else {
            check(ret.rc == INVALID_ARGUMENT, "open_file of a path with no terminator in PATH_MAX bytes: \(statusName(ret.rc))")
        }
        // The same answer from the size probe, which never opens the file.
        let probe = guarded.use { path in withBuffer(Call(cap: 0, outNull: true)) { out, outLen in hkdfguard_open_file(pathPtr: path, outPtr: out, outLen: outLen) } }
        check(probe.rc == (terminated ? BUFFER_TOO_SMALL : INVALID_ARGUMENT), "open_file size probe of a long path: \(statusName(probe.rc))")
        return
    }

    let function = Function(rawValue: input.choice(Function.allCases.count)) ?? .exists
    let fill = serviceByte(input.u8())
    switch shape {
    case 0:
        // No terminator in the 129 bytes the scan may read, and nothing
        // readable after them.
        let bytes = [UInt8](repeating: fill == 0 ? 0x61 : fill, count: serviceScan)
        let answer = Guarded(bytes).use { call(function, $0) }
        check(answer.rc == INVALID_SERVICE_NAME, "\(function) of an unterminated service: \(statusName(answer.rc))")

    case 1:
        // The longest length the rule allows, and one byte over.
        let over = input.bool()
        let name = [UInt8](repeating: fill == 0 ? 0x61 : fill, count: over ? 129 : 128)
        let answer = Guarded(name + [0]).use { call(function, $0) }
        let valid = serviceNameIsValid(name)
        check(!over || !valid, "harness: a 129-byte name is valid")
        let expected = valid ? statusWithoutKEK(function) : INVALID_SERVICE_NAME
        check(answer.rc == expected, "\(function) of a \(name.count)-byte service of \(fill): \(statusName(answer.rc)), expected \(statusName(expected))")

    case 2:
        // A NUL, then bytes that must not be read as part of the name --
        // and the same name without them must answer the same.
        let name = Array(input.blob(max: 128).map(serviceByte).prefix { $0 != 0 })
        let after = input.blob(max: 200)
        let with = Guarded(name + [0] + after).use { call(function, $0) }
        let without = Guarded(name + [0]).use { call(function, $0) }
        // create_kek answers OK both times: the second finds the first's.
        check(with == without, "\(function): bytes after the terminator changed the answer (\(statusName(with.rc)) / \(statusName(without.rc)))")
        let expected = serviceNameIsValid(name) ? statusWithoutKEK(function) : INVALID_SERVICE_NAME
        check(Service.raw(name).isFuzz || with.rc == expected, "\(function) of \(name): \(statusName(with.rc)), expected \(statusName(expected))")

    case 3:
        // The genuine name, ending at the edge of the mapping.
        let spelling = input.bool() ? SERVICE : SERVICE_UPPER
        let answer = Guarded(Array(spelling.utf8) + [0]).use { call(function, $0) }
        check(answer.rc == OK, "\(function) of the genuine service at the edge of a mapping: \(statusName(answer.rc))")
        switch function {
        case .exists: check(answer.value == 1, "kek_exists: \(answer.value)")
        case .suite: check(answer.value == Int32(FUZZ_KEK_SUITE), "kek_suite: \(answer.value)")
        case .fingerprint: check(answer.out == genuineFingerprint, "kek_fingerprint returned another fingerprint")
        case .unwrap: check(answer.out == knownDek, "unwrap_dek returned another DEK")
        case .wrap, .generate: check(answer.outLen == Int32(WRAPPED_LEN), "no payload")
        case .create: break
        }

    default:
        // An empty string: the terminator is the last readable byte.
        let answer = Guarded([0]).use { call(function, $0) }
        check(answer.rc == INVALID_SERVICE_NAME, "\(function) of an empty service: \(statusName(answer.rc))")
    }
}, seeds: {
    var seeds: [NamedSeed] = []
    for function in Function.allCases {
        for (name, fill) in [("letter", UInt8(0)), ("dot", 9), ("digit", 6), ("high-byte", 0xFF), ("slash", 0xC8 + 0x2F)] {
            seeds.append(NamedSeed("\(function)-unterminated-\(name)") { $0.choice(0).choice(function.rawValue).u8(fill) })
            seeds.append(NamedSeed("\(function)-longest-\(name)") { $0.choice(1).choice(function.rawValue).u8(fill).bool(false) })
            seeds.append(NamedSeed("\(function)-one-over-\(name)") { $0.choice(1).choice(function.rawValue).u8(fill).bool(true) })
        }
        for (name, bytes) in serviceStringSeeds() {
            seeds.append(NamedSeed("\(function)-then-nul-\(name)") { $0.choice(2).choice(function.rawValue).u8(0).blob(Array(bytes.prefix(128))).blob(Array("/../x%n".utf8)) })
        }
        seeds.append(NamedSeed("\(function)-genuine") { $0.choice(3).choice(function.rawValue).u8(0).bool(true) })
        seeds.append(NamedSeed("\(function)-genuine-other-case") { $0.choice(3).choice(function.rawValue).u8(0).bool(false) })
        seeds.append(NamedSeed("\(function)-empty") { $0.choice(4).choice(function.rawValue).u8(0) })
    }
    for terminated in [false, true] {
        for extra in 0..<4 {
            seeds.append(NamedSeed("path-\(terminated ? "terminated" : "unterminated")-\(extra)") { $0.choice(5).bool(terminated).u8(0x61).choice(extra) })
        }
    }
    return seeds
})
