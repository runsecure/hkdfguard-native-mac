//
//  UnwrapDek.swift -- fuzz target `unwrap_dek`
//
//  hkdfguard_unwrap_dek on arbitrary bytes and on structured corruptions of
//  a genuine payload (bit flips, truncation, trailing bytes), under every
//  shape of service string, payload pointer and length, and output buffer.
//
//  Beyond "no crash": the status is exactly the one hkdfguard.h's order of
//  checks gives; only the genuine payload ever unwraps, only under its own
//  service, and only to its DEK; every failure zeroes the caller's buffer;
//  BUFFER_TOO_SMALL reports 32.
//

import Foundation

private enum Body {
    case genuine
    case raw([UInt8])
    case patched(ops: [(offset: UInt16, xor: UInt8)], truncate: UInt16?, extend: [UInt8])

    static func decode(_ input: inout FuzzInput) -> Body {
        switch input.choice(3) {
        case 0: return .genuine
        case 1: return .raw(input.blob(max: 600))
        default:
            let ops = (0..<Int(input.u8() % 9)).map { _ in (offset: input.u16(), xor: input.u8()) }
            let truncate = input.bool() ? input.u16() : nil
            return .patched(ops: ops, truncate: truncate, extend: input.blob(max: 300))
        }
    }

    func encode(_ seed: Seed) {
        switch self {
        case .genuine: seed.choice(0)
        case .raw(let bytes): seed.choice(1).blob(bytes)
        case .patched(let ops, let truncate, let extend):
            seed.choice(2).u8(UInt8(ops.count))
            for op in ops { seed.u16(op.offset).u8(op.xor) }
            seed.bool(truncate != nil)
            if let truncate { seed.u16(truncate) }
            seed.blob(extend)
        }
    }

    var bytes: [UInt8] {
        switch self {
        case .genuine: return genuinePayload
        case .raw(let bytes): return bytes
        case .patched(let ops, let truncate, let extend):
            var bytes = genuinePayload
            for op in ops { bytes[Int(op.offset) % bytes.count] ^= op.xor }
            if let truncate { bytes = Array(bytes.prefix(Int(truncate))) }
            return bytes + extend
        }
    }
}

/// How the payload pointer and length are presented.
private enum Presentation: Int {
    case honest, null, negativeLength
}

private func encodeUnwrap(_ service: Service, _ body: Body, _ call: Call, _ presentation: Presentation = .honest) -> (Seed) -> Void {
    { seed in
        service.encode(seed)
        body.encode(seed)
        call.encode(seed)
        seed.u8(UInt8(presentation.rawValue))
    }
}

let unwrapDekTarget = FuzzTarget(name: "unwrap_dek", run: { data in
    setup()
    var input = FuzzInput(data)
    let service = Service.decode(&input)
    let body = Body.decode(&input)
    let call = Call.decode(&input)
    // Mostly honest: the other two are one check each.
    let presentation = Presentation(rawValue: Int(input.u8())) ?? .honest
    let bytes = body.bytes

    let ret: Ret
    let expected: Int32
    switch presentation {
    case .honest:
        ret = unwrap(service, bytes, call)
        expected = expectedUnwrapStatus(service: service, payload: bytes, call: call)
    case .null:
        ret = unwrap(service, bytes, call, payloadNull: true)
        expected = INVALID_ARGUMENT
    case .negativeLength:
        ret = unwrap(service, bytes, call, lengthOverride: -1 - Int32(bytes.count))
        expected = INVALID_ARGUMENT
    }
    checkContract(ret, call, .zeroed, "unwrap_dek")
    check(ret.rc == expected,
          "unwrap_dek returned \(statusName(ret.rc)), expected \(statusName(expected)) (service \(service), \(bytes.count) bytes, call \(call), \(presentation))")

    switch ret.rc {
    case OK:
        // The only payload that can authenticate is the genuine one, under
        // its own KEK, and it must yield its DEK.
        check(service.isFuzz, "unwrapped under service \(service)")
        check(bytes == genuinePayload, "a payload other than the genuine one unwrapped")
        check(ret.outLen == Int32(DEK_LEN), "OK with *out_len \(String(describing: ret.outLen))")
        check(ret.written == knownDek, "unwrap returned another DEK")
        check(ret.buffer[DEK_LEN...].allSatisfy { $0 == FILL }, "unwrap wrote past the DEK")
    case BUFFER_TOO_SMALL:
        check(ret.outLen == Int32(DEK_LEN), "BUFFER_TOO_SMALL must report the DEK length")
    default:
        break
    }
}, seeds: {
    var seeds: [NamedSeed] = []
    func add(_ name: String, _ service: Service, _ body: Body, _ call: Call, _ presentation: Presentation = .honest) {
        seeds.append(NamedSeed(name, encodeUnwrap(service, body, call, presentation)))
    }
    add("genuine", .fuzz, .genuine, .dek)
    add("genuine-other-case", .fuzzUpper, .genuine, .full)
    add("genuine-service-without-a-kek", .other, .genuine, .dek)
    add("genuine-null-service", .null, .genuine, .dek)
    add("genuine-null-payload", .fuzz, .genuine, .dek, .null)
    add("genuine-negative-length", .fuzz, .genuine, .dek, .negativeLength)
    // Output buffers: fits exactly, one short, one over, zero, one,
    // negative, the extremes; out NULL, out_len NULL, both.
    for cap in [32, 31, 33, 0, 1, -1, Int(Int16.min), Int(Int16.max)] {
        add("cap-\(cap)", .fuzz, .genuine, Call(cap: Int16(cap)))
        add("cap-\(cap)-out-null", .fuzz, .genuine, Call(cap: Int16(cap), outNull: true))
    }
    add("out-len-null", .fuzz, .genuine, Call(cap: 32, outLenNull: true))
    add("out-and-out-len-null", .fuzz, .genuine, Call(cap: 32, outNull: true, outLenNull: true))
    // Payloads: cut off at every length, every header byte flipped to its
    // extremes, trailing bytes, raw blocks.
    for length in 0..<WRAPPED_LEN {
        add("truncated-\(length)", .fuzz, .patched(ops: [], truncate: UInt16(length), extend: []), .dek)
    }
    for offset in 0..<WRAPPED_LEN {
        for xor: UInt8 in [0x01, 0x80, 0xFF] {
            add("byte-\(offset)-xor-\(xor)", .fuzz, .patched(ops: [(UInt16(offset), xor)], truncate: nil, extend: []), .dek)
        }
    }
    for suite: UInt8 in [0, 1, 3, 0x7F, 0x80, 0xFF] {
        add("suite-\(suite)", .fuzz, .patched(ops: [(UInt16(SUITE_OFFSET), FUZZ_KEK_SUITE ^ suite)], truncate: nil, extend: []), .dek)
        add("suite-\(suite)-other-service", .other, .patched(ops: [(UInt16(SUITE_OFFSET), FUZZ_KEK_SUITE ^ suite)], truncate: nil, extend: []), .dek)
    }
    for extra in [1, 2, 125, 300] {
        add("trailing-\(extra)", .fuzz, .patched(ops: [], truncate: nil, extend: [UInt8](repeating: 0x5A, count: extra)), .dek)
    }
    for (name, byte) in [("zeros", UInt8(0)), ("ones", 0xFF), ("suite-2s", 2)] {
        for length in [0, 1, 32, 124, 125, 126, 600] {
            add("raw-\(name)-\(length)", .fuzz, .raw([UInt8](repeating: byte, count: length)), .dek)
        }
    }
    // Strings: see string_bounds for the ones at the edge of memory.
    for (name, bytes) in serviceStringSeeds() {
        add("service-\(name)", .raw(bytes), .genuine, .dek)
    }
    return seeds
})

/// Service strings worth trying wherever one is taken.
func serviceStringSeeds() -> [(String, [UInt8])] {
    let name = Array(SERVICE.utf8)
    return [
        ("empty", []),
        ("early-nul", [0] + name),
        ("nul-inside", Array(name.prefix(4)) + [0] + Array(name.dropFirst(4))),
        ("nul-after", name + [0] + Array("/../etc".utf8)),
        ("longest-128", [UInt8](repeating: 0x61, count: 128)),
        ("too-long-129", [UInt8](repeating: 0x61, count: 129)),
        ("too-long-300", [UInt8](repeating: 0x61, count: 300)),
        ("leading-dot", Array(".hidden".utf8)),
        ("dot", Array(".".utf8)),
        ("dot-dot", Array("..".utf8)),
        ("double-dot-inside", Array("com..example".utf8)),
        ("trailing-dot", name + [0x2E]),
        ("traversal", Array("../../etc/passwd".utf8)),
        ("slash", Array("com/example".utf8)),
        ("hyphen", Array("com.example-app".utf8)),
        ("underscore", Array("com.example_app".utf8)),
        ("space", Array("com.example app".utf8)),
        ("format-string", Array("%s%s%n%x".utf8)),
        ("control", [0x01, 0x1B, 0x7F]),
        ("newline", name + [0x0A]),
        ("non-utf8", [0xFF, 0xFE, 0x80]),
        ("overlong-utf8", [0xC0, 0xAE]),
        ("kelvin-sign", Array("com.hkdfguard.fuzz".utf8.dropLast()) + [0xE2, 0x84, 0xAA]),
        ("fullwidth", Array("ｃｏｍ".utf8)),
        ("combining-mark", Array("com".utf8) + [0xCC, 0x81]),
        ("policy-line", Array("<key>RequirePostQuantum</key><false/>".utf8)),
    ]
}
