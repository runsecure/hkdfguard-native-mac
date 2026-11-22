//
//  WrapRoundTrip.swift -- fuzz target `wrap_round_trip`
//
//  hkdfguard_wrap_dek (any DEK length, NULL DEK, a length that lies),
//  hkdfguard_generate_and_wrap_dek, and the calls that describe a KEK or the
//  process: hkdfguard_kek_exists, hkdfguard_kek_fingerprint,
//  hkdfguard_kek_suite, hkdfguard_keychain_mode, hkdfguard_machine_policy,
//  and hkdfguard_harden_process_with_flags's refusal of unknown flags.
//
//  Beyond "no crash": the status is the one hkdfguard.h's order of checks
//  gives; whatever wrap produces is 125 bytes, starts with the KEK's
//  fingerprint and suite, unwraps to the same DEK under either spelling of
//  the service, and is never the same payload twice; a failure leaves the
//  buffer untouched; the fingerprint and suite match the ones payloads
//  carry; kek_exists answers for exactly the created KEK.
//

import Foundation

private enum Op: Int, CaseIterable {
    case wrap, generate, fingerprint, suite, exists, keychainMode, machinePolicy, hardenFlags
}

/// What wrap and generate-and-wrap must return, up to the KEK lookup.
private func expectedWrapStatus(service: Service, dekLength: Int32, dekNull: Bool, call: Call) -> Int32 {
    if dekNull || call.outLenNull || dekLength != Int32(DEK_LEN) || call.cap < 0 { return INVALID_ARGUMENT }
    guard service.isValid else { return INVALID_SERVICE_NAME }
    if call.outNull && call.cap > 0 { return INVALID_ARGUMENT }
    if call.cap < WRAPPED_LEN { return BUFFER_TOO_SMALL }
    return service.isFuzz ? OK : KEK_NOT_FOUND
}

/// A payload wrap just produced: its shape, and that it opens to `dek`
/// (nil: whatever generate-and-wrap chose) under either spelling.
private func checkWrapped(_ ret: Ret, dek: [UInt8]?, _ what: String) {
    let payload = ret.written
    check(ret.outLen == Int32(WRAPPED_LEN) && payload.count == WRAPPED_LEN, "\(what): OK with *out_len \(String(describing: ret.outLen))")
    check(ret.buffer[WRAPPED_LEN...].allSatisfy { $0 == FILL }, "\(what) wrote past the payload")
    check(Array(payload[0..<FINGERPRINT_LEN]) == genuineFingerprint, "\(what): the payload does not start with the KEK's fingerprint")
    check(payload[SUITE_OFFSET] == FUZZ_KEK_SUITE, "\(what): the payload names suite \(payload[SUITE_OFFSET])")
    check(payload != genuinePayload, "\(what) produced the same payload twice: the salt or nonce repeated")
    check(expectedKeyFileStatus(payload) == OK, "\(what) produced a payload hkdfguard_open_file would refuse")

    var opened: [UInt8]?
    for spelling in [Service.fuzz, .fuzzUpper] {
        let back = unwrap(spelling, payload, .dek)
        checkContract(back, .dek, .zeroed, "unwrap of a fresh payload")
        check(back.rc == OK, "a payload \(what) produced does not unwrap under \(spelling): \(statusName(back.rc))")
        check(opened == nil || opened == back.written, "the two spellings of the service unwrapped different DEKs")
        opened = back.written
    }
    if let dek {
        check(opened == dek, "\(what): the payload unwrapped to another DEK")
    }
    let other = unwrap(.other, payload, .dek)
    check(other.rc == KEK_NOT_FOUND, "a fresh payload under a service with no KEK: \(statusName(other.rc))")
}

let wrapRoundTripTarget = FuzzTarget(name: "wrap_round_trip", run: { data in
    setup()
    _ = genuinePayload
    var input = FuzzInput(data)
    let op = Op(rawValue: input.choice(Op.allCases.count)) ?? .wrap
    let service = Service.decode(&input)
    let call = Call.decode(&input)

    switch op {
    case .wrap:
        let dek = input.blob(max: 100)
        let dekNull = input.u8() == 1
        // A length that isn't the buffer's -- only ever shorter, or one the
        // library must refuse before reading: lengths are trusted.
        let lie = input.u8()
        let length: Int32 = lie == 1 ? -1 : lie == 2 ? Int32(dek.count) - 1 : lie == 3 ? Int32.max : Int32(dek.count)
        let honest = length == Int32(dek.count)
        // A lie of exactly 32 would be read: only present ones that aren't.
        guard honest || length != Int32(DEK_LEN) else { return }
        let ret = wrap(service, dek: dek, call: call, dekNull: dekNull, lengthOverride: length)
        checkContract(ret, call, .untouched, "wrap_dek")
        let expected = expectedWrapStatus(service: service, dekLength: length, dekNull: dekNull, call: call)
        check(ret.rc == expected, "wrap_dek returned \(statusName(ret.rc)), expected \(statusName(expected)) (service \(service), DEK \(dek.count) bytes as \(length), call \(call))")
        if ret.rc == OK {
            checkWrapped(ret, dek: dek, "wrap_dek")
        } else if ret.rc == BUFFER_TOO_SMALL {
            check(ret.outLen == Int32(WRAPPED_LEN), "BUFFER_TOO_SMALL must report \(WRAPPED_LEN)")
        }

    case .generate:
        let ret = service.withCString { pointer in
            withBuffer(call) { out, outLen in hkdfguard_generate_and_wrap_dek(servicePtr: pointer, outPtr: out, outLen: outLen) }
        }
        checkContract(ret, call, .untouched, "generate_and_wrap_dek")
        let expected = expectedWrapStatus(service: service, dekLength: Int32(DEK_LEN), dekNull: false, call: call)
        check(ret.rc == expected, "generate_and_wrap_dek returned \(statusName(ret.rc)), expected \(statusName(expected)) (service \(service), call \(call))")
        if ret.rc == OK {
            checkWrapped(ret, dek: nil, "generate_and_wrap_dek")
        } else if ret.rc == BUFFER_TOO_SMALL {
            check(ret.outLen == Int32(WRAPPED_LEN), "BUFFER_TOO_SMALL must report \(WRAPPED_LEN)")
        }

    case .fingerprint:
        let ret = service.withCString { pointer in
            withBuffer(call) { out, outLen in hkdfguard_kek_fingerprint(servicePtr: pointer, outPtr: out, outLen: outLen) }
        }
        // Not one of the four functions that refuse a negative capacity as
        // such: below 32 is BUFFER_TOO_SMALL, negative included.
        let expected: Int32 = call.outNull || call.outLenNull ? INVALID_ARGUMENT
            : call.cap < FINGERPRINT_LEN ? BUFFER_TOO_SMALL
            : !service.isValid ? INVALID_SERVICE_NAME
            : service.isFuzz ? OK : KEK_NOT_FOUND
        check(ret.rc == expected, "kek_fingerprint returned \(statusName(ret.rc)), expected \(statusName(expected)) (service \(service), call \(call))")
        check(ret.canaryIntact, "kek_fingerprint wrote past the declared capacity")
        switch ret.rc {
        case OK:
            check(ret.outLen == Int32(FINGERPRINT_LEN) && ret.written == genuineFingerprint, "kek_fingerprint: the KEK's fingerprint changed")
            check(ret.buffer[FINGERPRINT_LEN...].allSatisfy { $0 == FILL }, "kek_fingerprint wrote past the fingerprint")
        case BUFFER_TOO_SMALL:
            check(ret.outLen == Int32(FINGERPRINT_LEN) && ret.untouched, "kek_fingerprint: BUFFER_TOO_SMALL must report 32 and write nothing")
        default:
            check(ret.untouched && (ret.outLen == nil || ret.outLen == call.capacity), "kek_fingerprint: a failure wrote to the caller's buffer or length")
        }

    case .suite:
        var suite: Int32 = 0x5A5A
        let outNull = call.outNull
        let rc = service.withCString { pointer in
            outNull ? hkdfguard_kek_suite(servicePtr: pointer, outSuite: nil) : hkdfguard_kek_suite(servicePtr: pointer, outSuite: &suite)
        }
        let expected: Int32 = outNull ? INVALID_ARGUMENT : !service.isValid ? INVALID_SERVICE_NAME : service.isFuzz ? OK : KEK_NOT_FOUND
        check(rc == expected, "kek_suite returned \(statusName(rc)), expected \(statusName(expected)) (service \(service))")
        if !outNull {
            check(suite == (rc == OK ? Int32(FUZZ_KEK_SUITE) : 0), "kek_suite: \(statusName(rc)) with *out_suite \(suite)")
        }

    case .exists:
        var exists: Int32 = 0x5A5A
        let outNull = call.outNull
        let rc = service.withCString { pointer in
            outNull ? hkdfguard_kek_exists(servicePtr: pointer, outExists: nil) : hkdfguard_kek_exists(servicePtr: pointer, outExists: &exists)
        }
        let expected: Int32 = outNull ? INVALID_ARGUMENT : !service.isValid ? INVALID_SERVICE_NAME : OK
        check(rc == expected, "kek_exists returned \(statusName(rc)), expected \(statusName(expected)) (service \(service))")
        if !outNull {
            check(exists == (rc == OK && service.isFuzz ? 1 : 0), "kek_exists: \(statusName(rc)) with *out_exists \(exists) for \(service)")
        }

    case .keychainMode:
        var mode: Int32 = 0x5A5A
        let rc = call.outNull ? hkdfguard_keychain_mode(outMode: nil) : hkdfguard_keychain_mode(outMode: &mode)
        check(rc == (call.outNull ? INVALID_ARGUMENT : OK), "keychain_mode returned \(statusName(rc))")
        check(call.outNull || mode == 0 || mode == 1, "keychain_mode wrote \(mode)")

    case .machinePolicy:
        let ret = withBuffer(call) { out, outLen in hkdfguard_machine_policy(outPtr: out, outLen: outLen) }
        checkContract(ret, call, .untouched, "machine_policy")
        // The size, from a probe; no policy is installed for this target.
        let probe = withBuffer(Call(cap: 0, outNull: true)) { out, outLen in hkdfguard_machine_policy(outPtr: out, outLen: outLen) }
        check(probe.rc == BUFFER_TOO_SMALL, "machine_policy size probe: \(statusName(probe.rc))")
        let size = probe.outLen ?? 0
        let expected: Int32 = call.outLenNull || call.cap < 0 ? INVALID_ARGUMENT
            : call.capacity < size ? BUFFER_TOO_SMALL
            : call.outNull ? INVALID_ARGUMENT : OK
        check(ret.rc == expected, "machine_policy returned \(statusName(ret.rc)), expected \(statusName(expected)) (call \(call), size \(size))")
        if ret.rc == BUFFER_TOO_SMALL {
            check(ret.outLen == size, "machine_policy: BUFFER_TOO_SMALL reported \(String(describing: ret.outLen)), the probe \(size)")
        }
        if ret.rc == OK {
            check(ret.outLen == size, "machine_policy wrote \(String(describing: ret.outLen)) bytes, the probe said \(size)")
            guard let object = try? JSONSerialization.jsonObject(with: Data(ret.written)) as? [String: Any] else {
                finding("machine_policy did not write a JSON object")
            }
            check(object["mode"] as? String == policyModeWithoutOverride(), "machine_policy: mode \(String(describing: object["mode"]))")
        }

    case .hardenFlags:
        // Only flags the library must refuse, before it changes anything:
        // the hardening itself can't be undone, and would end the campaign.
        let flags = UInt32(input.u16()) << 16 | UInt32(input.u16())
        guard flags & ~0x1 != 0 else { return }
        let rc = hkdfguard_harden_process_with_flags(flags: flags)
        check(rc == INVALID_ARGUMENT, "harden_process_with_flags(\(String(flags, radix: 16))) returned \(statusName(rc))")
    }
}, seeds: {
    var seeds: [NamedSeed] = []
    func add(_ name: String, _ op: Op, _ service: Service, _ call: Call, _ more: @escaping (Seed) -> Void = { _ in }) {
        seeds.append(NamedSeed(name) { seed in
            seed.choice(op.rawValue)
            service.encode(seed)
            call.encode(seed)
            more(seed)
        })
    }
    func dek(_ bytes: [UInt8], null: Bool = false, lie: UInt8 = 0) -> (Seed) -> Void {
        { $0.blob(bytes).u8(null ? 1 : 0).u8(lie) }
    }
    let payloadCaps = [125, 124, 126, 0, 1, -1, Int(Int16.min), Int(Int16.max)]
    for cap in payloadCaps {
        for (suffix, shape) in [("", Call(cap: Int16(cap))), ("-out-null", Call(cap: Int16(cap), outNull: true)),
                                ("-out-len-null", Call(cap: Int16(cap), outLenNull: true))] {
            add("wrap-cap-\(cap)\(suffix)", .wrap, .fuzz, shape, dek(knownDek))
            add("generate-cap-\(cap)\(suffix)", .generate, .fuzzUpper, shape)
            add("policy-cap-\(cap)\(suffix)", .machinePolicy, .null, shape)
        }
    }
    // DEKs of every length round the limit; NULL; lengths that lie.
    for length in [0, 1, 16, 31, 32, 33, 64, 100] {
        add("wrap-dek-\(length)", .wrap, .fuzz, .full, dek([UInt8](repeating: 0x11, count: length)))
    }
    add("wrap-dek-null", .wrap, .fuzz, .full, dek(knownDek, null: true))
    add("wrap-dek-length-negative", .wrap, .fuzz, .full, dek(knownDek, lie: 1))
    add("wrap-dek-length-31-of-32", .wrap, .fuzz, .full, dek(knownDek, lie: 2))
    add("wrap-dek-length-max", .wrap, .fuzz, .full, dek(knownDek, lie: 3))
    add("wrap-other-service", .wrap, .other, .full, dek(knownDek))
    add("wrap-null-service", .wrap, .null, .full, dek(knownDek))
    add("generate-other-service", .generate, .other, .full)
    for cap in [32, 31, 33, 0, -1, Int(Int16.max)] {
        add("fingerprint-cap-\(cap)", .fingerprint, .fuzz, Call(cap: Int16(cap)))
        add("fingerprint-cap-\(cap)-out-null", .fingerprint, .fuzz, Call(cap: Int16(cap), outNull: true))
    }
    add("fingerprint-out-len-null", .fingerprint, .fuzz, Call(cap: 32, outLenNull: true))
    for op in [Op.fingerprint, .suite, .exists] {
        for (name, service) in [("fuzz", Service.fuzz), ("upper", .fuzzUpper), ("other", .other), ("null", .null)] {
            add("\(op)-\(name)", op, service, .dek)
            add("\(op)-\(name)-out-null", op, service, Call(cap: 32, outNull: true))
        }
    }
    add("keychain-mode", .keychainMode, .null, .dek)
    add("keychain-mode-null", .keychainMode, .null, Call(cap: 0, outNull: true))
    for flags: UInt32 in [0x2, 0x3, 0x8000_0000, 0xFFFF_FFFF, 0x0001_0000] {
        add("harden-flags-\(String(flags, radix: 16))", .hardenFlags, .null, .dek) { $0.u16(UInt16(flags >> 16)).u16(UInt16(flags & 0xFFFF)) }
    }
    for (name, bytes) in serviceStringSeeds() {
        add("wrap-service-\(name)", .wrap, .raw(bytes), .full, dek(knownDek))
        add("exists-service-\(name)", .exists, .raw(bytes), .dek)
    }
    return seeds
})

/// "development", unless this Mac has a production policy or its marker
/// (then the harnesses that expect no policy can't run here at all).
func policyModeWithoutOverride() -> String {
    switch currentMachinePolicy() {
    case .none: return "development"
    case .loaded: return "production"
    case .invalid: return "invalid"
    }
}
