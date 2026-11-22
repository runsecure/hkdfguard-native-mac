//
//  ApiThreads.swift -- fuzz target `api_threads`
//
//  The C ABI called from several threads at once: the calls a service
//  makes -- create, exists, fingerprint, suite, wrap, unwrap, open_file,
//  the policy -- interleaved however the scheduler likes, each thread
//  checking its own answers. What it is for is the state the calls share:
//  the setup gate, the policy snapshot, the audit counters, the KEK.
//
//  Beyond "no crash": every thread gets the answer the call gets alone --
//  its own DEK back and never another thread's, a fingerprint that doesn't
//  change, no KEK appearing for a service without one. Under
//  AddressSanitizer a use after free or a stale pointer in shared state is
//  a finding. (A data race that corrupts nothing on the day is
//  ThreadSanitizer's to find: fuzz/build.sh --sanitizer thread.)
//

import Foundation

private let maxThreads = 4
private let maxOps = 24

private enum Op {
    /// Idempotent: the KEK exists already, and must still afterwards.
    case createKek
    case exists(other: Bool)
    case fingerprint
    case suite
    /// Wrap this DEK, then unwrap what came back.
    case wrapUnwrap(dek: [UInt8], upper: Bool)
    case generateUnwrap
    case unwrapGenuine(cap: Int16)
    /// The genuine payload with one byte changed: never opens.
    case unwrapPatched(offset: UInt16, xor: UInt8)
    case openFile(cap: Int16)
    /// A service with no KEK: refused, and not served by this one's.
    case wrapOther
    case machinePolicy

    static let count = 11

    static func decode(_ input: inout FuzzInput) -> Op {
        switch input.choice(count) {
        case 0: return .createKek
        case 1: return .exists(other: input.bool())
        case 2: return .fingerprint
        case 3: return .suite
        case 4: return .wrapUnwrap(dek: input.fixed(32), upper: input.bool())
        case 5: return .generateUnwrap
        case 6: return .unwrapGenuine(cap: input.i16())
        case 7: return .unwrapPatched(offset: input.u16(), xor: input.u8())
        case 8: return .openFile(cap: input.i16())
        case 9: return .wrapOther
        default: return .machinePolicy
        }
    }

    func encode(_ seed: Seed) {
        switch self {
        case .createKek: seed.choice(0)
        case .exists(let other): seed.choice(1).bool(other)
        case .fingerprint: seed.choice(2)
        case .suite: seed.choice(3)
        case .wrapUnwrap(let dek, let upper): seed.choice(4).fixed(dek).bool(upper)
        case .generateUnwrap: seed.choice(5)
        case .unwrapGenuine(let cap): seed.choice(6).i16(cap)
        case .unwrapPatched(let offset, let xor): seed.choice(7).u16(offset).u8(xor)
        case .openFile(let cap): seed.choice(8).i16(cap)
        case .wrapOther: seed.choice(9)
        case .machinePolicy: seed.choice(10)
        }
    }
}

private let threadsKeyFile: String = {
    let path = fuzzDirectory + "/threads-key.bin"
    writeFile(path, genuinePayload, mode: 0o600)
    return path
}()

private func run(_ op: Op) {
    switch op {
    case .createKek:
        let rc = SERVICE.withCString { hkdfguard_create_kek(servicePtr: $0) }
        check(rc == OK, "create_kek for a service that has one: \(statusName(rc))")
    case .exists(let other):
        var exists: Int32 = 0x5A5A
        let rc = (other ? OTHER_SERVICE : SERVICE).withCString { hkdfguard_kek_exists(servicePtr: $0, outExists: &exists) }
        check(rc == OK && exists == (other ? 0 : 1), "kek_exists (service without a KEK: \(other)): \(statusName(rc)), \(exists)")
    case .fingerprint:
        let ret = withBuffer(.dek) { out, outLen in SERVICE.withCString { hkdfguard_kek_fingerprint(servicePtr: $0, outPtr: out, outLen: outLen) } }
        check(ret.rc == OK && ret.written == genuineFingerprint, "the KEK's fingerprint changed (\(statusName(ret.rc)))")
    case .suite:
        var suite: Int32 = 0
        let rc = SERVICE_UPPER.withCString { hkdfguard_kek_suite(servicePtr: $0, outSuite: &suite) }
        check(rc == OK && suite == Int32(FUZZ_KEK_SUITE), "kek_suite: \(statusName(rc)), \(suite)")
    case .wrapUnwrap(let dek, let upper):
        let ret = wrap(upper ? .fuzzUpper : .fuzz, dek: dek, call: .full)
        checkContract(ret, .full, .untouched, "wrap_dek")
        check(ret.rc == OK, "wrap_dek: \(statusName(ret.rc))")
        let back = unwrap(.fuzz, ret.written, .dek)
        check(back.rc == OK, "a payload wrap produced does not unwrap: \(statusName(back.rc))")
        check(back.written == dek, "unwrap returned another thread's DEK, or none")
    case .generateUnwrap:
        let ret = withBuffer(.full) { out, outLen in SERVICE.withCString { hkdfguard_generate_and_wrap_dek(servicePtr: $0, outPtr: out, outLen: outLen) } }
        checkContract(ret, .full, .untouched, "generate_and_wrap_dek")
        check(ret.rc == OK, "generate_and_wrap_dek: \(statusName(ret.rc))")
        let back = unwrap(.fuzzUpper, ret.written, .dek)
        check(back.rc == OK && back.outLen == 32, "a generated payload does not unwrap: \(statusName(back.rc))")
    case .unwrapGenuine(let cap):
        let call = Call(cap: cap)
        let ret = unwrap(.fuzz, genuinePayload, call)
        checkContract(ret, call, .zeroed, "unwrap_dek")
        if cap >= 32 {
            check(ret.rc == OK && ret.written == knownDek, "the genuine payload failed to unwrap: \(statusName(ret.rc))")
        } else {
            check(ret.rc != OK, "unwrapped into \(cap) bytes")
        }
    case .unwrapPatched(let offset, let xor):
        var payload = genuinePayload
        payload[Int(offset) % payload.count] ^= xor | 1
        let ret = unwrap(.fuzz, payload, .dek)
        checkContract(ret, .dek, .zeroed, "unwrap_dek")
        check(ret.rc != OK, "a corrupted payload unwrapped")
    case .openFile(let cap):
        let call = Call(cap: cap)
        let ret = openFile(path: threadsKeyFile, call)
        checkContract(ret, call, .zeroed, "open_file")
        if cap >= WRAPPED_LEN {
            check(ret.rc == OK && ret.written == genuinePayload, "open_file of a genuine private key file: \(statusName(ret.rc))")
        } else {
            check(ret.rc != OK, "open_file into \(cap) bytes")
        }
    case .wrapOther:
        let ret = wrap(.other, dek: knownDek, call: .full)
        check(ret.rc == KEK_NOT_FOUND && ret.untouched, "wrap under a service with no KEK: \(statusName(ret.rc))")
    case .machinePolicy:
        let ret = withBuffer(.full) { out, outLen in hkdfguard_machine_policy(outPtr: out, outLen: outLen) }
        check(ret.rc == OK && (try? JSONSerialization.jsonObject(with: Data(ret.written))) != nil, "machine_policy: \(statusName(ret.rc))")
    }
}

private func runApiThreads(_ data: [UInt8]) {
    setup()
    // Everything the threads share, made before any of them starts.
    _ = (genuinePayload, genuineFingerprint, threadsKeyFile)
    var input = FuzzInput(data)
    let threadCount = 2 + input.choice(maxThreads - 1)
    let threads = (0..<threadCount).map { _ in
        (0..<input.choice(maxOps + 1)).map { _ in Op.decode(&input) }
    }
    // A failed check in a thread aborts the process, so it is recorded
    // with this input.
    DispatchQueue.concurrentPerform(iterations: threadCount) { index in
        // The harness's "no policy" is task-local: each thread needs its own.
        withNoPolicy { threads[index].forEach(run) }
    }
}

private func apiThreadsSeeds() -> [NamedSeed] {
    var seeds: [NamedSeed] = []
    func add(_ name: String, _ threads: [[Op]]) {
        seeds.append(NamedSeed(name) { seed in
            seed.choice(threads.count - 2)
            for ops in threads {
                seed.choice(ops.count)
                for op in ops { op.encode(seed) }
            }
        })
    }
    let all: [Op] = [.createKek, .exists(other: false), .exists(other: true), .fingerprint, .suite, .generateUnwrap,
                     .unwrapGenuine(cap: 32), .unwrapGenuine(cap: 31), .unwrapPatched(offset: 40, xor: 1),
                     .openFile(cap: 125), .openFile(cap: 124), .wrapOther, .machinePolicy]
    for (index, op) in all.enumerated() {
        add("every-thread-\(index)", [[Op]](repeating: [Op](repeating: op, count: 8), count: 4))
    }
    func wraps(_ first: Int, count: Int, upper: Bool) -> [Op] {
        (0..<count).map { index -> Op in
            .wrapUnwrap(dek: [UInt8](repeating: UInt8(first + index), count: 32), upper: upper)
        }
    }
    let creates = [Op](repeating: .createKek, count: 12)
    add("create-racing-wrap", [creates, wraps(0, count: 12, upper: false), creates, wraps(100, count: 12, upper: true)])
    add("distinct-deks", [wraps(0, count: 16, upper: false), wraps(16, count: 16, upper: true),
                          wraps(32, count: 16, upper: false), wraps(48, count: 16, upper: true)])
    add("setup-calls", [[.exists(other: false), .fingerprint, .suite, .createKek], [.createKek, .suite, .fingerprint, .exists(other: true)],
                        [.fingerprint, .fingerprint, .fingerprint], [.exists(other: true), .exists(other: false)]])
    let rotated: [[Op]] = (0..<4).map { thread -> [Op] in
        Array(all.dropFirst(thread)) + Array(all.prefix(thread))
    }
    add("everything", rotated)
    let backwards: [Op] = all.reversed()
    add("two-threads", [all, backwards])
    return seeds
}

let apiThreadsTarget = FuzzTarget(name: "api_threads", run: runApiThreads, seeds: apiThreadsSeeds)
