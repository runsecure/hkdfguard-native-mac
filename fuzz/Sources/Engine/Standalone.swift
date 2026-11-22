//
//  Standalone.swift
//  hkdfguard fuzz build only
//
//  `main` for the build without a fuzzing engine -- the one stock Xcode can
//  make (its toolchain has no libFuzzer). It does the two things that need
//  no coverage feedback:
//
//    hkdfguard-fuzz <file or folder>...     runs each input once: the seeds
//                                           as a regression suite, or a
//                                           finding's input, to reproduce it
//    hkdfguard-fuzz -mutate=<n> [-seed=<s>] <file or folder>...
//                                           then <n> more inputs, each one
//                                           of those with random changes
//                                           made to it: blind fuzzing
//
//  An input that ends the process -- a failed check, a trap, a sanitizer
//  report -- is written to ./crash-<target>-<pid> first, as libFuzzer does.
//

import Foundation

nonisolated(unsafe) private var currentInput = UnsafeMutableRawBufferPointer.allocate(byteCount: 1 << 16, alignment: 1)
nonisolated(unsafe) private var currentLength = 0
nonisolated(unsafe) private var crashPath: UnsafeMutablePointer<CChar>?

/// Async-signal-safe: writes the input being run, then dies as it was
/// going to.
private func recordCrash(_ signalNumber: Int32) {
    if signalNumber != SIGABRT {
        // A failed check and a sanitizer report have said what happened;
        // a fault has not.
        let message: StaticString = "FUZZ FINDING: the process was ended by a signal (a read or write of memory it does not have, most likely)\n"
        _ = write(2, message.utf8Start, message.utf8CodeUnitCount)
    }
    if let crashPath {
        let fd = open(crashPath, O_WRONLY | O_CREAT | O_TRUNC, 0o600)
        if fd >= 0 {
            _ = write(fd, currentInput.baseAddress, currentLength)
            close(fd)
            let message: StaticString = "\nthe input that did this was written to crash-<target>-<pid> in the current folder\n"
            _ = write(2, message.utf8Start, message.utf8CodeUnitCount)
        }
    }
    signal(signalNumber, SIG_DFL)
    raise(signalNumber)
}

private func run(_ bytes: [UInt8]) {
    currentLength = min(bytes.count, currentInput.count)
    bytes.withUnsafeBytes { currentInput.copyMemory(from: UnsafeRawBufferPointer(rebasing: $0.prefix(currentLength))) }
    fuzzOne(bytes)
}

/// xorshift64*: the same inputs for the same seed, on any machine.
private struct Random {
    var state: UInt64
    mutating func next() -> UInt64 {
        state ^= state >> 12
        state ^= state << 25
        state ^= state >> 27
        return state &* 2685821657736338717
    }
    mutating func below(_ bound: Int) -> Int {
        bound <= 1 ? 0 : Int(next() % UInt64(bound))
    }
}

private let interesting: [UInt8] = [0, 1, 2, 3, 4, 31, 32, 33, 124, 125, 126, 127, 128, 129, 0x7F, 0x80, 0xFE, 0xFF]

private func mutate(_ input: [UInt8], _ others: [[UInt8]], _ random: inout Random) -> [UInt8] {
    var bytes = input
    for _ in 0...random.below(4) {
        switch random.below(8) {
        case 0 where !bytes.isEmpty: bytes[random.below(bytes.count)] ^= 1 << UInt8(random.below(8))
        case 1 where !bytes.isEmpty: bytes[random.below(bytes.count)] = UInt8(truncatingIfNeeded: random.next())
        case 2 where !bytes.isEmpty: bytes[random.below(bytes.count)] = interesting[random.below(interesting.count)]
        case 3 where !bytes.isEmpty: bytes.remove(at: random.below(bytes.count))
        case 4: bytes.insert(UInt8(truncatingIfNeeded: random.next()), at: random.below(bytes.count + 1))
        case 5 where !bytes.isEmpty: bytes = Array(bytes.prefix(random.below(bytes.count)))
        case 6:
            // The head of this input, the tail of another.
            let other = others[random.below(others.count)]
            bytes = Array(bytes.prefix(random.below(bytes.count + 1))) + Array(other.suffix(random.below(other.count + 1)))
        default:
            let at = random.below(bytes.count + 1)
            bytes.insert(contentsOf: [UInt8](repeating: interesting[random.below(interesting.count)], count: 1 + random.below(16)), at: at)
        }
    }
    return Array(bytes.prefix(1 << 16))
}

@main
enum Standalone {
    static func main() {
        fuzzInitialize()
        let target = ProcessInfo.processInfo.environment["HKDFGUARD_FUZZ_TARGET"] ?? "target"
        crashPath = strdup("crash-\(target)-\(getpid())")
        for number in [SIGABRT, SIGTRAP, SIGSEGV, SIGBUS, SIGILL, SIGFPE] {
            signal(number, recordCrash)
        }

        var mutations = 0
        var seed: UInt64 = 0x9E3779B97F4A7C15
        var inputs: [[UInt8]] = []
        for argument in CommandLine.arguments.dropFirst() {
            if argument.hasPrefix("-mutate="), let count = Int(argument.dropFirst(8)) {
                mutations = count
            } else if argument.hasPrefix("-seed="), let value = UInt64(argument.dropFirst(6)) {
                seed = value | 1
            } else if argument.hasPrefix("-") {
                fputs("usage: hkdfguard-fuzz [-mutate=<n>] [-seed=<s>] <file or folder>...\n", stderr)
                exit(2)
            } else {
                var isFolder: ObjCBool = false
                guard FileManager.default.fileExists(atPath: argument, isDirectory: &isFolder) else {
                    fputs("no such file or folder: \(argument)\n", stderr)
                    exit(2)
                }
                let files = isFolder.boolValue
                    ? ((try? FileManager.default.contentsOfDirectory(atPath: argument)) ?? []).sorted().map { argument + "/" + $0 }
                    : [argument]
                for file in files {
                    guard let data = FileManager.default.contents(atPath: file) else { continue }
                    inputs.append([UInt8](data))
                }
            }
        }

        for input in inputs {
            run(input)
        }
        var random = Random(state: seed)
        let pool = inputs.isEmpty ? [[]] : inputs
        for _ in 0..<mutations {
            run(mutate(pool[random.below(pool.count)], pool, &random))
        }
        print("\(target): ran \(inputs.count) inputs and \(mutations) mutations of them: no findings")
    }
}
