//
//  Entry.swift
//  hkdfguard fuzz build only
//
//  The fuzz targets, and the two functions a fuzzing engine calls. One
//  binary holds every target; HKDFGUARD_FUZZ_TARGET (fuzz/run.sh sets it)
//  says which one this process runs. libFuzzer calls these when the binary
//  is linked with it (fuzz/build.sh --engine libfuzzer); otherwise
//  Standalone.swift's `main` does.
//

import Foundation

let fuzzTargets: [FuzzTarget] = [
    unwrapDekTarget,
    wrapRoundTripTarget,
    openFileTarget,
    folderTrustTarget,
    policyTarget,
    kekFormatsTarget,
    stringBoundsTarget,
    apiThreadsTarget,
    hashToCurveTarget,
    auditQuoteTarget,
]

/// Runs `body` with no production policy in effect, whatever this Mac has
/// installed: the harnesses' answers must not depend on the machine they
/// run on. (The `policy` target puts its own in effect inside this.)
func withNoPolicy<T>(_ body: () -> T) -> T {
    MachineScopeTestOverrides.$policy.withValue(PolicyLoad.none, operation: body)
}

nonisolated(unsafe) private var selected: FuzzTarget?

/// Chooses the target, and does what the environment asks instead of
/// fuzzing: HKDFGUARD_FUZZ_LIST prints the targets' names;
/// HKDFGUARD_FUZZ_WRITE_SEEDS=<dir> writes this target's seeds there.
func fuzzInitialize() {
    let environment = ProcessInfo.processInfo.environment
    if environment["HKDFGUARD_FUZZ_LIST"] != nil {
        print(fuzzTargets.map(\.name).joined(separator: "\n"))
        exit(0)
    }
    guard let name = environment["HKDFGUARD_FUZZ_TARGET"], let target = fuzzTargets.first(where: { $0.name == name }) else {
        fputs("set HKDFGUARD_FUZZ_TARGET to one of: \(fuzzTargets.map(\.name).joined(separator: " ")) (fuzz/run.sh does)\n", stderr)
        exit(2)
    }
    selected = target
    if let directory = environment["HKDFGUARD_FUZZ_WRITE_SEEDS"] {
        let seeds = withNoPolicy { target.seeds() }
        var names = Set<String>()
        for seed in seeds {
            let file = seed.name.map { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "." ? $0 : "_" }
            // As the filesystem sees names: without regard to case.
            guard names.insert(String(file).lowercased()).inserted else {
                fputs("\(name): two seeds are named \(seed.name)\n", stderr)
                exit(2)
            }
            guard FileManager.default.createFile(atPath: directory + "/" + String(file), contents: Data(seed.bytes)) else {
                fputs("\(name): can't write \(directory)/\(String(file))\n", stderr)
                exit(2)
            }
        }
        print("\(name): \(seeds.count) seeds")
        removeFuzzDirectory()
        exit(0)
    }
    atexit { removeFuzzDirectory() }
}

func fuzzOne(_ bytes: [UInt8]) {
    guard let selected else {
        fputs("no fuzz target selected\n", stderr)
        abort()
    }
    withNoPolicy { selected.run(bytes) }
}

@_cdecl("LLVMFuzzerInitialize")
public func LLVMFuzzerInitialize(_ argc: UnsafeMutablePointer<Int32>?, _ argv: UnsafeMutablePointer<UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?>?) -> Int32 {
    fuzzInitialize()
    return 0
}

@_cdecl("LLVMFuzzerTestOneInput")
public func LLVMFuzzerTestOneInput(_ data: UnsafePointer<UInt8>?, _ size: Int) -> Int32 {
    fuzzOne(Array(UnsafeBufferPointer(start: data, count: size)))
    return 0
}
