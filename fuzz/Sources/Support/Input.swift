//
//  Input.swift
//  hkdfguard fuzz build only
//
//  How a fuzzer's bytes become a harness's structured input, and how a seed
//  is written so that it decodes to the input it was meant to be. One
//  encoding, read by `FuzzInput` and written by `Seed`; a target's `decode`
//  and its seeds are a few lines apart, so they change together.
//

import Foundation

/// Reads structured values off the front of a fuzzer input. Never fails:
/// once the bytes run out every read gives zero (or empty), so any input at
/// all decodes to something.
struct FuzzInput {
    private let bytes: [UInt8]
    private var position = 0

    init(_ bytes: [UInt8]) {
        self.bytes = bytes
    }

    var remaining: Int { bytes.count - position }

    mutating func u8() -> UInt8 {
        guard position < bytes.count else { return 0 }
        defer { position += 1 }
        return bytes[position]
    }

    /// Little-endian.
    mutating func u16() -> UInt16 {
        let low = UInt16(u8())
        return low | UInt16(u8()) << 8
    }

    mutating func i16() -> Int16 {
        Int16(bitPattern: u16())
    }

    mutating func bool() -> Bool {
        u8() & 1 == 1
    }

    /// One of `count` alternatives, 0 ..< count.
    mutating func choice(_ count: Int) -> Int {
        Int(u8()) % count
    }

    /// A u16 length, then that many bytes: fewer if the input ends first,
    /// and never more than `max`.
    mutating func blob(max: Int = 2048) -> [UInt8] {
        let length = min(Int(u16()), max, remaining)
        defer { position += length }
        return Array(bytes[position..<(position + length)])
    }

    /// Exactly `count` bytes, zero-filled past the end of the input.
    mutating func fixed(_ count: Int) -> [UInt8] {
        (0..<count).map { _ in u8() }
    }

    /// Everything left.
    mutating func rest() -> [UInt8] {
        defer { position = bytes.count }
        return Array(bytes[position...])
    }
}

/// Writes what `FuzzInput` reads. A class, so the calls chain.
final class Seed {
    private(set) var bytes: [UInt8] = []

    @discardableResult func u8(_ value: UInt8) -> Seed {
        bytes.append(value)
        return self
    }

    @discardableResult func u16(_ value: UInt16) -> Seed {
        bytes.append(UInt8(value & 0xFF))
        bytes.append(UInt8(value >> 8))
        return self
    }

    @discardableResult func i16(_ value: Int16) -> Seed {
        u16(UInt16(bitPattern: value))
    }

    @discardableResult func bool(_ value: Bool) -> Seed {
        u8(value ? 1 : 0)
    }

    @discardableResult func choice(_ index: Int) -> Seed {
        u8(UInt8(index))
    }

    @discardableResult func blob(_ value: [UInt8]) -> Seed {
        u16(UInt16(value.count))
        bytes.append(contentsOf: value)
        return self
    }

    @discardableResult func fixed(_ value: [UInt8]) -> Seed {
        bytes.append(contentsOf: value)
        return self
    }

    @discardableResult func rest(_ value: [UInt8]) -> Seed {
        bytes.append(contentsOf: value)
        return self
    }
}

/// A seed: a name saying what it tries, and the input.
struct NamedSeed {
    let name: String
    let bytes: [UInt8]

    init(_ name: String, _ build: (Seed) -> Void) {
        let seed = Seed()
        build(seed)
        self.name = name
        self.bytes = seed.bytes
    }
}

/// One fuzz target: its name (the one `fuzz/run.sh` takes), what it does
/// with an input, and the inputs worth starting from.
struct FuzzTarget: Sendable {
    let name: String
    let run: @Sendable ([UInt8]) -> Void
    let seeds: @Sendable () -> [NamedSeed]
}
