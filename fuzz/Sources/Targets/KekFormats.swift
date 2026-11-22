//
//  KekFormats.swift -- fuzz target `kek_formats`
//
//  The two stored forms of a KEK -- the machine KEK file ("HKGK") and the
//  ML-KEM keychain item ("HKGQ") -- through their decoders, on arbitrary
//  bytes, on what the encoders write for arbitrary fields, and on mutated
//  encodings; and lengthPrefixedField, which both use, at any offset.
//  (Linux's `tpm_key_file`.) No Secure Enclave is involved: the decoders
//  only take the container apart.
//
//  Beyond "no crash": decode and encode agree -- whatever decodes
//  re-encodes to the same bytes (the format has one spelling), and whatever
//  the encoder writes decodes to exactly what it was given; an oversized or
//  truncated container is refused, never read past its end.
//

import Foundation
import CryptoKit

private func checkMachineKeyFile(_ bytes: [UInt8]) {
    guard let file = decodeMachineKeyFile(Data(bytes)) else { return }
    check(bytes.count <= 8192, "decodeMachineKeyFile accepted \(bytes.count) bytes")
    check(!file.blob.isEmpty && file.fingerprint.count == FINGERPRINT_LEN, "decodeMachineKeyFile: an empty blob or a short fingerprint")
    check(file.fingerprint.contains { $0 != 0 }, "decodeMachineKeyFile accepted an all-zero fingerprint")
    switch file.suite {
    case .p256HashedPoint:
        check(file.encapsulated.isEmpty && file.classicalBlob.isEmpty, "a P-256 machine KEK file with ML-KEM fields")
    case .mlkem1024StoredCiphertext:
        check(file.encapsulated.count == 1568 && !file.classicalBlob.isEmpty && file.publicKey == nil, "an ML-KEM machine KEK file of the wrong shape")
    }
    if let publicKey = file.publicKey {
        check(file.fingerprint == Data(SHA256.hash(data: publicKey)), "a format 1 file's fingerprint is not its public key's")
    }
    guard let encoded = encodeMachineKeyFile(file) else {
        finding("decodeMachineKeyFile accepted a file encodeMachineKeyFile can't write")
    }
    check([UInt8](encoded) == bytes, "a machine KEK file re-encodes to other bytes: the format has two spellings")
}

private func checkKeychainItem(_ bytes: [UInt8]) {
    let magic = Array("HKGQ".utf8)
    guard let item = decodeKeychainKEK(Data(bytes)) else {
        check(bytes.starts(with: magic), "decodeKeychainKEK refused bytes without the container's magic")
        return
    }
    switch item.stored {
    case .p256(let blob):
        check(!bytes.starts(with: magic) && [UInt8](blob) == bytes && item.fingerprint == nil, "a bare blob decoded as something else")
    case .mlkem1024(let blob, let encapsulated, let classicalBlob):
        check(bytes.starts(with: magic) && !blob.isEmpty && !classicalBlob.isEmpty && encapsulated.count == 1568
              && item.fingerprint?.count == FINGERPRINT_LEN, "an ML-KEM keychain item of the wrong shape")
        guard let encoded = encodeKeychainKEK(item.stored, fingerprint: item.fingerprint) else {
            finding("decodeKeychainKEK accepted an item encodeKeychainKEK can't write")
        }
        check([UInt8](encoded) == bytes, "a keychain item re-encodes to other bytes: the format has two spellings")
    }
}

/// The bytes after a mutation: xors, then a cut, then an extension.
private func mutated(_ bytes: [UInt8], _ input: inout FuzzInput) -> [UInt8] {
    var bytes = bytes
    for _ in 0..<input.choice(5) where !bytes.isEmpty {
        bytes[Int(input.u16()) % bytes.count] ^= input.u8()
    }
    if input.bool() { bytes = Array(bytes.prefix(Int(input.u16()))) }
    return bytes + input.blob(max: 64)
}

let kekFormatsTarget = FuzzTarget(name: "kek_formats", run: { data in
    var input = FuzzInput(data)
    switch input.choice(5) {
    case 0:
        let bytes = input.rest()
        checkMachineKeyFile(bytes)
        checkKeychainItem(bytes)

    case 1:
        // What the encoder writes for arbitrary fields, then mutated.
        let suite: KEKSuite = input.bool() ? .mlkem1024StoredCiphertext : .p256HashedPoint
        let fingerprint = Data(input.fixed(FINGERPRINT_LEN))
        let blob = Data(input.blob(max: 600))
        let ciphertextLength = input.bool() ? (suite == .mlkem1024StoredCiphertext ? 1568 : 0) : Int(input.u16()) % 1700
        let encapsulated = Data([UInt8](repeating: input.u8(), count: ciphertextLength))
        let classical = Data(input.blob(max: 300))
        let file = MachineKeyFile(suite: suite, publicKey: nil, fingerprint: fingerprint, blob: blob,
                                  encapsulated: encapsulated, classicalBlob: classical)
        guard let encoded = encodeMachineKeyFile(file) else { return }
        let decoded = decodeMachineKeyFile(encoded)
        // The decoder refuses an all-zero fingerprint; the encoder writes
        // whatever fingerprint it is given.
        if fingerprint.contains(where: { $0 != 0 }) {
            check(decoded == file, "encodeMachineKeyFile's output decodes to something else")
        } else {
            check(decoded == nil, "an all-zero fingerprint was accepted")
        }
        checkMachineKeyFile(mutated([UInt8](encoded), &input))

    case 2:
        // Format 1: a real public key, so the decoder's point check passes.
        let publicKey = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
        let blob = Data(input.blob(max: 600))
        guard let encoded = encodeMachineKeyFile(.v1(publicKey: publicKey, blob: blob)) else {
            check(blob.isEmpty, "encodeMachineKeyFile refused a format 1 file")
            return
        }
        check(decodeMachineKeyFile(encoded) == .v1(publicKey: publicKey, blob: blob), "a format 1 file decodes to something else")
        checkMachineKeyFile(mutated([UInt8](encoded), &input))

    case 3:
        let blob = Data(input.blob(max: 600))
        let classical = Data(input.blob(max: 300))
        let encapsulated = Data([UInt8](repeating: input.u8(), count: input.bool() ? 1568 : Int(input.u16()) % 1700))
        let fingerprint = Data(input.fixed(input.bool() ? FINGERPRINT_LEN : Int(input.u8() % 40)))
        let stored = StoredKEK.mlkem1024(blob: blob, encapsulated: encapsulated, classicalBlob: classical)
        guard let encoded = encodeKeychainKEK(stored, fingerprint: fingerprint) else { return }
        check(decodeKeychainKEK(encoded) == KeychainKEK(stored: stored, fingerprint: fingerprint), "encodeKeychainKEK's output decodes to something else")
        checkKeychainItem(mutated([UInt8](encoded), &input))

    default:
        // Any offset, the negative and the far past the end included.
        let offset = Int(input.i16())
        let bytes = input.rest()
        guard let range = lengthPrefixedField(in: bytes, at: offset) else { return }
        check(offset >= 0 && range.lowerBound == offset + 2 && range.upperBound <= bytes.count, "lengthPrefixedField returned \(range) of \(bytes.count) bytes at \(offset)")
        check(range.count == Int(bytes[offset]) << 8 | Int(bytes[offset + 1]), "lengthPrefixedField's length is not the prefix's")
    }
}, seeds: {
    var seeds: [NamedSeed] = []
    func raw(_ name: String, _ bytes: [UInt8]) {
        seeds.append(NamedSeed(name) { $0.choice(0).rest(bytes) })
    }
    let fingerprint = [UInt8](repeating: 0xA5, count: 32)
    func v3(suite: UInt8, blob: Int, ciphertext: Int, classical: Int) -> [UInt8] {
        var out = Array("HKGK".utf8) + [3, suite] + fingerprint
        for length in [blob, ciphertext, classical] {
            out += [UInt8(length >> 8), UInt8(length & 0xFF)] + [UInt8](repeating: 0x42, count: length)
        }
        return out
    }
    let p256 = v3(suite: 1, blob: 200, ciphertext: 0, classical: 0)
    let mlkem = v3(suite: 2, blob: 300, ciphertext: 1568, classical: 200)
    raw("machine-p256", p256)
    raw("machine-mlkem", mlkem)
    raw("machine-suite-0", v3(suite: 0, blob: 200, ciphertext: 0, classical: 0))
    raw("machine-suite-3", v3(suite: 3, blob: 200, ciphertext: 1568, classical: 200))
    raw("machine-p256-with-ciphertext", v3(suite: 1, blob: 200, ciphertext: 1568, classical: 0))
    raw("machine-p256-with-classical", v3(suite: 1, blob: 200, ciphertext: 0, classical: 10))
    raw("machine-mlkem-no-classical", v3(suite: 2, blob: 300, ciphertext: 1568, classical: 0))
    raw("machine-mlkem-short-ciphertext", v3(suite: 2, blob: 300, ciphertext: 1567, classical: 200))
    raw("machine-empty-blob", v3(suite: 1, blob: 0, ciphertext: 0, classical: 0))
    raw("machine-trailing-byte", p256 + [0])
    raw("machine-zero-fingerprint", Array("HKGK".utf8) + [3, 1] + [UInt8](repeating: 0, count: 32) + Array(p256.dropFirst(38)))
    raw("machine-format-2", Array("HKGK".utf8) + [2] + Array(p256.dropFirst(5)))
    raw("machine-format-1-bad-point", Array("HKGK".utf8) + [1] + [UInt8](repeating: 4, count: 65) + [0, 4, 1, 2, 3, 4])
    raw("machine-max-size", v3(suite: 2, blob: 3000, ciphertext: 1568, classical: 3580))
    raw("machine-over-max-size", v3(suite: 2, blob: 3000, ciphertext: 1568, classical: 3581))
    raw("machine-length-past-end", Array(p256.prefix(38)) + [0xFF, 0xFF, 1, 2, 3])
    for length in [0, 4, 5, 6, 37, 38, 39, 40] {
        raw("machine-truncated-\(length)", Array(mlkem.prefix(length)))
    }
    func item(blob: Int, ciphertext: Int, classical: Int, version: UInt8 = 3, suite: UInt8 = 2) -> [UInt8] {
        var out = Array("HKGQ".utf8) + [version, suite] + fingerprint
        out += [UInt8(blob >> 8), UInt8(blob & 0xFF)] + [UInt8](repeating: 0x42, count: blob)
        out += [UInt8](repeating: 0x43, count: ciphertext)
        out += [UInt8(classical >> 8), UInt8(classical & 0xFF)] + [UInt8](repeating: 0x44, count: classical)
        return out
    }
    let genuineItem = item(blob: 300, ciphertext: 1568, classical: 200)
    raw("item-mlkem", genuineItem)
    raw("item-version-2", item(blob: 300, ciphertext: 1568, classical: 200, version: 2))
    raw("item-suite-1", item(blob: 300, ciphertext: 1568, classical: 200, suite: 1))
    raw("item-empty-blob", item(blob: 0, ciphertext: 1568, classical: 200))
    raw("item-empty-classical", item(blob: 300, ciphertext: 1568, classical: 0))
    raw("item-short-ciphertext", item(blob: 300, ciphertext: 1567, classical: 200))
    raw("item-trailing-byte", genuineItem + [0])
    raw("item-magic-only", Array("HKGQ".utf8))
    raw("item-blob-length-past-end", Array(genuineItem.prefix(38)) + [0xFF, 0xFF])
    raw("item-classical-length-past-end", Array(genuineItem.dropLast(202)) + [0xFF, 0xFF])
    for length in [5, 6, 38, 39, 40, 340, 1908, 1909, 1910] {
        raw("item-truncated-\(length)", Array(genuineItem.prefix(length)))
    }
    raw("enclave-blob-shaped", [0x04, 0x82, 0x01, 0x00] + [UInt8](repeating: 0x55, count: 256))
    raw("empty", [])
    for offset: Int16 in [0, 1, -1, -2, Int16.min, Int16.max, 3, 4] {
        seeds.append(NamedSeed("field-at-\(offset)") { $0.choice(4).i16(offset).rest([0, 2, 9, 9, 0xFF, 0xFF]) })
    }
    seeds.append(NamedSeed("encode-machine-mlkem") { $0.choice(1).bool(true).fixed(fingerprint).blob([UInt8](repeating: 1, count: 300)).bool(true).u8(7).blob([UInt8](repeating: 2, count: 200)) })
    seeds.append(NamedSeed("encode-machine-p256") { $0.choice(1).bool(false).fixed(fingerprint).blob([UInt8](repeating: 1, count: 300)).bool(true).u8(7).blob([]) })
    seeds.append(NamedSeed("encode-machine-v1") { $0.choice(2).blob([UInt8](repeating: 1, count: 300)) })
    seeds.append(NamedSeed("encode-item") { $0.choice(3).blob([UInt8](repeating: 1, count: 300)).blob([UInt8](repeating: 2, count: 200)).u8(7).bool(true).bool(true).fixed(fingerprint) })
    return seeds
})
