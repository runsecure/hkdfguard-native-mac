//
//  Pure.swift -- fuzz targets `hash_to_curve` and `audit_quote`
//
//  Two functions of bytes alone.
//
//  hash_to_curve: hashToCurveP256 -- what turns a payload's salt into its
//  ECDH point -- on any message and domain separation tag, and
//  expandMessageXMD at every length it is specified for. The point is
//  valid, the same every time, and different for another message or tag;
//  the expansion is the length asked for and a prefix-free function of it.
//
//  audit_quote: auditQuote, which puts a caller's bytes (a path) into an
//  audit record. Whatever the bytes, the result is one double-quoted run of
//  printable ASCII with no quote, backslash or control character of its
//  own, so no value can end its field or forge a second record -- and it
//  decodes back to exactly the bytes.
//

import Foundation
import CryptoKit

let hashToCurveTarget = FuzzTarget(name: "hash_to_curve", run: { data in
    var input = FuzzInput(data)
    let length = Int(input.u16()) % 8161 // the most RFC 9380 allows for SHA-256
    let dst = Data(input.blob(max: 300))
    let message = Data(input.rest())

    let point = hashToCurveP256(message: message, dst: dst)
    if dst.count > 255 {
        check(point == nil, "hashToCurveP256 accepted a \(dst.count)-byte tag")
    } else {
        guard let point else {
            finding("hashToCurveP256 gave no point: the point at infinity, with probability 2^-256, or a bug")
        }
        let encoded = point.x963Representation
        check(encoded.count == 65 && encoded.first == 0x04, "the point is not an uncompressed P-256 point")
        check((try? P256.KeyAgreement.PublicKey(x963Representation: encoded)) != nil, "the point is not on the curve")
        // One of three more hashes per input, by its length: each is slow.
        switch data.count % 3 {
        case 0:
            check(hashToCurveP256(message: message, dst: dst)?.x963Representation == encoded, "hashToCurveP256 is not a function of its input")
        case 1:
            check(hashToCurveP256(message: message + [0], dst: dst)?.x963Representation != encoded, "a longer message hashed to the same point")
        default:
            if dst.count < 255 {
                check(hashToCurveP256(message: message, dst: dst + [0])?.x963Representation != encoded, "another tag hashed to the same point")
            }
        }
        // A key agreement with it works: what a payload's key needs.
        check((try? P256.KeyAgreement.PrivateKey().sharedSecretFromKeyAgreement(with: point)) != nil, "ECDH refused the point")

        let expanded = expandMessageXMD(message: message, dst: dst, length: length)
        check(expanded.count == length, "expandMessageXMD returned \(expanded.count) bytes for \(length)")
        if length > 0 && length < 8160 {
            // The length is hashed in: a longer output is not an extension.
            let longer = expandMessageXMD(message: message, dst: dst, length: length + 1)
            check(longer.count == length + 1 && longer.prefix(length) != expanded, "expandMessageXMD's output for \(length + 1) extends its output for \(length)")
        }
    }
}, seeds: {
    var seeds: [NamedSeed] = []
    func add(_ name: String, length: Int = 96, dst: [UInt8], message: [UInt8]) {
        seeds.append(NamedSeed(name) { $0.u16(UInt16(length)).blob(dst).rest(message) })
    }
    let tag = Array("HkdfGuard-payload-ECDH-point-V01-CS01-with-P256_XMD:SHA-256_SSWU_RO_".utf8)
    // RFC 9380 appendix J.1.1's tag and messages.
    let rfc = Array("QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_".utf8)
    for (name, message) in [("empty", ""), ("abc", "abc"), ("abcdef", "abcdef0123456789"), ("q128", "q128_" + String(repeating: "q", count: 128))] {
        add("rfc-\(name)", dst: rfc, message: Array(message.utf8))
    }
    for length in [0, 1, 31, 32, 33, 48, 64, 96, 255, 256, 8159, 8160] {
        add("expand-\(length)", length: length, dst: tag, message: [UInt8](repeating: 0x5A, count: 32))
    }
    for count in [0, 1, 254, 255, 256, 300] {
        add("tag-\(count)", dst: [UInt8](repeating: 0x41, count: count), message: [1, 2, 3])
    }
    add("salt-zeros", dst: tag, message: [UInt8](repeating: 0, count: 32))
    add("salt-ones", dst: tag, message: [UInt8](repeating: 0xFF, count: 32))
    add("long-message", dst: tag, message: [UInt8](repeating: 0x61, count: 1000))
    return seeds
})

/// auditQuote's inverse, written from its description.
private func unquote(_ text: String) -> [UInt8]? {
    let bytes = Array(text.utf8)
    guard bytes.count >= 2, bytes.first == 0x22, bytes.last == 0x22 else { return nil }
    var out: [UInt8] = []
    var index = 1
    while index < bytes.count - 1 {
        let byte = bytes[index]
        guard byte >= 0x20, byte < 0x7F, byte != 0x22 else { return nil }
        if byte == 0x5C {
            guard index + 3 < bytes.count - 1 || index + 3 == bytes.count - 2, bytes[index + 1] == UInt8(ascii: "x"),
                  let value = UInt8(String(decoding: bytes[(index + 2)...(index + 3)], as: UTF8.self), radix: 16) else { return nil }
            out.append(value)
            index += 4
        } else {
            out.append(byte)
            index += 1
        }
    }
    return out
}

let auditQuoteTarget = FuzzTarget(name: "audit_quote", run: { data in
    let quoted = auditQuote(data)
    guard let back = unquote(quoted) else {
        finding("auditQuote wrote a field that is not one quoted run of printable ASCII: \(quoted)")
    }
    check(back == data, "auditQuote's field decodes to other bytes than it was given")
    // And a whole record with these bytes in it is still one line.
    setup()
    auditCapture.withLock { $0 = [] }
    auditPlaintextKeyFile(path: data)
    let records = auditCapture.withLock { captured -> [String] in
        defer { captured = nil }
        return captured ?? []
    }
    check(records.count == 1, "one audit call wrote \(records.count) records")
    for record in records {
        check(!record.utf8.contains { $0 < 0x20 || $0 >= 0x7F }, "an audit record holds a control or non-ASCII byte: \(record)")
    }
}, seeds: {
    var seeds: [NamedSeed] = []
    func add(_ name: String, _ bytes: [UInt8]) {
        seeds.append(NamedSeed(name) { $0.rest(bytes) })
    }
    add("empty", [])
    add("path", Array("/Library/Application Support/HkdfGuard/key.bin".utf8))
    add("quote", Array("a\"b".utf8))
    add("backslash", Array("a\\b".utf8))
    add("escape-lookalike", Array("\\x22 msg=\"forged\"".utf8))
    add("newline-forged-record", Array("x\nevent=1 service=\"other\"".utf8))
    add("carriage-return", Array("x\r\n".utf8))
    add("nul", [0x61, 0, 0x62])
    add("del", [0x7F])
    add("high-bytes", [0x80, 0xFF, 0xC3, 0xA9])
    add("escape-sequence", [0x1B, 0x5B, 0x32, 0x4A])
    add("every-byte", (0...255).map { UInt8($0) })
    return seeds
})
