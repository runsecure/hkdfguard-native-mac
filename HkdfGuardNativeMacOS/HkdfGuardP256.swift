import Foundation
import CryptoKit
import Security

// MARK: - P-256 suite (0x01)
//
// The P-256 pieces of the construction in HkdfGuardNativeMacOS.swift: the
// RFC 9380 hash of a payload's salt to the point the Secure Enclave does
// ECDH against, the KEK fingerprint, and the enclave probe machine scope
// uses. The suite-independent payload code (`KEK`, `sealDek`,
// `openPayload`) stays in HkdfGuardNativeMacOS.swift.

/// The salt-to-point hash's RFC 9380 domain separation tag, byte for byte
/// the Linux library's (PAYLOAD_POINT_DST_PREFIX || the suite ID).
/// Payloads are host-only, so nothing requires the label to match; matching
/// keeps the three implementations reviewable as one design.
private let hkdfguardPayloadPointDST = Data("HkdfGuard-payload-ECDH-point-V01-CS01-with-P256_XMD:SHA-256_SSWU_RO_".utf8)

/// Hashes `salt` to a P-256 point with RFC 9380 `hash_to_curve`, suite
/// `P256_XMD:SHA-256_SSWU_RO_`, under `hkdfguardPayloadPointDST`.
///
/// Why: the wrapping key comes from `ECDH(KEK_priv, H)`. Nobody knows the
/// discrete log of a hash output, so computing it takes the KEK's private
/// key, which never leaves the Secure Enclave -- only this host can create
/// a payload, as well as open one. An ephemeral sender key (HPKE base mode,
/// ECIES) would let anyone holding the KEK's *public* key derive the same
/// secret and mint a payload carrying a DEK of their choosing. One point
/// per payload, rather than one fixed point, makes the shared secret unique
/// to the payload: capturing it once opens that payload, not the service's
/// whole history.
///
/// Nil only if the hash lands on the point at infinity (probability about
/// 2^-256), which must never be handed to ECDH.
func payloadECDHPoint(salt: Data) -> P256.KeyAgreement.PublicKey? {
    hashToCurveP256(message: salt, dst: hkdfguardPayloadPointDST)
}

/// RFC 9380 section 3 `hash_to_curve` for `P256_XMD:SHA-256_SSWU_RO_`:
/// expand the message to two field elements, map each with simplified SWU,
/// and add the two points. P-256 has cofactor 1, so there is no cofactor to
/// clear. Internal so the tests can run the RFC's own vectors (Appendix
/// J.1.1) through it.
///
/// CryptoKit has no public hash-to-curve, so `P256Field` does the
/// arithmetic. Not constant-time, and need not be: the salt is public.
/// CryptoKit validates the result when it becomes a public key.
func hashToCurveP256(message: Data, dst: Data) -> P256.KeyAgreement.PublicKey? {
    guard dst.count <= 255 else {
        return nil
    }
    let uniform = [UInt8](expandMessageXMD(message: message, dst: dst, length: 96))
    let u0 = P256Field.reduce(uniform[0..<48])
    let u1 = P256Field.reduce(uniform[48..<96])
    guard let sum = P256Field.addPoints(P256Field.mapToCurveSSWU(u0), P256Field.mapToCurveSSWU(u1)) else {
        return nil
    }
    var x963 = Data([0x04])
    x963.append(contentsOf: sum.x.bigEndianBytes)
    x963.append(contentsOf: sum.y.bigEndianBytes)
    return try? P256.KeyAgreement.PublicKey(x963Representation: x963)
}

/// RFC 9380 section 5.3.1 `expand_message_xmd` with SHA-256 (b = 32 bytes,
/// block size 64). `dst` must be at most 255 bytes and `length` at most
/// 8160; the one caller passes a fixed DST and 96.
func expandMessageXMD(message: Data, dst: Data, length: Int) -> Data {
    var dstPrime = dst
    dstPrime.append(UInt8(dst.count))
    var hasher = SHA256()
    hasher.update(data: Data(count: 64)) // Z_pad: one block of zeros
    hasher.update(data: message)
    hasher.update(data: [UInt8(length >> 8), UInt8(length & 0xFF), 0]) // l_i_b_str || I2OSP(0, 1)
    hasher.update(data: dstPrime)
    let b0 = [UInt8](hasher.finalize())
    var bi = [UInt8](SHA256.hash(data: b0 + [1] + dstPrime))
    var out = bi
    for i in stride(from: 2, through: (length + 31) / 32, by: 1) {
        bi = [UInt8](SHA256.hash(data: zip(b0, bi).map { $0 ^ $1 } + [UInt8(i)] + dstPrime))
        out += bi
    }
    return Data(out.prefix(length))
}

/// Arithmetic in P-256's base field, GF(p) with p = 2^256 - 2^224 + 2^192 +
/// 2^96 - 1, and on the curve y^2 = x^3 - 3x + b over it: just what
/// `hashToCurveP256` needs. Elements are kept fully reduced, in plain (not
/// Montgomery) form; `mul` uses Montgomery multiplication internally.
enum P256Field {
    /// A field element: four 64-bit limbs, least significant first, < p.
    struct Element: Equatable {
        var limbs: [UInt64]

        init(_ limbs: [UInt64]) {
            self.limbs = limbs
        }

        /// From big-endian bytes (at most 32) that encode a value below p.
        init<C: Collection>(bigEndian bytes: C) where C.Element == UInt8 {
            let padded = [UInt8](repeating: 0, count: 32 - bytes.count) + bytes
            limbs = (0..<4).map { i in
                padded[(24 - 8 * i)..<(32 - 8 * i)].reduce(0) { $0 << 8 | UInt64($1) }
            }
        }

        var bigEndianBytes: [UInt8] {
            limbs.reversed().flatMap { limb in (0..<8).reversed().map { UInt8(truncatingIfNeeded: limb >> (8 * $0)) } }
        }

        var isZero: Bool { limbs.allSatisfy { $0 == 0 } }

        /// RFC 9380 section 4.1 sgn0 for a prime field: x mod 2.
        var sgn0: Bool { limbs[0] & 1 == 1 }

        static func >= (a: Element, b: Element) -> Bool {
            for i in (0..<4).reversed() where a.limbs[i] != b.limbs[i] {
                return a.limbs[i] > b.limbs[i]
            }
            return true
        }
    }

    // Constants as limbs, least significant first.
    static let p = Element([0xffffffffffffffff, 0x00000000ffffffff, 0x0000000000000000, 0xffffffff00000001])
    static let b = Element([0x3bce3c3e27d2604b, 0x651d06b0cc53b0f6, 0xb3ebbd55769886bc, 0x5ac635d8aa3a93e7])
    /// 2^512 mod p: a Montgomery multiplication by it converts back to plain form.
    private static let r2 = Element([0x0000000000000003, 0xfffffffbffffffff, 0xfffffffffffffffe, 0x00000004fffffffd])
    private static let pMinus2 = Element([0xfffffffffffffffd, 0x00000000ffffffff, 0x0000000000000000, 0xffffffff00000001])
    private static let pPlus1Over4 = Element([0x0000000000000000, 0x0000000040000000, 0x4000000000000000, 0x3fffffffc0000000])
    private static let pMinus1Over2 = Element([0xffffffffffffffff, 0x000000007fffffff, 0x8000000000000000, 0x7fffffff80000000])
    static let zero = Element([0, 0, 0, 0])
    static let one = Element([1, 0, 0, 0])
    private static let three = Element([3, 0, 0, 0])
    private static let a = neg(three) // the curve's a = -3
    private static let z = neg(Element([10, 0, 0, 0])) // the suite's SSWU Z = -10

    /// acc + x * y + carry, as (low word, high word); never overflows 128 bits.
    private static func mulAdd(_ acc: UInt64, _ x: UInt64, _ y: UInt64, _ carry: UInt64) -> (UInt64, UInt64) {
        let (high, low) = x.multipliedFullWidth(by: y)
        let (s1, o1) = low.addingReportingOverflow(acc)
        let (s2, o2) = s1.addingReportingOverflow(carry)
        return (s2, high &+ (o1 ? 1 : 0) &+ (o2 ? 1 : 0))
    }

    /// a - b over 256 bits, and whether it borrowed.
    private static func subtractLimbs(_ a: Element, _ b: Element) -> (Element, Bool) {
        var out = [UInt64](repeating: 0, count: 4)
        var borrow = false
        for i in 0..<4 {
            let (d1, b1) = a.limbs[i].subtractingReportingOverflow(b.limbs[i])
            let (d2, b2) = d1.subtractingReportingOverflow(borrow ? 1 : 0)
            out[i] = d2
            borrow = b1 || b2
        }
        return (Element(out), borrow)
    }

    /// a + b over 256 bits, and whether it carried.
    private static func addLimbs(_ a: Element, _ b: Element) -> (Element, Bool) {
        var out = [UInt64](repeating: 0, count: 4)
        var carry = false
        for i in 0..<4 {
            let (s1, c1) = a.limbs[i].addingReportingOverflow(b.limbs[i])
            let (s2, c2) = s1.addingReportingOverflow(carry ? 1 : 0)
            out[i] = s2
            carry = c1 || c2
        }
        return (Element(out), carry)
    }

    static func add(_ a: Element, _ b: Element) -> Element {
        let (sum, carried) = addLimbs(a, b)
        return carried || sum >= p ? subtractLimbs(sum, p).0 : sum
    }

    static func sub(_ a: Element, _ b: Element) -> Element {
        let (difference, borrowed) = subtractLimbs(a, b)
        return borrowed ? addLimbs(difference, p).0 : difference
    }

    static func neg(_ a: Element) -> Element {
        sub(zero, a)
    }

    /// a * b * 2^-256 mod p (CIOS Montgomery multiplication). p's low limb
    /// is 2^64 - 1, so -p^-1 mod 2^64 is 1 and each round's m is just t[0].
    private static func montgomeryMul(_ a: Element, _ b: Element) -> Element {
        var t = [UInt64](repeating: 0, count: 6)
        for i in 0..<4 {
            var carry: UInt64 = 0
            for j in 0..<4 {
                (t[j], carry) = mulAdd(t[j], a.limbs[j], b.limbs[i], carry)
            }
            (t[4], carry) = mulAdd(t[4], 0, 0, carry)
            t[5] = carry
            let m = t[0]
            (_, carry) = mulAdd(t[0], m, p.limbs[0], 0)
            for j in 1..<4 {
                (t[j - 1], carry) = mulAdd(t[j], m, p.limbs[j], carry)
            }
            (t[3], carry) = mulAdd(t[4], 0, 0, carry)
            t[4] = t[5] &+ carry
        }
        let result = Element(Array(t[0..<4]))
        return t[4] != 0 || result >= p ? subtractLimbs(result, p).0 : result
    }

    static func mul(_ a: Element, _ b: Element) -> Element {
        montgomeryMul(montgomeryMul(a, b), r2) // (a * b / R) * R^2 / R = a * b
    }

    static func pow(_ base: Element, _ exponent: Element) -> Element {
        var result = one
        for limb in exponent.limbs.reversed() {
            for bit in (0..<64).reversed() {
                result = mul(result, result)
                if (limb >> UInt64(bit)) & 1 == 1 {
                    result = mul(result, base)
                }
            }
        }
        return result
    }

    /// RFC 9380 inv0: the inverse, with 0 mapping to 0 (Fermat: a^(p-2)).
    static func inv0(_ a: Element) -> Element {
        pow(a, pMinus2)
    }

    /// Euler's criterion: a^((p-1)/2) is 1 for a nonzero square, 0 for 0.
    static func isSquare(_ a: Element) -> Bool {
        let legendre = pow(a, pMinus1Over2)
        return legendre == one || legendre == zero
    }

    /// RFC 9380 Appendix F.2's sqrt for p = 3 mod 4: a^((p+1)/4). Only
    /// meaningful when `isSquare(a)`.
    static func sqrt(_ a: Element) -> Element {
        pow(a, pPlus1Over4)
    }

    /// A 48-byte big-endian integer (RFC 9380 section 5.2's L = 48) mod p:
    /// high * 2^256 + low, where a Montgomery multiplication of `high` by
    /// R^2 gives high * 2^256 mod p.
    static func reduce(_ bytes: ArraySlice<UInt8>) -> Element {
        let high = Element(bigEndian: bytes.prefix(16))
        var low = Element(bigEndian: bytes.suffix(32))
        if low >= p {
            low = subtractLimbs(low, p).0 // low < 2^256 < 2p
        }
        return add(montgomeryMul(high, r2), low)
    }

    /// x^3 + a x + b.
    private static func curveRHS(_ x: Element) -> Element {
        add(add(mul(mul(x, x), x), mul(a, x)), b)
    }

    /// RFC 9380 section 6.6.2 simplified SWU map, straight-line as written
    /// there (not the optimized Appendix F.2 form).
    static func mapToCurveSSWU(_ u: Element) -> (x: Element, y: Element) {
        let zu2 = mul(z, mul(u, u))
        let tv1 = inv0(add(mul(zu2, zu2), zu2)) // 1 / (Z^2 u^4 + Z u^2)
        let x1 = tv1.isZero
            ? mul(b, inv0(mul(z, a))) // B / (Z A)
            : mul(mul(b, inv0(three)), add(one, tv1)) // (-B / A) (1 + tv1), with -B / A = B / 3
        let gx1 = curveRHS(x1)
        let x: Element
        var y: Element
        if isSquare(gx1) {
            (x, y) = (x1, sqrt(gx1))
        } else {
            x = mul(zu2, x1)
            y = sqrt(curveRHS(x))
        }
        if u.sgn0 != y.sgn0 {
            y = neg(y)
        }
        return (x, y)
    }

    /// Affine point addition; nil for the point at infinity.
    static func addPoints(_ p1: (x: Element, y: Element), _ p2: (x: Element, y: Element)) -> (x: Element, y: Element)? {
        let slope: Element
        if p1.x == p2.x {
            guard p1.y == p2.y, !p1.y.isZero else {
                return nil // P + (-P)
            }
            let x2 = mul(p1.x, p1.x)
            slope = mul(add(add(add(x2, x2), x2), a), inv0(add(p1.y, p1.y))) // (3x^2 + a) / 2y
        } else {
            slope = mul(sub(p2.y, p1.y), inv0(sub(p2.x, p1.x)))
        }
        let x3 = sub(sub(mul(slope, slope), p1.x), p2.x)
        let y3 = sub(mul(slope, sub(p1.x, x3)), p1.y)
        return (x3, y3)
    }
}

/// Computes the "fingerprint" embedded at the front of every wrapped
/// payload: a SHA-256 hash of the KEK's public key, uncompressed X9.63
/// (0x04 || x || y).
/// Not a secret value — the public key it hashes isn't secret either —
/// so the explicit equality check against it in `hkdfguard_unwrap_dek`
/// exists purely to fail fast, cheaply, on "this payload wasn't wrapped
/// under the KEK I just resolved for this service" *before* spending any
/// effort on ECDH/AES-GCM. It is also in the authenticated header (see
/// `wrapDekCore`), so the derived key and the tag commit to it too.
func kekFingerprint(_ publicKey: P256.KeyAgreement.PublicKey) -> Data {
    Data(SHA256.hash(data: publicKey.x963Representation))
}

/// Whether `key` can do a key agreement now, and gets the answer its
/// public key predicts.
func keyAgreementWorks(_ key: SecureEnclave.P256.KeyAgreement.PrivateKey) -> Bool {
    let peer = P256.KeyAgreement.PrivateKey()
    guard let ours = try? key.sharedSecretFromKeyAgreement(with: peer.publicKey),
          let theirs = try? peer.sharedSecretFromKeyAgreement(with: key.publicKey) else {
        return false
    }
    return ours == theirs
}
