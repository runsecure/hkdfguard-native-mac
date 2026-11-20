//
//  HkdfGuardKEK.swift
//  HkdfGuardNativeMacOS
//
//  The KEK types -- P-256, and the ML-KEM-1024 hybrid -- and how each
//  derives a payload's wrapping key.
//

import Foundation
import CryptoKit
import Security

// MARK: - KEKs

/// ML-KEM-1024 sizes (FIPS 203): the encapsulation key and the ciphertext
/// are both 1568 bytes.
let mlkem1024PublicKeyLength = 1568
let mlkem1024CiphertextLength = 1568

/// A P-256 key that can do a key agreement: a Secure Enclave key in
/// production, a software one in tests.
protocol KeyAgreementKey {
    var publicKey: P256.KeyAgreement.PublicKey { get }
    func sharedSecretFromKeyAgreement(with publicKeyShare: P256.KeyAgreement.PublicKey) throws -> SharedSecret
}
extension SecureEnclave.P256.KeyAgreement.PrivateKey: KeyAgreementKey {}

/// A suite 0x02 KEK, a hybrid of two Secure Enclave keys:
///
/// - an ML-KEM-1024 key, and the ciphertext encapsulated to it once, at
///   provisioning. Decapsulating that ciphertext is the only way back to
///   the secret `K`, and it takes the enclave: the public key and the
///   ciphertext together don't give `K`, to a classical or a quantum
///   attacker, so neither needs to stay secret.
/// - a P-256 key (`classical`), used exactly as suite 0x01 uses its KEK:
///   one key agreement per payload, with a point hashed from the payload's
///   salt.
///
/// Every payload's key is derived from both (see `KEK.wrappingKey`). `K` is
/// one secret per KEK -- that is what keeps the payload at 125 bytes -- so
/// on its own, capturing it from memory once would open every payload
/// under the KEK and let its holder mint new ones, offline, for good. The
/// P-256 half is what prevents that: its secret is per payload and takes
/// the enclave each time, so a captured `K` opens nothing without this
/// Mac's enclave, as with suite 0x01. The ML-KEM half is what a quantum
/// attacker, who can recover the P-256 private key from its public key,
/// still can't get past.
///
/// The ciphertext is part of the KEK's identity: the same enclave keys with
/// another ciphertext have another `K`. The fingerprint covers both public
/// keys and the ciphertext, so one that was swapped or damaged in storage
/// shows up as a different KEK -- to a payload's fingerprint check, to an
/// operator's recorded fingerprint, and to the fingerprint the store
/// records -- rather than as a KEK of the same name that quietly derives
/// other keys. (ML-KEM decapsulation never fails on a wrong ciphertext; it
/// returns a different secret.) The fingerprint is in every payload's
/// header, so all three are bound into each payload's key and tag.
///
/// `key` and `classical` are protocol types so tests can use software
/// keys; production keys are always the Secure Enclave's.
struct KEMKEK {
    let key: any KEMPrivateKey
    /// The ML-KEM-1024 encapsulation key, raw; only ever fingerprinted.
    let publicKey: Data
    let encapsulated: Data
    let classical: any KeyAgreementKey

    /// SHA-256 of the ML-KEM public key, the stored ciphertext, and the
    /// P-256 public key (uncompressed x963). All three are fixed-length
    /// (1568, 1568, 65), so the split is unambiguous.
    var fingerprint: Data {
        var hash = SHA256()
        hash.update(data: publicKey)
        hash.update(data: encapsulated)
        hash.update(data: classical.publicKey.x963Representation)
        return Data(hash.finalize())
    }
}

/// A service's KEK, whichever suite it is.
enum KEK {
    case p256(SecureEnclave.P256.KeyAgreement.PrivateKey)
    case mlkem1024(KEMKEK)

    /// The suite every payload wrapped under this KEK names.
    var suite: KEKSuite {
        switch self {
        case .p256: return .p256HashedPoint
        case .mlkem1024: return .mlkem1024StoredCiphertext
        }
    }

    /// The fingerprint at the front of every payload: SHA-256 of the public
    /// key (see `kekFingerprint`) or, for suite 0x02, of both public keys
    /// and the stored ciphertext (see `KEMKEK`). The suite 0x02 input is
    /// 3201 bytes and the P-256 one 65, so the two kinds can't produce the
    /// same fingerprint.
    var fingerprint: Data {
        switch self {
        case .p256(let key): return kekFingerprint(key.publicKey)
        case .mlkem1024(let kem): return kem.fingerprint
        }
    }

    /// The AES-256 wrapping key for one payload: HKDF-SHA512 (salt = the
    /// payload salt, `info` = `wrappingKeyInfo`) over a secret only the
    /// Secure Enclave can compute -- `ECDH(KEK_priv, payloadECDHPoint(salt))`
    /// for P-256. Suite 0x02 chains two: that same per-payload derivation
    /// from its P-256 key gives 64 bytes, which then salt HKDF-SHA512 over
    /// the decapsulated `K` (same `info`). HKDF-Extract is HMAC keyed by
    /// its salt, so the result is secret while either input is -- the
    /// combination TLS 1.3's key schedule uses. The shared secrets stay
    /// inside CryptoKit's `SharedSecret` and `SymmetricKey`; none becomes a
    /// buffer here. The header holds the suite byte, so the two suites'
    /// keys are separated through `info`. Throws if the enclave refuses
    /// (CRYPTO_ERROR); nil only if the salt hashes to the point at infinity.
    func wrappingKey(service: String, header: Data) throws -> SymmetricKey? {
        let salt = header[hkdfguardSaltOffset..<hkdfguardNonceOffset]
        let info = wrappingKeyInfo(service: service, header: header)
        switch self {
        case .p256(let key):
            guard let point = payloadECDHPoint(salt: Data(salt)) else {
                return nil
            }
            let shared = try key.sharedSecretFromKeyAgreement(with: point)
            return shared.hkdfDerivedSymmetricKey(using: SHA512.self, salt: salt, sharedInfo: info, outputByteCount: 32)
        case .mlkem1024(let kem):
            guard let point = payloadECDHPoint(salt: Data(salt), suite: .mlkem1024StoredCiphertext) else {
                return nil
            }
            let shared = try kem.classical.sharedSecretFromKeyAgreement(with: point)
            let perPayload = shared.hkdfDerivedSymmetricKey(using: SHA512.self, salt: salt, sharedInfo: info, outputByteCount: 64)
            let secret = try kem.key.decapsulate(kem.encapsulated)
            return perPayload.withUnsafeBytes { perPayloadBytes in
                HKDF<SHA512>.deriveKey(inputKeyMaterial: secret, salt: perPayloadBytes, info: info, outputByteCount: 32)
            }
        }
    }
}

/// Generates a suite 0x02 KEK in the Secure Enclave under `access`: an
/// ML-KEM-1024 key, encapsulated to once, and a P-256 key. Returns it with
/// what to store; nil if the enclave refuses, or if decapsulating doesn't
/// give back the secret just encapsulated. The secret itself is dropped
/// here (best effort: CryptoKit's `SymmetricKey` can't be zeroed), so from
/// now on only the enclave can recover it.
@available(macOS 26.0, *)
func newMLKEM1024KEK(accessControl access: SecAccessControl) -> (kek: KEMKEK, stored: StoredKEK)? {
    guard let key = try? SecureEnclave.MLKEM1024.PrivateKey(accessControl: access),
          let encapsulation = try? key.publicKey.encapsulate(),
          encapsulation.encapsulated.count == mlkem1024CiphertextLength,
          (try? key.decapsulate(encapsulation.encapsulated)) == encapsulation.sharedSecret,
          let classical = try? SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access) else {
        return nil
    }
    let kek = KEMKEK(key: key, publicKey: key.publicKey.rawRepresentation,
                     encapsulated: encapsulation.encapsulated, classical: classical)
    return (kek, .mlkem1024(blob: key.dataRepresentation, encapsulated: encapsulation.encapsulated,
                            classicalBlob: classical.dataRepresentation))
}

/// Rebuilds a stored suite 0x02 KEK from its two enclave blobs and its
/// ciphertext, or nil if either blob isn't a key the enclave will load or
/// the ciphertext is the wrong size.
@available(macOS 26.0, *)
func reconstructMLKEM1024KEK(blob: Data, encapsulated: Data, classicalBlob: Data) -> KEMKEK? {
    guard encapsulated.count == mlkem1024CiphertextLength,
          let key = try? SecureEnclave.MLKEM1024.PrivateKey(dataRepresentation: blob),
          let classical = try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: classicalBlob) else {
        return nil
    }
    return KEMKEK(key: key, publicKey: key.publicKey.rawRepresentation, encapsulated: encapsulated, classical: classical)
}

func randomBytes(_ count: Int) -> Data? {
    var bytes = Data(count: count)
    let status = bytes.withUnsafeMutableBytes { raw -> OSStatus in
        guard let base = raw.baseAddress else { return errSecParam }
        return SecRandomCopyBytes(kSecRandomDefault, count, base)
    }
    return status == errSecSuccess ? bytes : nil
}
