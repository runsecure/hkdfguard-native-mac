import Foundation
import CryptoKit
import Security
import os // Logger interpolation in createMLKEMKEK

// MARK: - ML-KEM-1024 suite (0x02)
//
// The ML-KEM-1024 KEK: its sizes, the stored-ciphertext KEK type, and
// generating, rebuilding and provisioning one in the Secure Enclave. The
// suite-independent payload code (`KEK`, `sealDek`, `openPayload`) stays in
// HkdfGuardNativeMacOS.swift.

/// ML-KEM-1024 sizes (FIPS 203): the encapsulation key and the ciphertext
/// are both 1568 bytes.
let mlkem1024PublicKeyLength = 1568
let mlkem1024CiphertextLength = 1568

/// An ML-KEM KEK: the Secure Enclave key, and the ciphertext encapsulated to
/// it once, at provisioning. Decapsulating that ciphertext is the only way
/// back to the secret `K` every payload's key is derived from, and it takes
/// the enclave: the public key and the ciphertext together don't give `K`,
/// to a classical or a quantum attacker, so neither needs to stay secret.
///
/// `K` is one secret per KEK, not one per payload as the P-256 suite's
/// shared secret is: capturing it from memory opens every payload under
/// this KEK, and lets its holder create new ones, until the KEK is retired.
/// That is the price of keeping the payload at 125 bytes.
///
/// `key` is any `KEMPrivateKey` so tests can use a software ML-KEM key;
/// production keys are always `SecureEnclave.MLKEM1024.PrivateKey`.
struct KEMKEK {
    let key: any KEMPrivateKey
    /// The ML-KEM-1024 encapsulation key, raw; only ever fingerprinted.
    let publicKey: Data
    let encapsulated: Data
}

/// Generates an ML-KEM-1024 KEK in the Secure Enclave under `access`, and
/// encapsulates to it once. Returns it with the enclave blob to store; nil
/// if the enclave refuses, or if decapsulating doesn't give back the secret
/// just encapsulated. The secret itself is dropped here (best effort:
/// CryptoKit's `SymmetricKey` can't be zeroed), so from now on only the
/// enclave can recover it.
@available(macOS 26.0, *)
func newMLKEM1024KEK(accessControl access: SecAccessControl) -> (kek: KEMKEK, blob: Data)? {
    guard let key = try? SecureEnclave.MLKEM1024.PrivateKey(accessControl: access),
          let encapsulation = try? key.publicKey.encapsulate(),
          encapsulation.encapsulated.count == mlkem1024CiphertextLength,
          (try? key.decapsulate(encapsulation.encapsulated)) == encapsulation.sharedSecret else {
        return nil
    }
    let kek = KEMKEK(key: key, publicKey: key.publicKey.rawRepresentation, encapsulated: encapsulation.encapsulated)
    return (kek, key.dataRepresentation)
}

/// Rebuilds a stored ML-KEM-1024 KEK from its enclave blob and its
/// ciphertext, or nil if the blob isn't a key the enclave will load or the
/// ciphertext is the wrong size.
@available(macOS 26.0, *)
func reconstructMLKEM1024KEK(blob: Data, encapsulated: Data) -> KEMKEK? {
    guard encapsulated.count == mlkem1024CiphertextLength,
          let key = try? SecureEnclave.MLKEM1024.PrivateKey(dataRepresentation: blob) else {
        return nil
    }
    return KEMKEK(key: key, publicKey: key.publicKey.rawRepresentation, encapsulated: encapsulated)
}

/// Creates an ML-KEM-1024 KEK under `access`. Where this Mac's Secure
/// Enclave can't -- a macOS before 26, or an enclave that makes P-256 keys
/// under the same policy but not ML-KEM ones -- that is
/// `enclaveUnavailable`, logged: provisioning never falls back to P-256 on
/// its own, only through the policy's `KekSuite`. Any other refusal is
/// `keyGenerationFailed`.
func createMLKEMKEK(
    accessControl access: SecAccessControl,
    service: String
) -> (status: Int32, created: (kek: KEMKEK, blob: Data)?) {
    if !MachineScopeTestOverrides.withoutMLKEM, #available(macOS 26.0, *),
       let created = newMLKEM1024KEK(accessControl: access) {
        return (HKDFGuardStatus.success.rawValue, created)
    }
    guard (try? SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)) != nil else {
        return (HKDFGuardStatus.keyGenerationFailed.rawValue, nil)
    }
    machineLog.error("\(service, privacy: .public): this Mac's Secure Enclave can't create an ML-KEM-1024 KEK (that needs macOS 26 or later); to provision a classical P-256 KEK instead, set KekSuite to P-256 in the hkdfguard policy")
    return (HKDFGuardStatus.enclaveUnavailable.rawValue, nil)
}
