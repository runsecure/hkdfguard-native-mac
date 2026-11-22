//
//  FuzzKEKStore.swift
//  hkdfguard fuzz build only
//
//  Where the fuzz build keeps user-scoped KEKs: in memory, as software keys.
//  The library reaches it through its three `#if HKDFGUARD_FUZZING` branches
//  (HkdfGuardKeychain.swift), in place of the keychain lookup and the Secure
//  Enclave; everything above those branches -- argument checks, the policy,
//  the scope of a service, the payload format, the key derivation, AES-GCM --
//  is the code that ships. So the harnesses need no keychain, leave nothing
//  in the developer's, and run on a VM without a Secure Enclave.
//
//  Never compiled into the library that ships: this file is outside
//  HkdfGuardNativeMacOS/, and only fuzz/build.sh defines HKDFGUARD_FUZZING.
//

import Foundation
import CryptoKit

/// A software P-256 key in place of the enclave's, as the unit tests use.
extension P256.KeyAgreement.PrivateKey: KeyAgreementKey {}

enum FuzzKEKStore {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var keks: [String: KEK] = [:]

    /// `getKEK`'s answer for a user-scoped service.
    static func get(service: String) -> (status: Int32, key: KEK?) {
        lock.lock()
        defer { lock.unlock() }
        guard let kek = keks[service] else {
            return (HKDFGuardStatus.kekNotFound.rawValue, nil)
        }
        return (HKDFGuardStatus.success.rawValue, kek)
    }

    /// `kekExists`'s answer for a user-scoped service.
    static func exists(service: String) -> (status: Int32, exists: Bool) {
        lock.lock()
        defer { lock.unlock() }
        return (HKDFGuardStatus.success.rawValue, keks[service] != nil)
    }

    /// `createKEK`'s answer for a user-scoped service: idempotent, and one
    /// KEK however many threads race to make it. Only the ML-KEM-1024 hybrid
    /// can be a software key (`KEK.p256` holds an enclave key by type), so a
    /// policy asking for P-256 gets what a Mac that can't make the suite
    /// asked for gives: PROVIDER_UNAVAILABLE, never the other suite.
    static func create(service: String, suites: SuitePolicy) -> Int32 {
        lock.lock()
        defer { lock.unlock() }
        if let existing = keks[service] {
            return suiteRefusal(existing, suites, service: service) ?? HKDFGuardStatus.success.rawValue
        }
        guard suites.provisionSuite == .mlkem1024StoredCiphertext else {
            return HKDFGuardStatus.enclaveUnavailable.rawValue
        }
        guard let key = try? MLKEM1024.PrivateKey(),
              let encapsulation = try? key.publicKey.encapsulate() else {
            return HKDFGuardStatus.keyGenerationFailed.rawValue
        }
        keks[service] = .mlkem1024(KEMKEK(
            key: key, publicKey: key.publicKey.rawRepresentation,
            encapsulated: encapsulation.encapsulated, classical: P256.KeyAgreement.PrivateKey()))
        return HKDFGuardStatus.success.rawValue
    }

    /// Forgets every KEK but `service`'s: for a harness that creates KEKs
    /// under many names, so a long campaign's memory doesn't grow with them.
    static func removeAll(except service: String) {
        lock.lock()
        defer { lock.unlock() }
        keks = keks.filter { $0.key == service }
    }

    static var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return keks.count
    }
}
