// CLI tool with four commands:
//
//   provision  creates the persistent Secure Enclave KEK for a service if it
//              does not exist yet. The ONLY command that creates keys.
//              Prints the KEK's fingerprint, to be recorded by the operator.
//   wrap       wraps a Data Encryption Key (DEK) supplied by the calling
//              pipeline -- the 32-byte key that pipeline has already
//              encrypted its data with -- under an already-provisioned KEK,
//              and writes the wrapped payload to a file. Never creates a
//              KEK: if none exists for the service, it fails and points at
//              `provision`. It never generates a DEK either: the key is
//              always the pipeline's, read from stdin or a file.
//   retire     deletes a service's KEK keychain item, after the operator
//              proves which KEK they mean by supplying its fingerprint. The
//              ONLY command that deletes keys, and deliberately implemented
//              here rather than in the library: the dylib's C ABI offers no
//              delete, so no consumer that loads it gets a one-call wipe.
//              Everything wrapped under a retired KEK is permanently
//              unrecoverable -- retire only after migrating to a new service.
//   status     reports the keychain mode, whether a service's KEK exists, and
//              its fingerprint. Read-only: never creates or deletes a key.
//
// Calls into the HkdfGuard library through its stable C ABI (`provision`:
// `hkdfguard_kek_exists`, then `hkdfguard_create_kek`; `wrap`:
// `hkdfguard_wrap_dek`), the same interface
// any other-language caller uses -- this tool takes no shortcut through
// the library's internal Swift types (it doesn't even `import` the
// library's own Swift module; see Package.swift). Modeled on this project's
// Linux equivalent
// (hkdfguard-native-linux/src/bin/hkdfguard-v1-initialize.rs),
// with two deliberate differences: the Linux tool's `--dek <base64>`
// argument is not offered here at all (see "DEK sources" below for why),
// and the output file is written with POSIX 0600 permissions (see
// writeWrappedKeyFile).
//
// The KEK's `service` identity is exactly the caller-supplied
// `--service-name`; there is no further structure to it.
//
// Usage:
//   hkdfguard-v1-initialize provision --service-name|-sn <name>
//
//   hkdfguard-v1-initialize retire --service-name|-sn <name> \
//       ( --fingerprint|-fp <64 hex chars> | --corrupt )
//
//   hkdfguard-v1-initialize status --service-name|-sn <name>
//
//   hkdfguard-v1-initialize wrap \
//       --key-file-path|-kf <key-file-path> \
//       --service-name|-sn <name> \
//       ( --dek-stdin | --dek-file <path> ) \
//       [--fingerprint|-fp <64 hex chars>] [--force|-f]
//
// `provision` is idempotent: a second run against the same service reports
// that the KEK already exists and exits 0.
//
// `wrap` always prints the fingerprint of the KEK the payload was actually
// wrapped under (bytes 0-31 of the payload the library returned), and with
// --fingerprint it refuses to write the file unless that value equals the
// one the operator recorded at provision time. `wrap` is the one operation
// that commits a secret to a KEK: a keychain item swapped for a different
// enclave key before the wrap would otherwise be noticed only later, at
// unwrap (fingerprintMismatch, -16), after the DEK had already been sealed
// to the wrong key. The check is made on the returned payload itself, not
// through a separate hkdfguard_kek_fingerprint call, so there is no window
// between "which KEK?" and "wrap under it".
//
// For `wrap`, exactly one DEK source is required:
//   --dek-stdin        base64 DEK read from standard input (e.g. piped from
//                      the pipeline or a secret store; trailing newline ok).
//   --dek-file <path>  base64 DEK read from a file.
//
// There is deliberately no way to pass the DEK itself as a command-line
// argument: an argv value is visible to every other process on the host
// (`ps`) for the life of the process and is recorded in the invoking
// shell's history file. Both stdin and a file avoid that entirely.
//
// The wrapped payload is written to <key-file-path> with POSIX permissions
// 0600 (owner read/write, no access for anyone else) -- set
// atomically at file-creation time. With --force against a pre-existing
// file, that file's old contents are securely overwritten in place (8
// alternating all-zero/random passes) and then deleted before the new file
// is created -- see secureOverwriteAndRemoveIfExists/writeWrappedKeyFile
// below for the exact sequence and its one intentional fallback. --force
// only ever overwrites and removes a *regular file*: a symbolic link at
// <key-file-path> is refused rather than followed (so a planted link can't
// redirect the destructive overwrite onto some other file), as is a regular
// file with more than one hard link (the same redirection, through a link
// O_NOFOLLOW cannot see), a FIFO, a device, or a directory.
//
// `wrap` creates nothing but the output file, and only after every argument
// has been validated. `provision` creates nothing until its service name
// has been validated. A malformed invocation of either never leaves a
// freshly provisioned KEK behind.

import Darwin
import Foundation
import Security // SecRandomCopyBytes, used by the secure-overwrite passes below
import CryptoKit // retire only: the enclave liveness probe, and re-checking the exact item it deletes

// MARK: - Binding directly to the library's C ABI (no bridging header, no
// module import -- see Package.swift's comment on how this executable
// links). `@_silgen_name` binds this declaration straight to the exported
// symbol of that exact name in whatever this executable links against, the
// same way a C `extern` declaration would -- Swift's version of "trust me,
// this symbol exists with this signature," used here so this tool is
// provably calling the real C ABI and nothing library-internal.
@_silgen_name("hkdfguard_wrap_dek")
func hkdfguard_wrap_dek(
    _ service: UnsafePointer<CChar>?,
    _ dek: UnsafePointer<UInt8>?,
    _ dekLen: Int32,
    _ out: UnsafeMutablePointer<UInt8>?,
    _ outLen: UnsafeMutablePointer<Int32>?
) -> Int32

// The library's wrap calls never create a KEK. These two are used only by
// the `provision` command (see `provisionKEK` below): ask whether one
// exists, and create it only if the answer is a definite "no".
@_silgen_name("hkdfguard_kek_exists")
func hkdfguard_kek_exists(_ service: UnsafePointer<CChar>?, _ outExists: UnsafeMutablePointer<Int32>?) -> Int32

@_silgen_name("hkdfguard_create_kek")
func hkdfguard_create_kek(_ service: UnsafePointer<CChar>?) -> Int32

// Read-only: the KEK's public-key fingerprint. Printed by `provision`,
// checked by `retire`.
@_silgen_name("hkdfguard_kek_fingerprint")
func hkdfguard_kek_fingerprint(
    _ service: UnsafePointer<CChar>?,
    _ out: UnsafeMutablePointer<UInt8>?,
    _ outLen: UnsafeMutablePointer<Int32>?
) -> Int32

// Which keychain this process's KEK items live in (0 legacy, 1
// data-protection) -- decided by the library from this executable's own
// code-signing entitlements. Printed by both commands because a service's
// provisioner and its consumers must agree on it; see the header.
@_silgen_name("hkdfguard_keychain_mode")
func hkdfguard_keychain_mode(_ outMode: UnsafeMutablePointer<Int32>?) -> Int32

func keychainModeName() -> String {
    var mode: Int32 = -1
    _ = hkdfguard_keychain_mode(&mode)
    switch mode {
    case 0: return "legacy"
    case 1: return "data-protection"
    default: return "unknown(\(mode))"
    }
}

// Mirrors HKDFGuardStatus in HkdfGuardNativeMacOS.swift -- kept as
// a separate, parallel definition rather than importing that module, for
// the same "go through the C ABI only" reason as the `@_silgen_name`
// declaration above; the raw integer values are the actual contract, this
// enum just makes them readable here.
enum HKDFGuardStatus: Int32 {
    case success = 0
    case invalidInputLength = -1
    case outputBufferTooSmall = -2
    case keyUnavailable = -3 // reserved; no longer returned by the library -- see -10 and lower
    case publicKeyUnavailable = -4 // reserved; never returned by the library
    case encryptionFailed = -5
    case decryptionFailed = -6
    case unexpectedOutputLength = -7
    case invalidServiceIdentifier = -8
    case enclaveUnavailable = -9
    case kekNotFound = -10
    case kekCorrupted = -11
    case accessControlCreationFailed = -12
    case keyGenerationFailed = -13
    case keychainWriteFailed = -14
    case kekVerificationFailed = -15
    case fingerprintMismatch = -16
    case keychainAccessDenied = -17
    case keychainReadFailed = -18

    var description: String {
        switch self {
        case .success: return "success"
        case .invalidInputLength: return "invalid argument (bad service name or DEK length)"
        case .outputBufferTooSmall: return "output buffer too small"
        case .keyUnavailable: return "the Secure Enclave key could not be obtained"
        case .publicKeyUnavailable: return "the KEK's public key is unavailable (reserved code; not returned by this library version)"
        case .encryptionFailed: return "a cryptographic operation failed"
        case .decryptionFailed: return "decryption failed"
        case .unexpectedOutputLength: return "the library produced an unexpected output length"
        case .invalidServiceIdentifier: return "the service name is missing, empty, longer than 128 characters, or contains a character other than an ASCII letter, digit, or '.'"
        case .enclaveUnavailable: return "the Secure Enclave is not available on this machine"
        case .kekNotFound: return "no key exists yet for this service -- call hkdfguard_create_kek first"
        case .kekCorrupted: return "a keychain item exists for this service but could not be reconstructed into a usable key"
        case .accessControlCreationFailed: return "failed to set up access control for a new key"
        case .keyGenerationFailed: return "the Secure Enclave refused to generate a new key"
        case .keychainWriteFailed: return "failed to persist the newly generated key to the keychain"
        case .kekVerificationFailed: return "the newly created key could not be verified after being stored"
        case .fingerprintMismatch: return "the wrapped payload's embedded KEK fingerprint does not match the current key"
        case .keychainAccessDenied: return "the keychain denied access (locked, no UI session, access prompt declined, or missing entitlement) -- a key for this service may already exist"
        case .keychainReadFailed: return "reading the keychain failed"
        }
    }
}

func describeStatus(_ code: Int32) -> String {
    if let status = HKDFGuardStatus(rawValue: code) {
        return status.description
    }
    return "unknown status code \(code)"
}

// MARK: - Argument parsing

let programName = "hkdfguard-v1-initialize"
let dekLen = 32
// Generous starting capacity for the wrapped payload -- retried once at
// the library-reported size on outputBufferTooSmall, so this only needs to
// be a reasonable common case, not an absolute upper bound. Matches the
// Linux tool's own INITIAL_WRAPPED_CAPACITY.
let initialWrappedCapacity = 512

// Where the DEK comes from. Exactly one must be given (see parseArgs).
enum DekSource {
    case stdin               // --dek-stdin
    case file(String)        // --dek-file <path>

    var flag: String {
        switch self {
        case .stdin: return "--dek-stdin"
        case .file: return "--dek-file"
        }
    }
}

struct ProvisionArgs {
    var serviceName: String
}

struct WrapArgs {
    var keyFilePath: String
    var serviceName: String
    var dekSource: DekSource
    var force: Bool
    /// `--fingerprint`: the KEK the operator expects to wrap under. When set,
    /// the payload's embedded fingerprint must equal it or nothing is written.
    var expectedFingerprint: [UInt8]?
}

// How the operator confirms which KEK item `retire` may delete.
enum RetireConfirmation {
    case fingerprint([UInt8]) // --fingerprint: a valid KEK, by its public-key fingerprint
    case corrupt              // --corrupt: an item the library reports as kekCorrupted
}

struct RetireArgs {
    var serviceName: String
    var confirmation: RetireConfirmation
}

enum Command {
    case provision(ProvisionArgs)
    case wrap(WrapArgs)
    case retire(RetireArgs)
    case status(serviceName: String)
    case help
}

let dekSourceFlags = "--dek-stdin | --dek-file <path>"

func printUsage() {
    FileHandle.standardError.write(
        """
        Usage:
          \(programName) provision --service-name|-sn <name>
          \(programName) wrap --key-file-path|-kf <path> --service-name|-sn <name> \\
                                    ( \(dekSourceFlags) ) [--fingerprint|-fp <hex>] [--force|-f]
          \(programName) retire --service-name|-sn <name> ( --fingerprint|-fp <hex> | --corrupt )
          \(programName) status --service-name|-sn <name>

        Commands:
          provision   create the Secure Enclave KEK for <name> if it does not exist yet.
                      The only command that creates keys; safe to run repeatedly.
                      Prints the KEK's fingerprint -- record it.
          wrap        wrap the pipeline's 32-byte DEK under the already-provisioned KEK
                      for <name> and write the wrapped payload to <path>. Never creates
                      a KEK -- fails if none exists for <name> (run provision first).
                      Prints the fingerprint of the KEK the payload was wrapped under.
          retire      delete the KEK for <name>, only if its fingerprint matches <hex>
                      (64 hex characters, as printed by provision). The only command
                      that deletes keys. Everything wrapped under that KEK becomes
                      permanently unrecoverable: migrate to a new service name first.
                      With --corrupt instead, deletes the item only if the library
                      reports it as corrupt (-11) and the Secure Enclave is proven
                      usable in this session, so a healthy KEK that merely could not
                      be loaded right now is never mistaken for a corrupt one.
          status      report the keychain mode, whether a KEK exists for <name>, and
                      its fingerprint. Read-only: never creates or deletes anything.

        wrap options (exactly one DEK source is required):
          --key-file-path|-kf <path>  where to write the wrapped payload
          --dek-stdin         read the base64 DEK from standard input
          --dek-file <path>   read the base64 DEK from a file
          --fingerprint|-fp <hex>  refuse to write unless the KEK actually used has this
                      fingerprint (64 hex characters, as printed by provision)
          --force|-f          securely overwrite an existing <path>

        The DEK is never accepted as a command-line argument (it would be visible
        to other processes via ps and recorded in shell history).

        """.data(using: .utf8)!
    )
}

// `--service-name|-sn <name>`, shared by both commands' parsers.
func parseServiceName(_ arg: String, _ iterator: inout IndexingIterator<[String]>) throws -> String {
    guard let value = iterator.next() else {
        throw CLIError("\(arg) requires a value")
    }
    guard !value.isEmpty else {
        throw CLIError("--service-name must not be empty")
    }
    return value
}

func parseArgs(_ arguments: [String]) throws -> Command {
    var rest = Array(arguments.dropFirst()) // skip argv[0]
    guard !rest.isEmpty else {
        throw CLIError("missing command: expected provision or wrap")
    }
    let command = rest.removeFirst()
    switch command {
    case "--help", "-h":
        return .help
    case "provision":
        return try parseProvision(rest)
    case "wrap":
        return try parseWrap(rest)
    case "retire":
        return try parseRetire(rest)
    case "status":
        return try parseStatus(rest)
    default:
        throw CLIError("unknown command \"\(command)\": expected provision, wrap, retire, or status")
    }
}

func parseStatus(_ arguments: [String]) throws -> Command {
    var serviceName: String?
    var iterator = arguments.makeIterator()
    while let arg = iterator.next() {
        switch arg {
        case "--help", "-h":
            return .help
        case "--service-name", "-sn":
            serviceName = try parseServiceName(arg, &iterator)
        default:
            throw CLIError("status: unrecognized argument: \(arg)")
        }
    }
    guard let serviceName else { throw CLIError("status: missing required --service-name|-sn") }
    return .status(serviceName: serviceName)
}

func parseRetire(_ arguments: [String]) throws -> Command {
    var serviceName: String?
    var fingerprint: [UInt8]?
    var corrupt = false

    var iterator = arguments.makeIterator()
    while let arg = iterator.next() {
        switch arg {
        case "--help", "-h":
            return .help
        case "--service-name", "-sn":
            serviceName = try parseServiceName(arg, &iterator)
        case "--fingerprint", "-fp":
            guard let value = iterator.next(), !value.isEmpty else {
                throw CLIError("\(arg) requires a value")
            }
            fingerprint = try parseFingerprintHex(value)
        case "--corrupt":
            corrupt = true
        default:
            throw CLIError("retire: unrecognized argument: \(arg)")
        }
    }

    guard let serviceName else { throw CLIError("retire: missing required --service-name|-sn") }
    switch (fingerprint, corrupt) {
    case (let fingerprint?, false):
        return .retire(RetireArgs(serviceName: serviceName, confirmation: .fingerprint(fingerprint)))
    case (nil, true):
        return .retire(RetireArgs(serviceName: serviceName, confirmation: .corrupt))
    case (_?, true):
        throw CLIError("retire: --fingerprint and --corrupt are mutually exclusive: a KEK with a readable fingerprint is not corrupt")
    case (nil, false):
        throw CLIError("retire: missing required --fingerprint|-fp (the 64-hex-character value printed by provision), or --corrupt for an item the library reports as corrupt")
    }
}

let fingerprintLength = 32

// Exactly 64 hex digits, either case. No separators or prefixes: the value
// is meant to be pasted from provision's output, and a strict format keeps
// a truncated paste from ever looking valid.
func parseFingerprintHex(_ text: String) throws -> [UInt8] {
    let digits = Array(text.utf8)
    guard digits.count == fingerprintLength * 2 else {
        throw CLIError("--fingerprint must be exactly \(fingerprintLength * 2) hex characters, got \(digits.count)")
    }
    func nibble(_ c: UInt8) -> UInt8? {
        switch c {
        case 0x30...0x39: return c - 0x30
        case 0x41...0x46: return c - 0x41 + 10
        case 0x61...0x66: return c - 0x61 + 10
        default: return nil
        }
    }
    var bytes = [UInt8]()
    bytes.reserveCapacity(fingerprintLength)
    for i in stride(from: 0, to: digits.count, by: 2) {
        guard let hi = nibble(digits[i]), let lo = nibble(digits[i + 1]) else {
            throw CLIError("--fingerprint must contain only hex characters (0-9, a-f)")
        }
        bytes.append(hi << 4 | lo)
    }
    return bytes
}

func hexString(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

func parseProvision(_ arguments: [String]) throws -> Command {
    var serviceName: String?

    var iterator = arguments.makeIterator()
    while let arg = iterator.next() {
        switch arg {
        case "--help", "-h":
            return .help
        case "--service-name", "-sn":
            serviceName = try parseServiceName(arg, &iterator)
        default:
            throw CLIError("provision: unrecognized argument: \(arg)")
        }
    }

    guard let serviceName else { throw CLIError("provision: missing required --service-name|-sn") }
    return .provision(ProvisionArgs(serviceName: serviceName))
}

func parseWrap(_ arguments: [String]) throws -> Command {
    var keyFilePath: String?
    var serviceName: String?
    var dekSources: [DekSource] = []
    var force = false
    var expectedFingerprint: [UInt8]?

    var iterator = arguments.makeIterator()
    while let arg = iterator.next() {
        switch arg {
        case "--help", "-h":
            return .help
        case "--force", "-f":
            force = true
        case "--fingerprint", "-fp":
            guard let value = iterator.next(), !value.isEmpty else {
                throw CLIError("\(arg) requires a value")
            }
            expectedFingerprint = try parseFingerprintHex(value)
        case "--key-file-path", "-kf":
            guard let value = iterator.next(), !value.isEmpty else {
                throw CLIError("\(arg) requires a path")
            }
            keyFilePath = value
        case "--service-name", "-sn":
            serviceName = try parseServiceName(arg, &iterator)
        case "--generate", "-g":
            // This tool only wraps a DEK the calling pipeline already has --
            // the key its data was encrypted with. Generating one here
            // would produce a key nothing has used.
            throw CLIError("\(arg) is not supported: this tool wraps the pipeline's existing DEK; supply it with \(dekSourceFlags)")
        case "--dek-stdin":
            dekSources.append(.stdin)
        case "--dek-file":
            guard let value = iterator.next(), !value.isEmpty else {
                throw CLIError("\(arg) requires a path")
            }
            dekSources.append(.file(value))
        case "--dek", "-d":
            // Rejected explicitly, with the reason, rather than falling
            // through to a generic "unrecognized argument" -- anyone
            // reaching for the Linux tool's flag should learn why it isn't
            // here and what to use instead.
            throw CLIError("\(arg) is not supported: a DEK on the command line is visible via ps and recorded in shell history; use \(dekSourceFlags)")
        default:
            if !arg.hasPrefix("-") {
                // The key file path used to be positional; say so rather
                // than leaving the caller to guess what went wrong.
                throw CLIError("wrap: unexpected argument \"\(arg)\" -- the key file path is given with --key-file-path|-kf <path>")
            }
            throw CLIError("wrap: unrecognized argument: \(arg)")
        }
    }

    guard let keyFilePath else { throw CLIError("wrap: missing required --key-file-path|-kf") }
    guard let serviceName else { throw CLIError("wrap: missing required --service-name|-sn") }
    guard !dekSources.isEmpty else {
        throw CLIError("wrap: missing required DEK source: one of \(dekSourceFlags)")
    }
    guard dekSources.count == 1 else {
        throw CLIError("wrap: conflicting DEK sources (\(dekSources.map(\.flag).joined(separator: ", "))): give exactly one of \(dekSourceFlags)")
    }

    return .wrap(
        WrapArgs(
            keyFilePath: keyFilePath,
            serviceName: serviceName,
            dekSource: dekSources[0],
            force: force,
            expectedFingerprint: expectedFingerprint
        )
    )
}

struct CLIError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

// Maximum length, in bytes, the library accepts for a service name (see
// `validServiceName` in HkdfGuardNativeMacOS.swift). Checked here
// too so an over-length name fails fast with a clear message instead of
// making a wasted round trip through hkdfguard_create_kek/hkdfguard_wrap_dek
// just to get the same rejection back as an opaque status code.
let maxServiceNameLength = 128

// Enforces the exact same rule the library itself applies to `service` (see
// `validServiceName` in HkdfGuardNativeMacOS.swift): 1-128 ASCII
// alphanumeric characters or '.', matching this project's Linux/Windows
// tools.
func validateServiceCharset(_ service: String) throws {
    guard service.utf8.count <= maxServiceNameLength else {
        throw CLIError("service name \"\(service)\" must be at most \(maxServiceNameLength) characters, got \(service.utf8.count)")
    }
    let isValid = service.utf8.allSatisfy { byte in
        (byte >= 0x30 && byte <= 0x39) // '0'-'9'
            || (byte >= 0x41 && byte <= 0x5A) // 'A'-'Z'
            || (byte >= 0x61 && byte <= 0x7A) // 'a'-'z'
            || byte == 0x2E // '.'
    }
    guard isValid else {
        throw CLIError("service name \"\(service)\" must contain only alphanumeric characters or '.'")
    }
}

// MARK: - KEK provisioning (the `provision` command only)

// Creates the KEK for `service` if none exists; returns true if one was
// created, false if one already existed. hkdfguard_kek_exists first,
// hkdfguard_create_kek only on a definite "no key yet". Anything other than
// a clean yes/no from the exists check -- keychainAccessDenied,
// keychainReadFailed, kekCorrupted, enclaveUnavailable -- stops here with
// that specific reason, rather than falling through to a create attempt
// whose failure would be reported against the wrong step.
//
// This is the only place in the tool that calls either function: `wrap`
// never checks for or creates a KEK.
func provisionKEK(service: String) throws -> Bool {
    var exists: Int32 = 0
    let existsStatus = service.withCString { hkdfguard_kek_exists($0, &exists) }
    guard existsStatus == HKDFGuardStatus.success.rawValue else {
        throw CLIError("hkdfguard_kek_exists failed: \(describeStatus(existsStatus))")
    }
    if exists != 0 {
        return false
    }

    let createStatus = service.withCString { hkdfguard_create_kek($0) }
    guard createStatus == HKDFGuardStatus.success.rawValue else {
        throw CLIError("hkdfguard_create_kek failed: \(describeStatus(createStatus))")
    }
    return true
}

// The fingerprint of the KEK `service` resolves to, or the library's status
// code when it can't be read (kekNotFound, keychainAccessDenied, ...).
func readKekFingerprint(service: String) -> (status: Int32, fingerprint: [UInt8]) {
    var out = [UInt8](repeating: 0, count: fingerprintLength)
    var outLen = Int32(fingerprintLength)
    let status = service.withCString { servicePtr in
        out.withUnsafeMutableBufferPointer { buf in
            hkdfguard_kek_fingerprint(servicePtr, buf.baseAddress, &outLen)
        }
    }
    return (status, Array(out.prefix(Int(max(outLen, 0)))))
}

// MARK: - KEK retirement (the `retire` command only)

// Must equal `hkdfguardKeychainAccount` in HkdfGuardNativeMacOS.swift.
// Duplicated rather than exported: the library's C ABI deliberately has no
// way to address its keychain items directly.
let kekKeychainAccount = "kek-v1"

// The first non-empty `keychain-access-groups` entry this executable is
// signed with -- the same rule the library's detectKeychainMode applies.
func entitledAccessGroup() -> String? {
    guard let task = SecTaskCreateFromSelf(nil),
          let value = SecTaskCopyValueForEntitlement(task, "keychain-access-groups" as CFString, nil),
          let groups = value as? [String] else {
        return nil
    }
    return groups.first(where: { !$0.isEmpty })
}

// The query identifying `service`'s KEK item -- mirroring the library's
// keychainItemAttributes, including an explicit kSecUseDataProtectionKeychain
// in both modes (an omitted key can resolve to the data-protection keychain
// on current SDKs). The library's own mode decision and this executable's
// entitlements must agree; if they don't, something is wrong with the build
// and nothing is deleted.
func kekItemQuery(service: String) throws -> [String: Any] {
    var query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: kekKeychainAccount,
        kSecAttrSynchronizable as String: false,
    ]
    var libraryMode: Int32 = -1
    _ = hkdfguard_keychain_mode(&libraryMode)
    switch (libraryMode, entitledAccessGroup()) {
    case (0, nil):
        query[kSecUseDataProtectionKeychain as String] = false
    case (1, let group?):
        query[kSecUseDataProtectionKeychain as String] = true
        query[kSecAttrAccessGroup as String] = group
    default:
        throw CLIError("the library reports keychain mode \(libraryMode), which does not match this executable's keychain entitlements; refusing to delete anything")
    }
    return query
}

func describeOSStatus(_ status: OSStatus) -> String {
    if let message = SecCopyErrorMessageString(status, nil) as String? {
        return "\(message) (OSStatus \(status))"
    }
    return "OSStatus \(status)"
}

// Deletes `service`'s KEK item only if the KEK it currently holds has the
// fingerprint the operator supplied. A KEK that can't be read -- access
// denied, corrupt, read failure -- is never deleted: the fingerprint check
// is the confirmation, and without it there is nothing to confirm against.
func retireKEK(service: String, expectedFingerprint: [UInt8]) throws {
    let (status, current) = readKekFingerprint(service: service)
    switch status {
    case HKDFGuardStatus.success.rawValue:
        break
    case HKDFGuardStatus.kekNotFound.rawValue:
        throw CLIError("no KEK exists for service \"\(service)\" (keychain: \(keychainModeName())); nothing to retire")
    case HKDFGuardStatus.kekCorrupted.rawValue:
        throw CLIError("the KEK item for service \"\(service)\" cannot be reconstructed into a key, so it has no fingerprint to confirm; if it is genuinely corrupt, retire it with --corrupt")
    default:
        throw CLIError("cannot read the KEK fingerprint for service \"\(service)\": \(describeStatus(status)); refusing to retire a KEK that cannot be confirmed")
    }
    guard current == expectedFingerprint else {
        throw CLIError("fingerprint mismatch for service \"\(service)\": the current KEK is \(hexString(current)), not \(hexString(expectedFingerprint)); nothing was deleted")
    }

    // The library answered for "the KEK this service resolves to". Now pin
    // the exact keychain item that will be deleted, and confirm the
    // fingerprint again from *that item's own blob*, so the delete below can
    // only ever remove the key the operator just confirmed.
    var item = try locateSingleKEKItem(service: service)
    defer { item.scrub() }
    guard let key = try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: item.blob) else {
        throw CLIError("the KEK item for service \"\(service)\" could not be reconstructed when re-read for deletion; nothing was deleted -- inspect it again before retiring")
    }
    let itemFingerprint = Array(SHA256.hash(data: key.publicKey.rawRepresentation))
    guard itemFingerprint == expectedFingerprint else {
        throw CLIError("the KEK item for service \"\(service)\" changed between checks (now \(hexString(itemFingerprint))); nothing was deleted")
    }

    try deleteKEKItemAndConfirm(service: service, item: item)
}

// The library's kek_exists status for `service` (exists flag discarded when
// the status isn't success).
func kekExistsStatus(service: String) -> (status: Int32, exists: Bool) {
    var exists: Int32 = 0
    let status = service.withCString { hkdfguard_kek_exists($0, &exists) }
    return (status, exists != 0)
}

// Proves the Secure Enclave and this user's keybag are usable in this
// session, by creating a throwaway key under the library's own access
// policy, reconstructing it from its data representation exactly as the
// library reconstructs a stored KEK, and using it once. Nothing is stored.
// Without this, a healthy KEK that merely failed to load right now (locked
// session, SSH with no GUI login, enclave unavailable) would be
// indistinguishable from a corrupt item and could be deleted.
func secureEnclaveIsUsableNow() -> Bool {
    guard SecureEnclave.isAvailable,
          let access = SecAccessControlCreateWithFlags(
              nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage], nil
          ),
          let probe = try? SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access),
          let reloaded = try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: probe.dataRepresentation)
    else {
        return false
    }
    let peer = P256.KeyAgreement.PrivateKey().publicKey
    return (try? reloaded.sharedSecretFromKeyAgreement(with: peer)) != nil
}

// Deletes `service`'s KEK item only if the library reports it as corrupt
// (kekCorrupted, -11) -- present but not reconstructable -- and only after
// proving the enclave works in this session, so the -11 reflects the item
// itself. A valid KEK, a missing one, or one the keychain won't let this
// process read is never deleted here.
func retireCorruptKEK(service: String) throws {
    let (status, exists) = kekExistsStatus(service: service)
    switch status {
    case HKDFGuardStatus.kekCorrupted.rawValue:
        break
    case HKDFGuardStatus.success.rawValue where exists:
        throw CLIError("the KEK for service \"\(service)\" is valid, not corrupt; nothing was deleted -- retire a valid KEK with --fingerprint")
    case HKDFGuardStatus.success.rawValue:
        throw CLIError("no KEK exists for service \"\(service)\" (keychain: \(keychainModeName())); nothing to retire")
    default:
        throw CLIError("cannot inspect the KEK item for service \"\(service)\": \(describeStatus(status)); refusing to retire an item that cannot be confirmed corrupt")
    }

    guard secureEnclaveIsUsableNow() else {
        throw CLIError("the Secure Enclave is not usable in this session (locked, no GUI login, or unavailable), so a healthy KEK can look corrupt here; nothing was deleted -- rerun from an unlocked, logged-in session")
    }
    // Re-checked after the probe: the item must still be reported corrupt.
    guard kekExistsStatus(service: service).status == HKDFGuardStatus.kekCorrupted.rawValue else {
        throw CLIError("the KEK item for service \"\(service)\" is no longer reported as corrupt; nothing was deleted -- inspect it again before retiring")
    }

    // Pin the exact item, and confirm that *its* blob is the unreconstructable
    // one, so a valid item that appeared alongside or in place of the corrupt
    // one is never what gets deleted.
    var item = try locateSingleKEKItem(service: service)
    defer { item.scrub() }
    guard (try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: item.blob)) == nil else {
        throw CLIError("the KEK item for service \"\(service)\" reconstructs into a valid key when re-read for deletion; nothing was deleted -- retire a valid KEK with --fingerprint")
    }

    try deleteKEKItemAndConfirm(service: service, item: item)
}

// The one keychain item `retire` will act on: a persistent reference, which
// names that specific item row and no other, plus its stored blob as read
// through that reference.
struct KEKItem {
    let persistentRef: Data
    var blob: Data

    // The blob is the SEP-wrapped key credential; don't leave this process's
    // copy of it lying around once retire is done with it.
    mutating func scrub() {
        _ = blob.withUnsafeMutableBytes { raw in
            raw.initializeMemory(as: UInt8.self, repeating: 0)
        }
    }
}

// Finds `service`'s KEK item in this process's keychain mode and refuses
// unless there is exactly one. A query-based SecItemDelete removes *every*
// match: in legacy mode the search list spans more than one keychain (login
// and System, plus any the user added), so a same-named item elsewhere would
// be deleted alongside the one whose fingerprint was confirmed. Pinning a
// single persistent reference closes that, and also closes the window
// between the fingerprint check and the delete: an item swapped in after
// this point has a different reference, so the delete cannot reach it.
func locateSingleKEKItem(service: String) throws -> KEKItem {
    let base = try kekItemQuery(service: service)

    var listQuery = base
    listQuery[kSecMatchLimit as String] = kSecMatchLimitAll
    listQuery[kSecReturnPersistentRef as String] = true
    var listResult: CFTypeRef?
    let listStatus = SecItemCopyMatching(listQuery as CFDictionary, &listResult)
    switch listStatus {
    case errSecSuccess:
        break
    case errSecItemNotFound:
        throw CLIError("no KEK item exists for service \"\(service)\" (keychain: \(keychainModeName())); nothing was deleted")
    default:
        throw CLIError("listing the KEK items for service \"\(service)\" failed: \(describeOSStatus(listStatus)); nothing was deleted")
    }
    let refs: [Data]
    if let many = listResult as? [Data] {
        refs = many
    } else if let one = listResult as? Data {
        refs = [one]
    } else {
        throw CLIError("the keychain returned an unexpected result listing the KEK items for service \"\(service)\"; nothing was deleted")
    }
    guard refs.count == 1 else {
        throw CLIError("found \(refs.count) keychain items for service \"\(service)\" (keychain: \(keychainModeName())); refusing to choose which one to delete -- nothing was deleted. Inspect them with `security find-generic-password -s \(service) -a \(kekKeychainAccount)` (legacy mode) and remove the stray ones by hand")
    }
    let ref = refs[0]

    // Fetched by the reference alone: the data-protection keychain rejects a
    // persistent-reference lookup that also carries matching attributes
    // (errSecParam). The attributes it returns are checked instead, so the
    // reference is proven to name `service`'s KEK item and nothing else.
    var fetchQuery = persistentRefQuery(ref, base: base)
    fetchQuery[kSecReturnData as String] = true
    fetchQuery[kSecReturnAttributes as String] = true
    var fetchResult: CFTypeRef?
    let fetchStatus = SecItemCopyMatching(fetchQuery as CFDictionary, &fetchResult)
    guard fetchStatus == errSecSuccess,
          let attributes = fetchResult as? [String: Any],
          let blob = attributes[kSecValueData as String] as? Data else {
        throw CLIError("re-reading the KEK item for service \"\(service)\" failed: \(describeOSStatus(fetchStatus)); nothing was deleted")
    }
    for key in [kSecAttrService, kSecAttrAccount, kSecAttrAccessGroup] as [CFString] {
        guard let expected = base[key as String] as? String else { continue }
        guard (attributes[key as String] as? String) == expected else {
            throw CLIError("the keychain item found for service \"\(service)\" does not carry the expected \(key) (\"\(expected)\"); nothing was deleted")
        }
    }
    return KEKItem(persistentRef: ref, blob: blob)
}

// A query naming exactly one item by its persistent reference, in the same
// keychain `base` selects -- and nothing else, since the data-protection
// keychain refuses to combine a persistent reference with other matching
// attributes. Callers establish what the reference names before relying on it.
func persistentRefQuery(_ ref: Data, base: [String: Any]) -> [String: Any] {
    var query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecValuePersistentRef as String: ref,
    ]
    query[kSecUseDataProtectionKeychain as String] = base[kSecUseDataProtectionKeychain as String]
    return query
}

// Deletes exactly `item`, by the persistent reference locateSingleKEKItem
// proved names `service`'s KEK item, then confirms through the library --
// the same lookup every consumer uses -- that no KEK remains for `service`.
func deleteKEKItemAndConfirm(service: String, item: KEKItem) throws {
    let query = persistentRefQuery(item.persistentRef, base: try kekItemQuery(service: service))
    let deleteStatus = SecItemDelete(query as CFDictionary)
    guard deleteStatus == errSecSuccess else {
        if deleteStatus == errSecItemNotFound {
            throw CLIError("the KEK item for service \"\(service)\" was replaced or removed after it was confirmed; nothing was deleted -- inspect it again before retiring")
        }
        throw CLIError("deleting the KEK for service \"\(service)\" failed: \(describeOSStatus(deleteStatus))")
    }

    let (existsStatus, exists) = kekExistsStatus(service: service)
    guard existsStatus == HKDFGuardStatus.success.rawValue, !exists else {
        throw CLIError("the KEK for service \"\(service)\" was deleted but the library still reports one (status: \(describeStatus(existsStatus))); investigate before relying on it being gone")
    }
}

// MARK: - Wrap

// Calls `attempt` with an output buffer of initialWrappedCapacity and, if
// the library answers outputBufferTooSmall (having written the size it
// actually needs into the length out-parameter), retries exactly once at
// that size -- same pattern as the Linux tool's `wrap_dek`.
func callWithWrappedBuffer(
    _ functionName: String,
    service: String,
    _ attempt: (UnsafeMutablePointer<UInt8>?, UnsafeMutablePointer<Int32>?) -> Int32
) throws -> [UInt8] {
    var wrapped = [UInt8](repeating: 0, count: initialWrappedCapacity)
    var wrappedLen = Int32(wrapped.count)

    var rc = wrapped.withUnsafeMutableBufferPointer { buf in
        attempt(buf.baseAddress, &wrappedLen)
    }
    if rc == HKDFGuardStatus.outputBufferTooSmall.rawValue {
        wrapped = [UInt8](repeating: 0, count: Int(wrappedLen))
        rc = wrapped.withUnsafeMutableBufferPointer { buf in
            attempt(buf.baseAddress, &wrappedLen)
        }
    }

    guard rc == HKDFGuardStatus.success.rawValue else {
        if rc == HKDFGuardStatus.kekNotFound.rawValue {
            // `wrap` never provisions; point at the command that does.
            throw CLIError("no KEK exists for service \"\(service)\"; run `\(programName) provision --service-name \(service)` first")
        }
        throw CLIError("\(functionName) failed: \(describeStatus(rc))")
    }

    return Array(wrapped.prefix(Int(wrappedLen)))
}

// Wraps a caller-supplied DEK. Takes `dek` as `Data` rather than `[UInt8]`
// so the caller's already-tightly-scoped, zero-on-exit buffer (see `run`
// below) is the only copy of the plaintext DEK that ever exists --
// converting to `[UInt8]` first would leave a second, unzeroed copy sitting
// in memory for the rest of the process's life.
func wrapDek(service: String, dek: Data) throws -> [UInt8] {
    try callWithWrappedBuffer("hkdfguard_wrap_dek", service: service) { outPtr, outLen in
        service.withCString { servicePtr in
            dek.withUnsafeBytes { dekBuf in
                hkdfguard_wrap_dek(
                    servicePtr,
                    dekBuf.bindMemory(to: UInt8.self).baseAddress,
                    Int32(dek.count),
                    outPtr,
                    outLen
                )
            }
        }
    }
}

// MARK: - Reading the pipeline's DEK

// Upper bound on the DEK input, in bytes. Base64 of a 32-byte DEK is 44
// characters; this leaves generous room for surrounding whitespace while
// refusing anything that is clearly not a DEK (a file passed by mistake, an
// unbounded pipe) before it is ever buffered in full.
let maxDekInputLength = 1024

// ASCII whitespace that may surround the base64 text (trailing newline from
// `echo`, CRLF from a Windows-edited file, ...). Interior whitespace is not
// stripped: the base64 decoder rejects it, as before.
func isDekInputWhitespace(_ byte: UInt8) -> Bool {
    byte == 0x20 || (0x09...0x0D).contains(byte)
}

// Reads the base64 DEK for `source`, decodes it, and hands the decoded bytes
// to `body` -- the only window in which the plaintext DEK exists here.
//
// Every copy this function makes is zeroed before it returns, on every path:
//
// - The raw input is read with read(2) into ONE buffer, allocated up front
//   at a fixed size and never grown. A growable buffer (Data from
//   readDataToEndOfFile, Data(contentsOf:)) reallocates as it fills and
//   leaves the abandoned, unzeroed copies of the input in freed memory;
//   this one has no earlier copies to abandon.
// - The base64 text is never turned into a String. Swift Strings cannot be
//   zeroed in place, and the previous implementation made two (decoded and
//   trimmed) and could only drop references to them. Trimming here is an
//   index range over the raw bytes, and decoding reads them in place.
// - The decoded DEK is zeroed as soon as `body` returns.
func withSuppliedDek<T>(_ source: DekSource, _ body: (Data) throws -> T) throws -> T {
    let buffer = UnsafeMutableRawBufferPointer.allocate(byteCount: maxDekInputLength + 1, alignment: 1)
    defer {
        buffer.initializeMemory(as: UInt8.self, repeating: 0)
        buffer.deallocate()
    }
    buffer.initializeMemory(as: UInt8.self, repeating: 0)

    let flag = source.flag
    let fd: Int32
    let what: String
    switch source {
    case .stdin:
        fd = STDIN_FILENO
        what = "standard input"
    case .file(let path):
        fd = open(path, O_RDONLY | O_CLOEXEC)
        guard fd >= 0 else {
            throw CLIError("\(flag): failed to read \(path): \(String(cString: strerror(errno)))")
        }
        what = path
    }
    defer {
        if case .file = source { close(fd) }
    }

    // Reads until EOF, or until one byte past the limit -- enough to know
    // the input is too large without reading the rest of it.
    var total = 0
    while total < buffer.count {
        let n = read(fd, buffer.baseAddress! + total, buffer.count - total)
        if n < 0 {
            if errno == EINTR { continue }
            throw CLIError("\(flag): failed to read \(what): \(String(cString: strerror(errno)))")
        }
        if n == 0 { break }
        total += n
    }
    guard total <= maxDekInputLength else {
        throw CLIError("\(flag): \(what) is larger than \(maxDekInputLength) bytes, which cannot be a base64 DEK")
    }

    let bytes = UnsafeRawBufferPointer(rebasing: buffer[0..<total])
    var start = 0
    var end = total
    while start < end && isDekInputWhitespace(bytes[start]) { start += 1 }
    while end > start && isDekInputWhitespace(bytes[end - 1]) { end -= 1 }
    guard start < end else {
        if case .stdin = source {
            throw CLIError("\(flag): no data on standard input")
        }
        throw CLIError("\(flag): \(what) is empty")
    }

    // A no-copy view of the trimmed bytes, for the decoder to read in place.
    // `.none`: the buffer is owned, zeroed, and freed by the defer above.
    let base64View = Data(
        bytesNoCopy: UnsafeMutableRawPointer(mutating: bytes.baseAddress! + start),
        count: end - start,
        deallocator: .none
    )
    guard var dek = Data(base64Encoded: base64View) else {
        throw CLIError("\(flag): the DEK is not valid base64")
    }
    defer {
        _ = dek.withUnsafeMutableBytes { raw in
            raw.initializeMemory(as: UInt8.self, repeating: 0)
        }
    }
    guard dek.count == dekLen else {
        throw CLIError("\(flag): the DEK must decode to exactly \(dekLen) bytes, got \(dek.count)")
    }
    return try body(dek)
}

// MARK: - Writing the wrapped key file

// The permissions every wrapped-key file is written with: owner
// read/write, no access for anyone else (POSIX 0600). The user who wraps
// must be the user whose keychain holds the KEK, so the same user unwraps.
let keyFilePermissions: mode_t = 0o600

// Number of secure-overwrite passes secureOverwriteAndRemoveIfExists below
// performs on a pre-existing file before deleting it, alternating an
// all-zero pass and a random-bytes pass, four times each (zero, random,
// zero, random, zero, random, zero, random).
let secureOverwritePassCount = 8

// Size of the one buffer the secure-overwrite passes write from. Large
// enough that the per-write overhead is negligible, small enough that
// overwriting a file of any size costs a fixed amount of memory.
let secureOverwriteChunkSize = 1 << 20 // 1 MiB

// Writes all of `bytes` to `fd` at its current file offset, looping in
// case a single `write(2)` call returns short (POSIX permits this even for
// a regular file, though it's rare in practice for the small writes this
// tool ever does). Shared by both the secure-overwrite passes below and
// the final real write, so there's exactly one "loop until everything is
// written, or throw" implementation.
func writeAll(fd: Int32, bytes: UnsafeBufferPointer<UInt8>, context: String) throws {
    var offset = 0
    while offset < bytes.count {
        let n = write(fd, bytes.baseAddress! + offset, bytes.count - offset)
        if n < 0 {
            throw CLIError("failed to write \(context): \(String(cString: strerror(errno)))")
        }
        offset += n
    }
}

// Before a --force overwrite is allowed to destroy an existing wrapped-key
// file, this overwrites its *current* contents in place --
// secureOverwritePassCount (8) alternating all-zero/random passes, each
// flushed to the storage device (F_FULLFSYNC) before the next pass starts so they're
// genuinely sequential rather than coalesced by the page cache -- and only
// then deletes it. Only ever called when --force was passed; without
// --force, an existing file is never touched at all (writeWrappedKeyFile's
// plain O_EXCL create fails outright instead).
//
// If the file doesn't exist, this is a no-op. If it exists but can't be
// opened for writing (EACCES/EPERM -- this tool doesn't own it), the
// overwrite passes are skipped entirely and this falls back to a plain
// `unlink`, per explicit product direction: destroying the old bytes first
// is worth attempting, but not worth failing the whole command over when
// this process isn't even allowed to write to the file it's about to
// replace. That fallback still refuses anything that isn't a regular file.
//
// Only a regular file is ever written to or removed. The open uses
// O_NOFOLLOW, so a symbolic link at `path` fails with ELOOP and is refused
// outright rather than followed -- without it, a link planted at
// <key-file-path> (trivial in a shared or world-writable directory) would
// redirect the eight destructive passes onto whatever file it points at,
// after which `unlink` would remove only the link. O_NONBLOCK keeps an
// open on a reader-less FIFO from blocking forever, and the fstat check
// after open rejects a FIFO, device node, or directory before a single
// byte is written (a device node opened for writing by a privileged
// invocation would otherwise be overwritten). It also rejects a regular
// file with more than one hard link: a hard link planted at <key-file-path>
// is indistinguishable from the original file to O_NOFOLLOW and S_IFREG,
// so without this check the passes would destroy the shared contents of
// whatever file it was linked to.
//
// Caveat this can't fully solve, worth knowing rather than assuming away:
// on copy-on-write/log-structured filesystems (e.g. APFS) and on SSDs
// generally (wear leveling), writing new bytes to a file's logical offsets
// does not guarantee those bytes land on the same physical storage cells
// the old bytes occupied -- the old bytes can persist in already-copied-
// away or already-remapped blocks until the medium itself reclaims them.
// This is a best-effort measure against casual recovery (e.g. `strings` on
// the raw device, a filesystem-level undelete), not a cryptographic
// guarantee against a determined attacker with access to the raw flash.
func requireRegularFile(_ st: stat, path: String) throws {
    switch st.st_mode & S_IFMT {
    case S_IFREG:
        guard st.st_nlink <= 1 else {
            throw CLIError("\(path) has \(st.st_nlink) hard links; refusing to overwrite it, since that would also destroy the other linked file -- remove \(path) yourself if it should be replaced")
        }
    case S_IFLNK:
        throw CLIError("\(path) is a symbolic link; refusing to overwrite through it -- remove the link, or point <key-file-path> at a regular file")
    default:
        throw CLIError("\(path) is not a regular file; refusing to overwrite or remove it")
    }
}

// Fail-fast twin of the checks secureOverwriteAndRemoveIfExists enforces at
// open time: with --force, refuse before any Secure Enclave or keychain
// work if <key-file-path> exists and is a symlink or anything other than a
// regular file. `lstat`, not `stat`, so a symlink is judged as itself, not
// as its target. Advisory only -- the path can change between here and the
// open -- the O_NOFOLLOW/fstat checks at open time are the guarantee.
func refuseUnlessAbsentOrRegularFile(path: String) throws {
    var st = stat()
    guard lstat(path, &st) == 0 else {
        if errno == ENOENT {
            return
        }
        throw CLIError("failed to stat \(path): \(String(cString: strerror(errno)))")
    }
    try requireRegularFile(st, path: path)
}

func secureOverwriteAndRemoveIfExists(path: String) throws {
    let fd = open(path, O_WRONLY | O_NOFOLLOW | O_NONBLOCK)
    guard fd >= 0 else {
        let err = errno
        if err == ENOENT {
            return // nothing to overwrite or delete
        }
        if err == ELOOP {
            throw CLIError("\(path) is a symbolic link; refusing to overwrite through it -- remove the link, or point <key-file-path> at a regular file")
        }
        if err == EACCES || err == EPERM {
            // Can't write to it -- skip the overwrite passes and go
            // straight to trying to remove it, but still only if it is a
            // regular file.
            var st = stat()
            if lstat(path, &st) == 0 {
                try requireRegularFile(st, path: path)
            }
            if unlink(path) != 0 && errno != ENOENT {
                throw CLIError("failed to remove \(path): \(String(cString: strerror(errno)))")
            }
            return
        }
        throw CLIError("failed to open \(path) for secure overwrite: \(String(cString: strerror(err)))")
    }
    // Every path out of this function from here on must still close `fd`
    // and, on success, `unlink` the file -- rather than duplicating that in
    // every throw site below, the passes loop below propagates failures by
    // `throw`ing out of this function entirely with `fd` closed via
    // `defer`, and the unlink happens once, after the loop, on the
    // fall-through success path.
    defer { close(fd) }

    var st = stat()
    guard fstat(fd, &st) == 0 else {
        throw CLIError("failed to stat \(path): \(String(cString: strerror(errno)))")
    }
    // Checked on the opened descriptor, so it can't be raced by swapping
    // the path out between a separate stat and this open.
    try requireRegularFile(st, path: path)
    let fileSize = Int(st.st_size)

    if fileSize > 0 {
        // One fixed-size chunk, reused for every write of every pass: memory
        // use is bounded by secureOverwriteChunkSize however large the file
        // is. The previous implementation allocated the whole file, so a
        // --force pointed at a multi-gigabyte file by mistake meant gigabytes
        // of RAM on top of the eight full-size writes.
        let chunkCapacity = min(fileSize, secureOverwriteChunkSize)
        var chunk = [UInt8](repeating: 0, count: chunkCapacity)
        // Scrub the chunk (random bytes from the last random pass, or zeros)
        // on every exit path once the passes are done with it.
        defer {
            _ = chunk.withUnsafeMutableBytes { raw in
                raw.initializeMemory(as: UInt8.self, repeating: 0)
            }
        }

        for pass in 0..<secureOverwritePassCount {
            let randomPass = pass % 2 == 1 // zero, random, zero, random, ...
            let context = "\(path) (secure-overwrite pass \(pass + 1))"

            guard lseek(fd, 0, SEEK_SET) == 0 else {
                throw CLIError("failed to seek \(path) during secure-overwrite pass \(pass + 1): \(String(cString: strerror(errno)))")
            }

            if !randomPass {
                _ = chunk.withUnsafeMutableBytes { raw in
                    raw.initializeMemory(as: UInt8.self, repeating: 0)
                }
            }

            // Covers exactly the fileSize bytes measured by fstat above, in
            // order, from offset 0.
            var remaining = fileSize
            while remaining > 0 {
                let count = min(remaining, chunkCapacity)
                if randomPass {
                    // Fresh CSPRNG bytes for every chunk, so no two regions
                    // of the file receive the same random pattern -- same
                    // source as every other random value this project
                    // generates (nonces, ephemeral keys).
                    let status = chunk.withUnsafeMutableBytes { raw in
                        SecRandomCopyBytes(kSecRandomDefault, count, raw.baseAddress!)
                    }
                    guard status == errSecSuccess else {
                        throw CLIError("failed to generate random bytes for secure-overwrite pass \(pass + 1) of \(path)")
                    }
                }
                try chunk.withUnsafeBufferPointer { buf in
                    try writeAll(fd: fd, bytes: UnsafeBufferPointer(rebasing: buf[0..<count]), context: context)
                }
                remaining -= count
            }
            try flushToStorage(fd: fd, context: "\(path) during secure-overwrite pass \(pass + 1)")
        }
    }

    guard unlink(path) == 0 else {
        throw CLIError("failed to remove \(path) after secure overwrite: \(String(cString: strerror(errno)))")
    }
}

// Flushes `fd`'s data to the storage device itself. On macOS, fsync(2) only
// hands the data to the drive, which may still hold it in a volatile write
// cache; F_FULLFSYNC asks the drive to commit it. Falls back to fsync where
// the filesystem does not support F_FULLFSYNC (some network filesystems).
func flushToStorage(fd: Int32, context: String) throws {
    if fcntl(fd, F_FULLFSYNC) == 0 { return }
    guard fsync(fd) == 0 else {
        throw CLIError("failed to flush \(context) to storage: \(String(cString: strerror(errno)))")
    }
}

// Makes the *directory entry* for a newly created file durable. Without it,
// a crash after the file's data is flushed can still lose the name that
// points at it. A filesystem that cannot sync a directory at all (EINVAL /
// ENOTSUP) is accepted: there is nothing further this tool can do there.
func flushParentDirectory(of path: String) throws {
    var dir = (path as NSString).deletingLastPathComponent
    if dir.isEmpty { dir = "." }
    let dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    guard dfd >= 0 else {
        throw CLIError("failed to open \(dir) to flush it: \(String(cString: strerror(errno)))")
    }
    defer { close(dfd) }
    if fcntl(dfd, F_FULLFSYNC) == 0 { return }
    if fsync(dfd) == 0 { return }
    let err = errno
    if err == EINVAL || err == ENOTSUP { return }
    throw CLIError("failed to flush directory \(dir) to storage: \(String(cString: strerror(err)))")
}

// Writes `bytes` to a new file at `path` with `keyFilePermissions`, durably,
// or leaves no file behind.
//
// 1. O_CREAT|O_EXCL makes "does it exist" and "create it" one kernel
//    operation, so a file that appeared since the pre-check in `runWrap` is
//    never clobbered, and a symlink at `path` is refused (EEXIST) rather
//    than followed. `mode` sets 0600 at creation; the fchmod after is
//    defense in depth against an unusual umask/ACL inheritance.
// 2. The data, then the directory entry, are flushed to the storage device
//    before success is reported. A pipeline may discard its only plaintext
//    copy of the DEK once `wrap` exits 0; a power loss after that must not
//    be able to take the wrapped copy with it.
// 3. If anything fails after the file was created (short write, full disk,
//    flush error), the partial file is removed -- but only if the name still
//    refers to the very inode this call created (same st_dev/st_ino), so a
//    file someone else put at that path in the meantime is never deleted. A
//    truncated payload left behind would also block a retry with EEXIST.
func writeWrappedKeyFile(path: String, bytes: [UInt8], force: Bool) throws {
    if force {
        try secureOverwriteAndRemoveIfExists(path: path)
    }

    let fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, keyFilePermissions)
    guard fd >= 0 else {
        let err = errno
        if err == EEXIST {
            throw CLIError("\(path) already exists; pass --force|-f to overwrite")
        }
        throw CLIError("failed to open \(path) for writing: \(String(cString: strerror(err)))")
    }

    var created = stat()
    guard fstat(fd, &created) == 0 else {
        let err = errno
        close(fd)
        throw CLIError("failed to stat \(path) after creating it: \(String(cString: strerror(err))); remove \(path) before retrying")
    }

    var committed = false
    defer {
        close(fd)
        if !committed {
            var now = stat()
            if lstat(path, &now) == 0, now.st_dev == created.st_dev, now.st_ino == created.st_ino {
                unlink(path)
            }
        }
    }

    guard fchmod(fd, keyFilePermissions) == 0 else {
        throw CLIError("failed to set permissions on \(path): \(String(cString: strerror(errno)))")
    }

    try bytes.withUnsafeBufferPointer { buf in
        try writeAll(fd: fd, bytes: buf, context: path)
    }
    try flushToStorage(fd: fd, context: path)
    try flushParentDirectory(of: path)
    committed = true
}

// MARK: - Run

func runProvision(_ args: ProvisionArgs) throws {
    try validateServiceCharset(args.serviceName)
    let created = try provisionKEK(service: args.serviceName)
    let (status, fingerprint) = readKekFingerprint(service: args.serviceName)
    guard status == HKDFGuardStatus.success.rawValue else {
        throw CLIError("the KEK for service \"\(args.serviceName)\" exists but its fingerprint could not be read: \(describeStatus(status))")
    }
    if created {
        print("provisioned KEK for service \"\(args.serviceName)\" (keychain: \(keychainModeName()))")
        print("fingerprint: \(hexString(fingerprint)) -- record this; retire requires it")
    } else {
        // A KEK this operator didn't create could have been planted by another
        // process; the fingerprint is how to tell.
        print("KEK already exists for service \"\(args.serviceName)\" (keychain: \(keychainModeName())); nothing to do")
        print("fingerprint: \(hexString(fingerprint)) -- confirm it matches the one recorded when this service was provisioned")
    }
}

func runRetire(_ args: RetireArgs) throws {
    try validateServiceCharset(args.serviceName)
    // Validated as ASCII above, so this is the exact form the library stores.
    let service = args.serviceName.lowercased()
    switch args.confirmation {
    case .fingerprint(let fingerprint):
        try retireKEK(service: service, expectedFingerprint: fingerprint)
        print("retired KEK for service \"\(service)\" (fingerprint \(hexString(fingerprint)), keychain: \(keychainModeName()))")
        print("every payload wrapped under it is now permanently unrecoverable")
    case .corrupt:
        try retireCorruptKEK(service: service)
        print("retired corrupt KEK item for service \"\(service)\" (keychain: \(keychainModeName())); service \"\(service)\" can now be provisioned again")
    }
}

// Read-only. Exits 0 whenever the keychain gave a definite answer (present,
// absent, or corrupt) and 1 when it could not answer (access denied, read
// failure, no enclave), so scripts can tell "no key" from "can't tell".
func runStatus(serviceName: String) throws {
    try validateServiceCharset(serviceName)
    let service = serviceName.lowercased()
    print("service: \(service)")
    print("keychain: \(keychainModeName())")

    let (status, exists) = kekExistsStatus(service: service)
    switch status {
    case HKDFGuardStatus.success.rawValue where exists:
        let (fingerprintStatus, fingerprint) = readKekFingerprint(service: service)
        guard fingerprintStatus == HKDFGuardStatus.success.rawValue else {
            throw CLIError("a KEK exists for service \"\(service)\" but its fingerprint could not be read: \(describeStatus(fingerprintStatus))")
        }
        print("kek: present")
        print("fingerprint: \(hexString(fingerprint))")
    case HKDFGuardStatus.success.rawValue:
        print("kek: absent")
    case HKDFGuardStatus.kekCorrupted.rawValue:
        print("kek: corrupt (present but not reconstructable; see retire --corrupt)")
    default:
        throw CLIError("could not determine the KEK state for service \"\(service)\": \(describeStatus(status))")
    }
}

func runWrap(_ args: WrapArgs) throws {
    // Fast, friendly pre-check: fail before ever touching the Secure
    // Enclave/Keychain if the output path obviously already exists,
    // rather than making the caller pay for a full wrap operation just to
    // find out at the very end. writeWrappedKeyFile's O_EXCL is the actual
    // correctness guarantee against the exists-then-create race; this is
    // purely a fail-fast convenience on top of it.
    if !args.force && FileManager.default.fileExists(atPath: args.keyFilePath) {
        throw CLIError("\(args.keyFilePath) already exists; pass --force|-f to overwrite")
    }
    // Same fail-fast idea for --force: a symlink or non-regular file at the
    // path will be refused by the overwrite step anyway; refusing it here
    // first means no Secure Enclave/keychain work is spent on a command
    // that cannot complete.
    if args.force {
        try refuseUnlessAbsentOrRegularFile(path: args.keyFilePath)
    }

    // `args.serviceName` is not secret -- it's a logical identifier, not key
    // material -- so no special scoping is needed for it. Validated before
    // any DEK is read.
    try validateServiceCharset(args.serviceName)

    // `wrap` never checks for or creates a KEK -- hkdfguard_kek_exists and
    // hkdfguard_create_kek belong to the `provision` command alone. With no
    // KEK for this service hkdfguard_wrap_dek fails with kekNotFound before
    // touching anything, which callWithWrappedBuffer reports as "run
    // provision first".
    // The DEK exists in plaintext only inside this closure: withSuppliedDek
    // zeroes every copy it made (raw input, decoded bytes) as soon as wrapDek
    // returns the wrapped form -- before the potentially slow --force
    // secure overwrite and the file write below.
    let wrapped = try withSuppliedDek(args.dekSource) { dek in
        try wrapDek(service: args.serviceName, dek: dek)
    }

    // The KEK this payload was actually sealed to, as the library embedded
    // it in bytes 0-31 of the payload it just returned. Taken from the
    // payload rather than from a separate hkdfguard_kek_fingerprint call,
    // so what is checked and printed is exactly what the file will say.
    guard wrapped.count >= fingerprintLength else {
        throw CLIError("hkdfguard_wrap_dek returned \(wrapped.count) bytes, too short to carry a KEK fingerprint; nothing was written")
    }
    let usedFingerprint = Array(wrapped.prefix(fingerprintLength))

    // With --fingerprint, this is the operator's assertion of which KEK the
    // secret may be committed to. Checked before the file is written: a
    // mismatch means the keychain item for this service is not the KEK
    // that was provisioned (swapped, re-provisioned, or a different mode),
    // and a payload sealed to it must not leave this process.
    if let expected = args.expectedFingerprint, usedFingerprint != expected {
        throw CLIError("fingerprint mismatch for service \"\(args.serviceName)\": the KEK in the keychain is \(hexString(usedFingerprint)), not \(hexString(expected)); nothing was written -- the DEK was NOT committed to that key")
    }

    try writeWrappedKeyFile(path: args.keyFilePath, bytes: wrapped, force: args.force)

    print("wrapped key written to \(args.keyFilePath) (\(wrapped.count) bytes, permissions 0600, service \"\(args.serviceName)\", keychain: \(keychainModeName()))")
    print("fingerprint: \(hexString(usedFingerprint))\(args.expectedFingerprint == nil ? " -- confirm it matches the one recorded when this service was provisioned" : " (confirmed)")")
}

// MARK: - Entry point

// Runs a command body; a runtime failure prints the error and exits 1 --
// distinct from an argument-parsing failure (exit 2) below, matching the
// Linux tool's own exit-code convention.
func runOrExit(_ body: () throws -> Void) -> Never {
    do {
        try body()
        exit(0)
    } catch {
        FileHandle.standardError.write("error: \(error)\n".data(using: .utf8)!)
        exit(1)
    }
}

do {
    switch try parseArgs(CommandLine.arguments) {
    case .help:
        printUsage()
        exit(0)
    case .provision(let args):
        runOrExit { try runProvision(args) }
    case .wrap(let args):
        runOrExit { try runWrap(args) }
    case .retire(let args):
        runOrExit { try runRetire(args) }
    case .status(let serviceName):
        runOrExit { try runStatus(serviceName: serviceName) }
    }
} catch {
    // An argument-parsing failure: print the error and usage, then exit 2.
    FileHandle.standardError.write("error: \(error)\n".data(using: .utf8)!)
    printUsage()
    exit(2)
}
