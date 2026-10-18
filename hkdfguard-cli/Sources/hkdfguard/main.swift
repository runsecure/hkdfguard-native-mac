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
// Linux equivalent (hkdfguard-native-linux/src/bin/hkdfguard.rs): the same
// `provision`/`wrap` commands and flags, DEK from stdin or a file only,
// 0600 output (see writeWrappedKeyFile), and process hardening at startup.
// `retire`, `status`, and `wrap --fingerprint` are macOS additions.
//
// The KEK's `service` identity is exactly the caller-supplied
// `--service-name`; there is no further structure to it.
//
// Usage:
//   hkdfguard provision --service-name|-sn <name>
//
//   hkdfguard retire --service-name|-sn <name> \
//       ( --fingerprint|-fp <64 hex chars> | --corrupt )
//
//   hkdfguard status --service-name|-sn <name>
//
//   hkdfguard wrap \
//       --key-file-path|-kf <key-file-path> \
//       --service-name|-sn <name> \
//       ( --dek-stdin | --dek-file <path> ) \
//       [--group|-g <name>] [--fingerprint|-fp <64 hex chars>] [--force|-f]
//
// `provision` is idempotent: a second run against the same service verifies
// the existing KEK (hkdfguard_create_kek loads and rebuilds it), reports
// "already provisioned ...; verified", and exits 0.
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
//                      the pipeline or a secret store), never from an
//                      interactive terminal. At most 64 bytes; one
//                      trailing newline (or CRLF) and a leading UTF-8 BOM
//                      are ignored, nothing else, and UTF-16 is refused --
//                      the Linux tool's rules, for both sources.
//   --dek-file <path>  base64 DEK read from a file. It must be a regular
//                      file (not a symlink, FIFO, or device), owned by root
//                      or by this process's user, granting no access to
//                      group or others (mode 0400/0600), and not reached
//                      through a symlinked folder -- the Linux tool's rule
//                      (see openDekFile, openRealFolder).
//
// There is deliberately no way to pass the DEK itself as a command-line
// argument: an argv value is visible to every other process on the host
// (`ps`) for the life of the process and is recorded in the invoking
// shell's history file. Both stdin and a file avoid that entirely.
//
// The wrapped payload is written to <key-file-path> with POSIX permissions
// 0600 (owner read/write, no access for anyone else) -- set
// atomically at file-creation time -- or, with --group <name>, 0640 with
// that group: the owner plus one group, read-only, as the Linux tool's
// --group does (see resolveKeyFileGroup for the groups refused). With --force against a pre-existing
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
// Opt-in process hardening: core dumps off, debugger attachment denied. The
// tool calls it before reading anything, as the Linux tool does.
//
// How strict it is about the executable's own code signature depends on
// the build. A distribution build -- build-dist.sh compiles with
// HKDFGUARD_STRICT_HARDENING, for the bare CLI always and for the app's
// CLI when exported for developer-id -- is signed with the Hardened Runtime
// and no get-task-allow, so it passes
// HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE: a shipped CLI whose
// signature somehow lost that protection refuses to handle a DEK. Every
// other build (`swift build`, the tests, a local Xcode build) is advisory:
// its development signature is only logged.
@_silgen_name("hkdfguard_harden_process")
func hkdfguard_harden_process() -> Int32

@_silgen_name("hkdfguard_harden_process_with_flags")
func hkdfguard_harden_process_with_flags(_ flags: UInt32) -> Int32

let hardenRequireProtectedSignature: UInt32 = 0x1 // HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE

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
    // The shared HkdfGuard status table (hkdfguard-native-linux's
    // include/hkdfguard.h is the source of record); the comment on each case
    // is its HKDFGUARD_* name.
    case success = 0                       // OK
    case invalidInputLength = -1           // ERR_INVALID_ARGUMENT
    case outputBufferTooSmall = -2         // ERR_BUFFER_TOO_SMALL
    case enclaveUnavailable = -3           // ERR_PROVIDER_UNAVAILABLE
    case encryptionFailed = -5             // ERR_CRYPTO_ERROR
    case unexpectedOutputLength = -6       // ERR_INTERNAL_ERROR
    case invalidServiceIdentifier = -8     // ERR_INVALID_SERVICE_NAME
    case payloadMalformed = -10            // ERR_PAYLOAD_MALFORMED
    case decryptionFailed = -11            // ERR_PAYLOAD_AUTH_FAILED
    case unsupportedCiphersuite = -12      // ERR_PAYLOAD_UNSUPPORTED
    case fingerprintMismatch = -16         // ERR_KEK_FINGERPRINT_MISMATCH
    case kekNotFound = -17                 // ERR_KEK_NOT_FOUND
    case keychainAccessDenied = -18        // ERR_KEK_ACCESS_DENIED
    case kekCorrupted = -19                // ERR_KEK_INVALID
    case processHardeningFailed = -20      // ERR_PROCESS_HARDENING_FAILED
    case fileNotFound = -32                // ERR_FILE_NOT_FOUND
    case fileAccessDenied = -33            // ERR_FILE_ACCESS_DENIED
    case fileIO = -34                      // ERR_FILE_IO
    case fileTooShort = -35                // ERR_FILE_TOO_SHORT
    case fileTooLong = -36                 // ERR_FILE_TOO_LONG
    case fileUnprotectedKey = -37          // ERR_FILE_PLAINTEXT_KEY
    case fileMalformed = -38               // ERR_FILE_MALFORMED
    case fileInsecure = -39                // ERR_FILE_UNTRUSTED
    case accessControlCreationFailed = -96 // ERR_MAC_ACCESS_CONTROL_CREATION_FAILED
    case keyGenerationFailed = -97         // ERR_MAC_KEY_GENERATION_FAILED
    case keychainWriteFailed = -98         // ERR_MAC_KEYCHAIN_WRITE_FAILED
    case kekVerificationFailed = -99       // ERR_MAC_KEK_VERIFICATION_FAILED
    case keychainReadFailed = -100         // ERR_MAC_KEYCHAIN_READ_FAILED

    var description: String {
        switch self {
        case .success: return "success"
        case .invalidInputLength: return "invalid argument (bad service name or DEK length)"
        case .outputBufferTooSmall: return "output buffer too small"
        case .enclaveUnavailable: return "the Secure Enclave is not available on this machine"
        case .encryptionFailed: return "a cryptographic operation failed"
        case .unexpectedOutputLength: return "internal error: the library produced an unexpected output length"
        case .invalidServiceIdentifier: return "the service name is missing, empty, longer than 128 characters, or contains a character other than an ASCII letter, digit, or '.', starts with '.', or contains \"..\""
        case .payloadMalformed: return "the wrapped payload is malformed"
        case .decryptionFailed: return "decryption failed"
        case .unsupportedCiphersuite: return "the wrapped payload uses a ciphersuite this build does not support"
        case .fingerprintMismatch: return "the wrapped payload's embedded KEK fingerprint does not match the current key"
        case .kekNotFound: return "no key exists yet for this service -- call hkdfguard_create_kek first"
        case .keychainAccessDenied: return "the keychain denied access (locked, no UI session, access prompt declined, or missing entitlement) -- a key for this service may already exist"
        case .kekCorrupted: return "a keychain item exists for this service but could not be reconstructed into a usable key"
        case .processHardeningFailed: return "the process could not be hardened (core dumps or debugger attachment could not be disabled, a debugger is already attached, or a distribution build's code signature lets other processes debug it)"
        case .fileNotFound: return "the key file does not exist"
        case .fileAccessDenied: return "this process may not read the key file"
        case .fileIO: return "the key file is not a regular file, or reading it failed"
        case .fileTooShort: return "the key file is shorter than a wrapped DEK"
        case .fileTooLong: return "the key file is longer than a wrapped DEK"
        case .fileUnprotectedKey: return "the key file appears to hold an UNWRAPPED DEK -- treat it as exposed"
        case .fileMalformed: return "the key file is not a well-formed wrapped DEK"
        case .fileInsecure: return "the key file is owned by another user, writable by group or others, or hard-linked"
        case .accessControlCreationFailed: return "failed to set up access control for a new key"
        case .keyGenerationFailed: return "the Secure Enclave refused to generate a new key"
        case .keychainWriteFailed: return "failed to persist the newly generated key to the keychain"
        case .kekVerificationFailed: return "the newly created key could not be verified after being stored"
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

let programName = "hkdfguard"
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
    /// `--group`: who besides the owner may read the key file. nil: no one.
    var groupName: String?
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
                                    ( \(dekSourceFlags) ) [--group|-g <name>]
                                    [--fingerprint|-fp <hex>] [--force|-f]
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
                      reports it as corrupt (-19) and the Secure Enclave is proven
                      usable in this session, so a healthy KEK that merely could not
                      be loaded right now is never mistaken for a corrupt one.
          status      report the keychain mode, whether a KEK exists for <name>, and
                      its fingerprint. Read-only: never creates or deletes anything.

        wrap options (exactly one DEK source is required):
          --key-file-path|-kf <path>  where to write the wrapped payload
          --dek-stdin         read the base64 DEK from standard input
          --dek-file <path>   read the base64 DEK from a file (a regular file, not a
                      symlink, owned by you or root, mode 0400 or 0600)
          --group|-g <name>   also let this group read the file (mode 0640): a dedicated
                      group for the service that unwraps it, which you belong to;
                      broad groups (staff, everyone, admin, wheel, ...) are refused
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

// Stores a flag's value, refusing a second one rather than letting the last
// win: `-kf a.key ... -kf b.key` is ambiguous about which file the operator
// meant, and silently picking one is how the wrong key file gets written or
// the wrong service's KEK gets used. `flag` is the flag's long name. The
// Linux tool's set_once.
func setOnce<T>(_ slot: inout T?, _ flag: String, _ value: T) throws {
    guard slot == nil else {
        throw CLIError("give \(flag) at most once")
    }
    slot = value
}

// The same for a flag that takes no value.
func setOnce(_ flag: inout Bool, _ name: String) throws {
    guard !flag else {
        throw CLIError("give \(name) at most once")
    }
    flag = true
}

let subcommandList = "`provision`, `wrap`, `retire` or `status`"

func parseArgs(_ arguments: [String]) throws -> Command {
    var rest = Array(arguments.dropFirst()) // skip argv[0]
    guard !rest.isEmpty else {
        throw CLIError("missing subcommand: expected \(subcommandList)")
    }
    let command = rest.removeFirst()
    switch command {
    case "--help", "-h", "help":
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
        throw CLIError("unknown subcommand \"\(command)\": expected \(subcommandList)")
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
            try setOnce(&serviceName, "--service-name", parseServiceName(arg, &iterator))
        default:
            throw CLIError("unrecognized argument for `status`: \(arg)")
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
            try setOnce(&serviceName, "--service-name", parseServiceName(arg, &iterator))
        case "--fingerprint", "-fp":
            guard let value = iterator.next(), !value.isEmpty else {
                throw CLIError("\(arg) requires a value")
            }
            try setOnce(&fingerprint, "--fingerprint", parseFingerprintHex(value))
        case "--corrupt":
            try setOnce(&corrupt, "--corrupt")
        default:
            throw CLIError("unrecognized argument for `retire`: \(arg)")
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
            try setOnce(&serviceName, "--service-name", parseServiceName(arg, &iterator))
        case "--key-file-path", "-kf", "--dek-stdin", "--dek-file", "--force", "-f", "--group", "-g":
            throw CLIError("\(arg) is not valid for `provision`; it belongs to `wrap`")
        default:
            throw CLIError("unrecognized argument for `provision`: \(arg)")
        }
    }

    guard let serviceName else { throw CLIError("provision: missing required --service-name|-sn") }
    return .provision(ProvisionArgs(serviceName: serviceName))
}

func parseWrap(_ arguments: [String]) throws -> Command {
    var keyFilePath: String?
    var serviceName: String?
    var dekSource: DekSource?
    var force = false
    var expectedFingerprint: [UInt8]?
    var groupName: String?

    // Rejects a second DEK source rather than letting the last one win:
    // silently ignoring one of two explicitly requested inputs is exactly
    // the kind of ambiguity that leads to wrapping the wrong key. The Linux
    // tool's message.
    func setSource(_ source: DekSource) throws {
        guard dekSource == nil else {
            throw CLIError("give exactly one of --dek-stdin or --dek-file")
        }
        dekSource = source
    }

    var iterator = arguments.makeIterator()
    while let arg = iterator.next() {
        switch arg {
        case "--help", "-h":
            return .help
        case "--force", "-f":
            try setOnce(&force, "--force")
        case "--fingerprint", "-fp":
            guard let value = iterator.next(), !value.isEmpty else {
                throw CLIError("\(arg) requires a value")
            }
            try setOnce(&expectedFingerprint, "--fingerprint", parseFingerprintHex(value))
        case "--key-file-path", "-kf":
            guard let value = iterator.next() else {
                throw CLIError("\(arg) requires a value")
            }
            guard !value.isEmpty else {
                throw CLIError("--key-file-path must not be empty")
            }
            try setOnce(&keyFilePath, "--key-file-path", value)
        case "--service-name", "-sn":
            try setOnce(&serviceName, "--service-name", parseServiceName(arg, &iterator))
        case "--group", "-g":
            guard let value = iterator.next() else {
                throw CLIError("\(arg) requires a value")
            }
            guard !value.isEmpty else {
                throw CLIError("--group must not be empty")
            }
            try setOnce(&groupName, "--group", value)
        case "--dek-stdin":
            try setSource(.stdin)
        case "--dek-file":
            guard let value = iterator.next() else {
                throw CLIError("\(arg) requires a value")
            }
            guard !value.isEmpty else {
                throw CLIError("--dek-file must not be empty")
            }
            try setSource(.file(value))
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
            throw CLIError("unrecognized argument for `wrap`: \(arg)")
        }
    }

    guard let keyFilePath else { throw CLIError("wrap: missing required --key-file-path|-kf") }
    guard let serviceName else { throw CLIError("wrap: missing required --service-name|-sn") }
    guard let dekSource else {
        throw CLIError("wrap: missing required --dek-stdin or --dek-file <path>")
    }

    return .wrap(
        WrapArgs(
            keyFilePath: keyFilePath,
            serviceName: serviceName,
            dekSource: dekSource,
            force: force,
            expectedFingerprint: expectedFingerprint,
            groupName: groupName
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
// alphanumeric characters or '.', not starting with '.', and with no two
// consecutive dots -- the Linux tool's rule and messages.
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
    if service.hasPrefix(".") {
        throw CLIError("service name \"\(service)\" must not start with '.'")
    }
    if service.contains("..") {
        throw CLIError("service name \"\(service)\" must not contain consecutive dots")
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
// `provision`: the only place the setup calls are made. Always calls
// hkdfguard_create_kek, whether or not the KEK exists, as the Linux and
// Windows tools do: for an existing KEK that call loads the keychain item
// and rebuilds the Secure Enclave key from it, so an item that exists but
// can't be used (kekCorrupted, -19; an access denial, -18) fails here at
// deployment rather than at the first wrap. kek_exists is still asked
// first, only to report the outcome precisely -- "provisioned" versus
// "already provisioned". Neither call changes an existing KEK. Returns
// whether the KEK was newly created.
func provisionKEK(service: String) throws -> Bool {
    var exists: Int32 = 0
    let existsStatus = service.withCString { hkdfguard_kek_exists($0, &exists) }
    guard existsStatus == HKDFGuardStatus.success.rawValue else {
        throw CLIError("hkdfguard_kek_exists failed: \(describeStatus(existsStatus))")
    }

    let createStatus = service.withCString { hkdfguard_create_kek($0) }
    guard createStatus == HKDFGuardStatus.success.rawValue else {
        throw CLIError("hkdfguard_create_kek failed for service \"\(service)\": \(describeStatus(createStatus))")
    }
    return exists == 0
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
    let itemFingerprint = Array(SHA256.hash(data: key.publicKey.x963Representation)) // the library's kekFingerprint: SHA-256 of 0x04 || x || y
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
// (kekCorrupted, -19) -- present but not reconstructable -- and only after
// proving the enclave works in this session, so the -19 reflects the item
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
func wrapDek(service: String, dek: UnsafeRawBufferPointer) throws -> [UInt8] {
    try callWithWrappedBuffer("hkdfguard_wrap_dek", service: service) { outPtr, outLen in
        service.withCString { servicePtr in
            hkdfguard_wrap_dek(
                servicePtr,
                dek.bindMemory(to: UInt8.self).baseAddress,
                Int32(dek.count),
                outPtr,
                outLen
            )
        }
    }
}

// MARK: - Reading the pipeline's DEK

// Upper bound on the DEK input, in bytes -- the Linux tool's
// MAX_DEK_INPUT_LEN. Base64 of a 32-byte DEK is 44 characters; this leaves
// room for a trailing newline (or CRLF) and little more, so a wrong file or
// an unbounded pipe fails fast instead of being buffered.
let maxDekInputLength = 64

// Mode bits that must be clear on a --dek-file: no access at all for group
// or others.
let forbidGroupOtherAccess: mode_t = 0o077

// The folder `path` is named in must be a real folder at the place spelled:
// no symbolic link anywhere in it, as the Linux tool requires (and as the
// Windows tool refuses junctions). O_NOFOLLOW and O_EXCL only guard the
// last component, so without this a symlinked folder above the path is
// followed silently -- and whoever can plant one where the operator writes
// could redirect an (often root) `wrap --force` into overwriting and
// deleting a file in another folder, or make `--dek-file` read a DEK they
// put somewhere else.
//
// One difference from Linux, for macOS's own layout: /tmp, /var and /etc
// are symbolic links into /private. A link is accepted when only root can
// have made it or can change it -- owned by root, in a root-owned folder no
// one else can write -- and is followed to its real folder. Any other link
// is refused.
//
// Returns the checked folder *open* (CheckedFolder), and callers do every
// filesystem call that follows through its descriptor -- openat, fstatat,
// unlinkat, fsync -- never by path, so nothing swapped after the check
// (a folder replaced by a link, say) can redirect them. `.` and `..` in the
// spelled path are removed as text first. `what` names the path in messages.
struct CheckedFolder {
    /// The folder the file is named in, reached by a chain of no-follow
    /// openat() calls from "/": every later operation on the file goes
    /// through this descriptor (openat, fstatat, unlinkat, fsync), so a
    /// folder swapped for a symbolic link after the check cannot redirect
    /// any of them -- the descriptor still names the folder that was checked.
    let fd: Int32
    /// That folder's path as walked, for messages.
    let path: String
    /// The file's name within it.
    let leaf: String

    var filePath: String { path == "/" ? "/" + leaf : path + "/" + leaf }
    func close() { _ = Darwin.close(fd) }
}

func openRealFolder(_ path: String, what: String) throws -> CheckedFolder {
    var components: [String] = []
    let absolute = path.hasPrefix("/") ? path : FileManager.default.currentDirectoryPath + "/" + path
    for part in absolute.split(separator: "/", omittingEmptySubsequences: true) {
        switch part {
        case ".": continue
        case "..": if !components.isEmpty { components.removeLast() }
        default: components.append(String(part))
        }
    }
    guard let leaf = components.popLast() else {
        throw CLIError("\(what) \(path) has no file name")
    }

    // Walked one folder at a time, each opened *from the previous one's
    // descriptor* with O_NOFOLLOW: what is checked is exactly what is held,
    // with no path re-resolved later. An accepted link's target is pushed
    // back onto the queue and walked the same way (never handed to
    // realpath(), which would follow a further link inside it, a user's
    // included), so every link on the way must itself be root-only. A `..`
    // inside a link target is opened as ".." from the folder reached so
    // far, which contains no links.
    var dirFd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    guard dirFd >= 0 else {
        throw CLIError("failed to open / to resolve \(what) \(path): \(String(cString: strerror(errno)))")
    }
    var current = "/"
    func join(_ folder: String, _ name: String) -> String { folder == "/" ? "/" + name : folder + "/" + name }
    func parentOf(_ folder: String) -> String {
        guard folder != "/", let slash = folder.lastIndex(of: "/") else { return "/" }
        return slash == folder.startIndex ? "/" : String(folder[..<slash])
    }
    func move(to newFd: Int32, _ newPath: String) {
        _ = Darwin.close(dirFd)
        dirFd = newFd
        current = newPath
    }

    var remaining = components[...]
    var linksFollowed = 0
    do {
        while let name = remaining.popFirst() {
            switch name {
            case ".":
                continue
            case "..":
                let up = openat(dirFd, "..", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
                guard up >= 0 else {
                    throw CLIError("failed to resolve the folder of \(what) \(path): \(String(cString: strerror(errno)))")
                }
                move(to: up, parentOf(current))
                continue
            default:
                break
            }
            let candidate = join(current, name)
            var st = stat()
            guard fstatat(dirFd, name, &st, AT_SYMLINK_NOFOLLOW) == 0 else {
                throw CLIError("failed to resolve the folder of \(what) \(path): \(candidate): \(String(cString: strerror(errno)))")
            }
            switch st.st_mode & S_IFMT {
            case S_IFDIR:
                let next = openat(dirFd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard next >= 0 else {
                    let err = errno
                    if err == ELOOP {
                        throw CLIError("\(what) \(path): the folder \(candidate) became a symbolic link while it was being checked; refusing to use it")
                    }
                    throw CLIError("failed to open the folder \(candidate) of \(what) \(path): \(String(cString: strerror(err)))")
                }
                move(to: next, candidate)
            case S_IFLNK:
                var parent = stat()
                let rootOnly = st.st_uid == 0 && fstat(dirFd, &parent) == 0 && parent.st_uid == 0
                    && parent.st_mode & (S_IWGRP | S_IWOTH) == 0
                guard rootOnly else {
                    throw CLIError("\(what) \(path): the folder \(candidate) is a symbolic link; the path must be a real path with no links in it (macOS's own root-owned links, such as /tmp and /var, are accepted)")
                }
                linksFollowed += 1
                guard linksFollowed <= 32 else { // the kernel's own ELOOP limit
                    throw CLIError("\(what) \(path): too many symbolic links in its folders")
                }
                var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN) + 1)
                let length = readlinkat(dirFd, name, &buffer, Int(MAXPATHLEN))
                guard length > 0 else {
                    throw CLIError("\(what) \(path): could not read the link \(candidate): \(String(cString: strerror(errno)))")
                }
                let target = String(decoding: buffer[0..<length].map { UInt8(bitPattern: $0) }, as: UTF8.self)
                if target.hasPrefix("/") {
                    let root = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
                    guard root >= 0 else {
                        throw CLIError("failed to open / to resolve \(what) \(path): \(String(cString: strerror(errno)))")
                    }
                    move(to: root, "/")
                }
                remaining = (target.split(separator: "/", omittingEmptySubsequences: true).map(String.init) + remaining)[...]
            default:
                throw CLIError("\(what) \(path): \(candidate) is not a folder")
            }
        }
    } catch {
        _ = Darwin.close(dirFd)
        throw error
    }
    return CheckedFolder(fd: dirFd, path: current, leaf: leaf)
}



// Opens a --dek-file with the same hardening as the Linux tool's
// read_dek_file: O_NOFOLLOW so a symlink fails the open outright, O_NONBLOCK
// so a FIFO fails the regular-file check below instead of blocking the open,
// and ownership/permission checks made against the *opened descriptor*
// rather than the path, so nothing can be swapped between the check and the
// read. The file must be a regular file owned by root or this process's
// effective user, granting no access to group or others (0400/0600).
func openDekFile(_ spelledPath: String) throws -> Int32 {
    // No symbolic link in the folders above it either (see openRealFolder);
    // O_NOFOLLOW below covers the file itself, opened within the checked
    // folder so nothing can be swapped in between.
    let folder = try openRealFolder(spelledPath, what: "--dek-file")
    defer { folder.close() }
    let path = spelledPath
    let fd = openat(folder.fd, folder.leaf, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK | O_NOCTTY)
    guard fd >= 0 else {
        let err = errno
        if err == ELOOP {
            throw CLIError("--dek-file \(path) is a symlink; refusing to follow it")
        }
        throw CLIError("--dek-file: failed to read \(path): \(String(cString: strerror(err)))")
    }
    var ok = false
    defer { if !ok { close(fd) } }

    var st = stat()
    guard fstat(fd, &st) == 0 else {
        throw CLIError("--dek-file: failed to stat \(path): \(String(cString: strerror(errno)))")
    }
    guard st.st_mode & S_IFMT == S_IFREG else {
        // A FIFO would block the read indefinitely; a directory or device
        // makes no sense as a key source.
        throw CLIError("--dek-file \(path) is not a regular file")
    }
    let euid = geteuid()
    guard st.st_uid == 0 || st.st_uid == euid else {
        throw CLIError("--dek-file \(path) is owned by uid \(st.st_uid), which is neither root nor this process's user")
    }
    let offending = st.st_mode & forbidGroupOtherAccess
    guard offending == 0 else {
        throw CLIError("--dek-file \(path) permissions are too broad (mode \(String(st.st_mode & 0o7777, radix: 8)); bits \(String(offending, radix: 8)) must be clear)")
    }
    ok = true
    return fd
}


// The Linux and Windows tools' messages, word for word.
//
// Deliberately fixed: it names no character, offset or bit pattern, so a
// mistyped DEK never puts part of itself into a log.
let invalidBase64DekMessage = "the DEK input is not valid base64 (standard alphabet, padded, at most one trailing newline)"
// A DEK typed or pasted at a terminal is echoed and stays in the scrollback.
let terminalDekMessage = "refusing to read the DEK from an interactive terminal, where it would be echoed and kept in the scrollback; pipe it in instead, e.g. printf '%s' \"$DEK_B64\" | hkdfguard wrap ... --dek-stdin"
// The fix is on the sending side, so say what it is.
let utf16DekMessage = "the DEK input is UTF-16 encoded; send it as ASCII or UTF-8 base64 text (in PowerShell, set [Console]::OutputEncoding or $OutputEncoding to UTF-8)"

// Branch-free helpers for decodeBase64ConstantTime. Every one returns 0 or 1
// (or a masked value) using wrapping arithmetic on UInt32, with no
// data-dependent branch or table lookup.
@inline(__always) func ctEq(_ a: UInt32, _ b: UInt32) -> UInt32 { ((a ^ b) &- 1) >> 31 }
@inline(__always) func ctInRange(_ c: UInt32, _ lo: UInt32, _ hi: UInt32) -> UInt32 {
    (((lo &- 1) &- c) & (c &- (hi &+ 1))) >> 31 & 1
}
@inline(__always) func ctMask(_ bit: UInt32) -> UInt32 { 0 &- bit }

// Decodes strict, padded, standard base64 (RFC 4648 section 4: the `+/`
// alphabet, a length that is a multiple of 4, `=` only as the last one or
// two characters, and zero in the bits the padding leaves unused) into
// `out`, and returns how many bytes it decodes to -- or nil if `text` is
// not that. The rules of the Linux tool's decoder (base64ct) and the
// Windows tool's.
//
// Constant time with respect to the text, as both of theirs are: the only
// branches are on its length, which is public; every character is
// classified and accumulated with mask arithmetic, so how long this takes
// says nothing about which character, if any, was wrong. Bytes are written
// to `out` at fixed positions only, up to its size; the caller checks the
// returned length.
func decodeBase64ConstantTime(_ text: UnsafeRawBufferPointer, into out: UnsafeMutableRawBufferPointer) -> Int? {
    let n = text.count
    guard n > 0, n % 4 == 0 else { return nil }

    let pad1 = ctEq(UInt32(text[n - 1]), 0x3D)        // '=' last
    let pad2 = ctEq(UInt32(text[n - 2]), 0x3D) & pad1 // and '=' before it
    var valid: UInt32 = 1
    var lastValue2: UInt32 = 0 // the value at n-2: the last data character when one '='
    var lastValue3: UInt32 = 0 // the value at n-3: the last data character when two
    var o = 0
    var quad: UInt32 = 0
    for i in 0..<n {
        let c = UInt32(text[i])
        let isPad = (ctEq(UInt32(i), UInt32(n - 1)) & pad1) | (ctEq(UInt32(i), UInt32(n - 2)) & pad2)
        let upper = ctInRange(c, 0x41, 0x5A)
        let lower = ctInRange(c, 0x61, 0x7A)
        let digit = ctInRange(c, 0x30, 0x39)
        let plus = ctEq(c, 0x2B)
        let slash = ctEq(c, 0x2F)
        let value = ((c &- 0x41) & ctMask(upper)) | ((c &- (0x61 - 26)) & ctMask(lower))
            | ((c &+ (52 - 0x30)) & ctMask(digit)) | (62 & ctMask(plus)) | (63 & ctMask(slash))
        valid &= upper | lower | digit | plus | slash | isPad
        let v = value & ~ctMask(isPad) & 0x3F // a pad contributes zero bits
        lastValue2 = (lastValue2 & ~ctMask(ctEq(UInt32(i), UInt32(n - 2)))) | (v & ctMask(ctEq(UInt32(i), UInt32(n - 2))))
        lastValue3 = (lastValue3 & ~ctMask(ctEq(UInt32(i), UInt32(n - 3)))) | (v & ctMask(ctEq(UInt32(i), UInt32(n - 3))))
        quad = (quad << 6) | v
        if i % 4 == 3 { // public: the position, not the data
            for k in 0..<3 where o < out.count {
                out[o] = UInt8(truncatingIfNeeded: quad >> (16 - 8 * UInt32(k)))
                o += 1
            }
            quad = 0
        }
    }
    // '=' anywhere but the end is not a pad, so it already failed above.
    // The unused bits: 2 under one '=' (n-2's low 2), 4 under two (n-3's low 4).
    let oneBad = (pad1 & (pad2 ^ 1)) & (ctEq(lastValue2 & 0x3, 0) ^ 1)
    let twoBad = pad2 & (ctEq(lastValue3 & 0xF, 0) ^ 1)
    valid &= (oneBad | twoBad) ^ 1
    let length = n / 4 * 3 - Int(pad1 + pad2)
    return valid == 1 ? length : nil
}

// Reads the base64 DEK for `source`, decodes it, and hands the decoded bytes
// to `body` -- the only window in which the plaintext DEK exists here.
//
// Every copy of the DEK this function makes -- the base64 text it reads and
// the bytes that decodes to -- lives in ONE allocation, as in the Linux
// tool's DekScratch:
//
// - Allocated up front at a fixed size and never grown. A growable buffer
//   (Data from readDataToEndOfFile, Data(contentsOf:)) reallocates as it
//   fills and leaves abandoned, unzeroed copies of the input in freed memory.
// - Locked into RAM with mlock(2), so it is never written to swap. If the
//   lock is refused, a warning is printed and the DEK is still handled
//   (macOS encrypts swap regardless), as on Linux.
// - Never turned into a String or Data: Swift Strings and Foundation's
//   base64 decoder make copies this function couldn't zero. Trimming is an
//   index range over the raw bytes, and decoding writes straight into the
//   locked allocation.
// - Zeroed (memset_s) on every path before it is unlocked and freed.
func withSuppliedDek<T>(_ source: DekSource, _ body: (UnsafeRawBufferPointer) throws -> T) throws -> T {
    let inputCapacity = maxDekInputLength + 1
    let pageSize = Int(getpagesize())
    let byteCount = (inputCapacity + dekLen + pageSize - 1) / pageSize * pageSize
    let scratch = UnsafeMutableRawBufferPointer.allocate(byteCount: byteCount, alignment: pageSize)
    scratch.initializeMemory(as: UInt8.self, repeating: 0)
    let locked = mlock(scratch.baseAddress!, byteCount) == 0
    if !locked {
        FileHandle.standardError.write("warning: could not lock the DEK's buffer into memory (mlock: \(String(cString: strerror(errno)))); it could be written to swap\n".data(using: .utf8)!)
    }
    defer {
        _ = memset_s(scratch.baseAddress!, byteCount, 0, byteCount)
        if locked { munlock(scratch.baseAddress!, byteCount) }
        scratch.deallocate()
    }
    let input = UnsafeMutableRawBufferPointer(rebasing: scratch[0..<inputCapacity])
    let decoded = UnsafeMutableRawBufferPointer(rebasing: scratch[inputCapacity..<(inputCapacity + dekLen)])

    let flag = source.flag
    let fd: Int32
    let what: String
    switch source {
    case .stdin:
        // A DEK typed or pasted at a terminal is echoed and stays in the
        // scrollback: refuse a terminal outright rather than read it, as the
        // Linux and Windows tools do.
        guard isatty(STDIN_FILENO) != 1 else {
            throw CLIError(terminalDekMessage)
        }
        fd = STDIN_FILENO
        what = "standard input"
    case .file(let path):
        fd = try openDekFile(path)
        what = path
    }
    defer {
        if case .file = source { close(fd) }
    }

    // Reads until EOF, or until one byte past the limit -- enough to know
    // the input is too large without reading the rest of it.
    var total = 0
    while total < input.count {
        let n = read(fd, input.baseAddress! + total, input.count - total)
        if n < 0 {
            if errno == EINTR { continue }
            throw CLIError("\(flag): failed to read \(what): \(String(cString: strerror(errno)))")
        }
        if n == 0 { break }
        total += n
    }
    guard total <= maxDekInputLength else {
        // UTF-16 doubles the text, so it is over the limit long before the
        // decoder could say why: name it here instead.
        if total >= 2 && ((input[0] == 0xFF && input[1] == 0xFE) || (input[0] == 0xFE && input[1] == 0xFF)) {
            throw CLIError(utf16DekMessage)
        }
        throw CLIError("\(flag): \(what) is longer than \(maxDekInputLength) bytes; expected base64 of a \(dekLen)-byte DEK")
    }

    // Exactly one trailing newline (optionally CRLF) is tolerated, so a file
    // written by `printf '%s\n'` or an editor still works -- nothing else,
    // as in the Linux tool: leading or other trailing whitespace is part of
    // the input and fails to decode.
    // A leading UTF-8 byte-order mark, which some Windows tools (PowerShell,
    // .NET) prepend, is skipped; a UTF-16 one is refused as such, since the
    // fix is on the sending side -- the Linux and Windows tools' rules.
    let bytes = UnsafeRawBufferPointer(rebasing: input[0..<total])
    var start = 0
    if total >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF {
        start = 3
    }
    if total - start >= 2 && ((bytes[start] == 0xFF && bytes[start + 1] == 0xFE) || (bytes[start] == 0xFE && bytes[start + 1] == 0xFF)) {
        throw CLIError(utf16DekMessage)
    }
    var end = total
    if end > start && bytes[end - 1] == 0x0A {
        end -= 1
        if end > start && bytes[end - 1] == 0x0D { end -= 1 }
    }
    guard start < end else {
        if case .stdin = source {
            throw CLIError("\(flag): no data on standard input")
        }
        throw CLIError("\(flag): \(what) is empty")
    }

    let text = UnsafeRawBufferPointer(rebasing: bytes[start..<end])
    guard let decodedLength = decodeBase64ConstantTime(text, into: decoded) else {
        throw CLIError("\(flag): \(invalidBase64DekMessage)")
    }
    guard decodedLength == dekLen else {
        throw CLIError("\(flag): the DEK must decode to exactly \(dekLen) bytes, got \(decodedLength)")
    }
    // The base64 text has served its only purpose: zero it now, before the
    // wrap, rather than when this function returns -- as the Linux tool
    // does. Only the decoded DEK stays, for `body`.
    if let inputBase = input.baseAddress {
        _ = memset_s(inputBase, input.count, 0, input.count)
    }
    return try body(UnsafeRawBufferPointer(decoded))
}

// MARK: - Writing the wrapped key file

// The permissions every wrapped-key file is written with: owner
// read/write, no access for anyone else (POSIX 0600). The user who wraps
// must be the user whose keychain holds the KEK, so the same user unwraps.
let keyFilePermissions: mode_t = 0o600
// With --group: rw-r-----, the owner plus that one group, read-only -- the
// Linux tool's 0640 and the Windows tool's owner-plus-group DACL.
let keyFileGroupPermissions: mode_t = 0o640

// Groups --group refuses: each covers essentially every account on a Mac
// (staff, everyone, localaccounts), its administrators (admin, wheel), or
// nobody in particular (nobody, nogroup). Granting one read access is no
// narrower than world-readable for this purpose. Matched by resolved gid,
// so a numeric gid can't dodge the list; gid 0 is refused whatever its
// name. The Linux and Windows tools refuse their own equivalents.
let overBroadGroups = ["wheel", "admin", "staff", "everyone", "localaccounts", "netaccounts", "nobody", "nogroup"]

// Looks a group up by name, or by gid when `spec` is all digits. nil when
// no such group exists; throws when the lookup itself failed.
func lookupGroup(_ spec: String) throws -> (gid: gid_t, name: String)? {
    let byGid = !spec.isEmpty && spec.utf8.allSatisfy { $0 >= 0x30 && $0 <= 0x39 }
    var gid: gid_t = 0
    if byGid {
        guard let parsed = gid_t(spec) else {
            throw CLIError("--group \(spec) is not a valid gid")
        }
        gid = parsed
    }
    var size = 16 * 1024
    while size <= 1024 * 1024 {
        var entry = group()
        var result: UnsafeMutablePointer<group>?
        var buffer = [CChar](repeating: 0, count: size)
        let rc = byGid
            ? getgrgid_r(gid, &entry, &buffer, size, &result)
            : getgrnam_r(spec, &entry, &buffer, size, &result)
        if rc == ERANGE {
            size *= 2 // a large directory group's member list didn't fit
            continue
        }
        guard rc == 0 else {
            throw CLIError("could not look up group \(spec): \(String(cString: strerror(rc)))")
        }
        guard let found = result, let namePtr = found.pointee.gr_name else {
            return nil
        }
        return (found.pointee.gr_gid, String(cString: namePtr))
    }
    throw CLIError("could not look up group \(spec): its entry is too large")
}

// Resolves --group to the gid the key file is given, refusing a group that
// doesn't exist or is over-broad. Done before the DEK is read or the Secure
// Enclave is used, so a bad --group costs nothing. The Linux tool's
// resolve_key_file_group.
func resolveKeyFileGroup(_ spec: String) throws -> (gid: gid_t, name: String) {
    guard let found = try lookupGroup(spec) else {
        throw CLIError("--group \"\(spec)\" does not name a group on this host")
    }
    let (gid, name) = (found.gid, found.name)
    // Fails closed: if a listed group can't be looked up, whether it is this
    // gid can't be ruled out, so --group is refused rather than allowed.
    var listed = overBroadGroups.contains(name)
    for broad in overBroadGroups where !listed {
        do {
            if let broadGroup = try lookupGroup(broad), broadGroup.gid == gid {
                listed = true
            }
        } catch {
            throw CLIError("--group \"\(spec)\": can't confirm it isn't the over-broad group \"\(broad)\" (\(error)); refusing")
        }
    }
    if gid == 0 || listed {
        throw CLIError("--group \"\(spec)\" (\(name), gid \(gid)) is an over-broad group (it covers essentially every account, or the host's administrators); name a dedicated group for the service that unwraps this key")
    }
    return (gid, name)
}

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
        // A wrapped key is 125 bytes; something far bigger at the key path
        // isn't one. The Linux tool's MAX_REPLACEABLE_KEY_FILE_LEN.
        guard st.st_size <= off_t(maxReplaceableKeyFileSize) else {
            throw CLIError("\(path) is \(st.st_size) bytes, far larger than any wrapped key; refusing to overwrite it")
        }
    case S_IFLNK:
        throw CLIError("\(path) is a symbolic link; refusing to overwrite through it -- remove the link, or point <key-file-path> at a regular file")
    default:
        throw CLIError("\(path) is not a regular file; refusing to overwrite or remove it")
    }
}

// Largest existing file --force will overwrite: 64 KiB, as on Linux.
let maxReplaceableKeyFileSize = 64 * 1024


// Fail-fast twin of the checks secureOverwriteAndRemoveIfExists enforces at
// open time: with --force, refuse before any Secure Enclave or keychain
// work if <key-file-path> exists and is a symlink or anything other than a
// regular file. `lstat`, not `stat`, so a symlink is judged as itself, not
// as its target. Advisory only -- the path can change between here and the
// open -- the O_NOFOLLOW/fstat checks at open time are the guarantee.
func refuseUnlessAbsentOrRegularFile(_ folder: CheckedFolder, display: String) throws {
    var st = stat()
    guard fstatat(folder.fd, folder.leaf, &st, AT_SYMLINK_NOFOLLOW) == 0 else {
        if errno == ENOENT {
            return
        }
        throw CLIError("failed to stat \(display): \(String(cString: strerror(errno)))")
    }
    try requireRegularFile(st, path: display)
}

// Whether anything at all -- a dangling symlink included -- occupies the
// key file's name in its checked folder.
func keyFileNameIsTaken(_ folder: CheckedFolder) -> Bool {
    var st = stat()
    return fstatat(folder.fd, folder.leaf, &st, AT_SYMLINK_NOFOLLOW) == 0
}

// Removes `folder.leaf` -- but only while that name still refers to the
// file open as `fd` (same device and inode): a file someone put at the name
// in the meantime is left alone. The Linux tool's remove_created_file.
func unlinkIfStillSame(_ folder: CheckedFolder, fd: Int32) -> Bool {
    var opened = stat()
    var named = stat()
    guard fstat(fd, &opened) == 0, fstatat(folder.fd, folder.leaf, &named, AT_SYMLINK_NOFOLLOW) == 0,
          opened.st_dev == named.st_dev, opened.st_ino == named.st_ino else {
        return false
    }
    return unlinkat(folder.fd, folder.leaf, 0) == 0
}


func secureOverwriteAndRemoveIfExists(_ folder: CheckedFolder, display path: String) throws {
    let fd = openat(folder.fd, folder.leaf, O_WRONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
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
            // straight to removing it, but only once it is confirmed to be a
            // regular file (one link, within the size cap). If it can't even
            // be examined, nothing is removed.
            var st = stat()
            guard fstatat(folder.fd, folder.leaf, &st, AT_SYMLINK_NOFOLLOW) == 0 else {
                throw CLIError("failed to stat \(path): \(String(cString: strerror(errno))); refusing to remove it")
            }
            try requireRegularFile(st, path: path)
            if unlinkat(folder.fd, folder.leaf, 0) != 0 && errno != ENOENT {
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
                    // generates (salts, nonces).
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

    // Only while the name still refers to the file just overwritten.
    guard unlinkIfStillSame(folder, fd: fd) else {
        throw CLIError("failed to remove \(path) after secure overwrite: it was moved or replaced, or \(String(cString: strerror(errno)))")
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
func flushFolder(_ folder: CheckedFolder) throws {
    if fcntl(folder.fd, F_FULLFSYNC) == 0 { return }
    if fsync(folder.fd) == 0 { return }
    let err = errno
    if err == EINVAL || err == ENOTSUP { return }
    throw CLIError("failed to flush directory \(folder.path) to storage: \(String(cString: strerror(err)))")
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
//
// With `group`, the file is given that group on the open descriptor
// (fchown) before its mode widens to 0640 and before a byte is written, so
// the payload never sits in it under any other group -- as the Linux tool
// does. A caller who isn't root can only give a group they belong to: the
// kernel's rule, reported plainly, and the empty file removed.
func writeWrappedKeyFile(_ folder: CheckedFolder, display path: String, bytes: [UInt8], force: Bool, group: (gid: gid_t, name: String)?) throws {
    if force {
        try secureOverwriteAndRemoveIfExists(folder, display: path)
    }

    // O_CREAT | O_EXCL never follows a link at the name, and openat() keeps
    // it in the checked folder.
    let fd = openat(folder.fd, folder.leaf, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, keyFilePermissions)
    guard fd >= 0 else {
        let err = errno
        if err == EEXIST {
            throw CLIError("\(path) already exists; pass --force|-f to overwrite")
        }
        throw CLIError("failed to open \(path) for writing: \(String(cString: strerror(err)))")
    }

    var committed = false
    defer {
        if !committed {
            _ = unlinkIfStillSame(folder, fd: fd) // only the file this call created
        }
        close(fd)
    }

    if let group {
        guard fchown(fd, uid_t.max, group.gid) == 0 else { // uid -1: the owner stays as it is
            throw CLIError("could not give \(path) to group \"\(group.name)\": \(String(cString: strerror(errno))) (only root, or a member of the group, can)")
        }
    }
    guard fchmod(fd, group == nil ? keyFilePermissions : keyFileGroupPermissions) == 0 else {
        throw CLIError("failed to set permissions on \(path): \(String(cString: strerror(errno)))")
    }

    try bytes.withUnsafeBufferPointer { buf in
        try writeAll(fd: fd, bytes: buf, context: path)
    }
    try flushToStorage(fd: fd, context: path)
    try flushFolder(folder)
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
    // The Linux and Windows tools' wording, plus the keychain mode and the
    // fingerprint, which only this platform reports.
    if created {
        print("KEK provisioned for service \"\(args.serviceName)\" (keychain: \(keychainModeName()))")
        print("fingerprint: \(hexString(fingerprint)) -- record this; retire requires it")
    } else {
        // A KEK this operator didn't create could have been planted by another
        // process; the fingerprint is how to tell.
        print("KEK already provisioned for service \"\(args.serviceName)\"; verified, nothing to do (keychain: \(keychainModeName()))")
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

func runWrap(_ spelledArgs: WrapArgs) throws {
    // The key file's folder must be a real folder with no symbolic link in
    // it (openRealFolder), checked first, before any Secure Enclave or
    // keychain work. It is held open, and every filesystem call below goes
    // through it; messages name the path as the operator spelled it.
    let args = spelledArgs
    let keyFolder = try openRealFolder(spelledArgs.keyFilePath, what: "--key-file-path")
    defer { keyFolder.close() }

    // Fast, friendly pre-check: fail before ever touching the Secure
    // Enclave/Keychain if the output path obviously already exists,
    // rather than making the caller pay for a full wrap operation just to
    // find out at the very end. writeWrappedKeyFile's O_EXCL is the actual
    // correctness guarantee against the exists-then-create race; this is
    // purely a fail-fast convenience on top of it.
    if !args.force && keyFileNameIsTaken(keyFolder) { // a dangling symlink counts
        throw CLIError("\(args.keyFilePath) already exists; pass --force|-f to overwrite")
    }
    // Same fail-fast idea for --force: a symlink or non-regular file at the
    // path will be refused by the overwrite step anyway; refusing it here
    // first means no Secure Enclave/keychain work is spent on a command
    // that cannot complete.
    if args.force {
        try refuseUnlessAbsentOrRegularFile(keyFolder, display: args.keyFilePath)
    }

    // `args.serviceName` is not secret -- it's a logical identifier, not key
    // material -- so no special scoping is needed for it. Validated before
    // any DEK is read.
    try validateServiceCharset(args.serviceName)

    // Resolved before the DEK is read or the Secure Enclave is used, so a
    // bad --group fails fast and costs nothing. Without --group: owner-only.
    let group = try args.groupName.map(resolveKeyFileGroup)

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

    try writeWrappedKeyFile(keyFolder, display: args.keyFilePath, bytes: wrapped, force: args.force, group: group)

    // The Linux tool's wording for who can read it.
    let access = group.map { "owner read/write + \($0.name) read-only" } ?? "owner read/write"
    print("wrapped key written to \(spelledArgs.keyFilePath) (\(wrapped.count) bytes, \(access), service \"\(args.serviceName)\", keychain: \(keychainModeName()))")
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

// Before anything is read: this process holds a plaintext DEK, so it must
// not be dumpable or debuggable by other processes of the same user. Refuse
// to run rather than handle a DEK unprotected -- the Linux tool's rule.
#if HKDFGUARD_STRICT_HARDENING
let hardenStatus = hkdfguard_harden_process_with_flags(hardenRequireProtectedSignature)
let hardenHint = " -- this distribution build must be signed with the Hardened Runtime and without get-task-allow"
#else
let hardenStatus = hkdfguard_harden_process()
let hardenHint = ""
#endif
guard hardenStatus == HKDFGuardStatus.success.rawValue else {
    FileHandle.standardError.write("error: \(describeStatus(hardenStatus))\(hardenHint); refusing to handle key material\n".data(using: .utf8)!)
    exit(1)
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
