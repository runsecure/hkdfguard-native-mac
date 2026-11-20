//
//  HkdfGuardHardening.swift
//  HkdfGuardNativeMacOS
//
//  hkdfguard_harden_process: opt-in hardening of the calling process.
//

import Foundation
import Security
import os

// MARK: - Process hardening (opt-in)

/// HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE: make a weak code signature
/// a failure instead of a logged warning. Same bit on every platform.
private let hkdfguardHardenRequireProtectedSignature: UInt32 = 0x1

/// Every hardening flag this build knows; any other bit is refused.
private let hkdfguardHardenAllFlags: UInt32 = hkdfguardHardenRequireProtectedSignature

private let hardeningLog = Logger(subsystem: "com.hkdfguard", category: "hardening")

/// Entitlements that let another process of the same user debug this one
/// (get-task-allow, which Xcode adds to Debug builds) or load code into it.
private let debuggableEntitlements = [
    "com.apple.security.get-task-allow",
    "com.apple.security.cs.allow-dyld-environment-variables",
    "com.apple.security.cs.disable-library-validation",
]

/// The kernel's code-signing status bits for a running process
/// (<kern/cs_blobs.h>), as `kSecCodeInfoStatus` reports them.
private let csValid: UInt32 = 0x0000_0001        // CS_VALID
private let csGetTaskAllow: UInt32 = 0x0000_0004 // CS_GET_TASK_ALLOW
private let csRuntime: UInt32 = 0x0001_0000      // CS_RUNTIME
private let csDebugged: UInt32 = 0x1000_0000     // CS_DEBUGGED

/// Why the host's code signature still lets same-user processes debug or
/// inject into this process -- empty when it doesn't. On macOS that
/// protection comes from the signature (Hardened Runtime, none of
/// `debuggableEntitlements`), which a library can read but not change.
///
/// Judged on the *running process*: the status and entitlements the kernel
/// holds for it and enforces, not the executable file's signature. The file
/// can have been replaced since launch, or be a differently signed copy of
/// what is running, so its signature says nothing certain about this
/// process -- and a file that looks protected must not vouch for a process
/// that isn't.
/// Internal, not private, so tests can check it against a known signature.
func codeSignatureWeaknesses() -> [String] {
    var code: SecCode?
    var info: CFDictionary?
    // SecCodeCopySigningInformation takes a running code object as well as
    // a static one (its parameter is typed for the latter); with
    // kSecCSDynamicInformation it then reports the process's live status.
    guard SecCodeCopySelf(SecCSFlags(), &code) == errSecSuccess, let code,
          SecCodeCopySigningInformation(
              unsafeBitCast(code, to: SecStaticCode.self),
              SecCSFlags(rawValue: kSecCSDynamicInformation), &info) == errSecSuccess,
          let signing = info as? [String: Any],
          let status = (signing[kSecCodeInfoStatus as String] as? NSNumber)?.uint32Value,
          let task = SecTaskCreateFromSelf(nil)
    else {
        return ["its code-signing status could not be read"]
    }

    var weaknesses: [String] = []
    if status & csValid == 0 {
        weaknesses.append("its code signature is no longer valid in the running process")
    }
    if status & csRuntime == 0 {
        weaknesses.append("it is not running with the Hardened Runtime (codesign --options runtime)")
    }
    if status & csDebugged != 0 {
        weaknesses.append("it has been run under a debugger")
    }
    var entitled: Set<String> = []
    for key in debuggableEntitlements {
        var error: Unmanaged<CFError>?
        let value = SecTaskCopyValueForEntitlement(task, key as CFString, &error)
        if let error {
            error.release()
            weaknesses.append("its \(key) entitlement could not be read")
        } else if (value as? Bool) == true {
            weaknesses.append("it has the \(key) entitlement")
            entitled.insert(key)
        }
    }
    // The kernel's own bit, in case it is set by something other than the
    // entitlement just reported.
    if status & csGetTaskAllow != 0 && !entitled.contains("com.apple.security.get-task-allow") {
        weaknesses.append("the kernel lets other processes take its task port (CS_GET_TASK_ALLOW)")
    }
    return weaknesses
}

/// `ptrace(2)` isn't imported into Swift's Darwin module, so it is bound to
/// the libc symbol directly, with <sys/ptrace.h>'s signature and request.
@_silgen_name("ptrace")
private func sys_ptrace(_ request: Int32, _ pid: pid_t, _ addr: UnsafeMutablePointer<CChar>?, _ data: Int32) -> Int32
private let PT_DENY_ATTACH: Int32 = 31

/// Whether a debugger is attached right now (`P_TRACED`), or nil if that
/// can't be determined. `PT_DENY_ATTACH` on a traced process terminates it
/// instead of returning, so it is only ever called after this says "no".
private func isBeingTraced() -> Bool? {
    var info = kinfo_proc()
    var size = MemoryLayout<kinfo_proc>.stride
    var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
    guard sysctl(&mib, u_int(mib.count), &info, &size, nil, 0) == 0 else {
        return nil
    }
    return info.kp_proc.p_flag & P_TRACED != 0
}

/// Same as `hkdfguard_harden_process_with_flags(0)`: core dumps off, debugger
/// attachment denied, and a weak code signature logged but not fatal.
@_cdecl("hkdfguard_harden_process")
public func hkdfguard_harden_process() -> Int32 {
    hkdfguard_harden_process_with_flags(flags: 0)
}

/// Opt-in hardening of the calling process against memory disclosure:
///
/// 1. `RLIMIT_CORE` = 0, soft and hard, so it can't be raised again.
/// 2. `ptrace(PT_DENY_ATTACH)`: later ptrace attaches fail. Refused (-20)
///    rather than attempted if a debugger is already attached, because
///    then the kernel would terminate the process.
/// 3. The process's code-signing status is checked, as the kernel holds
///    it for the running process, not as the file on disk is signed
///    (`codeSignatureWeaknesses`). That is what stops a same-user process
///    from taking this process's task port to read its memory, and only
///    the host's signer can change it. A weakness is logged as a warning
///    and the call still succeeds, so development hosts (python, dotnet,
///    Xcode Debug builds) work -- unless `flags` includes
///    HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE, which makes it -20.
///
/// Steps 1 and 2 are applied before step 3 is judged, so a strict-mode
/// failure still leaves the process as hardened as it could be made.
/// Unknown flag bits are -1, before anything changes. Idempotent.
@_cdecl("hkdfguard_harden_process_with_flags")
public func hkdfguard_harden_process_with_flags(flags: UInt32) -> Int32 {
    guard flags & ~hkdfguardHardenAllFlags == 0 else {
        hardeningLog.error("hkdfguard_harden_process_with_flags: unknown flag bits \(flags & ~hkdfguardHardenAllFlags, format: .hex)")
        return HKDFGuardStatus.invalidInputLength.rawValue
    }

    var noCore = rlimit(rlim_cur: 0, rlim_max: 0)
    guard setrlimit(RLIMIT_CORE, &noCore) == 0 else {
        hardeningLog.error("hkdfguard: could not disable core dumps (setrlimit RLIMIT_CORE): \(String(cString: strerror(errno)), privacy: .public)")
        return HKDFGuardStatus.processHardeningFailed.rawValue
    }

    switch isBeingTraced() {
    case .some(false):
        guard sys_ptrace(PT_DENY_ATTACH, 0, nil, 0) == 0 else {
            hardeningLog.error("hkdfguard: could not deny debugger attachment (ptrace PT_DENY_ATTACH): \(String(cString: strerror(errno)), privacy: .public)")
            return HKDFGuardStatus.processHardeningFailed.rawValue
        }
    case .some(true):
        hardeningLog.error("hkdfguard: a debugger is attached to this process; it can't be hardened against one")
        return HKDFGuardStatus.processHardeningFailed.rawValue
    case .none:
        hardeningLog.error("hkdfguard: could not tell whether a debugger is attached (sysctl KERN_PROC_PID): \(String(cString: strerror(errno)), privacy: .public)")
        return HKDFGuardStatus.processHardeningFailed.rawValue
    }

    let weaknesses = codeSignatureWeaknesses()
    if !weaknesses.isEmpty {
        let why = weaknesses.joined(separator: "; ")
        if flags & hkdfguardHardenRequireProtectedSignature != 0 {
            hardeningLog.error("hkdfguard: other processes of this user can still debug or inject code into this process: \(why, privacy: .public). Sign the host executable with the Hardened Runtime and without those entitlements.")
            return HKDFGuardStatus.processHardeningFailed.rawValue
        }
        hardeningLog.warning("hkdfguard: process hardened, but other processes of this user can still debug or inject code into it: \(why, privacy: .public). Fine for development; for production, sign the host executable with the Hardened Runtime and without those entitlements, and pass HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE.")
    }
    return HKDFGuardStatus.success.rawValue
}
