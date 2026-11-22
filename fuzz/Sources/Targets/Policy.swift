//
//  Policy.swift -- fuzz target `policy`
//
//  The production policy: parseMachinePolicy on property lists -- arbitrary
//  bytes read the way loadPolicyFile reads them, and dictionaries built
//  from the input out of the real settings, misspelt ones and values of
//  every type -- then the same policy put in effect and read back through
//  the C ABI. And the production-mode marker's rule (applyProductionMarker)
//  for every combination of policy, marker and caller.
//
//  Beyond "no crash": the parser accepts exactly what an independent
//  restatement of hkdfguard.h's rules accepts; whatever it refuses fails
//  closed -- every call POLICY_INVALID, hkdfguard_machine_policy "invalid"
//  -- and whatever it accepts is reported back as written; a service the
//  policy makes machine-scoped is never served by the user-scoped KEK of
//  the same name; a Mac with the marker and no policy is invalid, not in
//  development mode.
//

import Foundation

// MARK: - The rules, restated

private func groupNameIsValid(_ value: Any?) -> Bool {
    guard let name = value as? String else { return false }
    let bytes = Array(name.utf8)
    guard (1...255).contains(bytes.count), bytes[0] != UInt8(ascii: "-") else { return false }
    return bytes.allSatisfy { byte in
        (byte >= 0x30 && byte <= 0x39) || (byte >= 0x41 && byte <= 0x5A) || (byte >= 0x61 && byte <= 0x7A)
            || byte == UInt8(ascii: "_") || byte == UInt8(ascii: "-") || byte == UInt8(ascii: ".")
    }
}

private func isRealBoolean(_ value: Any) -> Bool {
    CFGetTypeID(value as CFTypeRef) == CFBooleanGetTypeID()
}

/// What a valid policy says, or nil for an invalid one.
private struct ExpectedPolicy {
    var services: [String: String?] = [:] // lowercase name -> runner group
    var suite = "ML-KEM-1024"
    var requirePostQuantum = false
    var securityAdminGroup: String?
    var deploymentAdminGroup: String?
}

private func expectedPolicy(_ values: [String: Any]) -> ExpectedPolicy? {
    var policy = ExpectedPolicy()
    let known: Set<String> = ["MachineServices", "SecurityAdminGroup", "DeploymentAdminGroup", "KekSuite", "RequirePostQuantum"]
    guard Set(values.keys).isSubset(of: known) else { return nil }
    if let raw = values["MachineServices"] {
        guard let table = raw as? [String: Any] else { return nil }
        for (name, value) in table {
            guard serviceNameIsValid(Array(name.utf8)), let settings = value as? [String: Any],
                  Set(settings.keys).isSubset(of: ["RunnerGroup"]) else { return nil }
            let lowered = String(decoding: asciiLowercased(Array(name.utf8)), as: UTF8.self)
            guard policy.services[lowered] == nil else { return nil }
            if let group = settings["RunnerGroup"] {
                guard groupNameIsValid(group) else { return nil }
                policy.services[lowered] = .some(group as? String)
            } else {
                policy.services[lowered] = .some(nil)
            }
        }
    }
    if let raw = values["KekSuite"] {
        guard let name = raw as? String, name == "ML-KEM-1024" || name == "P-256" else { return nil }
        policy.suite = name
    }
    if let raw = values["RequirePostQuantum"] {
        guard isRealBoolean(raw), let flag = raw as? Bool else { return nil }
        policy.requirePostQuantum = flag
    }
    if policy.requirePostQuantum && policy.suite == "P-256" { return nil }
    for (key, path) in [("SecurityAdminGroup", \ExpectedPolicy.securityAdminGroup), ("DeploymentAdminGroup", \.deploymentAdminGroup)] {
        if let raw = values[key] {
            guard groupNameIsValid(raw) else { return nil }
            policy[keyPath: path] = raw as? String
        }
    }
    return policy
}

// MARK: - Building a policy from the input

private let settingNames = ["MachineServices", "SecurityAdminGroup", "DeploymentAdminGroup", "KekSuite", "RequirePostQuantum",
                            "machineServices", "RunnerGroup", "KekSuites", ""]
private let stringValues = ["ML-KEM-1024", "P-256", "p-256", "ML-KEM-768", "_hkdfguard", "staff", "admin", "wheel", "-rf", "a.b-c_d", "",
                            SERVICE, SERVICE_UPPER, OTHER_SERVICE, "true"]
private let serviceNames = [SERVICE, SERVICE_UPPER, OTHER_SERVICE, "com.example.app", "Com.Example.App", "..", ".hidden", "a..b", "a/b", ""]

private func text(_ input: inout FuzzInput, _ table: [String]) -> String {
    let index = input.choice(table.count + 1)
    return index < table.count ? table[index] : String(decoding: input.blob(max: 300), as: UTF8.self)
}

private func value(_ input: inout FuzzInput, depth: Int = 0) -> Any {
    switch input.choice(depth < 2 ? 10 : 7) {
    case 0: return text(&input, stringValues)
    case 1: return true
    case 2: return false
    case 3: return NSNumber(value: Int(input.i16()))
    case 4: return NSNumber(value: Double(input.i16()) / 7)
    case 5: return Data(input.blob(max: 64))
    case 6: return Date(timeIntervalSince1970: Double(input.i16()))
    case 7: return (0..<input.choice(4)).map { _ in value(&input, depth: depth + 1) }
    case 8:
        var table: [String: Any] = [:]
        for _ in 0..<input.choice(4) { table[text(&input, settingNames)] = value(&input, depth: depth + 1) }
        return table
    default:
        // A MachineServices-shaped table.
        var table: [String: Any] = [:]
        for _ in 0..<input.choice(4) {
            let name = text(&input, serviceNames)
            switch input.choice(4) {
            case 0: table[name] = [String: Any]()
            case 1: table[name] = ["RunnerGroup": text(&input, stringValues)]
            case 2:
                // Not a literal: the second name may be RunnerGroup again.
                var settings: [String: Any] = ["RunnerGroup": text(&input, stringValues)]
                settings[text(&input, settingNames)] = value(&input, depth: 2)
                table[name] = settings
            default: table[name] = value(&input, depth: 2)
            }
        }
        return table
    }
}

// MARK: - The target

private let keyFolderOverride = fuzzDirectory + "/keks"

/// The policy in effect, as hkdfguard_machine_policy reports it.
private func reportedPolicy() -> [String: Any] {
    let ret = withBuffer(Call(cap: Int16.max)) { out, outLen in hkdfguard_machine_policy(outPtr: out, outLen: outLen) }
    check(ret.rc == OK, "machine_policy: \(statusName(ret.rc))")
    guard let object = try? JSONSerialization.jsonObject(with: Data(ret.written)) as? [String: Any] else {
        finding("machine_policy did not write a JSON object")
    }
    return object
}

private func checkInEffect(_ load: PolicyLoad, _ expected: ExpectedPolicy?) {
    let report = reportedPolicy()
    var exists: Int32 = 0x5A5A
    var suite: Int32 = 0x5A5A
    let existsStatus = SERVICE.withCString { hkdfguard_kek_exists(servicePtr: $0, outExists: &exists) }
    let suiteStatus = SERVICE.withCString { hkdfguard_kek_suite(servicePtr: $0, outSuite: &suite) }
    let fingerprint = withBuffer(.dek) { out, outLen in SERVICE.withCString { hkdfguard_kek_fingerprint(servicePtr: $0, outPtr: out, outLen: outLen) } }
    let created = SERVICE.withCString { hkdfguard_create_kek(servicePtr: $0) }
    let wrapped = wrap(.fuzz, dek: knownDek, call: .full)
    let generated = withBuffer(.full) { out, outLen in SERVICE.withCString { hkdfguard_generate_and_wrap_dek(servicePtr: $0, outPtr: out, outLen: outLen) } }
    let unwrapped = unwrap(.fuzzUpper, genuinePayload, .dek)
    checkContract(wrapped, .full, .untouched, "wrap_dek under a policy")
    checkContract(generated, .full, .untouched, "generate_and_wrap_dek under a policy")
    checkContract(unwrapped, .dek, .zeroed, "unwrap_dek under a policy")
    let statuses = [existsStatus, suiteStatus, fingerprint.rc, created, wrapped.rc, generated.rc, unwrapped.rc]

    guard let expected else {
        // Fails closed: every call, whatever the service.
        check(report["mode"] as? String == "invalid" && report["reason"] is String, "an invalid policy is reported as \(report)")
        check(statuses.allSatisfy { $0 == POLICY_INVALID }, "under an invalid policy the calls returned \(statuses.map(statusName))")
        check(exists == 0 && suite == 0, "an invalid policy left *out_exists \(exists), *out_suite \(suite)")
        return
    }
    check(report["mode"] as? String == "production", "a valid policy is reported as \(report)")
    check(report["kekSuite"] as? String == expected.suite && report["requirePostQuantum"] as? Bool == expected.requirePostQuantum,
          "the policy's suite settings are reported as \(report)")
    check(report["securityAdminGroup"] as? String == expected.securityAdminGroup
          && report["deploymentAdminGroup"] as? String == expected.deploymentAdminGroup, "the policy's groups are reported as \(report)")
    let services = report["machineServices"] as? [String: [String: String]] ?? [:]
    check(Set(services.keys) == Set(expected.services.keys), "machineServices is reported as \(services.keys.sorted()), expected \(expected.services.keys.sorted())")
    for (name, group) in expected.services {
        check(services[name]?["runnerGroup"] == group, "\(name)'s runner group is reported as \(String(describing: services[name]))")
    }

    if expected.services[SERVICE] != nil {
        // Machine-scoped now: the user-scoped KEK of the same name must not
        // serve it, and nothing here is root in the system context.
        check(statuses.dropFirst().allSatisfy { $0 != OK }, "a machine-scoped service was served: \(statuses.map(statusName))")
        check(exists != 1 && suite == 0, "a machine-scoped service has *out_exists \(exists), *out_suite \(suite)")
        check(!FileManager.default.fileExists(atPath: keyFolderOverride), "create_kek made a machine KEK folder without being root")
    } else {
        // User-scoped: the ML-KEM KEK works whatever the suite settings say.
        check(statuses.allSatisfy { $0 == OK }, "a user-scoped service under a valid policy: \(statuses.map(statusName))")
        check(exists == 1 && suite == Int32(FUZZ_KEK_SUITE) && fingerprint.written == genuineFingerprint, "the KEK is described differently under a policy")
        check(unwrapped.written == knownDek, "unwrap under a policy returned another DEK")
        check(unwrap(.fuzz, wrapped.written, .dek).written == knownDek, "a payload wrapped under a policy does not unwrap")
    }
    // A service with no KEK: under RequirePostQuantum or not, never created
    // as another suite than the policy's, and never by a call that isn't
    // create_kek.
    let other = wrap(.other, dek: knownDek, call: .full)
    check(other.rc != OK, "wrap under a service with no KEK: \(statusName(other.rc))")
}

let policyTarget = FuzzTarget(name: "policy", run: { data in
    setup()
    _ = (genuinePayload, genuineFingerprint)
    var input = FuzzInput(data)
    let kind = input.choice(3)

    if kind == 2 {
        // The marker's rule.
        let marker = fuzzDirectory + "/marker/production-mode"
        try? FileManager.default.removeItem(atPath: fuzzDirectory + "/marker")
        let present = input.bool()
        let asRoot = input.bool()
        let load: PolicyLoad = [.none, .invalid("fuzz"), parseMachinePolicy([:], source: "fuzz")][input.choice(3)]
        if present {
            check(mkdir(fuzzDirectory + "/marker", 0o755) == 0, "harness: mkdir")
            writeFile(marker, [], mode: 0o644)
        }
        let result = applyProductionMarker(load, markerPath: marker, asRoot: asRoot, requireTrustedFolder: false)
        let nowPresent = FileManager.default.fileExists(atPath: marker)
        switch load {
        case .none:
            check(present ? { if case .invalid = result { return true } else { return false } }() : result == .none,
                  "no policy, marker \(present): \(result)")
            check(nowPresent == present, "reading no policy changed the marker")
        case .invalid:
            check(result == load && nowPresent == present, "an invalid policy: \(result), marker \(nowPresent)")
        case .loaded:
            check(result == load, "a valid policy was changed by the marker: \(result)")
            check(nowPresent == (present || asRoot), "a valid policy read as root \(asRoot): marker \(nowPresent)")
        }
        return
    }

    let values: [String: Any]
    if kind == 0 {
        // As loadPolicyFile reads a file's bytes.
        guard let plist = try? PropertyListSerialization.propertyList(from: Data(input.rest()), options: [], format: nil),
              let dictionary = plist as? [String: Any] else { return }
        values = dictionary
    } else {
        var table: [String: Any] = [:]
        for _ in 0..<input.choice(7) { table[text(&input, settingNames)] = value(&input) }
        values = table
    }

    let load = parseMachinePolicy(values, source: "fuzz")
    let expected = expectedPolicy(values)
    switch load {
    case .none:
        finding("parseMachinePolicy returned no policy at all")
    case .invalid(let reason):
        check(expected == nil, "parseMachinePolicy refused a policy the rules allow (\(reason)): \(values)")
        check(reason.hasPrefix("fuzz: "), "an invalid policy's reason does not name its source: \(reason)")
    case .loaded(let policy):
        check(expected != nil, "parseMachinePolicy accepted a policy the rules refuse: \(values)")
        check(policy.source == "fuzz", "the policy's source is \(policy.source)")
    }
    MachineScopeTestOverrides.$keyFolder.withValue(keyFolderOverride) {
        MachineScopeTestOverrides.$policy.withValue(load) {
            checkInEffect(load, expected)
        }
    }
}, seeds: {
    var seeds: [NamedSeed] = []
    func plist(_ name: String, _ body: String) {
        let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\">\n\(body)\n</plist>\n"
        seeds.append(NamedSeed("plist-\(name)") { $0.choice(0).rest(Array(xml.utf8)) })
    }
    plist("empty", "<dict/>")
    plist("not-a-dictionary", "<array><string>MachineServices</string></array>")
    plist("string", "<string>MachineServices</string>")
    plist("machine-service", "<dict><key>MachineServices</key><dict><key>\(SERVICE)</key><dict><key>RunnerGroup</key><string>_hkdfguard</string></dict></dict></dict>")
    plist("machine-service-root-only", "<dict><key>MachineServices</key><dict><key>\(OTHER_SERVICE)</key><dict/></dict></dict>")
    plist("same-service-twice", "<dict><key>MachineServices</key><dict><key>\(SERVICE)</key><dict/><key>\(SERVICE_UPPER)</key><dict/></dict></dict>")
    plist("bad-service-name", "<dict><key>MachineServices</key><dict><key>../etc</key><dict/></dict></dict>")
    plist("unknown-service-setting", "<dict><key>MachineServices</key><dict><key>\(SERVICE)</key><dict><key>runnerGroup</key><string>staff</string></dict></dict></dict>")
    plist("services-not-a-dictionary", "<dict><key>MachineServices</key><array/></dict>")
    plist("groups", "<dict><key>SecurityAdminGroup</key><string>secadmins</string><key>DeploymentAdminGroup</key><string>deployers</string></dict>")
    plist("bad-group", "<dict><key>SecurityAdminGroup</key><string>-rf</string></dict>")
    plist("group-not-a-string", "<dict><key>DeploymentAdminGroup</key><integer>80</integer></dict>")
    plist("suite-mlkem", "<dict><key>KekSuite</key><string>ML-KEM-1024</string></dict>")
    plist("suite-p256", "<dict><key>KekSuite</key><string>P-256</string></dict>")
    plist("suite-unknown", "<dict><key>KekSuite</key><string>p-256</string></dict>")
    plist("require-pq", "<dict><key>RequirePostQuantum</key><true/></dict>")
    plist("require-pq-false", "<dict><key>RequirePostQuantum</key><false/></dict>")
    plist("require-pq-integer", "<dict><key>RequirePostQuantum</key><integer>1</integer></dict>")
    plist("require-pq-string", "<dict><key>RequirePostQuantum</key><string>true</string></dict>")
    plist("require-pq-with-p256", "<dict><key>KekSuite</key><string>P-256</string><key>RequirePostQuantum</key><true/></dict>")
    plist("unknown-setting", "<dict><key>MachineService</key><dict/></dict>")
    plist("everything", "<dict><key>MachineServices</key><dict><key>com.example.app</key><dict><key>RunnerGroup</key><string>_app</string></dict></dict>"
        + "<key>SecurityAdminGroup</key><string>sec</string><key>DeploymentAdminGroup</key><string>dep</string>"
        + "<key>KekSuite</key><string>ML-KEM-1024</string><key>RequirePostQuantum</key><true/></dict>")
    plist("truncated", "<dict><key>MachineServices</key><dict><key>")
    plist("deep", String(repeating: "<array>", count: 64) + String(repeating: "</array>", count: 64))
    seeds.append(NamedSeed("plist-binary-magic") { $0.choice(0).rest(Array("bplist00".utf8) + [UInt8](repeating: 0, count: 40)) })
    seeds.append(NamedSeed("plist-json") { $0.choice(0).rest(Array("{\"KekSuite\":\"P-256\"}".utf8)) })
    seeds.append(NamedSeed("plist-openstep") { $0.choice(0).rest(Array("{ KekSuite = \"P-256\"; }".utf8)) })
    // Built: one setting, by index into the tables above.
    for (index, name) in settingNames.enumerated() {
        for kind in 0..<10 {
            seeds.append(NamedSeed("built-setting-\(index)-value-\(kind)") { $0.choice(1).choice(1).choice(index).choice(kind).rest([0, 0, 0, 0, 0, 0, 0, 0]) })
        }
    }
    for present in [false, true] {
        for asRoot in [false, true] {
            for load in 0..<3 {
                seeds.append(NamedSeed("marker-\(present)-root-\(asRoot)-policy-\(load)") { $0.choice(2).bool(present).bool(asRoot).choice(load) })
            }
        }
    }
    return seeds
})
