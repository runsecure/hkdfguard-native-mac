//
//  FolderTrust.swift -- fuzz target `folder_trust`
//
//  The walk behind hkdfguard_open_file, the policy file and the machine KEK
//  files -- keyFileFoldersAreTrusted -- on random chains of folders, every
//  mode from 0700 to 1777, with a genuine key file at the bottom, reached
//  by its own path or through a symbolic link to one of its folders.
//  (Linux's `path_walk`: there the walk resolves the path itself; here it
//  climbs from the key's folder by descriptor, so what varies is the
//  folders, not the spelling of the path.)
//
//  Beyond "no crash": the library refuses exactly when the harness's own
//  reading of the rule does -- the key's own folder writable by group or
//  others, sticky or not, or a folder above it writable by them and not
//  sticky; a link to a folder does not change the answer, since the folders
//  judged are the ones the file really sits in; and `rootOnly` (the policy
//  file's and machine KEKs' rule) never accepts a chain this user owns.
//

import Foundation

private let folderModes: [mode_t] = [
    0o700, 0o755, 0o750, 0o711,
    0o770, 0o775, 0o777, 0o702, 0o720,       // group or others can write
    0o1777, 0o1770, 0o1775, 0o1707, 0o1700,  // sticky, /tmp-style
]

private let maxDepth = 4

let folderTrustTarget = FuzzTarget(name: "folder_trust", run: { data in
    setup()
    var input = FuzzInput(data)
    let depth = 1 + input.choice(maxDepth)
    let chain = (0..<depth).map { _ in folderModes[input.choice(folderModes.count)] }
    // 0: by its own path. Otherwise: through a link to its (n-1)th folder.
    let linkTo = input.choice(depth + 1)
    let call = Call.decode(&input)
    guard geteuid() != 0 else { return } // root owns nothing here, and passes rootOnly

    // <fuzz dir>/tree/d0/d1/.../key.bin, d0 outermost.
    let root = fuzzDirectory + "/tree"
    removeTree(root)
    check(mkdir(root, 0o700) == 0, "harness: mkdir \(root)")
    var folders: [String] = []
    var current = root
    for index in 0..<depth {
        current += "/d\(index)"
        check(mkdir(current, 0o700) == 0, "harness: mkdir \(current)")
        folders.append(current)
    }
    writeFile(current + "/key.bin", genuinePayload, mode: 0o600)
    // Modes last, and by chmod: mkdir's would be cut down by the umask.
    for (folder, mode) in zip(folders, chain) {
        check(chmod(folder, mode) == 0, "harness: chmod \(folder)")
    }

    // The rule, restated: the key's own folder, then the ones above it.
    var trusted = true
    for (index, mode) in chain.enumerated() {
        let writable = mode & 0o022 != 0
        let isKeyFolder = index == depth - 1
        if writable && (isKeyFolder || mode & 0o1000 == 0) {
            trusted = false
        }
    }

    var path = current + "/key.bin"
    if linkTo > 0 {
        let link = root + "/link"
        check(symlink(folders[linkTo - 1], link) == 0, "harness: symlink")
        path = link + folders[depth - 1].dropFirst(folders[linkTo - 1].count) + "/key.bin"
    }

    let ret = openFile(path: path, call)
    checkContract(ret, call, .zeroed, "open_file (folders \(chain.map { String($0, radix: 8) }))")
    if call.wellFormed && call.cap >= WRAPPED_LEN {
        let expected = trusted ? OK : FILE_UNTRUSTED
        check(ret.rc == expected,
              "open_file returned \(statusName(ret.rc)), expected \(statusName(expected)), for a key under folders \(chain.map { String($0, radix: 8) }) (outermost first, link to \(linkTo))")
        check(ret.rc != OK || ret.written == genuinePayload, "open_file returned bytes that are not the file's")
    } else {
        check(ret.rc != OK, "open_file succeeded into \(call)")
    }

    // The walk itself, from the key's folder.
    let fd = open(current, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    check(fd >= 0, "harness: open \(current)")
    check(keyFileFoldersAreTrusted(folderFd: fd) == trusted,
          "keyFileFoldersAreTrusted disagrees with the rule for folders \(chain.map { String($0, radix: 8) })")
    check(!keyFileFoldersAreTrusted(folderFd: fd, rootOnly: true), "rootOnly accepted a chain of this user's folders")
    close(fd)
    // An ACL can't be read from a descriptor that isn't a file or folder's:
    // the checks fail closed rather than trap.
    check(!keyFileFoldersAreTrusted(folderFd: -1), "keyFileFoldersAreTrusted accepted a bad descriptor")

    removeTree(root)
    var info = stat()
    check(lstat(root, &info) != 0, "harness: can't remove \(root)")
}, seeds: {
    var seeds: [NamedSeed] = []
    func add(_ name: String, _ chain: [Int], link: Int = 0, _ call: Call = .full) {
        seeds.append(NamedSeed(name) { seed in
            seed.choice(chain.count - 1)
            for mode in chain { seed.choice(mode) }
            seed.choice(link)
            call.encode(seed)
        })
    }
    for (index, mode) in folderModes.enumerated() {
        let name = String(mode, radix: 8)
        add("key-folder-\(name)", [index])
        add("parent-\(name)", [index, 0])
        add("grandparent-\(name)", [index, 0, 0])
        add("key-folder-\(name)-under-sticky", [9, index])
        add("linked-parent-\(name)", [index, 0], link: 2)
        add("linked-key-folder-\(name)", [0, index], link: 2)
    }
    add("deepest", [0, 1, 2, 3])
    add("all-sticky", [9, 9, 9, 9])
    add("all-world-writable", [6, 6, 6, 6])
    add("probe", [0], Call(cap: 0, outNull: true))
    add("short-buffer", [0], Call(cap: 124))
    return seeds
})
