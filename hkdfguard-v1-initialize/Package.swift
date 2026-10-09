// swift-tools-version:5.9
import Foundation
import PackageDescription

// This package builds one executable, `hkdfguard-v1-initialize`, that links
// directly against the sibling Xcode project's already-built
// libhkdfguard_v1.dylib (the HkdfGuardNativeMacOSDylib
// target) and calls into it purely through its stable C ABI
// (`hkdfguard_wrap_dek`) -- the same interface any other-language caller
// uses, matching this project's Linux equivalent
// (hkdfguard-native-linux/src/bin/hkdfguard-v1-initialize.rs).
//
// Build the library first:
//   xcodebuild -project ../HkdfGuardNativeMacOS.xcodeproj \
//       -target HkdfGuardNativeMacOSDylib -configuration Release build
// then build/run this tool from anywhere:
//   swift build --package-path <this-directory> -c release
//   <this-directory>/.build/release/hkdfguard-v1-initialize --help
//
// The dylib's own `install_name` is `@rpath/libhkdfguard_v1.dylib`
// (see its build settings' DYLIB_INSTALL_NAME_BASE), so the executable needs
// an explicit -rpath pointing at the directory it actually lives in to
// resolve it at *run* time, not just link time. That directory is computed
// from `#filePath` (this manifest's own absolute path, resolved fresh by
// SwiftPM on every build) rather than hardcoded or left relative -- a
// relative -rpath is resolved by dyld against the *calling process's
// current working directory* at launch, not against where this executable
// lives on disk, so it would only work when invoked from inside this exact
// package directory. An absolute path sidesteps that entirely: the tool
// then runs correctly regardless of the caller's cwd, exactly like a
// normal installed command-line tool should.
//
// HKDFGUARD_DYLIB_DIR overrides that default directory. build-dist.sh uses
// it to link the CLI against its own Release dylib build
// (build-arm64/Release). Pair an override with a dedicated --scratch-path so
// a cached manifest/linker flags from another build can't bleed into it.
let hkdfguardDylibDir: String = {
    if let override = ProcessInfo.processInfo.environment["HKDFGUARD_DYLIB_DIR"], !override.isEmpty {
        return override
    }
    return URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent() // this package's own directory
        .appendingPathComponent("../build/Release")
        .standardizedFileURL
        .path
}()
let hkdfguardDylibPath = "\(hkdfguardDylibDir)/libhkdfguard_v1.dylib"

let package = Package(
    name: "hkdfguard-v1-initialize",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "hkdfguard-v1-initialize",
            linkerSettings: [
                // The exact dylib path is handed to the linker rather than
                // `-L<dir> -lhkdfguard_v1`, so the link can only ever pick up
                // the build named here, never a same-named library found
                // earlier on the linker's search path.
                .unsafeFlags([
                    "-Xlinker", hkdfguardDylibPath,
                    "-Xlinker", "-rpath", "-Xlinker", hkdfguardDylibDir,
                ])
            ]
        )
    ]
)
