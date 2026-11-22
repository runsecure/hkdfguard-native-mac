# Fuzzing the C ABI

Fuzz harnesses for the library's C ABI and the parsers behind it, in-process, under AddressSanitizer.
They are the macOS counterpart of `hkdfguard-native-linux/fuzz`, target for target where the two libraries have the same surface.

Nothing here is part of a build that ships.
The harnesses compile the library's own source files into one binary with `HKDFGUARD_FUZZING` defined, which only `fuzz/build.sh` does.
That flag turns on the one hook the harnesses need: in `HkdfGuardKeychain.swift`, three `#if HKDFGUARD_FUZZING` branches replace the keychain lookup and the Secure Enclave with software keys held in memory (`Sources/Support/FuzzKEKStore.swift`).
Everything above those branches is the code that ships: the argument checks, the policy, the payload format, the key derivation and AES-GCM.
So the fuzz build never reads or writes a keychain, never uses the Secure Enclave, and runs on a hosted runner's VM, which has neither.

## Targets

| Target | What it drives | What it checks beyond "no crash" |
|---|---|---|
| `unwrap_dek` | `hkdfguard_unwrap_dek` on arbitrary bytes and on bit-flipped, truncated and extended copies of a genuine payload, under every shape of service string, payload pointer and length, and output buffer | the status is exactly the one `hkdfguard.h`'s order of checks gives; only the genuine payload unwraps, only under its own service, and only to its DEK; every failure zeroes the caller's buffer; `BUFFER_TOO_SMALL` reports 32 |
| `wrap_round_trip` | `hkdfguard_wrap_dek` (any DEK length, a NULL DEK, a length that lies), `hkdfguard_generate_and_wrap_dek`, `hkdfguard_kek_exists`, `hkdfguard_kek_fingerprint`, `hkdfguard_kek_suite`, `hkdfguard_keychain_mode`, `hkdfguard_machine_policy`, and unknown flags to `hkdfguard_harden_process_with_flags` | whatever wrap produces is 125 bytes, carries the KEK's fingerprint and suite, unwraps to the same DEK under either spelling of the service, and is never the same payload twice; a failure leaves the buffer and `*out_len` untouched; the fingerprint and suite match the ones payloads carry; `kek_exists` answers for exactly the created KEK |
| `open_file` | `hkdfguard_open_file` on arbitrary file contents under ten file modes, on arbitrary paths, and on a symbolic link, a hard link, a folder, a FIFO, a missing file, a relative path | the status is the one the file's mode and bytes call for, by an independent restatement of the rules; the library's constant-time plaintext-key test agrees with the obvious one; success returns the file's own bytes; a refused file's bytes never reach the caller; a symbolic link is refused, not followed |
| `folder_trust` | `keyFileFoldersAreTrusted`, the walk behind `hkdfguard_open_file`, the policy file and the machine KEK files, on chains of up to four folders in fourteen modes, reached directly or through a symbolic link | the library refuses exactly when the rule does: the key's own folder writable by group or others, sticky or not, or a folder above it writable and not sticky; a link to a folder does not change the answer; `rootOnly` never accepts this user's folders |
| `policy` | `parseMachinePolicy` on arbitrary property lists and on dictionaries built from the real settings, misspelt ones and values of every type; then that policy put in effect and read through the C ABI; and `applyProductionMarker` | the parser accepts exactly what a restatement of `hkdfguard.h`'s rules accepts; an invalid policy fails closed (`POLICY_INVALID` from every call); a valid one is reported back as written; a machine-scoped service is never served by the user-scoped KEK of the same name; the marker with no policy is invalid, never development mode |
| `kek_formats` | the machine KEK file and keychain item decoders on arbitrary bytes, on the encoders' output and on mutated encodings; `lengthPrefixedField` at any offset | decode and encode agree, and each format has one spelling; a truncated or oversized container is refused |
| `string_bounds` | every C string the ABI takes, through each of the seven functions that take a service and through `hkdfguard_open_file`: unterminated, at the longest valid length, one byte over, and with a NUL before other bytes. Each string ends against an inaccessible page | a read one byte past the bounded scan is a fault in any build; an over-long or unterminated string gets its documented refusal; bytes after the first NUL change nothing |
| `api_threads` | two to four threads at once, each a sequence of `create_kek`, `kek_exists`, `kek_fingerprint`, `kek_suite`, wrap, unwrap, `open_file` and `machine_policy` | every thread gets the answer the call gets alone: its own DEK back, a fingerprint that doesn't change, no KEK for a service without one |
| `hash_to_curve` | `hashToCurveP256` on any message and tag; `expandMessageXMD` at every length it is specified for | the point is on the curve, the same every time, and different for another message or tag |
| `audit_quote` | `auditQuote`, and a whole audit record, with arbitrary bytes as the path | the field is one quoted run of printable ASCII that decodes back to the bytes, so no value can forge a second record |

Every harness aborts on a failed check, and on a Swift runtime trap, so the engine records the input.

### What is not ported from Linux

- **`unwrap_secret`, `wrap_secret_round_trip`, `open_secret_file`**: macOS has no secret-wrapping functions yet.
- **`tpm_key_file`**: `kek_formats` is its counterpart, for the macOS stored forms.
- **`path_walk`**: `folder_trust` is its counterpart. The macOS walk climbs from the key's folder by descriptor instead of resolving the path, so what varies is the folders, not the path's spelling.
- **`cli_args` and `cli_blackbox.py`**: not ported. The CLI is one `main.swift` with top-level code, so its private functions can't be compiled into a harness as Linux includes `hkdfguard.rs`; and `retire` and machine-scope `provision` go to the real keychain and LaunchDaemons, not through the library's seam.
- **The Secure Enclave and keychain paths** below the seam (`loadKEKDataRepresentation`, `reconstructKEK`, the machine KEK reads as root) are not reached. The unit tests and `scripts/verify-machine-scope.sh` cover those on real hardware.

## Running

### The seeds, as a regression suite

Needs nothing but Xcode, and takes a minute or two:

```sh
fuzz/replay-seeds.sh                 # every target
fuzz/replay-seeds.sh string_bounds   # or the ones named
```

It builds the harness with the standalone engine and runs each target's seeds once.
The seeds are listed in each target's source (`seeds:`), next to the decoder that reads them, and written to `fuzz/seeds/<target>/` (ignored by git) by `fuzz/make-seeds.sh`: about 1,600 inputs, each named for what it tries.

The standalone engine can also mutate inputs blindly, with no coverage feedback:

```sh
fuzz/run.sh unwrap_dek -mutate=100000 fuzz/seeds/unwrap_dek
```

An input that ends the process is written to `crash-<target>-<pid>` in the current folder; `fuzz/run.sh <target> <that file>` replays it.

### Coverage-guided campaigns

Xcode's toolchain compiles libFuzzer's instrumentation into Swift code but does not ship libFuzzer itself.
`fuzz/build-libfuzzer.sh` builds it once per machine, from one pinned commit of LLVM's source, into `fuzz/libfuzzer/`:

```sh
fuzz/build-libfuzzer.sh
fuzz/campaign.sh unwrap_dek 900    # the result, as the nightly workflow reports it
```

Or by hand, with any libFuzzer options:

```sh
fuzz/build.sh --engine libfuzzer
fuzz/run.sh policy fuzz/corpus/policy fuzz/seeds/policy -max_total_time=900 -dict=fuzz/policy.dict
```

A finding's input lands in `fuzz/artifacts/<target>/`.
Add a seed for every finding, named for it.

### Where the harnesses keep their files

The library refuses a key file under any folder that others can write, so the harnesses need a private folder whose every ancestor is root's or yours.
The default is `~/Library/Caches/hkdfguard-fuzz`; `HKDFGUARD_FUZZ_DIR` names another.
Each process works in its own subfolder and removes it when it ends normally.
Do not run the harnesses as root: several checks assume the caller is not.

### ThreadSanitizer

`api_threads` under AddressSanitizer finds memory corruption, not a race that corrupts nothing on the day:

```sh
fuzz/build.sh --engine standalone --sanitizer thread
fuzz/run.sh api_threads fuzz/seeds/api_threads
```

## Nightly campaigns

`.github/workflows/fuzz.yml` runs every target each night, and on demand from the Actions tab for any branch and time budget: 15 minutes each, on its own runner, through `fuzz/campaign.sh`.
Each night starts from the corpus the nights before built up (kept in the Actions cache, per target) and from the seeds.
The results:

- the run's **summary page**: a table per target with executions, corpus size, and whether there was a finding;
- a **failed run** when a target has a finding or no longer builds;
- for a finding, a **code scanning alert**: Security tab, tool `hkdfguard-fuzz`, filtered to the branch that was fuzzed. It says what failed and holds the input (base64, with the commands that replay it) and the end of the fuzzer's log (`fuzz/finding_sarif.py`).

A finding's input reproduces whatever it found.
So in CI the log and summary say only *that* a target failed, no artifact is kept, and the alert, which only people with write access can read, is the only copy.
An alert is never closed by a later night: replay its input against the fix, dismiss it by hand, and add the input to the target's seeds.

A scheduled workflow runs from the default branch's copy of the file and fuzzes `develop`.
