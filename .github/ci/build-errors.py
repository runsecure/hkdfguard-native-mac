"""Prints a result bundle's build errors with their file and line.

xcodebuild's summary can name only the file that failed to compile ("The
compiler is unable to type-check this expression in reasonable time"); the
result bundle keeps where. Each error becomes a GitHub annotation. Reads
`xcresulttool get build-results` output on stdin, and runs nothing itself:

    xcrun xcresulttool get build-results --path <path.xcresult> \\
        | python3 -I build-errors.py
"""

import json
import sys
import urllib.parse

text = sys.stdin.read()
if not text.strip():
    print("no build results (did the build start?)")
    sys.exit(0)
try:
    results = json.loads(text)
except json.JSONDecodeError:
    print(text)
    sys.exit(0)

errors = results.get("errors", [])
if not errors:
    print("no build errors in the result bundle")
for error in errors:
    message = error.get("message", "").replace("\n", " ")
    url = urllib.parse.urlparse(error.get("sourceURL", ""))
    if not url.path:
        print(f"::error::{message}")
        continue
    location = urllib.parse.parse_qs(url.fragment)
    # Xcode's document locations count lines and columns from 0.
    line = int(location.get("StartingLineNumber", ["-1"])[0]) + 1
    column = int(location.get("StartingColumnNumber", ["-1"])[0]) + 1
    print(f"::error file={url.path},line={line},col={column}::{message}")
    print(f"{url.path}:{line}:{column}: error: {message}")
