"""Prints a result bundle's failed tests with their file, line and message.

xcodebuild's log ends with a count ("failed ... with 127 issues"); the result
bundle keeps which tests and why. GitHub shows only the first 10 annotations
a step makes, so the first 10 failures become annotations and every failure
is printed. Reads `xcresulttool get test-results tests` output on stdin, and
runs nothing itself:

    xcrun xcresulttool get test-results tests --path <path.xcresult> \\
        | python3 -I test-failures.py
"""

import json
import sys

ANNOTATION_LIMIT = 10
MESSAGE_LIMIT = 300

text = sys.stdin.read()
if not text.strip():
    print("no test results (did testing start?)")
    sys.exit(0)
try:
    results = json.loads(text)
except json.JSONDecodeError:
    print(text)
    sys.exit(0)


def failed_cases(node, suite=""):
    if node.get("nodeType") == "Test Suite":
        suite = node.get("name", suite)
    if node.get("nodeType") == "Test Case" and node.get("result") == "Failed":
        yield suite, node
        return
    for child in node.get("children", []):
        yield from failed_cases(child, suite)


def shorten(message):
    # One line per annotation; a message can print a whole buffer, so cap it.
    joined = " | ".join(line.strip() for line in message.splitlines() if line.strip())
    return joined if len(joined) <= MESSAGE_LIMIT else joined[:MESSAGE_LIMIT] + "..."


annotations = 0
count = 0
for root in results.get("testNodes", []):
    for suite, case in failed_cases(root):
        count += 1
        name = f"{suite}/{case.get('name', '?')}" if suite else case.get("name", "?")
        print(f"FAILED {name}")
        failures = [c for c in case.get("children", []) if c.get("nodeType") == "Failure Message"]
        for failure in failures:
            message = shorten(failure.get("name", ""))
            location = failure.get("sourceLocation", {})
            path = location.get("filePath")
            line = location.get("lineNumber")
            print(f"    {path}:{line}: {message}" if path else f"    {message}")
            if annotations < ANNOTATION_LIMIT:
                annotations += 1
                where = f" file={path},line={line}" if path else ""
                print(f"::error{where}::{name}: {message}")
        if not failures:
            print("    (no failure message recorded)")
print(f"{count} failed test(s)" if count else "no failed tests in the result bundle")
