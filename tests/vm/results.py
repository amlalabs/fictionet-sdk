"""Validate one guest boot's transcript and the emulator's exit status.

Usage: python3 results.py --status 0 --require https=0 --require nxdomain=6 out.txt

Records occupy complete lines: === guest begin, === guest result ID STATUS MS,
and === guest end. IDs contain ASCII letters, digits, underscores, dots or
hyphens, starting with a letter, digit or underscore. STATUS is a shell exit
status (0..255); MS is a nonnegative integer. CRLF serial output is accepted.
The === guest prefix is reserved. Other output, including the legacy [exit N]
and [took N ms] diagnostics, is not completion evidence. The host must declare
every required command and still check its output separately.
"""

import argparse
from pathlib import Path
import re
import sys


ID = r"[A-Za-z0-9_][A-Za-z0-9_.-]*"
RESULT = re.compile(rf"=== guest result ({ID}) ([0-9]{{1,3}}) ([0-9]+)")
REQUIREMENT = re.compile(rf"({ID})=([0-9]{{1,3}})")


def requirements(values):
    """Read a nonempty inventory without silently replacing duplicate IDs."""
    required = {}
    for value in values:
        match = REQUIREMENT.fullmatch(value)
        if match is None or int(match[2]) > 255:
            raise ValueError(f"invalid requirement {value!r}; expected ID=STATUS (0..255)")
        name, status = match.groups()
        if name in required:
            raise ValueError(f"duplicate required ID: {name}")
        required[name] = int(status)
    if not required:
        raise ValueError("no required guest IDs declared")
    return required


def validate(transcript, status, required):
    """Return every protocol failure; emulator success never replaces an end."""
    errors = []
    if status != 0:
        reason = "timed out" if status == 124 else "failed"
        errors.append(f"emulator {reason} with status {status}")
    if not required:
        errors.append("no required guest IDs declared")
    begins = ends = 0
    seen = set()
    lines = transcript.split("\n")
    for number, raw in enumerate(lines, 1):
        line = raw.removesuffix("\r")
        if not line.startswith("=== guest"):
            continue
        if number == len(lines):
            errors.append(f"line {number}: unterminated guest record")
            continue
        if line == "=== guest begin":
            begins += 1
            if begins != 1 or ends:
                errors.append(f"line {number}: duplicate or misplaced guest begin")
        elif line == "=== guest end":
            ends += 1
            if begins != 1 or ends != 1:
                errors.append(f"line {number}: duplicate or misplaced guest end")
        else:
            match = RESULT.fullmatch(line)
            if match is None or int(match[2]) > 255:
                errors.append(f"line {number}: malformed guest record: {line!r}")
                continue
            name, actual, _ms = match.groups()
            if begins != 1 or ends:
                errors.append(f"line {number}: result {name} outside guest begin/end")
            if name in seen:
                errors.append(f"duplicate guest ID: {name}")
            seen.add(name)
            if name not in required:
                errors.append(f"undeclared guest ID: {name}")
            elif int(actual) != required[name]:
                errors.append(f"{name}: expected status {required[name]}, got {actual}")
    if not begins:
        errors.append("missing guest begin")
    if not ends:
        errors.append("missing guest end")
    for name in required:
        if name not in seen:
            errors.append(f"missing guest result: {name}")
    return errors


def shell_status(value):
    if not re.fullmatch(r"[0-9]{1,3}", value) or int(value) > 255:
        raise argparse.ArgumentTypeError("expected an exit status from 0 to 255")
    return int(value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--status", type=shell_status, action="append", required=True)
    parser.add_argument("--require", action="append", required=True, metavar="ID=STATUS")
    parser.add_argument("transcript", type=Path)
    args = parser.parse_args()
    if len(args.status) != 1:
        parser.error("--status must be given exactly once")
    try:
        required = requirements(args.require)
        with args.transcript.open(encoding="utf-8", newline="") as source:
            transcript = source.read()
    except (ValueError, OSError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    errors = validate(transcript, args.status[0], required)
    for error in errors:
        print(f"FAIL: {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
