#!/usr/bin/env python3
"""Offline digest generator for the ShellAuth gate.

Scheme (must match ShellAuth.c exactly):
  d0 = SHA256(salt || password_utf16le_padded_to_128_bytes)
  di = SHA256(salt || d(i-1))   for i = 1 .. ITERATIONS
  expected = d(ITERATIONS)

Usage:
  gen-digest.py [--output FILE] [password]

  --output FILE   write the 32-byte expected digest as binary (for tpm2_nvwrite)

  If password is omitted, it is read from stdin (first line, newline stripped).
  Prefer stdin: argv is visible in /proc/<pid>/cmdline while the KDF runs.
"""
import argparse
import hashlib
import sys

SALT = bytes([
    0xF7, 0x52, 0xD1, 0x4D, 0x1A, 0x0C, 0x1E, 0xC1,
    0xF0, 0x73, 0x47, 0x42, 0x96, 0xB7, 0x73, 0xA3,
])
MAX_PASSWORD_LEN = 64          # CHAR16s -> 128 bytes
ITERATIONS = 100000            # must match STRETCH_ITERATIONS in ShellAuth.c


def c_array(name: str, data: bytes) -> str:
    hexed = ", ".join(f"0x{b:02X}" for b in data)
    return f"const UINT8 {name}[{len(data)}] = {{ {hexed} }};"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", metavar="FILE",
                        help="write 32-byte binary digest to FILE (for tpm2_nvwrite)")
    parser.add_argument("password", nargs="?", default=None)
    args = parser.parse_args()

    password = args.password
    if password is None:
        password = sys.stdin.readline().rstrip("\n")

    if len(password) > MAX_PASSWORD_LEN:
        sys.exit(f"password longer than {MAX_PASSWORD_LEN} chars")

    buf = password.encode("utf-16-le").ljust(2 * MAX_PASSWORD_LEN, b"\0")
    digest = hashlib.sha256(SALT + buf).digest()
    print(f"d0 (cross-check against gate at iterations=0): {digest.hex()}")

    for _ in range(ITERATIONS):
        digest = hashlib.sha256(SALT + digest).digest()

    print(f"expected after {ITERATIONS} rounds:")
    print(c_array("expected", digest))

    if args.output:
        with open(args.output, "wb") as f:
            f.write(digest)
        print(f"wrote {args.output} ({len(digest)} bytes)")


if __name__ == "__main__":
    main()
