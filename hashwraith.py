#!/usr/bin/env python3
"""
hashwraith - a hashcat wrapper for streamlined hash cracking workflows
Author: Light
"""

import re
import sys
from pathlib import Path

HASH_PATTERNS = [
    (r"^\$2[aby]\$\d{2}\$.{53}$", (3200, "bcrypt")),
    (r"^\$6\$.{0,16}\$.{86}$", (1800, "sha512crypt")),
    (r"^\$5\$.{0,16}\$.{43}$", (7400, "sha256crypt")),
    (r"^\$1\$.{0,8}\$.{22}$", (500, "md5crypt")),
    (r"^[a-fA-F0-9]{32}$", (0, "MD5")),
    (r"^[a-fA-F0-9]{40}$", (100, "SHA1")),
    (r"^[a-fA-F0-9]{64}$", (1400, "SHA256")),
    (r"^[a-fA-F0-9]{128}$", (1700, "SHA512")),
    (r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$", (1000, "NTLM (with LM)")),
]


def detect_hash_type(hash_string):
    """Return list of (mode, name) candidate matches for a given hash string."""
    hash_string = hash_string.strip()
    return [info for pattern, info in HASH_PATTERNS if re.match(pattern, hash_string)]


if __name__ == "__main__":
    if len(sys.argv) > 1:
        print(detect_hash_type(sys.argv[1]))


def check_gpu():
    """Query hashcat for available backend devices."""
    import subprocess
    try:
        result = subprocess.run(["hashcat", "-I"], capture_output=True, text=True, timeout=15)
        devices = []
        for line in result.stdout.splitlines():
            if "Name" in line and "..." in line:
                devices.append(line.split(":", 1)[1].strip())
        return devices
    except FileNotFoundError:
        print("[!] hashcat not found. Install it: sudo pacman -S hashcat")
        sys.exit(1)


WORDLIST_SEARCH_PATHS = [
    Path.home() / "wordlists",
    Path.home() / "rt" / "wordlists",
    Path("/mnt/usb-transfer"),
]

RULE_SEARCH_PATHS = [
    Path("/usr/share/doc/hashcat/rules"),
    Path("/usr/share/john/rules"),
]


def find_wordlists():
    found = []
    for base in WORDLIST_SEARCH_PATHS:
        if base.exists():
            found.extend(base.glob("*.txt"))
            found.extend(f for f in base.glob("*") if f.is_symlink() and f.suffix == ".txt")
    seen, unique = set(), []
    for f in found:
        resolved = f.resolve() if f.exists() or f.is_symlink() else f
        if resolved not in seen:
            seen.add(resolved)
            unique.append(f)
    return unique


def find_rules():
    found = []
    for base in RULE_SEARCH_PATHS:
        if base.exists():
            found.extend(sorted(base.glob("*.rule")))
    return found
