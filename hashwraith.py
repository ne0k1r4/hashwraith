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
