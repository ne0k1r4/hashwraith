#!/usr/bin/env python3
"""
hashwraith - a hashcat wrapper for streamlined hash cracking workflows
Author: Light
"""

import re
import sys
import subprocess
import argparse
import json
from datetime import datetime
from pathlib import Path

# (mode, name, notes) - notes flag anything needing special handling
HASH_PATTERNS = [
    (r"^\$2[aby]\$\d{2}\$.{53}$", (3200, "bcrypt", None)),
    (r"^\$6\$.{0,16}\$.{86}$", (1800, "sha512crypt", None)),
    (r"^\$5\$.{0,16}\$.{43}$", (7400, "sha256crypt", None)),
    (r"^\$1\$.{0,8}\$.{22}$", (500, "md5crypt / Cisco-IOS type 5", None)),
    (r"^pbkdf2_sha256\$\d+\$.+\$.+$", (10000, "Django PBKDF2-SHA256", None)),
    (r"^\$P\$[./0-9A-Za-z]{31}$", (400, "WordPress / phpBB (phpass)", None)),
    (r"^\$H\$[./0-9A-Za-z]{31}$", (400, "phpass (older phpBB3)", None)),
    (r"^\*[A-F0-9]{40}$", (300, "MySQL 4.1+", None)),
    (r"^[a-f0-9]{16}$", (200, "MySQL <4.1 (old)", None)),
    (r"^\$krb5tgs\$23\$.+$", (13100, "Kerberos 5 TGS-REP (Kerberoasting)", None)),
    (r"^\$krb5asrep\$23\$.+$", (18200, "Kerberos 5 AS-REP (AS-REP roasting)", None)),
    (r"^\$keepass\$.+$", (13400, "KeePass 1/2 (.kdbx)", "extract with keepass2john first")),
    (r"^[a-fA-F0-9]{32}$", (0, "MD5", None)),
    (r"^[a-fA-F0-9]{40}$", (100, "SHA1", None)),
    (r"^[a-fA-F0-9]{64}$", (1400, "SHA256", None)),
    (r"^[a-fA-F0-9]{128}$", (1700, "SHA512", None)),
    (r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$", (1000, "NTLM (with LM)", None)),
]

# Formats that are never a single pasted string - always need an extraction
# tool first and a --hashfile pointed at hashcat's own capture format.
FILE_BASED_HINTS = {
    "WPA/WPA2 handshake": (22000, "Capture with airodump-ng, convert with hcxpcapngtool to .hc22000, then use --hashfile"),
    "KeePass .kdbx": (13400, "Run keepass2john file.kdbx > hash.txt, then use --hashfile hash.txt"),
}


def detect_hash_type(hash_string):
    hash_string = hash_string.strip()
    return [(m, n) for pattern, (m, n, note) in HASH_PATTERNS if re.match(pattern, hash_string)]


def check_gpu():
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

PRIORITY_WORDLIST = Path.home() / "wordlists" / "priority.txt"


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


CONFIG_DIR = Path.home() / ".hashwraith"
CRACKED_LOG = CONFIG_DIR / "cracked.log"


def ensure_dirs():
    CONFIG_DIR.mkdir(exist_ok=True)
    CRACKED_LOG.touch(exist_ok=True)


def prompt_choice(prompt, options, allow_none=True):
    if not options:
        print(f"[!] No options found for: {prompt}")
        return None
    print(f"\n{prompt}")
    for i, opt in enumerate(options, 1):
        print(f"  {i}) {opt}")
    if allow_none:
        print("  0) skip / none")
    while True:
        choice = input("> ").strip()
        if allow_none and choice == "0":
            return None
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            return options[int(choice) - 1]
        print("Invalid choice, try again.")


def log_cracked(hash_type, hash_value, plaintext):
    with open(CRACKED_LOG, "a") as f:
        f.write(f"{datetime.now().isoformat()} | {hash_type} | {hash_value} | {plaintext}\n")


def check_path_exists(path_str, label):
    if not path_str:
        return True
    p = Path(path_str)
    if not p.exists():
        print(f"[!] {label} not found: {path_str}")
        if p.is_symlink():
            print(f"    This is a broken symlink — target may not be mounted/available.")
        return False
    if not p.is_file():
        print(f"[!] {label} is not a regular file: {path_str}")
        return False
    return True


def run_hashcat(target_file, mode, wordlist, rule, session_name, is_hashfile=False):
    """target_file is either a single-hash temp file we wrote, or a
    user-supplied --hashfile (e.g. from keepass2john / hcxpcapngtool)."""
    if not check_path_exists(wordlist, "Wordlist"):
        return None
    if rule and not check_path_exists(rule, "Rule file"):
        return None
    if not check_path_exists(target_file, "Hash file"):
        return None

    potfile = CONFIG_DIR / f"{session_name}.pot"
    cmd = ["hashcat", "-m", str(mode), "-a", "0", str(target_file), wordlist,
           "--session", session_name, "--potfile-path", str(potfile)]
    if rule:
        cmd += ["-r", rule]

    print(f"\n[*] Running: {' '.join(cmd)}\n")
    subprocess.run(cmd)

    if potfile.exists():
        content = potfile.read_text().strip()
        if content:
            last_line = content.splitlines()[-1]
            if ":" in last_line:
                h, plain = last_line.split(":", 1)
                print(f"\n[✓] CRACKED: {plain}")
                log_cracked(mode, h, plain)
                return plain
    return None


def crack_single_hash(hash_value, mode, wordlist, rule, session_prefix, use_priority=True):
    hash_file = CONFIG_DIR / f"{session_prefix}_hash.txt"
    hash_file.write_text(hash_value + "\n")

    if use_priority and PRIORITY_WORDLIST.exists():
        print(f"[*] Trying priority list first ({PRIORITY_WORDLIST})...")
        plain = run_hashcat(hash_file, mode, str(PRIORITY_WORDLIST), None, f"{session_prefix}_priority")
        if plain:
            return plain
        print("[*] Not in priority list, falling back to full wordlist...")
    elif use_priority:
        print("[*] No priority list found, skipping straight to full wordlist.")

    return run_hashcat(hash_file, mode, wordlist, rule, session_prefix)


def cmd_crack(args):
    ensure_dirs()

    if args.hashfile:
        # File-based mode: WPA captures, KeePass exports, etc.
        mode = args.mode or input("Enter hashcat mode number for this file (e.g. 22000 for WPA, 13400 for KeePass): ").strip()
        wordlist = args.wordlist or str(prompt_choice("Select a wordlist:", find_wordlists(), allow_none=False))
        rule = args.rule
        if rule is None and not args.no_rule_prompt:
            chosen = prompt_choice("Select a rule file (optional):", find_rules(), allow_none=True)
            rule = str(chosen) if chosen else None
        session_name = args.session or f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        run_hashcat(args.hashfile, mode, wordlist, rule, session_name, is_hashfile=True)
        return

    hash_value = args.hash or input("Enter the hash to crack: ").strip()

    mode = args.mode
    if mode is None:
        candidates = detect_hash_type(hash_value)
        if len(candidates) == 1:
            mode, name = candidates[0]
            print(f"[*] Detected hash type: {name} (hashcat mode {mode})")
        elif candidates:
            labels = [f"{n} (mode {m})" for m, n in candidates]
            choice = prompt_choice("Select the correct hash type:", labels, allow_none=False)
            mode = candidates[labels.index(choice)][0]
        else:
            print("[!] Could not auto-detect. If this is a WPA handshake or KeePass file,")
            print("    use --hashfile instead of --hash (see README for extraction steps).")
            mode = input("Enter hashcat mode number manually: ").strip()

    wordlist = args.wordlist
    if not wordlist:
        chosen = prompt_choice("Select a wordlist:", find_wordlists(), allow_none=False)
        wordlist = str(chosen)

    rule = args.rule
    if rule is None and not args.no_rule_prompt:
        chosen = prompt_choice("Select a rule file (optional):", find_rules(), allow_none=True)
        rule = str(chosen) if chosen else None

    session_name = args.session or f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    crack_single_hash(hash_value, mode, wordlist, rule, session_name, use_priority=not args.no_priority)


def cmd_batch(args):
    ensure_dirs()
    hashes = Path(args.file).read_text().splitlines()
    hashes = [h.strip() for h in hashes if h.strip()]
    print(f"[*] Loaded {len(hashes)} hashes from {args.file}")

    wordlist = args.wordlist or str(prompt_choice("Select a wordlist:", find_wordlists(), allow_none=False))
    rule = args.rule

    results = {}
    for i, h in enumerate(hashes, 1):
        print(f"\n=== [{i}/{len(hashes)}] {h[:50]} ===")
        candidates = detect_hash_type(h)
        mode = candidates[0][0] if candidates else args.mode
        if mode is None:
            print("[!] Skipping - could not detect hash type and no --mode given")
            continue
        plain = crack_single_hash(h, mode, wordlist, rule, f"batch_{i}")
        results[h] = plain

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(results, indent=2))
        print(f"\n[*] Results exported to {args.json_out}")


def cmd_benchmark(args):
    subprocess.run(["hashcat", "-b"])


def cmd_list_wordlists(args):
    for f in find_wordlists():
        size = f.stat().st_size if f.exists() else 0
        unit = f"{size / (1024**3):.2f} GB" if size > 10**8 else f"{size/1024:.1f} KB"
        exists = "✓" if f.exists() else "✗ (broken link)"
        print(f"  {exists} {f}  ({unit})")


def cmd_list_rules(args):
    for r in find_rules():
        print(f"  {r}")


def cmd_gpu(args):
    devices = check_gpu()
    print("[*] Detected devices:" if devices else "[!] No devices detected.")
    for d in devices:
        print(f"  - {d}")


def cmd_formats(args):
    print("Supported hash formats (auto-detected from a pasted string):\n")
    for pattern, (mode, name, note) in HASH_PATTERNS:
        note_str = f"  [{note}]" if note else ""
        print(f"  mode {mode:<6} {name}{note_str}")
    print("\nFile-based formats (require --hashfile, need extraction first):\n")
    for name, (mode, howto) in FILE_BASED_HINTS.items():
        print(f"  mode {mode:<6} {name}")
        print(f"           → {howto}")


def main():
    parser = argparse.ArgumentParser(prog="hashwraith", description="A streamlined hashcat wrapper.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_crack = sub.add_parser("crack", help="Crack a single hash or hash file")
    p_crack.add_argument("--hash", help="Paste a single hash string")
    p_crack.add_argument("--hashfile", help="Path to a pre-extracted hash file (WPA/KeePass/etc)")
    p_crack.add_argument("--mode", type=int)
    p_crack.add_argument("--wordlist")
    p_crack.add_argument("--rule")
    p_crack.add_argument("--session")
    p_crack.add_argument("--no-rule-prompt", action="store_true")
    p_crack.add_argument("--no-priority", action="store_true", help="Skip the fast priority-list pass")
    p_crack.set_defaults(func=cmd_crack)

    p_batch = sub.add_parser("batch", help="Crack every hash in a file (one per line)")
    p_batch.add_argument("--file", required=True)
    p_batch.add_argument("--mode", type=int)
    p_batch.add_argument("--wordlist")
    p_batch.add_argument("--rule")
    p_batch.add_argument("--json-out")
    p_batch.set_defaults(func=cmd_batch)

    sub.add_parser("benchmark", help="Run hashcat's benchmark").set_defaults(func=cmd_benchmark)
    sub.add_parser("wordlists", help="List discovered wordlists").set_defaults(func=cmd_list_wordlists)
    sub.add_parser("rules", help="List discovered rule files").set_defaults(func=cmd_list_rules)
    sub.add_parser("gpu", help="Show detected GPU devices").set_defaults(func=cmd_gpu)
    sub.add_parser("formats", help="List all supported hash formats").set_defaults(func=cmd_formats)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
