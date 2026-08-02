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
    from datetime import datetime
    with open(CRACKED_LOG, "a") as f:
        f.write(f"{datetime.now().isoformat()} | {hash_type} | {hash_value} | {plaintext}\n")


def run_hashcat(hash_value, mode, wordlist, rule, session_name):
    import subprocess
    from datetime import datetime

    hash_file = CONFIG_DIR / f"{session_name}_hash.txt"
    hash_file.write_text(hash_value + "\n")
    potfile = CONFIG_DIR / f"{session_name}.pot"

    cmd = ["hashcat", "-m", str(mode), "-a", "0", str(hash_file), wordlist,
           "--session", session_name, "--potfile-path", str(potfile)]
    if rule:
        cmd += ["-r", rule]

    print(f"\n[*] Running: {' '.join(cmd)}\n")
    subprocess.run(cmd)

    if potfile.exists():
        content = potfile.read_text().strip()
        for line in content.splitlines():
            if ":" in line:
                h, plain = line.split(":", 1)
                print(f"\n[✓] CRACKED: {plain}")
                log_cracked(mode, hash_value, plain)
                return plain
    print("\n[!] Not cracked with this wordlist/rule combo.")
    return None


def cmd_crack(args):
    ensure_dirs()
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
            mode = input("Enter hashcat mode number manually: ").strip()

    wordlist = args.wordlist or str(prompt_choice("Select a wordlist:", find_wordlists(), allow_none=False))
    rule = args.rule
    if rule is None and not args.no_rule_prompt:
        chosen = prompt_choice("Select a rule file (optional):", find_rules(), allow_none=True)
        rule = str(chosen) if chosen else None

    from datetime import datetime
    session_name = args.session or f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    run_hashcat(hash_value, mode, wordlist, rule, session_name)


def cmd_batch(args):
    """Crack every hash in a file, one at a time, same wordlist/rule for all."""
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
        plain = run_hashcat(h, mode, wordlist, rule, f"batch_{i}")
        results[h] = plain

    if args.json_out:
        import json
        Path(args.json_out).write_text(json.dumps(results, indent=2))
        print(f"\n[*] Results exported to {args.json_out}")


def cmd_benchmark(args):
    import subprocess
    subprocess.run(["hashcat", "-b"])


def cmd_list_wordlists(args):
    for f in find_wordlists():
        size = f.stat().st_size if f.exists() else 0
        unit = f"{size / (1024**3):.2f} GB" if size > 10**8 else f"{size/1024:.1f} KB"
        print(f"  {f}  ({unit})")


def cmd_list_rules(args):
    for r in find_rules():
        print(f"  {r}")


def cmd_gpu(args):
    devices = check_gpu()
    print("[*] Detected devices:" if devices else "[!] No devices detected.")
    for d in devices:
        print(f"  - {d}")


def main():
    import argparse
    parser = argparse.ArgumentParser(prog="hashwraith", description="A streamlined hashcat wrapper.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_crack = sub.add_parser("crack", help="Crack a single hash")
    p_crack.add_argument("--hash")
    p_crack.add_argument("--mode", type=int)
    p_crack.add_argument("--wordlist")
    p_crack.add_argument("--rule")
    p_crack.add_argument("--session")
    p_crack.add_argument("--no-rule-prompt", action="store_true")
    p_crack.set_defaults(func=cmd_crack)

    p_batch = sub.add_parser("batch", help="Crack every hash in a file")
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

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
