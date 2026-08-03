#!/usr/bin/env python3
"""
hashwraith - a hashcat wrapper for streamlined hash cracking workflows
Author: Light

Got tired of re-typing mode numbers and hunting for wordlist paths every
time, so this exists. Everything still shells out to real hashcat under
the hood - this just adds auto-detection and sane defaults on top of it.
"""

import re
import sys
import subprocess
import argparse
import json
from datetime import datetime
from pathlib import Path


# ─── Terminal colors (plain ANSI, no external deps) ────────────────────
# Deliberately not using a library like `rich` here - this tool should
# work on a bare Python 3 install with nothing extra to pip install.
class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def info(msg):
    """Neutral status message - cyan [*]."""
    print(f"{C.CYAN}[*]{C.RESET} {msg}")


def ok(msg):
    """Success message - green [✓], bolded so a crack result stands out
    even when scrolled past a wall of hashcat's own verbose output."""
    print(f"{C.GREEN}{C.BOLD}[✓]{C.RESET} {msg}")


def warn(msg):
    """Non-fatal problem - yellow [!]. Used for things like a missing
    optional file, not something that stops execution."""
    print(f"{C.YELLOW}[!]{C.RESET} {msg}")


def err(msg):
    """Fatal problem - red [✗]. Always paired with sys.exit(1) at the
    call site; this function itself never exits, just prints."""
    print(f"{C.RED}[✗]{C.RESET} {msg}")


# ─── Hash type auto-detection ───────────────────────────────────────────
# (regex pattern, (hashcat mode number, display name, optional extraction note))
# Ordered roughly by specificity - the more distinctive $-prefixed formats
# come first so a generic 32-hex-char pattern doesn't accidentally win
# over a more specific match further down the list. Kept as simple regex
# rather than a full hash-identification library (like hashid) on purpose:
# no dependency, easy to read, easy to extend with one more tuple.
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
    # Bare hex-length formats last - these are the least specific patterns
    # (many different hash types share the same output length), so they
    # act as a fallback rather than a first match.
    (r"^[a-fA-F0-9]{32}$", (0, "MD5", None)),
    (r"^[a-fA-F0-9]{40}$", (100, "SHA1", None)),
    (r"^[a-fA-F0-9]{64}$", (1400, "SHA256", None)),
    (r"^[a-fA-F0-9]{128}$", (1700, "SHA512", None)),
    (r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$", (1000, "NTLM (with LM)", None)),
]

# Formats that are never a single pasted string - WPA captures and KeePass
# databases are binary files that need a separate extraction tool first
# (hcxpcapngtool, keepass2john). Listed here purely for the `formats`
# command's documentation output; detect_hash_type() never matches these.
FILE_BASED_HINTS = {
    "WPA/WPA2 handshake": (22000, "Capture with airodump-ng, convert with hcxpcapngtool to .hc22000, then use --hashfile"),
    "KeePass .kdbx": (13400, "Run keepass2john file.kdbx > hash.txt, then use --hashfile hash.txt"),
}

# All persistent tool state lives under ~/.hashwraith/ - hash files,
# potfiles, the cracked-hash log, and the config file. Kept separate from
# hashcat's OWN session/restore files, which hashcat insists on writing to
# its own default location (see HASHCAT_SESSIONS_DIR below) regardless of
# --potfile-path; that was a real bug caught during testing, not a design
# choice - hashcat's --restore mechanism ignores custom paths entirely.
DRY_RUN = False  # set by --dry-run, checked in every run_* function before subprocess.run

CONFIG_DIR = Path.home() / ".hashwraith"
CRACKED_LOG = CONFIG_DIR / "cracked.log"
CONFIG_FILE = CONFIG_DIR / "config.json"
HASHCAT_SESSIONS_DIR = Path.home() / ".local" / "share" / "hashcat" / "sessions"

DEFAULT_CONFIG = {
    "default_wordlist": None,
    "default_rule": None,
    # A small, frequency-ranked wordlist tried BEFORE the big exhaustive
    # one (see crack_single_hash below). This is the single biggest
    # real-world speed win in the whole tool: an alphabetically-sorted
    # multi-billion-line list can take 10+ minutes to reach a password
    # as common as "password" purely because of where it falls alphabetically.
    # A ~100k frequency-ranked list finds the same password in under a second.
    "priority_wordlist": str(Path.home() / "wordlists" / "priority.txt"),
}


def ensure_dirs():
    """Create ~/.hashwraith/ and touch the cracked-hash log if missing.
    Called defensively at the top of most commands rather than assuming
    a previous run already set things up."""
    CONFIG_DIR.mkdir(exist_ok=True)
    CRACKED_LOG.touch(exist_ok=True)


def load_config():
    """Load saved defaults, falling back to DEFAULT_CONFIG for any key
    that's missing or if the file is corrupted. Never raises - a broken
    config file should degrade to defaults, not crash the whole tool."""
    ensure_dirs()
    if CONFIG_FILE.exists():
        try:
            cfg = json.loads(CONFIG_FILE.read_text())
            merged = DEFAULT_CONFIG.copy()
            merged.update(cfg)
            return merged
        except json.JSONDecodeError:
            print("[!] Config file is corrupted, using defaults.")
            return DEFAULT_CONFIG.copy()
    return DEFAULT_CONFIG.copy()


def save_config(cfg):
    ensure_dirs()
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))


def detect_hash_type(hash_string):
    """Return every HASH_PATTERNS entry that matches the given string,
    as a list of (mode, name) tuples. Deliberately returns ALL matches,
    not just the first - some hash lengths are genuinely ambiguous
    (e.g. 32 hex chars could be MD5 or old MySQL), and the caller decides
    what to do with multiple candidates (auto-pick if there's only one,
    prompt the user if there's more)."""
    hash_string = hash_string.strip()
    return [(m, n) for pattern, (m, n, note) in HASH_PATTERNS if re.match(pattern, hash_string)]


def check_gpu():
    # querying hashcat directly instead of lspci - if hashcat can't see
    # the GPU (missing OpenCL runtime etc) there's no point reporting
    # hardware that's there but unusable
    try:
        result = subprocess.run(["hashcat", "-I"], capture_output=True, text=True, timeout=15)
        devices = []
        for line in result.stdout.splitlines():
            if "Name" in line and "..." in line:
                devices.append(line.split(":", 1)[1].strip())
        return devices
    except FileNotFoundError:
        warn("hashcat not found. Install it: sudo pacman -S hashcat")
        sys.exit(1)


# Every location this tool will scan looking for wordlists/rules, rather
# than requiring a hardcoded single path. Covers a personal ~/wordlists
# folder, a security-work-specific ~/rt/wordlists folder, and a mounted
# USB drive - the actual layout this tool was built against, but easy to
# extend with more paths if your own setup differs.
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
    """Scan all WORDLIST_SEARCH_PATHS for .txt files and symlinks to
    .txt files (the latter matters for e.g. ~/wordlists/priority.txt
    symlinked to a file that lives on a mounted USB drive). Dedupes by
    resolved path so the same physical file isn't listed twice if it's
    reachable via more than one search path."""
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


def prompt_choice(prompt, options, allow_none=True):
    # every interactive menu in this tool goes through here, saves
    # rewriting the same input-validation loop five times
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
    # plaintext + append-only on purpose, don't need a db for this and
    # it's nice being able to just cat the file
    with open(CRACKED_LOG, "a") as f:
        f.write(f"{datetime.now().isoformat()} | {hash_type} | {hash_value} | {plaintext}\n")


def check_path_exists(path_str, label):
    """Pre-flight check run before every hashcat invocation. Added after
    a real failure during testing: an unmounted USB drive left a broken
    symlink in place, and hashcat's own error ("No such file or directory")
    was easy to miss buried in its startup banner. This surfaces the
    problem clearly and specifically flags broken symlinks, since that's
    the most common real-world cause here (drive not mounted yet)."""
    if not path_str:
        return True  # None is valid for optional args like --rule
    p = Path(path_str)
    if not p.exists():
        warn(f"{label} not found: {path_str}")
        if p.is_symlink():
            print(f"    This is a broken symlink — target may not be mounted/available.")
        return False
    if not p.is_file():
        warn(f"{label} is not a regular file: {path_str}")
        return False
    return True


# ─── Shared potfile parsing ─────────────────────────────────────────────
# Every run_* function below used to have its own copy-pasted "read the
# potfile, split on the last colon" logic. Consolidated here after a real
# bug: a patch updated three of the four copies but silently missed one,
# and it went unnoticed until a test caught it. One implementation now,
# used everywhere - if it's wrong, it's wrong in exactly one place.
def read_last_potfile_result(potfile):
    """Read a potfile and return (hash, plaintext) for the LAST cracked
    entry, or (None, None) if nothing's there. 'Last', not 'any', matters
    when a session name gets reused and the potfile accumulates more than
    one result over time."""
    if not potfile.exists():
        return None, None
    content = potfile.read_text().strip()
    if not content:
        return None, None
    last_line = content.splitlines()[-1]
    if ":" not in last_line:
        return None, None
    h, plain = last_line.split(":", 1)
    return h, plain


def read_all_potfile_results(potfile):
    """Same idea but returns every cracked (hash, plaintext) pair, not
    just the last one - used by multi-hash mode where a single hashcat
    run can crack several hashes in one potfile."""
    if not potfile.exists():
        return []
    content = potfile.read_text().strip()
    if not content:
        return []
    results = []
    for line in content.splitlines():
        if ":" in line:
            h, plain = line.split(":", 1)
            results.append((h, plain))
    return results


def run_hashcat(target_file, mode, wordlist, rule, session_name):
    """Core dictionary-attack (-a 0) invocation. Every other attack mode
    (mask, combinator) has its own similar run_* function rather than
    trying to force every hashcat attack mode through one shared function -
    the -a modes take different positional arguments (one wordlist vs
    two vs a mask string), so keeping them separate is more readable than
    one function with a pile of conditional argument-building logic.
    Potfile parsing itself IS shared though - see read_last_potfile_result."""
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
    if DRY_RUN:
        info("(dry run - not actually executing)")
        return None
    subprocess.run(cmd)

    h, plain = read_last_potfile_result(potfile)
    if plain:
        print(f"\n[✓] CRACKED: {plain}")
        log_cracked(mode, h, plain)
        return plain
    return None


def crack_single_hash(hash_value, mode, wordlist, rule, session_prefix, cfg, use_priority=True):
    """The actual entry point most single-hash cracks go through. Tries
    the small priority wordlist first (near-instant if the password is
    common), only falling through to the full wordlist + rules if that
    doesn't find a match. This ordering is the single biggest practical
    speedup in the tool - see DEFAULT_CONFIG's priority_wordlist comment."""
    hash_file = CONFIG_DIR / f"{session_prefix}_hash.txt"
    hash_file.write_text(hash_value + "\n")

    priority_path = cfg.get("priority_wordlist")
    if use_priority and priority_path and Path(priority_path).exists():
        info(f"Trying priority list first ({priority_path})...")
        plain = run_hashcat(hash_file, mode, priority_path, None, f"{session_prefix}_priority")
        if plain:
            return plain
        info("Not in priority list, falling back to full wordlist...")
    elif use_priority:
        info("No priority list configured/found, skipping straight to full wordlist.")

    return run_hashcat(hash_file, mode, wordlist, rule, session_prefix)


def cmd_crack(args):
    """Handles three distinct input modes in one command:
    1. --restore: resume a previously interrupted session (checked first,
       since none of the other hash/wordlist logic applies to a resume)
    2. --hashfile: a pre-extracted hash file (WPA/KeePass/etc)
    3. --hash: a single pasted hash string (the common case)

    Every prompt in this function is guarded by `args.yes` - if set, a
    missing required value is a hard error instead of a prompt, so this
    command is safe to call from a script without ever hanging waiting
    for input that will never come."""
    cfg = load_config()

    if args.restore:
        # hashcat's OWN restore mechanism ignores our --potfile-path entirely
        # and writes/reads its .restore file from its own default sessions
        # directory - this was discovered by testing an actual interrupted
        # session, not assumed. Hence HASHCAT_SESSIONS_DIR being a totally
        # separate constant from our own CONFIG_DIR.
        restore_file = HASHCAT_SESSIONS_DIR / f"{args.restore}.restore"
        if not restore_file.exists():
            err(f"No restore file found for session '{args.restore}'. Run 'hashwraith sessions' to see available ones.")
            sys.exit(1)
        info(f"Resuming session: {args.restore}")
        cmd = ["hashcat", "--session", args.restore, "--restore"]
        subprocess.run(cmd)
        potfile = CONFIG_DIR / f"{args.restore}.pot"
        h, plain = read_last_potfile_result(potfile)
        if plain:
            ok(f"CRACKED: {plain}")
            log_cracked("restored", h, plain)
        return

    if args.hashfile:
        mode = args.mode
        if mode is None:
            if args.yes:
                err("--yes was set but no --mode given for --hashfile input. Aborting.")
                sys.exit(1)
            mode = input("Enter hashcat mode number for this file: ").strip()
        wordlist = args.wordlist or cfg.get("default_wordlist")
        if not wordlist:
            if args.yes:
                err("--yes was set but no wordlist given and no default configured. Aborting.")
                sys.exit(1)
            wordlist = str(prompt_choice("Select a wordlist:", find_wordlists(), allow_none=False))
        rule = args.rule or cfg.get("default_rule")
        if rule is None and not args.no_rule_prompt and not args.yes:
            chosen = prompt_choice("Select a rule file (optional):", find_rules(), allow_none=True)
            rule = str(chosen) if chosen else None
        session_name = args.session or f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        run_hashcat(args.hashfile, mode, wordlist, rule, session_name)
        return

    if not args.hash and not args.hashfile:
        if args.yes:
            err("--yes was set but no --hash or --hashfile was given. Aborting.")
            sys.exit(1)
        hash_value = input("Enter the hash to crack: ").strip()
    else:
        hash_value = args.hash

    mode = args.mode
    if mode is None:
        candidates = detect_hash_type(hash_value)
        if len(candidates) == 1:
            mode, name = candidates[0]
            info(f"Detected hash type: {name} (hashcat mode {mode})")
        elif candidates:
            # Genuinely ambiguous - e.g. a bare 32-hex-char string could be
            # MD5 or something else the same length. Ask rather than guess.
            labels = [f"{n} (mode {m})" for m, n in candidates]
            choice = prompt_choice("Select the correct hash type:", labels, allow_none=False)
            mode = candidates[labels.index(choice)][0]
        else:
            print("[!] Could not auto-detect. If this is a WPA handshake or KeePass file,")
            print("    use --hashfile instead of --hash (see README for extraction steps).")
            mode = input("Enter hashcat mode number manually: ").strip()

    wordlist = args.wordlist or cfg.get("default_wordlist")
    if not wordlist:
        if args.yes:
            err("--yes was set but no wordlist given and no default configured. Aborting.")
            sys.exit(1)
        wordlist = str(prompt_choice("Select a wordlist:", find_wordlists(), allow_none=False))

    rule = args.rule or cfg.get("default_rule")
    if rule is None and not args.no_rule_prompt and not args.yes:
        chosen = prompt_choice("Select a rule file (optional):", find_rules(), allow_none=True)
        rule = str(chosen) if chosen else None

    session_name = args.session or f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    crack_single_hash(hash_value, mode, wordlist, rule, session_name, cfg, use_priority=not args.no_priority)


def cmd_batch(args):
    """Crack every hash in a file, one at a time. Each hash gets its own
    hashcat session (batch_1, batch_2, ...) rather than combining them
    into a single hashcat run - simpler to reason about progress and
    results per-hash, at the cost of not sharing GPU warm-up time across
    hashes. Fine tradeoff for typical batch sizes (dozens, not millions).
    For same-type hashes at real scale, use 'multibatch' instead."""
    cfg = load_config()
    hashes = Path(args.file).read_text().splitlines()
    hashes = [h.strip() for h in hashes if h.strip()]
    info(f"Loaded {len(hashes)} hashes from {args.file}")

    wordlist = args.wordlist or cfg.get("default_wordlist")
    if not wordlist:
        if args.yes:
            err("--yes was set but no wordlist given and no default configured. Aborting.")
            sys.exit(1)
        wordlist = str(prompt_choice("Select a wordlist:", find_wordlists(), allow_none=False))
    rule = args.rule or cfg.get("default_rule")

    results = {}
    for i, h in enumerate(hashes, 1):
        print(f"\n=== [{i}/{len(hashes)}] {h[:50]} ===")
        candidates = detect_hash_type(h)
        mode = candidates[0][0] if candidates else args.mode
        if mode is None:
            print("[!] Skipping - could not detect hash type and no --mode given")
            continue
        plain = crack_single_hash(h, mode, wordlist, rule, f"batch_{i}", cfg)
        results[h] = plain

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(results, indent=2))
        info(f"\nResults exported to {args.json_out}")


def cmd_benchmark(args):
    # not reinventing hashcat's own benchmark, just passing through
    subprocess.run(["hashcat", "-b"])


def cmd_list_wordlists(args):
    for f in find_wordlists():
        size = f.stat().st_size if f.exists() else 0
        unit = f"{size / (1024**3):.2f} GB" if size > 10**8 else f"{size/1024:.1f} KB"
        # Flags broken symlinks visibly here too, not just at crack-time -
        # lets you spot an unmounted-drive problem before you even try
        # to crack anything.
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
    # just a docs command, lists what we can auto-detect + the file-based stuff
    print("Supported hash formats (auto-detected from a pasted string):\n")
    for pattern, (mode, name, note) in HASH_PATTERNS:
        note_str = f"  [{note}]" if note else ""
        print(f"  mode {mode:<6} {name}{note_str}")
    print("\nFile-based formats (require --hashfile, need extraction first):\n")
    for name, (mode, howto) in FILE_BASED_HINTS.items():
        print(f"  mode {mode:<6} {name}")
        print(f"           → {howto}")


def cmd_sessions(args):
    # reads HASHCAT_SESSIONS_DIR not our own config dir - see the note
    # up top about hashcat ignoring --potfile-path for restore stuff
    if not HASHCAT_SESSIONS_DIR.exists():
        print("No resumable sessions found.")
        return
    restore_files = sorted(HASHCAT_SESSIONS_DIR.glob("*.restore"))
    if not restore_files:
        print("No resumable sessions found.")
        return
    print("Resumable sessions (use: hashwraith crack --restore <name>):\n")
    for rf in restore_files:
        session_name = rf.stem
        print(f"  {session_name}")


def cmd_config(args):
    # persists defaults so I'm not picking the same wordlist every time
    cfg = load_config()
    if args.action == "show":
        print(json.dumps(cfg, indent=2))
    elif args.action == "set-wordlist":
        cfg["default_wordlist"] = args.value
        save_config(cfg)
        ok(f"Default wordlist set to: {args.value}")
    elif args.action == "set-rule":
        cfg["default_rule"] = args.value
        save_config(cfg)
        ok(f"Default rule set to: {args.value}")
    elif args.action == "set-priority":
        cfg["priority_wordlist"] = args.value
        save_config(cfg)
        ok(f"Priority wordlist set to: {args.value}")
    elif args.action == "reset":
        save_config(DEFAULT_CONFIG.copy())
        ok("Config reset to defaults.")


# ─── Mask attacks (-a 3) ────────────────────────────────────────────────
# Dictionary attacks only find passwords that exist verbatim (or via a
# rule-mutation) somewhere in a wordlist. Mask attacks instead brute-force
# by PATTERN - e.g. "capital letter, 5 lowercase, 2 digits" - which catches
# passwords that would never appear in any wordlist but still follow a
# predictable human structure (like "Summer23"). Genuinely complementary
# to dictionary attacks, not a replacement - hence being a separate
# `mask` subcommand rather than folded into `crack`.
# ?l lowercase  ?u uppercase  ?d digit  ?s special  ?a all
COMMON_MASKS = {
    "4-digit PIN": "?d?d?d?d",
    "6-digit PIN": "?d?d?d?d?d?d",
    "8 lowercase letters": "?l?l?l?l?l?l?l?l",
    "Word + 2 digits (e.g. summer23)": "?l?l?l?l?l?l?d?d",
    "Capitalized word + 2 digits (e.g. Summer23)": "?u?l?l?l?l?l?d?d",
    "Capitalized word + 4 digits (e.g. Summer2023)": "?u?l?l?l?l?l?d?d?d?d",
    "Word + special + 2 digits (e.g. summer!23)": "?l?l?l?l?l?l?s?d?d",
    "8-char fully random (all charsets)": "?a?a?a?a?a?a?a?a",
}


def run_mask_attack(target_file, mode, mask, session_name):
    potfile = CONFIG_DIR / f"{session_name}.pot"
    cmd = ["hashcat", "-m", str(mode), "-a", "3", str(target_file), mask,
           "--session", session_name, "--potfile-path", str(potfile)]
    info(f"Running mask attack: {' '.join(cmd)}")
    if DRY_RUN:
        info("(dry run - not actually executing)")
        return None
    subprocess.run(cmd)
    h, plain = read_last_potfile_result(potfile)
    if plain:
        ok(f"CRACKED: {plain}")
        log_cracked(mode, h, plain)
        return plain
    return None


def cmd_mask(args):
    ensure_dirs()
    hash_value = args.hash or input("Enter the hash to crack: ").strip()

    mode = args.mode
    if mode is None:
        candidates = detect_hash_type(hash_value)
        if candidates:
            mode = candidates[0][0]
            info(f"Detected hash type: {candidates[0][1]} (hashcat mode {mode})")
        else:
            mode = input("Enter hashcat mode number manually: ").strip()

    mask = args.mask
    if not mask:
        labels = list(COMMON_MASKS.keys())
        choice = prompt_choice("Select a common mask (or supply --mask yourself next time):", labels, allow_none=False)
        mask = COMMON_MASKS[choice]

    hash_file = CONFIG_DIR / f"mask_{datetime.now().strftime('%Y%m%d_%H%M%S')}_hash.txt"
    hash_file.write_text(hash_value + "\n")
    session_name = args.session or f"mask_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    run_mask_attack(hash_file, mode, mask, session_name)


def cmd_masks(args):
    print("Built-in common masks (use with: hashwraith mask --mask '<pattern>'):\n")
    for name, pattern in COMMON_MASKS.items():
        print(f"  {pattern:<20} {name}")
    print("\nMask syntax: ?l lowercase, ?u uppercase, ?d digit, ?s special, ?a all")


# ─── Wordlist statistics (inspired by PACK's statsgen) ─────────────────
# The idea, borrowed from the Password Analysis and Cracking Kit (PACK):
# before guessing which mask pattern to try, look at REAL data. Sampling
# a wordlist's actual length/charset distribution tells you which
# COMMON_MASKS entry is actually worth running against a similar target
# population, instead of picking one blind.
def analyze_wordlist(path, sample_size=500000):
    """Sample a wordlist and report length distribution + charset patterns.
    Sampling (not scanning the whole file) matters for multi-billion-line
    lists - a 500k sample is statistically representative and vastly
    faster than reading the entire file line by line."""
    lengths = {}
    charset_patterns = {}
    count = 0

    with open(path, "r", errors="ignore") as f:
        for line in f:
            word = line.rstrip("\n")
            if not word:
                continue
            count += 1
            if count > sample_size:
                break

            l = len(word)
            lengths[l] = lengths.get(l, 0) + 1

            has_lower = any(c.islower() for c in word)
            has_upper = any(c.isupper() for c in word)
            has_digit = any(c.isdigit() for c in word)
            has_special = any(not c.isalnum() for c in word)

            pattern = ""
            if has_lower:
                pattern += "l"
            if has_upper:
                pattern += "u"
            if has_digit:
                pattern += "d"
            if has_special:
                pattern += "s"
            pattern = pattern or "?"
            charset_patterns[pattern] = charset_patterns.get(pattern, 0) + 1

    return count, lengths, charset_patterns


def cmd_stats(args):
    # sampling logic works fine but the pattern_names dict below is
    # incomplete - only covers the common combos, rare ones just print
    # the raw letter code. good enough for now
    path = args.wordlist
    if not check_path_exists(path, "Wordlist"):
        return

    info(f"Sampling up to {args.sample:,} entries from {path}...")
    count, lengths, patterns = analyze_wordlist(path, args.sample)

    print(f"\nSampled {count:,} passwords\n")

    print("Length distribution (top 10):")
    for length, n in sorted(lengths.items(), key=lambda x: -x[1])[:10]:
        pct = (n / count) * 100
        bar = "#" * int(pct / 2)
        print(f"  {length:>3} chars: {n:>7,} ({pct:5.1f}%) {bar}")

    print("\nCharacter-set pattern distribution (top 10):")
    pattern_names = {
        "l": "lowercase only", "u": "uppercase only", "d": "digits only",
        "s": "special only", "lu": "mixed case", "ld": "lower+digit",
        "lud": "lower+upper+digit", "lds": "lower+digit+special",
        "luds": "lower+upper+digit+special",
    }
    for pattern, n in sorted(patterns.items(), key=lambda x: -x[1])[:10]:
        pct = (n / count) * 100
        name = pattern_names.get(pattern, pattern)
        bar = "#" * int(pct / 2)
        print(f"  {pattern:<6} ({name:<28}): {n:>7,} ({pct:5.1f}%) {bar}")

    print("\nSuggested next step: pick a COMMON_MASKS entry (see 'hashwraith masks')")
    print("that matches the dominant length + pattern above.")
    # This caveat matters: if the wordlist being analyzed has already been
    # through hashcat rule-mutation (leetspeak/symbol injection), the stats
    # reflect what the RULES produced, not genuine human password behavior.
    # Discovered this the hard way analyzing a mutated list and seeing
    # unrealistically high "special character" percentages.
    warn("If this wordlist has been rule-mutated (leetspeak/symbol injection),")
    warn("these stats reflect the mutation rules, not raw human password behavior.")
    warn("For representative human stats, run against an unmutated source list instead.")


# ─── Combinator attack (-a 1) ───────────────────────────────────────────
# Combines every word from list1 with every word from list2 - e.g.
# firstnames.txt + suffixes.txt catches patterns like "john2023", "sarah!".
# A third distinct attack surface alongside dictionary+rules and mask
# attacks: useful specifically for compound patterns that neither of the
# other two modes are well-suited to generate on their own.
def run_combinator_attack(target_file, mode, wordlist1, wordlist2, session_name):
    potfile = CONFIG_DIR / f"{session_name}.pot"
    cmd = ["hashcat", "-m", str(mode), "-a", "1", str(target_file), wordlist1, wordlist2,
           "--session", session_name, "--potfile-path", str(potfile)]
    info(f"Running combinator attack: {' '.join(cmd)}")
    if DRY_RUN:
        info("(dry run - not actually executing)")
        return None
    subprocess.run(cmd)
    h, plain = read_last_potfile_result(potfile)
    if plain:
        ok(f"CRACKED: {plain}")
        log_cracked(mode, h, plain)
        return plain
    return None


def cmd_combinator(args):
    ensure_dirs()
    hash_value = args.hash or input("Enter the hash to crack: ").strip()

    mode = args.mode
    if mode is None:
        candidates = detect_hash_type(hash_value)
        if candidates:
            mode = candidates[0][0]
            info(f"Detected hash type: {candidates[0][1]} (hashcat mode {mode})")
        else:
            mode = input("Enter hashcat mode number manually: ").strip()

    wordlist1 = args.wordlist1
    if not wordlist1:
        wordlist1 = str(prompt_choice("Select the FIRST wordlist (prefix):", find_wordlists(), allow_none=False))
    wordlist2 = args.wordlist2
    if not wordlist2:
        wordlist2 = str(prompt_choice("Select the SECOND wordlist (suffix):", find_wordlists(), allow_none=False))

    hash_file = CONFIG_DIR / f"combo_{datetime.now().strftime('%Y%m%d_%H%M%S')}_hash.txt"
    hash_file.write_text(hash_value + "\n")
    session_name = args.session or f"combo_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    run_combinator_attack(hash_file, mode, wordlist1, wordlist2, session_name)


# ─── Auto escalation mode ───────────────────────────────────────────────
# Chains every attack strategy in cheapest-to-most-expensive order,
# stopping the moment one succeeds. Philosophy borrowed from naive-hashcat
# (dictionary -> combinator -> mask, escalating), but built on our own
# existing attack functions rather than hardcoded hashcat calls - this is
# genuinely "run everything reasonable and stop when it works" instead of
# making the user pick a strategy up front.
def cmd_auto(args):
    """Try, in order: priority wordlist -> full wordlist (+rule if given)
    -> each COMMON_MASKS pattern. Stops at the first crack. Reports which
    stage succeeded so you know what actually worked."""
    cfg = load_config()
    hash_value = args.hash or input("Enter the hash to crack: ").strip()

    mode = args.mode
    if mode is None:
        candidates = detect_hash_type(hash_value)
        if len(candidates) == 1:
            mode, name = candidates[0]
            info(f"Detected hash type: {name} (hashcat mode {mode})")
        elif candidates:
            labels = [f"{n} (mode {m})" for m, n in candidates]
            choice = prompt_choice("Select the correct hash type:", labels, allow_none=False)
            mode = candidates[labels.index(choice)][0]
        else:
            mode = input("Enter hashcat mode number manually: ").strip()

    wordlist = args.wordlist or cfg.get("default_wordlist")
    rule = args.rule or cfg.get("default_rule")
    session_base = args.session or f"auto_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    info("=== Stage 1/3: priority wordlist ===")
    hash_file = CONFIG_DIR / f"{session_base}_hash.txt"
    hash_file.write_text(hash_value + "\n")
    priority_path = cfg.get("priority_wordlist")
    if priority_path and Path(priority_path).exists():
        plain = run_hashcat(hash_file, mode, priority_path, None, f"{session_base}_stage1")
        if plain:
            ok(f"Cracked at Stage 1 (priority wordlist): {plain}")
            return
    else:
        warn("No priority wordlist configured, skipping stage 1.")

    if wordlist:
        info("=== Stage 2/3: full wordlist" + (" + rule" if rule else "") + " ===")
        plain = run_hashcat(hash_file, mode, wordlist, rule, f"{session_base}_stage2")
        if plain:
            ok(f"Cracked at Stage 2 (full wordlist): {plain}")
            return
    else:
        warn("No wordlist given/configured, skipping stage 2.")

    info("=== Stage 3/3: common mask patterns ===")
    for i, (name, pattern) in enumerate(COMMON_MASKS.items(), 1):
        info(f"Trying mask: {name} ({pattern})")
        plain = run_mask_attack(hash_file, mode, pattern, f"{session_base}_mask{i}")
        if plain:
            ok(f"Cracked at Stage 3 (mask: {name}): {plain}")
            return

    err("Not cracked by any stage. Consider: a larger wordlist, --hashfile for WPA/KeePass, or a custom --mask.")


# ─── Native multi-hash batch cracking ───────────────────────────────────
# cmd_batch() loops one hash at a time - simple, but wasteful: each hash
# pays its own GPU warm-up, wordlist-load, and rule-compile cost from
# scratch. hashcat natively supports cracking MANY hashes in one pass if
# they're the same type - loads the wordlist/rules ONCE and tests every
# hash against every candidate together. If no --mode is given, hashes
# get auto-detected and grouped by type, one hashcat pass per group.
def _run_multibatch_group(hash_lines, mode, wordlist, rule, session_name, json_results):
    group_file = CONFIG_DIR / f"{session_name}_hashes.txt"
    group_file.write_text("\n".join(hash_lines) + "\n")
    potfile = CONFIG_DIR / f"{session_name}.pot"
    cmd = ["hashcat", "-m", str(mode), "-a", "0", str(group_file), wordlist,
           "--session", session_name, "--potfile-path", str(potfile)]
    if rule:
        cmd += ["-r", rule]
    info(f"Running native multi-hash attack (mode {mode}, {len(hash_lines)} hashes): {' '.join(cmd)}")
    if DRY_RUN:
        info("(dry run - not actually executing)")
        return
    subprocess.run(cmd)

    results = read_all_potfile_results(potfile)
    ok(f"Cracked {len(results)} of {len(hash_lines)} hash(es) in mode {mode}:")
    for h, plain in results:
        print(f"  {h} -> {plain}")
        log_cracked(mode, h, plain)
        json_results[h] = plain
    if not results:
        warn(f"No potfile produced for mode {mode} group - nothing cracked, or hashcat failed to run.")


def cmd_multibatch(args):
    ensure_dirs()
    cfg = load_config()
    if not check_path_exists(args.file, "Hash file"):
        return
    wordlist = args.wordlist or cfg.get("default_wordlist")
    if not wordlist:
        wordlist = str(prompt_choice("Select a wordlist:", find_wordlists(), allow_none=False))
    rule = args.rule or cfg.get("default_rule")

    all_hashes = [h.strip() for h in Path(args.file).read_text().splitlines() if h.strip()]
    json_results = {}

    if args.mode is not None:
        session_name = args.session or f"multibatch_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        _run_multibatch_group(all_hashes, args.mode, wordlist, rule, session_name, json_results)
    else:
        info("No --mode given, auto-detecting and grouping hashes by type...")
        groups = {}
        skipped = []
        for h in all_hashes:
            candidates = detect_hash_type(h)
            if not candidates:
                skipped.append(h)
                continue
            mode = candidates[0][0]
            groups.setdefault(mode, []).append(h)
        if skipped:
            warn(f"{len(skipped)} hash(es) could not be auto-detected and will be skipped.")
        info(f"Found {len(groups)} distinct hash type(s): {list(groups.keys())}")
        for mode, hashes_in_group in groups.items():
            session_name = f"{args.session or 'multibatch'}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_mode{mode}"
            _run_multibatch_group(hashes_in_group, mode, wordlist, rule, session_name, json_results)

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(json_results, indent=2))
        info(f"Results exported to {args.json_out}")


# ─── Cracked-hash history/search ────────────────────────────────────────
def cmd_history(args):
    """Search/display the cracked-hash log. Supports filtering by a
    substring match against hash, plaintext, or mode - useful once
    cracked.log has accumulated hundreds of entries across sessions."""
    ensure_dirs()
    if not CRACKED_LOG.exists() or CRACKED_LOG.stat().st_size == 0:
        print("No cracked hashes logged yet.")
        return

    lines = CRACKED_LOG.read_text().strip().splitlines()
    if args.search:
        lines = [l for l in lines if args.search.lower() in l.lower()]

    if args.limit:
        lines = lines[-args.limit:]

    if not lines:
        print(f"No entries match '{args.search}'.")
        return

    for line in lines:
        parts = line.split(" | ")
        if len(parts) == 4:
            timestamp, mode, hash_val, plain = parts
            print(f"  {C.CYAN}{timestamp}{C.RESET}  mode={mode}  {hash_val[:20]}...  -> {C.GREEN}{C.BOLD}{plain}{C.RESET}")
        else:
            print(f"  {line}")

    print(f"\n{len(lines)} entr{'y' if len(lines) == 1 else 'ies'} shown.")



# ─── Hybrid attacks (-a 6 / -a 7) ────────────────────────────────────────
# Bridges dictionary and mask attacks: append (-a 6) or prepend (-a 7) a
# brute-force mask to every word in a wordlist. Catches patterns like
# "any rockyou word + 3 random digits" WITHOUT needing a pre-built suffix
# wordlist the way combinator does - the mask covers the whole space
# procedurally. Genuinely a third distinct attack surface, not a
# reshuffling of combinator/mask.
def run_hybrid_attack(target_file, mode, wordlist, mask, direction, session_name):
    """direction: 6 = wordlist+mask (append), 7 = mask+wordlist (prepend)"""
    potfile = CONFIG_DIR / f"{session_name}.pot"
    if direction == 6:
        cmd = ["hashcat", "-m", str(mode), "-a", "6", str(target_file), wordlist, mask,
               "--session", session_name, "--potfile-path", str(potfile)]
    else:
        cmd = ["hashcat", "-m", str(mode), "-a", "7", str(target_file), mask, wordlist,
               "--session", session_name, "--potfile-path", str(potfile)]
    info(f"Running hybrid attack (-a {direction}): {' '.join(cmd)}")
    if DRY_RUN:
        info("(dry run - not actually executing)")
        return None
    subprocess.run(cmd)
    h, plain = read_last_potfile_result(potfile)
    if plain:
        ok(f"CRACKED: {plain}")
        log_cracked(mode, h, plain)
        return plain
    return None


def cmd_hybrid(args):
    ensure_dirs()
    cfg = load_config()
    hash_value = args.hash or input("Enter the hash to crack: ").strip()

    mode = args.mode
    if mode is None:
        candidates = detect_hash_type(hash_value)
        if candidates:
            mode = candidates[0][0]
            info(f"Detected hash type: {candidates[0][1]} (hashcat mode {mode})")
        else:
            mode = input("Enter hashcat mode number manually: ").strip()

    wordlist = args.wordlist or cfg.get("default_wordlist")
    if not wordlist:
        wordlist = str(prompt_choice("Select a wordlist:", find_wordlists(), allow_none=False))

    mask = args.mask
    if not mask:
        labels = list(COMMON_MASKS.keys())
        choice = prompt_choice("Select a mask to combine with the wordlist:", labels, allow_none=False)
        mask = COMMON_MASKS[choice]

    direction = 7 if args.prepend else 6

    hash_file = CONFIG_DIR / f"hybrid_{datetime.now().strftime('%Y%m%d_%H%M%S')}_hash.txt"
    hash_file.write_text(hash_value + "\n")
    session_name = args.session or f"hybrid_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    run_hybrid_attack(hash_file, mode, wordlist, mask, direction, session_name)


def main():
    """CLI entry point. Every subcommand mirrors a distinct hashcat attack
    mode or a piece of tool-management functionality - see each cmd_*
    function above for the reasoning behind that specific command."""
    parser = argparse.ArgumentParser(prog="hashwraith", description="A streamlined hashcat wrapper.")
    parser.add_argument("--dry-run", action="store_true", help="Print the hashcat command that would run, without executing it")
    sub = parser.add_subparsers(dest="command", required=True)

    p_crack = sub.add_parser("crack", help="Crack a single hash or hash file")
    p_crack.add_argument("--hash")
    p_crack.add_argument("--hashfile")
    p_crack.add_argument("--mode", type=int)
    p_crack.add_argument("--wordlist")
    p_crack.add_argument("--rule")
    p_crack.add_argument("--session")
    p_crack.add_argument("--no-rule-prompt", action="store_true")
    p_crack.add_argument("--no-priority", action="store_true")
    p_crack.add_argument("--yes", action="store_true", help="Non-interactive: fail loudly instead of prompting if something required is missing")
    p_crack.add_argument("--restore", metavar="SESSION_NAME", help="Resume a previously interrupted session by name")
    p_crack.set_defaults(func=cmd_crack)

    p_batch = sub.add_parser("batch", help="Crack every hash in a file")
    p_batch.add_argument("--file", required=True)
    p_batch.add_argument("--mode", type=int)
    p_batch.add_argument("--wordlist")
    p_batch.add_argument("--rule")
    p_batch.add_argument("--json-out")
    p_batch.add_argument("--yes", action="store_true", help="Non-interactive mode")
    p_batch.set_defaults(func=cmd_batch)

    sub.add_parser("benchmark", help="Run hashcat's benchmark").set_defaults(func=cmd_benchmark)
    sub.add_parser("wordlists", help="List discovered wordlists").set_defaults(func=cmd_list_wordlists)
    sub.add_parser("rules", help="List discovered rule files").set_defaults(func=cmd_list_rules)
    sub.add_parser("gpu", help="Show detected GPU devices").set_defaults(func=cmd_gpu)
    sub.add_parser("formats", help="List all supported hash formats").set_defaults(func=cmd_formats)
    sub.add_parser("sessions", help="List resumable (interrupted) sessions").set_defaults(func=cmd_sessions)

    p_mask = sub.add_parser("mask", help="Crack using a pattern-based mask attack instead of a wordlist")
    p_mask.add_argument("--hash")
    p_mask.add_argument("--mode", type=int)
    p_mask.add_argument("--mask", help="Custom hashcat mask, e.g. ?u?l?l?l?l?l?d?d")
    p_mask.add_argument("--session")
    p_mask.set_defaults(func=cmd_mask)

    sub.add_parser("masks", help="List built-in common mask patterns").set_defaults(func=cmd_masks)

    p_stats = sub.add_parser("stats", help="Analyze a wordlist's length/charset patterns")
    p_stats.add_argument("--wordlist", required=True)
    p_stats.add_argument("--sample", type=int, default=500000, help="Max entries to sample (default 500k)")
    p_stats.set_defaults(func=cmd_stats)

    p_combo = sub.add_parser("combinator", help="Combine two wordlists (-a 1): every word from list1 + every word from list2")
    p_combo.add_argument("--hash")
    p_combo.add_argument("--mode", type=int)
    p_combo.add_argument("--wordlist1", help="Prefix wordlist")
    p_combo.add_argument("--wordlist2", help="Suffix wordlist")
    p_combo.add_argument("--session")
    p_combo.set_defaults(func=cmd_combinator)

    p_history = sub.add_parser("history", help="Search/view the cracked-hash log")
    p_history.add_argument("--search", help="Filter by substring match against hash, mode, or plaintext")
    p_history.add_argument("--limit", type=int, help="Show only the last N entries")
    p_history.set_defaults(func=cmd_history)

    p_multibatch = sub.add_parser("multibatch", help="Crack many hashes of the SAME type in one native hashcat pass (faster than 'batch' for same-type hashes)")
    p_multibatch.add_argument("--file", required=True, help="File with one hash per line, all the same type")
    p_multibatch.add_argument("--mode", type=int, help="hashcat mode - if omitted, hashes are auto-detected and grouped by type")
    p_multibatch.add_argument("--wordlist")
    p_multibatch.add_argument("--rule")
    p_multibatch.add_argument("--session")
    p_multibatch.add_argument("--json-out")
    p_multibatch.set_defaults(func=cmd_multibatch)

    p_hybrid = sub.add_parser("hybrid", help="Combine a wordlist with a mask (-a 6 append / -a 7 prepend)")
    p_hybrid.add_argument("--hash")
    p_hybrid.add_argument("--mode", type=int)
    p_hybrid.add_argument("--wordlist")
    p_hybrid.add_argument("--mask", help="Mask to append (default) or prepend, e.g. ?d?d?d")
    p_hybrid.add_argument("--prepend", action="store_true", help="Prepend the mask instead of appending it (-a 7 instead of -a 6)")
    p_hybrid.add_argument("--session")
    p_hybrid.set_defaults(func=cmd_hybrid)

    p_auto = sub.add_parser("auto", help="Try every attack strategy in escalating order, stop at first success")
    p_auto.add_argument("--hash")
    p_auto.add_argument("--mode", type=int)
    p_auto.add_argument("--wordlist")
    p_auto.add_argument("--rule")
    p_auto.add_argument("--session")
    p_auto.set_defaults(func=cmd_auto)

    p_config = sub.add_parser("config", help="View or set saved defaults")
    p_config.add_argument("action", choices=["show", "set-wordlist", "set-rule", "set-priority", "reset"])
    p_config.add_argument("value", nargs="?", help="Path value for set-* actions")
    p_config.set_defaults(func=cmd_config)

    args = parser.parse_args()
    global DRY_RUN
    DRY_RUN = getattr(args, "dry_run", False)
    args.func(args)


def cli():
    """Entry point wrapper - catches Ctrl+C cleanly instead of dumping a
    raw traceback. A long mask/wordlist attack can run for minutes, and
    interrupting it shouldn't look like the tool crashed."""
    try:
        main()
    except KeyboardInterrupt:
        print()
        warn("Interrupted. If a hashcat session was running, it may be resumable - check 'hashwraith sessions'.")
        sys.exit(130)


if __name__ == "__main__":
    cli()
