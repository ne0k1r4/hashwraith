# hashwraith

A hashcat wrapper that streamlines hash cracking workflows — auto hash-type
detection, wordlist/rule discovery, six distinct attack modes, session
management, and batch cracking.

Every command shells out to real hashcat underneath — this tool adds an
intelligence layer on top (auto-detection, discovery, sane defaults), it
never limits what hashcat itself can do.

## Features

- **Auto hash-type detection** — 16+ formats via regex (MD5, SHA1/256/512,
  bcrypt, sha512crypt/sha256crypt/md5crypt, Django PBKDF2, WordPress/phpBB,
  MySQL old/new, Kerberos TGS-REP/AS-REP, KeePass, NTLM)
- **Six attack modes**:
  - Dictionary + rules (`-a 0`), with a fast priority-list pass tried first
  - Mask attacks (`-a 3`) — pattern-based brute force for passwords that
    won't appear in any wordlist but follow a predictable human structure
  - Combinator attacks (`-a 1`) — combine two wordlists for compound
    patterns (e.g. names + suffixes), with optional per-side rules (`-j`/`-k`)
  - Hybrid attacks (`-a 6`/`-a 7`) — append or prepend a brute-force mask
    to every wordlist entry (e.g. "any word + 3 random digits")
  - Auto escalation — tries priority list, then full wordlist, then every
    built-in mask pattern in order, stopping at the first crack
  - Native multi-hash batching — crack many hashes in one hashcat pass;
    auto-groups by detected type if `--mode` is omitted
- **File-based formats** — WPA/WPA2 handshakes and KeePass databases via
  `--hashfile`, after extraction with `hcxpcapngtool` / `keepass2john`
- **Auto-discovery** — finds your GPU/backend, wordlists, and hashcat rule
  files automatically, no hardcoded paths
- **Wordlist statistics** — samples a wordlist's length/charset patterns
  (inspired by PACK's statsgen) to help pick the right mask
- **Wordlist merge/dedupe** — combine multiple wordlists into one
  deduplicated file via a memory-capped `sort -u`, safe on constrained RAM
- **Rule effectiveness report** — identifies exactly which hashcat rule
  cracked a given hash, via `--debug-mode`
- **Session management** — resume interrupted long-running cracks
- **Config persistence** — save default wordlist/rule/priority-list so you
  aren't prompted every run
- **Batch mode** — crack every hash in a file in one pass, export results
  as JSON
- **Scriptable** — `--yes` skips all prompts and fails loudly instead of
  hanging; `--dry-run` prints the hashcat command without executing it
- **Cracked-hash log** — every successful crack logged with timestamp to
  `~/.hashwraith/cracked.log`, searchable via `history`, or check a single
  hash instantly via `show` without re-running hashcat at all
- **Graceful interrupts** — Ctrl+C prints a clean message instead of a
  raw traceback, and points you at `sessions` to resume if applicable

## Install

```bash
git clone <this-repo-url>
cd hashwraith
pip install -e . --break-system-packages
```

Requires `hashcat` with a working OpenCL/CUDA/HIP backend, and Python 3.8+.

## Usage

```bash
# single hash, fully interactive
hashwraith crack

# single hash, flags only (non-interactive)
hashwraith crack --hash <hash> --mode 0 --wordlist rockyou.txt --yes

# mask attack (pattern-based brute force)
hashwraith mask --hash <hash>
hashwraith masks                    # list built-in patterns

# combinator attack (two wordlists combined), optionally with per-side rules
hashwraith combinator --hash <hash> --wordlist1 names.txt --wordlist2 suffixes.txt
hashwraith combinator --hash <hash> --wordlist1 names.txt --wordlist2 suffixes.txt --rule1 c

# hybrid attack (wordlist + brute-force mask suffix/prefix)
hashwraith hybrid --hash <hash> --wordlist rockyou.txt --mask ?d?d?d
hashwraith hybrid --hash <hash> --wordlist rockyou.txt --mask ?d?d?d --prepend

# batch mode (one hash at a time, mixed types OK)
hashwraith batch --file hashes.txt --wordlist rockyou.txt --json-out results.json

# native multi-hash batch (faster; auto-groups by type if --mode omitted)
hashwraith multibatch --file hashes.txt --wordlist rockyou.txt

# file-based formats (WPA, KeePass)
hcxpcapngtool -o capture.hc22000 capture.pcapng
hashwraith crack --hashfile capture.hc22000 --mode 22000 --wordlist rockyou.txt

# resume an interrupted session
hashwraith sessions                 # list resumable sessions
hashwraith crack --restore <session_name>

# let the tool try everything and stop at the first crack
hashwraith auto --hash <hash>

# search the cracked-hash log, or check one hash instantly
hashwraith history
hashwraith history --search summer --limit 10
hashwraith show --hash <hash>

# analyze a wordlist's patterns
hashwraith stats --wordlist rockyou.txt

# merge/dedupe multiple wordlists (memory-capped, safe on constrained RAM)
hashwraith merge list1.txt list2.txt --output merged.txt --memory 1G

# find out which specific rule cracked a hash
hashwraith rules-report --hash <hash> --wordlist rockyou.txt --rule best66.rule

# save defaults so you're not prompted every time
hashwraith config set-wordlist ~/wordlists/rockyou.txt
hashwraith config show

# preview a command without running it
hashwraith --dry-run crack --hash <hash> --wordlist rockyou.txt

# discovery
hashwraith wordlists
hashwraith rules
hashwraith gpu
hashwraith formats
hashwraith benchmark
```

## Testing

```bash
python3 -m unittest discover tests/ -v
```

Unit tests cover hash detection, config persistence, mask validity, path
checking, CLI argument validation, and history-filtering logic — all pure
logic, no hashcat/GPU required to run them. CI runs this suite automatically
on every push/PR across Python 3.10–3.12 (see `.github/workflows/tests.yml`).

## Requirements

- `hashcat` (with a working OpenCL/CUDA/HIP backend)
- Python 3.8+
- For file-based formats: `hcxpcapngtool` (WPA) or `keepass2john` (KeePass)
  to do the extraction step first

## License

MIT — see [LICENSE](LICENSE)
