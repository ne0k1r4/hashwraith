# hashwraith

A hashcat wrapper that streamlines hash cracking workflows — auto hash-type
detection, wordlist/rule discovery, multiple attack modes, session
management, and batch cracking.

Every command shells out to real hashcat underneath — this tool adds an
intelligence layer on top (auto-detection, discovery, sane defaults), it
never limits what hashcat itself can do.

## Features

- **Auto hash-type detection** — 16+ formats via regex (MD5, SHA1/256/512,
  bcrypt, sha512crypt/sha256crypt/md5crypt, Django PBKDF2, WordPress/phpBB,
  MySQL old/new, Kerberos TGS-REP/AS-REP, KeePass, NTLM)
- **Multiple attack modes**:
  - Dictionary + rules (`-a 0`), with a fast priority-list pass tried first
  - Mask attacks (`-a 3`) — pattern-based brute force for passwords that
    won't appear in any wordlist but follow a predictable human structure
  - Combinator attacks (`-a 1`) — combine two wordlists for compound
    patterns (e.g. names + suffixes)
- **File-based formats** — WPA/WPA2 handshakes and KeePass databases via
  `--hashfile`, after extraction with `hcxpcapngtool` / `keepass2john`
- **Auto-discovery** — finds your GPU/backend, wordlists, and hashcat rule
  files automatically, no hardcoded paths
- **Wordlist statistics** — samples a wordlist's length/charset patterns
  (inspired by PACK's statsgen) to help pick the right mask
- **Session management** — resume interrupted long-running cracks
- **Config persistence** — save default wordlist/rule/priority-list so you
  aren't prompted every run
- **Batch mode** — crack every hash in a file in one pass, export results
  as JSON
- **Scriptable** — `--yes` skips all prompts and fails loudly instead of
  hanging, for use in scripts/CI
- **Cracked-hash log** — every successful crack logged with timestamp to
  `~/.hashwraith/cracked.log`

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

# combinator attack (two wordlists combined)
hashwraith combinator --hash <hash> --wordlist1 names.txt --wordlist2 suffixes.txt

# batch mode
hashwraith batch --file hashes.txt --wordlist rockyou.txt --json-out results.json

# file-based formats (WPA, KeePass)
hcxpcapngtool -o capture.hc22000 capture.pcapng
hashwraith crack --hashfile capture.hc22000 --mode 22000 --wordlist rockyou.txt

# resume an interrupted session
hashwraith sessions                 # list resumable sessions
hashwraith crack --restore <session_name>

# analyze a wordlist's patterns
hashwraith stats --wordlist rockyou.txt

# save defaults so you're not prompted every time
hashwraith config set-wordlist ~/wordlists/rockyou.txt
hashwraith config show

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

19 unit tests covering hash detection, config persistence, mask validity,
and path checking — all pure logic, no hashcat/GPU required to run them.

## Requirements

- `hashcat` (with a working OpenCL/CUDA/HIP backend)
- Python 3.8+
- For file-based formats: `hcxpcapngtool` (WPA) or `keepass2john` (KeePass)
  to do the extraction step first

## License

MIT — see [LICENSE](LICENSE)
