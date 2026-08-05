# Changelog

## 0.2.0

Major feature expansion since initial release.

### Added
- Mask attacks (`-a 3`) with 8 built-in common patterns
- Combinator attacks (`-a 1`), with optional per-side rules (`-j`/`-k`)
- Hybrid attacks (`-a 6`/`-a 7`) — wordlist + brute-force mask suffix/prefix
- Auto escalation mode — chains priority list → full wordlist → masks,
  stopping at first crack
- Native multi-hash batching, with auto-grouping by detected type
- Wordlist statistics analyzer (length/charset distribution)
- Wordlist merge/dedupe command (memory-capped `sort -u`)
- Rules-report command — identifies which specific rule cracked a hash
  via hashcat's `--debug-mode`
- `show` command — check cracked-hash history without re-running hashcat
- Session resume support (`--restore`)
- Config persistence (`config` command) for default wordlist/rule/priority
- `--dry-run` flag — preview a command without executing it
- `--yes` flag — full non-interactive/scriptable mode
- Colorized terminal output
- Expanded hash-type detection to 16+ formats (Django, WordPress, MySQL,
  Kerberos, KeePass, and more)
- File-based format support (`--hashfile`) for WPA/WPA2 and KeePass
- Unit test suite (pure logic, no hashcat/GPU required)
- GitHub Actions CI running tests across Python 3.10–3.12
- pip packaging (`pyproject.toml`, installable via `pip install -e .`)
- Type hints throughout the codebase
- Consolidated potfile-parsing logic into shared helpers
- Graceful Ctrl+C handling (no more raw tracebacks on interrupt)
- Consistent "hashcat not found" handling across every command, not just GPU detection

### Fixed
- Priority-wordlist fast-path ordering (previously alphabetical sort could
  take 10+ minutes to reach a common password that a frequency-ranked
  list finds in under a second)
- Multibatch auto-grouping (an earlier patch silently failed to apply,
  caught by the test suite)
- Rules-report's potfile parsing (initial assumption about hashcat's
  debug-file format was wrong; corrected after testing against real output)

## 0.1.0

Initial release — hash auto-detection, dictionary attack with rule support,
GPU/wordlist/rule discovery, batch mode, basic CLI.
