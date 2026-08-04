# TODO

Random list of stuff I want to get to eventually, no particular order.

- [ ] live progress display - hashcat supports --status-json, would be nice
      to parse that into a clean single-line progress bar instead of
      dumping hashcat's raw verbose output. Bigger change than it sounds -
      every run_* function currently uses subprocess.run() (blocking, waits
      for exit), would need to switch to Popen with real-time stdout
      reading. Worth doing eventually, not a quick patch.
- [ ] rules-report only reports the ONE rule that cracked a hash (since
      hashcat's debug-mode only logs matches, not every rule tried) -
      would be nice to also report ruleset coverage stats across a whole
      wordlist run (which rules fired zero times across many hashes, e.g.
      via multibatch), not just a single-hash lookup
- [ ] no Windows support at all, paths are all Unix-style. probably fine,
      not sure anyone needs this on Windows
- [ ] auto mode doesn't try hybrid or combinator attacks, only priority
      list -> full wordlist -> masks. could add a 4th stage but combinator
      needs two wordlists picked up front which doesn't fit the
      no-prompts escalation flow well - needs some thought

## Done (keeping for history / so I remember what shipped when)

- [x] multibatch auto-groups hashes by detected type when --mode is omitted
- [x] --dry-run flag prints the hashcat command without executing it
- [x] combinator attack supports per-side rules via -j/-k
- [x] hybrid attack mode (-a 6/-a 7)
- [x] wordlist merge/dedupe command
- [x] rules-report command (single-hash rule identification)
- [x] show command (check cracked-hash history without re-running hashcat)
