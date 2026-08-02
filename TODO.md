# TODO

Random list of stuff I want to get to eventually, no particular order.

- [ ] multibatch should auto-group hashes by detected type instead of
      requiring one --mode for the whole file
- [ ] stats command's pattern_names dict is incomplete, only covers the
      common charset combos
- [ ] auto mode's mask stage naming is ugly (session names with spaces
      replaced by underscores, gets truncated weird for long mask names)
- [ ] would be nice to have a --dry-run flag that shows what command
      would run without actually invoking hashcat
- [ ] combinator attack doesn't support rules on top of the combination
      (hashcat supports -j/-k for this, haven't wired it up)
- [ ] no Windows support at all, paths are all Unix-style. probably fine,
      not sure anyone needs this on Windows
