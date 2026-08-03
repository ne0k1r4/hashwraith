# TODO

Random list of stuff I want to get to eventually, no particular order.

- [ ] multibatch should auto-group hashes by detected type instead of
      requiring one --mode for the whole file
- [ ] would be nice to have a --dry-run flag that shows what command
      would run without actually invoking hashcat
- [ ] combinator attack doesn't support rules on top of the combination
      (hashcat supports -j/-k for this, haven't wired it up)
- [ ] no Windows support at all, paths are all Unix-style. probably fine,
      not sure anyone needs this on Windows
