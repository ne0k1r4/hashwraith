# hashwraith

A hashcat wrapper that streamlines hash cracking workflows.

## Features

- Auto-detects hash type from format (MD5, SHA1/256/512, bcrypt, sha512crypt, NTLM, more)
- Auto-discovers your GPU/backend, wordlists, and hashcat rule files — no hardcoded paths
- Interactive prompts when flags are omitted, full flag control when scripting
- Batch mode — crack a whole file of hashes in one pass, export results as JSON
- Logs every successful crack with timestamp to `~/.hashwraith/cracked.log`

## Usage

```bash
hashwraith crack
hashwraith crack --hash <hash> --mode 0 --wordlist rockyou.txt
hashwraith batch --file hashes.txt --wordlist rockyou.txt --json-out results.json
hashwraith wordlists
hashwraith rules
hashwraith gpu
```

## Requirements

- `hashcat` (with a working OpenCL/CUDA backend)
- Python 3.8+

## License

MIT — see [LICENSE](LICENSE)
