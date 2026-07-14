# Wordlist Sources

These wordlists back `Options.WordlistTier` ("medium" and "large") in the
discovery subdomain brute-force stage. The "small" tier stays the original
hand-curated ~70-word list defined in `engine.go` (`bruteforceWordlist`) and
needs no data file.

- `medium.txt` — 5,000 entries, sourced from SecLists
  `Discovery/DNS/subdomains-top1million-5000.txt`.
- `large.txt` — 110,000 entries, sourced from SecLists
  `Discovery/DNS/subdomains-top1million-110000.txt`.

SecLists (https://github.com/danielmiessler/SecLists) is distributed under
the MIT License. These files are embedded verbatim via `go:embed` in
`wordlists.go`.
