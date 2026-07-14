#!/usr/bin/env bash
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib.sh
source "${SCRIPT_DIR}/lib.sh"

run_step "sublist3r" git_pip_tool "aboul3la/Sublist3r" "sublist3r.py" "sublist3r"

# subbrute: last commit is python2-era. Cloned and wrapped like the others,
# but note this one is likely to fail at runtime under python3 unless
# someone ports it — that's an upstream problem, not an install problem, so
# it's still worth installing rather than silently dropping it from the
# 66. Flagging honestly rather than pretending it's fine.
run_step "subbrute" git_pip_tool "TheRook/subbrute" "subbrute.py" "subbrute"

# SubDomainizer: Enabled:false in the tool registry, but still installed —
# "disabled" in the registry means "off by default in scans", not "should
# not exist on disk".
run_step "SubDomainizer" git_pip_tool "nsonaniya2010/SubDomainizer" "SubDomainizer.py" "SubDomainizer" "requests bs4 PyYAML"

run_step "linkfinder" git_pip_tool "GerbenJavado/LinkFinder" "linkfinder.py" "linkfinder" "jsbeautifier"
run_step "secretfinder" git_pip_tool "m4ll0k/SecretFinder" "SecretFinder.py" "secretfinder" "jsbeautifier"
# NOTE: originally pointed at Tuhinshubhra/CloudFlair, which 404s — that
# repo doesn't exist under this owner. The real, maintained CloudFlair is
# christophetd/CloudFlair (verified: clones, entry is still cloudflair.py at
# repo root, requirements.txt already pins censys==2.2.0). CloudFlair also
# needs a Censys API ID/secret at runtime (free-tier Censys API access was
# discontinued in late 2024) — the binary installs and runs fine without
# one, it just can't find origin IPs until CENSYS_API_ID/CENSYS_API_SECRET
# are set.
run_step "cloudflair" git_pip_tool "christophetd/CloudFlair" "cloudflair.py" "cloudflair" "requests censys"
# NOTE: originally pointed at m4ll0k/Cloakquest3r, which also 404s — wrong
# owner. The real, maintained CloakQuest3r is spyboy-productions/CloakQuest3r
# (verified: clones, entry is still cloakquest3r.py at repo root,
# requirements.txt already pins requests/colorama/bs4/cryptography).
run_step "cloakquest3r" git_pip_tool "spyboy-productions/CloakQuest3r" "cloakquest3r.py" "cloakquest3r" "requests colorama"
run_step "ssrfmap" git_pip_tool "swisskyrepo/SSRFmap" "ssrfmap.py" "ssrfmap"
run_step "gopherus" git_pip_tool "tarunkant/Gopherus" "gopherus.py" "gopherus"
run_step "smuggler" git_pip_tool "defparam/smuggler" "smuggler.py" "smuggler"
run_step "h2csmuggler" git_pip_tool "assetnote/h2csmuggler" "h2csmuggler.py" "h2csmuggler" "h2 hyperframe"
run_step "jwt_tool" git_pip_tool "ticarpi/jwt_tool" "jwt_tool.py" "jwt_tool"
run_step "corsy" git_pip_tool "s0md3v/Corsy" "corsy.py" "corsy"
run_step "enum4linux-ng" git_pip_tool "cddmp/enum4linux-ng" "enum4linux-ng.py" "enum4linux-ng"
run_step "xsstrike" git_pip_tool "s0md3v/XSStrike" "xsstrike.py" "xsstrike"
run_step "commix" git_pip_tool "commixproject/commix" "commix.py" "commix"

# tplmap: strictly python2, unmaintained since ~2019, but Enabled: true in
# the registry — meaning the UI already advertises it as usable, so a
# stubbed-out skip here was a real gap, not a documented tradeoff. Ubuntu
# 22.04's universe repo still carries python2 (2.7.18), and the Dockerfile
# bootstraps pip2 for it, so this installs the same way every other
# git-cloned python tool does, just via git_pip2_tool instead of
# git_pip_tool. requirements.txt is pinned old-style (PyYAML 5.1.2,
# requests 2.22.0, etc.) but those exact versions are still on PyPI, so
# nothing here needs re-pinning to install cleanly.
run_step "tplmap" git_pip2_tool "epinna/tplmap" "tplmap.py" "tplmap"

# paramspider was rewritten from a single script into a packaged CLI
# (pyproject.toml). The exact post-rewrite entrypoint path wasn't verified
# against a live checkout at script-authoring time — if this 404s or the
# wrapper can't find the entry file after cloning, install with
# `pip3 install "git+https://github.com/devanshbatham/ParamSpider.git"`
# instead, which resolves the entrypoint from its packaging metadata rather
# than a hardcoded path.
run_step "paramspider" git_pip_tool "devanshbatham/ParamSpider" "paramspider/main.py" "paramspider" "requests"

# crackmapexec: Enabled:false, and deliberately not installed at all — the
# project is unmaintained and its PyPI/git installs have been broken for a
# while post-fork. Its maintained successor is NetExec (Pennyw0rth/NetExec,
# `pip install netexec`), but that's a different binary name than what's in
# the registry, so swapping it in silently would be misleading. Left as a
# registry entry that's honestly absent rather than quietly renamed.
echo ">>> crackmapexec — skipped deliberately (disabled + unmaintained; see comment in script)"

# snyk: Enabled:false, and deliberately not installed. Unlike every other
# tool here, snyk is non-functional without a Snyk account + `snyk auth` —
# there's no offline/API-key-only mode for the free CLI, so installing the
# binary here wouldn't actually make the tool usable. `npm install -g snyk`
# if/when that account exists.
echo ">>> snyk — skipped deliberately (requires a Snyk account; binary alone isn't usable — see comment in script)"

print_summary
