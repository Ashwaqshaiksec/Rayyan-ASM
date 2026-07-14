#!/usr/bin/env bash
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib.sh
source "${SCRIPT_DIR}/lib.sh"

pip_tool() {
  local label="$1" pkg="$2"
  run_step "$label" pip_system_install "$pkg"
}

# theHarvester: NOT `pip_tool "theHarvester" "theHarvester"` — the PyPI
# package literally named "theHarvester" is a stale, abandoned upload from
# ~2020 (reports itself as v0.0.1 / describes itself as "theHarvester 3.0.6"
# in its own README). It ships the tool's Python modules as loose files with
# zero packaging metadata and NO console_scripts entry point — `pip install`
# succeeds and reports nothing wrong, but no `theHarvester` executable is
# ever created, so the tool silently shows as not-installed. Verified
# directly: `pip download theHarvester` and inspecting the wheel confirms
# there is no bin/ entry in RECORD.
#
# The real, maintained project (github.com/laramies/theHarvester, currently
# 4.x) was restructured around a proper pyproject.toml with
# `[project.scripts] theHarvester = "theHarvester.theHarvester:main"`.
# Installing straight from git respects that and pip creates the real
# console script automatically — no manual wrapper needed, unlike the
# git_pip_tool-wrapped tools in git-tools.sh that have no packaging at all.
run_step "theHarvester" pip_system_install "git+https://github.com/laramies/theHarvester.git"

pip_tool "dnstwist"     "dnstwist"
pip_tool "arjun"        "arjun"
pip_tool "droopescan"   "droopescan"
pip_tool "dirsearch"    "dirsearch"
# az: the only one of the 3 cloud CLIs with a real, officially-published
# PyPI package (Microsoft publishes azure-cli to PyPI directly) — aws and
# gcloud don't work this way, see scripts/tools/cloud-tools.sh for those.
pip_tool "az"           "azure-cli"

print_summary
