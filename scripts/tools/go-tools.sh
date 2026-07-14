#!/usr/bin/env bash
# `go install` for tools that don't ship prebuilt release binaries. Unlike
# release-tools.sh, these are NOT pinned to a specific reproducible tag
# except where noted — several of these projects don't cut regular tagged
# releases, so pinning to a real tag isn't always possible. That's a real
# reproducibility gap versus the rest of this install pipeline; if a build
# ever needs to be pinned exactly, replace @latest below with a specific
# commit SHA (`go install pkg@<sha>` works) and record it here.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib.sh
source "${SCRIPT_DIR}/lib.sh"

GOBIN="${GOBIN:-/root/go/bin}"
export GOBIN

go_tool() {
  local label="$1" pkg="$2"
  run_step "$label" go install "$pkg"
}

go_tool "assetfinder"     "github.com/tomnomnom/assetfinder@latest"
go_tool "waybackurls"     "github.com/tomnomnom/waybackurls@latest"
go_tool "gau"             "github.com/lc/gau/v2/cmd/gau@latest"
go_tool "dalfox"          "github.com/hahwul/dalfox/v2@latest"
go_tool "crlfuzz"         "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
# subzy: the tool registry's original author (lobuhi/subzy) is unmaintained;
# the actively maintained fork/successor lives at PentestPad/subzy and is
# what upstream docs now point installers at.
go_tool "subzy"           "github.com/PentestPad/subzy@latest"
go_tool "ffuf"             "github.com/ffuf/ffuf/v2@latest"
go_tool "gobuster"        "github.com/OJ/gobuster/v3@latest"
go_tool "hakrawler"       "github.com/hakluke/hakrawler@latest"
go_tool "hakoriginfinder" "github.com/hakluke/hakoriginfinder@latest"
go_tool "subjack"         "github.com/haccer/subjack@latest"
go_tool "trufflehog"      "github.com/trufflesecurity/trufflehog/v3@latest"
go_tool "aquatone"        "github.com/michenriksen/aquatone@latest"

print_summary
