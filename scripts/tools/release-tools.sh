#!/usr/bin/env bash
# Installs tools distributed as single-binary GitHub release assets.
# Pin version variables here; changes are deliberate and reviewable.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib.sh
source "${SCRIPT_DIR}/lib.sh"

SUBFINDER_VERSION="2.6.6"
NUCLEI_VERSION="3.2.6"
GOWITNESS_VERSION="3.0.5"
HTTPX_VERSION="1.6.7"
DNSX_VERSION="1.2.1"
NAABU_VERSION="2.3.1"
KATANA_VERSION="1.1.0"
AMASS_VERSION="4.2.0"

# subfinder — tag "v2.6.6", asset subfinder_2.6.6_linux_amd64.zip
run_step "subfinder" install_from_github \
  "projectdiscovery/subfinder" "$SUBFINDER_VERSION" \
  "subfinder_${SUBFINDER_VERSION}_${OS}_${ARCH}.zip" "subfinder" "v"

# nuclei — tag "v3.2.6", asset nuclei_3.2.6_linux_amd64.zip
run_step "nuclei" install_from_github \
  "projectdiscovery/nuclei" "$NUCLEI_VERSION" \
  "nuclei_${NUCLEI_VERSION}_${OS}_${ARCH}.zip" "nuclei" "v"

# httpx — tag "v1.6.7", asset httpx_1.6.7_linux_amd64.zip
run_step "httpx" install_from_github \
  "projectdiscovery/httpx" "$HTTPX_VERSION" \
  "httpx_${HTTPX_VERSION}_${OS}_${ARCH}.zip" "httpx" "v"

# gowitness — tags releases WITHOUT a "v" prefix, ships a bare ELF binary
# (no archive). See the long-form comment in git history for how this was
# confirmed against the actual release assets.
run_step "gowitness" install_from_github \
  "sensepost/gowitness" "$GOWITNESS_VERSION" \
  "gowitness-${GOWITNESS_VERSION}-${OS}-${ARCH}" "gowitness" ""

# dnsx / naabu / katana — same ProjectDiscovery release layout as the three
# tools above: tag "vX.Y.Z", asset "{tool}_X.Y.Z_linux_amd64.zip".
run_step "dnsx" install_from_github \
  "projectdiscovery/dnsx" "$DNSX_VERSION" \
  "dnsx_${DNSX_VERSION}_${OS}_${ARCH}.zip" "dnsx" "v"

run_step "naabu" install_from_github \
  "projectdiscovery/naabu" "$NAABU_VERSION" \
  "naabu_${NAABU_VERSION}_${OS}_${ARCH}.zip" "naabu" "v"

run_step "katana" install_from_github \
  "projectdiscovery/katana" "$KATANA_VERSION" \
  "katana_${KATANA_VERSION}_${OS}_${ARCH}.zip" "katana" "v"

# amass — owasp-amass, tag "vX.Y.Z", asset "amass_linux_amd64.zip" (note:
# no version number embedded in the asset filename itself, unlike PD tools).
run_step "amass" install_from_github \
  "owasp-amass/amass" "$AMASS_VERSION" \
  "amass_${OS}_${ARCH}.zip" "amass" "v"

# gitleaks — moved here from apt-packages.txt: it doesn't exist in ANY
# Ubuntu 22.04 (jammy) apt source, only from 24.04 (noble) onward (see the
# comment in apt-packages.txt for how this was verified). Installed from its
# GitHub release instead, same as every other tool in this file — which is
# what gitleaks' own docs recommend for Linux. Asset naming uses "x64"/
# "arm64", not the "amd64" that $ARCH gives, so it's mapped locally here
# rather than reusing $ARCH directly.
GITLEAKS_VERSION="8.30.1"
GITLEAKS_ARCH="x64"
[[ "$ARCH" == "arm64" ]] && GITLEAKS_ARCH="arm64"
run_step "gitleaks" install_from_github \
  "gitleaks/gitleaks" "$GITLEAKS_VERSION" \
  "gitleaks_${GITLEAKS_VERSION}_${OS}_${GITLEAKS_ARCH}.tar.gz" "gitleaks" "v"

print_summary
