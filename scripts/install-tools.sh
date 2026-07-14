#!/usr/bin/env bash
# Installs the tools that only need curl/unzip/git/python3+pip3 — everything
# the tool-installer Docker stage has available. See scripts/tools/ for the
# category-specific scripts and scripts/tools/apt-packages.txt +
# Dockerfile's go-tools-builder/rust-tools-builder/npm/gem stages for the
# rest of the 66-tool registry.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="${SCRIPT_DIR}/tools"

overall_status=0

echo "###### release-tools.sh ######"
bash "${TOOLS_DIR}/release-tools.sh" || overall_status=1

echo ""
echo "###### git-tools.sh ######"
bash "${TOOLS_DIR}/git-tools.sh" || overall_status=1

echo ""
echo "###### cloud-tools.sh ######"
bash "${TOOLS_DIR}/cloud-tools.sh" || overall_status=1

exit "$overall_status"
