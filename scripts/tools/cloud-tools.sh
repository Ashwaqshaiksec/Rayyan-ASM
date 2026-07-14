#!/usr/bin/env bash
# aws (AWS CLI v2) and gcloud (Google Cloud CLI). Both are real installers,
# not simple binary downloads — install_from_github/pip don't fit either.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib.sh
source "${SCRIPT_DIR}/lib.sh"

install_aws_cli() {
  local tmp; tmp="$(mktemp -d)"
  local zip_arch="x86_64"
  [[ "$ARCH" == "arm64" ]] && zip_arch="aarch64"
  curl_retry "https://awscli.amazonaws.com/awscli-exe-linux-${zip_arch}.zip" "${tmp}/awscliv2.zip"
  unzip -q "${tmp}/awscliv2.zip" -d "$tmp"
  # --update: safe to pass even on a first install, and makes re-runs of
  # this script idempotent instead of erroring "already installed".
  "${tmp}/aws/install" --install-dir /opt/asm-tools/aws-cli --bin-dir "$INSTALL_DIR" --update
  rm -rf "$tmp"
}

install_gcloud_cli() {
  local tmp; tmp="$(mktemp -d)"
  local gcloud_arch="x86_64"
  [[ "$ARCH" == "arm64" ]] && gcloud_arch="arm"
  curl_retry "https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-linux-${gcloud_arch}.tar.gz" \
    "${tmp}/gcloud.tar.gz"
  tar -xzf "${tmp}/gcloud.tar.gz" -C /opt/asm-tools
  # --path-update=false, --usage-reporting=false, --command-completion=false:
  # this installer normally offers to edit the invoking user's shell rc
  # files and phone home usage stats — none of which makes sense
  # non-interactively inside a Docker build.
  /opt/asm-tools/google-cloud-sdk/install.sh \
    --quiet --path-update=false --usage-reporting=false --command-completion=false
  ln -sf /opt/asm-tools/google-cloud-sdk/bin/gcloud "${INSTALL_DIR}/gcloud"
  rm -rf "$tmp"
}

run_step "aws"    install_aws_cli
run_step "gcloud" install_gcloud_cli

print_summary
