#!/usr/bin/env bash
# Shared helpers, sourced (not executed) by the other scripts/tools/*.sh files.
# Not `set -e`: this file only defines functions, the caller controls strictness.

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported arch: $ARCH" && exit 1 ;;
esac

INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# curl_retry: like `curl -fsSL <url> -o <out>`, but retries with exponential
# backoff before giving up. Added after gowitness's release asset
# intermittently returned a 404 mid-run — the URL itself is correct (same
# URL succeeds seconds later), the cause is GitHub's abuse-rate-limiting
# kicking in when install-tools.sh fires ~30 release downloads back-to-back
# from the same IP with no delay between them. This does NOT rely on curl's
# own --retry flag: --retry only retries curl's own transient/5xx
# classification, not a plain 404, which is exactly the status GitHub's
# rate limiter returns here.
curl_retry() {
  local url="$1" out="$2" attempts="${3:-4}"
  local delay=2 i
  for ((i = 1; i <= attempts; i++)); do
    if curl -fsSL "$url" -o "$out"; then
      return 0
    fi
    if [[ $i -lt $attempts ]]; then
      echo "  ... download failed (attempt ${i}/${attempts}), retrying in ${delay}s"
      sleep "$delay"
      delay=$((delay * 3))
    fi
  done
  echo "  ... download failed after ${attempts} attempts: ${url}"
  return 1
}

# git_clone_retry: same rationale as curl_retry, for the git-cloned Python
# tools in git-tools.sh — a transient DNS blip or GitHub hiccup on tool #4
# of 18 shouldn't be indistinguishable from that repo genuinely being gone.
git_clone_retry() {
  local repo_url="$1" dest="$2" attempts="${3:-3}"
  local delay=2 i
  for ((i = 1; i <= attempts; i++)); do
    if git clone --depth 1 "$repo_url" "$dest" >/dev/null 2>&1; then
      return 0
    fi
    rm -rf "$dest"
    if [[ $i -lt $attempts ]]; then
      echo "  ... git clone failed (attempt ${i}/${attempts}), retrying in ${delay}s"
      sleep "$delay"
      delay=$((delay * 3))
    fi
  done
  echo "  ... git clone failed after ${attempts} attempts: ${repo_url}"
  return 1
}

# Tracks pass/fail across an entire run so a single 404 or missing package
# doesn't take down the other tools in the same script (the old script used
# `set -euo pipefail` with no per-tool isolation, which meant tool #5 failing
# silently skipped tools #6-66 in an install-tools run). run_step captures
# that instead: each tool gets its own subshell, failures are recorded and
# reported at the end, and the script's own exit code reflects whether
# anything failed.
declare -a STEP_OK=()
declare -a STEP_FAIL=()

run_step() {
  local label="$1"; shift
  echo ">>> ${label}"
  # NOT `if ( ...; "$@" ); then` — bash disables the effect of `set -e`
  # for any command that is itself the condition of an if/while/until (or
  # connected by && / ||), even a subshell that sets -e internally. Tested
  # against a deliberately-broken tool install: with the `if (...)` form
  # this silently reported "OK" after a failed curl *and* a failed mv, with
  # the function still limping to its final echo. Running the subshell as
  # a plain statement first and testing $? afterward avoids that trap.
  ( set -eo pipefail; "$@" )
  local status=$?
  if [[ $status -eq 0 ]]; then
    STEP_OK+=("$label")
  else
    echo "!!! FAILED: ${label}"
    STEP_FAIL+=("$label")
  fi
}

print_summary() {
  echo ""
  echo "=== $(basename "$0") summary: ${#STEP_OK[@]} ok, ${#STEP_FAIL[@]} failed ==="
  for s in "${STEP_OK[@]}"; do echo "  OK    ${s}"; done
  for s in "${STEP_FAIL[@]}"; do echo "  FAIL  ${s}"; done
  [[ ${#STEP_FAIL[@]} -eq 0 ]]
}

# install_from_github: download a single-binary GitHub release asset and
# install it to $INSTALL_DIR. Unchanged from the original install-tools.sh —
# see its inline comments for why tag_prefix and is-it-an-archive both vary
# per project (ProjectDiscovery tags "vX.Y.Z" + ships .zip; gowitness tags
# "X.Y.Z" + ships a bare binary; etc).
# pip_system_install: installs a package into the system Python, tolerating
# PEP 668's "externally-managed-environment" guard. That guard doesn't
# exist on the pip shipped with Ubuntu 22.04 (the runtime stage's base
# image, and what this was built and tested against), but pinning the base
# image doesn't pin it forever — if it's ever bumped to a newer Ubuntu, pip
# there would refuse a plain `pip install` outright. This is the container's
# own throwaway Python (nothing else depends on its system site-packages),
# so --break-system-packages is the correct override here, not a workaround
# being papered over.
pip_system_install() {
  if pip3 install --no-cache-dir --disable-pip-version-check "$@" 2>/tmp/pip_err.$$; then
    rm -f /tmp/pip_err.$$
    return 0
  fi
  if grep -qi "externally-managed-environment" /tmp/pip_err.$$; then
    rm -f /tmp/pip_err.$$
    pip3 install --no-cache-dir --disable-pip-version-check --break-system-packages "$@"
    return $?
  fi
  cat /tmp/pip_err.$$ >&2
  rm -f /tmp/pip_err.$$
  return 1
}

install_from_github() {
  local repo="$1" version="$2" asset="$3" binary="$4" tag_prefix="${5:-v}"
  local url="https://github.com/${repo}/releases/download/${tag_prefix}${version}/${asset}"
  echo "Installing ${binary} ${tag_prefix}${version} from ${url}"
  local tmp
  tmp="$(mktemp -d)"
  curl_retry "$url" "${tmp}/${asset}"
  if curl -fsSL "${url}.sha256" -o "${tmp}/${asset}.sha256" 2>/dev/null; then
    echo "Verifying checksum..."
    (cd "$tmp" && sha256sum -c "${asset}.sha256")
  fi
  if [[ "$asset" == *.tar.gz || "$asset" == *.tgz || "$asset" == *.zip ]]; then
    tar -xzf "${tmp}/${asset}" -C "$tmp" 2>/dev/null || unzip -o "${tmp}/${asset}" -d "$tmp" 2>/dev/null || true
  fi
  local bin_path
  bin_path="$(find "$tmp" -name "$binary" -type f | head -1)"
  if [[ -z "$bin_path" ]]; then
    bin_path="${tmp}/${asset}"
  fi
  chmod +x "$bin_path"
  mv -f "$bin_path" "${INSTALL_DIR}/${binary}"
  rm -rf "$tmp"
  echo "Installed ${binary} -> ${INSTALL_DIR}/${binary}"
}

# git_pip_tool: clone a single-file/simple-repo Python tool that has no
# packaging (no setup.py/pyproject.toml, no PyPI listing), install its
# Python deps into an isolated --target dir (so they don't need to survive
# a multi-stage COPY of site-packages, which /opt/asm-tools alone does not
# capture), and drop a thin exec wrapper on $INSTALL_DIR so the tool is
# invocable by the bare name the tool registry expects (e.g. "linkfinder"
# rather than "python3 /opt/asm-tools/src/linkfinder/linkfinder.py").
#
# repo:      owner/name
# entry:     path to the .py entrypoint, relative to the repo root
# binary:    name to expose on $INSTALL_DIR
# extra_pip: space-separated extra pip packages beyond requirements.txt
#            (some of these repos have no requirements.txt at all)
git_pip_tool() {
  local repo="$1" entry="$2" binary="$3" extra_pip="${4:-}"
  local src="${SRC_DIR:-/opt/asm-tools/src}/${binary}"
  local libs="${LIB_DIR:-/opt/asm-tools/pylibs}/${binary}"
  rm -rf "$src"
  git_clone_retry "https://github.com/${repo}.git" "$src"
  mkdir -p "$libs"
  if [[ -f "${src}/requirements.txt" ]]; then
    pip3 install --no-cache-dir --disable-pip-version-check --target "$libs" -r "${src}/requirements.txt"
  fi
  if [[ -n "$extra_pip" ]]; then
    # shellcheck disable=SC2086
    pip3 install --no-cache-dir --disable-pip-version-check --target "$libs" $extra_pip
  fi
  cat > "${INSTALL_DIR}/${binary}" <<EOF
#!/usr/bin/env bash
# Generated by scripts/tools/git-tools.sh — thin wrapper around a git-cloned
# Python tool with no native packaging. Do not hand-edit; re-run the
# installer to regenerate.
exec env PYTHONPATH="${libs}\${PYTHONPATH:+:\$PYTHONPATH}" python3 "${src}/${entry}" "\$@"
EOF
  chmod +x "${INSTALL_DIR}/${binary}"
  echo "Installed ${binary} -> ${INSTALL_DIR}/${binary} (wrapper around ${src}/${entry})"
}

# git_pip2_tool: identical to git_pip_tool above, except it targets the
# python2 interpreter/pip2 bootstrapped by the tool-installer stage's
# Dockerfile RUN block. Exists only for tplmap — the single registry tool
# that's genuinely python2-only (see git-tools.sh) — everything else in the
# registry runs on python3 via git_pip_tool. Kept as a separate function
# rather than a python2/3 flag on git_pip_tool so the common case can't
# accidentally be pointed at the wrong interpreter by a typo'd argument.
git_pip2_tool() {
  local repo="$1" entry="$2" binary="$3" extra_pip="${4:-}"
  local src="${SRC_DIR:-/opt/asm-tools/src}/${binary}"
  local libs="${LIB_DIR:-/opt/asm-tools/pylibs}/${binary}"
  rm -rf "$src"
  git_clone_retry "https://github.com/${repo}.git" "$src"
  mkdir -p "$libs"
  if [[ -f "${src}/requirements.txt" ]]; then
    pip2 install --no-cache-dir --target "$libs" -r "${src}/requirements.txt"
  fi
  if [[ -n "$extra_pip" ]]; then
    # shellcheck disable=SC2086
    pip2 install --no-cache-dir --target "$libs" $extra_pip
  fi
  cat > "${INSTALL_DIR}/${binary}" <<EOF
#!/usr/bin/env bash
# Generated by scripts/tools/git-tools.sh — thin wrapper around a
# python2-only tool with no native packaging. Do not hand-edit; re-run
# the installer to regenerate.
exec env PYTHONPATH="${libs}\${PYTHONPATH:+:\$PYTHONPATH}" python2 "${src}/${entry}" "\$@"
EOF
  chmod +x "${INSTALL_DIR}/${binary}"
  echo "Installed ${binary} -> ${INSTALL_DIR}/${binary} (wrapper around ${src}/${entry}, python2)"
}
