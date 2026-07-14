#!/usr/bin/env bash
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib.sh
source "${SCRIPT_DIR}/lib.sh"

# --root isolates installed binaries under CARGO_ROOT/bin, separate from
# cargo/rustc/rustfmt/clippy themselves (which otherwise live in the same
# $CARGO_HOME/bin) — so the Dockerfile can COPY --from just the 3 tool
# binaries out of this stage instead of the whole ~200MB toolchain.
CARGO_ROOT="${CARGO_ROOT:-/opt/rust-tools}"

# --locked: use each crate's checked-in Cargo.lock so the dependency graph
# resolved at release time is reproduced, rather than re-resolving against
# whatever crates.io has today.
run_step "feroxbuster" cargo install feroxbuster --locked --root "$CARGO_ROOT"
run_step "rustscan"    cargo install rustscan --locked --root "$CARGO_ROOT"
# NOTE: `cargo install findomain` (from crates.io) is broken — every
# published version of the findomain crate (up to 2.1.5) has been yanked
# (verified: crates.io API reports max_stable_version=null, and 2.1.5
# itself has "yanked": true). The project moved to github.com/Findomain/Findomain
# and is no longer distributed via crates.io; install from git instead. This
# also needs rustc >= 1.80 (a dependency, rayon-core, requires it) — see the
# rust-tools-builder base image pin in the Dockerfile.
run_step "findomain"   cargo install findomain --locked --root "$CARGO_ROOT" --git "https://github.com/Findomain/Findomain"

print_summary
