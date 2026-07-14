# Stage 1: Go builder
# IMPORTANT: must be a glibc-based image, not Alpine/musl, because the
# runtime image (ubuntu:22.04) is glibc-based. Using golang:1.22.4-alpine
# here was the actual cause of "exec ./server: no such file or directory" —
# the binary was dynamically linked against /lib/ld-musl-x86_64.so.1, which
# does not exist on Ubuntu.
#
# We pin to the "bullseye" (Debian 11) variant rather than the default
# "bookworm" (Debian 12) tag. golang:1.22.4 defaults to bookworm, which
# ships glibc 2.36 — newer than Ubuntu 22.04's glibc 2.35. A binary linked
# against a newer glibc than the runtime provides fails to start
# ("version `GLIBC_2.36' not found"), even though it's not musl. bullseye
# ships glibc 2.31, which is older than and fully compatible with Ubuntu
# 22.04's 2.35 (glibc is backward compatible: older-linked binaries run
# fine on newer glibc, not vice versa).
FROM golang:1.22.4-bullseye AS go-builder

WORKDIR /app

# gcc + libc6-dev required for CGO (gorm's sqlite driver / mattn/go-sqlite3
# uses cgo bindings — CGO_ENABLED=1 is required even though production runs
# against Postgres, because internal/database imports the sqlite driver
# unconditionally and it is compiled into the binary).
RUN apt-get update && apt-get install -y --no-install-recommends \
    git gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

ENV GOPRIVATE=github.com/ShadooowX/*
ENV GONOSUMDB=github.com/ShadooowX/*
ENV GONOSUMCHECK=github.com/ShadooowX/*
# GOPROXY=direct: this environment's network resets connections to
# proxy.golang.org (confirmed directly — a `go mod download` here failed
# with "read tcp ...: connection reset by peer" against proxy.golang.org
# before this was added). `direct` fetches every module straight from its
# VCS host (github.com, etc.) instead of through Google's proxy, which
# this network does allow. GOSUMDB=off is paired with it: proxy.golang.org
# and sum.golang.org are different hosts, but the same class of network
# restriction that resets one often resets the other, and GOPROXY=direct
# alone does not skip checksum-database verification — only GOSUMDB does.
# go.sum still pins every dependency's hash locally either way, so this
# does not weaken reproducibility, only where the *first* download of an
# unpinned hash is checked against.
ENV GOPROXY=direct
ENV GOSUMDB=off
# -mod=readonly (the default whenever go.sum exists) rather than -mod=mod:
# -mod=mod lets `go build`/`go mod tidy` silently rewrite go.mod/go.sum
# against whatever the module proxy serves at build time, which is exactly
# what breaks reproducibility (requirement #9). readonly makes the build
# fail loudly if go.mod/go.sum and the source tree ever disagree, instead
# of quietly drifting.
ENV GOFLAGS=-mod=readonly

# go.mod's local `replace` directives point at ./stubs, so stubs must be
# present before `go mod download` resolves them.
COPY go.mod go.sum ./
COPY stubs ./stubs
RUN go mod download

COPY . .
# `go mod tidy` was removed here. Running it inside the build is a
# reproducibility bug in itself: it can add/remove/upgrade dependencies
# based on whatever the module proxy has *right now*, so the same commit can
# produce a different binary on different days — and it partly defeats the
# `go mod download` step above, which exists precisely so dependency
# resolution isn't repeated at build time. go.mod/go.sum are already tidy in
# the repo; run `go mod tidy` locally and commit the result if dependencies
# ever change, not as a build step.
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w" -o /app/server ./cmd/server

FROM ubuntu:22.04 AS tool-installer

ENV DEBIAN_FRONTEND=noninteractive
# python2 (2.7.18, from Ubuntu 22.04's universe repo — not dropped from
# jammy the way it was from 24.04+) is only here for tplmap, the one
# registry tool that's genuinely python2-only. It ships with no pip, and
# jammy's universe repo has no python2-pip binary package either (only an
# unbuilt source package) — get-pip.py's pinned 2.7 branch is the
# documented, still-maintained way pypa itself provides pip on old
# interpreters, not a workaround.
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash curl wget git python3 python3-pip python2 \
    ca-certificates gnupg unzip \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL https://bootstrap.pypa.io/pip/2.7/get-pip.py -o /tmp/get-pip2.py \
    && python2 /tmp/get-pip2.py \
    && rm -f /tmp/get-pip2.py

WORKDIR /install
COPY scripts/install-tools.sh .
COPY scripts/tools ./tools
# INSTALL_DIR must point at /opt/asm-tools/bin, not the script's default of
# /usr/local/bin. The runtime stage below only COPYs --from=tool-installer
# /opt/asm-tools, so without this the recon tools were built successfully
# but landed in a directory nothing ever copies out of the tool-installer
# layer, and the runtime image's /opt/asm-tools/bin ended up empty.
RUN mkdir -p /opt/asm-tools/bin
ENV INSTALL_DIR=/opt/asm-tools/bin
# install-tools.sh handles the tools this stage's toolchain can reach
# (GitHub-release zips + git-cloned Python scripts). It reports a non-fatal
# per-tool summary and exits non-zero if anything failed, but the build
# continues either way — `|| true` here is deliberate, not accidental: a
# single upstream 404 in 66 tools shouldn't fail the whole image build. The
# printed summary in the build log is how failures actually get noticed.
RUN chmod +x install-tools.sh && ./install-tools.sh || true

# Go-source tools with no prebuilt release binaries — needs a real Go
# toolchain + module proxy access, which the ubuntu-based tool-installer
# stage above doesn't have.
#
# Pinned to 1.25, NOT 1.22.4 (which the rest of this Dockerfile uses to
# match go.mod's `go 1.22`/`toolchain go1.22.12`): that match only matters
# for building the app itself. This stage's only job is `go install`-ing
# six independent, unrelated tools into /root/go/bin, which get COPY'd as
# static binaries into the final image — they never touch the app's own
# module graph or toolchain, so there is no reason to hold this stage back
# to 1.22.4, and real reason not to. Verified directly (GOPROXY=direct,
# bypassing the module proxy to fetch straight from GitHub) that with Go
# 1.22.4 every one of dalfox, gobuster, subjack, subzy, trufflehog, and
# aquatone fails outright with "requires go >= 1.25.x" (aquatone itself
# predates Go modules and has no go.mod, but its resolved transitive
# dependencies — e.g. github.com/parnurzeal/gorequest — now require 1.25.5
# # too). This is why all six showed as "Missing" despite this script
# correctly listing them: not a script bug, a stage-toolchain bug. 1.25
# clears the highest observed requirement (1.25.5) with margin.
#
# NOTE: golang:1.25-bullseye does not exist as a published Docker tag —
# verified directly (docker build failed with "not found" against it).
# Docker's official golang image stopped publishing -bullseye variants for
# Go releases this new; -bookworm is 1.25's current Debian base. Safe to
# differ from the -bullseye pin used elsewhere in this file: bullseye and
# bookworm are both glibc, and every tool this stage builds is pure Go
# with no cgo, so `go install` produces a statically linked binary with no
# runtime dependency on the builder image's libc or Debian version at all
# — it's just a static executable COPY'd into the ubuntu:22.04 runtime
# # stage below. go-builder (the app's own build, a few lines up) keeps its
# original -bullseye pin unchanged.
#
# Pinned to the exact patch (1.25.12), not floating 1.25-bookworm, for the
# same reproducibility reasoning already applied to rust-tools-builder's
# 1.83 pin elsewhere in this file. Confirmed against docker-library/golang's
# own versions.json (the source of truth for what's actually published)
# that 1.25's available variants are trixie/bookworm/alpine — no bullseye.
FROM golang:1.25.12-bookworm AS go-tools-builder
WORKDIR /install
# Same network constraint as go-builder above — see its GOPROXY comment.
# (This stage's own comment above already described testing with
# GOPROXY=direct; that was verified ad hoc but never actually set here —
# fixing that now.)
ENV GOPROXY=direct
ENV GOSUMDB=off
COPY scripts/tools/lib.sh scripts/tools/go-tools.sh ./
RUN chmod +x go-tools.sh && ./go-tools.sh || true

# Rust-source recon tools. bullseye (glibc), matching the rest of the build
# for the same reason as go-tools-builder above.
#
# Pinned to 1.83, not 1.75: verified in a real build that 1.75 cannot
# install ANY of the three tools below, not just findomain —
#   - feroxbuster 2.13.1 / rustscan 2.4.1: both ship a Cargo.lock in
#     "version 4" format, which requires cargo >= 1.78 to parse at all
#     ("lock file version 4 requires `-Znext-lockfile-bump`" on 1.75).
#   - findomain (installed from git, see rust-tools.sh): a transitive dep
#     (icu_properties_data) requires rustc >= 1.82.
# 1.83-bullseye clears both with margin and is a published tag (glibc,
# matching the rest of this build).
FROM rust:1.83-bullseye AS rust-tools-builder
WORKDIR /install
COPY scripts/tools/lib.sh scripts/tools/rust-tools.sh ./
RUN chmod +x rust-tools.sh && ./rust-tools.sh || true

FROM node:20-alpine AS frontend-builder

WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci

COPY frontend/ .
RUN npm run build

# Stage: dev — used ONLY by docker-compose.dev.yml for local development
# with hot reload. Never used in production; not part of the `runtime` image.
# docker-compose.dev.yml bind-mounts the repo over /app at container
# start, so this stage only needs the toolchain + a warm module cache, not a
# COPY of the source itself.
#
# Pinned to 1.24-bullseye (not 1.22.4 like go-builder/runtime above): air
# v1.61.1 needs go >= 1.23, and pinned dlv v1.24.2 (below) needs go >= 1.24.
# This only affects the dev toolchain used to build the air/dlv binaries;
# it does not change the go.mod `go 1.22` directive or the production build
# stages, and a 1.24 toolchain builds go-1.22 modules fine (Go toolchains
# are backward compatible with older go.mod versions).
FROM golang:1.24-bullseye AS dev

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    git gcc libc6-dev curl unzip \
    && rm -rf /var/lib/apt/lists/*

# Same network constraint as go-builder above — see its GOPROXY comment.
ENV GOPROXY=direct
ENV GOSUMDB=off

# air: rebuilds and restarts the server on file change.
# dlv: debugger, listens on :2345 (see docker-compose.dev.yml).
#
# dlv is pinned to v1.24.2, not @latest. @latest is a moving target — it
# broke this build once already (v1.27.0 required a newer Go than air
# v1.61.1 did), and delve additionally refuses to run against a Go version
# it considers "too new" (see dlv's own --check-go-version), so a floating
# tag can break in either direction as the toolchain or delve moves. v1.24.2
# is the same reproducibility rationale already applied to go.mod/go.sum
# above, just for the dev-image tool versions.
RUN go install github.com/air-verse/air@v1.61.1 \
    && go install github.com/go-delve/delve/cmd/dlv@v1.24.2

ENV GOFLAGS=-mod=readonly
COPY go.mod go.sum ./
COPY stubs ./stubs
RUN go mod download

EXPOSE 8080 2345

ENTRYPOINT ["air", "-c", ".air.toml"]

FROM ubuntu:22.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /app

# PATH below puts /opt/asm-tools/bin first. install-tools.sh's default
# INSTALL_DIR (see lib.sh) is /usr/local/bin, which only applies inside the
# tool-installer *build* stage because that stage sets INSTALL_DIR itself —
# ENV does not carry across a multi-stage FROM. Without this, the live
# "Install Tools" button (which re-runs install-tools.sh inside this
# already-running image, see ToolHandler.Install) would write updated
# binaries to /usr/local/bin, where they'd be silently shadowed by the
# older build-time copies already sitting in /opt/asm-tools/bin earlier in
# PATH — re-running the installer to pick up a tool update would appear to
# succeed but have no actual effect.
ENV INSTALL_DIR=/opt/asm-tools/bin

# apt-packages.txt is the registry's apt-installable tool list (masscan,
# nikto, dnsenum, dnsrecon, whatweb, sqlmap, wafw00f, testssl.sh — gitleaks
# was removed from this list and is now installed via release-tools.sh
# instead, see that file's comment for why. nmap/smbclient are listed
# separately below since they were already here before this list existed. `xargs` rather than `$(cat ...)` so comment
# lines in the file don't get passed to apt-get as package names.
COPY scripts/tools/apt-packages.txt /tmp/apt-packages.txt
# git + unzip: the runtime image is also what /api/v1/tools/install runs
# scripts/install-tools.sh inside of live (see internal/api/handlers/tools.go)
# — release-tools.sh unzips GitHub release assets and git-tools.sh git-clones
# 18 tools (sublist3r, linkfinder, tplmap, ...). Without these two packages
# here, the *build-time* install baked into the image via the
# tool-installer/go-tools-builder/rust-tools-builder COPYs below would work,
# but clicking "Install Tools" again from the running app would fail on every
# git-based tool with "git: command not found" — the button would look like
# it's reinstalling but silently do nothing for a third of the registry.
#
# python2: tplmap's install-tools.sh wrapper (see git-tools.sh) execs
# `python2` directly. That binary gets baked into /opt/asm-tools/bin at
# build time regardless (via the tool-installer stage COPY below), but
# without python2 present *in this runtime image too*, running tplmap in
# production would fail with "python2: not found" even though the tool
# "installed" successfully — the interpreter and the wrapper that calls it
# have to live in the same image, not just the tool-installer build stage.
# whois: used directly by ToolboxHandler.Whois (internal/api/handlers/toolbox.go),
# which shells out to the system `whois` binary via exec.CommandContext. It was
# never in this list — not part of the 66-tool registry install-tools.sh covers,
# just a bare apt package the handler assumes is present. Without it, the WHOIS
# lookup in the UI fails with "executable file not found in $PATH".
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash ca-certificates nmap python3 python3-pip python2 curl gnupg git unzip \
    smbclient wkhtmltopdf whois \
    && grep -v '^#' /tmp/apt-packages.txt | xargs apt-get install -y --no-install-recommends \
    && rm -f /tmp/apt-packages.txt && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL https://bootstrap.pypa.io/pip/2.7/get-pip.py -o /tmp/get-pip2.py \
    && python2 /tmp/get-pip2.py \
    && rm -f /tmp/get-pip2.py

# The Debian/Ubuntu testssl.sh apt package (verified directly against the
# jammy universe pool: testssl.sh_3.0.7+dfsg-1_all.deb) installs its
# executable as /usr/bin/testssl — without the .sh suffix the package is
# named after. The tool registry (registry.go) and every toolrunner call
# site (workflows.go, workflow_dispatcher.go, vulns_waf_smb_origin.go — 8
# references total) expect the binary on PATH to be literally "testssl.sh".
# A symlink is a smaller, safer fix than renaming the tool everywhere it's
# referenced in Go: apt already installed the real, working binary, it's
# just under a name nothing in this codebase looks for.
RUN ln -sf /usr/bin/testssl /usr/local/bin/testssl.sh

# Pure-PyPI tools (theHarvester, dnstwist, arjun, droopescan) — plain pip
# install straight into this stage, no wrapper/target-dir dance needed
# since, unlike tool-installer, this *is* the final image.
COPY scripts/tools/lib.sh scripts/tools/pip-tools.sh /tmp/pip-install/
RUN bash /tmp/pip-install/pip-tools.sh || true \
    && rm -rf /tmp/pip-install

# Node (for retire, wappalyzer) and Ruby (for wpscan) — installed directly
# in this stage rather than a separate builder image + COPY, deliberately:
# node:20-alpine / ruby:*-slim base images are musl-linked, and this
# codebase already hit the musl-vs-glibc "exec: no such file or directory"
# failure once (see go-builder's comment above) when a binary built in one
# libc landed in a glibc runtime. Installing in-place avoids repeating that
# mistake for native npm/gem addons.
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs ruby-full build-essential \
    && rm -rf /var/lib/apt/lists/*
# wappalyzer's CLI pulls in a headless-Chromium dependency at install time —
# this is the one tool in the registry where the "official" implementation
# is genuinely heavy for what it does.
#
# UPDATE: the official `wappalyzer` npm package is now deprecated — its own
# package description says so directly ("This package is no longer being
# maintained. Please use the API at wappalyzer.com/api instead"), and it has
# no `bin` entry at all, so `npm install -g wappalyzer` was never producing
# a working CLI regardless of the Chromium weight. `wappalyzer-cli` (the
# name the tool registry's own description references) also has no `bin`
# entry — same dead end. Verified directly against the npm registry for
# both, not assumed.
#
# wappalyzer-puppeteer is the best available substitute: it actually ships
# a working CLI (`bin: { 'wappalyzer-puppeteer': './cli.js' }`), but it's a
# single-maintainer project last published 2022 — genuinely less robust
# than the other tools in this registry. Documenting that tradeoff here
# rather than silently swapping it in: if this breaks or a better
# alternative appears, this is why it's here.
#
# wpscan's yajl-ruby dependency ships a native C extension, so this needs
# build-essential (make/gcc) present above — without it, gem install fails
# with "make failed: No such file or directory" even though ruby-full is
# installed, since ruby-full doesn't pull in a toolchain.
# npm install -g wappalyzer-puppeteer is wrapped in a retry loop: it pulls
# down Puppeteer's bundled Chromium from Google's CDN, by far the single
# largest download in this Dockerfile, and the one most exposed to a flaky
# connection timing out mid-transfer (seen directly: ETIMEDOUT against
# googleapis.com IPs after ~170s). `apt-get install chromium` is not a safe
# substitute on Ubuntu 22.04: that package is a transitional snap redirect
# in this release, which has no snapd to resolve to inside a container.
RUN for i in 1 2 3; do \
      npm install -g retire wappalyzer-puppeteer && break; \
      echo "wappalyzer-puppeteer install failed (attempt $i/3), retrying..."; \
      [ "$i" -lt 3 ] && sleep 5; \
    done \
    && ln -sf "$(npm root -g)/wappalyzer-puppeteer/cli.js" /usr/local/bin/wappalyzer \
    && chmod +x /usr/local/bin/wappalyzer \
    && gem install wpscan --no-document \
    && apt-get purge -y build-essential && apt-get autoremove -y

# Copy compiled Go binary
COPY --from=go-builder /app/server .

# tool-installer's own install-tools.sh never uses `go install` or `cargo
# install` — no Go/Rust toolchain exists in the ubuntu:22.04 tool-installer
# stage, only curl/unzip/git/python3. Those tool families are built in the
# separate go-tools-builder/rust-tools-builder stages below and merged into
# the same /opt/asm-tools/bin directory via the two COPYs that follow this
# one.
COPY --from=tool-installer /opt/asm-tools /opt/asm-tools
# go install (GOBIN=/root/go/bin, see go-tools.sh) and cargo install
# (--root /opt/rust-tools, see rust-tools.sh) tools, merged into the same
# /opt/asm-tools/bin the rest of the tools live in.
COPY --from=go-tools-builder /root/go/bin/. /opt/asm-tools/bin/
COPY --from=rust-tools-builder /opt/rust-tools/bin/. /opt/asm-tools/bin/

# Copy static frontend build
COPY --from=frontend-builder /app/dist/frontend ./frontend/dist

# Copy migrations and scripts
COPY --from=go-builder /app/internal/database/migrations ./internal/database/migrations
COPY --from=go-builder /app/scripts ./scripts

ENV PATH="/opt/asm-tools/bin:/usr/local/bin:${PATH}"

EXPOSE 8080

# start-period matches docker-compose.yml's app healthcheck override — see
# that file's comment: a cold-start (fresh Postgres volume) 42-model
# AutoMigrate was observed taking ~44s on its own, so a short start-period
# marks the container unhealthy before the server ever opens its port.
HEALTHCHECK --interval=10s --timeout=5s --start-period=90s --retries=3 \
  CMD curl -sf http://localhost:8080/health || exit 1

ENTRYPOINT ["./server"]
