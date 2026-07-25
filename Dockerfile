# =============================================================================
#  GUI-AX Framework — All-in-One Docker Image
#  Includes: Ax recon framework + Dashboard (Flask bridge + Vite UI)
#  Based on the official Ax Docker install method (Ubuntu + git clone)
# =============================================================================

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV SHELL=/bin/zsh

# ── System dependencies (matches Ax Docker install + dashboard needs) ──
RUN apt-get clean && rm -rf /var/lib/apt/lists/* \
    && apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    wget \
    jq \
    tmux \
    zsh \
    python3 \
    python3-pip \
    python3-venv \
    openssh-client \
    ca-certificates \
    gnupg \
    sudo \
    lsb-release \
    unzip \
    bc \
    bsdmainutils \
    rsync \
    && rm -rf /var/lib/apt/lists/*
# bc + bsdmainutils(column): required by Ax's includes/functions.sh for the
# fleet listing's cost math ($/M column) and table formatting — without them
# `axiom-ls`/`ax ls` spam "bc: command not found" / "column: command not found".
# rsync: REQUIRED by axiom-scp (interact/axiom-scp) for ALL file transfers to/from
# fleet instances. Without it every scan's input/command upload fails silently
# ("rsync: command not found"), the remote `bash -i command` then errors with
# "command: No such file or directory", the module never runs, and the scan hangs
# until timeout producing zero output — the #1 cause of "scans return nothing".

# ── Install Node.js 20 LTS ──
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# ── Python dependencies (--break-system-packages needed for Ubuntu 24.04 / PEP 668) ──
#    geoip2 powers the optional offline IP-geolocation source for the Geo Map.
#    It's inert until a GeoLite2-City.mmdb is present (mount into /app/data or
#    set GEOIP_DB_PATH) — WHOIS geo works without it.
#    mcp provides the Model Context Protocol server (tools/mcp-server.py); httpx
#    is its HTTP client. Both are optional — the dashboard runs without them.
RUN pip3 install --break-system-packages flask flask-cors geoip2 mcp httpx

# ── Install Interlace (REQUIRED by axiom-scan) ──
#    axiom-scan (interact/axiom-scan line ~977) hard-requires the standalone
#    `interlace` binary to fan a module across the fleet: `command -v interlace`.
#    It is NOT part of the ax git clone — without it EVERY scan prints
#    "Error: Interlace is not installed.", exits 0, and produces zero output
#    (so the dashboard/workflow just sees a scan that "returned nothing").
RUN pip3 install --break-system-packages 'git+https://github.com/codingo/Interlace.git' \
    && command -v interlace

# ── Install AWS CLI v2 natively for the image's architecture ──
#    Ax would otherwise install its hardcoded x86_64 build at runtime
#    (see interact/account-helpers/aws.sh). Two things wedged it before:
#      1. QEMU x86_64 emulation on an arm64 host — every network call
#         (describe-regions, describe-instances, ...) busy-loops at ~100% CPU.
#      2. AWS CLI's "latest" (2.36.x) bundles Python 3.14, which busy-loops on
#         --version even natively on this Docker Desktop linuxkit kernel.
#    So we pin AWSCLI_VERSION to 2.17.45 (Python 3.11.9 — Ax's own recommended
#    version) and install the NATIVE build for the image arch. Being >= Ax's
#    recommended AWSCliVersion, Ax's version check skips its own install rather
#    than clobbering this with the x86_64 build. Bump only after verifying the
#    target version's bundled Python runs cleanly here (test: `aws --version`
#    must return in <2s, not spin at 100% CPU).
ARG AWSCLI_VERSION=2.17.45
RUN ARCH="$(uname -m)" \
    && if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then AWS_ARCH=aarch64; else AWS_ARCH=x86_64; fi \
    && echo "Installing AWS CLI v2 ${AWSCLI_VERSION} for $ARCH ($AWS_ARCH)" \
    && curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-${AWS_ARCH}-${AWSCLI_VERSION}.zip" -o /tmp/awscliv2.zip \
    && cd /tmp && unzip -q awscliv2.zip && ./aws/install \
    && rm -rf /tmp/aws /tmp/awscliv2.zip \
    && aws --version

# ── Clone Ax framework ──
RUN git clone https://github.com/attacksurge/ax/ /root/.axiom/

# ── Add Ax to PATH ──
ENV PATH="/root/.axiom/interact:${PATH}"

# ── Dashboard setup ──
WORKDIR /app

# Install Node.js dependencies first (layer caching)
COPY package.json package-lock.json* ./
RUN npm install

# Copy the rest of the application
COPY . .

# Create data / import directories & make scripts executable
RUN mkdir -p data imports/processed \
    && chmod +x tools/*.sh

# ── Expose ports ──
#    3000 = Vite UI
#    5000 = Flask bridge API
#    8787 = MCP server (optional; started on demand from Settings → MCP Server)
EXPOSE 3000 5000 8787

# ── Environment defaults ──
ENV PORT=5000
ENV HOST=0.0.0.0

# ── Entrypoint ──
ENTRYPOINT ["bash", "tools/docker-entrypoint.sh"]

