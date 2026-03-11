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
    && rm -rf /var/lib/apt/lists/*

# ── Install Node.js 20 LTS ──
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# ── Python dependencies (--break-system-packages needed for Ubuntu 24.04 / PEP 668) ──
RUN pip3 install --break-system-packages flask flask-cors

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
EXPOSE 3000 5000

# ── Environment defaults ──
ENV PORT=5000
ENV HOST=0.0.0.0

# ── Entrypoint ──
ENTRYPOINT ["bash", "tools/docker-entrypoint.sh"]

