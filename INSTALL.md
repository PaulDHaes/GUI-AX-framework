# GUI-AX Installation Guide

Two paths: **Development** (local, hot-reload) and **Production** (AWS/server, nginx).

---

## Development

Designed for active development on your local machine. Source files are bind-mounted into the container so Vite picks up changes without rebuilding the image.

### Prerequisites

- Docker Desktop (Mac/Windows) or Docker Engine + Docker Compose (Linux)
- An AWS account configured for the Ax fleet

### Steps

```bash
# 1. Clone the repo
git clone <repo-url>
cd GUI-AX-framework

# 2. Copy and fill in secrets
cp .env.example .env
# Edit .env — set GUI_AX_PASSWORD, API keys, etc.

# 3. Build and start
docker compose up -d --build

# 4. Configure Ax (first run only)
docker exec -it gui-ax-dashboard zsh
# Follow the axiom-configure --run prompt

# 5. Open the dashboard
open http://localhost:3000
```

### Useful commands

```bash
# View live logs (Vite + bridge)
docker exec -it gui-ax-dashboard tmux attach -t dashboard

# Restart after code changes (if HMR doesn't pick up)
docker restart gui-ax-dashboard

# Stop
docker compose down
```

### Ports (dev)

| Port | Service |
|------|---------|
| 3000 | Vite dev server (UI) |
| 5000 | Flask bridge API |
| 8787 | MCP server (optional) |

---

## Production (AWS)

The production image bakes the frontend into a static build served by nginx. No Vite, no Node process for the UI. Lighter resource usage, suitable for shared team access.

### Recommended EC2 instance

| Load | Instance | Cost |
|------|----------|------|
| ≤ 10 users, no local scanning | **t3a.small** | ~$15/month |
| 10+ users | t3a.medium | ~$30/month |

Scanning runs on the **fleet**, not on this machine.

### EC2 security group

| Port | Source | Reason |
|------|--------|--------|
| 22 | Your IP | SSH |
| 80 | Team IPs | Dashboard UI |
| 5000 | Team IPs | Bridge API (direct downloads/uploads) |

Do **not** open port 80 or 5000 to `0.0.0.0/0`.

### Steps

```bash
# 1. SSH into the EC2 instance
ssh -i your-key.pem ubuntu@<ec2-ip>

# 2. Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker ubuntu
newgrp docker

# 3. Clone the repo
git clone <repo-url>
cd GUI-AX-framework

# 4. Copy and fill in secrets
cp .env.example .env
# Edit .env — set GUI_AX_PASSWORD, strong GUI_AX_SECRET_KEY, API keys, etc.

# 5. Build and start (production image)
docker compose -f docker-compose.prod.yml up -d --build
# First build takes 10-20 min (installs Ax, Metasploit, compiles frontend)

# 6. Configure Ax (first run only)
docker exec -it gui-ax-prod zsh
# Follow the axiom-configure --run prompt

# 7. Open the dashboard
# http://<ec2-ip>   (port 80, served by nginx)
```

### Useful commands

```bash
# View bridge logs
docker exec -it gui-ax-prod tmux attach -t dashboard

# Rebuild after updating code
git pull
docker compose -f docker-compose.prod.yml up -d --build

# Stop
docker compose -f docker-compose.prod.yml down
```

### Ports (prod)

| Port | Service |
|------|---------|
| 80 | nginx — serves frontend + proxies /api/ to bridge |
| 5000 | Flask bridge API (direct, for file downloads) |
| 8787 | MCP server (optional) |

### How the prod routing works

```
Browser → port 80 (nginx)
  /          → serves /app/dist/index.html  (React SPA)
  /api/*     → proxies to 127.0.0.1:5000   (Flask bridge)
  /assets/*  → serves /app/dist/assets/    (JS/CSS, cached 1yr)

Browser → port 5000 (Flask, direct)
  Used for large file downloads (raw-zip, gowitness bundles)
  and scan imports. Restrict to team IPs in security group.
```

### Updating in production

```bash
git pull
docker compose -f docker-compose.prod.yml up -d --build
```

The image rebuild runs `npm run build` fresh. Data in `/app/data` is preserved via the named volume `gui-ax-prod-data`.

---

## Environment variables

Copy `.env.example` to `.env` and set these before starting:

| Variable | Required | Description |
|----------|----------|-------------|
| `GUI_AX_PASSWORD` | Recommended | Login password. Leave empty to run open. |
| `GUI_AX_USERNAME` | No | Login username (default: `admin`) |
| `GUI_AX_SECRET_KEY` | Recommended in prod | Stable Flask session key — generate with `python3 -c "import secrets; print(secrets.token_hex(32))"` |
| `GUI_AX_STATIC_TOKEN` | No | Static bearer token so browser sessions survive bridge restarts |
| `ANTHROPIC_API_KEY` | No | Claude AI analysis |
| `OLLAMA_URL` | No | Local LLM (default: `http://host.docker.internal:11434`) |
| `AXIOM_EXCLUDED_REGIONS` | No | Space-separated AWS regions to skip |
