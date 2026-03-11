# Contributing to GUI-AX

Thanks for your interest in contributing! Here's how to get started.

## Development Setup

1. **Clone the repo**

   ```bash
   git clone https://github.com/PaulDHaes/GUI-AX-framework ~/gui-ax-framework
   cd ~/gui-ax-framework
   ```

2. **Install dependencies**

   ```bash
   npm install
   pip3 install flask flask-cors
   ```

3. **Copy the environment config**

   ```bash
   cp .env.example .env
   ```

4. **Start the dev servers**
   ```bash
   bash tools/start-dev.sh
   ```
   This starts both the Flask bridge (port 5000) and Vite UI (port 3000).

## Branch Naming

Use descriptive branch names prefixed by type:

| Prefix      | Purpose                                        |
| ----------- | ---------------------------------------------- |
| `feat/`     | New feature (e.g. `feat/scan-templates`)       |
| `fix/`      | Bug fix (e.g. `fix/fleet-refresh-loop`)        |
| `docs/`     | Documentation only (e.g. `docs/api-reference`) |
| `refactor/` | Code cleanup, no behaviour change              |
| `chore/`    | Tooling, CI, deps (e.g. `chore/update-vite`)   |

## Pull Request Process

1. **Create a branch** off `main` using the naming convention above.
2. **Make your changes** — keep PRs focused on a single concern.
3. **Test locally** — make sure the dashboard loads, scans launch, and the bridge responds.
4. **Open a PR** with a clear title and description of what changed and why.
5. **Link any related issues** in the PR body.

## Code Style

- **TypeScript/React**: Follow the existing patterns in the codebase. Use functional components with hooks.
- **Python (bridge)**: Keep it readable. Use `snake_case` for functions and variables.
- **Commits**: Use clear, concise commit messages. One logical change per commit.

## Reporting Bugs

Open a GitHub issue with:

- Steps to reproduce
- Expected vs actual behaviour
- Browser and OS info
- Bridge logs if relevant (check the terminal running `axiom-bridge.py`)

## Security

If you find a security vulnerability, please follow the process in [SECURITY.md](SECURITY.md) instead of opening a public issue.
