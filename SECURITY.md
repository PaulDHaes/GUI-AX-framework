# Security Policy

## Supported versions

Only the latest release on `main` receives security fixes.

| Version         | Supported |
| --------------- | --------- |
| `main` (latest) | ✅        |
| older commits   | ❌        |

---

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, report them privately:

1. Go to the [Security tab](https://github.com/PaulDHaes/GUI-AX-framework/security/advisories/new) of this repository and open a **private security advisory**.  
   — _or_ —
2. Email the maintainer directly. You can find contact info in the GitHub profile.

Please include:

- A description of the vulnerability and its potential impact
- Steps to reproduce (proof-of-concept code or payload if applicable)
- Any suggested fix or mitigation

We will acknowledge your report within **72 hours** and aim to release a fix within **14 days** for confirmed critical issues.

---

## Scope

This project is a **local-first dashboard** that is intended to run on your own machine and communicate with your own Ax fleet. The attack surface is limited to:

- The Flask bridge API (`axiom-bridge.py`) — runs on localhost by default
- The Vite development server — runs on localhost by default
- Subprocess calls to `axiom-scan`, `axiom-ls`, and other Ax tools

**Out of scope:**

- Vulnerabilities in Ax itself — please report those to [attacksurge/ax](https://github.com/attacksurge/ax)
- Vulnerabilities in cloud providers you have configured with Ax
- Social engineering attacks

---

## Security best practices for users

- **Never expose the bridge port (default 5000) to the internet.** The API has no authentication and is designed for localhost-only use.
- Use a firewall rule or VPN if you need remote access.
- Keep your `.env` file out of version control (it is `.gitignore`d by default).
- Rotate your `GEMINI_API_KEY` if it is accidentally exposed.
