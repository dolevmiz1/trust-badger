# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Trust Badger, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, email: dolevmiz2@gmail.com

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You will receive a response within 48 hours. We will work with you to understand and address the issue before any public disclosure.

## Supported Versions

| Version | Supported |
|---------|-----------|
| v7.x    | Yes       |
| < v7    | No        |

## Security Model

Trust Badger provides defense-in-depth for AI agents in CI/CD:

1. **Input scanning** detects prompt injection patterns in PR/issue text
2. **Trust level detection** assigns permissions based on who triggered the workflow
3. **MCP proxy** intercepts all tool calls and enforces policy
4. **Network isolation** (Linux) blocks exfiltration via network namespace
5. **Filesystem protection** (Linux + bubblewrap) makes protected paths read-only

See [docs/DESIGN.md](docs/DESIGN.md) for the full architecture.

## Known Limitations

See the Known Limitations section in [README.md](README.md).
