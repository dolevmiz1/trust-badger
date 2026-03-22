# Trust Badger

![CI](https://github.com/dolevmiz1/trust-badger/actions/workflows/ci.yml/badge.svg)

![Trust Badger](docs/diagrams/og-image.png)

> Your CI/CD pipeline trusts AI agents. Trust Badger makes sure that trust isn't misplaced.

Context-aware runtime enforcement for AI agents in CI/CD. Detects who triggered the workflow, assigns a trust level, and enforces tool policies through an MCP proxy with kernel-level sandboxing. Fork PRs get read-only tools. Contributors get an allow list with no network. Admins get full access.

## The Problem

![The Problem: No Boundary](docs/diagrams/01_problem.png)

AI coding agents run inside CI/CD with shell access, git credentials, and secret tokens. A fork PR from a stranger gives the agent the exact same permissions as an admin's PR. Every major attack in Q1 2026 (Hackerbot Claw, PromptPwnd, Clinejection, RoguePilot) exploited this gap.

## How It Works

![Trust Badger: How It Works](docs/diagrams/02_solution.png)

1. **Reads GitHub context** (who triggered, fork vs org, actor role via API)
2. **Assigns a trust level** (untrusted, contributor, or trusted)
3. **Starts an MCP proxy** that the agent uses for all tool calls
4. **Enforces policies per tool call** with kernel-level sandboxing on Linux

The agent thinks it has full access. The proxy decides what actually gets through.

## Trust Levels

![Trust Levels and Policies](docs/diagrams/03_trust_levels.png)

| Level | Who | What the agent can do |
|-------|-----|----------------------|
| **Untrusted** | Fork PRs, first-time contributors, triage permission | Read, search, browse only. No Bash, no file writes. |
| **Contributor** | Read/write collaborators, bots | Allowed commands only (npm test, node, python, etc). No network access. Protected paths (.github/workflows/, CLAUDE.md, .cursorrules) are read-only. |
| **Trusted** | Repo admins only | Everything. No restrictions. |

## Quick Start

```yaml
steps:
  - uses: dolevmiz1/trust-badger@v7
    id: badger
    with:
      mode: audit

  - uses: anthropics/claude-code-action@v1
    with:
      anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
      claude_args: >
        --mcp-config '${{ steps.badger.outputs.mcp-config }}'
        --allowedTools 'mcp__trust-badger__*'
        --disallowedTools '${{ steps.badger.outputs.disallowed-tools }}'
```

## Proven in Real GitHub Actions

All 3 CI jobs pass, including a live Claude Code integration:

![CI Results](docs/diagrams/claude-integration-success.png)

<details>
<summary>Proxy integration test logs</summary>

![Proxy Job Logs](docs/diagrams/proxy-job.png)

</details>

## What It Catches

**Clinejection:** Input scanning detects the fake error. Runtime enforcement blocks Bash for untrusted actors. Network isolation blocks exfiltration even for contributors. Three layers, any one is enough.

**Hackerbot Claw:** Fork PR = untrusted. Agent gets read-only tools. Cannot push code, modify CODEOWNERS, or edit CLAUDE.md.

**PromptPwnd:** Even if prompt injection succeeds at the LLM level, the proxy blocks tool calls for untrusted actors. Network isolation prevents exfiltration for contributors.

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `github-token` | `${{ github.token }}` | Token for actor permission lookup |
| `policy` | `''` | Path to custom policy file (optional) |
| `mode` | `audit` | Both modes block violations. `enforce` also fails the job. `audit` blocks + logs without failing. |

## Outputs

| Output | Description |
|--------|-------------|
| `trust-level` | Detected trust level (trusted, contributor, untrusted) |
| `violations` | Number of blocked tool calls |
| `mcp-config` | MCP config JSON to pass to the agent via `--mcp-config` |
| `disallowed-tools` | Native tools to disable via `--disallowedTools` (prevents proxy bypass) |

## Security Model

On Linux, contributor Bash commands run inside a triple sandbox:

1. **Bash allow list**: only permitted command prefixes (npm test, node, python, go test, etc). Everything else is blocked before execution.
2. **Network namespace** (`unshare --net`): no internet access. `curl`, `wget`, and any exfiltration fails at the OS level. Loopback stays up for test servers.
3. **Filesystem sandbox** (bubblewrap): protected paths (`.github/workflows/`, `CLAUDE.md`, `.cursorrules`, `.claude/`, etc.) are mounted read-only. Any command or language that tries to write to these paths gets "Read-only file system" from the kernel.

All three controls are kernel-enforced. The agent cannot bypass them via prompt injection.

## Known Limitations

**Linux only.** Network isolation and filesystem sandboxing use Linux kernel features (network namespaces, bubblewrap). On macOS and Windows runners, contributor Bash relies on the command allow list only. 85%+ of GitHub Actions workflows run on Linux. This is the same limitation StepSecurity Harden-Runner ships with.

**The command allow list is defense-in-depth, not a security boundary.** Commands starting with allowed prefixes can chain additional commands via `&&` or `;`. The primary security controls are network isolation and filesystem sandboxing, both kernel-enforced on Linux.

**Trusted level has no restrictions.** Repo admins get full tool access by design. If an admin account is compromised, Trust Badger cannot help. This matches GitHub's own threat model.

## Design

See [docs/DESIGN.md](docs/DESIGN.md) for architecture diagrams and the full design rationale.

## Contributing

Found a false positive? Missing a pattern? Open an issue or submit a PR. Policies live in `src/policies.js`, detection patterns in `src/patterns.js`.

## License

Apache 2.0
