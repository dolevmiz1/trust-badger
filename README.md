# Trust Badger

![Trust Badger](docs/diagrams/og-image.png)

> Your CI/CD pipeline trusts AI agents. Trust Badger makes sure that trust isn't misplaced.

Context-aware runtime enforcement for AI agents in CI/CD. Detects who triggered the workflow, assigns a trust level, and enforces tool policies through an MCP proxy. A fork PR from a stranger gets read-only tools. A maintainer gets full access. The agent cannot bypass it.

## The Problem

![The Problem: No Boundary](docs/diagrams/01_problem.png)

AI coding agents run inside CI/CD with shell access, git credentials, and secret tokens. Today, a fork PR from a stranger gives the agent the exact same permissions as a maintainer's PR. Every major attack in Q1 2026 (Hackerbot Claw, PromptPwnd, Clinejection, RoguePilot) exploited this gap.

Existing tools either scan inputs (but don't enforce at runtime) or enforce static policies (but don't know who triggered the workflow). Trust Badger does both.

## How It Works

![Trust Badger: How It Works](docs/diagrams/02_solution.png)

1. **Trust Badger reads GitHub context** (who triggered, fork vs org, actor permissions)
2. **Assigns a trust level** (untrusted, contributor, or trusted)
3. **Starts an MCP proxy** that the agent uses for all tool calls
4. **Every tool call goes through the proxy**, which enforces policies based on trust level

The agent thinks it has full access. But the proxy decides what actually gets through.

## Trust Levels

![Trust Levels and Policies](docs/diagrams/03_trust_levels.png)

| Level | Who | What the agent can do |
|-------|-----|----------------------|
| **Untrusted** | Fork PRs, first-time contributors, unknown actors | Read, search, browse. No bash, no file writes, no git push. |
| **Contributor** | Repo collaborators with read permission | All tools, but destructive commands and config file edits are blocked. |
| **Trusted** | Repo admins and maintainers (write+) | Everything. No restrictions. |

## Quick Start

```yaml
steps:
  # Trust Badger detects trust level and starts the MCP proxy
  - uses: dolevmiz1/trust-badger@v2
    id: badger
    with:
      mode: audit  # start with audit, switch to enforce when ready

  # Your AI agent uses Trust Badger's proxy
  - uses: anthropics/claude-code-action@v1
    with:
      anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
      claude_args: >
        --mcp-config '${{ steps.badger.outputs.mcp-config }}'
        --allowedTools 'mcp__trust-badger__*'
```

## What It Catches

**Clinejection:** Input scanning detects the fake error. Runtime enforcement blocks `Bash(npm install)` for untrusted actors. Two layers, either one is enough.

**Hackerbot Claw:** Fork PR = untrusted. Agent gets read-only tools. Cannot push code, modify CODEOWNERS, or edit CLAUDE.md.

**PromptPwnd:** Even if prompt injection succeeds at the LLM level, the proxy blocks `gh issue edit` for untrusted actors. Token exfiltration is impossible.

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `github-token` | `${{ github.token }}` | Token for actor permission lookup |
| `policy` | `''` | Path to custom policy file (optional) |
| `mode` | `audit` | `enforce` blocks violations, `audit` logs only |

## Outputs

| Output | Description |
|--------|-------------|
| `trust-level` | Detected trust level (trusted, contributor, untrusted) |
| `violations` | Number of blocked tool calls |
| `mcp-config` | MCP config JSON to pass to the agent |

## Audit Mode (safe rollout)

Start with `mode: audit`. Trust Badger logs what it would block but allows everything through. Review the logs, tune your policies, then switch to `mode: enforce`.

## Custom Policies

Add a `.trust-badger.yml` to your repo to override defaults. Or pass a policy file via the `policy` input.

## Security Model

On Linux, contributor Bash commands run inside a double sandbox:

1. **Network namespace** (`unshare --net`): no internet access. `curl`, `wget`, and any network exfiltration fails at the OS level.
2. **Filesystem sandbox** (bubblewrap): protected paths (`.github/workflows/`, `CLAUDE.md`, `.cursorrules`, `.claude/`, etc.) are mounted read-only. Any command that tries to write to these paths gets "Read-only file system" from the kernel, regardless of which tool or language is used.

Both controls are kernel-enforced. The agent cannot bypass them via prompt injection because the sandbox operates at the OS level, not the application level.

## Known Limitations

**Linux only.** Network isolation and filesystem sandboxing use Linux kernel features (network namespaces, bubblewrap). On macOS and Windows runners, contributor Bash relies on the command allow list only. 85%+ of GitHub Actions workflows run on Linux. This is the same limitation StepSecurity Harden-Runner ships with.

**The command allow list is defense-in-depth, not a security boundary.** Commands starting with allowed prefixes can chain additional commands via `&&` or `;`. The primary security controls are network isolation and filesystem sandboxing, both kernel-enforced on Linux.

**Trusted level has no restrictions.** Repo admins get full tool access by design. If an admin account is compromised, Trust Badger cannot help. This matches GitHub's own threat model.

## Design

See [docs/DESIGN.md](docs/DESIGN.md) for the full design rationale and architecture details.

## Contributing

Found a false positive? Missing a pattern? Open an issue or submit a PR. Policies live in `src/policies.js`, detection patterns in `src/patterns.js`.

## License

Apache 2.0
