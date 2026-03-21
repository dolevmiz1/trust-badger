# Trust Badger

> Your CI/CD pipeline trusts AI agents. Trust Badger makes sure that trust isn't misplaced.

Context-aware runtime enforcement for AI agents in CI/CD. Detects who triggered the workflow, assigns a trust level, and enforces tool policies through an MCP proxy. A fork PR from a stranger gets read-only tools. A maintainer gets full access. The agent cannot bypass it.

## Why?

AI coding agents run inside CI/CD with shell access, git credentials, and secret tokens. Today, a fork PR from a stranger gives the agent the exact same permissions as a maintainer's PR. Every major attack in Q1 2026 (Hackerbot Claw, PromptPwnd, Clinejection, RoguePilot) exploited this gap.

Existing tools either scan inputs (but don't enforce at runtime) or enforce static policies (but don't know who triggered the workflow). Trust Badger does both.

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

## How It Works

1. **Trust Badger reads GitHub context** (who triggered, fork vs org, actor permissions)
2. **Assigns a trust level** (untrusted, contributor, or trusted)
3. **Starts an MCP proxy** that the agent uses for all tool calls
4. **Every tool call goes through the proxy**, which enforces policies based on trust level

The agent thinks it has full access. But the proxy decides what actually gets through.

## Trust Levels

| Level | Who | What the agent can do |
|-------|-----|----------------------|
| **Untrusted** | Fork PRs, first-time contributors, unknown actors | Read, search, browse. No bash, no file writes, no git push. |
| **Contributor** | Repo collaborators with read permission | All tools, but destructive commands and config file edits are blocked. |
| **Trusted** | Repo admins and maintainers (write+) | Everything. No restrictions. |

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

## Design

See [docs/DESIGN.md](docs/DESIGN.md) for architecture diagrams and the full design rationale.

## Contributing

Found a false positive? Missing a pattern? Open an issue or submit a PR. Policies live in `src/policies.js`, detection patterns in `src/patterns.js`.

## License

Apache 2.0
