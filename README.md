# Trust Badger

![CI](https://github.com/dolevmiz1/trust-badger/actions/workflows/ci.yml/badge.svg)

![Trust Badger](docs/diagrams/og-image.png)

> Your CI/CD pipeline trusts AI agents. Trust Badger makes sure that trust isn't misplaced.

Context-aware runtime enforcement for AI agents in CI/CD. Detects who triggered the workflow, assigns a trust level, and enforces tool policies through an MCP proxy with kernel-level sandboxing on Linux. Fork PRs get read-only tools. Contributors get a Bash allow list with network isolation and filesystem protection. Admins get full access.

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
| **Untrusted** | Fork PRs, first-time contributors, read/triage permission | Read, Glob, Grep only. No Bash, no Write, no Edit. |
| **Contributor** | Write/maintain collaborators, bots (admin bots capped here) | All tools available. Bash restricted to allow list (npm test, node, python, etc). On Linux: no network, protected paths read-only. Write/Edit available but config files (.github/workflows/, CLAUDE.md, .cursorrules) blocked. |
| **Trusted** | Repo admins only (human). Schedule events. | Everything. No restrictions. |

## Quick Start

```yaml
steps:
  - uses: dolevmiz1/trust-badger@v7
    id: badger
    with:
      mode: audit  # both modes block violations; enforce also fails the job

  - uses: anthropics/claude-code-action@v1
    with:
      anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
      claude_args: >
        --mcp-config '${{ steps.badger.outputs.mcp-config }}'
        --allowedTools 'mcp__trust-badger__*'
        --disallowedTools '${{ steps.badger.outputs.disallowed-tools }}'
```

**About `mode`:** Both `audit` and `enforce` block denied tool calls. The difference: `enforce` also fails the GitHub Actions job. `audit` blocks the call and logs it, but lets the job complete. Start with `audit` to see what gets blocked without failing your CI.

## Proven in Real GitHub Actions

All CI jobs pass, including a live Claude Code integration and real fork PR enforcement:

![CI Results](docs/diagrams/claude-integration-success.png)

**Real fork PR enforcement proven:** A fork PR with a Clinejection-style payload was correctly assigned `untrusted` trust level, all 4 injection patterns detected, all write tools blocked, zero data exfiltrated.

![Fork PR Submission](docs/diagrams/fork-pr-submision.png)

![Input Scanning: 4 findings](docs/diagrams/fork-pr-scan.png)

<details>
<summary>Full detection logs from the CI job</summary>

![Trust Badger Setup Detection](docs/diagrams/trust-badget-setup-detection.png)

Shows the complete chain: fork detected, untrusted assigned, bubblewrap installed, all 4 injection patterns caught (fake-context, [RESTORE CONTEXT], HTML comment targeting Claude, GITHUB_TOKEN exfiltration via curl).

</details>

<details>
<summary>Proxy integration test logs</summary>

![Proxy Job Logs](docs/diagrams/proxy-job.png)

</details>

## What It Catches

**Clinejection:** Input scanning detects the fake error. Runtime enforcement blocks Bash for untrusted actors. Network isolation blocks exfiltration even for contributors. Three independent layers.

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

Trust Badger provides defense-in-depth through multiple layers. Each is independent.

**Layer 1: Input Scanning (early warning, not a security boundary)**

Regex patterns detect known attack signatures (Clinejection, PromptPwnd, RoguePilot) in PR titles, bodies, branch names, commit messages, issue bodies, comments, and dispatch payloads. This is a heuristic layer. Novel patterns or obfuscated variants will bypass it. This layer provides visibility and catches blatant injection attempts in tool arguments, but it is not the security boundary.

**Layers 2-5: Deterministic Enforcement (the security boundary)**

These layers do not depend on parsing attacker content:
- **Trust Detection**: fork PR = untrusted. Admin = trusted. Based on GitHub API, not input content. Not bypassable by prompt injection.
- **Policy Engine**: untrusted actors don't have Bash in their tool list. Contributors get an allow list. No amount of prompt crafting changes this.
- **Network Isolation** (Linux, contributor level): kernel network namespace. No internet. Not bypassable.
- **Filesystem Sandbox** (Linux, contributor level): bubblewrap read-only mounts. Kernel-enforced. Not bypassable.

The agent cannot bypass Layers 2-5 via prompt injection because these layers operate at the OS/API level, not the application level.

**Recommended org setting:** Disable "Allow GitHub Actions to create and approve pull requests" in your organization settings. `GITHUB_TOKEN` can approve PRs via the reviews API, and this setting is enabled by default. Trust Badger mitigates this for untrusted actors (no Bash) and contributors (`gh` not in the allow list), but the org setting provides an additional safeguard.

## Known Limitations

**Network isolation and filesystem sandboxing are Linux only.** These features use Linux kernel features (network namespaces, bubblewrap). On macOS and Windows runners, contributor Bash relies on the command allow list only.

**The command allow list is defense-in-depth, not a security boundary.** Commands starting with allowed prefixes can chain additional commands via `&&` or `;`. On Linux, network isolation and filesystem sandboxing catch what the allow list misses. On non-Linux, the allow list is the only Bash restriction for contributors.

**Trusted level has no restrictions.** Repo admins and schedule events get full tool access by design. If an admin account is compromised, Trust Badger cannot help.

## Why Not Rely on the LLM Alone?

We tested what happens WITHOUT Trust Badger. A fork PR with a Clinejection-style payload was submitted to a vulnerable workflow running `claude-code-action` with `allowed_non_write_users: "*"`, `pull_request_target` (exposes secrets to forks), and full Bash access.

In this test, the malicious commands were not executed and a comment was posted identifying the attack. However, this does not mean the threat is solved:

- The real Clinejection attack (Feb 2026) used the same `claude-code-action` and succeeded in tricking Claude into running `npm install` from a malicious fork, leading to secret exfiltration and a supply chain compromise affecting 5M+ users.
- LLM behavior is non-deterministic. A different payload, model version, or prompt structure might bypass the safety layer. Anthropic's own post-incident fixes prove the previous version was vulnerable.
- Trust Badger's enforcement layers (2-5) are deterministic. They do not depend on the LLM's judgment. Tools are blocked by policy, network isolation, and filesystem sandboxing at the OS level.

## Design

See [docs/DESIGN.md](docs/DESIGN.md) for architecture diagrams and the full design rationale.

## Contributing

Found a false positive? Missing a pattern? Open an issue or submit a PR. Policies live in `src/policies.js`, detection patterns in `src/patterns.js`.

## License

Apache 2.0
