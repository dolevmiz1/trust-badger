# Trust Badger

> Your CI/CD pipeline trusts AI agents. Trust Badger makes sure that trust isn't misplaced.

Scans pull request inputs for prompt injection patterns that target AI coding agents. Built from real attack payloads (Hackerbot Claw, PromptPwnd, Clinejection, RoguePilot) so you catch what actually matters.

## Why?

AI coding agents now run inside CI/CD pipelines with shell access, git credentials, and secret tokens. Attackers have figured out they can hide instructions in PR titles, issue bodies, branch names, and config files to hijack these agents.

In Q1 2026 alone, this led to compromises at Microsoft, Datadog, and 5+ Fortune 500 companies.

Trust Badger sits between the untrusted input and the agent, scanning everything before the agent gets to read it.

## Quick Start

```yaml
name: Trust Badger
on:
  pull_request:
    types: [opened, synchronize, edited]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: dolevmiz1/trust-badger@v1
```

That's it. No config. No API keys. No signup.

## What It Catches

| Rule | Catches | Inspired By |
|------|---------|-------------|
| **Prompt injection phrases** | "ignore previous instructions", fake config delimiters, suppression language | PromptPwnd |
| **Fake context simulation** | Fake error messages, `[RESTORE CONTEXT]`, `<override>` tags | Clinejection, Hackerbot Claw |
| **HTML comment injection** | Hidden instructions inside `<!-- -->` comments | RoguePilot |
| **Hidden Unicode** | Zero width characters, bidirectional markers | Rules File Backdoor |
| **Shell injection in metadata** | `$()`, `${IFS}`, brace expansion in branch names and filenames | Hackerbot Claw |
| **Token exfiltration language** | Instructions to leak GITHUB_TOKEN, secrets, credentials | PromptPwnd |
| **Agent config file changes** | Modifications to `.cursorrules`, `CLAUDE.md`, `copilot-instructions.md`, and more | Hackerbot Claw |

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `fail-on-finding` | `false` | Fail the check if findings are detected |
| `github-token` | `${{ github.token }}` | Token for posting PR comments |

## Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Number of findings detected |

## SARIF Upload (GitHub Code Scanning)

```yaml
steps:
  - uses: dolevmiz1/trust-badger@v1
    id: scan
  - uses: github/codeql-action/upload-sarif@v3
    if: always()
    with:
      sarif_file: trust-badger-results.sarif
```

## Block Merge on Finding

```yaml
steps:
  - uses: dolevmiz1/trust-badger@v1
    with:
      fail-on-finding: 'true'
```

## Scan Issues Too

```yaml
on:
  pull_request:
    types: [opened, synchronize, edited]
  issues:
    types: [opened, edited]
```

## How It Works

Trust Badger runs as a GitHub Action on every pull request. It grabs the PR title, body, branch name, commit messages, and changed files, then runs 7 detection rules against each input. If something looks suspicious, it posts a comment on the PR and writes a SARIF file.

No network calls to external services. No data leaves your runner. Everything runs locally.

## Contributing

Found a false positive? Missing a pattern? Open an issue or submit a PR. The detection rules live in `src/patterns.js` and are easy to extend.

## License

Apache 2.0
