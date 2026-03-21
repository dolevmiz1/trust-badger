const core = require('@actions/core');
const github = require('@actions/github');
const fs = require('fs');
const { RULES, SURFACE_RULES } = require('./patterns');

async function run() {
  try {
    const token = core.getInput('github-token');
    const failOnFinding = core.getInput('fail-on-finding') === 'true';
    const octokit = github.getOctokit(token);
    const { context } = github;

    const findings = [];

    if (context.eventName === 'pull_request' || context.eventName === 'pull_request_target') {
      await scanPullRequest(octokit, context, findings);
    } else if (context.eventName === 'issues') {
      scanIssue(context, findings);
    } else {
      core.info(`Event '${context.eventName}' is not supported. Skipping scan.`);
    }

    // Output results
    core.setOutput('findings-count', findings.length.toString());

    if (findings.length === 0) {
      core.info('No findings detected.');
    } else {
      core.warning(`${findings.length} finding(s) detected.`);

      // Write SARIF
      const sarif = generateSarif(findings);
      const sarifPath = 'trust-badger-results.sarif';
      fs.writeFileSync(sarifPath, JSON.stringify(sarif, null, 2));
      core.info(`SARIF written to ${sarifPath}`);

      // Post PR comment
      if (context.eventName.startsWith('pull_request')) {
        await postComment(octokit, context, findings);
      }

      if (failOnFinding) {
        core.setFailed(`Trust Badger found ${findings.length} issue(s).`);
      }
    }
  } catch (error) {
    core.setFailed(`Trust Badger error: ${error.message}`);
  }
}

// Scanning ---

async function scanPullRequest(octokit, context, findings) {
  const pr = context.payload.pull_request;
  const { owner, repo } = context.repo;

  // Scan text surfaces
  scanText(pr.title, 'prTitle', 'PR title', findings);
  scanText(pr.body || '', 'prBody', 'PR body', findings);
  scanText(pr.head.ref, 'branchName', 'Branch name', findings);

  // Scan commit messages
  try {
    const { data: commits } = await octokit.rest.pulls.listCommits({
      owner, repo, pull_number: pr.number, per_page: 100,
    });
    for (const commit of commits) {
      scanText(commit.commit.message, 'commitMsg', `Commit ${commit.sha.slice(0, 7)}`, findings);
    }
  } catch (e) {
    core.warning(`Could not fetch commits: ${e.message}`);
  }

  // Scan changed files
  try {
    const { data: files } = await octokit.rest.pulls.listFiles({
      owner, repo, pull_number: pr.number, per_page: 100,
    });

    for (const file of files) {
      // Rule 5: shell injection in filenames
      scanText(file.filename, 'filename', `Filename: ${file.filename}`, findings);

      // Rule 7: agent config file changes
      checkConfigFile(file, findings);

      // Rule 7: symlink detection
      if (file.status === 'added' && file.patch && /^120000/.test(file.sha || '')) {
        findings.push({
          ruleId: 'agent-config-change',
          severity: 'high',
          location: file.filename,
          message: `Symlink added: ${file.filename} (symlinks can be used to access secret files)`,
        });
      }
    }

    // Deep scan: if agent config file was changed, scan its new content for injection
    for (const file of files) {
      if (isAgentConfigFile(file.filename) && file.patch) {
        const addedLines = file.patch
          .split('\n')
          .filter(line => line.startsWith('+') && !line.startsWith('+++'))
          .map(line => line.slice(1))
          .join('\n');

        if (addedLines.length > 0) {
          const configFindings = [];
          scanText(addedLines, 'prBody', `Config file: ${file.filename}`, configFindings);
          for (const f of configFindings) {
            f.severity = 'critical'; // injection inside config file = critical
            f.message = `[In agent config] ${f.message}`;
            findings.push(f);
          }
        }
      }
    }
  } catch (e) {
    core.warning(`Could not fetch files: ${e.message}`);
  }
}

function scanIssue(context, findings) {
  const issue = context.payload.issue;
  scanText(issue.title, 'issueTitle', 'Issue title', findings);
  scanText(issue.body || '', 'issueBody', 'Issue body', findings);
}

// Core detection ---

function scanText(text, surface, locationLabel, findings) {
  if (!text || text.length === 0) return;

  const applicableRuleIds = SURFACE_RULES[surface] || [];

  for (const rule of RULES) {
    if (!applicableRuleIds.includes(rule.id)) continue;

    // Custom detector (Rule 4: Unicode)
    if (rule.detect) {
      const matches = rule.detect(text);
      for (const m of matches) {
        findings.push({
          ruleId: rule.id,
          severity: rule.severity,
          location: locationLabel,
          message: `${rule.name}: ${m.match}`,
          index: m.index,
        });
      }
      continue;
    }

    // Regex-based rules
    if (rule.patterns) {
      for (const pattern of rule.patterns) {
        const match = text.match(pattern);
        if (match) {
          findings.push({
            ruleId: rule.id,
            severity: rule.severity,
            location: locationLabel,
            message: `${rule.name}: matched "${match[0].slice(0, 80)}"`,
            index: match.index,
          });
          break; // one finding per rule per surface is enough
        }
      }
    }
  }
}

function isAgentConfigFile(filename) {
  const rule7 = RULES.find(r => r.id === 'agent-config-change');
  if (rule7.configFiles.includes(filename)) return true;
  for (const prefix of rule7.configDirPrefixes) {
    if (filename.startsWith(prefix)) return true;
  }
  return false;
}

function checkConfigFile(file, findings) {
  if (isAgentConfigFile(file.filename)) {
    findings.push({
      ruleId: 'agent-config-change',
      severity: 'medium',
      location: file.filename,
      message: `Agent config file modified: ${file.filename} (review for injection)`,
    });
  }
}

// SARIF output ---

function generateSarif(findings) {
  const ruleMap = {};
  for (const rule of RULES) {
    ruleMap[rule.id] = {
      id: rule.id,
      shortDescription: { text: rule.name },
      defaultConfiguration: { level: sarifLevel(rule.severity) },
    };
  }

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'Trust Badger',
          version: '0.1.0',
          rules: Object.values(ruleMap),
        },
      },
      results: findings.map((f, i) => ({
        ruleId: f.ruleId,
        level: sarifLevel(f.severity),
        message: { text: f.message },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: f.location.replace(/^\//, '') },
            region: { startLine: 1 },
          },
        }],
        partialFingerprints: {
          primaryLocationLineHash: `${f.ruleId}-${f.location}-${i}`,
        },
      })),
    }],
  };
}

function sarifLevel(severity) {
  const map = { critical: 'error', high: 'warning', medium: 'note', low: 'note' };
  return map[severity] || 'warning';
}

// PR comment ---

async function postComment(octokit, context, findings) {
  const marker = '<!-- trust-badger-results -->';
  const { owner, repo } = context.repo;
  const prNumber = context.payload.pull_request.number;

  const severityIcon = { critical: 'X', high: '!', medium: '~', low: '-' };
  const rows = findings.map(f =>
    `| ${f.severity.toUpperCase()} | ${f.ruleId} | ${f.location} | ${f.message} |`
  ).join('\n');

  const body = `${marker}
## Trust Badger Scan Results

**${findings.length} finding(s) detected** in this pull request.

| Severity | Rule | Location | Description |
|----------|------|----------|-------------|
${rows}

<details>
<summary>What is Trust Badger?</summary>

Trust Badger scans pull request inputs for prompt injection patterns that target AI coding agents. These patterns were derived from real attacks in Q1 2026 including Hackerbot Claw, PromptPwnd, Clinejection, and RoguePilot.

</details>`;

  // Update existing comment or create new one
  try {
    const { data: comments } = await octokit.rest.issues.listComments({
      owner, repo, issue_number: prNumber, per_page: 100,
    });
    const existing = comments.find(c => c.body && c.body.startsWith(marker));

    if (existing) {
      await octokit.rest.issues.updateComment({ owner, repo, comment_id: existing.id, body });
    } else {
      await octokit.rest.issues.createComment({ owner, repo, issue_number: prNumber, body });
    }
  } catch (e) {
    core.warning(`Could not post PR comment: ${e.message}`);
  }
}

run();
