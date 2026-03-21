const core = require('@actions/core');
const github = require('@actions/github');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { POLICIES } = require('./policies');
const { RULES, SURFACE_RULES } = require('./patterns');

const MAX_INPUT_LENGTH = 50000; // MED-01 fix

async function run() {
  try {
    const token = core.getInput('github-token');
    const rawMode = core.getInput('mode') || 'audit';
    const customPolicyPath = core.getInput('policy');
    const octokit = github.getOctokit(token);
    const { context } = github;

    // LOW-02 fix: validate mode
    const validModes = ['enforce', 'audit'];
    const mode = validModes.includes(rawMode) ? rawMode : 'audit';
    if (rawMode !== mode) {
      core.warning(`Invalid mode "${rawMode}". Valid values: enforce, audit. Defaulting to audit.`);
    }

    // Step 1: Detect trust level
    const trustLevel = await detectTrustLevel(octokit, context);
    core.info(`Trust level: ${trustLevel}`);
    core.setOutput('trust-level', trustLevel);

    // Step 2: Resolve policy
    let policy = { ...POLICIES[trustLevel] };

    // CRIT-03 fix: custom policies can only ADD deny rules, not replace allow/denyAll
    if (customPolicyPath && fs.existsSync(customPolicyPath)) {
      core.info(`Loading custom policy from ${customPolicyPath}`);
      try {
        const custom = JSON.parse(fs.readFileSync(customPolicyPath, 'utf-8'));
        if (custom[trustLevel] && Array.isArray(custom[trustLevel].deny)) {
          // Merge deny rules (additive only, cannot remove defaults)
          policy.deny = [...policy.deny, ...custom[trustLevel].deny];
          core.info(`Added ${custom[trustLevel].deny.length} custom deny rule(s)`);
        }
        // Ignore attempts to change allow, denyAll, or label
        if (custom[trustLevel]?.allow || custom[trustLevel]?.denyAll !== undefined) {
          core.warning('Custom policies cannot modify allow lists or denyAll. Only additional deny rules are accepted.');
        }
      } catch (e) {
        core.warning(`Failed to parse custom policy: ${e.message}`);
      }
    }

    // MED-03 fix: remove .trust-badger.yml detection (was detected but never loaded)
    // Will implement in a future version with proper schema validation

    // Step 3: Run input scanning (Layer 1)
    const inputFindings = await scanInputs(octokit, context);
    if (inputFindings.length > 0) {
      core.warning(`Input scanning found ${inputFindings.length} suspicious pattern(s)`);
      for (const f of inputFindings) {
        core.warning(`  [${f.ruleId}] ${f.location}: ${f.message}`);
      }
    }

    // CRIT-04 fix: random filename for policy file
    const policyId = crypto.randomBytes(16).toString('hex');
    const policyFile = path.join(
      process.env.RUNNER_TEMP || '/tmp',
      `trust-badger-${policyId}.json`
    );

    const policyData = {
      trustLevel,
      mode,
      inputFindings,
      context: {
        actor: process.env.GITHUB_ACTOR,
        triggeringActor: process.env.GITHUB_TRIGGERING_ACTOR,
        eventName: process.env.GITHUB_EVENT_NAME,
        repository: process.env.GITHUB_REPOSITORY,
      },
    };

    const policyJson = JSON.stringify(policyData, null, 2);
    fs.writeFileSync(policyFile, policyJson);

    // HMAC for integrity verification with runtime-generated key
    const hmacKey = crypto.randomBytes(32).toString('hex');
    const hmac = crypto.createHmac('sha256', hmacKey)
      .update(policyJson).digest('hex');

    const proxyPath = path.resolve(__dirname, 'proxy.js');
    const mcpConfig = JSON.stringify({
      mcpServers: {
        'trust-badger': {
          command: 'node',
          args: [proxyPath, policyFile, hmac, hmacKey],
          env: {
            GITHUB_STEP_SUMMARY: process.env.GITHUB_STEP_SUMMARY || '',
            GITHUB_WORKSPACE: process.env.GITHUB_WORKSPACE || '',
          },
        },
      },
    });

    core.setOutput('mcp-config', mcpConfig);
    core.setOutput('violations', '0');
    core.info('MCP proxy config ready. Pass it to your agent via --mcp-config.');

    // Step 4: Write summary
    const summaryFile = process.env.GITHUB_STEP_SUMMARY;
    if (summaryFile) {
      const summary = [
        '## Trust Badger',
        '',
        `**Trust level:** ${trustLevel} (${policy.description})`,
        `**Mode:** ${mode}`,
        '',
        inputFindings.length > 0
          ? `**Input scanning:** ${inputFindings.length} finding(s)`
          : '**Input scanning:** clean',
        '',
      ].join('\n');
      fs.appendFileSync(summaryFile, summary);
    }

  } catch (error) {
    core.setFailed(`Trust Badger setup error: ${error.message}`);
  }
}

async function detectTrustLevel(octokit, context) {
  const actor = process.env.GITHUB_TRIGGERING_ACTOR || process.env.GITHUB_ACTOR;
  const eventName = process.env.GITHUB_EVENT_NAME;
  const { owner, repo } = context.repo;

  // Fork PR is always untrusted
  if (context.payload.pull_request?.head?.repo?.fork) {
    core.info(`Fork PR detected (actor: ${actor})`);
    return 'untrusted';
  }

  // HIGH-04 fix: pull_request_target from ANY fork is untrusted, regardless of actor permissions.
  // This event is inherently high-risk because it runs with base branch secrets.
  if (eventName === 'pull_request_target') {
    const prHead = context.payload.pull_request?.head;
    const prBase = context.payload.pull_request?.base;
    if (prHead?.repo?.full_name !== prBase?.repo?.full_name) {
      core.info(`pull_request_target from fork: ${prHead?.repo?.full_name}. Untrusted.`);
      return 'untrusted';
    }
  }

  // Check actor's permission level via API
  try {
    const { data } = await octokit.rest.repos.getCollaboratorPermissionLevel({
      owner, repo, username: actor,
    });

    const permission = data.permission;
    core.info(`Actor ${actor} has '${permission}' permission`);

    if (permission === 'admin' || permission === 'write') {
      return 'trusted';
    }
    if (permission === 'read') {
      return 'contributor';
    }
    return 'untrusted';
  } catch (e) {
    core.warning(`Could not check permissions for ${actor}: ${e.message}. Defaulting to untrusted.`);
    return 'untrusted';
  }
}

// MED-04 fix: also scan commit messages
async function scanInputs(octokit, context) {
  const findings = [];
  const pr = context.payload.pull_request;
  const issue = context.payload.issue;

  if (pr) {
    scanText(pr.title || '', 'prTitle', 'PR title', findings);
    scanText(pr.body || '', 'prBody', 'PR body', findings);
    scanText(pr.head?.ref || '', 'branchName', 'Branch name', findings);

    // MED-04 fix: scan commit messages
    try {
      const { owner, repo } = context.repo;
      const { data: commits } = await octokit.rest.pulls.listCommits({
        owner, repo, pull_number: pr.number, per_page: 100,
      });
      for (const commit of commits) {
        scanText(commit.commit.message || '', 'commitMsg', `Commit ${commit.sha.slice(0, 7)}`, findings);
      }
    } catch (e) {
      core.warning(`Could not fetch commits for scanning: ${e.message}`);
    }
  }

  if (issue) {
    scanText(issue.title || '', 'issueTitle', 'Issue title', findings);
    scanText(issue.body || '', 'issueBody', 'Issue body', findings);
  }

  return findings;
}

function scanText(text, surface, locationLabel, findings) {
  if (!text || text.length === 0) return;

  // MED-01 fix: cap input length before regex
  const capped = text.slice(0, MAX_INPUT_LENGTH);

  const applicableRuleIds = SURFACE_RULES[surface] || [];

  for (const rule of RULES) {
    if (!applicableRuleIds.includes(rule.id)) continue;

    if (rule.detect) {
      const matches = rule.detect(capped);
      for (const m of matches) {
        findings.push({
          ruleId: rule.id,
          severity: rule.severity,
          location: locationLabel,
          message: `${rule.name}: ${m.match}`,
        });
      }
      continue;
    }

    const isMetadata = surface === 'branchName' || surface === 'filename';
    const allPatterns = [
      ...(rule.patterns || []),
      ...(isMetadata && rule.metadataOnlyPatterns ? rule.metadataOnlyPatterns : []),
    ];
    for (const pattern of allPatterns) {
      const match = capped.match(pattern);
      if (match) {
        findings.push({
          ruleId: rule.id,
          severity: rule.severity,
          location: locationLabel,
          message: `${rule.name}: matched "${match[0].slice(0, 80)}"`,
        });
        break;
      }
    }
  }
}

run();
