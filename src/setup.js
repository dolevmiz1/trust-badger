const core = require('@actions/core');
const github = require('@actions/github');
const fs = require('fs');
const path = require('path');
const { POLICIES } = require('./policies');
const { RULES, SURFACE_RULES } = require('./patterns');

async function run() {
  try {
    const token = core.getInput('github-token');
    const mode = core.getInput('mode') || 'audit';
    const customPolicyPath = core.getInput('policy');
    const octokit = github.getOctokit(token);
    const { context } = github;

    // Step 1: Detect trust level
    const trustLevel = await detectTrustLevel(octokit, context);
    core.info(`Trust level: ${trustLevel}`);
    core.setOutput('trust-level', trustLevel);

    // Step 2: Resolve policy
    let policy = POLICIES[trustLevel];
    if (customPolicyPath && fs.existsSync(customPolicyPath)) {
      core.info(`Loading custom policy from ${customPolicyPath}`);
      const custom = JSON.parse(fs.readFileSync(customPolicyPath, 'utf-8'));
      if (custom[trustLevel]) {
        policy = { ...policy, ...custom[trustLevel] };
      }
    }

    // Also check for .trust-badger.yml in repo root
    const repoPolicyPath = path.join(process.env.GITHUB_WORKSPACE || '.', '.trust-badger.yml');
    if (!customPolicyPath && fs.existsSync(repoPolicyPath)) {
      core.info('Found .trust-badger.yml in repo root');
    }

    // Step 3: Run input scanning (Layer 1)
    const inputFindings = scanInputs(context);
    if (inputFindings.length > 0) {
      core.warning(`Input scanning found ${inputFindings.length} suspicious pattern(s)`);
      for (const f of inputFindings) {
        core.warning(`  [${f.ruleId}] ${f.location}: ${f.message}`);
      }
    }

    // Step 4: Write policy file for proxy to read
    const policyFile = path.join(process.env.RUNNER_TEMP || '/tmp', 'trust-badger-policy.json');
    const policyData = {
      trustLevel,
      mode,
      policy,
      inputFindings,
      context: {
        actor: process.env.GITHUB_ACTOR,
        triggeringActor: process.env.GITHUB_TRIGGERING_ACTOR,
        eventName: process.env.GITHUB_EVENT_NAME,
        repository: process.env.GITHUB_REPOSITORY,
      },
    };
    fs.writeFileSync(policyFile, JSON.stringify(policyData, null, 2));
    core.info(`Policy written to ${policyFile}`);

    // Step 5: Output MCP config for the proxy
    const proxyPath = path.resolve(__dirname, 'proxy.js');
    const mcpConfig = JSON.stringify({
      mcpServers: {
        'trust-badger': {
          command: 'node',
          args: [proxyPath],
          env: {
            TRUST_BADGER_POLICY: policyFile,
            GITHUB_STEP_SUMMARY: process.env.GITHUB_STEP_SUMMARY || '',
          },
        },
      },
    });

    core.setOutput('mcp-config', mcpConfig);
    core.info('MCP proxy config ready. Pass it to your agent via --mcp-config.');

    // Step 6: Write summary
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

  // pull_request_target from external = untrusted
  if (eventName === 'pull_request_target') {
    const prAuthor = context.payload.pull_request?.user?.login;
    if (prAuthor !== owner) {
      core.info(`pull_request_target from external user: ${prAuthor}`);
      return 'untrusted';
    }
  }

  // Check actor's permission level via API
  try {
    const { data } = await octokit.rest.repos.getCollaboratorPermissionLevel({
      owner, repo, username: actor,
    });

    const permission = data.permission; // admin, write, read, none
    core.info(`Actor ${actor} has '${permission}' permission`);

    if (permission === 'admin' || permission === 'write') {
      return 'trusted';
    }
    if (permission === 'read') {
      return 'contributor';
    }
    return 'untrusted';
  } catch (e) {
    // If we can't check permissions (e.g., token doesn't have access), default to untrusted
    core.warning(`Could not check permissions for ${actor}: ${e.message}. Defaulting to untrusted.`);
    return 'untrusted';
  }
}

function scanInputs(context) {
  const findings = [];
  const pr = context.payload.pull_request;
  const issue = context.payload.issue;

  if (pr) {
    scanText(pr.title || '', 'prTitle', 'PR title', findings);
    scanText(pr.body || '', 'prBody', 'PR body', findings);
    scanText(pr.head?.ref || '', 'branchName', 'Branch name', findings);
  }
  if (issue) {
    scanText(issue.title || '', 'issueTitle', 'Issue title', findings);
    scanText(issue.body || '', 'issueBody', 'Issue body', findings);
  }

  return findings;
}

function scanText(text, surface, locationLabel, findings) {
  if (!text || text.length === 0) return;

  const applicableRuleIds = SURFACE_RULES[surface] || [];

  for (const rule of RULES) {
    if (!applicableRuleIds.includes(rule.id)) continue;

    if (rule.detect) {
      const matches = rule.detect(text);
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
      const match = text.match(pattern);
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
