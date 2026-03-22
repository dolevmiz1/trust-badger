const core = require('@actions/core');
const github = require('@actions/github');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { POLICIES } = require('./policies');
const { RULES, SURFACE_RULES } = require('./patterns');

const MAX_INPUT_LENGTH = 50000;

async function run() {
  try {
    const token = core.getInput('github-token');
    const rawMode = core.getInput('mode') || 'audit';
    const customPolicyPath = core.getInput('policy');
    const octokit = github.getOctokit(token);
    const { context } = github;

    // Validate mode
    const validModes = ['enforce', 'audit'];
    const mode = validModes.includes(rawMode) ? rawMode : 'audit';
    if (rawMode !== mode) {
      core.warning(`Invalid mode "${rawMode}". Valid values: enforce, audit. Defaulting to audit.`);
    }

    // Step 1: Detect trust level
    const trustLevel = await detectTrustLevel(octokit, context);
    core.info(`Trust level: ${trustLevel}`);
    core.setOutput('trust-level', trustLevel);

    // Install bubblewrap for filesystem sandboxing (Linux, non-trusted only)
    if (process.platform === 'linux' && trustLevel !== 'trusted') {
      try {
        require('child_process').execFileSync('which', ['bwrap'], { stdio: 'ignore' });
        core.info('bubblewrap already installed.');
      } catch (e) {
        core.info('Installing bubblewrap for filesystem sandboxing...');
        try {
          require('child_process').execSync('sudo apt-get install -y -qq bubblewrap 2>/dev/null', { stdio: 'ignore', timeout: 30000 });
          core.info('bubblewrap installed.');
        } catch (installErr) {
          core.warning('Could not install bubblewrap. Filesystem sandboxing will be unavailable.');
        }
      }
    }

    // Step 2: Resolve policy
    let policy = { ...POLICIES[trustLevel] };

    // Custom policies can only ADD deny rules
    if (customPolicyPath && fs.existsSync(customPolicyPath)) {
      core.info(`Loading custom policy from ${customPolicyPath}`);
      try {
        const custom = JSON.parse(fs.readFileSync(customPolicyPath, 'utf-8'));
        if (custom[trustLevel] && Array.isArray(custom[trustLevel].deny)) {
          policy.deny = [...policy.deny, ...custom[trustLevel].deny];
          core.info(`Added ${custom[trustLevel].deny.length} custom deny rule(s)`);
        }
        if (custom[trustLevel]?.allow || custom[trustLevel]?.denyAll !== undefined) {
          core.warning('Custom policies cannot modify allow lists or denyAll. Only additional deny rules are accepted.');
        }
      } catch (e) {
        core.warning(`Failed to parse custom policy: ${e.message}`);
      }
    }

    // Step 3: Run input scanning (Layer 1)
    const inputFindings = await scanInputs(octokit, context);
    if (inputFindings.length > 0) {
      core.warning(`Input scanning found ${inputFindings.length} suspicious pattern(s)`);
      for (const f of inputFindings) {
        core.warning(`  [${f.ruleId}] ${f.location}: ${f.message}`);
      }
    }

    // Step 4: Write policy file (random filename + HMAC)
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

    const hmacKey = crypto.randomBytes(32).toString('hex');
    const hmac = crypto.createHmac('sha256', hmacKey)
      .update(policyJson).digest('hex');

    // Step 5: Output MCP config + disallowed tools
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

    // Output disallowed-tools so native tools are blocked
    core.setOutput('disallowed-tools', 'Bash,Read,Write,Edit,Glob,Grep');

    core.info('MCP proxy config ready.');
    core.info('IMPORTANT: Use --disallowedTools with the value from the disallowed-tools output to prevent the agent from bypassing the proxy.');

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

  // Deleted fork: head.repo is null when the source repo is deleted
  if (context.payload.pull_request && !context.payload.pull_request.head?.repo) {
    core.info(`PR source repo is null (deleted fork). Untrusted.`);
    return 'untrusted';
  }

  // Fork PR is always untrusted
  if (context.payload.pull_request?.head?.repo?.fork) {
    core.info(`Fork PR detected (actor: ${actor})`);
    return 'untrusted';
  }

  // pull_request_target from any fork is untrusted (high risk event)
  if (eventName === 'pull_request_target') {
    const prHead = context.payload.pull_request?.head;
    const prBase = context.payload.pull_request?.base;
    if (!prHead?.repo || prHead.repo.full_name !== prBase?.repo?.full_name) {
      core.info(`pull_request_target from fork or deleted repo. Untrusted.`);
      return 'untrusted';
    }
  }

  // Bot actors are capped at contributor (never trusted)
  const actorType = context.payload.sender?.type ||
    context.payload.pull_request?.user?.type ||
    context.payload.issue?.user?.type;
  const isBot = actorType === 'Bot' || (actor && actor.endsWith('[bot]'));

  // Check actor's permission level via API
  try {
    const { data } = await octokit.rest.repos.getCollaboratorPermissionLevel({
      owner, repo, username: actor,
    });

    // Prefer role_name (5 levels) over permission (4 levels)
    const role = data.role_name || data.permission;
    core.info(`Actor ${actor} has '${role}' role (type: ${actorType || 'User'})`);

    // Trust mapping:
    //   admin = trusted (unless bot)
    //   write, maintain = contributor
    //   read, triage = untrusted
    //   none = untrusted

    if (role === 'admin' && !isBot) {
      return 'trusted';
    }
    if (role === 'admin' && isBot) {
      core.info(`Bot actor with admin permission capped at contributor.`);
      return 'contributor';
    }
    if (role === 'write' || role === 'maintain') {
      return 'contributor';
    }
    if (role === 'read' || role === 'triage') {
      return 'untrusted';
    }
    return 'untrusted';
  } catch (e) {
    core.warning(`Could not check permissions for ${actor}: ${e.message}. Defaulting to untrusted.`);
    return 'untrusted';
  }
}

async function scanInputs(octokit, context) {
  const findings = [];
  const pr = context.payload.pull_request;
  const issue = context.payload.issue;
  const comment = context.payload.comment;

  if (pr) {
    scanText(pr.title || '', 'prTitle', 'PR title', findings);
    scanText(pr.body || '', 'prBody', 'PR body', findings);
    scanText(pr.head?.ref || '', 'branchName', 'Branch name', findings);

    // Scan commit messages
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

  // Scan issue_comment body
  if (comment) {
    scanText(comment.body || '', 'issueBody', 'Comment body', findings);
  }

  // Scan workflow_dispatch inputs
  if (context.payload.inputs) {
    const inputStr = JSON.stringify(context.payload.inputs);
    scanText(inputStr, 'prBody', 'workflow_dispatch inputs', findings);
  }

  // Scan repository_dispatch client_payload
  if (context.payload.client_payload) {
    const payloadStr = JSON.stringify(context.payload.client_payload);
    scanText(payloadStr, 'prBody', 'repository_dispatch payload', findings);
  }

  return findings;
}

function scanText(text, surface, locationLabel, findings) {
  if (!text || text.length === 0) return;

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
