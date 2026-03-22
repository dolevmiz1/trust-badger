// Trust Badger MCP Proxy
// True intercepting proxy: evaluates policy, executes allowed calls, blocks denied ones.
// The agent ONLY has access to tools through this proxy.

const fs = require('fs');
const path = require('path');
const readline = require('readline');
const { execSync } = require('child_process');
const { evaluatePolicy, POLICIES } = require('./policies');
const { RULES, SURFACE_RULES } = require('./patterns');

// CRIT-05 fix: policy file path comes from CLI args (set at spawn time by setup.js),
// not from an environment variable that other steps could overwrite via GITHUB_ENV.
const policyFile = process.argv[2] || process.env.TRUST_BADGER_POLICY;
if (!policyFile || !fs.existsSync(policyFile)) {
  process.stderr.write('Trust Badger proxy: no policy file found. Exiting.\n');
  process.exit(1);
}

// Verify policy file integrity via HMAC (required, not optional)
const policyRaw = fs.readFileSync(policyFile, 'utf-8');
const policyData = JSON.parse(policyRaw);

const expectedHmac = process.argv[3];
const hmacKey = process.argv[4] || 'trust-badger-default';
if (!expectedHmac) {
  process.stderr.write('Trust Badger proxy: HMAC argument missing. Policy integrity cannot be verified. Exiting.\n');
  process.exit(1);
}
const crypto = require('crypto');
const computed = crypto.createHmac('sha256', hmacKey)
  .update(policyRaw).digest('hex');
if (computed !== expectedHmac) {
  process.stderr.write('Trust Badger proxy: policy file integrity check FAILED. File may have been tampered with.\n');
  process.exit(1);
}

const { trustLevel, mode } = policyData;

// Validate trust level is one of the known values
if (!POLICIES[trustLevel]) {
  process.stderr.write(`Trust Badger proxy: invalid trust level "${trustLevel}". Defaulting to untrusted.\n`);
}
const policy = POLICIES[trustLevel] || POLICIES.untrusted;
const violations = [];

// LOW-02 fix: validate mode
const validModes = ['enforce', 'audit'];
const effectiveMode = validModes.includes(mode) ? mode : 'audit';
if (mode !== effectiveMode) {
  process.stderr.write(`Trust Badger proxy: invalid mode "${mode}", defaulting to "audit".\n`);
}

process.stderr.write(`Trust Badger proxy started (trust: ${trustLevel}, mode: ${effectiveMode})\n`);

const MAX_INPUT_LENGTH = 50000; // MED-01 fix: cap input length before regex scanning

const rl = readline.createInterface({ input: process.stdin, terminal: false });

rl.on('line', (line) => {
  if (!line.trim()) return;
  try {
    const msg = JSON.parse(line);
    handleMessage(msg);
  } catch (e) {
    process.stderr.write(`Trust Badger proxy: error processing message: ${e.message}\n`);
  }
});

function handleMessage(msg) {
  if (msg.method === 'initialize') {
    respond(msg.id, {
      protocolVersion: '2024-11-05',
      capabilities: { tools: { listChanged: false } },
      serverInfo: { name: 'trust-badger', version: '0.3.0' },
    });
    return;
  }

  if (msg.method === 'notifications/initialized') return;

  if (msg.method === 'tools/list') {
    respond(msg.id, { tools: getAvailableTools() });
    return;
  }

  if (msg.method === 'tools/call') {
    handleToolCall(msg);
    return;
  }

  if (msg.method === 'ping') {
    respond(msg.id, {});
    return;
  }

  respond(msg.id, null, { code: -32601, message: `Method not found: ${msg.method}` });
}

function handleToolCall(msg) {
  // MED-02 fix: validate required fields
  if (!msg.params || !msg.params.name || msg.id === undefined) {
    respond(msg.id || null, null, {
      code: -32602,
      message: 'Invalid params: "name" is required for tools/call',
    });
    return;
  }

  // CRIT-02 fix: normalize tool name (case-insensitive matching)
  const rawToolName = msg.params.name;
  const toolName = normalizeToolName(rawToolName);
  const toolArgs = msg.params.arguments || {};

  // Evaluate policy
  const decision = evaluatePolicy(policy, toolName, toolArgs);

  // HIGH-03 fix: deep-stringify all args for injection scanning (not just top-level strings)
  const argText = JSON.stringify(toolArgs);
  const cappedArgText = argText.slice(0, MAX_INPUT_LENGTH); // MED-01 fix
  const injectionFindings = scanForInjection(cappedArgText);

  if (injectionFindings.length > 0 && trustLevel !== 'trusted') {
    decision.allowed = false;
    decision.reason = `Prompt injection detected in tool arguments: ${injectionFindings[0].message}`;
  }

  logDecision(toolName, toolArgs, decision);

  if (!decision.allowed) {
    violations.push({ tool: toolName, reason: decision.reason });

    if (effectiveMode === 'enforce') {
      respond(msg.id, {
        content: [{ type: 'text', text: `[Trust Badger] BLOCKED: ${decision.reason}` }],
        isError: true,
      });
      return;
    }
    // VULN-10 fix: audit mode still blocks denied calls but logs as AUDIT instead of BLOCK.
    // The previous behavior (execute denied calls in audit mode) was a security hole.
    // Audit mode now means: block AND log the reason, but don't fail the overall job.
    process.stderr.write(`[AUDIT] Blocked: ${toolName} (${decision.reason})\n`);
    respond(msg.id, {
      content: [{ type: 'text', text: `[Trust Badger] AUDIT: ${decision.reason}. This call was blocked. Set mode to "enforce" to also fail the job.` }],
      isError: true,
    });
    return;
  }

  // Execute allowed tool calls only.
  const result = executeTool(toolName, toolArgs);
  respond(msg.id, result);
}

// Tool execution with security hardening.
// NEVER construct shell commands from user input. Use argument arrays or Node APIs.
function executeTool(toolName, toolArgs) {
  const workspace = process.env.GITHUB_WORKSPACE || process.cwd();

  try {
    switch (toolName) {
      case 'Bash': {
        const cmd = toolArgs.command || '';

        // Reject null bytes (could cause truncation at C level)
        if (cmd.includes('\0')) {
          return { content: [{ type: 'text', text: 'Command rejected: contains null bytes' }], isError: true };
        }

        // Sandboxed execution for contributor on Linux:
        // 1. Network namespace (unshare --net): no internet access
        // 2. Filesystem sandbox (bubblewrap): protected paths are read-only
        // Command is written to temp file (no shell escaping issues).
        if (process.platform === 'linux' && policy.bashMode === 'allowlist') {
          const tmpScript = path.join(workspace, `.trust-badger-cmd-${process.pid}-${Date.now()}.sh`);
          try {
            fs.writeFileSync(tmpScript, cmd, { mode: 0o700 });
            const { execFileSync } = require('child_process');
            const envVars = 'PATH,HOME,NODE_PATH,PYTHONPATH,GOPATH,CARGO_HOME,npm_config_cache,LANG,TERM';
            const user = process.env.USER || 'runner';

            // Protected paths: read-only inside sandbox (kernel-enforced via bwrap)
            const protectedPaths = [
              '.github', 'CLAUDE.md', '.cursorrules', '.cursorignore',
              '.clinerules', '.clineignore', 'AGENTS.md', 'AGENTS.yaml',
              '.windsurfrules', '.claude',
            ];

            // Check if bwrap is available
            let hasBwrap = false;
            try {
              execFileSync('which', ['bwrap'], { stdio: 'ignore' });
              hasBwrap = true;
            } catch (e) { /* bwrap not installed */ }

            let innerCmd;
            if (hasBwrap) {
              // Build bwrap args: ro-bind everything, writable workspace, protected paths re-bound as ro
              const bwrapParts = [
                'bwrap',
                '--ro-bind', '/', '/',
                '--dev', '/dev',
                '--proc', '/proc',
                '--tmpfs', '/tmp',
                '--bind', workspace, workspace,
              ];
              for (const p of protectedPaths) {
                const fullPath = path.join(workspace, p);
                if (fs.existsSync(fullPath)) {
                  bwrapParts.push('--ro-bind', fullPath, fullPath);
                }
              }
              bwrapParts.push('--', 'bash', tmpScript);
              const bwrapCmd = bwrapParts.map(a => `'${a}'`).join(' ');
              innerCmd = `ip link set lo up && sudo --preserve-env=${envVars} -u ${user} ${bwrapCmd}`;
            } else {
              // Fallback: network isolation only (no filesystem protection)
              process.stderr.write('[Trust Badger] bwrap not available, using network isolation only\n');
              innerCmd = `ip link set lo up && sudo --preserve-env=${envVars} -u ${user} bash ${tmpScript}`;
            }

            const output = execFileSync('sudo', ['unshare', '--net', 'sh', '-c', innerCmd], {
              encoding: 'utf-8',
              timeout: 120000,
              maxBuffer: 4 * 1024 * 1024,
              cwd: workspace,
              env: process.env,
            });
            return { content: [{ type: 'text', text: output }] };
          } catch (e) {
            const combined = (e.stdout || '') + (e.stderr ? '\nSTDERR:\n' + e.stderr : '');
            return { content: [{ type: 'text', text: combined || e.message }], isError: true };
          } finally {
            try { fs.unlinkSync(tmpScript); } catch (e) { /* cleanup */ }
          }
        }

        // Non-Linux or trusted: direct execution (no network isolation)
        try {
          const output = execSync(cmd, {
            encoding: 'utf-8',
            timeout: 120000,
            maxBuffer: 4 * 1024 * 1024,
            cwd: workspace,
          });
          return { content: [{ type: 'text', text: output }] };
        } catch (e) {
          const combined = (e.stdout || '') + (e.stderr ? '\nSTDERR:\n' + e.stderr : '');
          return { content: [{ type: 'text', text: combined || e.message }], isError: true };
        }
      }

      case 'Read': {
        const filePath = resolveAndValidatePath(toolArgs.file_path, workspace);
        const content = fs.readFileSync(filePath, 'utf-8');
        return { content: [{ type: 'text', text: content }] };
      }

      case 'Write': {
        const filePath = resolveAndValidatePath(toolArgs.file_path, workspace);
        fs.mkdirSync(path.dirname(filePath), { recursive: true });
        fs.writeFileSync(filePath, toolArgs.content || '');
        return { content: [{ type: 'text', text: `File written: ${filePath}` }] };
      }

      case 'Edit': {
        const filePath = resolveAndValidatePath(toolArgs.file_path, workspace);
        let content = fs.readFileSync(filePath, 'utf-8');
        if (toolArgs.old_string && content.includes(toolArgs.old_string)) {
          // Replace first occurrence only (matches Claude Code Edit semantics)
          content = content.replace(toolArgs.old_string, toolArgs.new_string || '');
          fs.writeFileSync(filePath, content);
          return { content: [{ type: 'text', text: `File edited: ${filePath}` }] };
        }
        return { content: [{ type: 'text', text: `old_string not found in ${filePath}` }], isError: true };
      }

      case 'Glob': {
        // Fix: use Node.js glob, NOT shell exec with unsanitized input
        const pattern = toolArgs.pattern || '**/*';
        const { execFileSync } = require('child_process');
        // Use find with -maxdepth for safety, pass pattern as argument (not shell interpolation)
        const output = execFileSync('find', [workspace, '-maxdepth', '10', '-path', `*/${pattern}`, '-type', 'f'], {
          encoding: 'utf-8',
          timeout: 10000,
          maxBuffer: 1024 * 1024,
        });
        const lines = output.trim().split('\n').filter(Boolean).slice(0, 100).join('\n');
        return { content: [{ type: 'text', text: lines || 'No files found' }] };
      }

      case 'Grep': {
        // Fix: use execFileSync with argument array, NEVER shell interpolation
        const pattern = toolArgs.pattern || '';
        const searchPath = toolArgs.path || workspace;
        const validatedPath = resolveAndValidatePath(searchPath, workspace);
        const { execFileSync } = require('child_process');
        try {
          const output = execFileSync('grep', ['-rn', '--', pattern, validatedPath], {
            encoding: 'utf-8',
            timeout: 10000,
            maxBuffer: 1024 * 1024,
          });
          const lines = output.trim().split('\n').slice(0, 100).join('\n');
          return { content: [{ type: 'text', text: lines || 'No matches found' }] };
        } catch (e) {
          // grep exits with code 1 when no matches found
          if (e.status === 1) return { content: [{ type: 'text', text: 'No matches found' }] };
          throw e;
        }
      }

      case 'WebFetch':
      case 'WebSearch':
        return { content: [{ type: 'text', text: `[Trust Badger] ${toolName} is not supported through the proxy.` }] };

      default:
        return { content: [{ type: 'text', text: `[Trust Badger] Unknown tool: ${toolName}` }], isError: true };
    }
  } catch (e) {
    return { content: [{ type: 'text', text: `Error executing ${toolName}: ${e.message}` }], isError: true };
  }
}

// Resolve file path, follow symlinks, and validate it stays within workspace.
// Prevents path traversal (/etc/passwd) and symlink attacks (symlink to workflow files).
function resolveAndValidatePath(filePath, workspace) {
  if (!filePath) throw new Error('file_path is required');

  const resolved = path.resolve(workspace, filePath);

  // Check the path is within workspace BEFORE following symlinks
  if (!resolved.startsWith(workspace)) {
    throw new Error(`Path traversal blocked: ${filePath} resolves outside workspace`);
  }

  // If the file exists, resolve symlinks and recheck
  if (fs.existsSync(resolved)) {
    const real = fs.realpathSync(resolved);
    if (!real.startsWith(workspace)) {
      throw new Error(`Symlink escape blocked: ${filePath} points to ${real} outside workspace`);
    }
    return real;
  }

  // File doesn't exist yet (Write/create), resolved path is fine
  return resolved;
}

// CRIT-02 fix: normalize tool names for case-insensitive matching
function normalizeToolName(name) {
  if (!name || typeof name !== 'string') return '';
  // Map known tool names case-insensitively
  const knownTools = ['Bash', 'Read', 'Write', 'Edit', 'Glob', 'Grep', 'WebFetch', 'WebSearch'];
  const lower = name.toLowerCase();
  const match = knownTools.find(t => t.toLowerCase() === lower);
  return match || name; // return canonical name if known, original if unknown
}

function getAvailableTools() {
  // Bash description changes based on policy: tell the agent WHAT it can do, not WHY.
  // This reduces wasted tokens and turns (Claude Code SDK issue #21773).
  const bashDesc = policy.bashMode === 'allowlist'
    ? 'Execute an allowed command (npm test, npm run, node, python, go test, cargo test, make, jest, eslint, git status/log/diff). Other commands are blocked.'
    : policy.bashMode === 'none'
      ? 'Not available'
      : 'Execute a shell command';

  const allTools = [
    { name: 'Bash', description: bashDesc, inputSchema: { type: 'object', properties: { command: { type: 'string' } }, required: ['command'] } },
    { name: 'Read', description: 'Read a file', inputSchema: { type: 'object', properties: { file_path: { type: 'string' } }, required: ['file_path'] } },
    { name: 'Write', description: 'Write a file', inputSchema: { type: 'object', properties: { file_path: { type: 'string' }, content: { type: 'string' } }, required: ['file_path', 'content'] } },
    { name: 'Edit', description: 'Edit a file', inputSchema: { type: 'object', properties: { file_path: { type: 'string' }, old_string: { type: 'string' }, new_string: { type: 'string' } }, required: ['file_path', 'old_string', 'new_string'] } },
    { name: 'Glob', description: 'Find files by pattern', inputSchema: { type: 'object', properties: { pattern: { type: 'string' } }, required: ['pattern'] } },
    { name: 'Grep', description: 'Search file contents', inputSchema: { type: 'object', properties: { pattern: { type: 'string' }, path: { type: 'string' } }, required: ['pattern'] } },
    { name: 'WebFetch', description: 'Fetch a URL', inputSchema: { type: 'object', properties: { url: { type: 'string' } }, required: ['url'] } },
    { name: 'WebSearch', description: 'Search the web', inputSchema: { type: 'object', properties: { query: { type: 'string' } }, required: ['query'] } },
  ];

  // Filter: only show tools the agent can actually use (reduces token waste)
  if (policy.denyAll) {
    return allTools.filter(t => policy.allow.includes(t.name));
  }
  return allTools;
}

function scanForInjection(text) {
  if (!text) return [];
  // MED-01 fix: cap input length
  const capped = text.slice(0, MAX_INPUT_LENGTH);
  const findings = [];
  const ruleIds = SURFACE_RULES.prBody || [];

  for (const rule of RULES) {
    if (!ruleIds.includes(rule.id)) continue;
    if (rule.detect) {
      const matches = rule.detect(capped);
      for (const m of matches) {
        findings.push({ ruleId: rule.id, message: `${rule.name}: ${m.match}` });
      }
      continue;
    }
    if (rule.patterns) {
      for (const pattern of rule.patterns) {
        const match = capped.match(pattern);
        if (match) {
          findings.push({ ruleId: rule.id, message: `${rule.name}: "${match[0].slice(0, 60)}"` });
          break;
        }
      }
    }
  }
  return findings;
}

function logDecision(toolName, toolArgs, decision) {
  const status = decision.allowed ? 'ALLOW' : (effectiveMode === 'enforce' ? 'BLOCK' : 'AUDIT');
  const argSummary = Object.keys(toolArgs).map(k => `${k}=${String(toolArgs[k]).slice(0, 40)}`).join(', ');
  const line = `[${status}] ${toolName}(${argSummary})${decision.reason ? ' | ' + decision.reason : ''}`;
  process.stderr.write(line + '\n');

  const summaryFile = process.env.GITHUB_STEP_SUMMARY;
  if (summaryFile && !decision.allowed) {
    try {
      fs.appendFileSync(summaryFile, `| ${status} | ${toolName} | ${decision.reason || ''} |\n`);
    } catch (e) { /* ignore */ }
  }
}

function respond(id, result, error) {
  const response = { jsonrpc: '2.0', id };
  if (error) {
    response.error = error;
  } else {
    response.result = result;
  }
  process.stdout.write(JSON.stringify(response) + '\n');
}

process.on('beforeExit', () => {
  if (violations.length > 0) {
    process.stderr.write(`\nTrust Badger summary: ${violations.length} violation(s)\n`);
    for (const v of violations) {
      process.stderr.write(`  ${v.tool}: ${v.reason}\n`);
    }
  }
});
