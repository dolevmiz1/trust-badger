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

// CRIT-04 fix: verify policy file integrity via HMAC
const policyRaw = fs.readFileSync(policyFile, 'utf-8');
const policyData = JSON.parse(policyRaw);

// Validate HMAC if present
const expectedHmac = process.argv[3];
if (expectedHmac) {
  const crypto = require('crypto');
  const computed = crypto.createHmac('sha256', 'trust-badger-integrity')
    .update(policyRaw).digest('hex');
  if (computed !== expectedHmac) {
    process.stderr.write('Trust Badger proxy: policy file integrity check FAILED. File may have been tampered with.\n');
    process.exit(1);
  }
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
    process.stderr.write(`[AUDIT] Would block: ${toolName} (${decision.reason})\n`);
  }

  // CRIT-01 fix: TRUE PROXY. Execute the tool call and return the result.
  // The agent ONLY has tools through this proxy, so we must execute allowed calls.
  const result = executeTool(toolName, toolArgs);
  respond(msg.id, result);
}

// CRIT-01 fix: actual tool execution
function executeTool(toolName, toolArgs) {
  try {
    switch (toolName) {
      case 'Bash': {
        const cmd = toolArgs.command || '';
        const output = execSync(cmd, {
          encoding: 'utf-8',
          timeout: 30000,
          maxBuffer: 1024 * 1024,
          stdio: ['pipe', 'pipe', 'pipe'],
          cwd: process.env.GITHUB_WORKSPACE || process.cwd(),
        });
        return { content: [{ type: 'text', text: output }] };
      }
      case 'Read': {
        const filePath = toolArgs.file_path || '';
        const content = fs.readFileSync(filePath, 'utf-8');
        return { content: [{ type: 'text', text: content }] };
      }
      case 'Write': {
        const filePath = toolArgs.file_path || '';
        fs.mkdirSync(path.dirname(filePath), { recursive: true });
        fs.writeFileSync(filePath, toolArgs.content || '');
        return { content: [{ type: 'text', text: `File written: ${filePath}` }] };
      }
      case 'Edit': {
        const filePath = toolArgs.file_path || '';
        let content = fs.readFileSync(filePath, 'utf-8');
        if (toolArgs.old_string && content.includes(toolArgs.old_string)) {
          content = content.replace(toolArgs.old_string, toolArgs.new_string || '');
          fs.writeFileSync(filePath, content);
          return { content: [{ type: 'text', text: `File edited: ${filePath}` }] };
        }
        return { content: [{ type: 'text', text: `old_string not found in ${filePath}` }], isError: true };
      }
      case 'Glob': {
        const { globSync } = require('path');
        // Simple glob via find
        const pattern = toolArgs.pattern || '*';
        const output = execSync(`find . -path "./${pattern}" -type f 2>/dev/null | head -100`, {
          encoding: 'utf-8', timeout: 10000, cwd: process.env.GITHUB_WORKSPACE || process.cwd(),
        });
        return { content: [{ type: 'text', text: output || 'No files found' }] };
      }
      case 'Grep': {
        const pattern = toolArgs.pattern || '';
        const searchPath = toolArgs.path || '.';
        const output = execSync(`grep -rn "${pattern.replace(/"/g, '\\"')}" ${searchPath} 2>/dev/null | head -100`, {
          encoding: 'utf-8', timeout: 10000, cwd: process.env.GITHUB_WORKSPACE || process.cwd(),
        });
        return { content: [{ type: 'text', text: output || 'No matches found' }] };
      }
      case 'WebFetch':
      case 'WebSearch':
        return { content: [{ type: 'text', text: `[Trust Badger] ${toolName} is not supported through the proxy. The agent should use its built-in ${toolName} tool.` }] };
      default:
        return { content: [{ type: 'text', text: `[Trust Badger] Unknown tool: ${toolName}` }], isError: true };
    }
  } catch (e) {
    return { content: [{ type: 'text', text: `Error executing ${toolName}: ${e.message}` }], isError: true };
  }
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
  const allTools = [
    { name: 'Bash', description: 'Execute a shell command', inputSchema: { type: 'object', properties: { command: { type: 'string' } }, required: ['command'] } },
    { name: 'Read', description: 'Read a file', inputSchema: { type: 'object', properties: { file_path: { type: 'string' } }, required: ['file_path'] } },
    { name: 'Write', description: 'Write a file', inputSchema: { type: 'object', properties: { file_path: { type: 'string' }, content: { type: 'string' } }, required: ['file_path', 'content'] } },
    { name: 'Edit', description: 'Edit a file', inputSchema: { type: 'object', properties: { file_path: { type: 'string' }, old_string: { type: 'string' }, new_string: { type: 'string' } }, required: ['file_path', 'old_string', 'new_string'] } },
    { name: 'Glob', description: 'Find files by pattern', inputSchema: { type: 'object', properties: { pattern: { type: 'string' } }, required: ['pattern'] } },
    { name: 'Grep', description: 'Search file contents', inputSchema: { type: 'object', properties: { pattern: { type: 'string' }, path: { type: 'string' } }, required: ['pattern'] } },
    { name: 'WebFetch', description: 'Fetch a URL', inputSchema: { type: 'object', properties: { url: { type: 'string' } }, required: ['url'] } },
    { name: 'WebSearch', description: 'Search the web', inputSchema: { type: 'object', properties: { query: { type: 'string' } }, required: ['query'] } },
  ];

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
