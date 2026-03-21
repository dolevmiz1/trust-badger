// Trust Badger MCP Proxy
// Stdio MCP server that intercepts tool calls and enforces policies.
// Launched by the AI agent via --mcp-config.

const fs = require('fs');
const readline = require('readline');
const { evaluatePolicy } = require('./policies');
const { RULES, SURFACE_RULES } = require('./patterns');

// Load policy written by setup.js
const policyFile = process.env.TRUST_BADGER_POLICY;
if (!policyFile || !fs.existsSync(policyFile)) {
  process.stderr.write('Trust Badger proxy: no policy file found. Exiting.\n');
  process.exit(1);
}

const policyData = JSON.parse(fs.readFileSync(policyFile, 'utf-8'));
const { trustLevel, mode } = policyData;
// Import policies directly to preserve RegExp objects (JSON serialization strips them)
const { POLICIES } = require('./policies');
const policy = POLICIES[trustLevel];
const violations = [];

process.stderr.write(`Trust Badger proxy started (trust: ${trustLevel}, mode: ${mode})\n`);

// MCP stdio transport: read JSON-RPC messages from stdin, write to stdout
const rl = readline.createInterface({ input: process.stdin, terminal: false });
let buffer = '';

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
  // JSON-RPC request
  if (msg.method === 'initialize') {
    // Respond with server info
    respond(msg.id, {
      protocolVersion: '2024-11-05',
      capabilities: { tools: { listChanged: false } },
      serverInfo: { name: 'trust-badger', version: '0.2.0' },
    });
    return;
  }

  if (msg.method === 'notifications/initialized') {
    // Client acknowledged initialization, no response needed
    return;
  }

  if (msg.method === 'tools/list') {
    // Return the tools this proxy exposes
    // We expose wrapper tools that map to the real Claude Code tools
    const tools = getAvailableTools();
    respond(msg.id, { tools });
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

  // Unknown method
  respond(msg.id, null, { code: -32601, message: `Method not found: ${msg.method}` });
}

function handleToolCall(msg) {
  const toolName = msg.params?.name;
  const toolArgs = msg.params?.arguments || {};

  // Evaluate policy
  const decision = evaluatePolicy(policy, toolName, toolArgs);

  // Also scan tool arguments for prompt injection patterns (Layer 2)
  const argText = Object.values(toolArgs).filter(v => typeof v === 'string').join('\n');
  const injectionFindings = scanForInjection(argText);

  if (injectionFindings.length > 0 && trustLevel !== 'trusted') {
    decision.allowed = false;
    decision.reason = `Prompt injection detected in tool arguments: ${injectionFindings[0].message}`;
  }

  // Log the decision
  logDecision(toolName, toolArgs, decision);

  if (!decision.allowed) {
    violations.push({ tool: toolName, reason: decision.reason });

    if (mode === 'enforce') {
      // Block the call
      respond(msg.id, {
        content: [{ type: 'text', text: `[Trust Badger] BLOCKED: ${decision.reason}` }],
        isError: true,
      });
      return;
    }
    // Audit mode: log but allow
    process.stderr.write(`[AUDIT] Would block: ${toolName} (${decision.reason})\n`);
  }

  // Forward the call by executing the tool
  // Since we are a standalone MCP server (not a proxy to another server),
  // we provide the tool results directly based on what we can do.
  // For the MVP, we return a message telling the agent the tool was allowed.
  respond(msg.id, {
    content: [{ type: 'text', text: `[Trust Badger] Tool "${toolName}" is allowed at ${trustLevel} trust level. Please use the tool directly.` }],
  });
}

function getAvailableTools() {
  // Expose tools that map to the real agent tools
  // The agent calls these, we evaluate policy, then let it through
  const allTools = [
    { name: 'Bash', description: 'Execute a shell command', inputSchema: { type: 'object', properties: { command: { type: 'string' } } } },
    { name: 'Read', description: 'Read a file', inputSchema: { type: 'object', properties: { file_path: { type: 'string' } } } },
    { name: 'Write', description: 'Write a file', inputSchema: { type: 'object', properties: { file_path: { type: 'string' }, content: { type: 'string' } } } },
    { name: 'Edit', description: 'Edit a file', inputSchema: { type: 'object', properties: { file_path: { type: 'string' }, old_string: { type: 'string' }, new_string: { type: 'string' } } } },
    { name: 'Glob', description: 'Find files by pattern', inputSchema: { type: 'object', properties: { pattern: { type: 'string' } } } },
    { name: 'Grep', description: 'Search file contents', inputSchema: { type: 'object', properties: { pattern: { type: 'string' } } } },
    { name: 'WebFetch', description: 'Fetch a URL', inputSchema: { type: 'object', properties: { url: { type: 'string' } } } },
    { name: 'WebSearch', description: 'Search the web', inputSchema: { type: 'object', properties: { query: { type: 'string' } } } },
  ];

  // Filter based on policy: only show allowed tools (hides denied tools from the agent)
  if (policy.denyAll) {
    return allTools.filter(t => policy.allow.includes(t.name));
  }
  return allTools;
}

function scanForInjection(text) {
  if (!text) return [];
  const findings = [];
  const ruleIds = SURFACE_RULES.prBody || [];

  for (const rule of RULES) {
    if (!ruleIds.includes(rule.id)) continue;
    if (rule.detect) {
      const matches = rule.detect(text);
      for (const m of matches) {
        findings.push({ ruleId: rule.id, message: `${rule.name}: ${m.match}` });
      }
      continue;
    }
    if (rule.patterns) {
      for (const pattern of rule.patterns) {
        const match = text.match(pattern);
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
  const status = decision.allowed ? 'ALLOW' : (mode === 'enforce' ? 'BLOCK' : 'AUDIT');
  const argSummary = Object.keys(toolArgs).map(k => `${k}=${String(toolArgs[k]).slice(0, 40)}`).join(', ');
  const line = `[${status}] ${toolName}(${argSummary})${decision.reason ? ' | ' + decision.reason : ''}`;
  process.stderr.write(line + '\n');

  // Also write to GITHUB_STEP_SUMMARY if available
  const summaryFile = process.env.GITHUB_STEP_SUMMARY;
  if (summaryFile && !decision.allowed) {
    try {
      fs.appendFileSync(summaryFile, `| ${status} | ${toolName} | ${decision.reason || ''} |\n`);
    } catch (e) {
      // ignore
    }
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

// On exit, write violation summary
process.on('beforeExit', () => {
  if (violations.length > 0) {
    process.stderr.write(`\nTrust Badger summary: ${violations.length} violation(s)\n`);
    for (const v of violations) {
      process.stderr.write(`  ${v.tool}: ${v.reason}\n`);
    }
  }
});
