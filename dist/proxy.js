/******/ (() => { // webpackBootstrap
/******/ 	var __webpack_modules__ = ({

/***/ 386:
/***/ ((module) => {

// Detection patterns derived from real Q1 2026 attacks.
// Each rule maps to a documented incident.

const RULES = [
  // Rule 1: Prompt injection phrases
  // Catches: PromptPwnd, generic injection, Rules File Backdoor suppression
  {
    id: 'prompt-injection',
    name: 'Prompt injection phrase detected',
    severity: 'high',
    patterns: [
      /\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|all|earlier|system)\b.{0,40}\b(instructions?|prompts?|rules?|context|guidelines?)\b/i,
      /\b(you are now|act as|pretend to be|from now on you|you must now)\b/i,
      /\bnew (system |)instructions?:/i,
      /\bsystem prompt:/i,
      /\bIMPORTANT:\s*(override|ignore|disregard|new instructions)/i,
      /--\s*(additional|new|updated|override)\s+\w+\.\w+\s+(instruction|config|rule|setting)/i,
      /\b(do not mention|never reveal|hide this from|don't tell|never discuss|keep (this|it) secret)\b/i,
      /\b(do not|never|don't)\s+(log|report|output|display|show|mention)\s+(the |this |these |any )?(change|modification|instruction|action)/i,
    ],
  },

  // Rule 2: Fake context / error simulation
  // Catches: Clinejection (faked npm error), Hackerbot Claw vs Datadog (<override> tags)
  {
    id: 'fake-context',
    name: 'Fake context or error simulation detected',
    severity: 'critical',
    patterns: [
      /\[RESTORE CONTEXT\]/i,
      /\[SYSTEM\]/i,
      /\[ADMIN\]/i,
      /\[INST\]/i,
      /\bTool error\b/i,
      /\bError[.:].{0,80}\b(please |you will need to |you need to |you must )(run|execute|install|try)\b/i,
      /<\s*(override|system|instructions?|admin|prompt)\s*>/i,
      /<\s*\/(override|system|instructions?|admin|prompt)\s*>/i,
      /```system\b/i,
      /\bAssistant:\s/,
      /\bSystem:\s/,
      /\bHuman:\s/,
    ],
  },

  // Rule 3: HTML comment injection
  // Catches: RoguePilot (hid entire attack chain in HTML comments)
  {
    id: 'html-comment-injection',
    name: 'Suspicious HTML comment detected',
    severity: 'critical',
    patterns: [
      /<!--[\s\S]{0,2000}?(copilot|claude|gemini|gpt|cline|cursor|devin|agent|assistant)[\s\S]{0,2000}?-->/i,
      /<!--[\s\S]{0,2000}?(instruction|ignore|override|execute|secret|token|password|credential)[\s\S]{0,2000}?-->/i,
      /<!--[\s\S]{0,2000}?(run:|exec:|curl |wget |bash |sh )[\s\S]{0,2000}?-->/i,
      /<!--[\s\S]{0,2000}?(gh\s+(issue|pr|api)\s+)[\s\S]{0,2000}?-->/i,
    ],
  },

  // Rule 4: Hidden Unicode
  // Catches: Rules File Backdoor (encoded payloads in invisible chars)
  {
    id: 'hidden-unicode',
    name: 'Hidden Unicode characters detected',
    severity: 'high',
    detect: (text) => {
      const zwChars = /[\u200B\u200C\u200D\u200E\u200F\u2060\u2061\u2062\u2063\u2064\uFEFF\u00AD\u034F\u17B4\u17B5]/;
      const bidiMarkers = /[\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069]/;

      const matches = [];
      if (zwChars.test(text)) {
        const count = (text.match(new RegExp(zwChars.source, 'g')) || []).length;
        matches.push({ match: `${count} zero-width character(s) found`, index: text.search(zwChars) });
      }
      if (bidiMarkers.test(text)) {
        const count = (text.match(new RegExp(bidiMarkers.source, 'g')) || []).length;
        matches.push({ match: `${count} bidirectional marker(s) found`, index: text.search(bidiMarkers) });
      }
      return matches;
    },
  },

  // Rule 5: Shell injection in metadata
  // Catches: Hackerbot Claw (command substitution in branch names + base64 in filenames)
  {
    id: 'shell-injection',
    name: 'Shell injection in metadata detected',
    severity: 'critical',
    patterns: [
      /\$\([^)]+\)/,
      /\$\{IFS\}/,
      /\{[a-z]+,-[a-z]/i,                          // brace expansion: {curl,-sSfL,...}
      /(curl|wget)\s[^|]*\|\s*(bash|sh|zsh)/i,
      /\bbase64\s+(-d|--decode)\b/i,
      /\beval\s*\(/,
    ],
    // Backticks are only suspicious in metadata (branch names, filenames),
    // not in PR/issue bodies where they are normal markdown formatting
    metadataOnlyPatterns: [
      /`[^`]+`/,
    ],
  },

  // Rule 6: Token/secret exfiltration language
  // Catches: PromptPwnd (exfiltrated tokens via gh issue edit)
  {
    id: 'exfiltration',
    name: 'Token/secret exfiltration language detected',
    severity: 'critical',
    patterns: [
      /(exfiltrate|leak|steal|extract|send|post|upload|forward).{0,60}(secret|token|key|credential|password|GITHUB_TOKEN|API_KEY|PAT|NPM_TOKEN)/i,
      /(secret|token|key|credential|password|GITHUB_TOKEN|API_KEY|PAT|NPM_TOKEN).{0,60}(exfiltrate|leak|steal|extract|send|post|upload|forward|curl|wget|fetch)/i,
      /(curl|wget|fetch)\s[^\n]{0,120}(GITHUB_TOKEN|API_KEY|SECRET|CREDENTIAL|PAT|NPM_TOKEN)/i,
      /gh\s+(issue|pr)\s+(edit|create|comment).{0,60}(TOKEN|SECRET|KEY|CRED)/i,
      /\$\{\{\s*secrets\./,                         // ${{ secrets.* }} in user-controlled text
    ],
  },

  // Rule 7: Agent config file changes (detection by filename, not regex on content)
  {
    id: 'agent-config-change',
    name: 'Agent config file modified',
    severity: 'medium',
    configFiles: [
      '.cursorrules',
      '.cursorignore',
      'CLAUDE.md',
      '.github/copilot-instructions.md',
      'AGENTS.md',
      'AGENTS.yaml',
      '.windsurfrules',
      '.clinerules',
      '.clineignore',
      'mcp.json',
      'mcp-servers.json',
    ],
    configDirPrefixes: [
      '.claude/',
    ],
  },
];

// Which rules apply to which scan surfaces
const SURFACE_RULES = {
  prTitle:     ['prompt-injection', 'fake-context', 'hidden-unicode', 'shell-injection', 'exfiltration'],
  prBody:      ['prompt-injection', 'fake-context', 'html-comment-injection', 'hidden-unicode', 'shell-injection', 'exfiltration'],
  branchName:  ['shell-injection'],
  commitMsg:   ['prompt-injection', 'fake-context', 'hidden-unicode', 'exfiltration'],
  issueTitle:  ['prompt-injection', 'fake-context', 'hidden-unicode', 'shell-injection', 'exfiltration'],
  issueBody:   ['prompt-injection', 'fake-context', 'html-comment-injection', 'hidden-unicode', 'shell-injection', 'exfiltration'],
  filename:    ['shell-injection'],
};

module.exports = { RULES, SURFACE_RULES };


/***/ }),

/***/ 935:
/***/ ((module) => {

// Default policies per trust level.
// These define what tools the agent can use based on who triggered the workflow.

const POLICIES = {
  untrusted: {
    label: 'untrusted',
    description: 'Fork PRs, first-time contributors, unknown actors',
    allow: ['Read', 'Glob', 'Grep', 'WebFetch', 'WebSearch'],
    denyAll: true, // deny everything not in allow list
    deny: [],
  },

  contributor: {
    label: 'contributor',
    description: 'Repo collaborators with read permission',
    allow: ['*'],
    denyAll: false,
    deny: [
      {
        tool: 'Bash',
        when: { argKey: 'command', regex: /(rm\s+-rf|git\s+push|npm\s+publish|curl\s[^|]*\|\s*(bash|sh)|wget\s[^|]*\|\s*(bash|sh)|npm\s+install\s+github:|pip\s+install\s+git\+)/i },
        reason: 'Destructive or untrusted install command blocked for contributor trust level',
      },
      {
        tool: 'Edit',
        when: { argKey: 'file_path', regex: /(\.github\/workflows\/|CLAUDE\.md|\.cursorrules|\.cursorignore|\.clinerules|copilot-instructions\.md|AGENTS\.md|AGENTS\.yaml|\.windsurfrules|mcp\.json|mcp-servers\.json)/i },
        reason: 'Agent config and workflow files cannot be modified at contributor trust level',
      },
      {
        tool: 'Write',
        when: { argKey: 'file_path', regex: /(\.github\/workflows\/|CLAUDE\.md|\.cursorrules|\.cursorignore|\.clinerules|copilot-instructions\.md|AGENTS\.md|AGENTS\.yaml|\.windsurfrules|mcp\.json|mcp-servers\.json)/i },
        reason: 'Agent config and workflow files cannot be created at contributor trust level',
      },
    ],
  },

  trusted: {
    label: 'trusted',
    description: 'Repo admins and maintainers (write+ permission)',
    allow: ['*'],
    denyAll: false,
    deny: [],
  },
};

function evaluatePolicy(policy, toolName, toolArgs) {
  // Check explicit deny rules first (with conditional matching)
  for (const rule of policy.deny) {
    if (rule.tool !== toolName) continue;

    if (rule.when) {
      const argValue = toolArgs?.[rule.when.argKey];
      if (argValue) {
        const regex = rule.when.regex instanceof RegExp
          ? rule.when.regex
          : new RegExp(rule.when.regex.source || rule.when.regex, rule.when.regex.flags || 'i');
        if (regex.test(argValue)) {
          return { allowed: false, reason: rule.reason };
        }
      }
    } else {
      // Unconditional deny
      return { allowed: false, reason: rule.reason || `Tool "${toolName}" is denied` };
    }
  }

  // Check allow list
  if (policy.allow.includes('*') || policy.allow.includes(toolName)) {
    return { allowed: true };
  }

  // If denyAll is set, block anything not in allow
  if (policy.denyAll) {
    return { allowed: false, reason: `Tool "${toolName}" is not allowed at ${policy.label} trust level` };
  }

  return { allowed: true };
}

module.exports = { POLICIES, evaluatePolicy };


/***/ }),

/***/ 896:
/***/ ((module) => {

"use strict";
module.exports = require("fs");

/***/ }),

/***/ 785:
/***/ ((module) => {

"use strict";
module.exports = require("readline");

/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __nccwpck_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		var threw = true;
/******/ 		try {
/******/ 			__webpack_modules__[moduleId](module, module.exports, __nccwpck_require__);
/******/ 			threw = false;
/******/ 		} finally {
/******/ 			if(threw) delete __webpack_module_cache__[moduleId];
/******/ 		}
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/compat */
/******/ 	
/******/ 	if (typeof __nccwpck_require__ !== 'undefined') __nccwpck_require__.ab = __dirname + "/";
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
// Trust Badger MCP Proxy
// Stdio MCP server that intercepts tool calls and enforces policies.
// Launched by the AI agent via --mcp-config.

const fs = __nccwpck_require__(896);
const readline = __nccwpck_require__(785);
const { evaluatePolicy } = __nccwpck_require__(935);
const { RULES, SURFACE_RULES } = __nccwpck_require__(386);

// Load policy written by setup.js
const policyFile = process.env.TRUST_BADGER_POLICY;
if (!policyFile || !fs.existsSync(policyFile)) {
  process.stderr.write('Trust Badger proxy: no policy file found. Exiting.\n');
  process.exit(1);
}

const policyData = JSON.parse(fs.readFileSync(policyFile, 'utf-8'));
const { trustLevel, mode } = policyData;
// Import policies directly to preserve RegExp objects (JSON serialization strips them)
const { POLICIES } = __nccwpck_require__(935);
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

module.exports = __webpack_exports__;
/******/ })()
;