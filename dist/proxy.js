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
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

// Default policies per trust level.

// Bash command allow list for contributor level.
// Only these command prefixes are permitted. Everything else is blocked.
const ALLOWED_BASH_PREFIXES = [
  'npm test', 'npm run ', 'npm ci', 'npm ls', 'npm info', 'npm view', 'npm outdated',
  'npx jest', 'npx eslint', 'npx tsc', 'npx prettier', 'npx vitest',
  'node ', 'node --',
  'python ', 'python3 ', 'pytest', 'pip list', 'pip show',
  'go test', 'go build', 'go vet', 'go fmt',
  'cargo test', 'cargo build', 'cargo check', 'cargo clippy', 'cargo fmt',
  'make ', 'make\n', 'cmake ',
  'jest ', 'jest\n',
  'eslint ', 'tsc ', 'tsc\n',
  'cat ', 'head ', 'tail ', 'wc ', 'sort ', 'uniq ', 'diff ',
  'ls ', 'ls\n', 'pwd', 'echo ', 'date',
  'git status', 'git log', 'git diff', 'git show', 'git branch', 'git remote',
];

const POLICIES = {
  untrusted: {
    label: 'untrusted',
    description: 'Fork PRs, first-time contributors, unknown actors, triage permission',
    allow: ['Read', 'Glob', 'Grep', 'WebFetch', 'WebSearch'],
    denyAll: true,
    deny: [],
    bashMode: 'none', // no Bash at all
  },

  contributor: {
    label: 'contributor',
    description: 'Collaborators with read/write permission, bots',
    allow: ['Bash', 'Read', 'Write', 'Edit', 'Glob', 'Grep', 'WebFetch', 'WebSearch'],
    denyAll: true,
    deny: [
      {
        tool: 'Edit',
        when: {
          argKey: 'file_path',
          regex: /(\.github\/workflows\/|\.github\/copilot|CLAUDE\.md|\.cursorrules|\.cursorignore|\.clinerules|\.clineignore|copilot-instructions|AGENTS\.(md|yaml)|\.windsurfrules|mcp[\-.].*\.json|\.claude\/)/i,
        },
        reason: 'Agent config and workflow files cannot be modified at contributor trust level',
      },
      {
        tool: 'Write',
        when: {
          argKey: 'file_path',
          regex: /(\.github\/workflows\/|\.github\/copilot|CLAUDE\.md|\.cursorrules|\.cursorignore|\.clinerules|\.clineignore|copilot-instructions|AGENTS\.(md|yaml)|\.windsurfrules|mcp[\-.].*\.json|\.claude\/)/i,
        },
        reason: 'Agent config and workflow files cannot be created at contributor trust level',
      },
    ],
    bashMode: 'allowlist', // only ALLOWED_BASH_PREFIXES permitted
  },

  trusted: {
    label: 'trusted',
    description: 'Repo admins',
    allow: ['Bash', 'Read', 'Write', 'Edit', 'Glob', 'Grep', 'WebFetch', 'WebSearch'],
    denyAll: false,
    deny: [],
    bashMode: 'all', // no restrictions
  },
};

function evaluatePolicy(policy, toolName, toolArgs) {
  // Bash allow list enforcement (replaces regex deny list)
  if (toolName.toLowerCase() === 'bash' && policy.bashMode === 'allowlist') {
    const cmd = (toolArgs?.command || '').trim();
    const isAllowed = ALLOWED_BASH_PREFIXES.some(prefix =>
      cmd === prefix.trim() || cmd.startsWith(prefix)
    );
    if (!isAllowed) {
      return {
        allowed: false,
        reason: `Bash command not in allow list. Allowed prefixes: npm test, npm run, node, python, go test, cargo test, make, jest, eslint, git status/log/diff. Use a more specific command.`,
      };
    }
  }

  // Bash completely blocked for untrusted
  if (toolName.toLowerCase() === 'bash' && policy.bashMode === 'none') {
    return { allowed: false, reason: `Bash is not allowed at ${policy.label} trust level` };
  }

  // Check explicit deny rules (file path restrictions)
  for (const rule of policy.deny) {
    if (rule.tool.toLowerCase() !== toolName.toLowerCase()) continue;

    if (rule.when) {
      const argValue = toolArgs?.[rule.when.argKey];
      if (argValue) {
        const regex = rule.when.regex instanceof RegExp
          ? rule.when.regex
          : new RegExp(rule.when.regex.source || rule.when.regex, rule.when.regex.flags || 'i');

        const testValue = rule.when.argKey === 'file_path'
          ? canonicalizePath(argValue)
          : argValue;

        if (regex.test(testValue)) {
          return { allowed: false, reason: rule.reason };
        }
      }
    } else {
      return { allowed: false, reason: rule.reason || `Tool "${toolName}" is denied` };
    }
  }

  // Allow list check (case-insensitive)
  const allowLower = policy.allow.map(a => a.toLowerCase());
  if (allowLower.includes('*') || allowLower.includes(toolName.toLowerCase())) {
    return { allowed: true };
  }

  if (policy.denyAll) {
    return { allowed: false, reason: `Tool "${toolName}" is not allowed at ${policy.label} trust level` };
  }

  return { allowed: true };
}

function canonicalizePath(filePath) {
  if (!filePath) return '';
  const resolved = (__nccwpck_require__(928).resolve)(filePath);
  return resolved + '\n' + filePath;
}

module.exports = { POLICIES, evaluatePolicy, ALLOWED_BASH_PREFIXES };


/***/ }),

/***/ 317:
/***/ ((module) => {

"use strict";
module.exports = require("child_process");

/***/ }),

/***/ 982:
/***/ ((module) => {

"use strict";
module.exports = require("crypto");

/***/ }),

/***/ 896:
/***/ ((module) => {

"use strict";
module.exports = require("fs");

/***/ }),

/***/ 928:
/***/ ((module) => {

"use strict";
module.exports = require("path");

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
// True intercepting proxy: evaluates policy, executes allowed calls, blocks denied ones.
// The agent ONLY has access to tools through this proxy.

const fs = __nccwpck_require__(896);
const path = __nccwpck_require__(928);
const readline = __nccwpck_require__(785);
const { execSync } = __nccwpck_require__(317);
const { evaluatePolicy, POLICIES } = __nccwpck_require__(935);
const { RULES, SURFACE_RULES } = __nccwpck_require__(386);

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
const crypto = __nccwpck_require__(982);
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
            const { execFileSync } = __nccwpck_require__(317);
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
        const { execFileSync } = __nccwpck_require__(317);
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
        const { execFileSync } = __nccwpck_require__(317);
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

module.exports = __webpack_exports__;
/******/ })()
;