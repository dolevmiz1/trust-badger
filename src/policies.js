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
  const resolved = require('path').resolve(filePath);
  return resolved + '\n' + filePath;
}

module.exports = { POLICIES, evaluatePolicy, ALLOWED_BASH_PREFIXES };
