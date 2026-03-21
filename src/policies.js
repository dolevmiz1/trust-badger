// Default policies per trust level.
// These define what tools the agent can use based on who triggered the workflow.

const POLICIES = {
  untrusted: {
    label: 'untrusted',
    description: 'Fork PRs, first-time contributors, unknown actors',
    allow: ['Read', 'Glob', 'Grep', 'WebFetch', 'WebSearch'],
    denyAll: true,
    deny: [],
  },

  // HIGH-04 fix: explicit allow list instead of wildcard
  contributor: {
    label: 'contributor',
    description: 'Repo collaborators with read permission',
    allow: ['Bash', 'Read', 'Write', 'Edit', 'Glob', 'Grep', 'WebFetch', 'WebSearch'],
    denyAll: true, // deny unknown tools (HIGH-04 fix)
    deny: [
      {
        tool: 'Bash',
        // HIGH-01 fix: broader deny patterns including common bypasses
        when: {
          argKey: 'command',
          regex: /(rm\s+(-\w+\s+)*(-\w*f|-\w*r\b).*(-\w*f|-\w*r\b)|rm\s+-rf|rm\s+.*--force|find\s.*-delete|git\s+push|npm\s+publish|npx\s+npm\s+publish|curl\s.*\|\s*(bash|sh)|wget\s.*\|\s*(bash|sh)|bash\s+-c\s*"\$\(|npm\s+install\s+(github:|git\+|https?:\/\/)|yarn\s+add\s+(github:|git\+)|pnpm\s+add\s+(github:|git\+)|pip\s+install\s+git\+)/i,
        },
        reason: 'Destructive or untrusted install command blocked for contributor trust level',
      },
      {
        tool: 'Edit',
        when: {
          argKey: 'file_path',
          // HIGH-02 fix: broader config file matching including .claude/ paths
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
  },

  trusted: {
    label: 'trusted',
    description: 'Repo admins and maintainers (write+ permission)',
    allow: ['Bash', 'Read', 'Write', 'Edit', 'Glob', 'Grep', 'WebFetch', 'WebSearch'],
    denyAll: false,
    deny: [],
  },
};

function evaluatePolicy(policy, toolName, toolArgs) {
  // CRIT-02 fix: tool name normalization is done in proxy.js before calling this.
  // But as defense in depth, also do case-insensitive matching here.

  for (const rule of policy.deny) {
    // Case-insensitive tool name matching
    if (rule.tool.toLowerCase() !== toolName.toLowerCase()) continue;

    if (rule.when) {
      const argValue = toolArgs?.[rule.when.argKey];
      if (argValue) {
        const regex = rule.when.regex instanceof RegExp
          ? rule.when.regex
          : new RegExp(rule.when.regex.source || rule.when.regex, rule.when.regex.flags || 'i');

        // HIGH-02 fix: canonicalize file paths before matching
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

  // Case-insensitive allow list check
  const allowLower = policy.allow.map(a => a.toLowerCase());
  if (allowLower.includes('*') || allowLower.includes(toolName.toLowerCase())) {
    return { allowed: true };
  }

  if (policy.denyAll) {
    return { allowed: false, reason: `Tool "${toolName}" is not allowed at ${policy.label} trust level` };
  }

  return { allowed: true };
}

// HIGH-02 fix: resolve path traversal and normalize
function canonicalizePath(filePath) {
  if (!filePath) return '';
  // Resolve relative paths to catch traversal attacks like ../../.github/workflows/
  const resolved = require('path').resolve(filePath);
  // Also check the original (in case the config file name is at the end of a deeper path)
  return resolved + '\n' + filePath;
}

module.exports = { POLICIES, evaluatePolicy };
