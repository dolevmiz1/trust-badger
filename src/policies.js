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
