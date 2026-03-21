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
      /\bTool error for command\b/i,
      /\bError:.*\bplease (run|execute|install|try)\b/i,
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
      /`[^`]+`/,
      /\$\{IFS\}/,
      /\{[a-z]+,-[a-z]/i,                          // brace expansion: {curl,-sSfL,...}
      /(curl|wget)\s[^|]*\|\s*(bash|sh|zsh)/i,
      /\bbase64\s+(-d|--decode)\b/i,
      /\beval\s*\(/,
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
