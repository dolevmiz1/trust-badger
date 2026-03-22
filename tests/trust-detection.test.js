const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert');

// Mock @actions/core before importing setup.js
const logs = [];
const mockCore = {
  info: (msg) => logs.push(msg),
  warning: (msg) => logs.push(`WARN: ${msg}`),
  setFailed: (msg) => logs.push(`FAIL: ${msg}`),
  getInput: () => '',
  setOutput: () => {},
};

// We need to require detectTrustLevel, but setup.js requires @actions/core.
// Inject mock before requiring.
require.cache[require.resolve('@actions/core')] = {
  id: require.resolve('@actions/core'),
  filename: require.resolve('@actions/core'),
  loaded: true,
  exports: mockCore,
};
require.cache[require.resolve('@actions/github')] = {
  id: require.resolve('@actions/github'),
  filename: require.resolve('@actions/github'),
  loaded: true,
  exports: { getOctokit: () => ({}), context: { payload: {}, repo: { owner: 'test', repo: 'test' } } },
};

const { detectTrustLevel } = require('../src/setup');

function mockOctokit(roleOrError) {
  if (roleOrError instanceof Error) {
    return {
      rest: { repos: { getCollaboratorPermissionLevel: async () => { throw roleOrError; } } },
    };
  }
  const role = roleOrError;
  // Map role_name to legacy permission field
  const permissionMap = { admin: 'admin', maintain: 'write', write: 'write', triage: 'read', read: 'read' };
  return {
    rest: {
      repos: {
        getCollaboratorPermissionLevel: async () => ({
          data: { role_name: role, permission: permissionMap[role] || 'none' },
        }),
      },
    },
  };
}

function mockContext(payload = {}) {
  return {
    payload,
    repo: { owner: 'dolevmiz1', repo: 'trust-badger' },
  };
}

describe('Trust Detection: fork PRs', () => {
  beforeEach(() => {
    logs.length = 0;
    process.env.GITHUB_EVENT_NAME = 'pull_request';
    process.env.GITHUB_ACTOR = 'attacker';
    process.env.GITHUB_TRIGGERING_ACTOR = 'attacker';
  });

  it('fork PR -> untrusted', async () => {
    const ctx = mockContext({
      pull_request: {
        head: { repo: { fork: true, full_name: 'attacker/repo' } },
        base: { repo: { full_name: 'dolevmiz1/trust-badger' } },
        user: { login: 'attacker', type: 'User' },
      },
      sender: { type: 'User' },
    });
    assert.strictEqual(await detectTrustLevel(mockOctokit('admin'), ctx), 'untrusted');
  });

  it('deleted fork (null head.repo) -> untrusted', async () => {
    const ctx = mockContext({
      pull_request: {
        head: { repo: null },
        user: { login: 'attacker', type: 'User' },
      },
      sender: { type: 'User' },
    });
    assert.strictEqual(await detectTrustLevel(mockOctokit('admin'), ctx), 'untrusted');
  });

  it('PR with undefined head -> untrusted', async () => {
    const ctx = mockContext({
      pull_request: {
        user: { login: 'attacker', type: 'User' },
      },
      sender: { type: 'User' },
    });
    assert.strictEqual(await detectTrustLevel(mockOctokit('admin'), ctx), 'untrusted');
  });
});

describe('Trust Detection: pull_request_target', () => {
  beforeEach(() => {
    logs.length = 0;
    process.env.GITHUB_EVENT_NAME = 'pull_request_target';
    process.env.GITHUB_ACTOR = 'attacker';
    process.env.GITHUB_TRIGGERING_ACTOR = 'attacker';
  });

  it('pull_request_target from different repo -> untrusted', async () => {
    const ctx = mockContext({
      pull_request: {
        head: { repo: { fork: false, full_name: 'attacker/fork' } },
        base: { repo: { full_name: 'dolevmiz1/trust-badger' } },
        user: { login: 'attacker', type: 'User' },
      },
      sender: { type: 'User' },
    });
    assert.strictEqual(await detectTrustLevel(mockOctokit('write'), ctx), 'untrusted');
  });

  it('pull_request_target same-repo, read permission -> untrusted via API', async () => {
    const ctx = mockContext({
      pull_request: {
        head: { repo: { fork: false, full_name: 'dolevmiz1/trust-badger' } },
        base: { repo: { full_name: 'dolevmiz1/trust-badger' } },
        user: { login: 'reader', type: 'User' },
      },
      sender: { type: 'User' },
    });
    assert.strictEqual(await detectTrustLevel(mockOctokit('read'), ctx), 'untrusted');
  });
});

describe('Trust Detection: permission levels', () => {
  beforeEach(() => {
    logs.length = 0;
    process.env.GITHUB_EVENT_NAME = 'push';
    process.env.GITHUB_ACTOR = 'someuser';
    process.env.GITHUB_TRIGGERING_ACTOR = 'someuser';
  });

  it('admin human -> trusted', async () => {
    const ctx = mockContext({ sender: { type: 'User' } });
    assert.strictEqual(await detectTrustLevel(mockOctokit('admin'), ctx), 'trusted');
  });

  it('admin bot -> contributor (capped)', async () => {
    process.env.GITHUB_ACTOR = 'renovate[bot]';
    process.env.GITHUB_TRIGGERING_ACTOR = 'renovate[bot]';
    const ctx = mockContext({ sender: { type: 'Bot' } });
    assert.strictEqual(await detectTrustLevel(mockOctokit('admin'), ctx), 'contributor');
  });

  it('write permission -> contributor', async () => {
    const ctx = mockContext({ sender: { type: 'User' } });
    assert.strictEqual(await detectTrustLevel(mockOctokit('write'), ctx), 'contributor');
  });

  it('maintain permission -> contributor', async () => {
    const ctx = mockContext({ sender: { type: 'User' } });
    assert.strictEqual(await detectTrustLevel(mockOctokit('maintain'), ctx), 'contributor');
  });

  it('read permission -> untrusted', async () => {
    const ctx = mockContext({ sender: { type: 'User' } });
    assert.strictEqual(await detectTrustLevel(mockOctokit('read'), ctx), 'untrusted');
  });

  it('triage permission -> untrusted', async () => {
    const ctx = mockContext({ sender: { type: 'User' } });
    assert.strictEqual(await detectTrustLevel(mockOctokit('triage'), ctx), 'untrusted');
  });

  it('unknown role_name -> untrusted', async () => {
    const ctx = mockContext({ sender: { type: 'User' } });
    assert.strictEqual(await detectTrustLevel(mockOctokit('custom_enterprise_role'), ctx), 'untrusted');
  });

  it('API failure -> untrusted (fail-closed)', async () => {
    const ctx = mockContext({ sender: { type: 'User' } });
    assert.strictEqual(await detectTrustLevel(mockOctokit(new Error('API rate limited')), ctx), 'untrusted');
  });
});

describe('Trust Detection: special events', () => {
  beforeEach(() => {
    logs.length = 0;
    process.env.GITHUB_ACTOR = 'cron-user';
    process.env.GITHUB_TRIGGERING_ACTOR = 'cron-user';
  });

  it('schedule event -> trusted (no external input)', async () => {
    process.env.GITHUB_EVENT_NAME = 'schedule';
    const ctx = mockContext({});
    assert.strictEqual(await detectTrustLevel(mockOctokit('read'), ctx), 'trusted');
  });

  it('issue_comment event falls to API check', async () => {
    process.env.GITHUB_EVENT_NAME = 'issue_comment';
    process.env.GITHUB_ACTOR = 'commenter';
    process.env.GITHUB_TRIGGERING_ACTOR = 'commenter';
    const ctx = mockContext({
      issue: { user: { login: 'commenter', type: 'User' } },
      comment: { body: 'test comment' },
      sender: { type: 'User' },
    });
    assert.strictEqual(await detectTrustLevel(mockOctokit('write'), ctx), 'contributor');
  });

  it('empty payload falls to API check', async () => {
    process.env.GITHUB_EVENT_NAME = 'workflow_dispatch';
    const ctx = mockContext({});
    assert.strictEqual(await detectTrustLevel(mockOctokit('admin'), ctx), 'trusted');
  });
});

describe('Trust Detection: error handling', () => {
  beforeEach(() => {
    logs.length = 0;
    process.env.GITHUB_EVENT_NAME = 'push';
    process.env.GITHUB_ACTOR = 'user';
    process.env.GITHUB_TRIGGERING_ACTOR = 'user';
  });

  it('missing context.repo -> untrusted (P0 fix)', async () => {
    const ctx = {
      payload: {},
      get repo() { throw new Error('GITHUB_REPOSITORY not set'); },
    };
    assert.strictEqual(await detectTrustLevel(mockOctokit('admin'), ctx), 'untrusted');
  });
});
