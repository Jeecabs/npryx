// npryx end to end. Fake `npm`/`npx` sit first on PATH: npm answers `npm view`
// from fixtures, npx records what it was asked to run. stdin isn't a TTY, so
// these are the CI paths, where a wrong decision runs code nobody saw.
// Each case: argv (+ env, trust store, project dir), then what must happen.

import { test } from 'node:test'
import assert from 'node:assert'
import fs from 'node:fs'
import path from 'node:path'
import * as hegel from '@hegeldev/hegel'
import * as gs from '@hegeldev/hegel/generators'
import { npryx as run, check, pkg, skip } from './harness.mjs'

// A private registry, so --json's best-effort download lookup never goes out.
const REG = 'https://npm.internal.example'
const COWSAY = pkg('cowsay', '1.6.0', 'sha512-cow', REG)
const VIEWS = {
  cowsay: COWSAY,
  'cowsay@^1': [pkg('cowsay', '1.5.0', 'sha512-old', REG), COWSAY],
  'left-pad': pkg('left-pad', '1.3.0', 'sha512-pad', REG),
  'gitmoji-cli': pkg('gitmoji-cli', '9.0.0', 'sha512-git', REG),
  expres: { ...pkg('expres', '1.0.0', 'sha512-sq', REG), scripts: { postinstall: 'node x.js' } }
}
const trusted = integrity => ({ cowsay: { '1.6.0': { integrity, approvedAt: 'then' } } })
const withLocalTsc = dir => {
  fs.mkdirSync(path.join(dir, 'node_modules', '.bin'), { recursive: true })
  fs.writeFileSync(path.join(dir, 'node_modules', '.bin', 'tsc'), '')
  fs.writeFileSync(path.join(dir, 'package.json'), '{}')
}

const REFUSED = { status: 1, npx: [] }

const CASES = [
  // fail-closed
  { name: 'unverified package is refused in CI', argv: ['cowsay'], expect: { ...REFUSED, stderr: /refusing to auto-run/ } },
  { name: '-y meant for the package does not opt out', argv: ['cowsay', '-y'], expect: REFUSED },
  { name: 'unknown flag is refused, not guessed', argv: ['--frobnicate', 'x', 'cowsay'], env: { NPRYX_YES: '1' }, expect: { ...REFUSED, stderr: /unrecognised flag/ } },
  { name: 'git-prefixed name is previewed, not waved through', argv: ['gitmoji-cli'], expect: { ...REFUSED, npm: [['view', 'gitmoji-cli', '--json']] } },
  { name: 'git spec is gated, not forwarded with --yes', argv: ['github:u/r'], expect: { ...REFUSED, stderr: /can't verify/ } },
  { name: 'every -p must be cleared', argv: ['-p', 'cowsay', '-p', 'left-pad', 'x'], env: { NPRYX_ALLOW: 'cowsay' }, expect: REFUSED },
  { name: 'allow by name@version must match what resolves', argv: ['cowsay'], env: { NPRYX_ALLOW: 'cowsay@1.5.0' }, expect: REFUSED },
  { name: 'tampered bytes never run, even with NPRYX_YES', argv: ['cowsay'], env: { NPRYX_YES: '1' }, store: trusted('sha512-EVIL'), expect: { ...REFUSED, stderr: /not the bytes you approved/ } },
  { name: 'new version of a trusted package is a calm note', argv: ['cowsay'], store: { cowsay: { '1.5.0': { integrity: 'sha512-old' } } }, expect: { ...REFUSED, stderr: /you trusted cowsay@1\.5\.0; this is 1\.6\.0/ } },

  // runs, always pinned to what was previewed
  { name: 'allowed package runs pinned', argv: ['cowsay@^1', 'moo'], env: { NPRYX_ALLOW: 'cowsay' }, expect: { status: 0, npx: [['--yes', 'cowsay@1.6.0', 'moo']] } },
  { name: 'allow by integrity', argv: ['cowsay'], env: { NPRYX_ALLOW: 'sha512-cow' }, expect: { status: 0, npx: [['--yes', 'cowsay@1.6.0']] } },
  { name: 'leading -y is npx\'s and opts out', argv: ['-y', 'cowsay'], expect: { status: 0, npx: [['--yes', 'cowsay@1.6.0']] } },
  { name: 'all -p packages pinned', argv: ['-p', 'cowsay', '-p', 'left-pad', 'x'], env: { NPRYX_ALLOW: 'cowsay,left-pad' }, expect: { npx: [['--yes', '-p', 'cowsay@1.6.0', '-p', 'left-pad@1.3.0', 'x']] } },
  { name: '--registry reaches the preview too', argv: ['--registry', 'https://r/', 'cowsay'], env: { NPRYX_ALLOW: 'cowsay' }, expect: { npm: [['view', 'cowsay', '--json', '--registry', 'https://r/']], npx: [['--yes', '--registry', 'https://r/', 'cowsay@1.6.0']] } },
  { name: '--loglevel value is not the package', argv: ['--loglevel', 'warn', 'cowsay'], expect: { npm: [['view', 'cowsay', '--json']] } },
  { name: 'trusted version runs with no prompt', argv: ['cowsay'], store: trusted('sha512-cow'), expect: { status: 0, npx: [['--yes', 'cowsay@1.6.0']] } },
  { name: 'v1 trust store still honoured', argv: ['cowsay'], store: { cowsay: { version: '1.6.0', integrity: 'sha512-cow' } }, expect: { status: 0 } },
  { name: 'allowed git spec runs as given', argv: ['github:u/r'], env: { NPRYX_ALLOW: 'github:u/r' }, expect: { npx: [['--yes', 'github:u/r']] } },

  // handed to npx with --no, so npx itself refuses to install
  { name: 'local project bin skips the registry', argv: ['tsc', '-v'], project: withLocalTsc, expect: { npm: [], npx: [['--no', 'tsc', '-v']] } },
  { name: 'nothing to install', argv: ['--help'], expect: { npx: [['--no', '--help']] } },
  { name: 'local path is explicit intent', argv: ['./tool'], expect: { npx: [['--yes', './tool']] } },

  // exit status mirrors the child
  { name: 'exit code passes through', argv: ['-y', 'cowsay'], env: { FAKE_EXIT: '3' }, expect: { status: 3 } },
  { name: 'death by signal is not success', argv: ['-y', 'cowsay'], env: { FAKE_SIGNAL: 'SIGTERM' }, expect: { signal: 'SIGTERM' } },

  // --json: check only, one document on stdout, exit code is the decision
  {
    name: 'json: an untrusted package needs approval, with the pinned command and an exact approval',
    argv: ['--json', 'cowsay@^1', 'moo'],
    expect: {
      status: 3,
      npx: [],
      json: {
        schemaVersion: 1,
        decision: 'needs-approval',
        reason: 'untrusted',
        command: { npx: ['--yes', 'cowsay@1.6.0', 'moo'], npryx: ['cowsay@1.6.0', 'moo'] },
        approve: 'cowsay@1.6.0#sha512-cow',
        packages: [{ requested: 'cowsay@^1', kind: 'registry', resolved: 'cowsay@1.6.0', integrity: 'sha512-cow', publicRegistry: false, trust: { status: 'new', trustedVersions: [] }, warnings: [], scan: null, error: null }]
      }
    }
  },
  { name: 'json: warnings carry stable codes', argv: ['--json', 'expres'], expect: { status: 3, json: { packages: [{ typosquatOf: 'express', installScripts: { runs: true, hooks: ['postinstall'] }, warnings: [{ code: 'install-scripts' }, { code: 'typosquat' }] }] } } },
  { name: 'json: a trusted package is allowed', argv: ['--json', 'cowsay'], store: trusted('sha512-cow'), expect: { status: 0, npx: [], json: { decision: 'allow', reason: 'trusted', approve: null, packages: [{ trust: { status: 'trusted', approvedAt: 'then', trustedVersions: ['1.6.0'] } }] } } },
  { name: 'json: a new version of a trusted package needs approval', argv: ['--json', 'cowsay'], store: { cowsay: { '1.5.0': { integrity: 'sha512-old' } } }, expect: { status: 3, json: { packages: [{ trust: { status: 'updated', trustedVersions: ['1.5.0'] } }] } } },
  { name: 'json: tampered bytes are refused, whatever is allowed', argv: ['--json', 'cowsay'], env: { NPRYX_YES: '1', NPRYX_ALLOW: 'cowsay@1.6.0#sha512-cow' }, store: trusted('sha512-EVIL'), expect: { status: 1, json: { decision: 'refuse', reason: 'tampered', command: null, approve: null, packages: [{ trust: { status: 'tampered' } }] } } },
  { name: 'json: a package that fails lookup is refused as unverifiable', argv: ['--json', 'nope'], expect: { status: 1, json: { decision: 'refuse', reason: 'unverifiable', packages: [{ resolved: null, error: /404/ }] } } },
  { name: 'json: a git spec is refused as unverifiable', argv: ['--json', 'github:u/r'], expect: { status: 1, json: { reason: 'unverifiable', packages: [{ kind: 'remote', error: /outside the npm registry/ }] } } },
  { name: 'json: every -p is reported, and approve covers only what is still pending', argv: ['--json', '-p', 'cowsay', '-p', 'left-pad', 'x'], env: { NPRYX_ALLOW: 'cowsay' }, expect: { status: 3, json: { approve: 'left-pad@1.3.0#sha512-pad', command: { npx: ['--yes', '-p', 'cowsay@1.6.0', '-p', 'left-pad@1.3.0', 'x'] }, packages: [{ decision: 'allow', reason: 'allowed' }, { decision: 'needs-approval' }] } } },
  { name: 'json: the exact approval allows it', argv: ['--json', 'cowsay'], env: { NPRYX_ALLOW: 'cowsay@1.6.0#sha512-cow' }, expect: { status: 0, json: { decision: 'allow', reason: 'allowed' } } },
  { name: 'json: an approval for other bytes does not', argv: ['--json', 'cowsay'], env: { NPRYX_ALLOW: 'cowsay@1.6.0#sha512-other' }, expect: { status: 3 } },
  { name: 'the exact approval runs the pinned version without --json', argv: ['cowsay'], env: { NPRYX_ALLOW: 'cowsay@1.6.0#sha512-cow' }, expect: { status: 0, npx: [['--yes', 'cowsay@1.6.0']] } },
  { name: 'json: a local project bin needs no lookup', argv: ['--json', 'tsc', '-v'], project: withLocalTsc, expect: { status: 0, npm: [], npx: [], json: { decision: 'allow', reason: 'local-bin', command: { npx: ['--no', 'tsc', '-v'] }, packages: [] } } },
  { name: 'json: usage errors are JSON too', argv: ['--json', '--frobnicate', 'x', 'cowsay'], expect: { status: 2, npx: [], json: { schemaVersion: 1, error: { code: 'usage', message: /unrecognised flag/ } } } },
  { name: 'json: no package is a usage error', argv: ['--json'], expect: { status: 2, json: { error: { code: 'usage' } } } },
  { name: 'json: commands that change things have no JSON mode', argv: ['--json', '--forget', 'cowsay'], store: trusted('sha512-cow'), expect: { status: 2, json: { error: { message: /--forget has no JSON mode/ } } } },
  { name: 'json: --trust-list', argv: ['--trust-list', '--json'], store: trusted('sha512-cow'), expect: { status: 0, json: { packages: [{ name: 'cowsay', version: '1.6.0', integrity: 'sha512-cow', approvedAt: 'then' }] } } },
  { name: 'json: --scan-status', argv: ['--json', '--scan-status'], expect: { status: 0, json: { enabled: false, url: null } } }
]

for (const { name, expect, ...setup } of CASES) test(name, { skip }, () => check(run({ views: VIEWS, ...setup }), expect))

// --json never runs anything, always prints one document, and its decision is
// exactly what the same command does without --json: npx runs iff `allow`,
// with the args in `command.npx`.
const SPECS = ['cowsay', 'cowsay@^1', 'left-pad', 'expres', 'nope', 'github:u/r', './tool']
const ARGV = gs.composite(tc => [
  ...tc.draw(gs.arrays(gs.sampledFrom(['-y', '--no', '-q', '--registry=https://r/', '--frobnicate']), { maxSize: 2 })),
  ...tc.draw(gs.arrays(gs.sampledFrom(SPECS).map(s => ['-p', s]), { maxSize: 2 })).flat(),
  ...(tc.draw(gs.booleans()) ? [tc.draw(gs.sampledFrom(SPECS))] : []),
  ...tc.draw(gs.arrays(gs.sampledFrom(['moo', '-y']), { maxSize: 2 }))
])
const ENV = gs.sampledFrom([{}, { NPRYX_YES: '1' }, { NPRYX_ALLOW: 'cowsay,left-pad' }, { NPRYX_ALLOW: 'cowsay@1.6.0#sha512-cow,github:u/r' }])
const STORE = gs.sampledFrom([undefined, trusted('sha512-cow'), trusted('sha512-EVIL')])

test('--json never runs npx, and predicts exactly what the plain run does', { skip }, () => hegel.test(tc => {
  const [argv, env, store] = [tc.draw(ARGV), tc.draw(ENV), tc.draw(STORE)]
  const json = run({ argv: ['--json', ...argv], env, store, views: VIEWS })
  assert.deepStrictEqual(json.npx, [], 'json mode ran npx')
  assert.strictEqual(json.stderr, '', 'json mode is quiet on stderr')
  const doc = JSON.parse(json.stdout)
  assert.strictEqual(doc.schemaVersion, 1)
  if (doc.error) return assert.strictEqual(json.status, doc.error.code === 'usage' ? 2 : 1)
  assert.strictEqual(json.status, { allow: 0, refuse: 1, 'needs-approval': 3 }[doc.decision])
  const plain = run({ argv, env, store, views: VIEWS })
  assert.deepStrictEqual(plain.npx, doc.decision === 'allow' ? [doc.command.npx] : [])
}, { testCases: 10 }))

// --- shell alias: a suggestion, never forced ---------------------------------
test('--setup-alias asks first: without a terminal or --yes it changes nothing', { skip }, () => {
  const r = run({ argv: ['--setup-alias'], env: { SHELL: '/bin/zsh' } })
  assert.strictEqual(r.status, 1)
  assert.match(r.stdout, /This adds the following to .*\.zshrc/)
  assert.ok(!fs.existsSync(r.home('.zshrc')), 'no file written')
})

test('--setup-alias --yes adds a marked block, once; --remove-alias takes it out', { skip }, () => {
  const before = 'export PATH=$PATH:/opt/bin\n'
  const r = run({ argv: ['--setup-alias', '--yes'], env: { SHELL: '/bin/zsh' }, homeFiles: { '.zshrc': before } })
  assert.strictEqual(r.status, 0)
  const rc = fs.readFileSync(r.home('.zshrc'), 'utf8')
  assert.ok(rc.startsWith(before) && rc.includes("alias npx='npryx'"))
  const again = run({ argv: ['--setup-alias', '--yes'], env: { SHELL: '/bin/zsh' }, homeFiles: { '.zshrc': rc } })
  assert.match(again.stdout, /already set up/)
  assert.strictEqual(fs.readFileSync(again.home('.zshrc'), 'utf8'), rc, 'idempotent')
  const removed = run({ argv: ['--remove-alias', '--yes'], env: { SHELL: '/bin/zsh' }, homeFiles: { '.zshrc': rc } })
  assert.strictEqual(fs.readFileSync(removed.home('.zshrc'), 'utf8'), before)
})

test('--setup-alias leaves an existing npx alias of your own alone', { skip }, () => {
  const mine = "alias npx='my-wrapper'\n"
  const r = run({ argv: ['--setup-alias', '--yes'], env: { SHELL: '/bin/bash' }, homeFiles: { '.bashrc': mine, '.bash_profile': mine } })
  assert.strictEqual(r.status, 1)
  assert.match(r.stderr, /already defines its own npx alias/)
})

// --- colour: never in a pipe or log unless asked for -------------------------
const ESC = /\x1b\[/ // eslint-disable-line no-control-regex
const COLOUR_CASES = [
  ['without a terminal', {}, false],
  ['with NO_COLOR', { NO_COLOR: '1' }, false],
  ['with FORCE_COLOR', { FORCE_COLOR: '1' }, true]
]
for (const [when, env, want] of COLOUR_CASES) {
  test(`preview and refusal ${want ? 'are' : 'are not'} coloured ${when}`, { skip }, () => {
    const r = run({ argv: ['cowsay'], views: VIEWS, env })
    assert.match(r.stderr, /cowsay@1\.6\.0: no warnings[\s\S]*refusing to auto-run/)
    assert.strictEqual(ESC.test(r.stderr), want, r.stderr)
    const status = run({ argv: ['--scan-status'], env })
    assert.strictEqual(ESC.test(status.stdout), want, status.stdout)
  })
}
