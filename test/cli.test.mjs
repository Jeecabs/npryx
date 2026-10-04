// npryx end to end. Fake `npm`/`npx` sit first on PATH: npm answers `npm view`
// from fixtures, npx records what it was asked to run. stdin isn't a TTY, so
// these are the CI paths — where a wrong decision runs code nobody saw.
// Each case: argv (+ env, trust store, project dir), then what must happen.

import { test } from 'node:test'
import fs from 'node:fs'
import path from 'node:path'
import { npryx as run, check, pkg, skip } from './harness.mjs'

const COWSAY = pkg('cowsay', '1.6.0', 'sha512-cow')
const VIEWS = {
  cowsay: COWSAY,
  'cowsay@^1': [pkg('cowsay', '1.5.0', 'sha512-old'), COWSAY],
  'left-pad': pkg('left-pad', '1.3.0', 'sha512-pad'),
  'gitmoji-cli': pkg('gitmoji-cli', '9.0.0', 'sha512-git')
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

  // runs — always pinned to what was previewed
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
  { name: 'death by signal is not success', argv: ['-y', 'cowsay'], env: { FAKE_SIGNAL: 'SIGTERM' }, expect: { signal: 'SIGTERM' } }
]

for (const { name, expect, ...setup } of CASES) test(name, { skip }, () => check(run({ views: VIEWS, ...setup }), expect))
