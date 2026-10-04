// Shared harness for the end-to-end tests. Fake `npm`/`npx` go first on PATH:
// npm answers `npm view` from the given fixtures, npx records what it was asked
// to run. stdin isn't a TTY, so these exercise the non-interactive paths.

import assert from 'node:assert'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawnSync } from 'node:child_process'

export const skip = process.platform === 'win32' && 'fake npm/npx are POSIX shebang scripts'

export const pkg = (name, version, integrity, registry = 'https://registry.npmjs.org') =>
  ({ name, version, dist: { integrity, tarball: `${registry}/${name}/-/${name}-${version}.tgz` } })

export function check (got, want) {
  for (const k of ['status', 'signal', 'npx', 'npm']) if (k in want) assert.deepStrictEqual(got[k], want[k], k)
  if (want.stderr) assert.match(got.stderr, want.stderr)
  if (want.stdout) assert.match(got.stdout, want.stdout)
}

export function npryx ({ argv, env = {}, store, project, views = {} }) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'npryx-'))
  const [bin, home, cwd, log] = ['bin', 'home', 'cwd', 'log'].map(p => path.join(dir, p))
  for (const d of [bin, home, cwd]) fs.mkdirSync(d)
  const record = `require('fs').appendFileSync(${JSON.stringify(log)}, JSON.stringify([process.argv[1].endsWith('npm') ? 'npm' : 'npx', process.argv.slice(2)]) + '\\n')`
  fs.writeFileSync(path.join(bin, 'npm'), `#!/usr/bin/env node\n${record}
const v = ${JSON.stringify(views)}[process.argv[3]]
if (!v) { console.error('npm error 404 Not Found'); process.exit(1) }
console.log(JSON.stringify(v))\n`, { mode: 0o755 })
  fs.writeFileSync(path.join(bin, 'npx'), `#!/usr/bin/env node\n${record}
if (process.env.FAKE_SIGNAL) process.kill(process.pid, process.env.FAKE_SIGNAL)
process.exit(Number(process.env.FAKE_EXIT || 0))\n`, { mode: 0o755 })
  if (store) fs.writeFileSync(path.join(home, '.npryx.json'), JSON.stringify(store))
  if (project) project(cwd)

  const r = spawnSync(process.execPath, [path.join(import.meta.dirname, '..', 'npryx.js'), ...argv], {
    cwd, input: '', encoding: 'utf8', env: { PATH: bin + path.delimiter + process.env.PATH, HOME: home, ...env }
  })
  const calls = fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n').map(l => JSON.parse(l)) : []
  const by = tool => calls.filter(([t]) => t === tool).map(([, a]) => a)
  return { status: r.status, signal: r.signal, stdout: r.stdout, stderr: r.stderr, npx: by('npx'), npm: by('npm'), home: f => path.join(home, f) }
}
