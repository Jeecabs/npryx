// The opt-in remote scan, end to end. A fake scan service (separate process,
// real Ed25519 signatures) answers per package and logs every request, so we
// can prove nothing is sent unless the user opted in, and that a result can
// only ever add caution.

import { test, before, after } from 'node:test'
import assert from 'node:assert'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawn } from 'node:child_process'
import { npryx as run, check, pkg, skip } from './harness.mjs'

const VIEWS = {
  cowsay: pkg('cowsay', '1.6.0', 'sha512-cow'),
  'evil-pkg': pkg('evil-pkg', '1.0.1', 'sha512-evil'),
  'sus-pkg': pkg('sus-pkg', '2.0.0', 'sha512-sus'),
  'pending-pkg': pkg('pending-pkg', '1.0.0', 'sha512-pend'),
  'forged-pkg': pkg('forged-pkg', '1.0.0', 'sha512-forged'),
  'swapped-pkg': pkg('swapped-pkg', '1.0.0', 'sha512-swap'),
  'slow-pkg': pkg('slow-pkg', '1.0.0', 'sha512-slow'),
  'private-pkg': pkg('private-pkg', '1.0.0', 'sha512-priv', 'https://npm.internal.example')
}

const result = (name, verdict, findings = [], extra = {}) => {
  const v = VIEWS[name]
  return { schema: 1, status: 'done', analyzer: 'fake', name, version: v.version, integrity: v.dist.integrity, previous: { version: '0.9.0', integrity: 'sha512-prev' }, verdict, findings, network: { destinations: [] }, sandbox: null, ...extra }
}
const EXFIL = { id: 'sandbox.canary-exfil', severity: 'confirmed', title: 'sent your npm token over the network', phase: 'install', destinations: ['https://45.77.12.9/c'], new_since_previous: true, source: 'sandbox' }
const COLLECTOR = { id: 'net.collector-destination', severity: 'high', title: 'sends data to a request-catcher service', phase: 'import', destinations: ['https://webhook.site/abc'], new_since_previous: true, source: 'static' }

// What the fake service answers, per package name.
const ANSWERS = {
  cowsay: { status: 200, result: result('cowsay', 'clean') },
  'evil-pkg': { status: 200, result: result('evil-pkg', 'confirmed', [EXFIL]) },
  'sus-pkg': { status: 200, result: result('sus-pkg', 'suspected', [COLLECTOR]) },
  'pending-pkg': { status: 202, result: { ...result('pending-pkg', null), status: 'pending', retry_after_ms: 3000 } },
  'forged-pkg': { status: 200, result: result('forged-pkg', 'confirmed', [EXFIL]), forge: true },
  'swapped-pkg': { status: 200, result: { ...result('swapped-pkg', 'clean'), integrity: 'sha512-someone-else' } },
  'slow-pkg': { status: 200, result: result('slow-pkg', 'clean'), delayMs: 4000 }
}

const keys = crypto.generateKeyPairSync('ed25519')
const PUBKEY = keys.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64')
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'npryx-scan-'))
const LOG = path.join(dir, 'requests.log')
let server
let URL_

before(async () => {
  const forger = crypto.generateKeyPairSync('ed25519').privateKey.export({ format: 'pem', type: 'pkcs8' })
  const script = `
    const http = require('http'), crypto = require('crypto'), fs = require('fs')
    const key = crypto.createPrivateKey(process.env.KEY), forged = crypto.createPrivateKey(process.env.FORGED)
    const answers = JSON.parse(process.env.ANSWERS)
    const sign = (obj, k) => { const p = Buffer.from(JSON.stringify(obj)); return { payload: p.toString('base64'), sig: crypto.sign(null, p, k).toString('base64'), key_id: 'test' } }
    http.createServer((req, res) => {
      fs.appendFileSync(process.env.LOG, JSON.stringify({ url: req.url, auth: req.headers.authorization || null }) + '\\n')
      if (req.url === '/v1/pubkey') return res.end(JSON.stringify({ alg: 'ed25519', key_id: 'test', key: process.env.PUB }))
      const name = decodeURIComponent(req.url.split('/')[3] || '')
      const a = answers[name]
      if (!a) { res.statusCode = 404; return res.end('{"error":"unknown"}') }
      setTimeout(() => { res.statusCode = a.status; res.end(JSON.stringify(sign(a.result, a.forge ? forged : key))) }, a.delayMs || 0)
    }).listen(0, '127.0.0.1', function () { console.log(this.address().port) })`
  server = spawn(process.execPath, ['-e', script], {
    env: { ...process.env, KEY: keys.privateKey.export({ format: 'pem', type: 'pkcs8' }), FORGED: forger, PUB: PUBKEY, ANSWERS: JSON.stringify(ANSWERS), LOG },
    stdio: ['ignore', 'pipe', 'inherit']
  })
  const port = await new Promise(resolve => server.stdout.once('data', d => resolve(String(d).trim())))
  URL_ = `http://127.0.0.1:${port}`
})
after(() => server.kill())

// Run npryx with scanning switched on (unless `env` says otherwise) and
// return what it did plus the requests the scan service saw.
function scanRun ({ argv, env = {}, optIn = true, ...rest }) {
  fs.writeFileSync(LOG, '')
  const on = optIn ? { NPRYX_SCAN_URL: URL_, NPRYX_SCAN_KEY: PUBKEY } : {}
  const got = run({ argv, views: VIEWS, env: { ...on, ...env }, ...rest })
  got.requests = fs.readFileSync(LOG, 'utf8').trim().split('\n').filter(Boolean).map(l => JSON.parse(l))
  return got
}

const REFUSED = { status: 1, npx: [] }
const ALLOW = name => ({ NPRYX_ALLOW: name })

const CASES = [
  // opt-in: nothing leaves the machine unless the user turned scanning on
  { name: 'off by default: no request is made', argv: ['cowsay'], optIn: false, env: ALLOW('cowsay'), expect: { status: 0, requests: 0 } },
  { name: 'private-registry packages are never sent', argv: ['private-pkg'], env: ALLOW('private-pkg'), expect: { status: 0, requests: 0 } },
  { name: 'the request carries name, version and integrity', argv: ['cowsay'], env: ALLOW('cowsay'), expect: { status: 0, requests: 1, url: /^\/v1\/scan\/cowsay\/1\.6\.0\?integrity=sha512-cow&deep=0$/, stderr: /nothing found \(not a guarantee\)/ } },
  { name: 'deep scans are a separate opt-in', argv: ['cowsay'], env: { ...ALLOW('cowsay'), NPRYX_SCAN_DEEP: '1' }, expect: { url: /deep=1$/ } },
  { name: 'the api token is sent as a bearer token', argv: ['cowsay'], env: { ...ALLOW('cowsay'), NPRYX_SCAN_TOKEN: 't0k' }, expect: { auth: 'Bearer t0k' } },

  // results can only add caution
  { name: 'a confirmed threat is refused even with NPRYX_YES', argv: ['evil-pkg'], env: { NPRYX_YES: '1' }, expect: { ...REFUSED, stderr: /confirmed threat[\s\S]*sent your npm token[\s\S]*45\.77\.12\.9[\s\S]*refusing to run/ } },
  { name: 'a confirmed threat is refused even when allowed by name', argv: ['evil-pkg'], env: ALLOW('evil-pkg'), expect: REFUSED },
  { name: 'suspicious findings are shown but do not change the decision', argv: ['sus-pkg'], env: ALLOW('sus-pkg'), expect: { status: 0, stderr: /suspicious[\s\S]*webhook\.site[\s\S]*--ignore-scripts won't help here, this code runs on import/ } },

  // a broken, slow or lying service changes nothing
  { name: 'a pending scan says so and changes nothing', argv: ['pending-pkg'], env: ALLOW('pending-pkg'), expect: { status: 0, stderr: /queued, run again/ } },
  { name: 'a forged signature is ignored', argv: ['forged-pkg'], env: ALLOW('forged-pkg'), expect: { status: 0, stderr: /unavailable \(signature does not verify\)/ } },
  { name: 'a result for other bytes is ignored', argv: ['swapped-pkg'], env: ALLOW('swapped-pkg'), expect: { status: 0, stderr: /different package/ } },
  { name: 'a slow service times out and changes nothing', argv: ['slow-pkg'], env: ALLOW('slow-pkg'), expect: { status: 0, stderr: /unavailable \(timed out\)/ } },
  { name: 'an unreachable service changes nothing', argv: ['cowsay'], optIn: false, env: { ...ALLOW('cowsay'), NPRYX_SCAN_URL: 'http://127.0.0.1:9' }, expect: { status: 0, stderr: /remote scan +unavailable/ } },
  { name: 'without a pinned key, results are marked unsigned', argv: ['cowsay'], env: { ...ALLOW('cowsay'), NPRYX_SCAN_KEY: '' }, expect: { stderr: /nothing found \(not a guarantee\) \(unsigned\)/ } }
]

for (const { name, expect, ...setup } of CASES) {
  test(name, { skip }, () => {
    const got = scanRun(setup)
    check(got, expect)
    if ('requests' in expect) assert.strictEqual(got.requests.length, expect.requests, 'requests')
    if (expect.url) assert.match(got.requests[0].url, expect.url)
    if (expect.auth) assert.strictEqual(got.requests[0].auth, expect.auth)
  })
}

test('--scan-config pins the service key into a private config file', { skip }, () => {
  const setup = scanRun({ argv: ['--scan-config', URL_, '--deep'], optIn: false })
  assert.match(setup.stdout, /pinned the service's signing key test/)
  const file = setup.home('.npryx-scan.json')
  const saved = JSON.parse(fs.readFileSync(file, 'utf8'))
  assert.deepStrictEqual({ ...saved }, { url: URL_, token: null, key: PUBKEY, deep: true })
  assert.strictEqual(fs.statSync(file).mode & 0o777, 0o600, 'config holds a token, so it is private')
})

test('--scan-status says scanning is off by default', { skip }, () => {
  check(scanRun({ argv: ['--scan-status'], optIn: false }), { stdout: /remote scanning is off \(the default\)/ })
})
