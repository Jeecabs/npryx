#!/usr/bin/env node
'use strict'
// npryx: a SECURITY-FIRST superset of `npx` (npm exec).
// Forwards every arg to the real npx untouched, but BEFORE letting npm download
// & execute a remote package it shows the trust signals npx hides — install
// scripts, build provenance, age, popularity, deprecation, typosquatting — then
// you decide. FAILS CLOSED: if it can't verify the package it won't auto-run.
// Offers a one-keystroke `--ignore-scripts` safe run, and REMEMBERS prior
// approvals (TOFU trust store) so the prompt keeps meaning something.
//
// ponytail: wrapper, NOT a reimplementation. The install+run stays `npx --yes`;
// we only add the pre-flight. `npm view --json` is the single registry-correct
// source (resolves ranges/tags via the user's .npmrc, incl. private registries).

const { spawn } = require('child_process')
const readline = require('readline/promises')
const os = require('os')
const path = require('path')
const fs = require('fs')

const VALUE_FLAGS = new Set(['-p', '--package', '-c', '--call', '--cache', '--userconfig', '--shell', '-n', '--node-arg'])
const INSTALL_HOOKS = ['preinstall', 'install', 'postinstall']
const TRUST_PATH = path.join(os.homedir(), '.npryx.json')

// Common npx/install targets & known squat victims. Curated to length >= 4 to
// keep edit-distance-1 false positives down. ponytail: a static list, not a live
// popularity feed — covers the names attackers actually impersonate; grow it if
// a real squat slips through. Real packages here never warn (exact match).
const POPULAR = [
  'express', 'cross-env', 'lodash', 'chalk', 'commander', 'request', 'react',
  'react-dom', 'webpack', 'typescript', 'eslint', 'prettier', 'mocha', 'jest',
  'axios', 'moment', 'debug', 'dotenv', 'yargs', 'cowsay', 'create-react-app',
  'nodemon', 'rimraf', 'gulp', 'grunt', 'babel', 'postcss', 'tailwindcss',
  'vite', 'esbuild', 'rollup', 'prisma', 'next', 'svelte', 'electron',
  'puppeteer', 'playwright', 'sharp', 'uuid', 'semver', 'glob', 'husky', 'sigstore'
]

// npm verbs people type from muscle memory. npryx wraps `npx` (npm exec), which
// has no subcommands — `npx install …` RUNS the registry package named "install",
// it does not install anything. Warn (don't block: the package may be intended).
// ponytail: high-precision npm-only verbs; words that double as plausible package
// names (run/test/start/link/pack) are left out to avoid false alarms.
const NPM_SUBCOMMANDS = new Set([
  'install', 'i', 'ci', 'add', 'uninstall', 'remove', 'update', 'upgrade', 'audit', 'dedupe', 'prune'
])

// --- pure, testable arg handling ---------------------------------------------
function targetSpec (args) {
  for (let i = 0; i < args.length; i++) {
    const a = args[i]
    if (a === '-p' || a === '--package') return args[i + 1] || null
    if (a.startsWith('--package=')) return a.slice(10)
    if (VALUE_FLAGS.has(a)) { i++; continue } // skip a "flag value" pair
    if (a.startsWith('-')) continue // some other flag
    return a // first positional = the package
  }
  return null
  // ponytail: heuristic. Exotic flag combos may mis-identify the previewed pkg,
  // but ALL args are still forwarded verbatim, so execution is never wrong —
  // only the preview could be. Full arg parser: add if it actually bites.
}

function splitSpec (spec) {
  if (!spec) return null
  const at = spec.lastIndexOf('@') // lastIndexOf keeps @scope/ intact
  return at > 0
    ? { name: spec.slice(0, at), version: spec.slice(at + 1) }
    : { name: spec, version: null }
}

// Only registry names can be verified via `npm view`. Local paths, URLs and git
// specifiers are explicit user intent — forward them unaltered, don't fail-close.
function isRegistrySpec (name) {
  if (!name) return false
  if (name.startsWith('.') || name.startsWith('/')) return false // local path
  if (name.includes('://') || name.startsWith('git')) return false // url / git
  if (name.startsWith('@')) return name.includes('/') // scoped needs a slash
  return !name.includes('/') // unscoped must not (else it's a git shorthand)
}

// `npm view <range> --json` returns an ascending ARRAY; a single match is an
// OBJECT. Either way we want the highest matching version.
function pickVersion (json) {
  if (Array.isArray(json)) return json.length ? json[json.length - 1] : null
  return json || null
}

function maintainerNames (m) {
  if (!Array.isArray(m)) return []
  return m.map(x => typeof x === 'string' ? x.replace(/ <.*/, '') : (x && x.name)).filter(Boolean)
}

function repoUrl (r) {
  if (!r) return null
  return typeof r === 'string' ? r : (r.url || null)
}

function summarize (json) {
  const v = pickVersion(json)
  if (!v) return null
  const scripts = v.scripts || {}
  const hooks = INSTALL_HOOKS.filter(h => scripts[h])
  const dist = v.dist || {}
  const att = dist.attestations
  return {
    name: v.name,
    version: v.version,
    runsInstallScripts: hooks.length > 0 || v.hasInstallScript === true,
    hooks,
    deprecated: v.deprecated || null,
    published: (v.time && v.time[v.version]) || null,
    maintainers: maintainerNames(v.maintainers),
    repo: repoUrl(v.repository),
    integrity: dist.integrity || null,
    provenance: att ? ((att.provenance && att.provenance.predicateType) || 'attested') : null
  }
}

// Levenshtein — correct over the cheap one-edit special case (this is a security
// signal). Small inputs (package names), so the O(mn) DP is plenty fast.
function editDistance (a, b) {
  const m = a.length
  const n = b.length
  const d = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0))
  for (let i = 0; i <= m; i++) d[i][0] = i
  for (let j = 0; j <= n; j++) d[0][j] = j
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
    }
  }
  return d[m][n]
}

function typosquat (name) {
  if (!name || name.startsWith('@')) return null // squatting targets unscoped names
  if (POPULAR.includes(name)) return null // exact = the real thing
  for (const p of POPULAR) {
    if (Math.abs(p.length - name.length) > 1) continue
    if (editDistance(name, p) <= 1) return p
  }
  return null
}

// TOFU: match on integrity (sha512). Hit -> proceed silently. Name known but
// integrity differs -> a re-publish (possibly hijacked); always re-prompt.
function trustMatch (store, sum) {
  if (!store || !sum) return { status: 'unknown' }
  const e = store[sum.name]
  if (!e) return { status: 'unknown' }
  if (e.integrity && sum.integrity && e.integrity === sum.integrity) return { status: 'trusted', approvedAt: e.approvedAt }
  return { status: 'changed', from: e.version, to: sum.version }
}

// --- presentation (impure: reads the clock) ----------------------------------
function ageDays (iso) {
  if (!iso) return null
  return (Date.now() - new Date(iso).getTime()) / 86400000
}

function ageString (iso) {
  const days = ageDays(iso)
  if (days == null) return 'unknown'
  if (days < 1) return `${Math.round(days * 24)}h ago`
  if (days < 30) return `${Math.round(days)}d ago`
  if (days < 365) return `${Math.round(days / 30)}mo ago`
  return `${(days / 365).toFixed(1)}y ago`
}

function warnings (s, downloads, squat) {
  const w = []
  if (s.runsInstallScripts) w.push(`runs install scripts (${s.hooks.join(', ') || 'hasInstallScript'}) — executes code on install`)
  if (s.deprecated) w.push(`DEPRECATED: ${s.deprecated}`)
  const days = ageDays(s.published)
  if (days != null && days < 30) w.push(`published only ${Math.round(days)}d ago — brand new, little scrutiny yet`)
  if (downloads != null && downloads < 1000) w.push(`only ${downloads.toLocaleString()} weekly downloads — unusually low`)
  if (squat) w.push(`did you mean "${squat}"? "${s.name}" is one edit away from a popular package — possible typosquat`)
  if (NPM_SUBCOMMANDS.has(s.name)) w.push(`"${s.name}" is an npm subcommand — npryx wraps \`npx\` (npm exec), so this RUNS the registry package "${s.name}" rather than performing \`npm ${s.name}\`. Did you mean \`npm ${s.name} …\`?`)
  return w
}

function render (s, ctx) {
  const { requested, downloads, squat, trust } = ctx
  const lines = [
    '',
    '  npryx — about to fetch & run a package from the npm registry',
    ''
  ]
  if (trust && trust.status === 'changed') {
    lines.push(`  ⚠️  CHANGED since you trusted it: ${trust.from} → ${trust.to} (integrity differs).`)
    lines.push('      A hijacked re-publish looks exactly like this. Re-verify before approving.')
    lines.push('')
  }
  lines.push(
    `  package       ${s.name}@${s.version}   (asked: ${requested || 'latest'})`,
    `  published     ${ageString(s.published)}`,
    `  weekly dl     ${downloads != null ? downloads.toLocaleString() : 'unknown'}`,
    `  maintainers   ${s.maintainers.length ? s.maintainers.slice(0, 3).join(', ') + (s.maintainers.length > 3 ? ' …' : '') : 'unknown'}`,
    `  repo          ${s.repo || 'none listed'}`,
    `  integrity     ${s.integrity ? s.integrity.slice(0, 24) + '…' : 'unknown'}`,
    `  provenance    ${s.provenance ? '✓ ' + s.provenance : 'none'}`,
    `  install hook  ${s.runsInstallScripts ? '⚠️  YES — runs code on install' : '✓ none'}`,
    ''
  )
  const w = warnings(s, downloads, squat)
  if (w.length) {
    lines.push(`  ⚠️  ${w.length} warning(s):`)
    w.forEach(x => lines.push(`       • ${x}`))
    lines.push('')
  }
  return lines.join('\n')
}

// --- IO: registry lookup, downloads, trust store, exec -----------------------
function view (query) {
  return new Promise((resolve, reject) => {
    const child = spawn('npm', ['view', query, '--json'], { stdio: ['ignore', 'pipe', 'pipe'] })
    let out = ''
    let err = ''
    child.stdout.on('data', d => { out += d })
    child.stderr.on('data', d => { err += d })
    child.on('error', reject)
    child.on('close', code => {
      if (code !== 0) return reject(new Error(err.trim().split('\n')[0] || `npm view exited ${code}`))
      if (!out.trim()) return reject(new Error('package not found'))
      try { resolve(JSON.parse(out)) } catch { reject(new Error('could not parse npm view output')) }
    })
  })
}

async function weeklyDownloads (name) {
  try {
    const r = await fetch(`https://api.npmjs.org/downloads/point/last-week/${name}`, { signal: AbortSignal.timeout(5000) })
    if (!r.ok) return null
    const j = await r.json()
    return j.downloads ?? null
  } catch { return null } // best-effort, public registry only
}

function loadStore () {
  try { return JSON.parse(fs.readFileSync(TRUST_PATH, 'utf8')) } catch { return {} }
}

function saveStore (store) {
  fs.writeFileSync(TRUST_PATH, JSON.stringify(store, null, 2) + '\n')
}

function recordTrust (sum) {
  if (!sum || !sum.integrity) return
  const store = loadStore()
  store[sum.name] = { version: sum.version, integrity: sum.integrity, approvedAt: new Date().toISOString() }
  saveStore(store)
}

function runNpx (args, opts) {
  const flags = ['--yes']
  if (opts && opts.ignoreScripts) flags.push('--ignore-scripts')
  if (process.env.NPRYX_DRYRUN) { console.error(`  [dry-run] npx ${[...flags, ...args].join(' ')}`); process.exit(0) }
  const child = spawn('npx', [...flags, ...args], { stdio: 'inherit' })
  child.on('exit', code => process.exit(code ?? 0))
  child.on('error', e => { console.error('npryx: failed to launch npx:', e.message); process.exit(1) })
}

async function chooseAction () {
  const rl = readline.createInterface({ input: process.stdin, output: process.stderr })
  const ans = (await rl.question('  [y] run   [s] run with --ignore-scripts (safer)   [a] always-trust this version   [N] abort: ')).trim().toLowerCase()
  rl.close()
  return ans
}

function act (ans, args, sum) {
  if (ans === 'y' || ans === 'yes') return runNpx(args)
  if (ans === 's') return runNpx(args, { ignoreScripts: true })
  if (ans === 'a') { recordTrust(sum); return runNpx(args) }
  console.error('  aborted.')
  process.exit(1)
}

// --- helper subcommands ------------------------------------------------------
function aliasLine () {
  const shell = (process.env.SHELL || '').split('/').pop()
  const map = { zsh: '~/.zshrc', bash: '~/.bashrc', fish: '~/.config/fish/config.fish' }
  const rc = map[shell] || 'your shell startup file'
  const line = shell === 'fish' ? "alias npx 'npryx'" : "alias npx='npryx'"
  return `  # npryx alias — add to ${rc}, then restart your shell:\n  ${line}\n`
}

function printTrustList () {
  const store = loadStore()
  const names = Object.keys(store)
  if (!names.length) { console.log('  npryx: trust store is empty.'); return }
  console.log(`  trusted packages (${TRUST_PATH}):`)
  for (const n of names) console.log(`    ${n}@${store[n].version}   approved ${store[n].approvedAt}`)
}

function forget (name) {
  if (!name) { console.error('  usage: npryx --forget <package>'); process.exit(1) }
  const store = loadStore()
  if (!store[name]) { console.log(`  npryx: "${name}" was not trusted.`); return }
  delete store[name]
  saveStore(store)
  console.log(`  npryx: forgot "${name}".`)
}

// --- main --------------------------------------------------------------------
async function main () {
  const args = process.argv.slice(2)

  if (args[0] === '--alias') { process.stdout.write(aliasLine()); return }
  if (args[0] === '--trust-list') return printTrustList()
  if (args[0] === '--forget') return forget(args[1])

  const spec = splitSpec(targetSpec(args))
  if (!spec || !isRegistrySpec(spec.name)) return runNpx(args) // nothing verifiable → forward

  const isTTY = process.stdin.isTTY && process.stderr.isTTY
  const forceYes = args.includes('--yes') || args.includes('-y') || process.env.NPRYX_YES === '1'
  const allowed = (process.env.NPRYX_ALLOW || '').split(',').map(s => s.trim()).filter(Boolean).includes(spec.name)
  const query = spec.version ? `${spec.name}@${spec.version}` : spec.name

  let json
  try {
    json = await view(query)
  } catch (e) { // FAIL CLOSED: can't verify → never auto-run
    console.error(`\n  ⚠️  npryx: could not verify "${query}" — ${e.message}`)
    console.error('      This may be a typo, an unpublished/private package, or a registry issue.')
    if (forceYes || allowed) return runNpx(args)
    if (!isTTY) { console.error('  Refusing to run an unverified package non-interactively (fail-closed). Set NPRYX_YES=1 or add it to NPRYX_ALLOW.'); process.exit(1) }
    return act(await chooseAction(), args, null)
  }

  const sum = summarize(json)
  const trust = trustMatch(loadStore(), sum)
  if (trust.status === 'trusted') {
    console.error(`  npryx: ${sum.name}@${sum.version} trusted ✓ (approved ${trust.approvedAt})`)
    return runNpx(args)
  }

  const ctx = { requested: spec.version, squat: typosquat(sum.name), trust, downloads: null }
  if (!isTTY) {
    process.stderr.write(render(sum, ctx))
    if (forceYes || allowed) return runNpx(args)
    console.error('  npryx: refusing to auto-run in a non-interactive shell (fail-closed). Set NPRYX_YES=1 or NPRYX_ALLOW to override.')
    process.exit(1)
  }

  ctx.downloads = await weeklyDownloads(sum.name)
  process.stderr.write(render(sum, ctx))
  return act(await chooseAction(), args, sum)
}

// --- self-check: `node npryx.js --selftest` ----------------------------------
function selftest () {
  const assert = require('assert')
  assert.deepStrictEqual(splitSpec('cowsay'), { name: 'cowsay', version: null })
  assert.deepStrictEqual(splitSpec('cowsay@1.2.3'), { name: 'cowsay', version: '1.2.3' })
  assert.deepStrictEqual(splitSpec('@scope/pkg'), { name: '@scope/pkg', version: null })
  assert.deepStrictEqual(splitSpec('@scope/pkg@2'), { name: '@scope/pkg', version: '2' })
  assert.strictEqual(targetSpec(['cowsay', 'hello']), 'cowsay')
  assert.strictEqual(targetSpec(['-p', 'lol', '-c', 'x']), 'lol')
  assert.strictEqual(targetSpec(['--package=foo', 'bar']), 'foo')
  assert.strictEqual(targetSpec(['--cache', '/tmp/x', 'realpkg']), 'realpkg') // value-flag skip
  assert.strictEqual(targetSpec(['--help']), null)
  assert.strictEqual(isRegistrySpec('cowsay'), true)
  assert.strictEqual(isRegistrySpec('@scope/pkg'), true)
  assert.strictEqual(isRegistrySpec('./local'), false)
  assert.strictEqual(isRegistrySpec('github:piuccio/cowsay'), false)
  assert.strictEqual(isRegistrySpec('user/repo'), false)
  assert.strictEqual(pickVersion([{ version: '1.0.0' }, { version: '1.6.0' }]).version, '1.6.0')
  assert.strictEqual(pickVersion({ version: '2.0.0' }).version, '2.0.0')
  const esbuild = { name: 'esbuild', version: '0.28.1', scripts: { postinstall: 'node install.js' }, dist: { integrity: 'sha512-x', attestations: { provenance: { predicateType: 'https://slsa.dev/provenance/v1' } } } }
  const s = summarize(esbuild)
  assert.strictEqual(s.runsInstallScripts, true)
  assert.deepStrictEqual(s.hooks, ['postinstall'])
  assert.strictEqual(s.provenance, 'https://slsa.dev/provenance/v1')
  assert.strictEqual(typosquat('crossenv'), 'cross-env')
  assert.strictEqual(typosquat('expres'), 'express')
  assert.strictEqual(typosquat('express'), null) // exact, not a squat
  assert.strictEqual(typosquat('@scope/express'), null) // scoped, skipped
  const base = { runsInstallScripts: false, deprecated: null, published: null, maintainers: [] }
  const subRe = /npm subcommand/
  assert.ok(warnings({ ...base, name: 'install' }, null, null).some(x => subRe.test(x))) // npx install footgun
  assert.ok(!warnings({ ...base, name: 'cowsay' }, null, null).some(x => subRe.test(x))) // real pkg, no warning
  assert.strictEqual(trustMatch({ esbuild: { integrity: 'sha512-x' } }, s).status, 'trusted')
  assert.strictEqual(trustMatch({ esbuild: { integrity: 'sha512-OLD', version: '0.1.0' } }, s).status, 'changed')
  assert.strictEqual(trustMatch({}, s).status, 'unknown')
  console.log('npryx selftest: OK')
}

if (require.main === module) {
  if (process.argv.includes('--selftest')) selftest()
  else main().catch(e => { console.error('npryx:', e.message); process.exit(1) })
}

module.exports = { targetSpec, splitSpec, isRegistrySpec, pickVersion, summarize, typosquat, trustMatch }
