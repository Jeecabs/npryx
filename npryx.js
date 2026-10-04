#!/usr/bin/env node
'use strict'
// npryx: a SECURITY-FIRST superset of `npx` (npm exec).
// Before npm downloads & executes a remote package, npryx shows the trust signals
// npx hides — install scripts, build provenance, age, popularity, deprecation,
// typosquatting — then you decide. FAILS CLOSED: if it can't verify the package
// it won't auto-run. Offers a one-keystroke `--ignore-scripts` safe run, and
// REMEMBERS prior approvals (TOFU trust store) so the prompt keeps meaning something.
//
// ponytail: wrapper, NOT a reimplementation. The install+run stays `npx`; we add
// the pre-flight. `npm view --json` is the single registry-correct source.
//
// Invariants (each one closes a hole that let unverified code run):
//  - `--yes` is only ever passed to npx after a preview of EXACTLY what it will
//    install. The run is pinned to the previewed `name@version`.
//  - Anything we hand back to npx without a preview gets `--no`, so npx itself
//    refuses to install if we misjudged it.
//  - Args we can't classify are refused, never guessed: a wrong guess is a
//    preview of the wrong package.

const { spawn } = require('child_process')
const readline = require('readline/promises')
const os = require('os')
const path = require('path')
const fs = require('fs')
const crypto = require('crypto')

const INSTALL_HOOKS = ['preinstall', 'install', 'postinstall']
const TRUST_PATH = path.join(os.homedir(), '.npryx.json')
const PUBLIC_REGISTRY = 'https://registry.npmjs.org/'
const SCAN_CONFIG_PATH = path.join(os.homedir(), '.npryx-scan.json')
const SCAN_TIMEOUT_MS = 1500
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')
const SEVERITY = ['info', 'low', 'medium', 'high', 'confirmed']

// npm/npx flags npryx understands. All npx flags precede the package, and npm
// accepts ANY config key as a flag, so a flag we don't know might swallow the
// next arg. `--flag=value` is always unambiguous, so unknown ones are fine.
const VALUE_FLAGS = new Set([
  '-p', '--package', '-c', '--call', '--shell', '-w', '--workspace', '--prefix', '--loglevel',
  '--cache', '--userconfig', '--globalconfig', '--registry', '--cafile', '--proxy', '--https-proxy', '--noproxy'
])
const BOOL_FLAGS = new Set([
  '-h', '--help', '--version', '-y', '--yes', '--no', '-q', '--quiet', '-s', '--silent', '-d', '--ignore-scripts', '--workspaces',
  '--include-workspace-root', '--offline', '--prefer-offline', '--prefer-online', '--strict-ssl'
])
// Flags that change WHERE packages come from. Also passed to `npm view`, so the
// preview reads the same registry the run installs from.
const REGISTRY_FLAGS = new Set([
  '--cache', '--userconfig', '--globalconfig', '--registry', '--cafile', '--proxy', '--https-proxy',
  '--noproxy', '--offline', '--prefer-offline', '--prefer-online', '--strict-ssl'
])

// Common npx/install targets & known squat victims. Exact matches never warn.
// Names under 5 chars are exact-only: one edit from `jest` is `test`, `just`,
// `best` — too many innocent neighbours. ponytail: a static list, not a live
// popularity feed; grow it if a real squat slips through.
const POPULAR = [
  'express', 'cross-env', 'lodash', 'chalk', 'commander', 'request', 'react',
  'react-dom', 'webpack', 'typescript', 'eslint', 'prettier', 'mocha', 'jest',
  'axios', 'moment', 'debug', 'dotenv', 'yargs', 'cowsay', 'create-react-app',
  'nodemon', 'rimraf', 'gulp', 'grunt', 'babel', 'postcss', 'tailwindcss',
  'vite', 'esbuild', 'rollup', 'prisma', 'next', 'svelte', 'electron',
  'puppeteer', 'playwright', 'sharp', 'uuid', 'semver', 'glob', 'husky', 'sigstore'
]

// npm verbs people type from muscle memory. npx has no subcommands — `npx install`
// RUNS the registry package named "install". Warn (don't block: may be intended).
// ponytail: high-precision npm-only verbs; words that double as plausible package
// names (run/test/start/link/pack) are left out to avoid false alarms.
const NPM_SUBCOMMANDS = new Set([
  'install', 'i', 'ci', 'add', 'uninstall', 'remove', 'update', 'upgrade', 'audit', 'dedupe', 'prune'
])

// --- pure, testable arg handling ---------------------------------------------

// Parse npx's own flags up to the first positional. Everything after that
// positional belongs to the command being run (so a trailing `-y` is the
// package's flag, not npx's). Returns { error } instead of guessing.
function parseArgs (args) {
  const r = { packages: [], call: null, yes: null, yesAt: [], viewFlags: [], prefix: false, positional: -1, error: null }
  for (let i = 0; i < args.length; i++) {
    const a = args[i]
    if (a === '--') { if (i + 1 < args.length) r.positional = i + 1; break }
    if (a === '-' || !a.startsWith('-')) { r.positional = i; break }
    const eq = a.startsWith('--') ? a.indexOf('=') : -1
    const key = eq > 0 ? a.slice(0, eq) : a
    const scopedRegistry = /^--@[^/:]+:registry$/.test(key)
    let value = eq > 0 ? a.slice(eq + 1) : null
    const at = i
    if (eq < 0 && (VALUE_FLAGS.has(key) || scopedRegistry)) {
      if (i + 1 >= args.length) return { ...r, error: `${key} needs a value` }
      value = args[++i]
    } else if (eq < 0 && !BOOL_FLAGS.has(key) && !key.startsWith('--no-')) {
      return { ...r, error: `unrecognised flag ${key} — npryx can't tell whether it takes a value, so it can't tell which package would run. Write it as ${key}=<value>` }
    }
    if (key === '-p' || key === '--package') {
      r.packages.push({ spec: value, at: i, prefix: eq > 0 ? key + '=' : '' })
    } else if (key === '-c' || key === '--call') {
      r.call = value
    } else if (key === '-y' || key === '--yes' || key === '--no' || key === '--no-yes') {
      r.yes = key === '-y' || key === '--yes' ? value !== 'false' : false
      r.yesAt.push(at)
    } else if (key === '--prefix') {
      r.prefix = true
    }
    if (REGISTRY_FLAGS.has(key) || scopedRegistry || REGISTRY_FLAGS.has('--' + key.slice(5))) {
      r.viewFlags.push(...args.slice(at, i + 1))
    }
  }
  return r
}

// The packages npx would install: every `-p`, else the first positional.
function targets (parsed, args) {
  if (parsed.packages.length) return parsed.packages
  if (parsed.positional >= 0 && parsed.call == null) return [{ spec: args[parsed.positional], at: parsed.positional, prefix: '' }]
  return []
}

function splitSpec (spec) {
  if (!spec) return null
  const at = spec.indexOf('@', 1) // skip a leading @scope
  return at > 0
    ? { name: spec.slice(0, at), version: spec.slice(at + 1) }
    : { name: spec, version: null }
}

const NAME_RE = /^(?:@[a-z0-9~-][a-z0-9._~-]*\/)?[a-z0-9~-][a-z0-9._~-]*$/i

// 'registry': a name `npm view` can verify. 'local': a path on this machine —
// explicit user intent, forwarded. 'remote': git, URLs, aliases, anything else —
// fetched from somewhere npryx can't check, so it is gated like a failed lookup.
function classify (spec) {
  if (!spec) return 'remote'
  if (/^(\.|\/|~|file:|[a-z]:[\\/])/i.test(spec)) return 'local'
  if (!spec.includes('://') && /\.(tgz|tar\.gz|tar)$/i.test(spec)) return 'local'
  const s = splitSpec(spec)
  if (!NAME_RE.test(s.name)) return 'remote'
  if (s.version && s.version.startsWith('npm:')) return 'remote' // alias: real name is elsewhere
  return 'registry'
}

// `npm view <range> --json` returns an ascending ARRAY; a single match is an
// OBJECT. Like npm, prefer the `latest` tag when it satisfies the range.
function pickVersion (json) {
  if (!Array.isArray(json)) return json || null
  const latest = json.find(v => v['dist-tags'] && v.version === v['dist-tags'].latest)
  return latest || json[json.length - 1] || null
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
    publicRegistry: typeof dist.tarball === 'string' && dist.tarball.startsWith(PUBLIC_REGISTRY),
    provenance: att ? ((att.provenance && att.provenance.predicateType) || 'attested') : null
  }
}

// Optimal-string-alignment distance: Levenshtein plus adjacent transpositions,
// so `lodahs` is one edit from `lodash`. Package names are tiny; O(mn) is fine.
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
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1)
    }
  }
  return d[m][n]
}

function typosquat (name) {
  if (!name || name.startsWith('@')) return null // squatting targets unscoped names
  if (POPULAR.includes(name)) return null // exact = the real thing
  for (const p of POPULAR) {
    if (p.length < 5 || Math.abs(p.length - name.length) > 1) continue
    if (editDistance(name, p) <= 1) return p
  }
  return null
}

// Trust store v2: { name: { version: { integrity, approvedAt } } }. v1 kept one
// { version, integrity, approvedAt } per name; read it transparently.
function trustedVersions (entry) {
  if (!entry) return {}
  if (typeof entry.version === 'string' && entry.integrity) return { [entry.version]: { integrity: entry.integrity, approvedAt: entry.approvedAt } }
  return entry
}

// npm never lets a published version be overwritten, so the two "not trusted"
// cases mean very different things:
//  - same version, different integrity → 'tampered' (registry, mirror or proxy
//    is serving other bytes). Loud.
//  - a version you haven't approved → 'updated'. Normal; just review it.
function trustMatch (store, sum) {
  if (!store || !sum || !sum.integrity) return { status: 'unknown' }
  const versions = trustedVersions(store[sum.name])
  const known = Object.keys(versions)
  if (!known.length) return { status: 'unknown' }
  const e = versions[sum.version]
  if (e && e.integrity === sum.integrity) return { status: 'trusted', approvedAt: e.approvedAt }
  if (e) return { status: 'tampered', version: sum.version }
  return { status: 'updated', from: known[known.length - 1], to: sum.version }
}

// NPRYX_ALLOW entries: `name` (any version), `name@version`, or an integrity
// (`sha512-…`). For an unverifiable spec, only the exact spec or bare name match.
function isAllowed (entries, spec, sum) {
  const candidates = sum
    ? [sum.name, `${sum.name}@${sum.version}`, sum.integrity]
    : [spec, splitSpec(spec) && splitSpec(spec).name]
  return entries.some(e => candidates.includes(e))
}

function parseAllow (value) {
  return (value || '').split(',').map(s => s.trim()).filter(Boolean)
}

// Drop the user's own --yes/--no: npryx decides that flag.
function withoutYes (args, parsed) {
  return args.filter((_, i) => !parsed.yesAt.includes(i))
}

// Rewrite each previewed target to the exact name@version shown, so npx runs
// what was previewed even if a new version lands in between.
function pinArgs (args, items) {
  const out = args.slice()
  for (const it of items) if (it.sum) out[it.target.at] = it.target.prefix + `${it.sum.name}@${it.sum.version}`
  return out
}

// --- remote scan (opt-in) -----------------------------------------------------
// Off unless the user configures a service (docs/scan-api.md). Results can only
// ADD warnings: an unreachable, slow or unverifiable service changes nothing.

function scanConfig (env, file) {
  const url = env.NPRYX_SCAN_URL || (file && file.url)
  if (!url) return null
  return {
    url: url.replace(/\/+$/, ''),
    token: env.NPRYX_SCAN_TOKEN || (file && file.token) || null,
    key: env.NPRYX_SCAN_KEY || (file && file.key) || null,
    deep: env.NPRYX_SCAN_DEEP != null ? env.NPRYX_SCAN_DEEP === '1' : Boolean(file && file.deep)
  }
}

// Signature is over the raw payload bytes. With a pinned key, anything that
// doesn't verify throws; without one the result is used but marked unsigned.
function verifyEnvelope (envelope, keyB64) {
  if (!envelope || typeof envelope.payload !== 'string') throw new Error('malformed response')
  const bytes = Buffer.from(envelope.payload, 'base64')
  if (keyB64) {
    const key = crypto.createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(keyB64, 'base64')]), format: 'der', type: 'spki' })
    if (!crypto.verify(null, bytes, key, Buffer.from(envelope.sig || '', 'base64'))) throw new Error('signature does not verify')
  }
  return { result: JSON.parse(bytes.toString('utf8')), verified: Boolean(keyB64) }
}

// 'confirmed' | 'suspected' | 'info' | 'clean', or null when there's no usable result.
function scanVerdict (scan) {
  if (!scan || !scan.result) return null
  if (scan.result.status === 'integrity_mismatch') return 'confirmed'
  return scan.result.status === 'done' ? scan.result.verdict : null
}

const PHASE = { install: 'on install', import: 'on import', runtime: 'when run' }

function renderScan (scan) {
  if (!scan) return []
  const pad = '                '
  if (scan.error) return [`  remote scan   unavailable (${scan.error}), nothing changed`]
  const r = scan.result
  const unsigned = scan.verified ? '' : ' (unsigned)'
  if (r.status === 'pending') return [`  remote scan   queued${unsigned}, run again in a moment for results`]
  if (r.status === 'integrity_mismatch') {
    return [`  remote scan   ⛔ the registry serves different bytes for this version than npryx resolved${unsigned}`,
      `${pad}registry has ${String(r.registry_integrity).slice(0, 24)}…`]
  }
  const head = { confirmed: '⛔ confirmed threat', suspected: '⚠️  suspicious', info: 'notes', clean: '✓ nothing found (not a guarantee)' }[r.verdict] || r.verdict
  const lines = [`  remote scan   ${head}${unsigned}${r.previous ? `   compared with ${r.previous.version}` : ''}`]
  const findings = [...(r.findings || [])].sort((a, b) => SEVERITY.indexOf(b.severity) - SEVERITY.indexOf(a.severity))
  for (const f of findings.slice(0, 6)) {
    const mark = f.severity === 'confirmed' ? '⛔' : f.severity === 'high' || f.severity === 'medium' ? '⚠️ ' : '•'
    const when = PHASE[f.phase] ? ` (${PHASE[f.phase]})` : ''
    const isNew = f.new_since_previous && r.previous ? `, new since ${r.previous.version}` : ''
    lines.push(`${pad}${mark} ${f.title}${when}${isNew}`)
    // the service writes § for parts of a URL it couldn't resolve statically
    for (const d of (f.destinations || []).slice(0, 2)) lines.push(`${pad}    → ${d.replace(/§/g, '*')}`)
  }
  if (findings.length > 6) lines.push(`${pad}  and ${findings.length - 6} more`)
  if (r.sandbox && r.sandbox.status !== 'ok') lines.push(`${pad}sandbox ${r.sandbox.status}${r.sandbox.reason ? `: ${r.sandbox.reason}` : ''}`)
  // [s] only stops lifecycle scripts; say so when the risky code runs later.
  if (findings.some(f => (f.severity === 'high' || f.severity === 'confirmed') && (f.phase === 'import' || f.phase === 'runtime'))) {
    lines.push(`${pad}note: [s] --ignore-scripts won't help here, this code runs ${findings.some(f => f.phase === 'import') ? 'on import' : 'when the package runs'}`)
  }
  return lines
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
  if (s.deprecated) w.push(`deprecated: ${s.deprecated}`)
  const days = ageDays(s.published)
  if (days != null && days < 30) w.push(`published only ${Math.round(days)}d ago — brand new, little scrutiny yet`)
  if (downloads != null && downloads < 1000) w.push(`only ${downloads.toLocaleString()} weekly downloads — unusually low`)
  if (squat) w.push(`did you mean "${squat}"? "${s.name}" is one edit away from a popular package — possible typosquat`)
  if (NPM_SUBCOMMANDS.has(s.name)) w.push(`"${s.name}" is an npm subcommand — npryx wraps \`npx\` (npm exec), so this runs the registry package "${s.name}" rather than performing \`npm ${s.name}\`. Did you mean \`npm ${s.name} …\`?`)
  return w
}

function render (s, ctx) {
  const { requested, downloads, squat, trust } = ctx
  const lines = ['']
  if (trust && trust.status === 'tampered') {
    lines.push(`  ⛔ ${s.name}@${s.version} is not the bytes you approved — same version, different integrity.`)
    lines.push('      npm never lets a version be republished, so a registry, mirror or proxy is')
    lines.push('      serving altered code. Do not run this.')
    lines.push('')
  } else if (trust && trust.status === 'updated') {
    lines.push(`  note: you trusted ${s.name}@${trust.from}; this is ${trust.to}, a version you haven't reviewed.`)
    lines.push('')
  }
  const dl = downloads != null ? downloads.toLocaleString() : (s.publicRegistry ? 'unknown' : 'n/a (not the public registry)')
  lines.push(
    `  package       ${s.name}@${s.version}   (asked: ${requested || 'latest'})`,
    `  published     ${ageString(s.published)}`,
    `  weekly dl     ${dl}`,
    `  maintainers   ${s.maintainers.length ? s.maintainers.slice(0, 3).join(', ') + (s.maintainers.length > 3 ? ' …' : '') : 'unknown'}`,
    `  repo          ${s.repo || 'none listed'}`,
    `  integrity     ${s.integrity ? s.integrity.slice(0, 24) + '…' : 'unknown'}`,
    `  provenance    ${s.provenance ? '✓ ' + s.provenance : 'none'}`,
    `  install hook  ${s.runsInstallScripts ? '⚠️  yes — runs code on install' : '✓ none'}`,
    ...renderScan(ctx.scan),
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

function renderUnverified (it) {
  const why = it.error
    ? `could not verify "${it.target.spec}" — ${it.error}\n      This may be a typo, an unpublished/private package, or a registry issue.`
    : `"${it.target.spec}" is fetched from outside the npm registry (git, URL or alias), so npryx can't verify it.`
  return `\n  ⚠️  npryx: ${why}\n`
}

// --- IO: npm, registry lookup, downloads, trust store, exec ------------------

// Windows ships npm/npx as .cmd shims, which Node won't spawn without a shell
// (and a shell would re-parse our args). Run npm's JS entry points directly.
function npmCommand (name) {
  if (process.platform !== 'win32') return [name, []]
  const cli = path.join(path.dirname(process.execPath), 'node_modules', 'npm', 'bin', `${name}-cli.js`)
  if (fs.existsSync(cli)) return [process.execPath, [cli]]
  throw new Error(`can't find ${name}-cli.js next to node (${cli})`)
}

function view (query, flags) {
  return new Promise((resolve, reject) => {
    const [cmd, pre] = npmCommand('npm')
    const child = spawn(cmd, [...pre, 'view', query, '--json', ...flags], { stdio: ['ignore', 'pipe', 'pipe'], timeout: 60000 })
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

// Public registry only: never send a private package's name to api.npmjs.org.
async function weeklyDownloads (sum) {
  if (!sum.publicRegistry) return null
  try {
    const r = await fetch(`https://api.npmjs.org/downloads/point/last-week/${sum.name}`, { signal: AbortSignal.timeout(5000) })
    if (!r.ok) return null
    const j = await r.json()
    return j.downloads ?? null
  } catch { return null } // best-effort
}

async function remoteScan (cfg, sum) {
  const query = new URLSearchParams({ integrity: sum.integrity, deep: cfg.deep ? '1' : '0' })
  const url = `${cfg.url}/v1/scan/${encodeURIComponent(sum.name)}/${encodeURIComponent(sum.version)}?${query}`
  try {
    const res = await fetch(url, {
      headers: cfg.token ? { authorization: `Bearer ${cfg.token}` } : {},
      signal: AbortSignal.timeout(SCAN_TIMEOUT_MS)
    })
    if (![200, 202, 409].includes(res.status)) return { error: `service answered ${res.status}` }
    const scan = verifyEnvelope(await res.json(), cfg.key)
    const r = scan.result
    if (r.name !== sum.name || r.version !== sum.version || r.integrity !== sum.integrity) return { error: 'response was for a different package' }
    return scan
  } catch (e) { return { error: e.name === 'TimeoutError' ? 'timed out' : e.message } }
}

function loadJson (file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')) } catch { return null }
}

// Mirrors npm's local prefix: the nearest ancestor with package.json or
// node_modules. If it has the bin, `npx <cmd>` runs it without installing.
function localBin (cmd, cwd) {
  for (let dir = cwd; ; dir = path.dirname(dir)) {
    if (fs.existsSync(path.join(dir, 'package.json')) || fs.existsSync(path.join(dir, 'node_modules'))) {
      const bin = path.join(dir, 'node_modules', '.bin', cmd)
      return fs.existsSync(bin) || fs.existsSync(bin + '.cmd') ? bin : null
    }
    if (path.dirname(dir) === dir) return null
  }
}

function loadStore () {
  try { return JSON.parse(fs.readFileSync(TRUST_PATH, 'utf8')) } catch { return {} }
}

function saveStore (store) {
  const tmp = TRUST_PATH + '.' + process.pid
  fs.writeFileSync(tmp, JSON.stringify(store, null, 2) + '\n')
  fs.renameSync(tmp, TRUST_PATH)
}

function recordTrust (sums) {
  const store = loadStore()
  for (const sum of sums) {
    const versions = trustedVersions(store[sum.name])
    versions[sum.version] = { integrity: sum.integrity, approvedAt: new Date().toISOString() }
    store[sum.name] = versions
  }
  saveStore(store)
}

function runNpx (args) {
  if (process.env.NPRYX_DRYRUN) { console.error(`  [dry-run] npx ${args.join(' ')}`); process.exit(0) }
  const [cmd, pre] = npmCommand('npx')
  const child = spawn(cmd, [...pre, ...args], { stdio: 'inherit' })
  // Ctrl-C reaches the whole process group: let the child handle it and exit
  // the way it does. Signals aimed only at us are relayed.
  const relay = sig => child.kill(sig)
  process.on('SIGINT', () => {})
  process.on('SIGTERM', relay)
  process.on('SIGHUP', relay)
  child.on('exit', (code, signal) => {
    if (!signal) process.exit(code ?? 1)
    process.exitCode = 128 + (os.constants.signals[signal] || 0)
    process.removeAllListeners(signal)
    process.kill(process.pid, signal) // die the same way, so callers see the signal
  })
  child.on('error', e => { console.error('npryx: failed to launch npx:', e.message); process.exit(1) })
}

async function chooseAction (canTrust) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stderr })
  const trust = canTrust ? '   [a] always-trust this version' : ''
  const ans = (await rl.question(`  [y] run   [s] run with --ignore-scripts (safer)${trust}   [N] abort: `)).trim().toLowerCase()
  rl.close()
  return ans === 'yes' ? 'y' : ans
}

function refuse (msg) {
  console.error(msg)
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
  for (const n of names) {
    for (const [v, e] of Object.entries(trustedVersions(store[n]))) console.log(`    ${n}@${v}   approved ${e.approvedAt}`)
  }
}

function forget (spec) {
  if (!spec) refuse('  usage: npryx --forget <package>[@<version>]')
  const { name, version } = splitSpec(spec)
  const store = loadStore()
  const versions = trustedVersions(store[name])
  if (version ? !versions[version] : !store[name]) { console.log(`  npryx: "${spec}" was not trusted.`); return }
  if (version) {
    delete versions[version]
    if (Object.keys(versions).length) store[name] = versions
    else delete store[name]
  } else delete store[name]
  saveStore(store)
  console.log(`  npryx: forgot "${spec}".`)
}

async function scanSetup (args) {
  const url = args[0]
  if (!url || url.startsWith('-')) refuse('  usage: npryx --scan-config <url> [--token <token>] [--key <base64>] [--deep]')
  const opt = flag => { const i = args.indexOf(flag); return i > 0 ? args[i + 1] || null : null }
  const cfg = { url: url.replace(/\/+$/, ''), token: opt('--token'), key: opt('--key'), deep: args.includes('--deep') }
  if (!cfg.key) { // trust on first use: pin the key the service presents now
    try {
      const res = await fetch(`${cfg.url}/v1/pubkey`, { signal: AbortSignal.timeout(5000) })
      const j = await res.json()
      if (j.alg !== 'ed25519' || !j.key) throw new Error('unexpected /v1/pubkey response')
      cfg.key = j.key
      console.log(`  pinned the service's signing key ${j.key_id}: ${j.key}`)
      console.log('  (pass --key to pin a key you received some other way instead)')
    } catch (e) { refuse(`  npryx: couldn't fetch the service's signing key: ${e.message}`) }
  }
  fs.writeFileSync(SCAN_CONFIG_PATH, JSON.stringify(cfg, null, 2) + '\n', { mode: 0o600 })
  console.log(`  npryx: remote scanning on. Public-registry packages you're asked to approve are sent to ${cfg.url} for scanning.`)
  console.log(`  sandbox scans ${cfg.deep ? 'on' : 'off'}. Turn it all off with: npryx --scan-off`)
}

function scanOff () {
  try { fs.unlinkSync(SCAN_CONFIG_PATH); console.log('  npryx: remote scanning off.') } catch { console.log('  npryx: remote scanning was already off.') }
  if (process.env.NPRYX_SCAN_URL) console.log('  note: NPRYX_SCAN_URL is still set in your environment, which turns it back on.')
}

function scanStatus () {
  const cfg = scanConfig(process.env, loadJson(SCAN_CONFIG_PATH))
  if (!cfg) { console.log('  npryx: remote scanning is off (the default). Opt in with: npryx --scan-config <url>'); return }
  console.log(`  npryx: remote scanning on, using ${cfg.url}`)
  console.log(`  signing key ${cfg.key ? 'pinned' : 'not pinned, results are marked unsigned'}`)
  console.log(`  api token ${cfg.token ? 'set' : 'not set'}, sandbox scans ${cfg.deep ? 'on' : 'off'}`)
}

// --- main --------------------------------------------------------------------
async function main () {
  const args = process.argv.slice(2)

  if (args[0] === '--alias') { process.stdout.write(aliasLine()); return }
  if (args[0] === '--trust-list') return printTrustList()
  if (args[0] === '--forget') return forget(args[1])
  if (args[0] === '--scan-config') return scanSetup(args.slice(1))
  if (args[0] === '--scan-off') return scanOff()
  if (args[0] === '--scan-status') return scanStatus()

  const parsed = parseArgs(args)
  if (parsed.error) refuse(`  npryx: ${parsed.error}`)
  const base = withoutYes(args, parsed)
  const tgts = targets(parsed, args)

  // Nothing to install (`--help`, `-c` with no -p): hand to npx, but with --no
  // unless the user chose themselves, so it can't install behind our back.
  if (!tgts.length) return runNpx(parsed.yes == null ? ['--no', ...args] : args)

  // `npx tsc` in a project with typescript runs the local bin; don't preview
  // the unrelated registry package `tsc`. `--no` makes npx refuse to install
  // if we got this wrong.
  const only = tgts[0]
  if (tgts.length === 1 && only.prefix === '' && parsed.packages.length === 0 && !parsed.prefix &&
      classify(only.spec) === 'registry' && !splitSpec(only.spec).version && !only.spec.startsWith('@') &&
      localBin(only.spec, process.cwd())) {
    return runNpx(['--no', ...base])
  }

  const isTTY = process.stdin.isTTY && process.stderr.isTTY
  const forceYes = parsed.yes === true || process.env.NPRYX_YES === '1'
  const allow = parseAllow(process.env.NPRYX_ALLOW)
  const store = loadStore()

  const items = await Promise.all(tgts.map(async target => {
    const kind = classify(target.spec)
    if (kind !== 'registry') return { target, kind }
    const s = splitSpec(target.spec)
    const query = s.version ? `${s.name}@${s.version}` : s.name
    try {
      const sum = summarize(await view(query, parsed.viewFlags))
      if (!sum) return { target, kind, error: 'no matching version' }
      return { target, kind, sum, requested: s.version, trust: trustMatch(store, sum) }
    } catch (e) { return { target, kind, error: e.message } }
  }))

  const cleared = it => it.kind === 'local' || (it.trust && it.trust.status === 'trusted')
  const pinned = withoutYes(pinArgs(args, items), parsed) // pin by original index, then strip
  if (items.every(cleared)) {
    for (const it of items) if (it.sum) console.error(`  npryx: ${it.sum.name}@${it.sum.version} trusted ✓ (approved ${it.trust.approvedAt})`)
    return runNpx(['--yes', ...pinned])
  }

  const pending = items.filter(it => !cleared(it))
  // Downloads (interactive only) and the opt-in remote scan, in parallel.
  // Only public-registry packages are ever sent to a scan service.
  const scanCfg = scanConfig(process.env, loadJson(SCAN_CONFIG_PATH))
  await Promise.all(pending.filter(it => it.sum).map(it => Promise.all([
    isTTY && weeklyDownloads(it.sum).then(d => { it.downloads = d }),
    scanCfg && it.sum.publicRegistry && it.sum.integrity && remoteScan(scanCfg, it.sum).then(s => { it.scan = s })
  ])))
  for (const it of pending) {
    process.stderr.write(it.sum
      ? render(it.sum, { requested: it.requested, downloads: it.downloads ?? null, squat: typosquat(it.sum.name), trust: it.trust, scan: it.scan })
      : renderUnverified(it))
  }

  // Never auto-run, and never offer to trust: altered bytes, or a confirmed
  // threat from the remote scan.
  const blocked = it => (it.trust && it.trust.status === 'tampered') || scanVerdict(it.scan) === 'confirmed'

  // FAIL CLOSED: non-interactive runs need every pending package explicitly
  // allowed (or a blanket opt-out). Blocked packages are never auto-run.
  if (!isTTY) {
    if (pending.some(blocked)) refuse('  npryx: refusing to run: a package above is tampered or a confirmed threat. NPRYX_YES and NPRYX_ALLOW do not override this.')
    const ok = forceYes || pending.every(it => isAllowed(allow, it.target.spec, it.sum))
    if (ok) return runNpx(['--yes', ...pinned])
    refuse('  npryx: refusing to auto-run in a non-interactive shell (fail-closed). Set NPRYX_ALLOW=<name>[@<version>] or NPRYX_YES=1 to override.')
  }

  const canTrust = pending.every(it => it.sum && it.sum.integrity && !blocked(it))
  const ans = await chooseAction(canTrust)
  if (ans === 'y') return runNpx(['--yes', ...pinned])
  if (ans === 's') return runNpx(['--yes', '--ignore-scripts', ...pinned])
  if (ans === 'a' && canTrust) { recordTrust(pending.map(it => it.sum)); return runNpx(['--yes', ...pinned]) }
  refuse('  aborted.')
}

if (require.main === module) {
  main().catch(e => { console.error('npryx:', e.message); process.exit(1) })
}

module.exports = {
  parseArgs, targets, splitSpec, classify, pickVersion, summarize, editDistance, typosquat,
  trustMatch, isAllowed, parseAllow, pinArgs, withoutYes, localBin,
  scanConfig, verifyEnvelope, scanVerdict, renderScan
}
