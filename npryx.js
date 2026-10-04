#!/usr/bin/env node
'use strict'
// npryx: a SECURITY-FIRST superset of `npx` (npm exec).
// Before npm downloads & executes a remote package, npryx shows the trust signals
// npx hides (install scripts, build provenance, age, popularity, deprecation,
// typosquatting), then you decide. FAILS CLOSED: if it can't verify the package
// it won't auto-run. Offers a one-keystroke `--ignore-scripts` safe run, and
// REMEMBERS prior approvals (TOFU trust store) so the prompt keeps meaning something.
//
// A wrapper, not a reimplementation. The install+run stays `npx`; we add
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
  '-h', '--help', '--version', '-v', '-y', '--yes', '--no', '-q', '--quiet', '-s', '--silent', '-d', '--ignore-scripts', '--workspaces',
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
// `best`: too many innocent neighbours. A static list, not a live
// popularity feed; grow it if a real squat slips through.
const POPULAR = [
  'express', 'cross-env', 'lodash', 'chalk', 'commander', 'request', 'react',
  'react-dom', 'webpack', 'typescript', 'eslint', 'prettier', 'mocha', 'jest',
  'axios', 'moment', 'debug', 'dotenv', 'yargs', 'cowsay', 'create-react-app',
  'nodemon', 'rimraf', 'gulp', 'grunt', 'babel', 'postcss', 'tailwindcss',
  'vite', 'esbuild', 'rollup', 'prisma', 'next', 'svelte', 'electron',
  'puppeteer', 'playwright', 'sharp', 'uuid', 'semver', 'glob', 'husky', 'sigstore'
]

// npm verbs people type from muscle memory. npx has no subcommands: `npx install`
// RUNS the registry package named "install". Warn (don't block: may be intended).
// High-precision npm-only verbs; words that double as plausible package
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
      return { ...r, error: `unrecognised flag ${key}: npryx can't tell whether it takes a value, so it can't tell which package would run. Write it as ${key}=<value>` }
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

// 'registry': a name `npm view` can verify. 'local': a path on this machine,
// explicit user intent, forwarded. 'remote': git, URLs, aliases, anything else
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

// NPRYX_ALLOW entries: `name` (any version), `name@version`, an integrity
// (`sha512-…`), or `name@version#integrity` (exactly those bytes, what --json
// offers). For an unverifiable spec, only the exact spec or bare name match.
function isAllowed (entries, spec, sum) {
  const candidates = sum
    ? [sum.name, `${sum.name}@${sum.version}`, sum.integrity, sum.integrity && approvalToken(sum)]
    : [spec, splitSpec(spec) && splitSpec(spec).name]
  return entries.some(e => candidates.includes(e))
}

function approvalToken (sum) {
  return `${sum.name}@${sum.version}#${sum.integrity}`
}

// The decision a non-interactive run acts on, per package. --json reports it.
// Tampered bytes and confirmed threats come first: nothing overrides them.
function decide (it, { forceYes, allow }) {
  const d = (decision, reason) => ({ decision, reason })
  if (it.kind === 'local') return d('allow', 'local')
  if (it.trust && it.trust.status === 'tampered') return d('refuse', 'tampered')
  if (scanVerdict(it.scan) === 'confirmed') return d('refuse', 'confirmed-threat')
  if (it.trust && it.trust.status === 'trusted') return d('allow', 'trusted')
  if (forceYes) return d('allow', 'yes')
  if (isAllowed(allow, it.target.spec, it.sum)) return d('allow', 'allowed')
  return it.sum ? d('needs-approval', 'untrusted') : d('refuse', 'unverifiable')
}

// The whole command is only as clear as its least clear package.
const PRECEDENCE = ['tampered', 'confirmed-threat', 'unverifiable', 'untrusted']
function overall (decisions) {
  for (const r of PRECEDENCE) { const d = decisions.find(x => x.reason === r); if (d) return d }
  return decisions[0] || { decision: 'allow', reason: 'nothing-to-install' }
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

// --- terminal styling --------------------------------------------------------
// Plain text unless the stream is a terminal. FORCE_COLOR wins over NO_COLOR,
// as in Node itself, and FORCE_COLOR=0 turns colour off.
function useColor (stream, env) {
  if (env.FORCE_COLOR != null && env.FORCE_COLOR !== '') return !['0', 'false'].includes(env.FORCE_COLOR)
  if (env.NO_COLOR != null && env.NO_COLOR !== '') return false
  return Boolean(stream && stream.isTTY) && env.TERM !== 'dumb'
}

function palette (on) {
  const sgr = (open, close) => s => on ? `\x1b[${open}m${s}\x1b[${close}m` : String(s)
  const c = { bold: sgr(1, 22), dim: sgr(2, 22), red: sgr(31, 39), green: sgr(32, 39), yellow: sgr(33, 39) }
  return { ...c, good: c.green('✓'), warn: c.yellow('!'), bad: c.red('✗') }
}

const ERR = palette(useColor(process.stderr, process.env))
const OUT = palette(useColor(process.stdout, process.env))

// Terminal width, or 0 (never wrap) when the output is going to a file or pipe.
function columns (stream) {
  return stream.isTTY ? stream.columns || 80 : 0
}

// Word-wrap plain text to `cols`, continuing at `indent`. Words too long for a
// line (URLs, hashes) are split rather than overflowing.
function wrap (text, indent, cols) {
  if (!cols) return String(text)
  const room = Math.max(cols - indent - 1, 20)
  const lines = []
  let line = ''
  for (let word of String(text).split(' ')) {
    while (word.length > room) {
      if (line) { lines.push(line); line = '' }
      lines.push(word.slice(0, room))
      word = word.slice(room)
    }
    if (line && line.length + 1 + word.length > room) { lines.push(line); line = word } else line = line ? `${line} ${word}` : word
  }
  lines.push(line)
  return lines.join('\n' + ' '.repeat(indent))
}

// One `label   value` line of a preview. `value` may already be styled, so
// callers wrap the plain text before colouring it.
function row (c, label, value) {
  return `  ${c.dim(label.padEnd(12))}  ${value}`
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

function renderScan (scan, c = ERR, cols = 0) {
  if (!scan) return []
  const pad = ' '.repeat(16)
  const head = text => row(c, 'remote scan', text)
  if (scan.error) return [head(c.dim(`unavailable (${scan.error}), nothing changed`))]
  const r = scan.result
  const unsigned = scan.verified ? '' : ' (unsigned)'
  if (r.status === 'pending') return [head(`queued${unsigned}, run again in a moment for results`)]
  if (r.status === 'integrity_mismatch') {
    return [head(`${c.bad} ${c.red(wrap(`the registry serves different bytes for this version than npryx resolved${unsigned}`, 18, cols))}`),
      `${pad}registry has ${String(r.registry_integrity).slice(0, 24)}…`]
  }
  const status = {
    confirmed: `${c.bad} ${c.red('confirmed threat')}`,
    suspected: `${c.warn} ${c.yellow('suspicious')}`,
    info: 'notes',
    clean: `${c.good} nothing found (not a guarantee)`
  }[r.verdict] || r.verdict
  const lines = [head(`${status}${unsigned}${r.previous ? c.dim(`   compared with ${r.previous.version}`) : ''}`)]
  const findings = [...(r.findings || [])].sort((a, b) => SEVERITY.indexOf(b.severity) - SEVERITY.indexOf(a.severity))
  for (const f of findings.slice(0, 6)) {
    const mark = f.severity === 'confirmed' ? c.bad : f.severity === 'high' || f.severity === 'medium' ? c.warn : c.dim('-')
    const when = PHASE[f.phase] ? ` (${PHASE[f.phase]})` : ''
    const isNew = f.new_since_previous && r.previous ? `, new since ${r.previous.version}` : ''
    lines.push(`${pad}${mark} ${wrap(`${f.title}${when}${isNew}`, 18, cols)}`)
    // the service writes § for parts of a URL it couldn't resolve statically
    for (const d of (f.destinations || []).slice(0, 2)) lines.push(`${pad}  ${c.dim('→')} ${wrap(d.replace(/§/g, '*'), 20, cols)}`)
  }
  if (findings.length > 6) lines.push(`${pad}${c.dim(`and ${findings.length - 6} more`)}`)
  if (r.sandbox && r.sandbox.status !== 'ok') lines.push(`${pad}sandbox ${r.sandbox.status}${r.sandbox.reason ? `: ${r.sandbox.reason}` : ''}`)
  // [s] only stops lifecycle scripts; say so when the risky code runs later.
  if (findings.some(f => (f.severity === 'high' || f.severity === 'confirmed') && (f.phase === 'import' || f.phase === 'runtime'))) {
    lines.push(`${pad}${wrap(`note: [s] --ignore-scripts won't help here, this code runs ${findings.some(f => f.phase === 'import') ? 'on import' : 'when the package runs'}`, 16, cols)}`)
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

// Each warning has a stable code, for --json.
function warnings (s, downloads, squat) {
  const w = []
  const add = (code, message) => w.push({ code, message })
  if (s.runsInstallScripts) add('install-scripts', `runs install scripts (${s.hooks.join(', ') || 'hasInstallScript'}) which execute code on install`)
  if (s.deprecated) add('deprecated', `deprecated: ${s.deprecated}`)
  const days = ageDays(s.published)
  if (days != null && days < 30) add('new-package', `published only ${Math.round(days)}d ago, brand new with little scrutiny yet`)
  if (downloads != null && downloads < 1000) add('low-downloads', `only ${downloads.toLocaleString()} weekly downloads, unusually low`)
  if (squat) add('typosquat', `did you mean "${squat}"? "${s.name}" is one edit away from a popular package, possible typosquat`)
  if (NPM_SUBCOMMANDS.has(s.name)) add('npm-subcommand', `"${s.name}" is an npm subcommand. npryx wraps \`npx\` (npm exec), so this runs the registry package "${s.name}" rather than performing \`npm ${s.name}\`. Did you mean \`npm ${s.name} …\`?`)
  return w
}

// The conclusion, first: one line the eye lands on, then the reasons.
function verdict (id, w, trust, scan, c, cols) {
  const v = scanVerdict(scan)
  const head = (mark, paint, text) => `  ${mark} ${paint(wrap(text, 4, cols))}`
  const lines = []
  if (trust && trust.status === 'tampered') {
    const why = ['Same version, different integrity. npm never lets a version be republished,', 'so a registry, mirror or proxy is serving altered code.']
    lines.push(head(c.bad, s => c.bold(c.red(s)), `do not run ${id}: it is not the bytes you approved`),
      ...(cols && cols < 80 ? [wrap(why.join(' '), 4, cols)] : why).map(l => '    ' + l))
  } else if (v === 'confirmed') {
    const why = scan.result.status === 'integrity_mismatch' ? 'the registry serves different bytes than npryx resolved' : 'the remote scan confirmed a threat'
    lines.push(head(c.bad, s => c.bold(c.red(s)), `do not run ${id}: ${why}`))
  } else if (w.length || v === 'suspected') {
    const found = [w.length && `${w.length} ${w.length === 1 ? 'warning' : 'warnings'}`, v === 'suspected' && 'suspicious scan findings'].filter(Boolean)
    lines.push(head(c.warn, c.bold, `${id}: ${found.join(' and ')}, review before running`))
  } else {
    lines.push(head(c.good, c.bold, `${id}: no warnings`))
  }
  for (const x of w) lines.push(`    ${c.dim('-')} ${wrap(x.message, 6, cols)}`)
  return lines
}

function render (s, ctx, c = ERR, cols = columns(process.stderr)) {
  const { requested, downloads, squat, trust, scan } = ctx
  const id = `${s.name}@${s.version}`
  const w = warnings(s, downloads, squat)
  const title = wrap('npryx: about to fetch & run a package from the npm registry', 2, cols)
  const lines = ['', `  ${c.bold('npryx:')}${title.slice(6)}`, '', ...verdict(id, w, trust, scan, c, cols), '']
  if (trust && trust.status === 'updated') {
    lines.push(`  ${wrap(`note: you trusted ${s.name}@${trust.from}; this is ${trust.to}, a version you haven't reviewed.`, 2, cols)}`, '')
  }
  const fresh = ageDays(s.published) != null && ageDays(s.published) < 30
  const dl = downloads != null ? downloads.toLocaleString() : (s.publicRegistry ? 'unknown' : 'n/a (not the public registry)')
  const field = (label, text, paint = x => x) => row(c, label, paint(wrap(text, 16, cols)))
  const marked = (label, mark, text, paint = x => x) => row(c, label, `${mark} ${paint(wrap(text, 18, cols))}`)
  lines.push(
    row(c, 'package', `${c.bold(id)}${c.dim(`   (asked: ${requested || 'latest'})`)}`),
    field('published', ageString(s.published), fresh ? c.yellow : undefined),
    field('weekly dl', dl, downloads == null ? c.dim : downloads < 1000 ? c.yellow : undefined),
    field('maintainers', s.maintainers.length ? s.maintainers.slice(0, 3).join(', ') + (s.maintainers.length > 3 ? ' …' : '') : 'unknown'),
    field('repo', s.repo || 'none listed', s.repo ? undefined : c.dim),
    field('integrity', s.integrity ? s.integrity.slice(0, 24) + '…' : 'unknown'),
    s.provenance ? marked('provenance', c.good, s.provenance) : field('provenance', 'none', c.dim),
    s.runsInstallScripts ? marked('install hook', c.warn, 'yes, runs code on install', c.yellow) : marked('install hook', c.good, 'none'),
    ...renderScan(scan, c, cols),
    '', ''
  )
  return lines.join('\n')
}

function renderUnverified (it, c = ERR, cols = columns(process.stderr)) {
  const why = it.error
    ? `could not verify "${it.target.spec}": ${it.error}`
    : `"${it.target.spec}" is fetched from outside the npm registry (git, URL or alias), so npryx can't verify it.`
  const more = it.error ? `\n           ${wrap('This may be a typo, an unpublished/private package, or a registry issue.', 11, cols)}` : ''
  return `\n  ${c.bold('npryx:')} ${c.warn} ${c.bold(wrap(why, 11, cols))}${more}\n\n`
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

// The keys stand out, and the default is marked. On a narrow terminal the
// choices stack rather than wrap mid-option.
function promptText (canTrust, c = ERR, cols = columns(process.stderr)) {
  const options = [['y', 'run'], ['s', 'run with --ignore-scripts (safer)'], canTrust && ['a', 'always-trust this version'], ['N', 'abort (default)']].filter(Boolean)
  const plain = '  ' + options.map(([k, text]) => `[${k}] ${text}`).join('   ') + ': '
  const shown = options.map(([k, text]) => `${c.dim('[')}${c.bold(k)}${c.dim(']')} ${k === 'N' ? c.dim(text) : text}`)
  if (cols && plain.length > cols) return shown.map(o => `  ${o}\n`).join('') + '  choice: '
  return `  ${shown.join('   ')}: `
}

async function chooseAction (canTrust) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stderr })
  const text = promptText(canTrust)
  const cut = text.lastIndexOf('\n') + 1 // readline redraws only the last line
  process.stderr.write(text.slice(0, cut))
  const ans = (await rl.question(text.slice(cut))).trim().toLowerCase()
  rl.close()
  return ans === 'yes' ? 'y' : ans
}

// One-line messages: `npryx:`, a status mark, then what happened.
function say (c, mark, text) {
  return `  ${c.bold('npryx:')} ${mark ? mark + ' ' : ''}${text}`
}

function refuse (msg) {
  console.error(msg)
  process.exit(1)
}

// --- helper subcommands ------------------------------------------------------
// The alias is a suggestion, never a requirement: --alias only prints it, and
// --setup-alias edits the shell startup file only after showing the change and
// getting a yes. The block is marked so --remove-alias can take out exactly it.
const ALIAS_START = '# >>> npryx alias (npryx --remove-alias takes this out) >>>'
const ALIAS_END = '# <<< npryx alias <<<'

function aliasShell (env) {
  const shell = (env.SHELL || '').split('/').pop()
  return ['zsh', 'bash', 'fish'].includes(shell) ? shell : null
}

// macOS login shells read ~/.bash_profile rather than ~/.bashrc.
function aliasRcPath (shell, home, platform, exists) {
  if (shell === 'zsh') return path.join(home, '.zshrc')
  if (shell === 'fish') return path.join(home, '.config', 'fish', 'config.fish')
  if (shell === 'bash') {
    const profile = path.join(home, '.bash_profile')
    return platform === 'darwin' && exists(profile) ? profile : path.join(home, '.bashrc')
  }
  return null
}

function aliasCommand (shell) {
  return shell === 'fish' ? "alias npx 'npryx'" : "alias npx='npryx'"
}

function aliasBlock (shell) {
  return `${ALIAS_START}\n${aliasCommand(shell)}\n${ALIAS_END}\n`
}

// A blank line between the user's own config and the block, for readability.
function appendAliasBlock (text, shell) {
  const base = text && !text.endsWith('\n') ? text + '\n' : text
  return base + (base ? '\n' : '') + aliasBlock(shell)
}

function hasAliasBlock (text) {
  return text.includes(ALIAS_START)
}

// An npx alias that isn't ours: leave it alone rather than stack a second one.
function foreignNpxAlias (text) {
  const outside = removeAliasBlock(text)
  return /^\s*alias\s+npx[\s=]/m.test(outside)
}

// Exactly undoes --setup-alias: the block, plus the blank line it put before it.
function removeAliasBlock (text) {
  const start = text.indexOf(ALIAS_START)
  const end = start < 0 ? -1 : text.indexOf(ALIAS_END, start)
  if (end < 0) return text
  return text.slice(0, start).replace(/\n\n$/, '\n') + text.slice(end + ALIAS_END.length).replace(/^\n/, '')
}

function aliasLine () {
  const shell = aliasShell(process.env)
  const rc = shell ? aliasRcPath(shell, '~', process.platform, f => fs.existsSync(f.replace('~', os.homedir()))) : 'your shell startup file'
  return `  ${OUT.dim(`# npryx alias: add to ${rc}, then restart your shell:`)}\n  ${OUT.bold(aliasCommand(shell))}\n` +
    `  ${OUT.dim('# or let npryx add it for you (it shows the change and asks first): npryx --setup-alias')}\n`
}

function helpText () {
  return `${OUT.bold('npryx')}: npx that shows you what you're about to run, first.

  npryx <pkg>[@<version>] [args...]   preview, then run with npx (all npx flags work)

  npryx --json <pkg>[@<version>] [args...]
                                      for agents and scripts: check only, never runs or
                                      prompts. One JSON document on stdout. Exit 0 allow,
                                      3 needs approval, 1 refuse, 2 usage error

  npryx --trust-list [--json]         packages you've trusted
  npryx --forget <pkg>[@<version>]    drop one from the trust store
  npryx --scan-config <url> [--token <t>] [--key <k>] [--deep]
                                      opt in to a remote scan service
  npryx --scan-status [--json]        show whether remote scanning is on
  npryx --scan-off                    turn off remote scanning
  npryx --setup-alias | --remove-alias
                                      optionally make \`npx\` run npryx (asks first)
  npryx --alias                       print the alias line instead

  NPRYX_ALLOW=<name>[@<version>]      allow packages in CI (comma-separated). Use
                                      <name>@<version>#<integrity> to allow exactly those
                                      bytes (what --json prints as "approve")
  NPRYX_YES=1                         opt out of the CI refusal entirely

${OUT.dim("npx's own help follows.")}

`
}

// `[y/N]` with the keys picked out; N, the default, stays capitalised.
function yesNo (c) {
  return `${c.dim('[')}${c.bold('y')}${c.dim('/')}${c.bold('N')}${c.dim(']')}`
}

async function confirm (question, yesFlag) {
  if (yesFlag) return true
  if (!process.stdin.isTTY) return false
  const rl = readline.createInterface({ input: process.stdin, output: process.stderr })
  const ans = (await rl.question(question)).trim().toLowerCase()
  rl.close()
  return ans === 'y' || ans === 'yes'
}

async function setupAlias (args) {
  const shell = aliasShell(process.env)
  if (!shell) refuse(say(ERR, ERR.warn, `couldn't tell which shell you use (SHELL=${process.env.SHELL || 'unset'}). Add the alias yourself:\n  alias npx='npryx'`))
  const rc = aliasRcPath(shell, os.homedir(), process.platform, fs.existsSync)
  const text = fs.existsSync(rc) ? fs.readFileSync(rc, 'utf8') : ''
  if (hasAliasBlock(text)) { console.log(say(OUT, OUT.good, `the alias is already set up in ${rc}.`)); return }
  if (foreignNpxAlias(text)) refuse(say(ERR, ERR.warn, `${rc} already defines its own npx alias, so npryx left it alone.`))
  console.log(`  This adds the following to ${OUT.bold(rc)}:\n`)
  console.log(aliasBlock(shell).trimEnd().split('\n').map(l => '    ' + (l.startsWith('#') ? OUT.dim(l) : l)).join('\n') + '\n')
  console.log('  After that, npx runs npryx. To skip npryx for one command, run `command npx …`.')
  if (!await confirm(`  Add it? ${yesNo(ERR)} `, args.includes('--yes'))) refuse(say(ERR, null, 'left your shell config unchanged.'))
  fs.mkdirSync(path.dirname(rc), { recursive: true })
  fs.writeFileSync(rc, appendAliasBlock(text, shell))
  console.log(say(OUT, OUT.good, `added. Open a new terminal, or run: source ${rc}`))
}

async function removeAlias (args) {
  const shell = aliasShell(process.env)
  const rc = shell && aliasRcPath(shell, os.homedir(), process.platform, fs.existsSync)
  const text = rc && fs.existsSync(rc) ? fs.readFileSync(rc, 'utf8') : ''
  if (!hasAliasBlock(text)) { console.log(say(OUT, null, 'no npryx alias block found, nothing to remove.')); return }
  if (!await confirm(`  Remove the npryx alias block from ${rc}? ${yesNo(ERR)} `, args.includes('--yes'))) refuse(say(ERR, null, 'left your shell config unchanged.'))
  fs.writeFileSync(rc, removeAliasBlock(text))
  console.log(say(OUT, OUT.good, `removed. Open a new terminal, or run: source ${rc}`))
}

function printTrustList () {
  const store = loadStore()
  const names = Object.keys(store)
  if (!names.length) { console.log(say(OUT, null, 'trust store is empty.')); return }
  const rows = names.flatMap(n => Object.entries(trustedVersions(store[n])).map(([v, e]) => [`${n}@${v}`, e.approvedAt]))
  const width = Math.max(...rows.map(([id]) => id.length))
  console.log(say(OUT, null, `trusted versions, from ${TRUST_PATH}`) + '\n')
  for (const [id, at] of rows) console.log(`    ${OUT.good} ${OUT.bold(id.padEnd(width))}   ${OUT.dim(`approved ${approvedOn(at)}`)}`)
}

// The approval date; the time of day adds noise. v1 entries may have none.
function approvedOn (iso) {
  return iso ? String(iso).slice(0, 10) : 'at an unknown date'
}

function forget (spec) {
  if (!spec) refuse('  usage: npryx --forget <package>[@<version>]')
  const { name, version } = splitSpec(spec)
  const store = loadStore()
  const versions = trustedVersions(store[name])
  if (version ? !versions[version] : !store[name]) { console.log(say(OUT, null, `"${spec}" was not trusted.`)); return }
  if (version) {
    delete versions[version]
    if (Object.keys(versions).length) store[name] = versions
    else delete store[name]
  } else delete store[name]
  saveStore(store)
  console.log(say(OUT, OUT.good, `forgot "${spec}".`))
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
      console.log(say(OUT, OUT.good, `pinned the service's signing key ${j.key_id}: ${j.key}`))
      console.log(OUT.dim('           Pass --key to pin a key you received some other way instead.'))
    } catch (e) { refuse(say(ERR, ERR.warn, `couldn't fetch the service's signing key: ${e.message}`)) }
  }
  fs.writeFileSync(SCAN_CONFIG_PATH, JSON.stringify(cfg, null, 2) + '\n', { mode: 0o600 })
  console.log(say(OUT, OUT.good, `remote scanning is on. Public-registry packages you're asked to approve are sent to ${cfg.url} for scanning.`))
  console.log(`           Sandbox scans ${cfg.deep ? 'on' : 'off'}. Turn it all off with: ${OUT.bold('npryx --scan-off')}`)
}

function scanOff () {
  try { fs.unlinkSync(SCAN_CONFIG_PATH); console.log(say(OUT, null, 'remote scanning is off.')) } catch { console.log(say(OUT, null, 'remote scanning was already off.')) }
  if (process.env.NPRYX_SCAN_URL) console.log(say(OUT, OUT.warn, 'NPRYX_SCAN_URL is still set in your environment, which turns it back on.'))
}

function scanStatus () {
  const cfg = scanConfig(process.env, loadJson(SCAN_CONFIG_PATH))
  if (!cfg) { console.log(say(OUT, null, `remote scanning is off (the default). Opt in with: ${OUT.bold('npryx --scan-config <url>')}`)); return }
  console.log(say(OUT, null, 'remote scanning is on') + '\n')
  console.log(row(OUT, 'service', cfg.url))
  console.log(row(OUT, 'signing key', cfg.key ? `${OUT.good} pinned` : `${OUT.warn} ${OUT.yellow('not pinned, results are marked unsigned')}`))
  console.log(row(OUT, 'api token', cfg.token ? 'set' : OUT.dim('not set')))
  console.log(row(OUT, 'sandbox', cfg.deep ? 'on' : OUT.dim('off')))
}

// --- JSON mode (--json) ------------------------------------------------------
// For agents and scripts: one JSON document on stdout, never a prompt, never a
// run. The decision is the one a non-interactive `npryx <args>` acts on.
const SCHEMA_VERSION = 1
const EXIT = { allow: 0, refuse: 1, usage: 2, 'needs-approval': 3 }
const NO_JSON = new Set(['--alias', '--setup-alias', '--remove-alias', '--forget', '--scan-config', '--scan-off'])
const TRUST_STATUS = { unknown: 'new', trusted: 'trusted', updated: 'updated', tampered: 'tampered' }

function usageError (message) {
  return Object.assign(new Error(message), { code: 'usage' })
}

function scanReport (scan) {
  if (!scan) return null
  if (scan.error) return { status: 'unavailable', error: scan.error, signed: false, verdict: null, previous: null, findings: [] }
  const r = scan.result
  return {
    status: r.status === 'integrity_mismatch' ? 'integrity-mismatch' : r.status,
    error: null,
    signed: scan.verified,
    verdict: scanVerdict(scan),
    previous: (r.previous && r.previous.version) || null,
    findings: (r.findings || []).map(f => ({
      id: f.id, severity: f.severity, title: f.title, phase: f.phase || null, destinations: f.destinations || [], newSincePrevious: Boolean(f.new_since_previous)
    }))
  }
}

function trustReport (store, it) {
  if (!it.sum) return null
  return {
    status: TRUST_STATUS[it.trust.status],
    approvedAt: it.trust.approvedAt || null,
    trustedVersions: Object.keys(trustedVersions(store[it.sum.name]))
  }
}

function packageReport (it, store) {
  const s = it.sum
  const squat = s ? typosquat(s.name) : null
  const outside = it.kind === 'remote' && !it.error ? 'fetched from outside the npm registry (git, URL or alias), so npryx can\'t verify it' : null
  return {
    requested: it.target.spec,
    kind: it.kind,
    ...it.decision,
    resolved: s ? `${s.name}@${s.version}` : null,
    name: s ? s.name : null,
    version: s ? s.version : null,
    integrity: s ? s.integrity : null,
    provenance: s ? s.provenance : null,
    installScripts: s ? { runs: s.runsInstallScripts, hooks: s.hooks } : null,
    published: s ? s.published : null,
    weeklyDownloads: it.downloads ?? null,
    maintainers: s ? s.maintainers : [],
    repo: s ? s.repo : null,
    deprecated: s ? s.deprecated : null,
    typosquatOf: squat,
    publicRegistry: s ? s.publicRegistry : null,
    warnings: s ? warnings(s, it.downloads ?? null, squat) : [],
    trust: trustReport(store, it),
    scan: scanReport(it.scan),
    approve: it.decision.decision === 'needs-approval' && s.integrity ? approvalToken(s) : null,
    error: it.error || outside
  }
}

const MESSAGES = {
  trusted: 'every package is trusted, npryx would run it with no prompt',
  local: 'local paths only, npryx would run them as given',
  allowed: 'allowed by NPRYX_ALLOW',
  yes: 'NPRYX_YES or a leading -y opts out of the check',
  'nothing-to-install': 'nothing to install, npx would run with --no',
  'local-bin': 'runs the bin installed in this project, npx would run with --no',
  untrusted: 'not trusted yet: a human should review the packages, then approve them',
  tampered: 'same version, different bytes than you approved. Nothing overrides this',
  'confirmed-threat': 'the remote scan confirmed a threat. Nothing overrides this',
  unverifiable: 'npryx could not verify a package against the registry'
}

function checkReport (args, p) {
  const { decision, reason } = p.decision
  const items = p.items || []
  const pending = items.filter(it => it.decision.decision === 'needs-approval')
  const tokens = pending.map(it => it.sum.integrity && approvalToken(it.sum))
  return {
    schemaVersion: SCHEMA_VERSION,
    decision,
    reason,
    message: MESSAGES[reason],
    command: decision === 'refuse' ? null : { npx: p.npx, npryx: pinArgs(args, items) },
    approve: pending.length && tokens.every(Boolean) ? tokens.join(',') : null,
    packages: items.map(it => packageReport(it, p.store))
  }
}

function trustListReport () {
  const store = loadStore()
  const packages = Object.keys(store).flatMap(name => Object.entries(trustedVersions(store[name]))
    .map(([version, e]) => ({ name, version, integrity: e.integrity || null, approvedAt: e.approvedAt || null })))
  return { schemaVersion: SCHEMA_VERSION, path: TRUST_PATH, packages }
}

function scanStatusReport () {
  const cfg = scanConfig(process.env, loadJson(SCAN_CONFIG_PATH))
  return { schemaVersion: SCHEMA_VERSION, enabled: Boolean(cfg), url: cfg ? cfg.url : null, keyPinned: Boolean(cfg && cfg.key), token: Boolean(cfg && cfg.token), deep: Boolean(cfg && cfg.deep) }
}

function emit (doc, code) {
  process.stdout.write(JSON.stringify(doc, null, 2) + '\n')
  process.exitCode = code
}

async function jsonMain (args) {
  try {
    if (args[0] === '--trust-list') return emit(trustListReport(), 0)
    if (args[0] === '--scan-status') return emit(scanStatusReport(), 0)
    if (NO_JSON.has(args[0])) throw usageError(`${args[0]} has no JSON mode`)
    if (!args.length) throw usageError('usage: npryx --json <pkg>[@<version>] [args...]')
    const parsed = parseArgs(args)
    if (parsed.error) throw usageError(parsed.error)
    const p = await plan(args, parsed, { downloads: true })
    emit(checkReport(args, p), EXIT[p.decision.decision])
  } catch (e) {
    const code = e.code === 'usage' ? 'usage' : 'internal'
    emit({ schemaVersion: SCHEMA_VERSION, error: { code, message: e.message } }, code === 'usage' ? EXIT.usage : 1)
  }
}

// --- main --------------------------------------------------------------------

// What npryx would do with these args, worked out without running anything.
// The interactive run, the CI run and --json all act on this.
async function plan (args, parsed, { downloads }) {
  const base = withoutYes(args, parsed)
  const tgts = targets(parsed, args)
  const shortcut = (reason, npx) => ({ decision: { decision: 'allow', reason }, npx })

  // Nothing to install (`--help`, `-c` with no -p): hand to npx, but with --no
  // unless the user chose themselves, so it can't install behind our back.
  if (!tgts.length) return shortcut('nothing-to-install', parsed.yes == null ? ['--no', ...args] : args)

  // `npx tsc` in a project with typescript runs the local bin; don't preview
  // the unrelated registry package `tsc`. `--no` makes npx refuse to install
  // if we got this wrong.
  const only = tgts[0]
  if (tgts.length === 1 && only.prefix === '' && parsed.packages.length === 0 && !parsed.prefix &&
      classify(only.spec) === 'registry' && !splitSpec(only.spec).version && !only.spec.startsWith('@') &&
      localBin(only.spec, process.cwd())) {
    return shortcut('local-bin', ['--no', ...base])
  }

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
  const pending = items.filter(it => !cleared(it))
  // Downloads and the opt-in remote scan, in parallel, for what still needs a
  // decision. Only public-registry packages are ever sent to a scan service.
  const scanCfg = scanConfig(process.env, loadJson(SCAN_CONFIG_PATH))
  await Promise.all(pending.filter(it => it.sum).map(it => Promise.all([
    downloads && weeklyDownloads(it.sum).then(d => { it.downloads = d }),
    scanCfg && it.sum.publicRegistry && it.sum.integrity && remoteScan(scanCfg, it.sum).then(s => { it.scan = s })
  ])))

  const policy = { forceYes: parsed.yes === true || process.env.NPRYX_YES === '1', allow: parseAllow(process.env.NPRYX_ALLOW) }
  for (const it of items) it.decision = decide(it, policy)
  const pinned = withoutYes(pinArgs(args, items), parsed) // pin by original index, then strip
  return { items, pending, store, pinned, npx: ['--yes', ...pinned], decision: overall(items.map(it => it.decision)) }
}

async function main () {
  const args = process.argv.slice(2)

  if (args[0] === '--json') return jsonMain(args.slice(1))
  if (args.length === 2 && args[1] === '--json' && ['--trust-list', '--scan-status'].includes(args[0])) return jsonMain(args.slice(0, 1))
  if (args.length === 1 && (args[0] === '--help' || args[0] === '-h')) process.stdout.write(helpText())
  if (args.length === 1 && (args[0] === '--version' || args[0] === '-v')) process.stdout.write(`npryx ${require('./package.json').version}, npx `)
  if (args[0] === '--alias') { process.stdout.write(aliasLine()); return }
  if (args[0] === '--setup-alias') return setupAlias(args.slice(1))
  if (args[0] === '--remove-alias') return removeAlias(args.slice(1))
  if (args[0] === '--trust-list') return printTrustList()
  if (args[0] === '--forget') return forget(args[1])
  if (args[0] === '--scan-config') return scanSetup(args.slice(1))
  if (args[0] === '--scan-off') return scanOff()
  if (args[0] === '--scan-status') return scanStatus()

  const parsed = parseArgs(args)
  if (parsed.error) refuse(say(ERR, ERR.warn, parsed.error))
  const isTTY = process.stdin.isTTY && process.stderr.isTTY
  const p = await plan(args, parsed, { downloads: isTTY })
  if (!p.items) return runNpx(p.npx)

  const { items, pending, pinned } = p
  if (!pending.length) {
    for (const it of items) if (it.sum) console.error(say(ERR, ERR.good, `${ERR.bold(`${it.sum.name}@${it.sum.version}`)} is trusted ${ERR.dim(`(approved ${approvedOn(it.trust.approvedAt)})`)}`))
    return runNpx(p.npx)
  }
  for (const it of pending) {
    process.stderr.write(it.sum
      ? render(it.sum, { requested: it.requested, downloads: it.downloads ?? null, squat: typosquat(it.sum.name), trust: it.trust, scan: it.scan })
      : renderUnverified(it))
  }

  // Never auto-run, and never offer to trust: altered bytes, or a confirmed
  // threat from the remote scan.
  const blocked = it => ['tampered', 'confirmed-threat'].includes(it.decision.reason)

  // FAIL CLOSED: non-interactive runs need every pending package explicitly
  // allowed (or a blanket opt-out). Blocked packages are never auto-run.
  if (!isTTY) {
    if (p.decision.decision === 'allow') return runNpx(p.npx)
    if (pending.some(blocked)) refuse(say(ERR, ERR.bad, `${ERR.red('refusing to run: a package above is tampered or a confirmed threat.')}\n           NPRYX_YES and NPRYX_ALLOW do not override this.`))
    refuse(say(ERR, ERR.warn, `refusing to auto-run in a non-interactive shell (fail-closed).\n           Set ${ERR.bold('NPRYX_ALLOW=<name>[@<version>]')} or ${ERR.bold('NPRYX_YES=1')} to override.`))
  }

  const canTrust = pending.every(it => it.sum && it.sum.integrity && !blocked(it))
  const ans = await chooseAction(canTrust)
  if (ans === 'y') return runNpx(p.npx)
  if (ans === 's') return runNpx(['--yes', '--ignore-scripts', ...pinned])
  if (ans === 'a' && canTrust) { recordTrust(pending.map(it => it.sum)); return runNpx(p.npx) }
  refuse(say(ERR, null, 'aborted, nothing ran.'))
}

if (require.main === module) {
  main().catch(e => { console.error(say(ERR, ERR.bad, e.message)); process.exit(1) })
}

module.exports = {
  parseArgs, targets, splitSpec, classify, pickVersion, summarize, editDistance, typosquat,
  trustMatch, isAllowed, parseAllow, approvalToken, decide, overall, pinArgs, withoutYes, localBin,
  scanConfig, verifyEnvelope, scanVerdict, renderScan, render, useColor, palette, wrap, promptText,
  aliasRcPath, aliasBlock, appendAliasBlock, hasAliasBlock, foreignNpxAlias, removeAliasBlock
}
