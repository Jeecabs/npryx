'use strict'
// npryx sandbox preload. Loaded into EVERY node process in the container via
// NODE_OPTIONS=--require, before any package code runs. It records what the
// package tries to do — network (tcp/tls/http/https/fetch/websocket/dns/udp),
// subprocesses, reads of credential files — as JSON lines, and makes network
// calls fail without sending anything.
//
// Limits (be honest about them): this is in-process instrumentation. Package
// code that loads a native addon, or that deliberately restores the originals
// (e.g. via process.binding), can bypass it. That is fine for *safety* — the
// container runs with --network none, so nothing can actually leave — but it
// means an evasive package can hide its attempts from this log. The upgrade
// path is kernel-level observation (eBPF / gVisor's syscall log), not more JS.

const fs = require('fs')
const path = require('path')

// Capture the originals before anything else can touch them, and open the
// event log append-only now, while we're the only code that has run.
const origOpenSync = fs.openSync
const origWriteSync = fs.writeSync
const EVENTS = process.env.NPRYX_EVENTS
let logFd = -1
try { if (EVENTS) logFd = origOpenSync(EVENTS, 'a') } catch {}

const RUN = process.env.NPRYX_RUN || 'unknown'
const HOME = process.env.HOME || '/home/sandbox'
const MAX_PAYLOAD = 64 * 1024
// npm's own CLI process (npm rebuild) spawns the lifecycle scripts and reads
// ~/.npmrc itself; that's not the package's behaviour, so don't log it.
const IS_NPM = /npm-cli\.js$|[/\\]npm$/.test(process.argv[1] || '')

function phase () { return process.env.NPRYX_PHASE || 'unknown' }

function toBuf (chunk, enc) {
  if (chunk == null) return Buffer.alloc(0)
  if (Buffer.isBuffer(chunk)) return chunk
  if (typeof chunk === 'string') return Buffer.from(chunk, typeof enc === 'string' ? enc : 'utf8')
  if (chunk instanceof ArrayBuffer) return Buffer.from(chunk)
  if (ArrayBuffer.isView(chunk)) return Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength)
  try { return Buffer.from(String(chunk)) } catch { return Buffer.alloc(0) }
}

function emit (ev) {
  if (logFd < 0) return
  ev.run = RUN
  ev.phase = ev.phase || phase()
  ev.pid = process.pid
  if (ev.payload) {
    const b = ev.payload.length > MAX_PAYLOAD ? ev.payload.subarray(0, MAX_PAYLOAD) : ev.payload
    ev.payload_b64 = b.toString('base64')
    delete ev.payload
  }
  try { origWriteSync(logFd, JSON.stringify(ev) + '\n') } catch {}
}

function refused (target) {
  const e = new Error(`connect ECONNREFUSED ${target} (npryx sandbox: network disabled)`)
  e.code = 'ECONNREFUSED'
  return e
}

// --- http / https: a fake ClientRequest that captures the body ---------------
const { EventEmitter } = require('events')

function urlFrom (proto, a, b) {
  try {
    if (typeof a === 'string' || a instanceof URL) {
      const u = new URL(String(a))
      return u.toString()
    }
    const o = a || {}
    const host = o.hostname || o.host || 'localhost'
    const port = o.port ? `:${o.port}` : ''
    return `${o.protocol || proto}//${host}${port}${o.path || '/'}`
  } catch { return `${proto}//?` }
}

function headersText (o) {
  const h = (o && typeof o === 'object' && !(o instanceof URL) && o.headers) || {}
  return Object.entries(h).map(([k, v]) => `${k}: ${v}`).join('\n')
}

function fakeRequest (proto) {
  return function request (a, b, c) {
    const opts = (typeof a === 'string' || a instanceof URL) ? (typeof b === 'object' ? b : {}) : a
    const target = urlFrom(proto, a, b)
    const req = new EventEmitter()
    const chunks = []
    let headers = headersText(opts)
    req.write = (chunk, enc, cb) => { chunks.push(toBuf(chunk, enc)); if (typeof enc === 'function') enc(); else if (cb) cb(); return true }
    req.end = (chunk, enc, cb) => {
      if (chunk && typeof chunk !== 'function') chunks.push(toBuf(chunk, enc))
      emit({ kind: 'http', target, method: (opts && opts.method) || 'GET', payload: Buffer.concat([Buffer.from(headers ? headers + '\n\n' : ''), ...chunks]) })
      process.nextTick(() => req.emit('error', refused(target)))
      const fn = [chunk, enc, cb].find(x => typeof x === 'function'); if (fn) fn()
      return req
    }
    req.setHeader = (k, v) => { headers += `\n${k}: ${v}` }
    req.getHeader = () => undefined
    req.removeHeader = () => {}
    req.setTimeout = () => req
    req.setNoDelay = () => {}
    req.setSocketKeepAlive = () => {}
    req.flushHeaders = () => {}
    req.abort = () => {}
    req.destroy = () => req
    return req
  }
}

for (const [mod, proto] of [['http', 'http:'], ['https', 'https:']]) {
  const m = require(mod)
  const request = fakeRequest(proto)
  m.request = request
  m.get = function get (a, b, c) { const r = request(a, b, c); r.end(); return r }
}

// --- fetch / WebSocket ---------------------------------------------------------
async function bodyBuf (body) {
  if (body == null) return Buffer.alloc(0)
  if (typeof body === 'string' || Buffer.isBuffer(body) || body instanceof ArrayBuffer || ArrayBuffer.isView(body)) return toBuf(body)
  if (typeof URLSearchParams !== 'undefined' && body instanceof URLSearchParams) return Buffer.from(body.toString())
  if (typeof Blob !== 'undefined' && body instanceof Blob) return Buffer.from(await body.arrayBuffer())
  if (typeof FormData !== 'undefined' && body instanceof FormData) {
    const parts = []
    for (const [k, v] of body.entries()) parts.push(`${k}=${typeof v === 'string' ? v : '[file]'}`)
    return Buffer.from(parts.join('&'))
  }
  return Buffer.from('[stream body]')
}

if (typeof globalThis.fetch === 'function') {
  globalThis.fetch = async function fetch (input, init = {}) {
    const target = typeof input === 'string' ? input : (input && (input.url || String(input)))
    let headers = ''
    try { headers = [...new Headers(init.headers || (input && input.headers) || {}).entries()].map(([k, v]) => `${k}: ${v}`).join('\n') } catch {}
    const body = await bodyBuf(init.body)
    emit({ kind: 'http', target, method: init.method || 'GET', payload: Buffer.concat([Buffer.from(headers ? headers + '\n\n' : ''), body]) })
    throw new TypeError('fetch failed (npryx sandbox: network disabled)')
  }
}

if (typeof globalThis.WebSocket === 'function') {
  globalThis.WebSocket = function WebSocket (url) {
    emit({ kind: 'tcp', target: String(url), proto: 'websocket' })
    throw refused(String(url))
  }
}

// --- net / tls -----------------------------------------------------------------
const net = require('net')
const tls = require('tls')

function netTarget (args) {
  const a = args[0]
  if (a && typeof a === 'object') return `${a.host || a.hostname || 'localhost'}:${a.port || ''}${a.path ? a.path : ''}`
  if (typeof a === 'number') return `${typeof args[1] === 'string' ? args[1] : 'localhost'}:${a}`
  return String(a)
}

const origSocketConnect = net.Socket.prototype.connect
net.Socket.prototype.connect = function connect (...args) {
  const target = netTarget(Array.isArray(args[0]) ? args[0] : args)
  // Unix sockets / local IPC (npm talks to its own children this way) are not egress.
  const a0 = Array.isArray(args[0]) ? args[0][0] : args[0]
  if (a0 && typeof a0 === 'object' && a0.path && !a0.port) return origSocketConnect.apply(this, args)
  if (typeof a0 === 'string' && isNaN(Number(a0))) return origSocketConnect.apply(this, args)
  emit({ kind: 'tcp', target })
  process.nextTick(() => this.destroy(refused(target)))
  return this
}
const origTlsConnect = tls.connect
tls.connect = function connect (...args) {
  const target = netTarget(args)
  emit({ kind: 'tcp', target, proto: 'tls' })
  const s = new net.Socket()
  process.nextTick(() => s.destroy(refused(target)))
  return s
}
void origTlsConnect

// --- dns -----------------------------------------------------------------------
const dns = require('dns')
function dnsFail (name) { const e = new Error(`getaddrinfo ENOTFOUND ${name}`); e.code = 'ENOTFOUND'; e.hostname = name; return e }
const DNS_FNS = ['lookup', 'resolve', 'resolve4', 'resolve6', 'resolveAny', 'resolveCname', 'resolveMx', 'resolveNs', 'resolveTxt', 'resolveSrv', 'resolveCaa', 'resolveNaptr', 'resolvePtr', 'resolveSoa', 'reverse', 'lookupService']
for (const fn of DNS_FNS) {
  if (typeof dns[fn] === 'function') {
    dns[fn] = function (name, ...rest) {
      emit({ kind: 'dns', target: String(name), rrtype: fn })
      const cb = rest.reverse().find(x => typeof x === 'function')
      if (cb) process.nextTick(() => cb(dnsFail(name)))
    }
  }
  if (dns.promises && typeof dns.promises[fn] === 'function') {
    dns.promises[fn] = async function (name) {
      emit({ kind: 'dns', target: String(name), rrtype: fn })
      throw dnsFail(name)
    }
  }
}
if (dns.Resolver) {
  for (const fn of DNS_FNS) {
    if (typeof dns.Resolver.prototype[fn] === 'function') {
      dns.Resolver.prototype[fn] = function (name, ...rest) {
        emit({ kind: 'dns', target: String(name), rrtype: fn })
        const cb = rest.reverse().find(x => typeof x === 'function')
        if (cb) process.nextTick(() => cb(dnsFail(name)))
      }
    }
  }
}

// --- dgram (udp) ---------------------------------------------------------------
const dgram = require('dgram')
dgram.createSocket = function createSocket () {
  const s = new EventEmitter()
  s.send = (msg, ...rest) => {
    const nums = rest.filter(x => typeof x === 'number')
    const strs = rest.filter(x => typeof x === 'string')
    const port = nums.length >= 3 ? nums[2] : nums[0]
    const addr = strs[0] || 'localhost'
    emit({ kind: 'udp', target: `${addr}:${port}`, payload: toBuf(Array.isArray(msg) ? Buffer.concat(msg.map(m => toBuf(m))) : msg) })
    const cb = rest.find(x => typeof x === 'function'); if (cb) process.nextTick(() => cb(refused(addr)))
  }
  for (const k of ['bind', 'close', 'connect', 'disconnect', 'setBroadcast', 'setTTL', 'addMembership', 'unref', 'ref']) s[k] = () => s
  s.address = () => ({ address: '0.0.0.0', port: 0, family: 'IPv4' })
  return s
}

// --- child_process ---------------------------------------------------------------
// Logged, then allowed: blocking every subprocess would break legitimate
// native builds. Network tools are shimmed on PATH (sandbox/shims) and the
// container has no network, so a spawned curl can't send anything either.
const cp = require('child_process')
function cmdline (file, args) {
  if (Array.isArray(args)) return [file, ...args].join(' ')
  return String(file)
}
for (const fn of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) {
  const orig = cp[fn]
  if (typeof orig !== 'function') continue
  cp[fn] = function (file, args, ...rest) {
    if (!IS_NPM) emit({ kind: 'exec', target: cmdline(file, Array.isArray(args) ? args : null) })
    return orig.call(this, file, args, ...rest)
  }
}

// --- fs reads of credential files ------------------------------------------------
const SENSITIVE = [
  '.npmrc', '.yarnrc', '.yarnrc.yml', '.netrc', '.git-credentials', '.gitconfig',
  '.aws/', '.ssh/', '.config/gcloud/', '.config/gh/', '.docker/config.json', '.kube/config',
  '.bash_history', '.zsh_history', '.config/solana/', '.ethereum/', '.electrum/', '.bitcoin/'
]
function sensitive (p) {
  let abs
  try { abs = path.resolve(String(p instanceof URL ? p.pathname : p)) } catch { return null }
  if (/^\/proc\/(self|\d+)\/environ$/.test(abs)) return abs
  const base = path.basename(abs)
  if (base === '.env' || base.startsWith('.env.')) return abs
  if (abs.startsWith(HOME + '/')) {
    const rel = abs.slice(HOME.length + 1)
    if (SENSITIVE.some(s => s.endsWith('/') ? (rel + '/').startsWith(s) : rel === s)) return '~/' + rel
  }
  return null
}
function watchRead (obj, fn) {
  const orig = obj[fn]
  if (typeof orig !== 'function') return
  obj[fn] = function (p, ...rest) {
    if (!IS_NPM && (typeof p === 'string' || p instanceof URL || Buffer.isBuffer(p))) {
      const hit = sensitive(Buffer.isBuffer(p) ? p.toString() : p)
      if (hit) emit({ kind: 'file_read', target: hit })
    }
    return orig.call(this, p, ...rest)
  }
}
for (const fn of ['readFileSync', 'readFile', 'open', 'createReadStream']) watchRead(fs, fn)
// openSync last: our own log fd was opened with the original above.
watchRead(fs, 'openSync')
if (fs.promises) for (const fn of ['readFile', 'open']) watchRead(fs.promises, fn)
