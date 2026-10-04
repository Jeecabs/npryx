'use strict'
// Stand-in for network tools (curl, wget, nc, …) on the sandbox PATH. Records
// the command line and anything piped to it, then fails. The container has no
// network anyway; this exists so the attempt (and what it tried to send) is seen.
const fs = require('fs')
const tool = process.argv[2]
const args = process.argv.slice(3)
let stdin = Buffer.alloc(0)
try { if (!process.stdin.isTTY) stdin = fs.readFileSync(0).subarray(0, 64 * 1024) } catch {}
const ev = {
  kind: 'exec', via: 'shim', target: [tool, ...args].join(' '),
  phase: process.env.NPRYX_PHASE || 'unknown', run: process.env.NPRYX_RUN || 'unknown', pid: process.pid,
  payload_b64: stdin.length ? stdin.toString('base64') : undefined
}
try { fs.appendFileSync(process.env.NPRYX_EVENTS, JSON.stringify(ev) + '\n') } catch {}
process.stderr.write(`${tool}: network disabled in npryx sandbox\n`)
process.exit(7)
