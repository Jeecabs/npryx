'use strict'
// Pure-logic tests for npryx — zero deps (Node's stdlib test runner), no network.
// Every registry shape is a captured `npm view --json` fixture (cowsay / esbuild /
// sigstore, real shapes Jan 2026). Run with: node --test test/npryx.js

const { test } = require('node:test')
const assert = require('node:assert')
const { targetSpec, splitSpec, isRegistrySpec, pickVersion, summarize, typosquat, trustMatch } = require('../npryx.js')

// --- captured `npm view --json` fixtures (trimmed to fields npryx reads) ------
const COWSAY = { // clean: no install hooks, signed, popular
  name: 'cowsay',
  version: '1.6.0',
  maintainers: ['piuccio <piuccio@gmail.com>'],
  repository: { type: 'git', url: 'git+https://github.com/piuccio/cowsay.git' },
  time: { '1.6.0': '2024-01-26T06:24:22.739Z' },
  scripts: { prepare: 'rollup -c', test: 'tape test/**/*.js' },
  dist: { integrity: 'sha512-8C4H1jdrgNusTQr3Yu4SCm+ZKsAlDFbpa0KS0Z3im8u', signatures: [{ keyid: 'SHA256:jl3b', sig: 'MEYC' }] }
}
const ESBUILD = { // install script + provenance
  name: 'esbuild',
  version: '0.28.1',
  scripts: { postinstall: 'node install.js' },
  dist: { integrity: 'sha512-esbuildxxx', attestations: { url: 'https://registry.npmjs.org/-/npm/v1/attestations/esbuild@0.28.1', provenance: { predicateType: 'https://slsa.dev/provenance/v1' } } }
}
const SIGSTORE = { // clean scripts + provenance
  name: 'sigstore',
  version: '5.0.0',
  scripts: { clean: 'shx rm -rf dist', build: 'tsc --build', test: 'jest' },
  dist: { integrity: 'sha512-sigstorexxx', attestations: { provenance: { predicateType: 'https://slsa.dev/provenance/v1' } } }
}

test('targetSpec finds the package and skips flags + value-flag pairs', () => {
  assert.strictEqual(targetSpec(['cowsay', 'moo']), 'cowsay')
  assert.strictEqual(targetSpec(['-p', 'lol', '-c', 'x']), 'lol')
  assert.strictEqual(targetSpec(['--package=foo', 'bar']), 'foo')
  assert.strictEqual(targetSpec(['--cache', '/tmp/x', 'realpkg']), 'realpkg', 'value-flag value is not mistaken for the pkg')
  assert.strictEqual(targetSpec(['--node-arg', '--inspect', 'cowsay']), 'cowsay')
  assert.strictEqual(targetSpec(['--help']), null)
  assert.strictEqual(targetSpec([]), null)
})

test('splitSpec separates name@version and keeps @scope intact', () => {
  assert.deepStrictEqual(splitSpec('cowsay'), { name: 'cowsay', version: null })
  assert.deepStrictEqual(splitSpec('cowsay@1.2.3'), { name: 'cowsay', version: '1.2.3' })
  assert.deepStrictEqual(splitSpec('@scope/pkg'), { name: '@scope/pkg', version: null })
  assert.deepStrictEqual(splitSpec('@scope/pkg@2'), { name: '@scope/pkg', version: '2' })
  assert.strictEqual(splitSpec(null), null)
})

test('isRegistrySpec accepts registry names, rejects paths/urls/git', () => {
  assert.strictEqual(isRegistrySpec('cowsay'), true)
  assert.strictEqual(isRegistrySpec('@scope/pkg'), true)
  assert.strictEqual(isRegistrySpec('./local'), false)
  assert.strictEqual(isRegistrySpec('/abs/path'), false)
  assert.strictEqual(isRegistrySpec('github:piuccio/cowsay'), false)
  assert.strictEqual(isRegistrySpec('git+ssh://x/y.git'), false)
  assert.strictEqual(isRegistrySpec('user/repo'), false, 'github shorthand is not a registry name')
})

test('pickVersion takes the highest from an ascending array, else the object', () => {
  assert.strictEqual(pickVersion([{ version: '1.5.0' }, { version: '1.6.0' }]).version, '1.6.0')
  assert.strictEqual(pickVersion({ version: '2.0.0' }).version, '2.0.0')
  assert.strictEqual(pickVersion([]), null)
})

test('summarize: cowsay is clean (no install hooks, no provenance)', () => {
  const s = summarize(COWSAY)
  assert.strictEqual(s.name, 'cowsay')
  assert.strictEqual(s.version, '1.6.0')
  assert.strictEqual(s.runsInstallScripts, false)
  assert.deepStrictEqual(s.hooks, [])
  assert.strictEqual(s.provenance, null)
  assert.strictEqual(s.deprecated, null)
  assert.strictEqual(s.published, '2024-01-26T06:24:22.739Z')
  assert.deepStrictEqual(s.maintainers, ['piuccio'], 'name parsed out of "name <email>"')
  assert.strictEqual(s.repo, 'git+https://github.com/piuccio/cowsay.git')
  assert.ok(s.integrity.startsWith('sha512-'))
})

test('summarize: esbuild flags the postinstall hook AND shows provenance', () => {
  const s = summarize(ESBUILD)
  assert.strictEqual(s.runsInstallScripts, true)
  assert.deepStrictEqual(s.hooks, ['postinstall'])
  assert.strictEqual(s.provenance, 'https://slsa.dev/provenance/v1')
})

test('summarize: sigstore has provenance but no install hooks', () => {
  const s = summarize(SIGSTORE)
  assert.strictEqual(s.runsInstallScripts, false)
  assert.strictEqual(s.provenance, 'https://slsa.dev/provenance/v1')
})

test('summarize picks the highest version when handed a range array', () => {
  const s = summarize([{ name: 'cowsay', version: '1.5.0' }, COWSAY])
  assert.strictEqual(s.version, '1.6.0')
})

test('typosquat catches one-edit lookalikes, not exact or scoped names', () => {
  assert.strictEqual(typosquat('crossenv'), 'cross-env', 'the real crossenv malware case')
  assert.strictEqual(typosquat('expres'), 'express')
  assert.strictEqual(typosquat('express'), null, 'exact match is the real package')
  assert.strictEqual(typosquat('cowsay'), null, 'popular exact name is not a squat')
  assert.strictEqual(typosquat('@scope/express'), null, 'scoped names are skipped')
  assert.strictEqual(typosquat('totally-unrelated-name'), null)
})

test('trustMatch: integrity hit = trusted, differ = changed, absent = unknown', () => {
  const s = summarize(ESBUILD)
  assert.strictEqual(trustMatch({ esbuild: { integrity: s.integrity } }, s).status, 'trusted')
  const changed = trustMatch({ esbuild: { integrity: 'sha512-OLD', version: '0.1.0' } }, s)
  assert.strictEqual(changed.status, 'changed')
  assert.strictEqual(changed.from, '0.1.0')
  assert.strictEqual(changed.to, '0.28.1')
  assert.strictEqual(trustMatch({}, s).status, 'unknown')
})
