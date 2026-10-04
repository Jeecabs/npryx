// npryx's pure logic. Properties (via Hegel) cover the parser — the part where
// one wrong guess means previewing package A and running package B. A few
// real-world examples pin down the cases we know attackers use.

import { test } from 'node:test'
import assert from 'node:assert'
import * as hegel from '@hegeldev/hegel'
import * as gs from '@hegeldev/hegel/generators'
import npryx from '../npryx.js'

const { parseArgs, targets, splitSpec, classify, pickVersion, summarize, editDistance, typosquat, trustMatch, pinArgs, withoutYes } = npryx

// --- generators --------------------------------------------------------------
const NAME = gs.fromRegex('(@[a-z][a-z0-9-]{0,5}/)?[a-z][a-z0-9._-]{0,10}')
const VERSION = gs.fromRegex('(\\^|~)?[0-9]{1,2}\\.[0-9]{1,2}\\.[0-9]{1,2}|latest|next')
const SPEC = gs.oneOf(NAME, gs.tuples(NAME, VERSION).map(([n, v]) => `${n}@${v}`))
const ANY = gs.text({ maxSize: 12 })

// One npx flag as it might appear on a command line (1 or 2 tokens).
const FLAG = gs.oneOf(
  gs.sampledFrom(['-y', '--yes', '--no', '--no-yes', '--yes=false', '-q', '--prefer-offline', '--no-color', '--ignore-scripts']).map(f => [f]),
  gs.tuples(gs.sampledFrom(['--registry', '--cache', '--loglevel', '-w', '--userconfig', '--@acme:registry']), ANY),
  gs.tuples(gs.sampledFrom(['-p', '--package']), gs.oneOf(SPEC, ANY)),
  SPEC.map(s => [`--package=${s}`]),
  gs.tuples(gs.sampledFrom(['-c', '--call']), ANY),
  gs.fromRegex('--[a-z]{2,8}=[a-z]{0,4}').map(f => [f]),
  gs.fromRegex('--[a-z]{3,8}').map(f => [f]) // unknown: must be refused, never guessed
)

const ARGV = gs.composite(tc => [
  ...tc.draw(gs.arrays(FLAG, { maxSize: 5 })).flat(),
  ...(tc.draw(gs.booleans()) ? [tc.draw(SPEC)] : []),
  ...tc.draw(gs.arrays(ANY, { maxSize: 4 })) // the command's own args — anything goes
])

const prop = (name, fn) => test(name, () => hegel.test(fn, { testCases: 300 }))

// --- the core invariant: run exactly what was previewed ----------------------
prop('after pinning, npx would install exactly the previewed packages', tc => {
  const args = tc.draw(ARGV)
  const parsed = parseArgs(args)
  if (parsed.error) return // refused: nothing runs, which is always safe
  const items = targets(parsed, args).map(target => ({ target, sum: { name: `p${target.at}`, version: '9.9.9' } }))
  const run = withoutYes(pinArgs(args, items), parsed)
  const again = parseArgs(run)

  assert.strictEqual(again.error, null)
  assert.deepStrictEqual(targets(again, run).map(t => t.spec), items.map(i => `p${i.target.at}@9.9.9`))
  assert.strictEqual(again.yes, null, 'npryx alone decides --yes/--no')
  if (parsed.positional >= 0) {
    assert.deepStrictEqual(run.slice(again.positional + 1), args.slice(parsed.positional + 1), "the command's args pass through untouched")
  }
})

prop('a flag npryx does not know (without =value) is refused, wherever it sits before the package', tc => {
  const before = tc.draw(gs.arrays(FLAG, { maxSize: 3 })).flat()
  const unknown = tc.draw(gs.fromRegex('--(x|zz)[a-z]{2,6}'))
  const args = [...before, unknown, 'value', 'cowsay']
  const parsed = parseArgs(args)
  assert.ok(parsed.error, `expected ${JSON.stringify(args)} to be refused`)
})

prop('a -y after the package belongs to the command and never opts out', tc => {
  const args = [tc.draw(SPEC), ...tc.draw(gs.arrays(gs.sampledFrom(['-y', '--yes', 'x']), { maxSize: 4 }))]
  assert.strictEqual(parseArgs(args).yes, null)
})

// --- spec handling -----------------------------------------------------------
prop('splitSpec round-trips name@version, scoped or not', tc => {
  const [name, version] = [tc.draw(NAME), tc.draw(VERSION)]
  assert.deepStrictEqual(splitSpec(`${name}@${version}`), { name, version })
  assert.deepStrictEqual(splitSpec(name), { name, version: null })
})

prop('classify: registry names stay registry; paths are local; git/url/alias forms are remote', tc => {
  const spec = tc.draw(SPEC)
  assert.strictEqual(classify(spec), 'registry')
  assert.strictEqual(classify(`./${spec}`), 'local')
  for (const remote of [`github:${spec}`, `git+https://x/${spec}`, `https://x/${spec}.tgz`, `alias@npm:${spec}`]) {
    assert.strictEqual(classify(remote), 'remote', remote)
  }
})

test('classify: names that merely start with "git" are registry packages', () => {
  for (const s of ['gitmoji-cli', 'git-cz', 'github-release-notes']) assert.strictEqual(classify(s), 'registry')
  assert.strictEqual(classify('user/repo'), 'remote', 'github shorthand')
})

// --- typosquat ---------------------------------------------------------------
prop('editDistance is symmetric, zero on itself, one per insert or adjacent swap', tc => {
  const a = tc.draw(gs.fromRegex('[a-z-]{0,10}'))
  const b = tc.draw(gs.fromRegex('[a-z-]{0,10}'))
  assert.strictEqual(editDistance(a, b), editDistance(b, a))
  assert.strictEqual(editDistance(a, a), 0)
  assert.strictEqual(editDistance(a, a + 'q'), 1)
  const i = tc.draw(gs.integers({ minValue: 0, maxValue: Math.max(0, a.length - 2) }))
  if (a.length >= 2 && a[i] !== a[i + 1]) assert.strictEqual(editDistance(a, a.slice(0, i) + a[i + 1] + a[i] + a.slice(i + 2)), 1)
})

test('typosquat: known squats are caught, real and short names are not', () => {
  const cases = {
    crossenv: 'cross-env', // the 2017 crossenv malware
    expres: 'express',
    lodahs: 'lodash', // swapped letters
    express: null, // the real thing
    test: null, // one edit from `jest`, but short names are exact-only
    '@scope/express': null // squats target unscoped names
  }
  for (const [name, want] of Object.entries(cases)) assert.strictEqual(typosquat(name), want, name)
})

// --- registry metadata -------------------------------------------------------
test('summarize reads hooks, provenance and registry from real npm view shapes', () => {
  const tarball = 'https://registry.npmjs.org/x/-/x.tgz'
  const cases = [
    [{ name: 'cowsay', version: '1.6.0', scripts: { prepare: 'rollup -c' }, dist: { integrity: 'sha512-c', tarball } },
      { runsInstallScripts: false, hooks: [], provenance: null, publicRegistry: true }],
    [{ name: 'esbuild', version: '0.28.1', scripts: { postinstall: 'node install.js' }, dist: { integrity: 'sha512-e', attestations: { provenance: { predicateType: 'https://slsa.dev/provenance/v1' } } } },
      { runsInstallScripts: true, hooks: ['postinstall'], provenance: 'https://slsa.dev/provenance/v1', publicRegistry: false }]
  ]
  for (const [json, want] of cases) {
    const s = summarize(json)
    for (const [k, v] of Object.entries(want)) assert.deepStrictEqual(s[k], v, `${json.name}.${k}`)
  }
})

test('pickVersion prefers the latest tag within a range, like npm', () => {
  const tags = { latest: '1.5.0' }
  assert.strictEqual(pickVersion([{ version: '1.5.0', 'dist-tags': tags }, { version: '1.6.0', 'dist-tags': tags }]).version, '1.5.0')
  assert.strictEqual(pickVersion([{ version: '1.5.0' }, { version: '1.6.0' }]).version, '1.6.0')
})

// --- trust store -------------------------------------------------------------
prop('trust: only the exact approved (version, integrity) pair is trusted', tc => {
  const [v1, v2] = [tc.draw(VERSION), tc.draw(VERSION)]
  const [i1, i2] = [tc.draw(gs.fromRegex('sha512-[a-z]{4}')), tc.draw(gs.fromRegex('sha512-[a-z]{4}'))]
  const store = { pkg: { [v1]: { integrity: i1 } } }
  const status = trustMatch(store, { name: 'pkg', version: v2, integrity: i2 }).status
  const want = v1 !== v2 ? 'updated' : i1 === i2 ? 'trusted' : 'tampered'
  assert.strictEqual(status, want)
  assert.strictEqual(trustMatch({ pkg: { version: v1, integrity: i1 } }, { name: 'pkg', version: v2, integrity: i2 }).status, want, 'v1 store format')
})
