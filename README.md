<p align="center">
  <img src="assets/npryx-logo.png" alt="npryx logo" width="180" />
</p>

<h1 align="center">npryx</h1>
<p align="center"><strong>A security-first superset of <code>npx</code>.</strong></p>

`npx` will happily download and **execute** an arbitrary remote package behind a
bare prompt:

```
Need to install the following packages:
  some-package@1.0.0
Ok to proceed? (y/N)
```

That prompt tells you **nothing** — not whether the package runs install scripts,
how old or popular it is, whether it's deprecated, whether it has build
provenance, or whether the name is one keystroke away from a package you actually
meant. It's exactly where supply-chain attacks land: typosquats, `postinstall`
RCE, hijacked re-publishes.

**npryx** forwards every argument to the real `npx`, untouched — but **first** it
shows you the trust signals `npx` hides, **fails closed** if it can't verify the
package, offers a one-keystroke `--ignore-scripts` safe run, and **remembers**
what you've already approved so the prompt keeps meaning something.

```
  npryx — about to fetch & run a package from the npm registry

  package       esbuild@0.28.1   (asked: latest)
  published     11d ago
  weekly dl     243,988,517
  maintainers   esbuild
  repo          git+https://github.com/evanw/esbuild.git
  integrity     sha512-HrJrvZv5ayxBzPfwp…
  provenance    ✓ https://slsa.dev/provenance/v1
  install hook  ⚠️  YES — runs code on install

  ⚠️  2 warning(s):
       • runs install scripts (postinstall) — executes code on install
       • published only 11d ago — brand new, little scrutiny yet

  [y] run   [s] run with --ignore-scripts (safer)   [a] always-trust this version   [N] abort:
```

## What it shows

A single `npm view <spec> --json` (so it resolves ranges, tags, and **your**
`.npmrc` — including private registries and auth) gives every signal below.
Weekly downloads come from the public npm API as a best-effort hint.

| signal | flagged when |
|---|---|
| **install scripts** | `preinstall` / `install` / `postinstall` present — the package runs code the moment it's installed |
| **provenance** | shown ✓ when the build has signed [SLSA provenance](https://slsa.dev) attestations |
| **publish age** | younger than ~30 days — brand new, little scrutiny yet |
| **weekly downloads** | under ~1,000 — unusually low |
| **deprecation** | the maintainer marked it deprecated |
| **typosquat** | the name is one edit away from a popular package (`crossenv` → `cross-env`) |
| **context** | resolved `name@version`, maintainers, repo, and `dist.integrity` — always shown |

## The prompt

| key | action |
|---|---|
| `y` | run it — `npx --yes <args>` |
| `s` | run with `--ignore-scripts` (skips install hooks; safer). Note: a few packages legitimately need a `postinstall` to fetch a native binary, e.g. `esbuild` — if it breaks, re-run with `y`. |
| `a` | always-trust **this exact version**, then run (see below) |
| `N` | abort (the default — just press Enter) |

## Trust model (TOFU)

Choosing `a` records the package's **integrity hash** (sha512) in
`~/.npryx.json`. Next time you run the same package:

- **integrity matches** → it's the bytes you approved. npryx prints `trusted ✓`
  and proceeds with no prompt — no fatigue, no reflexive `y`.
- **integrity differs** → something changed since you trusted it. npryx re-prompts
  with a loud `⚠️ CHANGED 1.5.0 → 1.6.0`. A hijacked re-publish produces new bytes,
  so it **always** re-prompts — trust never silently carries to code you haven't seen.

```
npryx --trust-list        # show what you've trusted
npryx --forget <pkg>      # drop a package from the trust store
```

## Fails closed

If npryx **can't** verify a package (no such name, registry error), it does **not**
quietly run it:

- **interactive terminal** → it warns and defaults the prompt to **No**.
- **non-interactive / CI** → it **refuses and exits 1**. This deliberately inverts
  npm's "assume yes in CI" default — an unverified package never auto-runs in a
  pipeline. To allow specific packages, set `NPRYX_ALLOW=pkg-a,pkg-b`, or
  `NPRYX_YES=1` to opt out entirely. Packages already in your trust store run
  without a prompt.

Local paths, URLs, and git specifiers (`./x`, `github:u/r`, `git+ssh://…`) can't be
verified via the registry and are forwarded straight through, unaltered.

## Install

Requires **Node 18+** (uses global `fetch` and `readline/promises`). Zero runtime
dependencies.

```
npm install -g npryx
npryx cowsay "moo"
```

Want every `npx` to go through npryx? Add an alias (npryx prints the right line
for your shell — it never edits your rc for you):

```
npryx --alias
# → add to ~/.zshrc, then restart your shell:
#   alias npx='npryx'
```

## Prior art

[`npq`](https://github.com/lirantal/npq) pioneered install-time marshalling of npm
package safety signals, and npryx borrows its signal taxonomy. npryx differs by
wrapping **`npx` execution** specifically, **failing closed**, offering the inline
`--ignore-scripts` run, and keeping a TOFU trust store.

## License

ISC. See `LICENSE.md`.
