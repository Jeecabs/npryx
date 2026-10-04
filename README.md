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

**npryx** hands your command to the real `npx`, but **first** it shows you the
trust signals `npx` hides, **fails closed** if it can't verify the package, offers
a one-keystroke `--ignore-scripts` safe run, and **remembers** what you've already
approved so the prompt keeps meaning something. It then runs **exactly the
version it showed you**, never a fresh resolve.

```
  npryx — about to fetch & run a package from the npm registry

  package       esbuild@0.28.1   (asked: latest)
  published     11d ago
  weekly dl     41,284,663
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
Registry flags you pass (`--registry`, `--userconfig`, `--@scope:registry`, …) are
used for the preview too, so it reads the same registry the run installs from.
Weekly downloads come from the public npm API as a best-effort hint, and only for
packages served by the public registry, so private package names never leave your
machine.

| signal | flagged when |
|---|---|
| **install scripts** | `preinstall` / `install` / `postinstall` present — the package runs code the moment it's installed |
| **provenance** | shown ✓ when the build has signed [SLSA provenance](https://slsa.dev) attestations |
| **publish age** | younger than ~30 days — brand new, little scrutiny yet |
| **weekly downloads** | under ~1,000 — unusually low |
| **deprecation** | the maintainer marked it deprecated |
| **typosquat** | the name is one edit or one swapped pair of letters away from a popular package (`crossenv` → `cross-env`, `lodahs` → `lodash`) |
| **context** | resolved `name@version`, maintainers, repo, and `dist.integrity` — always shown |

> **Scope:** npryx previews the **target** package — `npm view` reports the target's
> own install scripts, not a transitive dependency's. The `s` (`--ignore-scripts`)
> option blocks install hooks across the whole tree, so reach for it when a target
> you trust pulls deps you don't.

## The prompt

| key | action |
|---|---|
| `y` | run it — `npx --yes <args>`, pinned to the version shown |
| `s` | run with `--ignore-scripts` (skips install hooks; safer). Note: a few packages legitimately need a `postinstall` to fetch a native binary, e.g. `esbuild` — if it breaks, re-run with `y`. |
| `a` | always-trust **this exact version**, then run (see below). Not offered when the package couldn't be verified. |
| `N` | abort (the default — just press Enter) |

## Trust model (TOFU)

Choosing `a` records the version and its **integrity hash** (sha512) in
`~/.npryx.json`. You can trust several versions of the same package. Next time:

- **same version, same integrity** → the bytes you approved. npryx prints
  `trusted ✓` and runs with no prompt — no fatigue, no reflexive `y`.
- **a version you haven't approved** → a normal new release. npryx shows the full
  preview with a note (`you trusted cowsay@1.5.0; this is 1.6.0`) and asks again.
- **same version, different integrity** → npm never lets a published version be
  overwritten, so a registry, mirror or proxy is serving altered code. npryx shows
  a loud warning, and this is **never** auto-run, not even with `NPRYX_YES=1`.

```
npryx --trust-list                 # show what you've trusted
npryx --forget <pkg>[@<version>]   # drop a package, or one version of it
```

## Fails closed

If npryx **can't** verify a package (no such name, registry error), it does **not**
quietly run it:

- **interactive terminal** → it warns and defaults the prompt to **No**.
- **non-interactive / CI** → it **refuses and exits 1** for any package that isn't
  already trusted. This deliberately inverts npm's "assume yes in CI" default —
  an unverified package never auto-runs in a pipeline. To allow packages, set
  `NPRYX_ALLOW` to a comma-separated list of `name` (any version), `name@version`
  (prefer this) or an integrity hash (`sha512-…`). `NPRYX_YES=1`, or `-y` placed
  **before** the package, opts out entirely. A `-y` after the package belongs to
  the command being run and changes nothing.

It also refuses, rather than guesses, when it can't tell which package would run:

- **unrecognised flags** before the package. npm treats any config key as a flag,
  so an unknown `--flag` might swallow the next argument. Write it as
  `--flag=value` and npryx will pass it through.
- **git, URL and alias specs** (`github:u/r`, `git+ssh://…`, `https://…/x.tgz`,
  `foo@npm:bar`) can't be checked against the registry, so they're treated like
  an unverifiable package: a prompt that defaults to No, or a refusal in CI unless
  the exact spec is in `NPRYX_ALLOW`.

Every `-p` package is previewed, not just the first.

Two things go straight to npx without a preview:

- **local paths** (`./x`, `/abs/path`, `file:…`, `x.tgz`) — your own files.
- **bins installed in your project** (`npx tsc` with `typescript` in
  `node_modules`), which npx runs without fetching anything. These are passed
  with `--no`, so if npryx misjudged and npx would need to install something,
  npx refuses instead.

## Remote scanning (optional)

npryx can also ask a scan service whether a package **sends data off your machine**:
environment variables to a raw IP, tokens to a webhook, secrets hidden in DNS lookups.
The service reads the code, compares it with the previous version, checks OSV for known
malware and, if you opt in to that too, runs the package in a sandbox full of fake
credentials to see if any of them try to leave.

It's **off by default**. Nothing is sent anywhere until you turn it on:

```
npryx --scan-config https://scan.example.com [--token <key>] [--deep]
npryx --scan-status
npryx --scan-off
```

- Only packages from the public npm registry are sent. Private package names never leave
  your machine.
- Results are signed, and npryx pins the service's key when you opt in.
- A scan can only **add** caution. A confirmed threat is blocked like tampered bytes:
  never auto-run, even with `NPRYX_YES`. If the service is down, slow or unverifiable,
  npryx behaves exactly as it does without it.
- The service is open source (`scan-service/`, Rust), so you can run your own. A hosted
  version needs an API key.

Design and detection details: [docs/scan-service.md](docs/scan-service.md). Wire format:
[docs/scan-api.md](docs/scan-api.md).

## Install

Requires **Node 22+**. Zero runtime dependencies. The only dev dependency is
[Hegel](https://github.com/hegeldev/hegel-typescript) for property-based tests,
pinned by the lockfile and installed with scripts disabled (see `.npmrc`).

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

## Roadmap

npryx isn't on npm yet. Planned, roughly in order:

- **Publish with provenance.** Ship npryx itself via `npm publish --provenance` from
  CI using OIDC trusted publishing (no long-lived token) — so `npryx npryx` shows its
  own `provenance ✓`. Practise what it preaches.
- **Transitive install-script preview.** Today npryx previews the **target** only, but
  the real risk is a *dependency's* `postinstall`. A metadata-only resolve
  (`npm install --package-lock-only --ignore-scripts` — no download, nothing executed,
  ~3s) surfaces every package in the tree that runs install scripts. The TOFU store
  would pin that set, so a trusted target re-prompts when its tree changes.

## License

ISC. See `LICENSE.md`.
