# npryx scan service

`npryx-scan` is an optional remote scanner that tells you when a package would send your
data somewhere it shouldn't: tokens to a webhook, environment variables to a raw IP,
secrets hidden in a DNS lookup. It lives in `scan-service/` and is written in Rust.

The wire format is in [scan-api.md](scan-api.md). This document is the design: what it
looks for, how it decides, and what it can't do.

## Principles

- **Opt-in, twice.** npryx never contacts a scan service unless the user configures one
  (`npryx --scan-config <url>` or `NPRYX_SCAN_URL`). The sandbox scan, which actually
  runs the package, is a second opt-in on top (`--deep` / `NPRYX_SCAN_DEEP=1`).
- **It can only add caution.** A scan result can add warnings or block a package. It can
  never clear a warning, approve a package, or skip the prompt. If the service is down,
  slow, unsigned or lying, npryx behaves exactly as it does without it.
- **Public packages only.** npryx only sends packages whose tarball comes from
  `registry.npmjs.org`. Private package names never leave the machine.
- **Signed results.** Every response is signed with the service's Ed25519 key, pinned by
  the client at setup. A result that doesn't verify is ignored.
- **One scan per published version, ever.** Published npm versions can't change, so
  results are cached by integrity hash forever. The service downloads the tarball itself
  and checks it against that hash before scanning, so the cache can't be poisoned.
- **"Nothing found" is not "safe".** The UI never claims otherwise.

## Hosted or self-hosted

The same binary serves both:

- **Hosted (paid).** Run with an API keys file (`NPRYX_SCAN_API_KEYS`). Every request
  needs a key; each key has its own rate limit; one JSON usage line per request goes to
  stdout for metering and billing. Users opt in with
  `npryx --scan-config https://scan.example.com --token <key>`.
- **Self-hosted.** Run with no keys file and the service is open to whoever can reach it.
  Typical for a company running it inside its own network.

The sandbox needs Docker and should run on a separate, dedicated host. See
`scan-service/sandbox/README.md`.

## What it detects

The headline question is: **does this package send data off the machine, and if so,
what, where, and when?**

### Layer 1: reading the code (static)

Every `.js`, `.cjs` and `.mjs` file is parsed with `oxc` into a syntax tree.

**Sinks: ways data can leave.**

- HTTP: `http.request`, `https.get`, `fetch`, `XMLHttpRequest`, WebSocket.
- Raw sockets: `net.connect`, `tls.connect`, `dgram` (UDP).
- **DNS.** Lookups whose hostname is computed. Data can be smuggled out inside a domain
  name (`dXNlcj1sYWNo.attacker.com`), and DNS gets through most firewalls.
- Shelling out: `child_process` running `curl`, `wget`, `nc`, `powershell`.

**Sources: things worth stealing.**

- The whole `process.env` (`JSON.stringify(process.env)` is a classic), or secret-named
  variables: `NPM_TOKEN`, `GITHUB_TOKEN`, `AWS_*`, `*_KEY`, `*_SECRET`, `*_TOKEN`.
- Credential files: `~/.npmrc`, `~/.ssh/*`, `~/.aws/credentials`, `~/.config/gcloud`,
  `.env`, git credentials, browser profiles, crypto wallets.
- Machine fingerprinting: `os.hostname()`, `os.userInfo()`, `os.networkInterfaces()`.

**Flow.** Within a function, a value read from a source is tracked through assignments,
template literals, concatenation, `JSON.stringify`, `Buffer.from` and base64 encoding. If
it reaches a sink's URL, arguments or body, that's `net.exfil-flow` (high). Source and
sink in the same file without a traced flow is `secret.read` (medium).

**Destinations.** The URLs, IPs and domains near each sink are collected, after undoing
the usual hiding: joined string pieces, `String.fromCharCode`, base64 and hex decoding,
`atob`. Each is classified:

| Kind | Examples | Treatment |
|---|---|---|
| `raw-ip` | `45.77.12.9` | High at install, medium otherwise |
| `collector` | webhook.site, pipedream, requestbin, interact.sh / oast, Burp Collaborator, canarytokens | High: these exist to collect data |
| `chat-webhook` | Discord webhooks, Telegram bot API | High: common exfil channels |
| `paste` | pastebin and similar | High |
| `tunnel` | ngrok, trycloudflare, localtunnel | High |
| `registry` | registry.npmjs.org | Expected |
| `package-home` | the package's own repo, homepage, GitHub releases | Expected (binary downloads) |
| `known-telemetry` | telemetry.nextjs.org | Info, with the opt-out shown |
| `other` | anything else | New since last version: medium |

**When it runs.** Install hooks are followed to their entry files, then through the
relative `require`/`import` graph. Findings are tagged by phase:

- **install**: runs during `npx` before you've used anything. Worst.
- **import**: runs as soon as the package is loaded.
- **runtime**: runs only when its code is called.

**Suspicious on their own,** whatever they connect to:

- `code.remote-eval`: fetched or decoded data reaching `eval`, `new Function` or `vm.run*`.
- `code.ci-gated-network`: a network call behind a check of `CI`, `GITHUB_ACTIONS` or the
  hostname. Malware often only fires in CI, where the valuable tokens live.
- `code.obfuscation`: high-entropy blobs, huge single lines in files not named `.min`,
  escape-sequence soup, decode-then-run.

### Diffing against the previous version

Diffing is what keeps false alarms down. Every finding is compared with the previous
published version, also scanned and cached:

- **New since the previous version:** marked `new_since_previous`, and reported at full
  severity. A new outbound connection to a new destination is the strongest signal there
  is.
- **Also present before:** treated as baseline and downgraded one level. esbuild has
  always downloaded its binary from the registry, so that's one quiet line, not an alarm.
- **Registry-level changes:** `script.install-added` (an install hook appeared),
  `provenance.dropped` (the last version was built in CI with signed provenance, this one
  wasn't, which is what a stolen-token publish looks like), `maintainers.changed`,
  `deps.added`.

### Known malware

One query to OSV (`api.osv.dev`). A `MAL-` advisory is `osv.malware`, confirmed. Other
advisories are low severity, since this tool is about supply-chain attacks rather than
ordinary vulnerabilities.

### Layer 2: running it (sandbox, opt-in)

Static analysis can only produce suspicion. To prove data leaves, the sandbox installs
and runs the package somewhere disposable and watches.

1. **Install without running anything.** On the host, `npm install --ignore-scripts`
   fetches the package and its dependencies. No package code runs here.
2. **Plant bait.** Inside the container: a fake `~/.npmrc` with a canary npm token, fake
   AWS keys, a fake SSH key, and canary values in `NPM_TOKEN`, `GITHUB_TOKEN` and the AWS
   variables. Every canary is unique to the run.
3. **Cut the network.** `--network none`, so nothing can actually leave. A preloaded hook
   records every attempt to connect, look up a name or spawn `curl`/`wget`/`nc`, with
   what it tried to send. Shims on `PATH` log those tools' arguments.
4. **Run it three ways.** `npm rebuild` (install scripts, for the package and its deps),
   then `require()` / `import()`, then its command with `--help`. Twice: once as a
   developer laptop, once dressed as CI (`CI=true`, `GITHUB_ACTIONS=true`).
5. **Look for the bait.** Every recorded payload is searched for each canary: plain,
   base64, base64url, hex, URL-encoded and compressed. A hit is proof:
   `sandbox.canary-exfil`, confirmed. Contacting any non-registry host is
   `sandbox.blocked-egress`; reading a planted credential file is `sandbox.secret-read`.

Hardening: memory, CPU and process limits, read-only root, non-root user, and a 60s
limit per run. gVisor (`--runtime=runsc`) is the recommended next step.

## How results reach the user

The verdict sets npryx's behaviour:

| Verdict | Meaning | npryx |
|---|---|---|
| `confirmed` | Canary exfiltration, an OSV malware advisory, or the registry serving different bytes | Handled like tampered bytes: never auto-run (not even with `NPRYX_YES` or `NPRYX_ALLOW`), and `[a]` isn't offered |
| `suspected` | A high-severity finding | Loud warning. Default is still No |
| `info` | Lower findings | Shown, nothing else changes |
| `clean` | Nothing found | Shown as "nothing found (not a guarantee)" |

Example preview lines:

```
  remote scan   ⛔ confirmed threat   compared with 1.5.0
                ⛔ sent your npm token over the network (on install), new since 1.5.0
                    → https://45.77.12.9/c
```

```
  remote scan   ⚠️  suspicious   compared with 2.3.0
                ⚠️  sends data to a request-catcher service (on import), new since 2.3.0
                    → https://webhook.site/abc
                note: [s] --ignore-scripts won't help here, this code runs on import
```

That last line matters: `--ignore-scripts` only stops install hooks. Code that runs on
import or when called still runs, and npryx says so.

## Cost

- **Scans only on a cache miss**, once per published version, forever.
- **Hard caps:** tarball size, files parsed, time per scan, total concurrency.
- **Rate limits** per API key and per IP. Concurrent requests for the same version share
  one scan.
- **The sandbox runs only when asked** (`deep=1`). It's the expensive part. A hosted
  service can restrict it to paid keys.
- **Optional pre-scanning** of new releases of a fixed list of popular packages, so
  hijacked releases are flagged within minutes. Cost is bounded by the list size.

## Limits

- **Static analysis can be evaded** by heavy obfuscation, staged payloads and time bombs.
  The evasion itself is flagged where it's visible: decode-then-eval is a finding even
  when we can't tell what it does.
- **The sandbox can be evaded** by malware that detects it, waits, or uses native code to
  avoid the in-process hooks. `--network none` still guarantees nothing actually leaves
  during the scan. eBPF syscall tracing and gVisor are the upgrade path.
- **A scan describes one version.** Dependencies resolved at install time can change
  between the scan and your run. The sandbox scans the tree as resolved at scan time.
