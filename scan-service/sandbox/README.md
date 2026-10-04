# npryx sandbox (deep scan)

The deep scan installs a package in a throwaway container and watches what it does.
It is the second opt-in: a client asks for it with `deep=1` (`NPRYX_SCAN_DEEP=1`), and the
server only runs it when started with `NPRYX_SCAN_SANDBOX=docker`.

## What happens

1. **On the host, nothing from the package runs.** `npm install <tarball> --ignore-scripts`
   materialises the package and its dependencies in a temp directory.
2. **Two container runs**, `dev` and `ci`. The `ci` run sets `CI=true`, `GITHUB_ACTIONS=true` and
   other `GITHUB_*` variables, because a lot of malware only fires in CI, where the valuable
   tokens are.
3. **Honeytokens.** Each run gets fresh, unique fake credentials: `~/.npmrc` with an `npm_` token,
   `~/.aws/credentials`, `~/.ssh/id_ed25519`, `~/.git-credentials`, and `NPM_TOKEN`,
   `GITHUB_TOKEN`, `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` in the environment.
4. **Three phases** (`entry.sh`), so every event says when it happened:
   - `install`: `npm rebuild --foreground-scripts` runs preinstall, install and postinstall for
     the package and its dependencies.
   - `import`: `require()` the package, falling back to `import()` for ESM.
   - `runtime`: the package's bin with `--help`, if it has one.
5. **Instrumentation.** `hook.cjs` is preloaded into every node process. It logs, and then
   fails, every network call: tcp, tls, http, https, fetch, WebSocket, dns and udp, with the
   request body. It also logs subprocesses and reads of credential files. `curl`, `wget`, `nc`,
   `ssh`, `powershell` and similar tools on `PATH` are shims that log their arguments and stdin.
6. **Canary search.** The host decodes every payload and target: url-encoding, base64, base64url,
   hex, base32, gzip, zlib and raw deflate, nested a few levels deep. It then searches for the
   planted values. A hit means the package tried to send your credentials somewhere, and it
   becomes the `sandbox.canary-exfil` finding (severity `confirmed`).

## Container hardening

`--network none --read-only --memory 512m --cpus 1 --pids-limit 256 --cap-drop ALL
--security-opt no-new-privileges`, a non-root user (uid 10001), and tmpfs for `/tmp`.
Runs are capped at 60 seconds each, after which the container is killed and the report is
marked `timeout` with partial results. At most two sandboxes run at once per host
(`NPRYX_SCAN_SANDBOX_CONCURRENCY`).

## Threat model and limits

- **Nothing can leave.** The container has no network interface beyond loopback, so even a
  package that evades the instrumentation can't actually exfiltrate anything.
- **The instrumentation can be evaded.** The hook runs inside the same process as the package.
  A native addon, or JS that restores the original functions, can hide its attempts from the
  log. A clean deep scan therefore means "nothing observed", never "safe".
- **Delayed or environment-sensitive malware.** A package that waits hours, checks for real
  cloud metadata, or detects the sandbox won't show its behaviour here.
- **Native builds** that need to download Node headers or toolchains fail with no network. The
  attempt is still logged, but the build can't complete.
- **The upgrade path is kernel-level observation**, not more JS hooks:
  - **gVisor:** run the containers with `--runtime=runsc` (install
    [gVisor](https://gvisor.dev) and register the runtime with Docker). The package then talks
    to a user-space kernel instead of the host's, which is much stronger isolation, and
    `runsc` can log every syscall, including socket and file access by native code.
  - **eBPF:** trace `connect`, `sendto` and `openat` for the container's cgroup from the host.
    This catches native code the hook can't see.

## Running it in production

- **Run the sandbox on its own host or VM**, not on the internet-facing API machine. Whatever
  runs `docker run` effectively has root on that host, so the API process should never hold
  the Docker socket directly. Split it: the API enqueues deep-scan jobs, and a separate worker
  on a dedicated, disposable VM pulls them, runs the sandbox and writes results back.
- **Use gVisor (`runsc`) there.** It is a one-line change in how Docker is configured and the
  biggest isolation win available.
- **Rebuild the VM regularly.** Treat the sandbox host as hostile: no credentials on it, no
  access to internal networks, egress allowed only to the npm registry (needed for step 1).
- **Pre-pull `node:22-slim`.** The image (`npryx-sandbox:<hash>`) is built on first use and
  rebuilt automatically whenever the files in this directory change.

## Files

| File | Role |
|---|---|
| `Dockerfile` | The `node:22-slim` image with the hook, shims and entry script. |
| `entry.sh` | Runs the install, import and runtime phases inside the container. |
| `hook.cjs` | The node preload that records and blocks network, subprocess and credential activity. |
| `shim-log.cjs`, `shims/_shim.sh` | The stand-in for network tools on `PATH`. |
| `fixtures/` | Test packages: `benign`, `exfil-postinstall` (posts the npm token to a raw IP on install), `dns-import` (hostname exfil over DNS at import). |

Tests: `cargo test sandbox` from `scan-service/`. The decoder tests always run. The Docker
tests run the fixtures for real, and skip with a message when Docker isn't available.
