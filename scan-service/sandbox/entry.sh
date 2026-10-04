#!/bin/sh
# Runs inside the sandbox container (no network, read-only root, non-root user).
# Three phases, each tagged so events say WHEN something happened:
#   install — npm rebuild runs preinstall/install/postinstall for the package and its deps
#   import  — require() the package (falls back to import() for ESM)
#   runtime — run its bin with --help, if it has one
export PATH=/npryx/shims:$PATH
export NODE_OPTIONS="--require /npryx/hook.cjs"
cd /work || exit 1

NPRYX_PHASE=install timeout 40 npm rebuild --foreground-scripts >/tmp/install.log 2>&1

NPRYX_PHASE=import timeout 10 node -e '
const name = process.env.NPRYX_PKG
try { require(name) } catch (e) { import(name).catch(() => {}) }
' >/tmp/import.log 2>&1

if [ -n "$NPRYX_BIN" ] && [ -e "./node_modules/.bin/$NPRYX_BIN" ]; then
  NPRYX_PHASE=runtime timeout 8 "./node_modules/.bin/$NPRYX_BIN" --help </dev/null >/tmp/runtime.log 2>&1
fi

# Let the host clean up the bind mounts afterwards.
chmod -R a+rwX /work /home/sandbox /npryx-log 2>/dev/null
exit 0
