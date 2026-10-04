#!/bin/sh
# Every network tool name on PATH points here (see Dockerfile).
NODE_OPTIONS= exec node /npryx/shim-log.cjs "$(basename "$0")" "$@"
