#!/bin/sh
# Runs bench/compare.ts inside workerd. Local workerd keeps its clock running
# during computation, unlike production Workers.
set -eu
cd "$(dirname "$0")"
../node_modules/.bin/esbuild compare.worker.ts --bundle --format=esm --log-level=warning --outfile=.trace/worker.js
../node_modules/.bin/workerd serve workerd.capnp >/dev/null &
server=$!
# A signal exits through the EXIT trap, so the server never outlives the script
trap 'kill "$server" 2>/dev/null' EXIT
trap 'exit 1' HUP INT PIPE TERM
curl --silent --retry 10 --retry-connrefused http://127.0.0.1:8789
echo
