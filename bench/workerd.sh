#!/bin/sh
# Runs bench/compare.ts inside workerd. Local workerd keeps the clock running
# during computation, unlike production Workers.
set -e
cd "$(dirname "$0")"
../node_modules/.bin/esbuild compare.worker.ts --bundle --format=esm --log-level=warning --outfile=.trace/worker.js
../node_modules/.bin/workerd serve workerd.capnp &
trap 'kill $!' EXIT
sleep 1
curl -s --retry 5 --retry-connrefused http://127.0.0.1:8789
echo
