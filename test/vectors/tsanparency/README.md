# TypeScript interop vectors

Run `node test/vectors/tsanparency/generate.ts` to regenerate the fixtures. Add `--check` to compare them byte for byte. The SHA identifies the base TypeScript revision. Fixed keys, timestamps and commitment openings keep the examples reproducible.

The suites cover both VRF and tree-head signature algorithms, tree proofs, prefix insertion, ladder interpretation, and contact-monitoring operations. The update cases distinguish an accepted write from a catch-up response that disregards the write. The boundary cases cover repeated timestamps, 255 values in one request, and a value that crosses the 4 KiB request boundary.

The auditor cases cover the first signed head, extension from a retained head, and rejection of a timestamp regression. The generator verifies each accepted root against the auditor signature before exporting it.

The Rust harness replays these files under `interop/vectors/tsanparency/` alongside the katie fixtures.
