#!/usr/bin/env bash
# Print each artifact's current BLAKE3 code hash and REFUSE if one of them is
# already recorded as a superseded generation in `legacy/`.
#
# WHAT THIS CATCHES, and why it is a hard failure rather than a note.
#
# `legacy/*.toml` lists SUPERSEDED generations only; the current generation is
# derived at runtime from the WASM this build ships and is deliberately never
# written down. So the current hash appearing in a registry means one of two
# things, and both are bugs:
#
#   * the outgoing hash was appended and the artifact was then NOT rebuilt, so
#     the registry describes a generation that is still live -- the probe would
#     walk to its own instance, find its own state, and report a successful
#     migration having moved nothing; or
#   * the change that moved the hash was reverted after the entry was recorded.
#
# Either way the lineage no longer describes reality, and nothing says so at
# runtime: every path reports success.
#
# The intended order is: run this, append the hash it prints, THEN rebuild
# (`cargo make sync-wasm`).
#
# Assumes the artifacts are already built -- `cargo make code-hashes` depends
# on the build task, and CI runs the build script in the same job. It does NOT
# build them itself, because building here would mean a second build path for
# bytes that are network addresses, which is the thing
# `scripts/build-contract-wasm.sh` exists to prevent.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
workspace="$(cd "$here/.." && pwd)"
out="${1:-$workspace/target/wasm32-unknown-unknown/release}"

# artifact:registry. Keep in step with the artifact list in
# build-contract-wasm.sh and with the tables in ui/build.rs; an artifact
# missing here is an artifact this guard does not watch.
pairs=(
  "store_contract:legacy/store_contract.toml"
  "reputation_contract:legacy/reputation_contract.toml"
  "mailbox_contract:legacy/mailbox_contract.toml"
  "harvest_delegate:legacy/harvest_delegate.toml"
)

if ! command -v b3sum >/dev/null 2>&1; then
  echo "error: b3sum not found; install with: cargo install b3sum --locked" >&2
  exit 1
fi

bad=0
printf '%-22s %-64s %s\n' artifact "current code hash" registry
for pair in "${pairs[@]}"; do
  a="${pair%%:*}"
  reg="$workspace/${pair#*:}"
  f="$out/$a.wasm"

  if [ ! -f "$f" ]; then
    echo "error: expected artifact not built: $f" >&2
    bad=1
    continue
  fi
  # A missing registry is a failure, never a skip. "No file, nothing to check"
  # is exactly how a guard stops being able to fail.
  if [ ! -f "$reg" ]; then
    echo "error: no migration registry at $reg" >&2
    bad=1
    continue
  fi

  h="$(b3sum --no-names "$f")"
  printf '%-22s %-64s %s\n' "$a" "$h" "${pair#*:}"
  if grep -q "$h" "$reg"; then
    echo "error: ${a}'s CURRENT code hash is already recorded as superseded in ${pair#*:}." >&2
    echo "       Either the artifact was not rebuilt after the entry was added," >&2
    echo "       or the change that moved it was reverted. The registries list" >&2
    echo "       superseded generations only -- never the live one." >&2
    bad=1
  fi
done

echo
if [ "$bad" != 0 ]; then
  exit 1
fi
echo "No current hash is recorded as superseded."
echo "If a hash above differs from the one you last published, that generation"
echo "is now superseded: append it to its registry BEFORE rebuilding."
