#!/usr/bin/env bash
# Builds the contracts and writes the bytecode the clients embed: op-core/eip8130 (Go) and op-alloy's keystore
# module (Rust).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
dests=("$here/../../op-core/eip8130" "$here/../../rust/op-alloy/crates/consensus/src/keystore")
forge build --root "$here" --force
for c in Keystore StatementAuthenticator; do
  name=$(echo "$c" | sed -E 's/([a-z])([A-Z])/\1_\2/g' | tr '[:upper:]' '[:lower:]')
  for dest in "${dests[@]}"; do
    jq -er '.bytecode.object' "$here/out/$c.sol/$c.json" | sed 's/^0x//' > "$dest/$name.initcode.hex"
    jq -er '.deployedBytecode.object' "$here/out/$c.sol/$c.json" | sed 's/^0x//' > "$dest/$name.runtime.hex"
  done
done
# The Keystore storage layout the clients read natively (op-alloy keystore module, op-core/eip8130): a change shows in
# the diff of this snapshot.
forge inspect --root "$here" src/Keystore.sol:Keystore storageLayout --json | jq -r '
  . as $l | ($l.storage[] | "\(.label) slot \(.slot) offset \(.offset)"),
  ($l.types | to_entries[] | select(.value.members != null) | .value.label as $t | .value.members[]
    | "\($t).\(.label) slot \(.slot) offset \(.offset) bytes \($l.types[.type].numberOfBytes)")' \
  > "$here/storage-layout.txt"
