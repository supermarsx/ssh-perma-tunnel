#!/usr/bin/env bash
# swap-pen.sh -- replace the placeholder IANA Private Enterprise Number
# (RFC 5612 / RFC 9371 documentation PEN 32473) with the production PEN
# returned by IANA. See docs/pen-registration.md for the registration packet.
#
# Effect:
#   * Rewrites the single `{ enterprises 32473 }` line in mibs/SPT-MIB.txt.
#   * Rewrites the single SPT enterprise OID constant in
#     crates/spt-snmp/src/lib.rs (SPT_ENTERPRISE_OID_ARCS).
#   * Leaves .bak copies of each edited file.
#   * Reminds the operator to bump the MIB REVISION and update
#     DOCUMENTATION_ENTERPRISE_PEN call sites if the production PEN is to
#     replace (not coexist with) the documentation PEN scalar.
#
# Usage: scripts/swap-pen.sh <NEW_PEN>

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <new-pen-number>" >&2
    exit 2
fi

NEW_PEN="$1"

if ! [[ "$NEW_PEN" =~ ^[0-9]+$ ]]; then
    echo "error: PEN must be a positive integer, got: ${NEW_PEN}" >&2
    exit 2
fi

# Resolve repo root from the script location so relative paths are stable.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

MIB="${REPO_ROOT}/mibs/SPT-MIB.txt"
LIB="${REPO_ROOT}/crates/spt-snmp/src/lib.rs"

[[ -f "$MIB" ]] || { echo "error: cannot find ${MIB}" >&2; exit 1; }
[[ -f "$LIB" ]] || { echo "error: cannot find ${LIB}" >&2; exit 1; }

# Sanity check: the placeholder must still be present. If not, either the
# swap already happened or someone edited the anchor by hand.
if ! grep -q "enterprises 32473" "$MIB"; then
    echo "error: no placeholder '{ enterprises 32473 }' found in ${MIB}" >&2
    echo "       (already swapped? edited by hand? -- aborting)" >&2
    exit 1
fi

if ! grep -q "SPT_ENTERPRISE_OID_ARCS" "$LIB"; then
    echo "error: SPT_ENTERPRISE_OID_ARCS not found in ${LIB}" >&2
    exit 1
fi

# Use a portable sed invocation. macOS BSD sed and GNU sed both accept
# `-i.bak` (with no space) which writes the backup alongside the original.
sed -i.bak "s|enterprises 32473|enterprises ${NEW_PEN}|" "$MIB"
sed -i.bak "s|&\[1, 3, 6, 1, 4, 1, 32_473\]|\&[1, 3, 6, 1, 4, 1, ${NEW_PEN}]|" "$LIB"

echo "swapped MIB enterprise OID 32473 -> ${NEW_PEN}"
echo "  - ${MIB}"
echo "  - ${LIB}"
echo
echo "Next steps:"
echo "  1) Bump the MIB REVISION line in ${MIB} (LAST-UPDATED + new REVISION entry)."
echo "  2) Review docs/pen-registration.md and mark it as 'assigned PEN: ${NEW_PEN}'."
echo "  3) Run: cargo build --workspace --locked && cargo test -p spt-snmp --locked"
echo "  4) Commit the change and the .bak files' deletion."
