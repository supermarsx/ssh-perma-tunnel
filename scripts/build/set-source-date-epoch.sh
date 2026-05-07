#!/usr/bin/env bash
# set-source-date-epoch.sh — print (and optionally export) SOURCE_DATE_EPOCH.
#
# Usage:
#   eval "$(scripts/build/set-source-date-epoch.sh)"   # exports the var
#   . scripts/build/set-source-date-epoch.sh           # exports the var
#   scripts/build/set-source-date-epoch.sh --print     # just print the value
#
# Source-friendly: when sourced, defines and exports SOURCE_DATE_EPOCH.
# Standalone: prints `export SOURCE_DATE_EPOCH=<n>` so callers can `eval` it.

set -euo pipefail

# Resolve _common.sh relative to this file even when sourced.
_self_dir() {
  local src=${BASH_SOURCE[0]}
  cd "$(dirname "$src")" >/dev/null 2>&1 && pwd
}
# shellcheck source=_common.sh
source "$(_self_dir)/_common.sh"

case "${1:-}" in
  -h|--help)
    cat <<EOF
Usage: $(basename "${BASH_SOURCE[0]}") [--print]

Computes SOURCE_DATE_EPOCH from the current git HEAD commit timestamp.

Modes:
  (default)   prints \`export SOURCE_DATE_EPOCH=<n>\`. Eval this from your shell.
  --print     prints just the integer epoch value.

When sourced (via \`. set-source-date-epoch.sh\`), the variable is exported
into the calling shell directly with no output.
EOF
    print_help_footer
    exit 0
    ;;
esac

epoch=$(source_date_epoch)

# Detect whether we're sourced. In bash, BASH_SOURCE[0] != $0 when sourced.
# shellcheck disable=SC2128
if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
  export SOURCE_DATE_EPOCH="$epoch"
else
  case "${1:-}" in
    --print) echo "$epoch" ;;
    *)       echo "export SOURCE_DATE_EPOCH=$epoch" ;;
  esac
fi
