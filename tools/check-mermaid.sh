#!/usr/bin/env bash
#
# Validate every mermaid diagram in the SCIM docs.
#
# A mermaid block with a syntax error does not fail loudly: GitHub renders it as
# a grey error box, so a broken diagram survives review and is only noticed by a
# reader who needed it. This renders each block headlessly and reports failures.
#
# Usage:
#   tools/check-mermaid.sh            # check docs/scim/*.md
#   tools/check-mermaid.sh FILE...    # check specific markdown files
#
# Requires: node/npx (mermaid-cli is fetched on demand, nothing is installed
# into the repo). No toolchain is needed to *read* the docs - only to check them.
#
# Exit code: 0 if every diagram renders, 1 otherwise.
#
set -uo pipefail

if ! command -v npx >/dev/null 2>&1; then
    echo "npx not found; install Node to run this check" >&2
    exit 2
fi

files=("$@")
if [ ${#files[@]} -eq 0 ]; then
    # shellcheck disable=SC2206  # word splitting is what we want on the glob
    files=(docs/scim/*.md)
fi

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

total=0
failed=0

for file in "${files[@]}"; do
    [ -f "$file" ] || { echo "skip: $file (not a file)"; continue; }

    # Split the file into mermaid blocks, one .mmd per block, recording the
    # source line the block opened on so a failure points somewhere useful.
    awk -v dir="$workdir" -v src="$file" '
        /^```mermaid$/ { inblock = 1; n++; start = NR; out = sprintf("%s/%03d.mmd", dir, n);
                         printf "%s:%d\n", src, start > sprintf("%s/%03d.loc", dir, n); next }
        /^```$/ && inblock { inblock = 0; close(out); next }
        inblock { print > out }
    ' "$file"

    for mmd in "$workdir"/*.mmd; do
        [ -e "$mmd" ] || continue
        total=$((total + 1))
        loc="$(cat "${mmd%.mmd}.loc" 2>/dev/null || echo "$file")"
        if npx -y -p @mermaid-js/mermaid-cli mmdc -i "$mmd" -o "$mmd.svg" >/dev/null 2>"$mmd.err"; then
            printf '  \033[32mok\033[0m   %s\n' "$loc"
        else
            failed=$((failed + 1))
            printf '  \033[31mFAIL\033[0m %s\n' "$loc"
            sed 's/^/         /' "$mmd.err" | head -8
        fi
    done
    rm -f "$workdir"/*.mmd "$workdir"/*.loc "$workdir"/*.err "$workdir"/*.svg 2>/dev/null
done

echo
if [ "$failed" -eq 0 ]; then
    echo "$total mermaid diagram(s) render cleanly."
    exit 0
fi
echo "$failed of $total mermaid diagram(s) failed to render." >&2
exit 1
