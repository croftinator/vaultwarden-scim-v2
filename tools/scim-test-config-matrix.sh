#!/usr/bin/env bash
#
# Runs the SCIM suite a second time under a different server configuration.
#
# Why this exists: CONFIG is a process-global LazyLock resolved once, pre-main,
# by the test-support ctor. A single test binary therefore observes exactly one
# value for each setting, and no amount of test-local trickery changes that for
# settings read by upstream code (as opposed to the few SCIM-local switches
# `scim::test_config` can override).
#
# The only honest way to cover the other branch is to run the binary again with
# a different environment. The ctor defers to any value already present for the
# keys in its CALLER_MAY_OVERRIDE list, which is what makes this work.
#
# Currently one dimension: SSO_ONLY. Add rows to MATRIX as more appear.

set -uo pipefail
cd "$(dirname "$0")/.."

# mktemp, not a $$-derived name in the world-writable /tmp: a predictable path
# there can be pre-created as a symlink by another local user, and `tee` would
# then clobber whatever it points at with this developer's permissions.
LOGFILE=$(mktemp "${TMPDIR:-/tmp}/scim-matrix.XXXXXXXX")
trap 'rm -f "$LOGFILE"' EXIT

c_ok()   { printf '  \033[32m%s\033[0m\n' "$*"; }
c_bad()  { printf '  \033[31m%s\033[0m\n' "$*"; }
c_info() { printf '\033[1m%s\033[0m\n' "$*"; }

FEATURES="${FEATURES:-sqlite}"

# Each row: <label>|<env assignments>|<test filter>
# The filter keeps each pass to the tests whose meaning actually changes, so a
# matrix pass stays seconds rather than re-running everything for no new signal.
MATRIX=(
    "SSO_ONLY=true|SSO_ONLY=true|the_invite_routes_through_sso_exactly_when_sso_only_is_set"
)

FAILED=0
PASSED=()

c_info "Config matrix (features: $FEATURES)"
printf '\n'

for row in "${MATRIX[@]}"; do
    IFS='|' read -r label envs filter <<<"$row"
    c_info "--- $label ---"

    # Written to $LOGFILE and then inspected, rather than piped straight into
    # `grep -q`: grep exits on its first match, which SIGPIPEs cargo mid-run, and
    # under `pipefail` that 141 is indistinguishable from a real test failure.
    # shellcheck disable=SC2086
    env $envs cargo test --features "$FEATURES" "$filter" 2>&1 | tee "$LOGFILE"

    # A NON-ZERO pass count, not merely "ok". cargo prints
    # "test result: ok. 0 passed; 0 failed; N filtered out" when the filter
    # selects nothing, so matching "ok" alone turns a renamed or deleted test
    # into a silent green - and this script is the ONLY way to exercise a config
    # branch CONFIG pins pre-main, so a false green here means the dimension is
    # untested with no signal at all. Same discipline as scim-test-backends.sh:
    # not-run is not passed.
    if grep -qE "test result: ok\\. [1-9][0-9]* passed" "$LOGFILE"; then
        count=$(grep -oE "[0-9]+ passed" "$LOGFILE" | head -1)
        c_ok "$label passed ($count)"
        PASSED+=("$label")
    else
        if grep -qE "test result: ok\\. 0 passed" "$LOGFILE"; then
            c_bad "$label selected NO TESTS - the filter no longer matches anything"
        fi
        c_bad "$label FAILED"
        grep -E "panicked at|assertion|test result" "$LOGFILE" | head -10
        FAILED=1
    fi
    printf '\n'
done

if [ "$FAILED" -eq 0 ]; then
    c_ok "all ${#PASSED[@]} configuration(s) passed"
else
    c_bad "one or more configurations failed"
fi
exit "$FAILED"
