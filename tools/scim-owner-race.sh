#!/usr/bin/env bash
#
# Concurrency stress for the last-owner guard.
#
# The unit test cannot demonstrate the mutex: Rocket's local client never
# achieves true request concurrency, so the two dispatches never interleave
# inside the count-then-write window. This drives a REAL server over real HTTP
# with real parallel connections, which is the only way to observe it.
#
# Each trial: seed exactly two active Owners, fire two DELETE requests
# simultaneously at the two different membership rows, then count how many
# Owners survive AND what the server actually answered.
#
#   1 survivor,  one 204 + one 400 -> correct
#   0 survivors                    -> THE RACE FIRED (org stranded with no Owner)
#   2 survivors                    -> both refused; only legitimate if both said 400
#
# The status codes are not decoration. Without them a 429 from the rate limiter,
# a 401 from a bad token and a 500 from a broken server all look identical to
# "the guard refused both", so a completely non-functional endpoint reports a
# clean run. Any 429 aborts immediately rather than being counted: a throttled
# trial has tested nothing, and averaging it in with real trials is how a
# measurement quietly stops measuring.
#
# Usage:
#   SCIM_RACE_DIR=/path/to/testdir tools/scim-owner-race.sh [trials]
#
# SCIM_RACE_DIR is REQUIRED and must contain vw-data/db.sqlite3, org-id.txt and
# scim-token.txt for a LOCAL THROWAWAY instance. It writes directly to the
# database to seed each trial, so never point it at anything you care about.
#
# The server must allow at least 2x trials requests inside its rate-limit
# window. Set SCIM_RATELIMIT_MAX_BURST accordingly (the default of 60 is not
# enough for the default 40 trials once other traffic is present).
#
# Exit code: 0 only if every trial produced the correct outcome. Non-zero if the
# race fired, if any trial was inconclusive, or if the harness could not seed.
#
# To reproduce the control arm (the race WITH the guard removed), build with the
# `scim-race-control` feature, which compiles out the mutex:
#
#   cargo build --features sqlite,scim-race-control
#
set -euo pipefail

TRIALS="${1:-40}"
case "$TRIALS" in
    ''|*[!0-9]*) echo "trials must be a positive integer, got '$TRIALS'" >&2; exit 2 ;;
esac
[ "$TRIALS" -gt 0 ] || { echo "trials must be greater than zero" >&2; exit 2; }

# No fallback. This script issues unguarded DELETE statements against whatever
# database it is pointed at, so defaulting to a guessable path is not a
# convenience.
SP="${SCIM_RACE_DIR:-}"
[ -n "$SP" ] || { echo "SCIM_RACE_DIR must be set to a throwaway instance directory" >&2; exit 2; }
[ -d "$SP" ] || { echo "SCIM_RACE_DIR '$SP' is not a directory" >&2; exit 2; }

DB="$SP/vw-data/db.sqlite3"
[ -f "$DB" ] || { echo "no database at $DB" >&2; exit 2; }
for f in org-id.txt scim-token.txt; do
    [ -s "$SP/$f" ] || { echo "missing or empty $SP/$f" >&2; exit 2; }
done
ORG="$(tr -d '[:space:]' < "$SP/org-id.txt")"
TOKEN="$(tr -d '[:space:]' < "$SP/scim-token.txt")"
# A blank ORG would build /scim/v2//Users/... and 404 every request, which the
# survivor count alone reads as "both refused".
case "$ORG" in
    [0-9a-fA-F]*-*-*-*-*) ;;
    *) echo "org-id.txt does not look like a uuid: '$ORG'" >&2; exit 2 ;;
esac
[ -n "$TOKEN" ] || { echo "scim-token.txt is empty" >&2; exit 2; }

BASE="${SCIM_RACE_BASE:-http://localhost:8000}/scim/v2/$ORG"

M1='aaaaaaaa-0000-4000-8000-000000000001'
M2='aaaaaaaa-0000-4000-8000-000000000002'

zero=0; one=0; two=0; other=0; throttled=0

# Fires one DELETE and prints only the HTTP status.
#
# The Authorization header goes in via `curl -K -` rather than -H, so the bearer
# token never appears in curl's argv where any local user could read it from
# ps(1) - and this script fires two of these per trial, forty times over. Same
# pattern as tools/scim-replay.sh and tools/scim-authentik-e2e.sh.
revoke() {
    printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" \
        | curl -s -K - -o /dev/null -w '%{http_code}' -X DELETE "$BASE/Users/$1"
}

for t in $(seq 1 "$TRIALS"); do
    # Reset to exactly two active, confirmed Owners on dedicated rows. A failure
    # here means every subsequent count is meaningless, so it is fatal.
    if ! sqlite3 "$DB" <<SQL
DELETE FROM users_organizations WHERE uuid IN ('$M1','$M2');
DELETE FROM users_organizations WHERE user_uuid IN (SELECT uuid FROM users WHERE email LIKE 'race.%');
DELETE FROM users WHERE email LIKE 'race.%';
INSERT INTO users (uuid, created_at, updated_at, email, name, password_hash, salt,
                   password_iterations, akey, security_stamp, equivalent_domains,
                   excluded_globals, client_kdf_type, client_kdf_iter, login_verify_count, enabled)
VALUES
 ('bbbbbbbb-0000-4000-8000-000000000001',datetime('now'),datetime('now'),'race.a@example.com','A',X'00',X'00',100000,'','s','[]','[]',0,100000,0,1),
 ('bbbbbbbb-0000-4000-8000-000000000002',datetime('now'),datetime('now'),'race.b@example.com','B',X'00',X'00',100000,'','s','[]','[]',0,100000,0,1);
INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, akey, status, atype, reset_password_key, external_id)
VALUES
 ('$M1','bbbbbbbb-0000-4000-8000-000000000001','$ORG',0,'k',2,0,NULL,NULL),
 ('$M2','bbbbbbbb-0000-4000-8000-000000000002','$ORG',0,'k',2,0,NULL,NULL);
SQL
    then
        echo "trial $t: could not seed the database - aborting" >&2
        exit 1
    fi

    # Fire both at once, keeping each status.
    s1_file="$(mktemp)"; s2_file="$(mktemp)"
    revoke "$M1" > "$s1_file" &
    p1=$!
    revoke "$M2" > "$s2_file" &
    p2=$!
    wait $p1 $p2
    s1="$(cat "$s1_file")"; s2="$(cat "$s2_file")"
    rm -f "$s1_file" "$s2_file"

    if [ "$s1" = "429" ] || [ "$s2" = "429" ]; then
        throttled=$((throttled+1))
        echo "trial $t: rate limited ($s1/$s2) - this trial tested nothing" >&2
        break
    fi

    survivors=$(sqlite3 "$DB" \
      "SELECT COUNT(*) FROM users_organizations
       WHERE org_uuid='$ORG' AND atype=0 AND status > -1;")

    case "$survivors" in
        0) zero=$((zero+1)); echo "  trial $t: 0 SURVIVORS - RACE FIRED ($s1/$s2)" ;;
        1)
            # Exactly one revoke must have succeeded and one must have been
            # refused BY THE GUARD. Anything else reached this count by accident.
            if { [ "$s1" = "204" ] && [ "$s2" = "400" ]; } || { [ "$s1" = "400" ] && [ "$s2" = "204" ]; }; then
                one=$((one+1))
            else
                other=$((other+1))
                echo "  trial $t: 1 survivor but statuses were $s1/$s2, not 204/400" >&2
            fi
            ;;
        2)
            if [ "$s1" = "400" ] && [ "$s2" = "400" ]; then
                two=$((two+1))
            else
                other=$((other+1))
                echo "  trial $t: 2 survivors and statuses $s1/$s2 - the endpoint is not working" >&2
            fi
            ;;
        *) other=$((other+1)); echo "  trial $t: unexpected survivor count '$survivors'" >&2 ;;
    esac
done

echo
echo "trials=$TRIALS  correct(1)=$one  both-refused(2)=$two  RACE(0)=$zero  inconclusive=$other  throttled=$throttled"

status=0
if [ "$throttled" -gt 0 ]; then
    echo "RATE LIMITED - raise SCIM_RATELIMIT_MAX_BURST above $((TRIALS * 2)) and re-run; this run proved nothing" >&2
    status=1
fi
if [ "$zero" -gt 0 ]; then
    echo "THE LAST-OWNER RACE IS REACHABLE ON THIS BUILD" >&2
    status=1
fi
if [ "$other" -gt 0 ]; then
    echo "$other trial(s) were inconclusive - see above" >&2
    status=1
fi
# The positive control. If no trial ever revoked anything, the harness never
# exercised the guard at all and a green run would be meaningless.
if [ "$one" -eq 0 ]; then
    echo "no trial produced the correct one-revoked-one-refused outcome - the harness proved nothing" >&2
    status=1
fi
exit "$status"
