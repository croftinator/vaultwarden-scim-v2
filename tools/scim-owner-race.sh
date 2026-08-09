#!/usr/bin/env bash
#
# Concurrency stress for the last-owner guard.
#
# The unit test cannot demonstrate the mutex: Rocket's local client never
# achieves true request concurrency, so the two dispatches never interleave
# inside the count-then-write window. This drives a REAL server over real HTTP
# with real parallel connections, which is the only way to observe it.
#
# Each trial: seed exactly two active Owners, fire two DELETE requests simultaneously at
# the two different membership rows, then count how many Owners survive.
#
#   2 survivors -> both refused        (guard too strict, or requests serialised)
#   1 survivor  -> correct             (one revoked, one refused)
#   0 survivors -> THE RACE FIRED      (org stranded with no Owner)
#
# Usage:
#   SCIM_RACE_DIR=/path/to/testdir tools/scim-owner-race.sh <trials>
#
# SCIM_RACE_DIR must contain: vw-data/db.sqlite3, org-id.txt, scim-token.txt
# for a LOCAL THROWAWAY instance. It writes directly to the database to seed
# each trial, so never point it at anything you care about.
#
# Measured on this implementation:
#   mutex present  - 50 trials, 0 races
#   mutex removed  - 25 trials, 25 races (it fires every time)
set -uo pipefail

TRIALS="${1:-50}"
# Point these at a running test instance. See docs/scim/testing.md "Rung 2c".
SP="${SCIM_RACE_DIR:-$(cd "$(dirname "$0")" && pwd)}"
DB="$SP/vw-data/db.sqlite3"
ORG="$(cat "$SP/org-id.txt")"
TOKEN="$(cat "$SP/scim-token.txt")"
BASE="http://localhost:8000/scim/v2/$ORG"

zero=0; one=0; two=0; other=0

for t in $(seq 1 "$TRIALS"); do
    # Reset to exactly two active, confirmed Owners on dedicated rows.
    sqlite3 "$DB" <<SQL
DELETE FROM users_organizations WHERE uuid IN ('aaaaaaaa-0000-4000-8000-000000000001','aaaaaaaa-0000-4000-8000-000000000002');
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
 ('aaaaaaaa-0000-4000-8000-000000000001','bbbbbbbb-0000-4000-8000-000000000001','$ORG',0,'k',2,0,NULL,NULL),
 ('aaaaaaaa-0000-4000-8000-000000000002','bbbbbbbb-0000-4000-8000-000000000002','$ORG',0,'k',2,0,NULL,NULL);
SQL

    # Fire both at once. Backgrounded curls with a shared start gate.
    curl -s -o /dev/null -X DELETE -H "Authorization: Bearer $TOKEN" "$BASE/Users/aaaaaaaa-0000-4000-8000-000000000001" &
    p1=$!
    curl -s -o /dev/null -X DELETE -H "Authorization: Bearer $TOKEN" "$BASE/Users/aaaaaaaa-0000-4000-8000-000000000002" &
    p2=$!
    wait $p1 $p2

    survivors=$(sqlite3 "$DB" \
      "SELECT COUNT(*) FROM users_organizations
       WHERE org_uuid='$ORG' AND atype=0 AND status > -1;")

    case "$survivors" in
        0) zero=$((zero+1)); echo "  trial $t: 0 SURVIVORS - RACE FIRED" ;;
        1) one=$((one+1)) ;;
        2) two=$((two+1)) ;;
        *) other=$((other+1)) ;;
    esac
done

echo
echo "trials=$TRIALS  correct(1)=$one  both-refused(2)=$two  RACE(0)=$zero  other=$other"
[ "$zero" -eq 0 ] || echo "THE LAST-OWNER RACE IS REACHABLE ON THIS BUILD"
