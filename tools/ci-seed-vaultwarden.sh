#!/usr/bin/env bash
#
# Start a throwaway Vaultwarden and seed one organisation with a SCIM credential.
#
# Shared by both jobs in .github/workflows/provisioning-e2e.yml. It used to be
# two near-identical 25-line blocks that had already drifted apart - one bound
# 0.0.0.0, one bound loopback; one verified the seeded token authenticated, one
# did not - so the two jobs were not testing the same server.
#
# Usage:
#   tools/ci-seed-vaultwarden.sh <workdir> <binary> [bind-address]
#
# Writes into <workdir>:
#   vw-data/db.sqlite3   the database (tools/scim-owner-race.sh expects this name)
#   org-id.txt           the seeded organisation uuid
#   scim-token.txt       the SCIM bearer token
#   vw.log               server output
#
# Prints ORG=... and TOKEN=... on stdout so a caller can eval or append them to
# $GITHUB_ENV, rather than each job re-deriving them.
#
# The SCIM guard needs only an `organizations` row and a `scim_api_key` row
# holding the sha256 of the secret, so this skips account registration and all of
# its E2EE crypto.
set -euo pipefail

WORKDIR="${1:?usage: ci-seed-vaultwarden.sh <workdir> <binary> [bind-address]}"
BINARY="${2:?usage: ci-seed-vaultwarden.sh <workdir> <binary> [bind-address]}"
BIND="${3:-127.0.0.1}"

mkdir -p "$WORKDIR/vw-data"
cat > "$WORKDIR/.env" <<EOF
DATA_FOLDER=$WORKDIR/vw-data
DATABASE_URL=sqlite://$WORKDIR/vw-data/db.sqlite3
ROCKET_PORT=8000
ROCKET_ADDRESS=$BIND
DOMAIN=http://localhost:8000
SCIM_ENABLED=true
ORG_GROUPS_ENABLED=true
ORG_EVENTS_ENABLED=true
WEB_VAULT_ENABLED=false
SIGNUPS_ALLOWED=true
# The concurrency harness fires two requests per trial as fast as it can, and
# the SCIM guard rate-limits BEFORE authentication or any database work. At the
# default burst of 60 the back half of a 40-trial run is answered with 429s that
# never reach the last-owner guard at all - which the survivor count alone reads
# as "both refused", i.e. as the guard working. Raise it well clear so the
# measurement is of the guard and not of the limiter.
SCIM_RATELIMIT_MAX_BURST=1000
EOF

cd "$WORKDIR"
set -a; . ./.env; set +a
nohup "$BINARY" > "$WORKDIR/vw.log" 2>&1 &

for _ in $(seq 1 60); do
    curl -sf -o /dev/null "http://localhost:8000/alive" && break
    sleep 2
done
curl -sf -o /dev/null "http://localhost:8000/alive" || {
    echo "server never came up" >&2
    tail -30 "$WORKDIR/vw.log" >&2
    exit 1
}

ORG=11111111-2222-3333-4444-555555555555
SECRET="ci-$(openssl rand -hex 16)"
HASH=$(printf '%s' "$SECRET" | sha256sum | cut -d' ' -f1)
sqlite3 "$WORKDIR/vw-data/db.sqlite3" "
  INSERT OR REPLACE INTO organizations (uuid,name,billing_email)
    VALUES ('$ORG','CI Org','ci@example.com');
  INSERT OR REPLACE INTO scim_api_key (uuid,org_uuid,key_hash,enabled,created_at,revision_date)
    VALUES ('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee','$ORG','$HASH',1,datetime('now'),datetime('now'));"

TOKEN="scim_v1.$ORG.$SECRET"
echo "$ORG" > "$WORKDIR/org-id.txt"
echo "$TOKEN" > "$WORKDIR/scim-token.txt"

# Both jobs verify this, because a seed that does not authenticate turns every
# later assertion into a 401 that the harnesses would otherwise score as a
# refusal.
printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" \
  | curl -sf -K - -o /dev/null "http://localhost:8000/scim/v2/$ORG/ServiceProviderConfig" \
  || { echo "seeded token does not authenticate" >&2; exit 1; }

echo "ORG=$ORG"
echo "TOKEN=$TOKEN"
