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
# Environment:
#   DATABASE_URL    Optional. Default is sqlite in <workdir>. Set a
#                   postgresql:// URL to seed a PostgreSQL-backed server
#                   instead - the binary must then have been built with
#                   `--features postgresql`, and psql must be installed.
#                   See tools/local-stack/docker-compose.yml for the container.
#   SEED_EXTRA_ENV  Optional. Extra lines appended verbatim to the generated
#                   .env, for the hands-on path in docs/scim/testing.md that
#                   needs the web vault and SMTP. The defaults below stay
#                   CI-shaped (no web vault, no mail) because that is what the
#                   two workflow jobs want.
#
# Writes into <workdir>:
#   vw-data/db.sqlite3   the database, in sqlite mode only
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

# sqlite unless the caller asked for something else. Resolved before the .env is
# written so both the server and the seed below agree on one value; deriving it
# twice is how the two CI blocks this script replaced drifted apart.
DB_URL="${DATABASE_URL:-sqlite://$WORKDIR/vw-data/db.sqlite3}"
case "$DB_URL" in
    postgresql://*|postgres://*) DB_BACKEND=postgresql ;;
    sqlite://*)                  DB_BACKEND=sqlite ;;
    mysql://*)
        echo "ERROR: MySQL is not wired into this seeder yet; the SCIM suite covers it" >&2
        echo "       via tools/scim-test-backends.sh mysql." >&2
        exit 2 ;;
    *)  echo "ERROR: unrecognised DATABASE_URL scheme: $DB_URL" >&2; exit 2 ;;
esac

# Not "which sha256 tool exists" as a style choice: coreutils' sha256sum is not
# on a stock macOS, and the fallback is what lets this script run locally rather
# than only on the CI runners it was written for.
sha256_hex() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum | cut -d' ' -f1
    else
        shasum -a 256 | cut -d' ' -f1
    fi
}

# Homebrew's libpq is keg-only, so psql is installed but not on PATH - which
# looks identical to "not installed" and sends you off to brew a package you
# already have. tools/scim-test-backends.sh hits the same thing when it links
# against the library.
PSQL=""
resolve_psql() {
    if command -v psql >/dev/null 2>&1; then PSQL="psql"; return 0; fi
    local prefix
    for prefix in /opt/homebrew/opt /usr/local/opt; do
        if [ -x "$prefix/libpq/bin/psql" ]; then PSQL="$prefix/libpq/bin/psql"; return 0; fi
    done
    echo "ERROR: DATABASE_URL is PostgreSQL but psql was not found." >&2
    echo "       macOS:  brew install libpq   (keg-only; this script finds it there)" >&2
    echo "       Debian: apt install postgresql-client" >&2
    return 1
}
[ "$DB_BACKEND" = "postgresql" ] && { resolve_psql || exit 2; }

# One entry point for both dialects. The SQL below is deliberately written to be
# dialect-neutral wherever it can be - CURRENT_TIMESTAMP and the TRUE literal
# are understood by both - so only the upsert has two forms.
db_exec() {
    if [ "$DB_BACKEND" = "postgresql" ]; then
        "$PSQL" "$DB_URL" -v ON_ERROR_STOP=1 -tAq -c "$1"
    else
        sqlite3 "$WORKDIR/vw-data/db.sqlite3" "$1"
    fi
}

mkdir -p "$WORKDIR/vw-data"
cat > "$WORKDIR/.env" <<EOF
DATA_FOLDER=$WORKDIR/vw-data
DATABASE_URL=$DB_URL
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
# Appended last so it wins: Vaultwarden takes the final assignment of a repeated
# key, which is what makes WEB_VAULT_ENABLED=true overridable from the caller
# without this script growing a flag per setting.
[ -n "${SEED_EXTRA_ENV:-}" ] && printf '%s\n' "$SEED_EXTRA_ENV" >> "$WORKDIR/.env"

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
HASH=$(printf '%s' "$SECRET" | sha256_hex)

# Two statements, not one multi-statement string: psql -c runs a multi-statement
# argument in a single implicit transaction, so a failure in the second would
# roll back the first and leave no trace of either. Separately, the org insert
# must be visible before the key insert can satisfy the foreign key on
# scim_api_key.org_uuid, which sqlite does not enforce without a PRAGMA but
# PostgreSQL always does.
if [ "$DB_BACKEND" = "postgresql" ]; then
    db_exec "INSERT INTO organizations (uuid,name,billing_email)
             VALUES ('$ORG','CI Org','ci@example.com')
             ON CONFLICT (uuid) DO UPDATE SET name=EXCLUDED.name,
                                              billing_email=EXCLUDED.billing_email;"
    db_exec "INSERT INTO scim_api_key (uuid,org_uuid,key_hash,enabled,created_at,revision_date)
             VALUES ('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee','$ORG','$HASH',TRUE,
                     CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
             ON CONFLICT (uuid) DO UPDATE SET key_hash=EXCLUDED.key_hash,
                                              enabled=EXCLUDED.enabled,
                                              revision_date=EXCLUDED.revision_date;"
else
    db_exec "INSERT OR REPLACE INTO organizations (uuid,name,billing_email)
             VALUES ('$ORG','CI Org','ci@example.com');"
    db_exec "INSERT OR REPLACE INTO scim_api_key (uuid,org_uuid,key_hash,enabled,created_at,revision_date)
             VALUES ('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee','$ORG','$HASH',TRUE,
                     CURRENT_TIMESTAMP,CURRENT_TIMESTAMP);"
fi

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
