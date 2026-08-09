#!/usr/bin/env bash
#
# Drive a REAL provisioning engine against a running Vaultwarden and assert the
# full lifecycle. Authentik is self-hosted, free and Docker-based, so unlike
# Entra, Okta and Google this one can run unattended in CI.
#
# What this covers that nothing else does: the in-process suite sends requests we
# wrote, and scim-replay.sh sends request shapes we wrote. Both encode our
# reading of what an engine does. This runs software that has never heard of us
# and lets it decide what to send, on its own sync schedule.
#
# What it does NOT cover: vendor quirks. Authentik sends textbook SCIM and will
# never produce Entra's "Replace" casing or Okta's path-less deactivate. Those
# stay the in-process suite's job. See docs/scim/testing.md "Rung 2b".
#
# Usage:
#   SCIM_TOKEN=scim_v1.<org_uuid>.<secret> \
#     tools/scim-authentik-e2e.sh --domain http://host.docker.internal:8000 \
#                                 --org <org_uuid> \
#                                 [--db /path/to/db.sqlite3] [--keep]
#
#   The token comes from SCIM_TOKEN, not argv: anything else on the machine can
#   read a command line out of ps(1), and this one can deprovision every member
#   of the organization. --token is still accepted for interactive use.
#
#   --domain  How AUTHENTIK reaches Vaultwarden, not how you do. Containers
#             cannot resolve "localhost" to your host: use
#             host.docker.internal on Docker Desktop, or 172.17.0.1 on Linux.
#   --db      Asserts revoke PRESERVED the membership row and its akey rather
#             than deleting it - the invariant the whole design rests on. Takes
#             either a sqlite FILE PATH or a postgresql:// URL, and the matching
#             client (sqlite3 or psql) must be present: a silently skipped
#             invariant check is worse than a missing one, because the run still
#             reports green. The assertions themselves are the same either way -
#             the SQL is dialect-neutral, only the client differs.
#   --keep    Leave the Authentik stack running for inspection.
#
# Requires: docker (with compose), curl, python3. Exit 0 if every check passed.
#
set -uo pipefail

DOMAIN="${DOMAIN:-}"; ORG_ID="${ORG_ID:-}"; SCIM_TOKEN="${SCIM_TOKEN:-}"
DB_PATH=""; KEEP=0
WORKDIR="$(mktemp -d)"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# The Authentik release this harness is pinned to. Bump deliberately, together
# with a local run: see tools/authentik/docker-compose.yml.
AUTHENTIK_TAG="${AUTHENTIK_TAG:-2025.8}"

# Ports are per-run so two local invocations cannot collide on 9000/9443, and so
# a leftover container from an earlier run is not silently reused. $$ keeps it
# deterministic within a run.
AK_PORT="${AK_PORT:-$((9000 + ($$ % 400)))}"
AK_PORT_HTTPS=$((AK_PORT + 500))
AK_URL="http://localhost:$AK_PORT"
# A per-run project name, so `docker compose down -v` in cleanup can never reach
# another run's containers and two runs cannot fight over container names.
COMPOSE_PROJECT_NAME="scimak$$"
export COMPOSE_PROJECT_NAME

while [ $# -gt 0 ]; do
    case "$1" in
        --domain) DOMAIN="${2:-}"; shift 2 ;;
        --org)    ORG_ID="${2:-}"; shift 2 ;;
        --token)  SCIM_TOKEN="${2:-}"; shift 2 ;;
        --db)     DB_PATH="${2:-}"; shift 2 ;;
        --keep)   KEEP=1; shift ;;
        -h|--help) sed -n '2,${/^#/!q;p;}' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done

for tool in docker curl python3; do
    command -v "$tool" >/dev/null 2>&1 || { echo "ERROR: '$tool' is required" >&2; exit 2; }
done
[ -n "$DOMAIN" ] && [ -n "$ORG_ID" ] && [ -n "$SCIM_TOKEN" ] || {
    echo "ERROR: --domain, --org and a SCIM_TOKEN are all required (see --help)" >&2; exit 2; }
# --db is a promise that the database invariants WILL be asserted. Skipping them
# because a client happens to be missing, and still exiting 0, is the failure
# this whole harness exists to avoid. That applies equally to both backends, so
# the reachability check below is not a formality: an unreachable PostgreSQL
# would otherwise turn every invariant assertion into an empty string, and an
# empty string compares unequal to the sentinel, which reads as a real failure
# rather than as a missing database.
DB_KIND=""
PSQL=""
if [ -n "$DB_PATH" ]; then
    case "$DB_PATH" in
        postgresql://*|postgres://*)
            DB_KIND=postgresql
            # Homebrew's libpq is keg-only, so psql is installed but not on
            # PATH - indistinguishable from absent unless you go looking.
            if command -v psql >/dev/null 2>&1; then
                PSQL="psql"
            else
                for _p in /opt/homebrew/opt /usr/local/opt; do
                    [ -x "$_p/libpq/bin/psql" ] && { PSQL="$_p/libpq/bin/psql"; break; }
                done
            fi
            [ -n "$PSQL" ] || {
                echo "ERROR: --db is a PostgreSQL URL but psql was not found; the invariant checks cannot run" >&2
                echo "       macOS:  brew install libpq   (keg-only; this script finds it there)" >&2
                echo "       Debian: apt install postgresql-client" >&2
                exit 2; }
            "$PSQL" "$DB_PATH" -v ON_ERROR_STOP=1 -tAqc 'SELECT 1' >/dev/null 2>&1 || {
                echo "ERROR: cannot reach the database at the given --db URL" >&2; exit 2; }
            ;;
        *)
            DB_KIND=sqlite
            command -v sqlite3 >/dev/null 2>&1 || {
                echo "ERROR: --db was given but sqlite3 is not installed; the invariant checks cannot run" >&2; exit 2; }
            [ -f "$DB_PATH" ] || { echo "ERROR: no database at $DB_PATH" >&2; exit 2; }
            ;;
    esac
fi

# One entry point for both dialects. Every statement this harness runs is plain
# SELECT/UPDATE with a join and a LIKE, so nothing below needs a per-dialect
# variant - and `psql -tA` emits bare unpadded values exactly as sqlite3 does,
# which is what lets the string comparisons on akey and status stay identical.
db() {
    if [ "$DB_KIND" = "postgresql" ]; then
        "$PSQL" "$DB_PATH" -v ON_ERROR_STOP=1 -tAqc "$1"
    else
        sqlite3 "$DB_PATH" "$1"
    fi
}

PASS=0; FAIL=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
sect() { printf '\n\033[1m%s\033[0m\n' "$1"; }

cleanup() {
    if [ "$KEEP" -eq 0 ]; then
        (cd "$WORKDIR" && docker compose down -v >/dev/null 2>&1)
        rm -rf "$WORKDIR"
    else
        echo "Kept: $WORKDIR (docker compose down -v to clean up)"
    fi
}
trap cleanup EXIT INT TERM

# SCIM query helper. Talks to Vaultwarden the way we reach it, which may differ
# from how Authentik does - the container needs host.docker.internal, we do not.
LOCAL_BASE="$(printf '%s' "$DOMAIN" | sed 's#host.docker.internal#localhost#')/scim/v2/$ORG_ID"
# The Authorization header goes in via `curl -K -` rather than -H, so the bearer
# token never appears in curl's argv where any local user could read it from
# ps(1). tools/scim-replay.sh made the same call and explains it at length.
scim() {
    printf 'header = "Authorization: Bearer %s"\n' "$SCIM_TOKEN" \
        | curl -s -K - "$LOCAL_BASE/$1"
}

# ---------------------------------------------------------------------------
sect "1. Start Authentik"
# ---------------------------------------------------------------------------
cd "$WORKDIR"
# Vendored and pinned; see tools/authentik/docker-compose.yml for why this is
# not fetched from goauthentik.io at run time.
cp "$REPO_ROOT/tools/authentik/docker-compose.yml" docker-compose.yml

AK_TOKEN="$(python3 -c 'import secrets;print(secrets.token_hex(32))')"
cat > .env <<EOF
PG_PASS=$(python3 -c 'import secrets;print(secrets.token_urlsafe(24))')
AUTHENTIK_SECRET_KEY=$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')
AUTHENTIK_ERROR_REPORTING__ENABLED=false
COMPOSE_PORT_HTTP=$AK_PORT
COMPOSE_PORT_HTTPS=$AK_PORT_HTTPS
AUTHENTIK_BOOTSTRAP_PASSWORD=$(python3 -c 'import secrets;print(secrets.token_urlsafe(18))')
AUTHENTIK_BOOTSTRAP_TOKEN=$AK_TOKEN
AUTHENTIK_BOOTSTRAP_EMAIL=admin@example.com
AUTHENTIK_TAG=$AUTHENTIK_TAG
EOF
chmod 600 .env

docker compose up -d >/dev/null 2>&1 || { echo "ERROR: compose up failed" >&2; exit 1; }
printf '  waiting for Authentik'
READY=0
for i in $(seq 1 60); do
    code="$(curl -s -o /dev/null -w '%{http_code}' "$AK_URL/-/health/ready/" 2>/dev/null)"
    if [ "$code" = "200" ] || [ "$code" = "204" ]; then
        printf ' ready (%ss)\n' "$((i*5))"; READY=1; break
    fi
    printf '.'; sleep 5
done
# A flag, not a repeat curl. The old backstop was `curl -s` with no -f, which
# exits 0 for ANY http status - so once the port was listening it always
# succeeded, and the guard meant to catch loop exhaustion reported success
# against a 500. The AUTHED and SYNCED loops below already use this pattern.
[ "$READY" -eq 1 ] || { echo; bad "Authentik never became ready"; docker compose logs --tail=40; exit 1; }
ok "Authentik is up"

# health/ready reflects the SERVER. The bootstrap token is created by the
# WORKER's startup task and lands a little later, so the API can be reachable
# and still reject it. Locally that gap is hidden by however long you take to do
# the next thing; in CI the next thing is immediate, and the first API call
# failed with a bare KeyError. Poll until the token actually authenticates.
printf '  waiting for the bootstrap token'
AUTHED=0
for i in $(seq 1 40); do
    code="$(printf 'header = "Authorization: Bearer %s"\n' "$AK_TOKEN" \
        | curl -s -K - -o /dev/null -w '%{http_code}' "$AK_URL/api/v3/core/users/?page_size=1")"
    [ "$code" = "200" ] && { AUTHED=1; printf ' ready (%ss)\n' "$((i*5))"; break; }
    printf '.'; sleep 5
done
[ "$AUTHED" -eq 1 ] && ok "API authenticates with the bootstrap token" \
                    || { printf '\n'; bad "bootstrap token never became usable"; exit 1; }

# Same treatment for Authentik's bootstrap token: it is an admin API credential,
# and it is written into the compose stack's database, so keeping it out of argv
# costs nothing. Bodies go through a file rather than -d for the same reason -
# the SCIM provider body carries the Vaultwarden token.
api() { # api <METHOD> <PATH> [BODY]
    local m="$1" p="$2" b="${3:-}" body_file
    if [ -n "$b" ]; then
        body_file="$(mktemp)"
        printf '%s' "$b" > "$body_file"
        printf 'header = "Authorization: Bearer %s"\nheader = "Content-Type: application/json"\n' "$AK_TOKEN" \
            | curl -s -K - -X "$m" "$AK_URL/api/v3$p" --data-binary "@$body_file"
        rm -f "$body_file"
    else
        printf 'header = "Authorization: Bearer %s"\n' "$AK_TOKEN" \
            | curl -s -K - -X "$m" "$AK_URL/api/v3$p"
    fi
}

# ---------------------------------------------------------------------------
sect "2. Point Authentik at Vaultwarden"
# ---------------------------------------------------------------------------
# The default SCIM property mappings ship as a BLUEPRINT, applied by the worker
# after startup - later still than the bootstrap token. Querying immediately
# returns an empty result set, not an error, so this polls for content rather
# than for a status code. Same race as the token, one layer deeper.
printf '  waiting for the SCIM property mappings'
UMAP=""; GMAP=""
for i in $(seq 1 40); do
    MAPS="$(api GET '/propertymappings/provider/scim/?page_size=20')"
    UMAP="$(printf '%s' "$MAPS" | python3 -c "
import json,sys
try: d = json.load(sys.stdin)
except Exception: raise SystemExit
for r in d.get('results', []):
    if 'User' in r.get('name',''): print(r['pk']); break
" 2>/dev/null)"
    GMAP="$(printf '%s' "$MAPS" | python3 -c "
import json,sys
try: d = json.load(sys.stdin)
except Exception: raise SystemExit
for r in d.get('results', []):
    if 'Group' in r.get('name',''): print(r['pk']); break
" 2>/dev/null)"
    [ -n "$UMAP" ] && [ -n "$GMAP" ] && { printf ' found (%ss)\n' "$((i*5))"; break; }
    printf '.'; sleep 5
done

if [ -n "$UMAP" ] && [ -n "$GMAP" ]; then
    ok "found the default SCIM property mappings"
else
    printf '\n'
    bad "SCIM property mappings never appeared"
    echo "  last response was: $(printf '%s' "$MAPS" | head -c 300)"
    exit 1
fi

PROV="$(api POST '/providers/scim/' "{\"name\":\"Vaultwarden\",
  \"url\":\"$DOMAIN/scim/v2/$ORG_ID\",\"token\":\"$SCIM_TOKEN\",
  \"exclude_users_service_account\":true,
  \"property_mappings\":[\"$UMAP\"],\"property_mappings_group\":[\"$GMAP\"]}" \
  | python3 -c "import json,sys; print(json.load(sys.stdin).get('pk',''))")"
[ -n "$PROV" ] && ok "SCIM provider created" || { bad "could not create the SCIM provider"; exit 1; }

APP="$(api POST '/core/applications/' "{\"name\":\"Vaultwarden\",\"slug\":\"vaultwarden\",\"provider\":$PROV}" \
  | python3 -c "import json,sys; print(json.load(sys.stdin).get('pk',''))" 2>/dev/null)"
# Checked, not assumed. An unbound application means Authentik never syncs
# anything, and the failure used to surface 200 seconds later as the misleading
# "users never appeared" - after three PASS lines were already on the board.
[ -n "$APP" ] && ok "application bound to the provider" \
              || { bad "could not bind the application to the provider"; exit 1; }

# ---------------------------------------------------------------------------
sect "3. Create a directory and let Authentik sync it"
# ---------------------------------------------------------------------------
# An array, not a whitespace string: an empty pk used to shorten the list and
# make `$2` below abort the script with a bare unbound-variable message under
# `set -u`, several steps after the real failure.
PKS=()
for pair in "ak.alice:Alice Example" "ak.bob:Bob Example" "ak.carol:Carol Example"; do
    u="${pair%%:*}"; n="${pair#*:}"
    pk="$(api POST '/core/users/' "{\"username\":\"$u\",\"name\":\"$n\",
        \"email\":\"$u@example.com\",\"is_active\":true,\"type\":\"internal\"}" \
        | python3 -c "import json,sys; print(json.load(sys.stdin).get('pk',''))" 2>/dev/null)"
    [ -n "$pk" ] || { bad "could not create directory user $u"; exit 1; }
    PKS+=("$pk")
done
[ "${#PKS[@]}" -eq 3 ] && ok "three users created in the directory" \
                       || { bad "expected 3 directory users, created ${#PKS[@]}"; exit 1; }

GRP="$(api POST '/core/groups/' "{\"name\":\"Engineering\",\"users\":[${PKS[0]},${PKS[1]}]}" \
  | python3 -c "import json,sys; print(json.load(sys.stdin).get('pk',''))" 2>/dev/null)"
[ -n "$GRP" ] && ok "group created with two of them" \
              || { bad "could not create the directory group"; exit 1; }

# Authentik syncs on its own schedule. Poll rather than sleep: a fixed wait is
# either flaky or slow, and this makes the timeout explicit.
printf '  waiting for the sync'
SYNCED=0
for i in $(seq 1 40); do
    n="$(scim Users | python3 -c "import json,sys; print(json.load(sys.stdin).get('totalResults',0))" 2>/dev/null || echo 0)"
    [ "${n:-0}" -ge 3 ] && { SYNCED=1; printf ' done (%ss)\n' "$((i*5))"; break; }
    printf '.'; sleep 5
done
[ "$SYNCED" -eq 1 ] && ok "all three users provisioned into Vaultwarden" \
                    || { printf '\n'; bad "users never appeared (waited 200s)"; }

# Polled, not checked once. Authentik provisions users and groups in the same
# task but not at the same instant, so the group lands a little after the third
# user does - and the user poll above is what releases us. A single shot here
# passed on a fast run and failed on a slow one, which is the definition of a
# flaky assertion: it was reporting scheduler timing, not whether group sync
# works. Every other wait in this script polls; this one did not.
printf '  waiting for the group sync'
GSYNCED=0
for i in $(seq 1 40); do
    n="$(scim Groups | python3 -c "
import json,sys
d=json.load(sys.stdin)
g=[r for r in d.get('Resources',[]) if r.get('displayName')=='Engineering']
print(len(g[0].get('members',[])) if g else -1)" 2>/dev/null || echo -1)"
    [ "${n:-0}" -eq 2 ] && { GSYNCED=1; printf ' done (%ss)\n' "$((i*5))"; break; }
    printf '.'; sleep 5
done
[ "$GSYNCED" -eq 1 ] && ok "group synced with both members" \
                     || { printf '\n'; bad "group or its members did not sync (waited 200s)"; }

# ---------------------------------------------------------------------------
sect "4. Deprovision (the highest-value path)"
# ---------------------------------------------------------------------------
# Seed a real wrapped org key and a Confirmed status BEFORE deprovisioning.
#
# Without this the whole E2EE assertion below is theatre: a SCIM-provisioned
# member is only ever Invited, so its akey is the empty string and its status is
# 0. "The akey survived" would then be true of a row that never held one. The
# invariant that matters - a CONFIRMED member's wrapped key survives revoke, so
# reinstatement needs no re-confirmation - is only reachable from a Confirmed
# row, and no server-side path can produce one (that is the point of the
# design), so the harness writes it directly.
AKEY_SENTINEL="SENTINEL-WRAPPED-ORG-KEY-$$"
if [ -n "$DB_PATH" ]; then
    db "
      UPDATE users_organizations
      SET akey='$AKEY_SENTINEL', status=2
      WHERE user_uuid IN (SELECT uuid FROM users WHERE email LIKE 'ak.alice%');" \
      || { bad "could not seed the confirmed membership"; exit 1; }
    seeded="$(db "SELECT COUNT(*) FROM users_organizations uo
              JOIN users u ON u.uuid=uo.user_uuid
              WHERE u.email LIKE 'ak.alice%' AND uo.akey='$AKEY_SENTINEL' AND uo.status=2;")"
    [ "${seeded:-0}" -eq 1 ] || { bad "the confirmed membership did not seed"; exit 1; }
fi

api PATCH "/core/users/${PKS[0]}/" '{"is_active":false}' >/dev/null
printf '  waiting for the deactivation'
DEACT=0
for i in $(seq 1 40); do
    a="$(scim Users | python3 -c "
import json,sys
d=json.load(sys.stdin)
u=[r for r in d.get('Resources',[]) if r.get('userName','').startswith('ak.alice')]
print(str(u[0]['active']).lower() if u else 'missing')" 2>/dev/null || echo err)"
    [ "$a" = "false" ] && { DEACT=1; printf ' done (%ss)\n' "$((i*5))"; break; }
    printf '.'; sleep 5
done
[ "$DEACT" -eq 1 ] && ok "deactivating in the directory revoked in Vaultwarden" \
                   || { printf '\n'; bad "deactivation never propagated"; }

# The invariant the whole design rests on: revoke must PRESERVE the row, so the
# wrapped org key survives and reinstatement needs no re-confirmation.
#
# Asserted on CONTENT, not on nullability. `uo.akey` is declared NOT NULL in the
# 2018 create-tables migration and typed non-nullable in schema.rs, so the
# previous `akey IS NOT NULL` was true for every row that existed - it restated
# the row-count check above it and could not detect akey loss of any kind.
if [ -n "$DB_PATH" ]; then
    rows="$(db "SELECT COUNT(*) FROM users_organizations uo
            JOIN users u ON u.uuid=uo.user_uuid WHERE u.email LIKE 'ak.%';")"
    [ "${rows:-0}" -eq 3 ] && ok "all three membership rows survived (revoke, not delete)" \
                           || bad "expected 3 membership rows, found ${rows:-0}"

    akey_now="$(db "SELECT uo.akey FROM users_organizations uo
                JOIN users u ON u.uuid=uo.user_uuid WHERE u.email LIKE 'ak.alice%';")"
    [ "$akey_now" = "$AKEY_SENTINEL" ] \
        && ok "the revoked member kept its wrapped org key byte for byte" \
        || bad "the revoked member's akey changed: expected '$AKEY_SENTINEL', found '$akey_now'"

    # The revocation ENCODING, not just the flag. `active:false` is read back
    # through the same membership_active() mapping that wrote it, so a
    # regression storing the MembershipStatus::Revoked sentinel (-1) instead of
    # applying ACTIVATE_REVOKE_DIFF (128) still reads as inactive. Confirmed (2)
    # must become exactly -126.
    status_now="$(db "SELECT uo.status FROM users_organizations uo
                  JOIN users u ON u.uuid=uo.user_uuid WHERE u.email LIKE 'ak.alice%';")"
    [ "$status_now" = "-126" ] \
        && ok "revoked-confirmed is stored as -126 (the 128 offset, not a sentinel)" \
        || bad "expected status -126 after revoking a confirmed member, found '$status_now'"
fi

# ---------------------------------------------------------------------------
sect "5. Reinstate (must be lossless)"
# ---------------------------------------------------------------------------
api PATCH "/core/users/${PKS[0]}/" '{"is_active":true}' >/dev/null
printf '  waiting for the reinstatement'
REACT=0
for i in $(seq 1 40); do
    a="$(scim Users | python3 -c "
import json,sys
d=json.load(sys.stdin)
u=[r for r in d.get('Resources',[]) if r.get('userName','').startswith('ak.alice')]
print(str(u[0]['active']).lower() if u else 'missing')" 2>/dev/null || echo err)"
    [ "$a" = "true" ] && { REACT=1; printf ' done (%ss)\n' "$((i*5))"; break; }
    printf '.'; sleep 5
done
[ "$REACT" -eq 1 ] && ok "reinstating in the directory restored access" \
                   || { printf '\n'; bad "reinstatement never propagated"; }

# "Lossless" is the whole claim of this section, and `active: true` does not
# establish it. A regression that dropped and re-created the row, or restored to
# Invited instead of the prior status, satisfies the flag check above and breaks
# the property the design actually promises: a returning employee needs no
# re-confirmation because their wrapped org key was never touched.
if [ -n "$DB_PATH" ]; then
    akey_after="$(db "SELECT uo.akey FROM users_organizations uo
                  JOIN users u ON u.uuid=uo.user_uuid WHERE u.email LIKE 'ak.alice%';")"
    [ "$akey_after" = "$AKEY_SENTINEL" ] \
        && ok "the reinstated member still holds the same wrapped org key" \
        || bad "reinstatement changed the akey: expected '$AKEY_SENTINEL', found '$akey_after'"

    status_after="$(db "SELECT uo.status FROM users_organizations uo
                    JOIN users u ON u.uuid=uo.user_uuid WHERE u.email LIKE 'ak.alice%';")"
    [ "$status_after" = "2" ] \
        && ok "restore returned the member to Confirmed, not to Invited" \
        || bad "expected status 2 after reinstatement, found '$status_after'"
fi

# The group-side deprovision path, which nothing else here exercises: removing a
# member from the directory group must remove them from the Vaultwarden group.
sect "6. Remove one member from the group"
api PATCH "/core/groups/$GRP/" "{\"users\":[${PKS[0]}]}" >/dev/null
printf '  waiting for the group update'
SHRANK=0
for i in $(seq 1 40); do
    n="$(scim Groups | python3 -c "
import json,sys
d=json.load(sys.stdin)
g=[r for r in d.get('Resources',[]) if r.get('displayName')=='Engineering']
print(len(g[0].get('members',[])) if g else -1)" 2>/dev/null || echo -1)"
    [ "${n:-0}" -eq 1 ] && { SHRANK=1; printf ' done (%ss)\n' "$((i*5))"; break; }
    printf '.'; sleep 5
done
[ "$SHRANK" -eq 1 ] && ok "removing a member in the directory removed them from the group" \
                    || { printf '\n'; bad "the group membership removal never propagated"; }

printf '\n\033[1mResult: %d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
