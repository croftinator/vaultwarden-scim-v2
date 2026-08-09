#!/usr/bin/env bash
#
# Drive a REAL provisioning engine against a running Vaultwarden and assert the
# full lifecycle. Authentik is self-hosted, free and Docker-based, so unlike
# Entra, Okta, AWS and Google this one can run unattended in CI.
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
#   tools/scim-authentik-e2e.sh --domain http://host.docker.internal:8000 \
#                               --org <org_uuid> \
#                               --token scim_v1.<org_uuid>.<secret> \
#                               [--db /path/to/db.sqlite3] [--keep]
#
#   --domain  How AUTHENTIK reaches Vaultwarden, not how you do. Containers
#             cannot resolve "localhost" to your host: use
#             host.docker.internal on Docker Desktop, or 172.17.0.1 on Linux.
#   --db      Optional. If given, asserts revoke preserved the membership row
#             rather than deleting it - the invariant the whole design rests on.
#   --keep    Leave the Authentik stack running for inspection.
#
# Requires: docker (with compose), curl, python3. Exit 0 if every check passed.
#
set -uo pipefail

DOMAIN="${DOMAIN:-}"; ORG_ID="${ORG_ID:-}"; SCIM_TOKEN="${SCIM_TOKEN:-}"
DB_PATH=""; KEEP=0
WORKDIR="$(mktemp -d)"
AK_URL="http://localhost:9000"

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
    echo "ERROR: --domain, --org and --token are all required (see --help)" >&2; exit 2; }

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
trap cleanup EXIT

# SCIM query helper. Talks to Vaultwarden the way we reach it, which may differ
# from how Authentik does - the container needs host.docker.internal, we do not.
LOCAL_BASE="$(printf '%s' "$DOMAIN" | sed 's#host.docker.internal#localhost#')/scim/v2/$ORG_ID"
scim() { curl -s -H "Authorization: Bearer $SCIM_TOKEN" "$LOCAL_BASE/$1"; }

# ---------------------------------------------------------------------------
sect "1. Start Authentik"
# ---------------------------------------------------------------------------
cd "$WORKDIR"
curl -fsSL -o docker-compose.yml https://goauthentik.io/docker-compose.yml || {
    echo "ERROR: could not fetch the Authentik compose file" >&2; exit 1; }

AK_TOKEN="$(python3 -c 'import secrets;print(secrets.token_hex(32))')"
cat > .env <<EOF
PG_PASS=$(python3 -c 'import secrets;print(secrets.token_urlsafe(24))')
AUTHENTIK_SECRET_KEY=$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')
AUTHENTIK_ERROR_REPORTING__ENABLED=false
COMPOSE_PORT_HTTP=9000
COMPOSE_PORT_HTTPS=9443
AUTHENTIK_BOOTSTRAP_PASSWORD=$(python3 -c 'import secrets;print(secrets.token_urlsafe(18))')
AUTHENTIK_BOOTSTRAP_TOKEN=$AK_TOKEN
AUTHENTIK_BOOTSTRAP_EMAIL=admin@example.com
EOF
chmod 600 .env

docker compose up -d >/dev/null 2>&1 || { echo "ERROR: compose up failed" >&2; exit 1; }
printf '  waiting for Authentik'
for i in $(seq 1 60); do
    code="$(curl -s -o /dev/null -w '%{http_code}' "$AK_URL/-/health/ready/" 2>/dev/null)"
    [ "$code" = "200" ] || [ "$code" = "204" ] && { printf ' ready (%ss)\n' "$((i*5))"; break; }
    printf '.'; sleep 5
done
curl -s -o /dev/null "$AK_URL/-/health/ready/" || { echo; bad "Authentik never became ready"; exit 1; }
ok "Authentik is up"

# health/ready reflects the SERVER. The bootstrap token is created by the
# WORKER's startup task and lands a little later, so the API can be reachable
# and still reject it. Locally that gap is hidden by however long you take to do
# the next thing; in CI the next thing is immediate, and the first API call
# failed with a bare KeyError. Poll until the token actually authenticates.
printf '  waiting for the bootstrap token'
AUTHED=0
for i in $(seq 1 40); do
    code="$(curl -s -o /dev/null -w '%{http_code}' \
        -H "Authorization: Bearer $AK_TOKEN" "$AK_URL/api/v3/core/users/?page_size=1")"
    [ "$code" = "200" ] && { AUTHED=1; printf ' ready (%ss)\n' "$((i*5))"; break; }
    printf '.'; sleep 5
done
[ "$AUTHED" -eq 1 ] && ok "API authenticates with the bootstrap token" \
                    || { printf '\n'; bad "bootstrap token never became usable"; exit 1; }

api() { # api <METHOD> <PATH> [BODY]
    local m="$1" p="$2" b="${3:-}"
    if [ -n "$b" ]; then
        curl -s -X "$m" "$AK_URL/api/v3$p" -H "Authorization: Bearer $AK_TOKEN" \
             -H "Content-Type: application/json" -d "$b"
    else
        curl -s -X "$m" "$AK_URL/api/v3$p" -H "Authorization: Bearer $AK_TOKEN"
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

api POST '/core/applications/' "{\"name\":\"Vaultwarden\",\"slug\":\"vaultwarden\",\"provider\":$PROV}" >/dev/null
ok "application bound to the provider"

# ---------------------------------------------------------------------------
sect "3. Create a directory and let Authentik sync it"
# ---------------------------------------------------------------------------
PKS=""
for pair in "ak.alice:Alice Example" "ak.bob:Bob Example" "ak.carol:Carol Example"; do
    u="${pair%%:*}"; n="${pair#*:}"
    pk="$(api POST '/core/users/' "{\"username\":\"$u\",\"name\":\"$n\",
        \"email\":\"$u@example.com\",\"is_active\":true,\"type\":\"internal\"}" \
        | python3 -c "import json,sys; print(json.load(sys.stdin).get('pk',''))")"
    PKS="$PKS $pk"
done
ok "three users created in the directory"

set -- $PKS
api POST '/core/groups/' "{\"name\":\"Engineering\",\"users\":[$1,$2]}" >/dev/null
ok "group created with two of them"

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

scim Groups | python3 -c "
import json,sys
d=json.load(sys.stdin)
g=[r for r in d.get('Resources',[]) if r.get('displayName')=='Engineering']
raise SystemExit(0 if g and len(g[0].get('members',[]))==2 else 1)
" 2>/dev/null && ok "group synced with both members" || bad "group or its members did not sync"

# ---------------------------------------------------------------------------
sect "4. Deprovision (the highest-value path)"
# ---------------------------------------------------------------------------
set -- $PKS
api PATCH "/core/users/$1/" '{"is_active":false}' >/dev/null
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
if [ -n "$DB_PATH" ] && command -v sqlite3 >/dev/null 2>&1; then
    rows="$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM users_organizations uo
            JOIN users u ON u.uuid=uo.user_uuid WHERE u.email LIKE 'ak.%';" 2>/dev/null)"
    [ "${rows:-0}" -eq 3 ] && ok "all three membership rows survived (revoke, not delete)" \
                           || bad "expected 3 membership rows, found ${rows:-0}"
    akey="$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM users_organizations uo
            JOIN users u ON u.uuid=uo.user_uuid
            WHERE u.email LIKE 'ak.alice%' AND uo.akey IS NOT NULL;" 2>/dev/null)"
    [ "${akey:-0}" -eq 1 ] && ok "the revoked member kept its akey" \
                           || bad "the revoked member lost its akey"
fi

# ---------------------------------------------------------------------------
sect "5. Reinstate (must be lossless)"
# ---------------------------------------------------------------------------
api PATCH "/core/users/$1/" '{"is_active":true}' >/dev/null
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

printf '\n\033[1mResult: %d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
