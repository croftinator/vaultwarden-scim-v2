#!/usr/bin/env bash
#
# Build the whole demo: sandbox, Authentik doing SSO and SCIM, a seeded vault,
# provisioned members, and the guided walkthrough page.
#
# What it is for, and what it deliberately stops short of, are in
# docs/scim/demo.md. The short version: the automated rungs in testing.md prove
# the endpoint answers correctly; this proves the feature is usable, including
# the one step no server can perform - confirming a member.
#
# Usage:
#   tools/scim-demo.sh                # build it (idempotent)
#   tools/scim-demo.sh --reset        # back to the seeded state, no rebuild
#   tools/scim-demo.sh --sync         # force a SCIM sync now
#   tools/scim-demo.sh --status
#   tools/scim-demo.sh --down         # stop everything, keep data
#   tools/scim-demo.sh --purge        # destroy everything
#
# Requires: everything tools/scim-sandbox.sh needs, plus node/npx and the
# Bitwarden CLI (bw).
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AK_DIR="$REPO_ROOT/tools/authentik"
AK_COMPOSE="$AK_DIR/docker-compose.demo.yml"
AK_PROJECT="scim-demo"
AK_URL="http://localhost:${AK_PORT:-9000}"
SANDBOX_DIR="${SANDBOX_DIR:-$HOME/vaultwarden-sandbox}"
PG_URL="postgresql://${PG_USER:-vaultwarden}:${PG_PASS:-vwscim}@127.0.0.1:${PG_PORT:-15433}/${PG_DB:-vaultwarden}"
DEMO_PORT="${DEMO_PORT:-8099}"

say()  { printf '\n\033[1m%s\033[0m\n' "$1"; }
ok()   { printf '  \033[32m%s\033[0m\n' "$1"; }
warn() { printf '  \033[33m%s\033[0m\n' "$1"; }
die()  { printf '  \033[31mERROR: %s\033[0m\n' "$1" >&2; exit 1; }

set -a; . "$REPO_ROOT/playwright/demo.env"; set +a

# Homebrew's libpq is keg-only, so psql is present but off PATH.
PSQL=psql
command -v psql >/dev/null 2>&1 || for p in /opt/homebrew/opt /usr/local/opt; do
    [ -x "$p/libpq/bin/psql" ] && PSQL="$p/libpq/bin/psql"
done
sql() { "$PSQL" "$PG_URL" -v ON_ERROR_STOP=1 -tAqc "$1"; }

ak_token() { grep '^AUTHENTIK_BOOTSTRAP_TOKEN=' "$AK_DIR/.env" | cut -d= -f2-; }
ak_api() { # ak_api METHOD PATH [BODY]
    local m="$1" p="$2" b="${3:-}" f
    if [ -n "$b" ]; then
        f="$(mktemp)"; printf '%s' "$b" > "$f"
        printf 'header = "Authorization: Bearer %s"\nheader = "Content-Type: application/json"\n' "$(ak_token)" \
            | curl -s -K - -X "$m" "$AK_URL/api/v3$p" --data-binary "@$f"
        rm -f "$f"
    else
        printf 'header = "Authorization: Bearer %s"\n' "$(ak_token)" | curl -s -K - -X "$m" "$AK_URL/api/v3$p"
    fi
}
jq_get() { python3 -c "import json,sys;d=json.load(sys.stdin);print(d.get('$1','') if isinstance(d,dict) else '')" 2>/dev/null || true; }

ak_compose() { ( cd "$AK_DIR" && docker compose -p "$AK_PROJECT" -f "$AK_COMPOSE" "$@" ); }

# ---------------------------------------------------------------------------
case "${1:-up}" in
    --down)
        "$REPO_ROOT/tools/scim-sandbox.sh" --down >/dev/null 2>&1 || true
        ak_compose down >/dev/null 2>&1 || true
        say "Stopped. Data kept - --purge destroys it."
        exit 0 ;;
    --purge)
        "$REPO_ROOT/tools/scim-sandbox.sh" --purge >/dev/null 2>&1 || true
        ak_compose down -v >/dev/null 2>&1 || true
        rm -f "$AK_DIR/.env"
        say "Purged everything, including both databases."
        exit 0 ;;
    --status)
        "$REPO_ROOT/tools/scim-sandbox.sh" --status || true
        curl -sf -o /dev/null "$AK_URL/-/health/ready/" && ok "Authentik up at $AK_URL" || warn "Authentik down"
        sql "SELECT u.email || '  status=' || uo.status FROM users_organizations uo
             JOIN users u ON u.uuid=uo.user_uuid ORDER BY u.email;" 2>/dev/null | sed 's/^/  /' || true
        exit 0 ;;
    --sync) ;;
    --reset) ;;
    up|"") ;;
    *) die "unknown argument: $1" ;;
esac
MODE="${1:-up}"

# ---------------------------------------------------------------------------
# --sync only: nudge Authentik and leave.
#
# Authentik has no "sync now" API endpoint in this release (POST .../sync/
# returns 405). Saving the provider enqueues a full sync, so a no-op PATCH is
# the supported way to trigger one. Without this you wait for its own schedule,
# which is the commonest reason a demo looks broken when it is merely early.
force_sync() {
    local pk="$1"
    ak_api PATCH "/providers/scim/$pk/" '{"name":"Vaultwarden SCIM"}' >/dev/null
}

if [ "$MODE" = "--sync" ]; then
    PK="$(ak_api GET '/providers/scim/' | python3 -c "
import json,sys
r=[p for p in json.load(sys.stdin).get('results',[]) if p['name']=='Vaultwarden SCIM']
print(r[0]['pk'] if r else '')")"
    [ -n "$PK" ] || die "no SCIM provider yet - run tools/scim-demo.sh first"
    force_sync "$PK"
    ok "sync requested; members appear within a few seconds"
    exit 0
fi

# ---------------------------------------------------------------------------
say "1. Sandbox"
# ---------------------------------------------------------------------------
"$REPO_ROOT/tools/scim-sandbox.sh" >/dev/null || die "the sandbox failed to start; run tools/scim-sandbox.sh directly to see why"
ok "Vaultwarden on $DEMO_DOMAIN"

# ---------------------------------------------------------------------------
say "2. Authentik"
# ---------------------------------------------------------------------------
command -v mkcert >/dev/null || die "mkcert is required (see tools/scim-sandbox.sh)"
if [ ! -f "$AK_DIR/.env" ]; then
    cat > "$AK_DIR/.env" <<EOF
PG_PASS=$(python3 -c 'import secrets;print(secrets.token_urlsafe(24))')
AUTHENTIK_SECRET_KEY=$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')
AUTHENTIK_ERROR_REPORTING__ENABLED=false
AUTHENTIK_TAG=2025.8
AK_PORT=${AK_PORT:-9000}
AK_PORT_HTTPS=$(( ${AK_PORT:-9000} + 443 ))
AUTHENTIK_BOOTSTRAP_PASSWORD=$(python3 -c 'import secrets;print(secrets.token_urlsafe(18))')
AUTHENTIK_BOOTSTRAP_TOKEN=$(python3 -c 'import secrets;print(secrets.token_hex(32))')
AUTHENTIK_BOOTSTRAP_EMAIL=admin@example.com
DEMO_OIDC_CLIENT_ID=vaultwarden-demo
DEMO_OIDC_CLIENT_SECRET=$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')
DEMO_VW_REDIRECT_URI=$DEMO_DOMAIN/identity/connect/oidc-signin
MKCERT_ROOT_CA=$(mkcert -CAROOT)/rootCA.pem
EOF
    chmod 600 "$AK_DIR/.env"
    ok "generated $AK_DIR/.env (gitignored)"
fi
ak_compose up -d >/dev/null 2>&1 || die "Authentik failed to start"
for _ in $(seq 1 60); do
    c="$(curl -s -o /dev/null -w '%{http_code}' "$AK_URL/-/health/ready/" || true)"
    [ "$c" = "200" ] || [ "$c" = "204" ] && break
    sleep 5
done
for _ in $(seq 1 40); do
    [ "$(printf 'header = "Authorization: Bearer %s"\n' "$(ak_token)" \
        | curl -s -K - -o /dev/null -w '%{http_code}' "$AK_URL/api/v3/core/users/")" = "200" ] && break
    sleep 5
done
ok "Authentik ready at $AK_URL, blueprints applied"

# ---------------------------------------------------------------------------
say "3. Reset"
# ---------------------------------------------------------------------------
# --reset wipes the Vaultwarden side only. Authentik's directory is declarative
# (blueprints) so it needs no reset, and re-registering is what costs time.
if [ "$MODE" = "--reset" ]; then
    sql "TRUNCATE users CASCADE;" >/dev/null
    sql "TRUNCATE organizations CASCADE;" >/dev/null
    # The CLI caches a session for a server that no longer has that account.
    bw logout >/dev/null 2>&1 || true
    ok "Vaultwarden emptied; re-seeding below"
fi

# ---------------------------------------------------------------------------
say "4. Owner account and organization"
# ---------------------------------------------------------------------------
# Playwright, because registration is the one thing the CLI cannot do: creating
# an account derives a master key in the client. Everything else below uses the
# far faster and far more stable CLI. See docs/scim/demo.md.
EXISTING="$(sql "SELECT count(*) FROM users WHERE email='$DEMO_OWNER_MAIL';")"
if [ "${EXISTING:-0}" -eq 0 ]; then
    ( cd "$REPO_ROOT/playwright" && [ -d node_modules ] || npm ci >/dev/null 2>&1 )
    ( cd "$REPO_ROOT/playwright" && npx playwright test --config demo.config.ts --reporter=line >/dev/null 2>&1 ) \
        || die "registration failed; run it directly to see why:
       cd playwright && npx playwright test --config demo.config.ts"
    ok "registered $DEMO_OWNER_MAIL and created $DEMO_ORG_NAME"
else
    ok "$DEMO_OWNER_MAIL already exists"
fi

# ---------------------------------------------------------------------------
say "5. Vault items"
# ---------------------------------------------------------------------------
ITEMS="$(sql 'SELECT count(*) FROM ciphers;')"
if [ "${ITEMS:-0}" -lt 6 ]; then
    "$REPO_ROOT/tools/scim-demo-seed-items.sh" >/dev/null || die "seeding vault items failed"
fi
ok "$(sql 'SELECT count(*) FROM ciphers;') items in the vault"

# ---------------------------------------------------------------------------
say "6. SCIM"
# ---------------------------------------------------------------------------
ORG="$(sql "SELECT uuid FROM organizations WHERE name='$DEMO_ORG_NAME' LIMIT 1;")"
[ -n "$ORG" ] || die "no organization named $DEMO_ORG_NAME"

# Minted straight into the database rather than through the Owner-gated
# endpoint. That endpoint needs an interactive session and an emailed one-time
# code, which is the RIGHT flow for an operator (setup.md Part B) and pointless
# friction for a script. Nothing about a token digest requires a client key.
SECRET="demo-$(openssl rand -hex 16)"
HASH="$(printf '%s' "$SECRET" | { command -v sha256sum >/dev/null 2>&1 && sha256sum || shasum -a 256; } | cut -d' ' -f1)"
sql "INSERT INTO scim_api_key (uuid,org_uuid,key_hash,enabled,created_at,revision_date)
     VALUES (gen_random_uuid(),'$ORG','$HASH',TRUE,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
     ON CONFLICT (org_uuid) DO UPDATE SET key_hash=EXCLUDED.key_hash, enabled=TRUE,
                                          revision_date=CURRENT_TIMESTAMP;" >/dev/null
SCIM_TOKEN="scim_v1.$ORG.$SECRET"

MAPS="$(ak_api GET '/propertymappings/provider/scim/?page_size=20')"
UMAP="$(printf '%s' "$MAPS" | python3 -c "import json,sys;[print(r['pk']) or exit() for r in json.load(sys.stdin).get('results',[]) if 'User' in r.get('name','')]")"
GMAP="$(printf '%s' "$MAPS" | python3 -c "import json,sys;[print(r['pk']) or exit() for r in json.load(sys.stdin).get('results',[]) if 'Group' in r.get('name','')]")"
ENG="$(ak_api GET '/core/groups/?name=Engineering' | python3 -c "import json,sys;r=json.load(sys.stdin)['results'];print(r[0]['pk'] if r else '')")"

# host.docker.internal, not localhost: Authentik is in a container and cannot
# resolve localhost to the host. The sandbox certificate covers this name for
# exactly this reason - see the SAN list in tools/scim-sandbox.sh.
SCIM_URL="https://host.docker.internal:8000/scim/v2/$ORG"
BODY="{\"name\":\"Vaultwarden SCIM\",\"url\":\"$SCIM_URL\",\"token\":\"$SCIM_TOKEN\",
       \"exclude_users_service_account\":true,\"filter_group\":\"$ENG\",
       \"property_mappings\":[\"$UMAP\"],\"property_mappings_group\":[\"$GMAP\"]}"

PK="$(ak_api GET '/providers/scim/' | python3 -c "
import json,sys
r=[p for p in json.load(sys.stdin).get('results',[]) if p['name']=='Vaultwarden SCIM']
print(r[0]['pk'] if r else '')")"
if [ -n "$PK" ]; then
    ak_api PATCH "/providers/scim/$PK/" "$BODY" >/dev/null
else
    PK="$(ak_api POST '/providers/scim/' "$BODY" | jq_get pk)"
    [ -n "$PK" ] || die "could not create the SCIM provider"
    ak_api POST '/core/applications/' \
        "{\"name\":\"Vaultwarden SCIM\",\"slug\":\"vaultwarden-scim\",\"provider\":$PK}" >/dev/null
fi
ok "SCIM provider points at $SCIM_URL, scoped to Engineering"

force_sync "$PK"
for _ in $(seq 1 24); do
    N="$(sql 'SELECT count(*) FROM users_organizations;')"
    [ "${N:-0}" -ge 5 ] && break
    sleep 5
done
ok "$(sql 'SELECT count(*) FROM users_organizations;') memberships (1 Owner + 4 provisioned)"

# ---------------------------------------------------------------------------
say "Ready"
# ---------------------------------------------------------------------------
sql "SELECT '  ' || u.email || '  status=' || uo.status FROM users_organizations uo
     JOIN users u ON u.uuid=uo.user_uuid ORDER BY u.email;"
cat <<EOF

  Walkthrough    file://$REPO_ROOT/docs/demo/index.html
                 or: python3 -m http.server $DEMO_PORT --directory docs/demo

  Vaultwarden    $DEMO_DOMAIN          $DEMO_OWNER_MAIL / $DEMO_OWNER_PASSWORD
  Authentik      $AK_URL     akadmin / see AUTHENTIK_BOOTSTRAP_PASSWORD in tools/authentik/.env
  Mail           ${DEMO_MAILPIT_URL}
  PostgreSQL     127.0.0.1:${PG_PORT:-15433}

  Every provisioned member is at status=0 (Invited). That is the design, not a
  fault: only a client can take them further. The walkthrough shows how.
EOF
