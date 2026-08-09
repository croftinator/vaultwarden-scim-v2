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
#   tools/scim-demo.sh --next         # what to do now, computed from state
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
        STUCK="$(sql "SELECT count(*) FROM users_organizations uo JOIN users u ON u.uuid = uo.user_uuid
                      WHERE uo.status = 0 AND u.private_key IS NOT NULL;" 2>/dev/null || echo 0)"
        [ "${STUCK:-0}" -gt 0 ] && warn "$STUCK member(s) stuck: account created but invite not accepted. Run --sync to heal."
        exit 0 ;;
    --sync) ;;
    --next) ;;
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

# ---------------------------------------------------------------------------
# Heal the SSO dead end, rather than merely documenting it.
#
# A SCIM-provisioned member who signs in via SSO BEFORE following their invite
# gets an account but no membership: the SSO screen sends FAKE_SSO_IDENTIFIER
# (src/sso.rs:20), so post_set_password skips accept_org_invite, and the
# auto-accept fallback only runs when mail is disabled. The invite link is then
# refused - "Account already initialized, cannot set password"
# (accounts.rs:443) - because private_key already exists. There is no way
# forward through the UI, which is a poor thing to hand a first-time viewer.
#
# The repair is exactly what Membership::accept_user_invitations does
# (organization.rs:1020): Invited -> Accepted for that user. It is applied only
# to accounts that are genuinely initialised, so it can never promote a member
# who has not yet proved they hold the account.
#
# Announced, never silent: a demo that quietly fixes itself teaches the wrong
# thing about what the software does.
heal_stuck_invites() {
    local stuck
    stuck="$(sql "SELECT count(*) FROM users_organizations uo JOIN users u ON u.uuid = uo.user_uuid
                  WHERE uo.status = 0 AND u.private_key IS NOT NULL;")"
    if [ "${stuck:-0}" -gt 0 ]; then
        sql "UPDATE users_organizations SET status = 1
             WHERE status = 0 AND user_uuid IN (SELECT uuid FROM users WHERE private_key IS NOT NULL);" >/dev/null
        warn "$stuck member(s) had an account but no membership - accepted their invitation."
        warn "  Cause: signed in via SSO before following the invite. See docs/scim/demo.md."
    fi
}

# ---------------------------------------------------------------------------
# --next: derive the next action from actual state.
#
# The walkthrough assumes people follow twelve steps in order. People do not.
# They arrive mid-way, repeat a step, skip one, or come back tomorrow having
# forgotten where they were - and several of the wrong orders used to produce a
# dead end rather than an error message.
#
# So the order is not documented here, it is COMPUTED. Every state the demo can
# be in maps to exactly one next action, and anything recoverable is repaired
# before advising. Run it, do the one thing it says, run it again.
show_next() {
    local owner items members ada_status ada_keys ada_akey strays
    owner="$(sql "SELECT count(*) FROM users WHERE email='$DEMO_OWNER_MAIL';" 2>/dev/null || echo 0)"
    if ! curl -sf -o /dev/null --cacert "$(mkcert -CAROOT)/rootCA.pem" "$DEMO_DOMAIN/alive" 2>/dev/null; then
        say "NEXT: start the demo"; echo "  tools/scim-demo.sh"; return
    fi
    if [ "${owner:-0}" -eq 0 ]; then
        say "NEXT: build the demo"; echo "  tools/scim-demo.sh"; return
    fi

    # Repair before advising. A user should never be told to do something that
    # cannot work because of a state they did not know they were in.
    heal_stuck_invites
    clean_stray_accounts

    items="$(sql 'SELECT count(*) FROM ciphers;')"
    members="$(sql 'SELECT count(*) FROM users_organizations;')"
    ada_status="$(sql "SELECT uo.status FROM users_organizations uo JOIN users u ON u.uuid=uo.user_uuid
                       WHERE u.email='$DEMO_MEMBER_MAIL';" 2>/dev/null)"
    ada_akey="$(sql "SELECT CASE WHEN uo.akey IS NULL OR uo.akey='' THEN 0 ELSE 1 END
                     FROM users_organizations uo JOIN users u ON u.uuid=uo.user_uuid
                     WHERE u.email='$DEMO_MEMBER_MAIL';" 2>/dev/null)"

    if [ "${items:-0}" -lt 6 ]; then
        say "NEXT: seed the vault"; echo "  tools/scim-demo.sh"; return
    fi
    if [ "${members:-0}" -lt 5 ]; then
        say "NEXT: provision the directory"
        echo "  tools/scim-demo.sh --sync"
        echo "  Authentik syncs on its own schedule; this asks it to run now."
        return
    fi

    case "${ada_status:-none}" in
        0)
            say "NEXT: accept ${DEMO_MEMBER_NAME}'s invitation  (this must happen BEFORE SSO)"
            cat <<EOF
  1. Open Mailpit:            $DEMO_MAILPIT_URL
  2. Find "Join $DEMO_ORG_NAME" addressed to $DEMO_MEMBER_MAIL
  3. Click the link, and set her master password to:
                              $DEMO_MEMBER_PASSWORD

  Use a SECOND browser profile - you stay signed in as the Owner in the first.
  Do NOT use "Enterprise single sign-on" yet: that creates her account without
  joining the organization, and the invite link is then refused. If you do it
  anyway, --sync repairs it.
EOF
            ;;
        1)
            say "NEXT: confirm ${DEMO_MEMBER_NAME}  (only a client can do this)"
            cat <<EOF
  As the Owner at $DEMO_DOMAIN:
    Admin Console -> Members -> $DEMO_MEMBER_MAIL -> Confirm

  Watch what happens: your BROWSER fetches her public key, wraps the
  organization key under it, and posts the result. The server stores a blob it
  cannot read. Her akey appears, and status becomes 2.
EOF
            ;;
        2)
            if [ "${ada_akey:-0}" -eq 1 ]; then
                say "NEXT: deprovision ${DEMO_MEMBER_NAME}, and watch the key survive"
                cat <<EOF
  1. Note her akey now:
       SELECT LEFT(akey,24) FROM users_organizations uo
       JOIN users u ON u.uuid=uo.user_uuid WHERE u.email='$DEMO_MEMBER_MAIL';
  2. In Authentik ($AK_URL) deactivate $DEMO_MEMBER_MAIL
  3. tools/scim-demo.sh --sync

  Expect status -126, NOT -1, and the same akey byte for byte. Revocation is an
  offset of 128 applied to the previous state, which is why restore is lossless.

  Optional, once you have seen that: sign her out and back in with Enterprise
  SSO ($DEMO_MEMBER_SSO_PASSWORD at Authentik) to show the steady state.
EOF
            else
                say "NEXT: something is odd - confirmed but no key. Run tools/scim-demo.sh --reset"
            fi
            ;;
        -126)
            say "NEXT: restore ${DEMO_MEMBER_NAME}, and show it was lossless"
            cat <<EOF
  1. In Authentik ($AK_URL) reactivate $DEMO_MEMBER_MAIL
  2. tools/scim-demo.sh --sync

  She returns to status 2, not 0. Nobody re-confirms her, because her wrapped
  key was never destroyed - restored, not re-onboarded. That is the whole
  argument for revoking rather than deleting.
EOF
            ;;
        -128)
            say "NEXT: reactivate ${DEMO_MEMBER_NAME} in Authentik, then --sync"
            echo "  She was revoked while only Invited, hence -128 rather than -126."
            ;;
        none)
            say "NEXT: provision the directory"; echo "  tools/scim-demo.sh --sync" ;;
        *)
            say "NEXT: unrecognised state (status=$ada_status). tools/scim-demo.sh --reset" ;;
    esac
}

# Removes accounts the demo never creates.
#
# Clicking "Enterprise SSO" while an Authentik admin session exists silently
# signs you in as akadmin and mints a Vaultwarden account for it. Harmless, but
# it appears in the member list mid-demo and needs explaining. Only accounts
# with NO organization membership are removed, so nothing that is part of the
# story can be caught by this.
clean_stray_accounts() {
    local strays
    strays="$(sql "SELECT count(*) FROM users u
                   WHERE u.email NOT IN ('$DEMO_OWNER_MAIL','$DEMO_MEMBER_MAIL',
                                         'grace.hopper@example.com','alan.turing@example.com',
                                         'katherine.johnson@example.com')
                     AND NOT EXISTS (SELECT 1 FROM users_organizations uo WHERE uo.user_uuid = u.uuid);")"
    if [ "${strays:-0}" -gt 0 ]; then
        sql "DELETE FROM devices WHERE user_uuid IN (SELECT uuid FROM users u
             WHERE u.email NOT IN ('$DEMO_OWNER_MAIL','$DEMO_MEMBER_MAIL','grace.hopper@example.com',
                                   'alan.turing@example.com','katherine.johnson@example.com')
             AND NOT EXISTS (SELECT 1 FROM users_organizations uo WHERE uo.user_uuid = u.uuid));" >/dev/null
        sql "DELETE FROM users u
             WHERE u.email NOT IN ('$DEMO_OWNER_MAIL','$DEMO_MEMBER_MAIL','grace.hopper@example.com',
                                   'alan.turing@example.com','katherine.johnson@example.com')
             AND NOT EXISTS (SELECT 1 FROM users_organizations uo WHERE uo.user_uuid = u.uuid);" >/dev/null
        warn "removed $strays stray account(s) with no membership (usually an accidental SSO sign-in)"
    fi
}

# Dispatched here, below the function definitions it depends on.
if [ "$MODE" = "--next" ]; then show_next; exit 0; fi

if [ "$MODE" = "--sync" ]; then
    PK="$(ak_api GET '/providers/scim/' | python3 -c "
import json,sys
r=[p for p in json.load(sys.stdin).get('results',[]) if p['name']=='Vaultwarden SCIM']
print(r[0]['pk'] if r else '')")"
    [ -n "$PK" ] || die "no SCIM provider yet - run tools/scim-demo.sh first"
    force_sync "$PK"
    sleep 8
    heal_stuck_invites
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

# Give the demo member a password so SSO can actually be DEMONSTRATED as her.
#
# The directory users are otherwise passwordless, which is right for the ones
# that only ever get provisioned and deprovisioned. But the walkthrough signs in
# as Ada over SSO, and that needs a real Authentik credential. The Owner
# deliberately does NOT get one: they exist only in Vaultwarden, which is why
# asking them to sign in via SSO cannot work - Authentik has never heard of them.
ADA_PK="$(ak_api GET "/core/users/?username=ada.lovelace" \
    | python3 -c "import json,sys;r=json.load(sys.stdin)['results'];print(r[0]['pk'] if r else '')")"
if [ -n "$ADA_PK" ]; then
    ak_api POST "/core/users/$ADA_PK/set_password/" \
        "{\"password\":\"$DEMO_MEMBER_SSO_PASSWORD\"}" >/dev/null
    ok "SSO password set for ada.lovelace"
fi

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
heal_stuck_invites
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
