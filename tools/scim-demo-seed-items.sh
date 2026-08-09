#!/usr/bin/env bash
#
# Fill the demo vault, using the official Bitwarden CLI rather than a browser.
#
# WHY NOT PLAYWRIGHT: vault items need client-side crypto, so they cannot be
# seeded with SQL - but "needs a real client" does not mean "needs a browser".
# `bw` IS a real client and performs the same encryption. Measured on the same
# machine, same six items:
#
#   web vault via Playwright   minutes, and repeatedly stalled
#   bw CLI                     18 seconds, first try
#
# The browser route also fought the UI at every step: a post-registration
# advert interstitial, a breach-check API call that blocks submission offline,
# a "New item" button that opens a form directly rather than a type menu, and a
# "View Login" modal left open after save that hides the next "New item" behind
# it. Every one of those is a property of one web-vault release. The CLI's
# interface is documented and stable, so this stays working across vault bumps.
#
# Playwright is still required for what the CLI genuinely cannot do -
# registering an account - which is why demo/seed.spec.ts still exists. Use each
# for what it is good at.
#
# Usage:
#   tools/scim-demo-seed-items.sh                 # uses playwright/demo.env
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
set -a; . "$REPO_ROOT/playwright/demo.env"; set +a

# Node does not read the macOS keychain, so a system-trusted mkcert CA is still
# refused by the CLI. This is the documented fix and costs nothing when the CA
# is absent.
if command -v mkcert >/dev/null 2>&1; then
    export NODE_EXTRA_CA_CERTS="$(mkcert -CAROOT)/rootCA.pem"
fi
command -v bw >/dev/null || {
    echo "ERROR: the Bitwarden CLI is required: npm i -g @bitwarden/cli (or brew install bitwarden-cli)" >&2
    exit 2; }

# `bw config server` is REFUSED while a session is logged in ("Logout required
# before server config update"), so only touch it when it actually differs -
# otherwise a second run of this script aborts on a no-op.
CURRENT_SERVER="$(bw status 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("serverUrl") or "")' 2>/dev/null || true)"
if [ "$CURRENT_SERVER" != "$DEMO_DOMAIN" ]; then
    bw logout >/dev/null 2>&1 || true
    bw config server "$DEMO_DOMAIN" >/dev/null
fi

# `bw login` fails if a session already exists, and `bw unlock` fails if one does
# not, so try both rather than guessing which state the machine is in.
SESSION="$(bw unlock "$DEMO_OWNER_PASSWORD" --raw 2>/dev/null || true)"
if [ -z "$SESSION" ]; then
    SESSION="$(bw login "$DEMO_OWNER_MAIL" "$DEMO_OWNER_PASSWORD" --raw 2>/dev/null || true)"
fi
[ -n "$SESSION" ] || {
    echo "ERROR: could not authenticate $DEMO_OWNER_MAIL against $DEMO_DOMAIN." >&2
    echo "       Register the account first: npx playwright test --config demo.config.ts" >&2
    exit 1; }

# The items must belong to the ORGANIZATION, not the Owner's personal vault.
#
# This is the difference between a demo that makes its point and one that does
# not. Provisioning members into an organization that shares nothing means
# confirming Ada grants her access to precisely no credentials, and the payoff
# of the whole walkthrough - "she is now in, and here is what she can see" -
# silently evaporates. Personal items are also invisible to every other member
# by design, so nothing about them can ever be demonstrated.
bw sync --session "$SESSION" >/dev/null
ORG_ID="$(bw list organizations --session "$SESSION" \
    | python3 -c "import json,sys;o=[x for x in json.load(sys.stdin) if x['name']=='$DEMO_ORG_NAME'];print(o[0]['id'] if o else '')")"
[ -n "$ORG_ID" ] || { echo "ERROR: no organization named $DEMO_ORG_NAME - register first" >&2; exit 1; }
COLL_ID="$(bw list collections --organizationid "$ORG_ID" --session "$SESSION" \
    | python3 -c "import json,sys;c=json.load(sys.stdin);print(c[0]['id'] if c else '')")"
[ -n "$COLL_ID" ] || { echo "ERROR: $DEMO_ORG_NAME has no collection to put items in" >&2; exit 1; }

# Fictional throughout. Nothing here resolves to a real service and no value is
# a credential for anything - a demo that shipped a plausible real secret would
# be a liability the first time someone screenshotted it.
add_login() {
    printf '{"type":1,"name":"%s","notes":null,"organizationId":"%s","collectionIds":["%s"],"login":{"username":"%s","password":"%s"}}' \
        "$1" "$ORG_ID" "$COLL_ID" "$2" "$3" \
        | base64 \
        | bw create item --session "$SESSION" >/dev/null
    printf '  + %s\n' "$1"
}

printf '\033[1mSeeding the demo vault\033[0m\n'
add_login "Example AWS root"        "root@example.com" "Aa1!demo-not-real-0001"
add_login "Example GitHub org"      "example-bot"          "Aa1!demo-not-real-0002"
add_login "Example Grafana"         "admin"             "Aa1!demo-not-real-0003"
add_login "Example Jira"            "svc-jira"          "Aa1!demo-not-real-0004"
add_login "Example Postgres (prod)" "example_app"          "Aa1!demo-not-real-0005"
add_login "Example SMTP relay"      "mailer"            "Aa1!demo-not-real-0006"

# Read back through a fresh sync rather than trusting the writes: an item that
# encrypts on the way out but does not decrypt on the way in is exactly the
# failure a demo must not discover on stage.
bw sync --session "$SESSION" >/dev/null
COUNT="$(bw list items --session "$SESSION" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')"
printf '\033[32m  %s items readable after a resync\033[0m\n' "$COUNT"
