#!/usr/bin/env bash
#
# Replay Microsoft Entra ID's SCIM request shapes against a running Vaultwarden
# instance from this fork.
#
# There is no self-hostable Entra ID, so this script stands in for it: it fires
# the exact payload shapes Entra sends - including the quirks a spec-correct
# SCIM client would never produce ("Replace" op casing, string booleans,
# path-less value objects, members[value eq "..."] removal paths) - and asserts
# the response status and body.
#
# It exercises a REAL server over HTTP, which the in-process integration tests
# (cargo test --features sqlite) deliberately do not: TLS/proxy setup, the
# configured DOMAIN, rate limiting, and the catchers all participate here.
#
# Usage:
#   tools/scim-entra-replay.sh --domain https://vault.example.com \
#                              --org  <org_uuid> \
#                              --token scim_v1.<org_uuid>.<secret>
#
#   Or via environment:
#     DOMAIN=... ORG_ID=... SCIM_TOKEN=... tools/scim-entra-replay.sh
#
# Mint the token first - see docs/scim/README.md Part B.
#
# Requires: bash, curl, jq.
#
# Exit code: 0 if every check passed, 1 otherwise.
#
set -uo pipefail

DOMAIN="${DOMAIN:-}"
ORG_ID="${ORG_ID:-}"
SCIM_TOKEN="${SCIM_TOKEN:-}"
KEEP=0

while [ $# -gt 0 ]; do
    case "$1" in
        --domain) DOMAIN="$2"; shift 2 ;;
        --org)    ORG_ID="$2"; shift 2 ;;
        --token)  SCIM_TOKEN="$2"; shift 2 ;;
        --keep)   KEEP=1; shift ;;          # leave test data behind for inspection
        -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done

for tool in curl jq; do
    command -v "$tool" >/dev/null 2>&1 || { echo "ERROR: '$tool' is required" >&2; exit 2; }
done

if [ -z "$DOMAIN" ] || [ -z "$ORG_ID" ] || [ -z "$SCIM_TOKEN" ]; then
    echo "ERROR: --domain, --org and --token are all required (see --help)" >&2
    exit 2
fi

DOMAIN="${DOMAIN%/}"
BASE="$DOMAIN/scim/v2/$ORG_ID"
CT="application/scim+json"
# Unique per run so repeat runs never collide on the uniqueness checks.
RUN="replay$(date +%s)$$"
USER_EMAIL="${RUN}@example.com"
EXT_ID="entra-${RUN}"

PASS=0
FAIL=0
MEMBER_ID=""
GROUP_ID=""

c_ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS + 1)); }
c_bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL + 1)); }
section(){ printf '\n\033[1m%s\033[0m\n' "$1"; }

# req <METHOD> <URL> [BODY] [AUTH_OVERRIDE]
# Writes the response body to $BODY_FILE and echoes the HTTP status.
BODY_FILE="$(mktemp)"
trap 'rm -f "$BODY_FILE"' EXIT

req() {
    local method="$1" url="$2" body="${3:-}" auth="${4:-Bearer $SCIM_TOKEN}"
    if [ -n "$body" ]; then
        curl -sS -o "$BODY_FILE" -w '%{http_code}' -X "$method" "$url" \
            -H "Authorization: $auth" -H "Content-Type: $CT" --data "$body" 2>/dev/null
    else
        curl -sS -o "$BODY_FILE" -w '%{http_code}' -X "$method" "$url" \
            -H "Authorization: $auth" 2>/dev/null
    fi
}

# expect <description> <actual_status> <expected_status> [jq_filter] [expected_value]
expect() {
    local desc="$1" got="$2" want="$3" filter="${4:-}" want_val="${5:-}"
    if [ "$got" != "$want" ]; then
        c_bad "$desc (expected HTTP $want, got $got)"
        [ -s "$BODY_FILE" ] && sed 's/^/       /' "$BODY_FILE" | head -3
        return 1
    fi
    if [ -n "$filter" ]; then
        local actual
        actual="$(jq -r "$filter" < "$BODY_FILE" 2>/dev/null)"
        if [ "$actual" != "$want_val" ]; then
            c_bad "$desc (expected $filter = '$want_val', got '$actual')"
            return 1
        fi
    fi
    c_ok "$desc"
    return 0
}

echo "Entra SCIM replay against $BASE"
echo "Test identity: $USER_EMAIL / externalId $EXT_ID"

# ---------------------------------------------------------------------------
section "1. Discovery (other SCIM clients read these; Entra tolerates them)"
# ---------------------------------------------------------------------------
status=$(req GET "$BASE/ServiceProviderConfig")
expect "ServiceProviderConfig advertises patch support" "$status" 200 '.patch.supported' 'true'
status=$(req GET "$BASE/ResourceTypes")
expect "ResourceTypes lists /Users" "$status" 200 '.Resources[0].endpoint' '/Users'
status=$(req GET "$BASE/Schemas")
expect "Schemas returns a ListResponse" "$status" 200 \
    '.schemas[0]' 'urn:ietf:params:scim:api:messages:2.0:ListResponse'

# ---------------------------------------------------------------------------
section "2. Auth matrix (every failure must be an identical 401)"
# ---------------------------------------------------------------------------
status=$(req GET "$BASE/ServiceProviderConfig" "" "Bearer garbage")
expect "malformed token rejected" "$status" 401
body_malformed="$(cat "$BODY_FILE")"

status=$(req GET "$BASE/ServiceProviderConfig" "" "Bearer scim_v1.$ORG_ID.wrong-secret")
expect "wrong secret rejected" "$status" 401
body_wrongsecret="$(cat "$BODY_FILE")"

status=$(req GET "$BASE/ServiceProviderConfig" "" "Basic abc")
expect "non-bearer rejected" "$status" 401
body_nonbearer="$(cat "$BODY_FILE")"

if [ "$body_malformed" = "$body_wrongsecret" ] && [ "$body_malformed" = "$body_nonbearer" ]; then
    c_ok "401 bodies are byte-identical (no oracle for which check failed)"
else
    c_bad "401 bodies differ between failure causes - leaks which check failed"
fi

# ---------------------------------------------------------------------------
section "3. Entra 'Test Connection' + initial sync probe"
# ---------------------------------------------------------------------------
# Entra probes with a userName filter for a user that does not exist and
# requires an empty 200 ListResponse, NOT a 404.
filter_q=$(printf 'userName eq "nobody-%s@example.com"' "$RUN" | jq -sRr @uri)
status=$(req GET "$BASE/Users?filter=$filter_q")
expect "unknown-user filter returns empty list, not 404" "$status" 200 '.totalResults' '0'

# ---------------------------------------------------------------------------
section "4. Provision a user (Entra POST shape, unknown attrs included)"
# ---------------------------------------------------------------------------
# Entra sends the enterprise extension and attributes this server ignores.
# RFC 7643 s2.1 requires unknown attributes to be ignored, not rejected.
create_body=$(jq -n --arg u "$USER_EMAIL" --arg e "$EXT_ID" '{
  schemas: [
    "urn:ietf:params:scim:schemas:core:2.0:User",
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
  ],
  userName: $u,
  externalId: $e,
  active: true,
  name: { givenName: "Replay", familyName: "Tester" },
  emails: [ { value: $u, type: "work", primary: true } ],
  title: "Ignored Title",
  preferredLanguage: "en-US",
  "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": { department: "Ignored" }
}')
status=$(req POST "$BASE/Users" "$create_body")
expect "POST /Users creates the member (201)" "$status" 201 '.active' 'true'
MEMBER_ID="$(jq -r '.id // empty' < "$BODY_FILE")"
expect_email="$(printf '%s' "$USER_EMAIL" | tr '[:upper:]' '[:lower:]')"
status=$(req GET "$BASE/Users/$MEMBER_ID")
expect "userName is stored lowercased" "$status" 200 '.userName' "$expect_email"

# Duplicate must be a 409 uniqueness conflict, which is how Entra detects
# an already-provisioned user rather than creating a second one.
status=$(req POST "$BASE/Users" "$create_body")
expect "duplicate POST is 409 uniqueness" "$status" 409 '.scimType' 'uniqueness'

# ---------------------------------------------------------------------------
section "5. Entra PATCH quirks"
# ---------------------------------------------------------------------------
# Quirk 1: capital-R "Replace" and a STRING boolean "False".
deactivate=$(jq -n '{
  schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  Operations: [ { op: "Replace", path: "active", value: "False" } ]
}')
status=$(req PATCH "$BASE/Users/$MEMBER_ID" "$deactivate")
expect 'PATCH op:"Replace" + string "False" deactivates' "$status" 200 '.active' 'false'

# Deprovisioning twice must be idempotent - Entra retries.
status=$(req PATCH "$BASE/Users/$MEMBER_ID" "$deactivate")
expect "repeat deactivate is idempotent" "$status" 200 '.active' 'false'

# Quirk 2: path-less operation carrying a value object.
activate=$(jq -n '{
  schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  Operations: [ { op: "replace", value: { active: true } } ]
}')
status=$(req PATCH "$BASE/Users/$MEMBER_ID" "$activate")
expect "path-less value object reactivates (lossless restore)" "$status" 200 '.active' 'true'

# Quirk 3: directory renames must be accepted and ignored, never error, or
# every rename in Entra would fail the sync.
rename=$(jq -n '{
  schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  Operations: [ { op: "replace", path: "displayName", value: "Renamed In Entra" } ]
}')
status=$(req PATCH "$BASE/Users/$MEMBER_ID" "$rename")
expect "displayName rename accepted as a no-op" "$status" 200 '.active' 'true'

# An unsupported path must be a clean 400 invalidPath, not a 500.
badpatch=$(jq -n '{
  schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  Operations: [ { op: "replace", path: "wibble", value: "x" } ]
}')
status=$(req PATCH "$BASE/Users/$MEMBER_ID" "$badpatch")
expect "unsupported patch path is 400 invalidPath" "$status" 400 '.scimType' 'invalidPath'

# ---------------------------------------------------------------------------
section "6. Filters and pagination"
# ---------------------------------------------------------------------------
# Entra sends the filter value in the directory's casing; the stored email is
# lowercased, so a case-insensitive match is required or Entra loops on 409.
upper_email="$(printf '%s' "$USER_EMAIL" | tr '[:lower:]' '[:upper:]')"
filter_q=$(printf 'userName eq "%s"' "$upper_email" | jq -sRr @uri)
status=$(req GET "$BASE/Users?filter=$filter_q")
expect "mixed-case userName filter still matches" "$status" 200 '.totalResults' '1'

filter_q=$(printf 'externalId eq "%s"' "$EXT_ID" | jq -sRr @uri)
status=$(req GET "$BASE/Users?filter=$filter_q")
expect "externalId filter matches" "$status" 200 '.totalResults' '1'

status=$(req GET "$BASE/Users?count=0")
expect "count=0 returns totals with no resources" "$status" 200 '.itemsPerPage' '0'

status=$(req GET "$BASE/Users?startIndex=99999")
expect "startIndex past the end is an empty page, not an error" "$status" 200 '.itemsPerPage' '0'

filter_q=$(printf 'userName co "partial"' | jq -sRr @uri)
status=$(req GET "$BASE/Users?filter=$filter_q")
expect "unsupported filter operator is 400 invalidFilter" "$status" 400 '.scimType' 'invalidFilter'

# ---------------------------------------------------------------------------
section "7. Groups (skipped automatically if ORG_GROUPS_ENABLED=false)"
# ---------------------------------------------------------------------------
group_body=$(jq -n --arg n "Replay Group $RUN" --arg e "grp-$EXT_ID" --arg m "$MEMBER_ID" '{
  schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
  displayName: $n,
  externalId: $e,
  members: [ { value: $m } ]
}')
status=$(req POST "$BASE/Groups" "$group_body")
if [ "$status" = "501" ]; then
    printf '  \033[33mSKIP\033[0m Groups disabled on this server (501) - set ORG_GROUPS_ENABLED=true to cover them\n'
else
    expect "POST /Groups creates the group with its member" "$status" 201 '.members | length' '1'
    GROUP_ID="$(jq -r '.id // empty' < "$BODY_FILE")"

    # Entra removes a single member with a filter path, not a value list.
    remove_member=$(jq -n --arg m "$MEMBER_ID" '{
      schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
      Operations: [ { op: "Remove", path: ("members[value eq \"" + $m + "\"]") } ]
    }')
    status=$(req PATCH "$BASE/Groups/$GROUP_ID" "$remove_member")
    expect 'Entra members[value eq "..."] removal form works' "$status" 200 '.members | length' '0'

    # And adds with a value list.
    add_member=$(jq -n --arg m "$MEMBER_ID" '{
      schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
      Operations: [ { op: "Add", path: "members", value: [ { value: $m } ] } ]
    }')
    status=$(req PATCH "$BASE/Groups/$GROUP_ID" "$add_member")
    expect "member add via value list works" "$status" 200 '.members | length' '1'

    # Adding twice must not duplicate the link.
    status=$(req PATCH "$BASE/Groups/$GROUP_ID" "$add_member")
    expect "duplicate add is idempotent" "$status" 200 '.members | length' '1'

    status=$(req GET "$BASE/Groups?excludedAttributes=members")
    expect "excludedAttributes=members omits member arrays" "$status" 200 \
        '.Resources[0] | has("members")' 'false'

    # A member id from outside this org must be refused, not silently linked.
    bad_member=$(jq -n '{
      schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
      Operations: [ { op: "Add", path: "members",
                      value: [ { value: "00000000-dead-beef-0000-000000000000" } ] } ]
    }')
    status=$(req PATCH "$BASE/Groups/$GROUP_ID" "$bad_member")
    expect "unknown member id refused with 400 invalidValue" "$status" 400 '.scimType' 'invalidValue'
fi

# ---------------------------------------------------------------------------
section "8. Deprovision (DELETE = revoke, row survives)"
# ---------------------------------------------------------------------------
status=$(req DELETE "$BASE/Users/$MEMBER_ID")
expect "DELETE returns 204" "$status" 204

status=$(req GET "$BASE/Users/$MEMBER_ID")
expect "membership survives DELETE, now inactive" "$status" 200 '.active' 'false'

status=$(req DELETE "$BASE/Users/$MEMBER_ID")
expect "repeat DELETE is idempotent" "$status" 204

# Restore proves the round trip is lossless.
status=$(req PATCH "$BASE/Users/$MEMBER_ID" "$activate")
expect "restore after DELETE works (lossless)" "$status" 200 '.active' 'true'

# ---------------------------------------------------------------------------
section "9. Enumeration safety"
# ---------------------------------------------------------------------------
status=$(req GET "$BASE/Users/00000000-dead-beef-0000-000000000000")
expect "unknown member id is 404" "$status" 404
body_unknown="$(cat "$BODY_FILE")"
# A malformed id fails Rocket's param guard before any handler. It must still
# come back as a SCIM envelope - a default HTML error page would be unparseable
# for a SCIM client. (This check caught exactly that bug.)
status=$(req GET "$BASE/Users/not-a-uuid-at-all")
expect "malformed id is a SCIM-enveloped 400, not an HTML page" "$status" 400 '.scimType' 'invalidValue'
if grep -qi "<!DOCTYPE\|<html" "$BODY_FILE"; then
    c_bad "malformed id returned an HTML body"
else
    c_ok "malformed id body contains no HTML"
fi

# ---------------------------------------------------------------------------
if [ "$KEEP" -eq 0 ]; then
    section "Cleanup"
    # Revoke rather than delete: this server never exposes a destructive path.
    req DELETE "$BASE/Users/$MEMBER_ID" >/dev/null
    [ -n "$GROUP_ID" ] && req DELETE "$BASE/Groups/$GROUP_ID" >/dev/null
    echo "  test member revoked${GROUP_ID:+, test group deleted}"
    echo "  note: the shell account $USER_EMAIL remains (SCIM never deletes accounts)"
else
    section "Cleanup skipped (--keep)"
    echo "  member: $MEMBER_ID${GROUP_ID:+  group: $GROUP_ID}"
fi

printf '\n\033[1mResult: %d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
