# Setup: server, token, and your identity provider

> [!NOTE]
> **Parts A and B apply to every provider.** Part C is a Microsoft Entra ID
> walkthrough, because that is the engine this was built against first. The
> endpoints are standard SCIM 2.0 and nothing in them is Entra-specific - for
> Okta, AWS IAM Identity Center, Google Workspace or Authentik, do Parts A and
> B here and then follow the per-provider notes in
> [providers.md](providers.md).

Everything needed to get provisioning working end to end. Follow it in order -
each part depends on the one before.

When you finish, continue to **[operations.md](operations.md)** for the day-two
runbook and troubleshooting.

Follow these parts in order. Parts A-B are done once on the Vaultwarden server;
Parts C-E are done in the Entra admin center and the web vault.

## Prerequisites

Before you start, make sure you have all of these. Missing any one of them is
the usual reason the setup stalls partway.

- [ ] **A running Vaultwarden server from this fork**, reachable over **HTTPS**.
  Entra refuses to connect to a plain-`http` endpoint, so a TLS-terminating
  reverse proxy (or a real cert) is mandatory, not optional.
- [ ] **SMTP configured and working** (`SMTP_HOST`, `SMTP_FROM`, etc.). Invites
  and the admin one-time code below are both email-delivered; without mail the
  practical path in Part B does not work and provisioned users never get an
  invite. Confirm mail works before continuing.
- [ ] **An existing organization** with at least one **Owner** account you can
  log into. SCIM provisions *into* an org; it does not create one. Owner, not
  Admin: minting the token is deliberately gated on `OwnerHeaders`, because the
  credential it produces can revoke an Owner and an Admin session is not allowed
  to do that interactively. An Admin session can read `GET .../scim/status` and
  nothing else.
- [ ] **An Entra tenant** where you can create an enterprise application
  (Application Administrator role or higher). Use a **throwaway test tenant and
  a test org first** - never wire a new SCIM connector straight into production.
- [ ] The reverse proxy in front of Vaultwarden **sets the real client IP** in
  the `IP_HEADER` header (default `X-Real-IP`), **and** the proxy's own address
  is covered by `IP_HEADER_TRUSTED_PROXIES` (default `local`, which covers a
  proxy on the same host or container network). The header is ignored unless
  both hold. The SCIM rate limiter keys on the resulting value; if every request
  appears to come from the proxy's IP, Entra's sync bursts will trip the
  limiter.

## Part A - Enable SCIM on the server

1. Add these to your server config (`.env` or `config.json`). SCIM is **off by
   default**:

   ```ini
   SCIM_ENABLED=true
   # strongly recommended: without it, SCIM changes leave no audit trail
   ORG_EVENTS_ENABLED=true
   # groups are optional; only needed if you sync Entra groups (Part C step 8)
   ORG_GROUPS_ENABLED=true
   # optional rate-limit tuning (defaults shown)
   SCIM_RATELIMIT_SECONDS=1
   SCIM_RATELIMIT_MAX_BURST=60
   ```

2. Restart Vaultwarden. On startup it prints a warning if `SCIM_ENABLED` is set
   while `ORG_EVENTS_ENABLED` is not - heed it, or SCIM changes will be
   invisible in the org event log.

## Part B - Generate the organization's SCIM token

Each organization has its own SCIM token. Generating it needs an authenticated
**Owner** session - an Admin session is refused - so there are three small
steps: find the org id, get an Owner session token, then mint the SCIM token. The commands below use the
emailed **one-time code (OTP)** rather than a master-password hash, because the
hash Vaultwarden expects is computed by the client during login and cannot be
typed by hand.

Set your server URL once:

```bash
DOMAIN="https://vault.example.com"   # your Vaultwarden base URL, no trailing slash
```

### B1. Find the organization id

Log into the **web vault** as the Owner/Admin, open the organization, and look
at the browser address bar. The URL contains the org's UUID, e.g.:

```
https://vault.example.com/#/organizations/3f2504e0-4f89-11d3-9a0c-0305e82c3301/members
                                            └──────────── this is the ORG_ID ────────────┘
```

```bash
ORG_ID="3f2504e0-4f89-11d3-9a0c-0305e82c3301"
```

### B2. Get an admin session (Bearer) token

The SCIM management endpoints authenticate with the same bearer token the web
vault uses for its own API calls. The reliable way to obtain it:

1. In the web vault (still logged in as Owner/Admin), open your browser's
   **Developer Tools > Network** tab.
2. Click around the organization (e.g. open **Members**) so the vault makes an
   API request.
3. Click any request to `/api/...`, find the **`Authorization: Bearer ...`**
   request header, and copy the token after `Bearer `.

```bash
ADMIN_TOKEN="<paste-the-value-after-Bearer-here>"
```

These session tokens are short-lived (about an hour). If a later step returns
`401`, repeat B2 to grab a fresh one.

### B3. Request the one-time code

This emails a protected-action code to the logged-in admin's address:

```bash
curl -s -X POST "$DOMAIN/api/accounts/request-otp" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

Check that admin's inbox for the code (a short string, e.g. `A1B2C3D4`).

```bash
OTP="A1B2C3D4"
```

### B4. Mint the SCIM token

```bash
curl -s -X POST "$DOMAIN/api/organizations/$ORG_ID/scim/api-key" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"otp\": \"$OTP\"}"
```

The response looks like:

```json
{
  "object": "scim-api-key",
  "token": "scim_v1.<org_id>.<secret-shown-once>",
  "scimBaseUrl": "https://vault.example.com/scim/v2/<org_id>",
  "revisionDate": "2026-07-19T10:00:00.000Z"
}
```

- **`token`** is the Secret Token you paste into Entra (Part C). **It is shown
  exactly once** - only its SHA-256 digest is stored server-side. If you lose
  it, mint a new one (which invalidates the old).
- **`scimBaseUrl`** is the Tenant URL you paste into Entra.

Prefer the master-password hash instead of the OTP? Send
`{"masterPasswordHash": "<client-computed-hash>"}` instead of `{"otp": ...}`.
This is only practical if you are scripting a full Bitwarden login to obtain
that hash; for a manual setup, use the OTP.

### Managing the token later

Same base path, `/api/organizations/$ORG_ID/scim/api-key`, with the same
`ADMIN_TOKEN` + OTP auth:

- **Rotate**: `POST` again. The previous token stops working immediately.
- **Disable SCIM for the org**: `DELETE`. Removes the key row; the endpoints
  return `401` until you mint a new one.
- **Inspect** (no OTP needed): `GET $DOMAIN/api/organizations/$ORG_ID/scim/status`
  returns whether a key is configured and enabled, its dates, and
  `confirmedOwners` / `directoryLinkedOwners`. When those two are equal the
  response also carries a `breakGlassWarning`: every Owner came from the
  directory, so a compromise of the IdP would leave the organization with no
  recovery path.

**Rotate the token if it might have leaked.** Because restore is lossless, a
leaked token can reinstate any ordinary member the org previously confirmed (see
"Deprovision from the IdP" below), not just invite and deprovision.
Administrators are excluded from that: SCIM cannot reinstate an Owner, Admin, or
Manager. It can still deprovision one, so a leaked token can revoke members in
bulk - recoverable, since the last active Owner cannot be revoked and can
restore the rest from the web vault.

> [!WARNING]
> **No identity provider has been validated against a live tenant yet. Do not
> roll this out to production without testing it yourself first.**
>
> Entra ID, Okta, AWS IAM Identity Center and Google Workspace are covered by
> tests written from each vendor's *published documentation*, not from observed
> traffic. Authentik is the one exception, verified end to end, but it is not one
> of the major cloud providers. Run the full lifecycle against a **throwaway**
> tenant and a test organisation before any rollout - never against production.
> [provider-setup.md](provider-setup.md) has the steps for each provider.
> See [providers.md](providers.md) for what is verified per provider, and
> [testing.md](testing.md) for the free rungs that get you most of the way.

## Part C - Configure the Entra enterprise application

In the Entra admin center (`entra.microsoft.com`):

1. **Enterprise applications > New application > Create your own application**.
   Name it (e.g. "Vaultwarden SCIM"), choose **Integrate any other application
   you don't find in the gallery (Non-gallery)**, and create it.
2. Open the new app > **Provisioning** > **Get started** (or **Provisioning**
   in the left menu) > set **Provisioning Mode** to **Automatic**.
3. Under **Admin Credentials**:
   - **Tenant URL**: the `scimBaseUrl` from B4
     (`https://<your-domain>/scim/v2/<org_id>`).
   - **Secret Token**: the `token` from B4 (the `scim_v1...` value).
4. Click **Test Connection**. It should succeed. (Under the hood Entra sends a
   `userName eq` filter and expects an empty `200` list - a green result means
   auth and TLS are working.) **Save**.
5. Expand **Mappings** > **Provision Microsoft Entra ID Users**. Set the
   attribute mappings to match the table below, and **delete the default
   mappings this server does not use** (`roles`, `preferredLanguage`, `title`,
   addresses, phone numbers) to keep the sync log clean - they are accepted and
   ignored either way.

   | Entra attribute | SCIM attribute | Becomes in Vaultwarden |
   |---|---|---|
   | `userPrincipalName` **or** `mail` | `userName` | account email (lowercased) |
   | `objectId` | `externalId` | membership external id (correlation key) |
   | `Switch([IsSoftDeleted], , "False", "True", "True", "False")` | `active` | revoke / restore |
   | `displayName` | `displayName` | account name (set at creation only) |

   Map `userName` from **`mail`** rather than `userPrincipalName` if your UPNs
   are not routable mailboxes. The value becomes the Vaultwarden login **and**
   receives the invite email, so it must be a deliverable address. A UPN that is
   not a real mailbox will provision an account that can never receive its
   invite.

6. Set **matching precedence 1** on `userName` (and optionally `externalId`) so
   Entra correlates existing members instead of creating duplicates.
7. Leave **Provision Microsoft Entra ID Groups** disabled unless you want the
   Entra groups to exist as **Vaultwarden groups**. If you do (and
   `ORG_GROUPS_ENABLED=true` on the server), enable it and map `displayName` and
   `objectId` -> `externalId`. This switch only controls whether *group objects*
   are created - which users get provisioned is decided by assignment; see
   [Part D](#part-d---choose-which-users-and-groups-sync).
8. Under **Settings**, set **Scope** to *Sync only assigned users and groups*,
   and set a notification email for sync failures. **Save**.
   This setting is what makes your assignment list act as an allowlist - the
   other option syncs your whole directory. Part D covers how to choose what to
   assign.

## Part D - Choose which users and groups sync

**This is the allowlist.** Read this part before assigning anything.

### The one rule

> **Only what you assign to the enterprise app is synced, and only its direct
> members.**
> Assigning a group makes it a Vaultwarden group and provisions its members.
> Every Entra group you do **not** assign is invisible to Vaultwarden - even the
> other groups that a provisioned user happens to belong to.

### Keep organization administrators out of scope

**Administrators belong in Entra like anyone else. They do not belong in this
app's assignment.** Their Vaultwarden Owner/Admin membership is created by a
human in the web vault, and there is nothing for SCIM to do with it: a person
has exactly one membership per organization, with one role, and roles never
sync. Leaving them unassigned means Entra simply never sends a request about
them.

The server enforces the half of this that matters even if the scoping slips:
SCIM can never create an administrator, promote to one, reinstate a revoked one,
or link one to a directory object. It *can* still deprovision one, deliberately -
see "SCIM never grants administrative privilege" below for why that asymmetry is
the safe one.

**Not assigning them individually is not enough.** Per the rule above, assigning
a *group* provisions its members. An admin sitting inside any assigned group is
pulled in regardless of their individual assignment.

**Use a scoping filter, not just assignment.** Under **Provisioning > Settings >
Scoping filters**, add a clause that excludes your admins by attribute - for
example `department NOT EQUALS "Vault Admins"`, or a dedicated
`extensionAttribute`. A filter is declarative, so it keeps holding when an admin
later joins an assigned group; an assignment list does not. The attribute you
filter on must be part of the app's mapped attributes.

> **Set the exclusion filter BEFORE the first sync cycle.**
>
> Entra does not treat "fell out of scope" as "stop managing" - it treats it as
> **deprovision**. A user who was in scope and then gets filtered out is
> disabled on the next cycle, exactly as if you had unassigned them.
>
> So if an admin was already provisioned by SCIM and later promoted to Owner in
> the web vault, adding the filter afterwards will *revoke* them. It is
> recoverable - restore is lossless, so reinstate them in the web vault with no
> re-invite and no re-confirmation - but it is avoidable by setting the filter
> first. Try this on a throwaway tenant before production.

To check your scoping actually holds: **Provisioning > Provisioning logs**,
filter by status *Failure*. An admin who slipped into scope shows up there,
because SCIM refuses to write their `externalId` and returns `400 mutability`.
That error is the signal; do not suppress it, fix the filter.

You can also ask the server. `GET /api/organizations/$ORG_ID/scim/status`
reports `confirmedOwners` and `directoryLinkedOwners`. If those two are equal,
every Owner was provisioned from the directory and you have no break-glass
account - see below. (The converse is not proof: an admin excluded by a scoping
filter is never provisioned, so they carry no `externalId` either and the server
cannot tell them apart from a Vaultwarden-only account.)

**Also keep one break-glass Owner that does not exist in Entra at all.** Scoping
protects you from a mistake in this app. It does nothing if the Entra tenant
itself is compromised, and an organization whose every administrator is an Entra
identity has no recovery path from that.

Two consequences worth stating plainly:

- **Assign as many groups as you like.** There is no limit imposed here - assign
  one group or fifty. Each assigned group becomes a Vaultwarden group (when group
  provisioning is on) and contributes its members. The assignment list is simply
  the set of groups you want synced.
- **Nesting is not followed.** Entra itself allows nested groups, but the
  provisioning service does **not** traverse them: only the *direct* members of
  an assigned group are provisioned. A sub-group inside an assigned group
  contributes nothing - neither its users nor itself. You do not need to
  restructure your directory; just **assign every group you want synced,
  individually**, including the nested ones.

There is no group allowlist in Vaultwarden itself. The server accepts whatever
the organization's SCIM token sends it, so **Entra's assignment list is the
control**. Keep `Scope` set to *Sync only assigned users and groups* (Part C
step 8); the alternative syncs your entire directory.

### Two independent switches

Decide these separately - they are often confused:

| You want | Do this |
|---|---|
| Provision **users** into the org, no Vaultwarden groups | Assign the groups (or users). Leave **Provision Microsoft Entra ID Groups** disabled. Members get provisioned; no groups are created. |
| Also create the groups **as Vaultwarden groups**, with membership | Additionally set `ORG_GROUPS_ENABLED=true` on the server and enable the **Provision Microsoft Entra ID Groups** mapping (Part C step 7). |

Assigning a group always provisions its member *users*. Whether that group also
becomes a *group object* inside Vaultwarden depends on the second switch.

### Steps

1. In Entra, decide (or create) the groups that should exist in Vaultwarden -
   for example `VW-Engineering`, `VW-Finance`, `VW-Support`. A naming prefix
   makes the in-scope set obvious to whoever audits it later.
2. Enterprise app > **Users and groups** > **Add user/group**. Assign **exactly
   those groups** and nothing else. Assign as many as you need - the picker takes
   multiple groups. This list is your allowlist: add a group here to bring it
   into Vaultwarden, remove it to take it out of scope.
   - If any group you want is **nested inside** another assigned group, assign it
     here **in its own right** as well. Provisioning does not look inside nested
     groups, so an unassigned sub-group syncs nothing.
3. **Provisioning > Start provisioning** (initial cycle), or **Provision on
   demand** to push a single user immediately while testing.
4. Watch **Provisioning logs**. The first cycle *lists* existing users
   (`userName eq` filters return empty for a fresh org), then *creates* them.

### What happens on an ongoing basis

- **User added to an assigned group** -> provisioned on the next cycle: account
  created if new, invite emailed, org membership at *Invited*, and added to the
  corresponding Vaultwarden group if group sync is on.
- **User removed from the group** (and not in any other assigned group) -> falls
  out of scope, so Entra sends `active: false` and the membership is **revoked**
  immediately. Their group membership is removed too.
- **User re-added** -> restored losslessly, back to exactly the state they were
  revoked from (see the deprovision note below).
- **Group unassigned from the app** -> its members fall out of scope and are
  revoked. Deleting the group in Entra deletes the Vaultwarden group.

### Traps to know before you design your groups

- **Nested groups are not followed.** Entra lets you nest groups, but its
  provisioning service does not traverse them - only the *direct* members of an
  assigned group are provisioned. Assign `VW-All-Staff` and it contains
  `VW-Engineering`, and you get neither the engineers nor an Engineering group in
  Vaultwarden. This is an Entra limitation, not something this server can work
  around. Fix it by assigning each group you want individually (nesting in the
  directory is fine, it is just ignored by the sync), or by flattening the groups
  you assign.
- **Assign users before (or together with) their groups.** A group member whose
  org membership does not exist yet is rejected with a `400`. Entra provisions
  users before groups, so assigning both at once is fine.
- **Confirm is still manual.** Group membership gets people to *Invited* /
  *Accepted*. An admin must still confirm them in the web vault before they have
  vault access (Part E) - end-to-end encryption makes this unavoidable.
- **Group membership is the source of truth for access.** Because restore is
  lossless, re-adding someone to an assigned group reinstates them, including
  back to *Confirmed* with no re-confirmation. Offboard people in Entra, not by
  revoking in the web vault.
- **Scoping filters** narrow the assigned set by attribute:
  **Provisioning > Settings > Scoping filters**, for example
  `department eq "Finance"`. Use one to exclude administrators - see "Keep
  organization administrators out of scope" in Part D, including the warning
  that a user who falls out of scope is *deprovisioned*, not merely ignored.

## Part E - Verify and confirm members

1. **In the web vault**, open the organization > **Members**. Newly provisioned
   people appear as **Invited** (or **Accepted** if they already had an
   account). If `ORG_EVENTS_ENABLED=true`, the **Event logs** tab shows the SCIM
   actions under the actor `vaultwarden-scim-...`.
2. Each provisioned user receives an **invite email**. They click it, create or
   log into their Vaultwarden account, and land in **Accepted**.
3. **Confirm each member** (the one manual step - see "Not automated" above). In
   **Members**, a member awaiting confirmation shows a *Needs confirmation*
   badge; open the member and choose **Confirm**. Your browser (the admin's
   client) wraps the org key for that member. Only after confirmation does the
   member have vault access.
4. **Test deprovision**: in Entra, unassign a test user (or disable them). On
   the next cycle their membership is revoked and vault access stops. Re-assign
   to confirm the restore is lossless (no re-invite, no re-confirm needed).
