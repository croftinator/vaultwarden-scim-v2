# SCIM v2 provisioning

This fork adds a SCIM v2 provisioning server (RFC 7643 / RFC 7644) so
organization membership can be driven from an identity provider. Microsoft
Entra ID is the tested IdP. Design details and diagrams: [design.md](design.md).

## What it does, honestly

- **Automated invite**: assigning a user in the IdP creates the Vaultwarden
  account (if needed) and org membership, and sends the invite email.
- **Automated deprovision**: removing a user (or setting `active: false`)
  revokes org access immediately. Restore is lossless.
- **Group sync**: group existence and membership, when `ORG_GROUPS_ENABLED=true`.
- **Not automated**: the final *Confirm* step. End-to-end encryption means the
  org key must be wrapped for each member by an admin's client; no server can
  do it. Provisioned users wait in *Invited* / *Accepted* until an admin
  confirms them in the web vault. See design.md for why this is a property of
  the encryption model, not a missing feature.

---

# Step-by-step setup

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
- [ ] **An existing organization** with at least one **Owner or Admin** account
  you can log into. SCIM provisions *into* an org; it does not create one.
- [ ] **An Entra tenant** where you can create an enterprise application
  (Application Administrator role or higher). Use a **throwaway test tenant and
  a test org first** - never wire a new SCIM connector straight into production.
- [ ] The reverse proxy in front of Vaultwarden **sets the real client IP** in
  the `IP_HEADER` header (default `X-Real-IP`). The SCIM rate limiter keys on
  that value; if every request appears to come from the proxy's IP, Entra's
  sync bursts will trip the limiter.

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
Owner/Admin session, so there are three small steps: find the org id, get an
admin session token, then mint the SCIM token. The commands below use the
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
  returns whether a key is configured and enabled, and its dates.

**Rotate the token if it might have leaked.** Because restore is lossless, a
leaked token can reinstate any member the org previously confirmed (see
"Deprovision from the IdP" below), not just invite and deprovision.

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
- **Scoping filters** are an optional extra lever if assignment alone is too
  coarse: **Provisioning > Settings > Scoping filters** can narrow by attribute
  (for example `department eq "Finance"`) on top of the assigned set.

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

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Entra **Test Connection fails** | Endpoint not reachable over HTTPS, wrong Tenant URL, or wrong/expired Secret Token | Confirm the URL is `https://<domain>/scim/v2/<org_id>` exactly; re-mint the token (B4); check `GET .../scim/status` shows `keyEnabled: true` |
| All requests return **401** | `SCIM_ENABLED` not set, no key configured for the org, token/org mismatch, or a rotated/deleted token | Verify Part A config and restart; check `/scim/status`; the token's embedded org must match the Tenant URL's org id |
| **429** in provisioning logs | Rate limiter tripped, usually because the proxy hides the real client IP | Ensure the proxy sets `IP_HEADER` (`X-Real-IP`); raise `SCIM_RATELIMIT_MAX_BURST` for large initial syncs |
| Users provision but **never get an invite** | SMTP not working, or `userName` mapped to a non-mailbox UPN | Fix SMTP; map `userName` from `mail` |
| Entra reports a user **quarantined / skipped** | `userName` value is not a valid email, or a case/format mismatch on the correlation key | Map to a real lowercased email; matching is case-insensitive on the email but `externalId` must be stable |
| Group sync does nothing / returns **501** | `ORG_GROUPS_ENABLED` is false on the server | Set `ORG_GROUPS_ENABLED=true` and restart, or leave Entra group provisioning disabled |
| A **revoked user reappears** with access | Restore is IdP-authoritative (see below) | Deprovision from Entra, not only in the vault |

---

# Rolling out the server to users (Bitwarden client apps)

SCIM creates the accounts and sends the invites, but it does **not** change
which server a user's app talks to. Every Bitwarden client ships pointed at the
public `bitwarden.com` cloud. Before a user can accept their invite or log in,
their app must be pointed at **your** Vaultwarden server URL. This is a one-time
setting per app, per device.

Give users a single fact and one instruction:

> **Server URL:** `https://vault.example.com`
> Set this as the *self-hosted environment* / *server URL* in your Bitwarden app
> **before** logging in, then log in with your work email and accept the org
> invite.

The web vault is the exception - it *is* your server, so it needs no
configuration. Cover it first for users who just need access now, then roll the
standalone apps out to the rest.

## Per-app configuration (manual)

The web vault needs nothing. For every other client the pattern is the same:
open the environment/server setting on the **login or create-account screen**
(not after logging in), enter your server URL, save, then log in.

- **Web vault (any browser)** - Users simply visit `https://vault.example.com`
  and log in. Nothing to configure; this is served by Vaultwarden itself
  (requires `WEB_VAULT_ENABLED=true`, the default).

- **Browser extension (Chrome, Edge, Firefox, Safari, Opera, Brave)** - On the
  extension's login screen, open the **region / settings** control (a cog or a
  region dropdown near the top), choose **Self-hosted**, enter the **Server URL**
  (`https://vault.example.com`), **Save**, then log in. Leave the other
  per-service URL fields blank - a single base URL is enough for Vaultwarden.

- **Desktop app (Windows, macOS, Linux)** - On the login screen, open the
  **region / settings** control, choose **Self-hosted environment**, set the
  **Server URL**, **Save**, then log in. Same as the extension.

- **Mobile - iOS / iPadOS (App Store)** - On the login screen, tap the **region**
  selector (top of the screen, defaults to *US*/*EU*), choose **Self-hosted**,
  enter the **Server URL**, save, then log in.

- **Mobile - Android (Google Play or F-Droid)** - Same as iOS: tap the **region**
  selector on the login screen, choose **Self-hosted**, enter the **Server URL**,
  save, then log in.

- **CLI (`bw`)** - Point it once, then log in:

  ```bash
  bw config server https://vault.example.com
  bw login you@example.com
  ```

  Scripts and CI can also set `BW_CLIENTURL` / the equivalent env var instead of
  `bw config`.

**Notes that avoid support tickets:**
- Keep clients **reasonably up to date**. Older client versions may not speak to
  a current Vaultwarden; if login fails on an ancient build, update first.
- The server URL is set **once per install per device**. A user with the
  extension, the desktop app, and mobile configures all three separately.
- If a user logged into the public cloud by mistake, they must **log out**,
  change the environment to self-hosted, and log back in - the server can't be
  switched while logged in.

## Mass / zero-touch rollout (managed devices)

For more than a handful of users, don't ask everyone to type a URL. Push the
server URL through the same management channel you already use for the app:

- **Managed mobile (iOS/Android MDM)** - Bitwarden's mobile apps read a
  **managed app configuration (AppConfig)** value for the self-hosted base URL.
  Deploy the app through your MDM (Intune, Jamf, Workspace ONE, Android
  Enterprise) and set that AppConfig key so the app opens pre-pointed at your
  server.
- **Managed browser extension** - The extension reads a **managed storage /
  enterprise policy** value for the self-hosted environment. Push it via Chrome
  Enterprise policy, Edge policy, or Firefox `policies.json` targeting the
  extension, so managed browsers are pre-configured.
- **Managed desktop** - Distribute the desktop app via your usual packaging
  (Intune, Jamf, MSI/winget, Homebrew) and pair it with the browser/OS policy
  above, or provide a short first-run instruction.
- **CLI at scale** - Bake `bw config server https://vault.example.com` into your
  provisioning scripts or a shared shell profile.

The exact AppConfig and browser-policy **key names change between Bitwarden
releases**, so configure them from Bitwarden's current official documentation
rather than copying values from a blog post - search Bitwarden's help center for
"self-hosting" + "configure self-hosted environment" and your platform's
deployment guide. Validate on one managed device before the fleet.

## Suggested rollout order

1. **Pilot** - a few admins/testers on the web vault and one extension; confirm
   invite -> accept -> confirm -> unlock works end to end.
2. **Web vault first** - give everyone `https://vault.example.com` so they have
   access immediately with zero client setup, and can accept their SCIM invite.
3. **Standalone apps** - roll out extension, desktop, and mobile, ideally via the
   managed configuration above so users never type the URL.
4. **Communicate the deprovision reality** - remind admins that offboarding must
   be driven from Entra, not just by revoking in the vault (see below).

---

## Behaviour notes and deviations

- **DELETE = revoke.** Both Entra soft delete (`active: false`) and hard
  DELETE revoke the membership. The row and its keys survive, so restoring a
  returning user needs no re-confirmation. No destructive operation is
  exposed to the IdP at all. This is a deliberate deviation from RFC 7644.
- **Roles are not synced.** Everyone provisions as the User role;
  promote people in the web vault. Vaultwarden's Custom role cannot round-trip
  through SCIM.
- **userName / displayName changes are not synced after creation.** The email
  is the login identity; the display name belongs to the person globally, not
  to one org's directory. Renames in Entra succeed (accepted and ignored)
  rather than erroring the sync.
- **SCIM user id** is the org membership id, not the account id. The same
  person in two orgs has two SCIM ids: SCIM is org-scoped by construction.
- **externalId is unique per org** for both Users and Groups, on every write
  path (create, PUT, PATCH). A write that would duplicate one is a 409
  `uniqueness` conflict and changes nothing; re-asserting a resource's own
  externalId succeeds.
- **A Group PUT that omits `members` leaves the member set unchanged.** Only
  an explicit `"members": []` clears the group, so a sparse non-Entra client
  cannot wipe membership by accident (Entra always sends the full list).
- **Deprovision from the IdP, not just the vault.** Because restore is lossless,
  a member you revoke in the web vault is silently re-activated on the next sync
  if the IdP still shows them active - `active: true` reinstates a previously
  confirmed member to full access with no re-confirmation. To offboard someone,
  unassign or disable them in Entra. Rotate the org's SCIM token if it may have
  leaked: it can reinstate any member the org previously confirmed, not only
  invite and deprovision.
- Every SCIM change is written to the org event log (admin-visible) with the
  synthetic actor `vaultwarden-scim-...` when `ORG_EVENTS_ENABLED=true`. Token
  generation, rotation, and deletion are logged too, under the acting admin's
  own identity.

## Operational lifecycle

1. Entra assigns user, SCIM creates membership at *Invited*, invite mail sent.
2. User clicks the invite, creates or logs into their account (*Accepted*).
3. An org admin confirms the member in the web vault (*Confirmed*). This is
   the manual step; the admin's client wraps the org key for the member.
4. Entra unassigns or soft deletes, SCIM revokes immediately. Vault access
   stops on the member's next sync.
5. Re-assignment restores the membership exactly as it was, including the
   confirmed state, with no new invite or confirmation needed.
