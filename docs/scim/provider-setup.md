# Setting up and verifying each identity provider

Step-by-step for Entra ID, Okta, AWS IAM Identity Center, Google Workspace and
Authentik, plus the verification procedure that proves it actually worked.

> [!WARNING]
> **No provider here has been validated against a live tenant.** The request
> shapes are covered by tests written from each vendor's published
> documentation, and Authentik has been driven end to end - but that is not the
> same as your tenant, your attribute mappings and your scoping rules. Work
> through the verification section below against a **throwaway tenant and a test
> organisation** before you point this at anything real.

## Before you start

Two things are the same for every provider, and both live in
[setup.md](setup.md):

1. **Part A** - enable SCIM on the server (`SCIM_ENABLED=true`).
2. **Part B** - mint the organization's SCIM token.

You end up with two values every provider below needs:

| Value | Shape | Where it comes from |
|---|---|---|
| **SCIM endpoint** | `https://<your-domain>/scim/v2/<org_uuid>` | Your domain plus the org id from Part B1 |
| **Bearer token** | `scim_v1.<org_uuid>.<secret>` | Printed once by Part B4. It is never recoverable - rotate if lost |

Three constraints that will waste your afternoon if you miss them:

- **HTTPS is mandatory.** Every engine here refuses a plain-HTTP endpoint. It
  must also be publicly reachable; these are SaaS services calling inward.
- **The reverse proxy must set the client IP header** (`X-Real-IP` by default),
  or the rate limiter sees every request as one client and throttles your sync.
- **Do not scope organization Owners into provisioning.** See "Keep organization
  administrators out of scope" in [setup.md](setup.md#part-d---choose-which-users-and-groups-sync).
  A directory-driven revoke of your last Owner is the one mistake with no easy
  way back.

---

## The verification procedure

**This is the part worth doing properly, and it is identical for every
provider.** Run it after configuring, before trusting anything.

Export these once:

```bash
export VW=https://vault.example.com
export ORG=<org_uuid>
export TOK='scim_v1.<org_uuid>.<secret>'
scim() { curl -s -H "Authorization: Bearer $TOK" "$VW/scim/v2/$ORG/$1"; }
```

### Step 0 - the endpoint answers at all

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $TOK" "$VW/scim/v2/$ORG/ServiceProviderConfig"
```

`200` means the endpoint, TLS, proxy and token all work. Anything else is a
problem with your deployment, not your IdP - fix it before configuring anything.

`401` means the token is wrong, the org id is wrong, SCIM is disabled, or the key
was revoked. The 401 body is deliberately identical for all four, so check
`/api/organizations/<org>/scim/status` as an Owner to tell them apart.

### Step 1 - the provider connects

Every engine has a "test connection" or equivalent. Under the hood it usually
sends `GET /Users?filter=userName eq "..."` for a user that does not exist, and
requires an **empty 200**, not a 404. Confirm the same thing by hand:

```bash
scim 'Users?filter=userName%20eq%20%22nobody@example.com%22'
# expect: "totalResults":0 with an empty Resources array
```

### Step 2 - one user provisions

Assign a single test user, then wait for a sync cycle:

```bash
scim Users | python3 -m json.tool | head -30
```

Check three things:

- `userName` is the person's email, lowercased.
- `active` is `true`.
- `externalId` is present - this is the directory's own id, and it is how the
  provider correlates on later cycles. If it is missing, correlation will fall
  back to email and reassignment gets messy.

They should also receive an invite email. If SMTP is not configured they will
not, and the membership sits at *Invited* with no way for them to join - so
configure mail before a real rollout.

### Step 3 - a group syncs

Assign a group, wait a cycle:

```bash
scim Groups | python3 -m json.tool | head -40
```

`members` should list membership ids matching the users from step 2. If the
group appears with an empty `members` array, the users were not assigned to the
application - most engines only push group members who are themselves in scope.

### Step 4 - deprovision, the half that matters most

Deactivate or unassign the test user in the directory, wait a cycle:

```bash
scim Users | python3 -c "
import json,sys
for r in json.load(sys.stdin)['Resources']:
    print(r['userName'], 'active =', r['active'])"
```

`active` must become `false`. **The user must still be listed** - deprovisioning
revokes, it never deletes. If the user vanished entirely, something is wrong.

### Step 5 - reinstate, and confirm it was lossless

Re-activate in the directory, wait a cycle, and confirm `active` returns to
`true`. The member should **not** need to re-accept an invitation or be
re-confirmed, because the wrapped organization key was preserved through the
revoke. If they are asked to re-register, the round trip lost something and you
should stop and investigate before rolling out.

### Step 6 - the audit trail

With `ORG_EVENTS_ENABLED=true`, the organization's event log should show the
provisioning actions. If it is empty, you are running without an audit trail -
the server logs a startup warning about exactly this.

### A faster version of all of it

`tools/scim-replay.sh` runs steps 0-5 automatically against a live server,
including the quirks each engine sends:

```bash
tools/scim-replay.sh --domain "$VW" --org "$ORG" --token "$TOK" --profile okta
```

It creates and cleans up its own test data. Run it before configuring a real
provider - if it fails, the problem is your deployment, and no amount of IdP
configuration will fix it.

---

## Microsoft Entra ID

**Requires an Entra ID P1 or P2 licence.** A free tenant does not offer
*Automatic* provisioning at all - the mode simply is not there. Use a P2 trial or
a developer sandbox.

The full walkthrough is [setup.md Part C](setup.md#part-c---configure-the-entra-enterprise-application).
In outline:

1. **Entra admin centre → Enterprise applications → New application → Create
   your own → Integrate any other application**.
2. Open **Provisioning**, set Mode to **Automatic**.
3. **Tenant URL** = your SCIM endpoint. **Secret Token** = the bearer token.
4. **Test Connection**, then Save.
5. Under **Mappings**, review *Provision Azure Active Directory Users*. The
   defaults work; the attribute that matters is `userPrincipalName` or `mail`
   mapping to `userName`.
6. **Users and groups** - assign only the people and groups that should exist in
   Vaultwarden.
7. Turn **Provisioning Status** on.

Entra behaviour worth knowing:

- The first cycle can take **20-40 minutes** to start. This is normal and not a
  fault in your endpoint.
- Entra **retries a failing write every cycle** and eventually quarantines the
  whole application, which takes deprovisioning down with it. That is why this
  server returns 200 and logs rather than failing on things like an invite email
  it could not send.
- The provisioning log in Entra is the first place to look, not your server log.

## Okta

A **free developer account** at `developer.okta.com` supports SCIM provisioning,
which makes Okta the cheapest of the cloud engines to validate properly.

1. **Admin → Applications → Create App Integration → SWA / API Services**, or
   create a private SCIM-enabled app.
2. Open the **Provisioning** tab → **Configure API Integration** → enable it.
3. **SCIM connector base URL** = your SCIM endpoint.
4. **Unique identifier field for users** = `userName`.
5. Enable **Push New Users**, **Push Profile Updates** and **Push Groups**.
6. **Authentication Mode** = HTTP Header, with the bearer token.
7. **Test Connector Configuration**, then save.
8. Under **To App**, enable **Create Users**, **Update User Attributes** and
   **Deactivate Users**.

Okta behaviour worth knowing:

- It deactivates with a **path-less** `replace` carrying a value object - the
  same shape Entra uses. Both are accepted.
- **Group Push** is configured separately from user assignment, under the
  *Push Groups* tab. Assigning a group to the app is not the same as pushing it.
- Reassignment reactivates the existing member rather than creating a new one,
  which is lossless here.

## AWS IAM Identity Center

**Free with any AWS account** - there is no charge for Identity Center itself.

1. **IAM Identity Center console → Applications → Add application → Add a custom
   SAML 2.0 application** (SCIM provisioning attaches to an application).
2. Open the application's **Provisioning** tab → **Automatic provisioning**.
3. AWS shows you a **SCIM endpoint** and an **access token** of its own - ignore
   those. You want the reverse: enter *your* endpoint and *your* token in the
   external provisioning configuration.
4. Assign users and groups to the application.

AWS behaviour worth knowing:

- It is the **narrowest** engine of the four. It sends only `eq` filters, and
  only on `userName` for users and `displayName` for groups. Both are supported.
- It issues **`DELETE`** on unassignment rather than `active: false`. That
  revokes here rather than destroying, so the membership row and its key survive
  and reassignment is still lossless - but it means step 4 above shows the user
  as inactive after a *delete*, which is the intended behaviour, not a bug.
- It does not read `/Schemas`.

## Google Workspace / Cloud Identity

**Automated provisioning is not on the free tier.** A Workspace trial works.

1. **Admin console → Apps → Web and mobile apps → Add app → Add custom SAML
   app**.
2. Complete the SAML step, then open **Auto-provisioning** on the app.
3. Enter the SCIM endpoint and bearer token.
4. Map attributes - primary email to `userName` is the one that matters.
5. Set the **deprovisioning** behaviour and the delay Google applies before
   acting on a suspension or deletion.
6. Turn auto-provisioning on and assign organizational units or groups.

Google behaviour worth knowing:

- It sends `name.givenName` and `name.familyName` **without** `displayName` and
  expects the server to compose one. This server does.
- Suspension maps to `active: false`; reinstatement is lossless.
- Google applies its own **configurable delay** before deprovisioning. If step 4
  seems not to work, check that delay before suspecting the endpoint.

## Authentik (self-hosted)

Free, Docker-based, and the only engine here that can be run locally or in CI -
which makes it the best way to see the whole lifecycle work before committing to
a cloud tenant.

1. **Providers → Create → SCIM Provider**.
2. **URL** = your SCIM endpoint. **Token** = the bearer token.
3. Leave the default User and Group property mappings.
4. **Applications → Create**, bound to that provider.
5. Assign users and groups.

Authentik syncs on its own schedule and also on object save, so changes usually
appear within a minute.

`tools/scim-authentik-e2e.sh` automates all of this against a running server,
including the assertions in the verification section. It is the fastest way to
watch a real engine drive the endpoint:

```bash
tools/scim-authentik-e2e.sh --domain http://host.docker.internal:8000 \
  --org "$ORG" --token "$TOK" --db /path/to/db.sqlite3
```

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Test connection fails, `401` | Wrong token, wrong org id, SCIM disabled, or the key was revoked. Check `/api/organizations/<org>/scim/status` as an Owner. |
| Test connection fails, timeout | Endpoint not publicly reachable, or not HTTPS. Every engine here refuses plain HTTP. |
| Users provision but get no email | SMTP not configured. The membership sits at *Invited* and nobody can join. |
| `429` responses during a sync | The rate limiter is seeing every request as one client. Your proxy is not setting the client IP header (`X-Real-IP` by default). |
| Groups appear with no members | The members are not themselves in scope. Most engines only push group members who are also assigned to the application. |
| Everything 404s | The org id in the URL is wrong, or the organization was deleted. |
| A user vanished after deprovisioning | Should not happen - this server revokes rather than deletes. Investigate before rolling out. |
| Provisioning stopped and will not restart | Entra quarantines an application after repeated failures. Fix the underlying error, then restart provisioning from the Entra side. |
| Reinstated user asked to re-register | The revoke/restore round trip lost the wrapped key. Stop and investigate - this should be lossless. |

If none of these fit, [providers.md](providers.md#if-your-provider-does-not-work)
covers the three ways a provider usually diverges, and what each looks like on
the wire.
