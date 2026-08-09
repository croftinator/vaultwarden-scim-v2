# Setting up and verifying each identity provider

Step-by-step for Entra ID, Okta, Google Workspace and Authentik, plus the
verification procedure that proves it actually worked.

Console paths were checked against each vendor's documentation on 2026-08-09 and
are cited below. **Vendor UIs move constantly** - if a menu is not where this
says, trust the vendor's own docs and please open an issue so this can be
corrected.

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

Source: [Microsoft - use SCIM to provision users and groups](https://learn.microsoft.com/en-us/entra/identity/app-provisioning/use-scim-to-provision-users-and-groups).

## Okta

A **free developer account** at `developer.okta.com` supports SCIM provisioning,
which makes Okta the cheapest cloud engine to validate properly.

Okta provisions to an *application*, and the simplest route for a custom
endpoint is the catalog's generic SCIM template rather than building an
integration from scratch:

1. **Admin Console → Applications → Applications → Browse App Catalog**.
2. Search for **SCIM 2.0 Test App (Header Auth)** and **Add Integration**.
   (Header Auth is the variant matching this server's bearer token. There are
   also Basic Auth and OAuth variants - do not pick those.)
3. Complete **General Settings** and the sign-on step.
4. Open the **Provisioning** tab → **Configure API Integration** → tick
   **Enable API integration**.
5. **SCIM connector base URL** = your SCIM endpoint.
6. **Unique identifier field for users** = `userName`.
7. Supported actions: enable **Push New Users**, **Push Profile Updates** and
   **Push Groups**.
8. Authentication: **HTTP Header**, with the bearer token.
9. **Test API Credentials**, then save.
10. Under **Provisioning → To App**, enable **Create Users**, **Update User
    Attributes** and **Deactivate Users**.
11. **Assignments** tab - assign the users and groups that should exist in
    Vaultwarden.

Okta behaviour worth knowing:

- It deactivates with a **path-less** `replace` carrying a value object, the same
  shape Entra uses. Both are accepted.
- **Group Push is configured separately** on its own tab. Assigning a group under
  *Assignments* controls who gets the app; it does **not** create the group here.
  If groups are not appearing, that tab is why.
- Reassignment reactivates the existing member rather than creating a new one,
  which is lossless here.

Source: [Okta - connect a SCIM 2.0 application](https://developer.okta.com/docs/guides/scim-provisioning-integration-connect/main/).

## AWS IAM Identity Center - not usable as a source

**Skip this one. It cannot provision into Vaultwarden.**

IAM Identity Center is a SCIM *server*, not a client: it receives provisioning
*from* an IdP and has no outbound SCIM to third-party applications. AWS's own
documentation is titled "Provision users and groups **from an external identity
provider** using SCIM" and instructs you to configure the connection in your IdP
using the endpoint and token that Identity Center generates.

**This is not a gap in practice.** Identity Center is almost never an
organisation's source of record - the standard pattern is Entra ID or Okta
feeding it over SAML and SCIM, and the AWS console page for enabling that is
literally titled *"Inbound automatic provisioning"*. If your users reach AWS
through Identity Center, they came from an IdP that can provision Vaultwarden
directly. Point that IdP at both, and follow its section above or below.

An earlier version of this guide had setup steps here. They were wrong, and the
reason is worth keeping: AWS publishes a thorough SCIM implementation guide that
describes everything Identity Center *accepts*, and it reads exactly like a
description of what it *sends*. The first question to ask about any provider is
**which direction does its SCIM run**.

## Google Workspace / Cloud Identity

**Auto-provisioning is not on the free tier.** A Workspace trial works.

1. **Admin console → Apps → Web and mobile apps → Add app → Add custom SAML app**.
2. Complete the SAML step (Google requires a SAML app before it will offer
   provisioning).
3. Back on the app, open **Auto-provisioning** - or click the
   *Provisioning available* text on the app, then **Configure auto-provisioning**
   at the bottom of the page.
4. Choose **SCIM** and continue.
5. **Endpoint URL** = your SCIM endpoint. **App authorization token** = the
   bearer token.
6. Leave the default **attribute mappings**. The one that matters is primary
   email to `userName`.
7. Set the **deprovisioning** behaviour and the delay Google applies before
   acting on a suspension or deletion.
8. Turn auto-provisioning on and assign organizational units or groups.

Google behaviour worth knowing:

- It sends `name.givenName` and `name.familyName` **without** `displayName` and
  expects the server to compose one. This server does.
- **Group provisioning is limited.** AWS's own integration guide states that
  Google Workspace does not support SCIM group provisioning, so expect users to
  sync and groups not to. Verify this against your own tenant before relying on
  group sync - if groups do not appear, this is the likely reason rather than a
  fault in the endpoint.
- **Both SAML and SCIM must use primaryEmail**, and syncs run every few hours
  rather than immediately.
- Google applies a **configurable delay** before deprovisioning. If step 4 of the
  verification seems not to work, check that delay before suspecting the server.

Sources: [Google - configure user provisioning](https://knowledge.workspace.google.com/admin/users/advanced/configure-amazon-web-services-user-provisioning),
[AWS - Google Workspace and IAM Identity Center](https://docs.aws.amazon.com/singlesignon/latest/userguide/gs-gwp.html)
(the AWS guide is the clearest published statement of Google's group limitation).

## Authentik (self-hosted)

Free, Docker-based, and the only engine here that can run locally or in CI -
which makes it the best way to watch the whole lifecycle work before committing
to a cloud tenant.

1. Log in as an administrator and open the **Admin interface**.
2. **Applications → Applications → Create with wizard** (or **New Application**).
3. Name the application, continue, and choose **SCIM** as the *Provider Type*.
4. On **Configure Provider**: **URL** = your SCIM endpoint, **Token** = the
   bearer token. Leave the default User and Group property mappings - Authentik
   notes they work for most setups.
5. Continue through bindings and **Create**.

If you created the provider separately rather than through the wizard, bind it
explicitly - and note the model, because it catches people out:

6. **Applications → Applications →** edit your application.
7. Click **+** next to **Backchannel providers**, select the SCIM provider,
   **Confirm**, then **Save changes**.

**A SCIM provider is a *backchannel* provider, not a normal one.** It becomes
active through that backchannel binding rather than by being set as the
application's main provider. If nothing is syncing and the configuration looks
right, this is the first thing to check.

Sync timing, from Authentik's own docs: a change to a user or group is sent to
all SCIM providers **as it happens**, and every SCIM provider is **fully
synchronised once an hour**. So new work appears within seconds, while a
correction to something already synced may wait for the hourly pass.

`tools/scim-authentik-e2e.sh` automates all of this against a running server,
including the assertions in the verification section:

```bash
tools/scim-authentik-e2e.sh --domain http://host.docker.internal:8000 \
  --org "$ORG" --token "$TOK" --db /path/to/db.sqlite3
```

Source: [Authentik - create a SCIM provider](https://docs.goauthentik.io/add-secure-apps/providers/scim/create-scim-provider/),
[Authentik - SCIM provider](https://docs.goauthentik.io/docs/add-secure-apps/providers/scim/).

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
