# Identity provider compatibility

These endpoints are RFC 7643 / 7644 SCIM 2.0. **Nothing in the request path
branches on which client is calling.** That is the whole compatibility story:
any provisioning engine that speaks standard SCIM works, and the vendor-specific
work in this codebase is *tolerance* rather than special-casing.

The distinction matters when reading the source. Comments mention Entra ID a
lot, because Entra sends several things a spec-correct client never would:

| Entra sends | Spec-correct form | What this server does |
|---|---|---|
| `"op": "Replace"` | `"op": "replace"` | Accepts any casing |
| `"value": "False"` | `"value": false` | Accepts the string form too |
| `{"op":"replace","value":{"active":false}}` (no `path`) | `path: "active"` | Accepts both |
| `members[value eq "id"]` for removal | `path: "members"` + value list | Accepts both |

Accepting those costs nothing for a client that does not send them. There is no
code path a strict client can take that a lenient one cannot.

## Support status

| Provider | Status | Verified how |
|---|---|---|
| **Microsoft Entra ID** | Primary target | Request shapes replayed in the suite and by `tools/scim-replay.sh`. No live tenant sync yet - see TODOS.md. |
| **Okta** | Supported | Documented provisioning cycle covered end to end in the suite. Not run against a live Okta org. |
| **AWS IAM Identity Center** | **Not applicable - cannot drive this endpoint** | It is a SCIM *server*: it RECEIVES provisioning from an IdP and has no outbound SCIM to third-party applications. Corrected 2026-08-09 after checking AWS's documentation; an earlier version of this table wrongly listed it as supported. |
| **Google Workspace / Cloud Identity** | Supported | Documented provisioning cycle covered end to end in the suite. Not run against a live tenant. |
| **Authentik** (self-hosted) | **Verified working** | The only provider actually run against this implementation: a full lifecycle sync, 46 requests, no errors. See "Rung 2b" in [testing.md](testing.md). |
| Any other SCIM 2.0 client | Should work | Only the standard surface is implemented. |

> [!IMPORTANT]
> **"Supported" here means the vendor's documented request shapes are exercised
> by the test suite, not that a live tenant has been synced.** Authentik is the
> one exception - a real engine has driven the endpoint end to end. Every provider in
> that table carries the same caveat, Entra included. Tenant validation is a P1
> item in `TODOS.md` and needs credentials this project does not have. Treat the
> table as "no known incompatibility", not as a certification.

## What every provider gets

- **Discovery**: `/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas`.
- **Users**: create, read, list, filter, update (PATCH and PUT), deactivate,
  reactivate, delete-as-revoke.
- **Groups**: create, read, list, filter, member add/remove/replace, delete.
- **Filters**: `attr eq "value"` on `userName`, `emails.value` and `externalId`
  (Users), and `displayName` and `externalId` (Groups). Anything else is a
  `400` with `scimType: invalidFilter` rather than a silently wrong result.
- **Pagination**: `startIndex` and `count`, 1-based, capped at 200 per page and
  ordered in SQL so a member cannot be skipped or repeated across pages.
- **Errors**: RFC-shaped envelopes with `status` as a string and the sanctioned
  `scimType` keywords.

## Provider notes

### Microsoft Entra ID

Needs an Entra ID P1 or P2 licence for automatic provisioning; a free tenant
will not offer the mode at all. Full walkthrough in [setup.md](setup.md).

The behaviour worth knowing: Entra retries a failing write **every cycle** and
eventually quarantines the whole application, which takes deprovisioning down
with it. That is why several paths here deliberately return `200` and log rather
than fail - an invite email that could not be sent, an attribute this server does
not sync. A `500` is the one outcome that compounds.

### Okta

Point Okta's SCIM 2.0 provisioning at `https://<your-domain>/scim/v2/<org_uuid>`
with the bearer token as the API token. Enable Create, Update and Deactivate.

- Okta imports with `userName eq`, which returns an empty `200` for an unknown
  user rather than a `404`.
- Okta deactivates with a **path-less** `replace` carrying a value object, the
  same shape Entra uses. Both are accepted.
- Group Push maps to `PATCH /Groups/<id>` with `add` and `remove` on `members`.
- Reassignment reactivates the existing membership rather than creating a new
  one, which is lossless here because revocation preserves the wrapped org key.

### AWS IAM Identity Center - does NOT work, and why

**IAM Identity Center cannot provision into this server, or into any third-party
SCIM application.** It is a SCIM *server*, not a client: its documentation is
titled "Provision users and groups **from an external identity provider** using
SCIM", and it tells you to configure the connection *in your IdP* using the SCIM
endpoint and bearer token that **Identity Center** generates. Provisioning flows
Entra/Okta/Google -> Identity Center, never Identity Center -> your app.

Applications that Identity Center fronts get access through SAML plus permission
sets and assignments. There is no outbound SCIM push.

This entry was wrong until 2026-08-09 and is left here rather than deleted,
because the mistake is easy to repeat: AWS publishes a detailed SCIM
implementation guide, and it is entirely about what Identity Center *accepts*.
Reading it as a description of what it *sends* is the same trap Zitadel sets,
and is why the first question about any provider must be **which direction does
its SCIM run**.

**In practice this costs you nothing**, because Identity Center is almost never
the source of record. The standard enterprise pattern is Entra ID (or Okta) as
the directory, feeding Identity Center over SAML and SCIM - AWS publishes a
dedicated guide for exactly that, and the UI you click through to enable it is
titled *"Inbound automatic provisioning"*. Identity Center is a **downstream
consumer of provisioning, the same as this server is.**

So if your users reach AWS through Identity Center, they got there from an IdP
that can also provision Vaultwarden directly. Point that IdP at both. The
topology is a fan-out from one directory, not a chain through AWS:

```
Entra ID / Okta ──SCIM──▶ AWS IAM Identity Center
        │
        └─────────SCIM──▶ Vaultwarden (this server)
```

Sources: [AWS - Configure SAML and SCIM with Microsoft Entra ID and IAM Identity
Center](https://docs.aws.amazon.com/singlesignon/latest/userguide/idp-microsoft-entra.html),
[AWS - provision from an external identity
provider](https://docs.aws.amazon.com/singlesignon/latest/userguide/provision-automatically.html).

### Google Workspace / Cloud Identity

Configure automated provisioning for a custom SCIM app.

- Google sends `name.givenName` and `name.familyName` **without** `displayName`
  and expects the server to compose one. This server does, and the composition is
  pinned by a test so it cannot silently change.
- Suspension maps to `active: false`; reinstatement is lossless.
- Google uses `PUT` for full-resource updates as well as `PATCH`.

## Why only one of these can run in CI

Entra ID, Okta and Google Workspace ship **no container, no emulator and no
local mode**. That is not an oversight - the provisioning engine
*is* the SaaS product, welded to their identity backends, so there is nothing to
hand out.

Microsoft is the only one of the three offering anything, and it is hosted
rather than local: the [SCIM Validator](https://scimvalidator.microsoft.com)
checks SCIM 2.0 conformance from their servers, needs no tenant, and despite the
name is useful for any provider - but it cannot run unattended in CI, because it
needs a publicly reachable endpoint and an interactive sign-in.

That constraint is the whole reason this repository is arranged the way it is:

| Layer | Covers | Why it exists |
|---|---|---|
| In-process suite | All four vendors' **documented** request shapes | The only option for the three that cannot be run |
| `tools/scim-authentik-e2e.sh` | One **real** engine, full lifecycle, unattended | Authentik is self-hostable, so it is the only engine CI can drive |
| `tools/scim-replay.sh` | Any vendor's shapes over real HTTPS | Manual, against a live deployment |
| A live tenant | Assignment scoping, sync cycles, nested groups | The only way to finish the job for the SaaS three |

So Authentik is not a substitute for the other three. It is the only place where
software we did not write gets to decide what to send, and that is worth having
even though it will never reproduce Entra's quirks.

## Getting a tenant to validate against

The support table says "not run against a live tenant" for every provider,
including Entra. That gap is smaller than it looks, because most of these can be
obtained free. Rough order of effort:

| Provider | Cost to validate | Notes |
|---|---|---|
| **Microsoft SCIM Validator** | Free, no tenant | Only needs a Microsoft account and a publicly reachable HTTPS endpoint. Despite the name it checks SCIM 2.0 conformance generally, so it is the best first move for any provider. |
| **Okta** | Free developer account | `developer.okta.com`. Create a private SCIM 2.0 app, enable provisioning, point it at your endpoint. Closest thing to a full engine at zero cost. |
| **Google Workspace** | Needs a paid plan | Automated provisioning is not on the free tier. A trial works. |
| **Microsoft Entra ID** | Needs P1/P2 | A free tenant will not offer *Automatic* provisioning at all. Use a P2 trial or a developer sandbox. |

Your endpoint has to be publicly reachable over HTTPS for any of them - see
"Exposing a local server" in [testing.md](testing.md), and read the warning
there before opening a tunnel to a dev box.

## Testing against your provider

Rungs 1 to 3 in [testing.md](testing.md) need no tenant at all:

1. `cargo test --features sqlite` runs the documented cycle for all four
   providers plus the Entra quirk corpus.
2. `tools/scim-replay.sh` fires the shapes at a **running** server over
   real HTTPS, so TLS, your reverse proxy, the rate limiter and the error
   catchers all participate. It takes `--profile entra|okta|aws|google`, which
   swaps the create payload and the deactivation form for that engine's
   documented shape; everything else it fires is plain SCIM 2.0 and is identical
   for all four. Running all four against one deployment takes about a minute:

   ```bash
   for p in entra okta aws google; do
     tools/scim-replay.sh --domain https://vault.example.com \
       --org <org_uuid> --token scim_v1.<org_uuid>.<secret> --profile "$p"
   done
   ```
3. <https://scimvalidator.microsoft.com> is Microsoft's hosted conformance
   validator. Despite the name it checks SCIM 2.0 conformance generally, needs
   only a Microsoft account, and is the cheapest way to get an independent
   opinion before committing to any tenant.

Only assignment scoping, sync-cycle behaviour and nested groups genuinely
require a real tenant, and those differ per provider.

## If your provider does not work

Most incompatibility surfaces as one of three things:

- **A filter this server refuses.** Look for `invalidFilter` in the response.
  Only `attr eq "value"` is implemented; a provider needing `co`, `sw` or a
  complex path would need the parser extended. That is a deliberate limit - a
  filter that is silently misparsed returns the wrong members, which is worse
  than a clear refusal.
- **An attribute that is accepted and ignored.** `userName`, `displayName` and
  `name` are not synced after creation; the server logs a warning rather than
  failing, because a `4xx` here makes an IdP retry forever. Named in
  [reference.md](reference.md).
- **A `500`.** That is a bug, not a limit. Capture the request and the server log
  and open an issue - every known path that could return one has been converted
  to a `400` with an explanatory `scimType`.
