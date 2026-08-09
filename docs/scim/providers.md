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
| **Microsoft Entra ID** | Primary target | Request shapes replayed in the suite and by `tools/scim-entra-replay.sh`. No live tenant sync yet - see TODOS.md. |
| **Okta** | Supported | Documented provisioning cycle covered end to end in the suite. Not run against a live Okta org. |
| **AWS IAM Identity Center** | Supported | Documented provisioning cycle covered end to end in the suite. Not run against a live AWS instance. |
| **Google Workspace / Cloud Identity** | Supported | Documented provisioning cycle covered end to end in the suite. Not run against a live tenant. |
| Any other SCIM 2.0 client | Should work | Only the standard surface is implemented. |

> [!IMPORTANT]
> **"Supported" here means the vendor's documented request shapes are exercised
> by the test suite, not that a live tenant has been synced.** Every provider in
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

### AWS IAM Identity Center

Use the SCIM endpoint and access token from the Identity Center console.

- AWS is the narrowest engine of the four: it sends only `eq` filters, and only
  on `userName` for Users and `displayName` for Groups. Both are implemented.
- It deactivates with an explicit `path: "active"` and a real JSON boolean.
- It issues `DELETE` on unassignment. That revokes rather than destroys, so the
  membership row and its `akey` survive and re-assignment needs no re-confirm.
- AWS does not read `/Schemas`, but the endpoint is there for anything that does.

### Google Workspace / Cloud Identity

Configure automated provisioning for a custom SCIM app.

- Google sends `name.givenName` and `name.familyName` **without** `displayName`
  and expects the server to compose one. This server does, and the composition is
  pinned by a test so it cannot silently change.
- Suspension maps to `active: false`; reinstatement is lossless.
- Google uses `PUT` for full-resource updates as well as `PATCH`.

## Testing against your provider

Rungs 1 to 3 in [testing.md](testing.md) need no tenant at all:

1. `cargo test --features sqlite` runs the documented cycle for all four
   providers plus the Entra quirk corpus.
2. `tools/scim-entra-replay.sh` fires the shapes at a **running** server over
   real HTTPS, so TLS, your reverse proxy, the rate limiter and the error
   catchers all participate.
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
