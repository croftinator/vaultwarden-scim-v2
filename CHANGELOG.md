# Changelog

Changes made by this fork, on top of upstream
[dani-garcia/vaultwarden](https://github.com/dani-garcia/vaultwarden). Upstream's
own changes are not repeated here.

This file exists because the fork's history is not otherwise reviewable: the
SCIM feature landed across many commits, and several changes were security fixes
whose *reasoning* matters more than the diff. Where a change has a rationale too
long for one line, it links to the document that holds it.

## Unreleased - `feature/scim-v2`

### Added

- **SCIM v2 provisioning server** (RFC 7643 / RFC 7644) at
  `/scim/v2/<org_id>`: Users and Groups full lifecycle, discovery endpoints,
  per-organization static bearer token, pre-auth rate limiting, SCIM error
  envelopes. Microsoft Entra ID is the tested provider.
  See [docs/scim/](docs/scim/README.md).
- **Token management** under `/api/organizations/<org_id>/scim/…`: mint, delete,
  enable/disable, and a status endpoint reporting configuration, last use, and a
  break-glass warning.
- **`last_used_at`** on the SCIM key, surfaced as `lastUsedAt`, so an operator can
  tell a live credential from a stale one. Recorded at hour resolution and only
  after the secret verifies, so a sync burst does not become thousands of writes
  and a failed authentication cannot keep the field warm.
- **Reversible kill switch** (`PUT …/scim/api-key/enabled`): stops provisioning
  immediately while keeping the digest, so resuming does not require pasting a
  new token into the IdP.
- **Composite indexes** on `users_organizations(org_uuid, external_id)` and
  `groups(organizations_uuid, external_id)`. A departure from upstream's
  index-free convention, taken because `users_organizations` is global across all
  organizations, so an unindexed correlation-key lookup scanned every membership
  on the server once per provisioned user.
- Operator documentation: deployment, setup, client rollout, operations,
  reference, upgrading, testing, and design with diagrams.
- Verification tooling: `tools/scim-test-backends.sh` (all three backends),
  `tools/scim-test-config-matrix.sh`, `tools/scim-replay.sh`,
  `tools/check-mermaid.sh`.

### Security

Findings from a security review of the branch. Each is stated as the defect,
because the defect is the thing worth not reintroducing.

- **An organization Admin could revoke Owners.** Minting the SCIM token was gated
  on `AdminHeaders`, which resolves for `membership_type >= Admin`. A SCIM token
  can revoke any member who is not the last confirmed Owner, while the web vault
  refuses an Admin revoking an Owner outright - so an Admin could issue itself a
  credential that did what its own session was denied. Minting and deleting now
  require `OwnerHeaders`. Rationale and diagram in
  [design.md](docs/scim/design.md).
- **Token rotation could silently fail, leaving the old token valid.** The
  sqlite/mysql upsert fallback filtered on `uuid`, but every mint generates a
  fresh `uuid`, so on rotation it matched no row, reported success, and left the
  previous digest live - handing out a dead token while the one being revoked
  kept working. Now filters on `org_uuid` and treats zero affected rows as an
  error.
- **SCIM list filters wrote directory email addresses into the request log.**
  Adding `/scim` to the logged routes meant `?filter=userName eq "…"` was logged
  at info level. Query values are now redacted for `/scim`. The same code sliced
  the query at a fixed byte offset, which panics on a multi-byte boundary and had
  become reachable pre-authentication; the cut is now on a character boundary.
- **A full sync could silently skip members.** Both list endpoints loaded the
  whole organization and sliced in memory with no `ORDER BY`. A client pages
  across separate requests, so two pages could disagree - and on PostgreSQL a
  concurrent revoke is an `UPDATE`, which relocates the row. A skipped member is
  a member who is never deprovisioned. Pagination now happens in SQL on a stable
  order.
- **Clearing `externalId` on an administrator was refused**, so Entra re-sent a
  write it could never satisfy every cycle, risking quarantine of the whole
  application and with it deprovisioning. Unlinking is the opposite of a
  privilege grant and is now allowed; only setting a non-empty value on a
  privileged member is refused.
- **A signup-policy bypass had no test on its enforcing side.** `POST /Users`
  applies `INVITATIONS_ALLOWED` and the domain allowlist because an `Invitation`
  row overrides `is_signup_allowed` at registration. Both were pinned permissive
  in the test environment, so the guard was unproven. Now covered, including that
  no `User` or `Invitation` row is left behind on refusal.
- **Rate-limiter memory was never released.** `retain_recent` removes entries but
  not the map's capacity, so a burst of spoofed client IPs - reachable
  pre-authentication - permanently inflated memory. Now followed by
  `shrink_to_fit`, and the sweep moved off the scheduler thread.
- Insecure predictable temp file in `tools/scim-test-config-matrix.sh`, now
  `mktemp` with a cleanup trap.

### Fixed

- **A migration had been edited in place after it was applied.** `diesel` records
  only a version with no checksum, so an edited migration never re-runs: any
  database that took the earlier version kept that schema permanently, with no
  error. Reissued as `2026-07-26-000000_add_scim_api_key`, which drops and
  recreates the table so it is reachable from either state. **Existing SCIM
  tokens are invalidated - re-mint them.** See
  [upgrading.md](docs/scim/upgrading.md).
- **MySQL: index DDL could leave the database unmigratable.** `groups` is a
  reserved word and was not quoted; because MySQL DDL is not transactional, the
  first index committed while the migration went unrecorded, so every retry died
  on "Duplicate key name". Indexes moved to their own migration and the
  identifier quoted. Found by running the suite against MySQL, not by reading it.
- **PostgreSQL: `scim_api_key.org_uuid` was narrower than its parent.** `CHAR(36)`
  against `organizations.uuid VARCHAR(40)`: a long organization id inserted fine
  on sqlite and MySQL and failed only here, and `bpchar` blank-padding made
  stored comparisons unreliable. Now `VARCHAR(40)` on both dialects.
- **PostgreSQL kept the old primary key on rotation.** `AsChangeset` never writes
  the primary key, so an `.set(self)` upsert diverged from `replace_into` on the
  other backends. Columns are now listed explicitly.
- **The served schema declared required attributes as `readOnly`.** RFC 7643
  defines `readOnly` as never client-writable, so a schema-driven client (Okta,
  OneLogin, Microsoft's SCIM Validator) would refuse to send `userName` - the one
  attribute a create requires - and every create would 400. Now `immutable`, and
  `externalId` is no longer listed, being a common rather than schema attribute.
- Discovery `meta.location` values for `/Schemas/{id}` and `/ResourceTypes/{id}`
  now resolve instead of 404ing.
- The oversized-member-list refusal uses `invalidValue`, not `tooMany`, which
  RFC 7644 defines as a *filter* keyword.
- A Group PATCH clearing `displayName` now returns 400 rather than a silent 200
  that the client records as applied.
- A PATCH to an attribute this server does not sync is still accepted with 200
  (a 400 would quarantine the user in Entra) but now logs at `warn`, so the
  resulting divergence between the directory and the vault is discoverable.
- Group resources now carry `meta.created` and `meta.lastModified`. Users
  deliberately do not - `Membership` has no revision column, and inventing one
  would let a client build delta sync on a timestamp that does not track the data.

### Known divergences from RFC 7644

Deliberate, documented in [reference.md](docs/scim/reference.md):

- `DELETE /Users/{id}` revokes rather than deletes, and the resource stays
  retrievable. Destroying the membership would destroy the wrapped organization
  key, which has no server-side reconstruction path under end-to-end encryption.
- `meta` carries no `created`/`lastModified` on Users, so delta sync is
  unavailable and every cycle is a full enumeration.
- SCIM never grants administrative privilege: it can deprovision an
  administrator but cannot reinstate or link one.
