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
  envelopes. Provider-agnostic: Entra ID, Okta and Google Workspace have their
  documented cycles covered by tests, and Authentik is driven end to end in CI.
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
- **UNIQUE indexes** on `users_organizations(org_uuid, external_id)` and
  `groups(organizations_uuid, external_id)`, one migration each. A departure from upstream's
  index-free convention, taken because `users_organizations` is global across all
  organizations, so an unindexed correlation-key lookup scanned every membership
  on the server once per provisioned user - and because the correlation key is an
  invariant the database should keep, not one application code re-checks on every
  write. **These migrations clear data: see Fixed, and read
  [docs/scim/upgrading.md](docs/scim/upgrading.md) before upgrading.**
  Collapsed while the branch is still unreleased: the whole SCIM schema is now a
  single migration per dialect, `2026-08-09-000000_scim_v2`. Every statement in
  it is re-runnable, including on MySQL, where each `CREATE INDEX` goes through
  an `information_schema` check and a prepared statement because MySQL 8 offers
  no `IF NOT EXISTS` for indexes. After merge such a change would have to arrive
  as a new migration; see CLAUDE.md.
- **Four distinct audit event types** for the SCIM credential lifecycle -
  `ScimCredentialCreated` (9100), `Revoked` (9101), `Enabled` (9102),
  `Disabled` (9103). Previously all four actions logged as
  `OrganizationUpdated`, so the org event stream could not tell a credential mint
  from any other configuration change. Numbered far outside Bitwarden's
  1000-1999 block on purpose: a number inside it could be reassigned by a future
  upstream release, which would silently relabel historical audit records rather
  than merely leaving them unknown. Clients that map event types by number render
  these as unknown, which is cosmetic and does not affect an events export.
- **Ownership guard on group deletion.** SCIM refuses to delete a group that
  grants collection access and carries no `externalId` (or grants access to all
  collections) - the same set additions are refused for. Without it a token
  holder could enumerate every group in the organization and delete
  administrator-curated ones, dropping their access grants.
- **Serialised owner revocation.** A process-global mutex holds the last-owner
  count and the write together, closing a race where two concurrent
  deprovisions of two different Owners each observed a count of two and both
  proceeded, leaving the organization with no Owner and no SCIM path back.
  Single-process only; the multi-replica case needs a database-level fix and is
  recorded in `TODOS.md`.
- **Rate-limiter pruning** on a schedule (`RATELIMIT_PRUNE_SCHEDULE`), because
  all four limiters key on client IP and are checked before authentication, so
  the keyed map grows without bound on unauthenticated traffic.
- New configuration: `SCIM_ENABLED`, `SCIM_RATELIMIT_SECONDS`,
  `SCIM_RATELIMIT_MAX_BURST`, `RATELIMIT_PRUNE_SCHEDULE`.
- **CI**: `scim-tests.yml` (the suite on sqlite, MySQL and PostgreSQL, plus a
  job that renders every mermaid diagram) and `provisioning-e2e.yml` (the
  last-owner concurrency race, and a full Authentik lifecycle against a real
  provisioning engine).
- Operator documentation: deployment, setup, client rollout, operations,
  reference, upgrading, testing, and design with diagrams.
- Verification tooling: `tools/scim-test-backends.sh` (all three backends),
  `tools/scim-test-config-matrix.sh`, `tools/scim-replay.sh`,
  `tools/check-mermaid.sh`, `tools/scim-owner-race.sh` (concurrency stress for
  the last-owner guard), `tools/scim-authentik-e2e.sh` and
  `tools/ci-seed-vaultwarden.sh` (the real-engine lifecycle).

### Changed

- **AWS IAM Identity Center is no longer listed as a supported provisioning
  source, and never could have been.** It is a SCIM *server*, not a client: it
  receives provisioning from an upstream IdP and does not push to third-party
  endpoints. The in-process test written for it now describes what it actually
  covers - a strict, spec-correct client - and `tools/scim-replay.sh --profile
  aws` became `--profile strict`. A user-visible retraction, recorded because
  the mistake is easy to repeat: AWS publishes a thorough SCIM guide describing
  the direction it does not support here.
- **`GET /scim/status` now requires the Owner role**, not merely an org admin.
  It reports credential state, `lastUsedAt`, and how many Owners are
  directory-linked - a map of the recovery path - and an Admin is exactly the
  role that cannot mint, revoke or disable the credential it describes.
- **SCIM writes no longer go through `replace_into`.** See Fixed.

### Security

Findings from a security review of the branch. Each is stated as the defect,
because the defect is the thing worth not reintroducing.

- **The guard against stranding a group outside SCIM never fired.** Clearing an
  access-granting group's `externalId` is irreversible through the API -
  `reject_privileged_group_adoption` refuses to ever set one back on such a group -
  so one clear put an administrator's group permanently beyond SCIM's reach. The
  PATCH guard asked `scim_may_add_members` about the group *as loaded*, which
  still carried the `externalId` being removed, and that helper returns `true` on
  `external_id.is_some()` before it looks at collection grants. It therefore fired
  only for `access_all` groups and waved through the collection-granting case it
  was written for; `put_group` had no clear-side guard at all. Both now ask
  `group_confers_access`, which is the property actually being protected, and both
  run before any write - so a bundled `[replace externalId "", add members]` can no
  longer commit the clear and then 400 on the members with nothing in the audit
  log. Whitespace-only values are treated as clears throughout, matching
  `set_external_id`.
- **A PATCH could commit a member removal and then refuse the rest.**
  `precheck_member_ops` applied the unmanaged-group guard to `add` but not to
  `replace`, so `[remove x, replace [a]]` on an admin-owned group passed the
  precheck, committed the removal, and then failed inside `set_members` -
  returning through `?` before `log_group_event`, leaving access changed with no
  audit record. That is exactly the invariant the function exists to hold. It now
  replays every op against the group's current member set, so it sees the same
  additions the apply loop will. A replace that only removes is still allowed on
  an unmanaged group; blocking deprovisioning would be the worse failure.
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

- **A duplicate `externalId` deleted the member who held it, and its wrapped
  organization key with it.** `Membership::save` and `Group::save` use
  `replace_into` on SQLite and MySQL, and `REPLACE` resolves a conflict on *any*
  unique index by DELETING the conflicting row and returning success. So the new
  UNIQUE indexes did not make a duplicate *fail*, they made it destroy a
  different member - taking the `akey` that wraps their copy of the organization
  key, which under end-to-end encryption nobody can reconstruct. Reachable
  through two concurrent writes on any backend, and on MySQL with no concurrency
  at all, because that index covers a 150-character prefix while the application
  compares the whole 300-character value. SCIM writes now use `save_strict`
  (`UPDATE`-then-`INSERT`), so the database raises the violation and the handlers
  answer it with a 409.
- **Upstream's Directory Connector import inherited the new constraint.**
  `ldap_import` reassigns an `external_id` between rows whenever a directory
  email changes, which the UNIQUE index turned into an aborted sync (PostgreSQL)
  or a silent row deletion (SQLite/MySQL). It now releases the key from the
  previous holder first, which is the same repair the migration performs on
  pre-existing duplicates.
- **The migrations that add those indexes clear data.** Where two rows in one
  organization claim the same directory object, one keeps its correlation key
  and the rest are set to NULL - nothing else is touched, and the next sync
  re-establishes them. Which row survives is arbitrary (`MIN` of a random v4
  uuid), MySQL additionally collapses values differing only after 150 characters
  or only in case, and PostgreSQL clears anything over 2000 bytes because a
  longer value would make the index creation fail and the server refuse to
  start. `docs/scim/upgrading.md` carries a pre-flight query.
- **An unbounded PATCH could drive ~11,900 sequential queries.** The member cap
  counted member *values*, and an operation with an empty value list counts
  zero - so thousands of them fit inside the body limit while each still reached
  a three-table join. Member *operations* are now capped separately.
- **The concurrency harness could not fail.** `tools/scim-owner-race.sh` had no
  `exit` statement, so the CI job guarding the last-owner invariant was green
  whether the race fired 0 or 40 times out of 40. It now asserts, records the
  HTTP status of every request (a 429 from the rate limiter was previously
  indistinguishable from the guard refusing), and CI additionally runs it
  against a binary built with the mutex compiled out and requires it to fail.
- **The Authentik end-to-end run asserted nothing about the E2EE invariant.**
  Its `akey IS NOT NULL` check was true for every row that existed, on a
  non-nullable column, for members that never held a wrapped key. It now seeds a
  Confirmed membership with a sentinel key and asserts that exact value, and the
  exact revoked status offset, survive the revoke/restore round trip.
- **Discovery advertised an attribute the handlers never return.** The User
  schema declared `name` as returned by default; it is honoured on create but
  never emitted. Now `returned: never`, which is what a schema-driven
  conformance checker compares against.
- **A PATCH that cleared an `externalId` and added members in one body refused
  its own member-add**, because the ownership guard ran against the in-memory
  group the same request had just made look unmanaged. Guards now run against
  the group as the database has it. Clearing an `externalId` on a group SCIM
  does not own is also refused now - it was the one unguarded direction, and it
  stranded administrator-curated groups outside SCIM permanently.
- **Failed audit-log writes are logged** rather than discarded silently.

- **A migration had been edited in place after it was applied.** `diesel` records
  only a version with no checksum, so an edited migration never re-runs: any
  database that took the earlier version kept that schema permanently, with no
  error. Reissued as `2026-08-09-000000_scim_v2`, which drops and
  recreates the table so it is reachable from either state. **Existing SCIM
  tokens are invalidated - re-mint them.** See
  [upgrading.md](docs/scim/upgrading.md).
- **MySQL: index DDL could leave the database unmigratable.** `groups` is a
  reserved word and was not quoted; because MySQL DDL is not transactional, the
  first index committed while the migration went unrecorded, so every retry died
  on "Duplicate key name". The identifier is quoted, and every `CREATE INDEX` now
  runs behind an `information_schema` check and a prepared statement, so the file
  is idempotent and a part-way failure can simply be retried. Found by running
  the suite against MySQL, not by reading it.
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
