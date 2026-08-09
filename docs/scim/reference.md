# Reference: behaviour, deviations, and named RFC divergences

Behaviour that is deliberate but surprising. If something here looks like a bug,
read the reason before changing it - most of these are load-bearing under
end-to-end encryption.

- **DELETE = revoke.** Both a soft delete (`active: false`, which Entra, Okta
  and Google all use) and a hard DELETE (which a strict SCIM client may issue on
  unassignment) revoke the membership. The row and its keys survive, so restoring a
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
- **SCIM does not bypass the server's signup gates.** Creating a brand-new
  account through `POST /Users` requires `INVITATIONS_ALLOWED` and an address
  inside `SIGNUPS_DOMAINS_WHITELIST`, exactly as the web vault's own invite
  does. Otherwise the response is a 400 `invalidValue`. Linking an account that
  already exists is unaffected.
- **PATCH operations apply in the order they arrive** (RFC 7644 section 3.5.2),
  including on group members, so a `remove` followed by an `add` of the same
  member ends with that member present.
- **A `remove` operation on an attribute Vaultwarden does not sync is accepted
  as a no-op**, not an error: Entra sends one whenever a mapped source attribute
  is cleared in the directory, and failing it would break the sync for that user.
  `remove` on `externalId` clears it; `remove` on `active` is refused - set it
  to `false` instead.
- **A Group write carries at most 1000 member values.** More returns a 400
  `invalidValue`. On a PATCH the values are counted across *all* operations in
  the body, so splitting a large change into several ops does not evade it.
  (This was `tooMany` before review: RFC 7644 section 3.12 defines `tooMany`
  as a *filter* keyword, so a client branching on scimType would have retried
  with a narrower filter, which never fixes an oversized body.)
- **SCIM can remove members from a group it does not manage, but not add
  them.** A group that grants collection access and carries no `externalId` -
  the shape of a group an administrator curated in the web vault - refuses
  member *additions* with a 400 `mutability`. So does any group with
  access-to-all-collections, `externalId` or not. Removals always proceed.

  The reason is that Vaultwarden grants collection access through
  `groups_users -> collections_groups` with no per-collection key, so adding
  somebody to such a group hands them real plaintext access. The asymmetry
  mirrors revoke-yes/restore-no on Users: a removal reduces access and is the
  deprovisioning path, and refusing it would leave the IdP re-sending a write it
  can never satisfy until it quarantines the application.

  This does not affect normal Entra operation - Entra sends an `externalId` on
  every group it creates, so groups it manages stay fully writable. A
  SCIM-created group with no collection grants also stays writable, because
  adding members to it escalates nothing.

- **Attribute lengths are capped, and the caps differ.** `externalId` at 300
  characters, a Group's `displayName` at 100, and `userName` at 255 - each
  matching the narrowest column it lands in across the three backends. Over-long
  values get a 400 `invalidValue`. Without the caps the backend decided, and the
  three disagreed: stored intact on SQLite, truncated or rejected on MySQL
  depending on strict mode, and a failed insert on PostgreSQL that surfaced as a
  500 - the one status that makes Entra retry forever.

- **A Group's `displayName` cannot be cleared.** It is a required attribute, so
  a PUT or PATCH setting it to `""`/whitespace, or a `remove` on it, returns a
  400 `invalidValue` rather than being silently ignored with a 200. Omitting
  the attribute entirely is different, and still leaves the name unchanged. A silent 200
  would make the client record the rename as applied and never retry, leaving
  the directory and the vault permanently disagreeing.
- **429 responses carry a `Retry-After` header** derived from
  `SCIM_RATELIMIT_SECONDS`.
- **Minting or deleting the SCIM token requires the Owner role**, not merely an
  org admin. A SCIM token can revoke any member who is not the last confirmed
  Owner, while the web vault refuses an Admin revoking an Owner outright. Since
  the admin guard admits Admins and Owners alike, allowing an Admin to mint
  would have let them issue themselves a credential that does what their own
  session is denied. **Reading `/scim/status` also requires the Owner role** (no
  password/OTP step-up), for the same reason: it reports the credential state and
  the break-glass Owner counts that describe it.
- **SCIM never grants administrative privilege.** It cannot create an
  administrator (provisioning always makes a plain member) and cannot promote
  one (roles never sync). On an existing Owner, Admin, or Manager it can
  *deprovision* normally, but `active: true` and setting `externalId` both
  return a 400 `mutability`.

  The asymmetry is deliberate. Restore is lossless, so reinstating a revoked
  Owner would return full vault access with no admin action and no
  re-confirmation - the path a departing administrator who kept their master
  password and a retained token could use on themselves. Deprovisioning stays
  open because refusing it would make offboarding an administrator through the
  IdP a silent no-op, which is the worse failure: a malicious mass-revoke is
  recoverable by the surviving Owner from the web vault, an admin who is never
  deprovisioned keeps access until someone audits.

  Reinstate such a member in the web vault. **Prefer excluding administrators
  from the SCIM app assignment in Entra entirely** - this guard is the backstop
  for when that is not done, not a substitute for it.

  *Unlinking* is allowed, though: a `remove` of `externalId` on a privileged
  member succeeds. Detaching an account from the directory is the opposite of a
  grant, and refusing it left Entra re-sending a write it could never satisfy -
  a permanently failing attribute write eventually quarantines the application
  and takes deprovisioning down with it. Only *setting* a non-empty externalId
  on a privileged member is refused.
- **Discovery follows the running configuration.** With
  `ORG_GROUPS_ENABLED=false`, `/ResourceTypes` and `/Schemas` omit Group
  entirely rather than advertising an endpoint that answers 501.
- **Every advertised discovery location resolves.** `/ResourceTypes/{id}` and
  `/Schemas/{id}` are retrievable individually (RFC 7644 section 4), so a
  conformance-checking client that dereferences the `meta.location` each
  collection entry advertises gets the resource rather than a 404.
- **Schema attributes are declared `immutable`, not `readOnly`.** `readOnly`
  means a client may never send the attribute, and a schema-driven client
  (Okta, OneLogin, Microsoft's SCIM Validator, Entra's discovery step) honours
  that - which would be fatal for `userName`, the one attribute a create
  requires, and for `emails[]`, the only address a tenant that maps into
  `emails` rather than `userName` ever sends. `immutable` says what the server
  actually does: accepted at create, not rewritten afterwards. `externalId` is
  deliberately absent from the attribute lists - RFC 7643 section 3.1 makes it
  a *common* attribute, not a schema-defined one.
- **Lists are paginated in the database on a stable order.** A client pages by
  issuing separate requests, so each page is its own query; without a total
  order the backend may return rows differently between them and a member can
  land on two pages or on none. That is a silent skip during a full sync, and
  on PostgreSQL it is reachable in practice because a concurrent revoke is an
  `UPDATE` and an `UPDATE` relocates the row.
- Every SCIM change is written to the org event log (admin-visible) with the
  synthetic actor `vaultwarden-scim-...` when `ORG_EVENTS_ENABLED=true`. Token
  generation, rotation, and deletion are logged too, under the acting admin's
  own identity.
- **SCIM request query strings are redacted in the server log.** `/scim` is in
  the logged-routes list so syncs are traceable, but a SCIM list request carries
  directory identity in the query itself
  (`?filter=userName eq "person@example.com"`). Only parameter *names* are
  logged for `/scim`; the values are replaced with `<redacted>`.

- **A PATCH to an unsynced attribute is accepted, ignored, and logged at
  `warn`.** Returning 200 for a write the server does not apply means the client
  records it as done and never retries, so the directory and the vault diverge
  permanently. The 200 is still the right answer - a 400 on `userName` would
  quarantine that user in Entra for an attribute this server will never own -
  so the log line is the only place the divergence surfaces. Grep the server log
  for `did not apply a write` when someone asks why a rename in the directory
  never reached the vault.
- **Group resources carry `meta.created` and `meta.lastModified`; Users do
  not.** `Group` has a revision timestamp to populate them from and `Membership`
  does not. Inventing one for Users would let a client build a delta sync on a
  timestamp that does not track the data, which is worse than omitting it. See
  the named divergence on delta sync below.

### Named divergences from RFC 7644

Two places where this server knowingly does not do what the RFC says. Both are
tolerated by Entra ID, whose default deprovision is `active: false` and which
does a full sync every cycle. Anyone integrating a *different* SCIM client
should read these first.

- **A deleted user stays retrievable.** RFC 7644 section 3.6 says a provider
  that does not permanently delete "MUST return a 404 ... for all operations
  associated with the previously deleted id" and "MUST also omit the resource
  from future query results". Here, `DELETE /Users/{id}` returns 204 but a
  later `GET` returns 200 with `active: false`, and the member still appears in
  list and filter results. This is the E2EE constraint, not an oversight:
  destroying the membership would destroy the wrapped org key (`akey`) with no
  server-side path to recreate it, so deprovision is a revoke. A client that
  interprets 404-after-delete as "gone" and re-creates the user will instead
  see them as present-but-inactive, which is the correct state.
- **No `meta.created`, `meta.lastModified`, or `meta.version` on `User`
  resources**, and no `meta.version` on either resource type. RFC 7643
  section 3.1 returns these by default. `Membership` carries no revision
  timestamp to populate `lastModified` from, so rather than invent one this
  server omits the sub-attributes entirely on Users. `Group` resources DO carry
  `meta.created` and `meta.lastModified`, because `Group` has a real revision
  timestamp - see the Groups section above. The consequence for operators:
  **delta sync is not available** - a client cannot filter on
  `meta.lastModified gt ...` - so every cycle is a full enumeration. Size your
  sync interval for that.

### Upgrading from an earlier build of this branch

Only relevant if you ran an earlier build of `feature/scim-v2`; it does not
affect a first-time install.

- **The `scim_api_key` migration was reissued** under a new version
  (`2026-08-09-000000_scim_v2`). The earlier one was edited in place after it had
  already been applied, and diesel records only a version with no checksum, so
  an edited migration never re-runs - any database that took the old one would
  have kept the old schema silently. The new migration drops and recreates the
  table, so **existing SCIM tokens are invalidated: re-mint each organization's
  token and update it in Entra.** Nothing else references the table.
- **PostgreSQL only:** the synthetic event actor changed length. Org event rows
  written by an earlier build carry the old value and will not match the new
  one, so old SCIM entries may show an unresolved actor. There is no backfill;
  delete them or ignore them.
