# TODOS

## SCIM

### SCIM x SSO - CLOSED except the token exchange

**All 13 Suite C cases are now written and green.** They drive the real
`/identity/connect/token` handler and the real account resolution at
`identity.rs:221`. No OIDC stub was needed: seeding `SsoAuth.auth_response`
makes `sso::exchange_code` return at `sso.rs:258`, the path that exists so the
2FA round trip does not redeem a code twice.

The three original findings, all now settled:

1. ~~A SCIM shell account links even when `SSO_SIGNUPS_MATCH_EMAIL=false`~~ -
   **pinned** by `sso_login_adopts_a_scim_provisioned_shell_account`, with
   `sso_refuses_an_account_that_has_already_registered` as the negative control
   proving the guard does fire when the account owns a keypair. Without both,
   "shell accounts link" was equally explained by a broken guard.
2. **Moved to design.md, not closed.** SSO account creation is gated only by
   `is_email_domain_allowed` and email verification - not by
   `INVITATIONS_ALLOWED`/`SIGNUPS_ALLOWED` - so SSO is a wider door than the
   SCIM path this review narrowed. `sso_login_alone_grants_no_organization_access`
   pins the blast radius (an account, but no org data). Whether the asymmetry is
   *intended* is an upstream policy question, recorded in design.md under "An
   asymmetry this design does not resolve".
3. ~~No recovery for a deleted-and-recreated Entra user~~ - **closed both ways.**
   `a_recreated_directory_entry_is_locked_out_by_the_old_identity_binding`
   proves the lockout is real; the recovery (admin panel -> **Delete SSO
   Association**, `DELETE /admin/users/<user_id>/sso`) is now a row in the
   README troubleshooting table.

**Still outstanding:** the OIDC token *exchange* itself - see "Outstanding test
coverage" below. These tests deliberately begin after it.

**Note for whoever extends this:** `SSO_ONLY` cannot be toggled within a test
binary (CONFIG is a `LazyLock` resolved pre-main). `tools/scim-test-config-matrix.sh`
re-runs the suite with it set, and the C8 test cross-checks the requested value
against `CONFIG` so a broken override fails loudly instead of silently taking
the other branch.

**Effort:** -
**Priority:** closed

### AWS IAM Identity Center was never a viable source - CLOSED 2026-08-09

Verified against AWS's own documentation, which is titled "Provision users and
groups **from an external identity provider** using SCIM" and instructs you to
configure the connection *in your IdP* using the endpoint and token Identity
Center generates. It is a SCIM **server**: provisioning flows Entra/Okta/Google
-> Identity Center, never Identity Center -> a third-party application.

Earlier documentation and a test here listed it as a supported source. That was
wrong and is corrected: the test is renamed to describe the strict, spec-correct
profile it actually exercises (explicit path, real boolean, DELETE on
unassignment), the replay script's `--profile aws` became `--profile strict`, and
providers.md now explains the mistake rather than deleting it, because the trap
is easy to repeat - AWS publishes a thorough SCIM guide describing what Identity
Center ACCEPTS, which reads exactly like a description of what it SENDS.

The first question about any provider is which direction its SCIM runs.

### Live tenant validation, all providers

**Scope widened 2026-08-09.** The suite now covers the documented provisioning
cycle for Okta and Google Workspace alongside Entra, plus a strict spec-correct
client
(`the_okta_provisioning_cycle_works_end_to_end` and siblings), all written from
published vendor documentation rather than observed traffic. The item below
therefore applies to each of them, not only Entra: no provider has been synced
from a real tenant. docs/scim/providers.md says so in its support table, so
"supported" is not read as "certified".

The cheapest independent check remains Microsoft's hosted SCIM Validator, which
tests SCIM 2.0 conformance generally despite the name and needs no tenant.

**Concurrency gap CLOSED 2026-08-09, and the race was worse than assumed.**
`tools/scim-owner-race.sh` drives a real server over real HTTP with parallel
connections, which is what the in-process suite cannot do. Result:

  mutex present (shipped)  50 trials, 0 races
  mutex removed (control)  25 trials, 25 races - it fired every attempt

So the last-owner race was not a narrow window. Under genuine concurrency two
parallel deprovisions of two different Owners stranded the organization with no
Owner at all, every single time. The mutex removes it completely. The unit test
comment claiming the lock was "correct by construction, not demonstration" has
been corrected - it is now demonstrated, just not in-process.

Still open on this thread: the same treatment for externalId uniqueness under
concurrent creates, and the multi-replica case, which no single-process lock can
close. See docs/scim/testing.md "Rung 2c".

**Now running in CI 2026-08-09.** The Authentik lifecycle is automated as
`tools/scim-authentik-e2e.sh` and runs weekly and on demand in
`provisioning-e2e.yml`: 13 assertions, all passing, including database checks
that revoke preserved every membership row and its akey.

Two ordering bugs had to be fixed to get there, both of which only ever appear
in CI and are worth remembering when automating anything against Authentik:
`/-/health/ready/` reflects the server, while the bootstrap token is created by
the worker (about 5s later) and the default SCIM property mappings arrive later
still as a blueprint (about 20s). Both passed locally purely because a human
takes longer than that to type the next command.

**Partially closed 2026-08-09 - one engine has now actually run.** Authentik
(self-hosted, free, Docker) was stood up locally against this branch and drove a
full provisioning lifecycle: 46 SCIM requests, zero 4xx/5xx, no code changes.
Discovery, the existence probe, POST-then-PUT user updates, group creation and
member sync, deprovision via `active:false`, and the revoke/restore round trip
with the membership row surviving at `status = -128` with its `akey` intact.

That closes the "no provisioning engine has ever driven this" gap, though not
the vendor-quirk or concurrency ones - three users is too small to make Authentik
parallelise, so the check-then-act races were not stressed. Details and a
reproduction recipe are in docs/scim/testing.md under "Rung 2b".

**Made cheaper 2026-08-09.** `tools/scim-replay.sh` now takes
`--profile entra|okta|strict|google`, swapping the create payload and deactivation
form for that engine's documented shape, so one deployment can be validated
against all four in about a minute. docs/scim/providers.md now also lists what
each tenant actually costs to obtain - Okta is a free developer account and the
Microsoft SCIM Validator needs no tenant at all. Only Google Workspace and Entra
P1/P2 need paid plans or trials. AWS IAM Identity Center is not on the list: it
cannot drive this endpoint, so no tenant of it would help. The remaining work is running them, which needs credentials this project
does not have.

### Live Entra ID tenant validation

**What:** Run the full lifecycle against a throwaway Entra tenant: Test
Connection, assign user, create/update/deprovision/restore, group sync, token
rotation. Follow docs/scim/setup.md as written and fix any doc drift found.

**Why:** Everything is verified against RFC 7643/7644 and observed Entra
behaviour, but no real Entra sync has run against this build yet.

**Context:** User-driven (needs a tenant). Never production. The rate limiter
keys on `IP_HEADER` (`X-Real-IP`) - the deployment in front must set it.
Note that Entra automatic provisioning needs an Entra ID P1/P2 licence, so a
free tenant will not offer it.

**Cheaper rungs first** (see docs/scim/testing.md): `tools/scim-replay.sh` replays Entra's exact
request shapes at a running server, and Microsoft's hosted SCIM Validator
checks Entra compatibility without any tenant. Only assignment scoping, sync
cycles, and nested-group behaviour genuinely require a tenant.

**Effort:** M
**Priority:** P1
**Depends on:** Branch pushed and deployed somewhere TLS-fronted

### Mail-enabled invite failure path, end to end

**CLOSED for POST 2026-08-08 (review pass).** The POST half is pinned by
`smtp_outage_keeps_the_membership_and_does_not_fail_the_request` (mail enabled,
`fail_sends_guard`, 201 asserted, membership and account survive, no silent
replay after recovery). **Still open: the RESTORE half.** `restore_member` has
its own independent mail branch (re-inviting a member restored to Invited) whose
failure must likewise return 200 with the membership already restored; a
regression propagating that error would break every restore-after-outage cycle
and no test would catch it. Same `fail_sends_guard` mechanism, so this is now a
small addition rather than new scaffolding.

**What:** An integration test that runs `post_user` with mail enabled and a
failing SMTP target, asserting that the membership SURVIVES, the response is
201, and the failure is logged.

**Why:** As of 2026-07-25 an invite-mail failure no longer rolls back and no
longer returns 500. Returning 5xx on every retry turned a transient SMTP outage
into an Entra tenant quarantine, and it disagreed with `restore_member`, which
had always logged and carried on. Nothing currently proves the new behaviour.

**Superseded:** the earlier version of this item asked for a test asserting
"the 500 plus the rollback outcome". That code path no longer exists. Rollback
is now reachable only when `member.save()` itself fails, and the decision logic
is covered directly by `provisioning_rollback_spares_preexisting_users`.

**Context:** Needs mail enabled in `CONFIG` plus a fast-failing SMTP endpoint;
naive versions are slow or flaky. Use the `scim::test_config` override added for
the config-gated denial tests.

**Effort:** M
**Priority:** P2
**Depends on:** Config-gated denial tests (shared override mechanism)

### Coverage: error-envelope edges and manage HTTP surface

**Done 2026-07-26 (CSO + review pass):** HTTP-level 429 envelope with the
`Retry-After` header (`a_throttled_request_gets_a_scim_429_with_retry_after`,
driven end to end by spoofing `X-Real-IP` at a drained synthetic bucket); the
manage endpoints over HTTP, now including the Owner-vs-Admin authorization
matrix (`only_an_owner_can_mint_or_revoke_the_scim_credential`); the GroupPatch
path-less object form for ignored attributes
(`ignored_attributes_are_also_tolerated_in_the_path_less_form`); and the
oversized-member-list refusal on all three write paths.

**Correction 2026-08-08 (review pass):** three items previously listed here as
open are in fact covered, and were re-verified against the suite:
malformed-body 400 and oversized-body 413 envelopes by
`malformed_and_oversized_bodies_stay_in_the_scim_envelope`; POST /Users
missing/invalid/empty userName 400s by the same test plus
`every_emitted_scim_type_reaches_the_wire_with_its_rfc_status`.

**Closed later the same day (follow-up pass).** Four of the five below now have
tests: the policy-blocked restore 400
(`a_policy_blocked_restore_is_refused_and_leaves_the_member_revoked`, which also
asserts the row stays revoked, plus a policy-disabled control so the refusal
cannot be explained by restore being broken); the POSITIVE externalId filter
match on both endpoints (`external_id_filters_find_the_resource_they_name`); the
sequential dup-externalId 409 on POST /Groups
(`a_sequential_duplicate_group_external_id_is_a_409`); and the SMTP-failure-
during-restore path (`an_smtp_outage_during_restore_still_restores_the_member`).

**Closed 2026-08-08 (final pass).** POST /Groups blank-name 400
(`post_groups_refuses_a_blank_or_missing_display_name`, covering empty,
whitespace-only and absent, verified to fail without the guard); query-parameter
tolerance including the single-group GET form
(`unimplemented_query_parameters_are_tolerated`); the `emails.value` alias
(`the_emails_value_filter_alias_resolves`); and the 405 envelope
(`a_method_not_allowed_stays_in_the_scim_envelope`). Nothing from the original
coverage list remains open.

**Superseded note:** POST /Groups blank-name 400 - the guard exists
(`display_name.filter(|n| !n.trim().is_empty())`) but only its PUT and PATCH
equivalents are pinned, so a POST with `""`, `"   "` or the attribute omitted is
untested.

Lower-value gaps also surfaced and deliberately left: `?attributes=` and
`excludedAttributes` tolerance on /Users (Microsoft's hosted SCIM Validator
sends these, and they currently work only because Rocket's FromForm derive is
lenient), the 405 catcher envelope, the `emails.value` filter alias, and
`excludedAttributes` on a single-group GET.

**Why:** These are the branches where a regression would surface to Entra as a
wrong status code or envelope, currently proven only by adjacent coverage.

**Context:** All testable in the existing Rocket-local harness. The manage
endpoints now need an **OwnerHeaders** fixture, not AdminHeaders - minting was
tightened to Owner on 2026-07-26; `seed_admin_session` already takes the
membership type, so this is a parameter change, not new scaffolding.

**Effort:** M
**Priority:** P2
**Depends on:** None

### Performance backlog for large orgs - CLOSED 2026-07-26

**Done 2026-07-25:** group member writes now diff instead of
delete-all+reinsert (`set_members`), and list responses load the whole page's
membership in one `eq_any` query (`GroupUser::find_by_groups`) rather than one
join per group.

**Done 2026-07-26 (CSO + review pass):**

- **SQL-side pagination** for both list endpoints
  (`Membership::find_by_org_paged`, `Group::find_by_organization_paged`). This
  turned out not to be only a performance item: the in-memory slice had no
  `ORDER BY`, and a client pages across separate requests, so two pages could
  disagree and a member could land on both or neither. On PostgreSQL that is
  reachable in practice because a concurrent revoke is an `UPDATE` and an
  `UPDATE` relocates the row - a silent skip during a full sync. Pinned by
  `user_paging_covers_every_member_exactly_once`.
- **Secondary indexes added** - reversing the earlier "skip the indexes"
  recommendation. That call was made on the argument that it diverges from
  upstream convention for an unmeasurable difference. It did not survive
  noticing that `users_organizations` is **global across all organizations**,
  not per-org, so an unindexed `external_id` lookup scans every membership on
  the whole server once per provisioned user. That is a full scan of the
  largest table on the hottest path, not a self-host-scale rounding error.
  Shipped as their own migrations rather than appended to the table migration,
  because MySQL DDL is not transactional and a failure partway through left the
  database unmigratable. **Split again on 2026-07-26 (second review pass)** to
  ONE `CREATE INDEX` per migration
  (`...000001_unique_users_organizations_external_id`,
  `...000002_unique_groups_external_id`), because separating the indexes from
  the *table* did not separate them from *each other*: two non-idempotent
  statements still shared one non-transactional migration, so a failure on the
  second left the first committed and unrecorded and every retry died on
  "Duplicate key name". MySQL supports neither `CREATE INDEX IF NOT EXISTS` nor
  `DROP INDEX IF EXISTS`, so one statement per migration is the only retryable
  shape.
- **Batched member resolution** (`Membership::find_by_uuids_and_org`, chunked
  at 500 for older SQLite's 999 bound-parameter cap). A 1000-member group
  write was ~2000 sequential round trips on one pooled connection.
- **Aggregate owner counts** in `/scim/status` instead of loading every
  membership row.
- **One fewer query per POST /Users** (the account was looked up twice).

**Still open:** none for lists. Group `displayName` filtering still loads the
org's groups and compares in Rust, because the three backends disagree on
collation defaults and group counts are bounded in a way membership counts are
not. Revisit only if an org appears with thousands of groups.

**Effort:** M **(done)**
**Priority:** ~~P3~~ closed
**Depends on:** None

### Harden SCIM write edges surfaced by adversarial review

**What:** Three lower-severity robustness gaps from the 2026-07-19 adversarial
pass: (1) externalId uniqueness is check-then-set with no backing DB unique
index, so concurrent writes could duplicate the correlation key; (2) a Group
displayName > 100 chars or externalId > 300 chars from Entra hits the MySQL
column limit and returns a 500 instead of a 400 invalidValue; (3) `scim_status`
returns key metadata behind only an AdminHeaders session with no password/OTP
re-auth, unlike generate/delete.

**Why:** None are exploitable today (single Entra sync engine; strict-mode MySQL
only; admin session required), but each is an unenforced invariant or an
inconsistent guard that a future change could turn into a real bug.

**Why not now:** (1) wants a migration adding a partial unique index across three
dialects - real schema work, deferrable; (2) wants length validation in the
Group handlers; (3) is a one-line guard tightening. Bundle them.

**Gap (2) CLOSED 2026-07-26 (second review pass).** `check_attribute_len`
(`src/api/scim/mod.rs`) caps externalId and Group displayName at
`SCIM_MAX_ATTRIBUTE_LEN` = 300 - the narrowest column any of them lands in
(`groups.external_id` is VARCHAR(300) on mysql and postgresql) - and returns 400
`invalidValue` before the write. This also closed a hazard the new postgresql
`(org_uuid, external_id)` index introduced: that column is TEXT there, and a
plain btree entry caps at about 2704 bytes, so an unvalidated externalId turned
a legal request into a hard write failure on one backend only. Pinned by
`over_long_attributes_are_refused_with_400_not_500`, which also asserts the
boundary is inclusive.

**Note (2026-07-26):** the composite `(org_uuid, external_id)` indexes on
`users_organizations` and `groups` are **non-unique** - added for lookup cost,
not as a constraint. Gap (1) therefore stands unchanged:
the check-then-set race is still unbacked. Anyone closing it can add
`UNIQUE` to that existing index rather than authoring a new one, which makes
this cheaper than when it was written. Gap (3) also stands, deliberately:
`scim_status` was left on `AdminHeaders` when minting moved to `OwnerHeaders`,
because it only returns metadata an org admin can already see.

**Note (2026-07-25):** the membership analogue of (1) is NOT a gap. All three
dialects already carry `UNIQUE (user_uuid, org_uuid)` on `users_organizations`
from the original 2018/2019 create-tables migration (verified against the live
sqlite schema, not just by grep). `post_user` now maps that constraint violation
to 409 `uniqueness` instead of 500. Only the `external_id` column is unbacked.

**Effort:** M
**Priority:** P2
**Depends on:** None

### Residual gaps from the 2026-07-26 adversarial pass

**What:** Four items the red-team pass raised that were recorded rather than
fixed, all lower severity than the ones that were.

1. **A policy-blocked restore still commits an externalId change made in the
   same body.** `precheck_active_change` deliberately does NOT call
   `OrgPolicy::check_user_allowed`, because that function is not the predicate
   it looks like: with `EMAIL_2FA_AUTO_FALLBACK` set, an org enforcing the
   TwoFactorAuthentication policy, and a member holding no 2FA, it calls
   `two_factor::email::find_and_activate_email_2fa`, which SAVES a TwoFactor
   row. Hoisting it into the precheck would move a persistent account mutation
   ahead of the externalId write - causing exactly the half-applied failure the
   precheck exists to prevent. Closing this properly needs a read-only policy
   predicate split out of `check_user_allowed`, which is upstream surface.
   The privileged-restore and last-owner refusals ARE precheck-covered, so the
   common cases write nothing.

2. **An organization whose sole Owner is Invited or Accepted is a dead end for
   SCIM.** The last-owner guard now counts ACTIVE owners, so that Owner can no
   longer be deprovisioned - correct, it is the only administrator - but
   `reject_privileged_grant` also refuses to restore a privileged membership, so
   Entra will re-send the refused `active:false` every cycle. The remedy is in
   the web vault (confirm a second Owner, or remove the member there); it is
   worth a line in operations.md if anyone hits it. Previously this case
   silently succeeded and left the org with no owner at all, which was worse.

3. **The active-change guard is evaluated twice per request** - once in
   `precheck_active_change` and once inside `revoke_member`/`restore_member` -
   so a PUT/PATCH carrying `active` costs one extra
   `count_active_by_org_and_type`. Deliberate for now: having the precheck
   return a decision the writers consume would put the guard in one place but
   couples them, and the query is a single indexed COUNT. Revisit if the write
   path ever shows up in a profile.

4. **An Invitation row created for a PRE-EXISTING account is now taken back on
   rollback** (`rollback_provisioning`), closing a standing signup-bypass leak.
   Not a gap any more; recorded because the asymmetry is easy to reintroduce -
   only `User::delete` clears an invitation, and that path runs only when this
   request also created the account.

**Effort:** S each (item 1 is M, and touches upstream code)
**Priority:** P3
**Depends on:** None

### Deferred items from the 2026-07-25 review

**What:** Lower-priority findings recorded rather than fixed:

- ~~`put_user`/`patch_user` commit an externalId change before attempting the
  active change, so a 400 from the second step leaves the first persisted.~~
  **Closed 2026-07-26:** `precheck_active_change` runs every guard the `active`
  transition would hit before the first write, so a refused request writes
  nothing. Pinned by
  `a_refused_active_change_rolls_back_nothing_because_it_writes_nothing`.
- Deleting a group also deletes its collection-group access grants, which the
  design reserves as an in-app admin decision.
- SCIM key lifecycle: no expiry. (`last_used_at` and the `enabled` kill
  switch both shipped on 2026-07-26 - see "SCIM token lifecycle" below, which
  is the single source of truth for what is left.)
- DRY: `put_user`/`patch_user` share a 15-line tail; two `list_response`
  builders exist; `log_scim_event`/`log_group_event` are the same wrapper.
- `meta.created` / `meta.lastModified` are not emitted **on User resources**,
  though `Membership` has no revision column to emit them from. Groups do emit
  both (`groups.rs:96`), so this item is now Users-only. With `etag`
  unsupported there is still no change-detection signal for a client doing
  incremental reconciliation of users.

**Effort:** M (as a whole; each item is S)
**Priority:** P3
**Depends on:** None

### Outstanding test coverage - what is genuinely left

**Most of the 2026-07-25/26 plan is now closed.** 161 tests (132 SCIM), green on sqlite, mysql and postgresql. What
remains, with the reasoning for each:

**1. OIDC token exchange - not tested.** Suite C seeds `SsoAuth.auth_response`
and so starts *after* `sso::exchange_code`. Signature verification, nonce
binding, PKCE and the discovery round trip are therefore unexercised. Closing it
needs the stub issuer originally scoped as H3 (discovery doc, JWKS, RS256
signing). **Effort L, value moderate** - that code is upstream's and shared with
every non-SCIM SSO deployment, so it is not SCIM-specific risk.

**2. Microsoft SCIM Validator (Suite H1) - manual.** Needs a publicly reachable
URL, so it cannot run in-process. Every other Suite H case (H2-H7) is now
written and green. **Effort M**, mostly tunnel setup.

**3. Connection-pool exhaustion (T5).** Property/fuzz is done (40k inputs across
both parsers); resource exhaustion is not. **Effort M.**

**4. Live Entra tenant (T4).** Tracked separately below.

**5. Deterministic clock (H5) - partial by decision.** Limiter *recovery* is
covered by waiting out the 1s window the test env pins. Full clock injection was
rejected because `governor` holds its clock in the `LazyLock` statics in
`ratelimit.rs`: injecting one means making production types generic and swapping
a static at runtime - a real change to shipping code for test-only benefit.
**Revisit if token expiry is ever added**, since an expiry window cannot be
waited out in a test.

**Also open, recorded in design.md rather than here:** whether SSO account
creation should honour `INVITATIONS_ALLOWED`. It currently does not, making SSO
a wider door than the SCIM path. Upstream policy decision - see "An asymmetry
this design does not resolve".

**New tooling from this round** (do not rebuild): `tools/scim-test-config-matrix.sh`
re-runs the suite under a different server config, which is the only way to
cover both branches of a setting `CONFIG` pins at startup. Currently one
dimension (`SSO_ONLY`); add rows as more appear.

**Effort:** L (as a whole)
**Priority:** P2
**Depends on:** a stub issuer for item 1; a public URL for item 2

### SCIM token lifecycle - PARTLY CLOSED 2026-07-26

**Done:** `last_used_at` on `scim_api_key`
(`2026-07-26-000003_add_scim_api_key_last_used`), written by the guard only
after the secret verifies and rate-limited to one write per hour per org so a
full sync does not become thousands of UPDATE statements. Surfaced as `lastUsedAt` on
`GET .../scim/status`, and reset on rotation so a new credential never inherits
the old one's activity. The `enabled` flag is now wired to
`PUT .../scim/api-key/enabled` (Owner + password/OTP) as a reversible kill
switch, so provisioning can be paused without destroying the digest and
re-pasting a token into Entra. Pinned by four tests including a rejected-request
case (a failed auth must not keep the field warm).

**Still open:** the token has no *expiry*. Nothing forces rotation on a
schedule, and it is still not invalidated when the Owner who minted it is
demoted or leaves. Closing that means either a `valid_until` column with a
background sweep, or tying key validity to the minting membership - the second
is more correct and more invasive.

**Mitigation today:** minting and deleting require Owner, rotation is provably
effective, `lastUsedAt` makes a stale key visible, and the kill switch makes
pausing cheap.

**Effort:** M
**Priority:** P3
**Depends on:** None

### DESIGN: JIT / PAM-brokered temporary access to sensitive collections

**What:** Let a PAM or ITSM approval workflow grant a member time-boxed access
to a sensitive collection, then remove it automatically.

**Feasible today with no new code, at the group layer.** `CollectionGroup`
(`src/db/models/group.rs:35`) maps a collection to a group with `read_only`,
`hide_passwords` and `manage` flags, and SCIM already owns group membership
while deliberately not touching collection access. So:

1. Admin creates the collection and a `jit-<system>` group, and grants the group
   access to the collection **once**, in the web vault. SCIM never changes this.
2. The matching directory group is provisioned to Vaultwarden by SCIM.
3. Entra PIM for Groups (or ServiceNow / Okta Workflows) owns approval and
   expiry, and adds the requester to the directory group for N hours.
4. SCIM syncs the membership in, and syncs it out again when PIM expires it.

**The honest limitation, which is the whole design problem:** removing access
does **not** un-see the password. Once a client has synced the item the user has
it, and expiry only stops future reads. Real PAM solves this by brokering the
session or rotating the credential on check-in; Vaultwarden cannot broker, so
**the only true revocation is rotating the secret itself**. A JIT scheme without
rotation is an audit trail, not a control - it should be described that way to
whoever asks for it.

**Second limitation:** SCIM sync is a polling cycle (commonly ~40 minutes), so
both grant and revoke are eventually-consistent. "Just in time" is really "some
time in the next cycle". Acceptable for change-window access; not acceptable if
the control needs to be immediate.

**What closing the rotation gap would need:** a headless rotation worker that,
on check-in, rotates the credential in the target system and writes the new
value back to the vault item. Writing an item requires the organization key, so
the worker has to be a confirmed member holding it - the same shape as the
confirm-worker in CLAUDE.md, and with the same objection: it is a long-lived
identity with standing access to the very collection the scheme exists to
protect. That is a PAM problem in its own right and should not be built without
deciding where that identity's credential lives (see docs/scim/deployment.md).

**Recommendation:** implement steps 1-4 as an operational pattern, document the
rotation caveat prominently, and for genuinely high-value infrastructure
credentials keep them in a real PAM rather than the shared vault. Revisit the
rotation worker only if a concrete requirement survives that recommendation.

**Effort:** S for the operational pattern (documentation only); L for the
rotation worker
**Priority:** P3
**Depends on:** Live Entra tenant validation (PIM for Groups needs a tenant to
verify sync latency against)

### CLOSED 2026-08-09: the web vault DID surface a dead SCIM control

**Resolved by inspecting the pinned web-vault image** rather than waiting for a
browser session. The blocker below said the web-vault directory is a gitignored
download and cannot be inspected from source - true, but it is also a Docker
image pinned by digest in the Dockerfile, so `docker create` plus `docker cp`
gets the exact bundle that ships.

**Finding: setting the flag true adds a SCIM link that leads nowhere.**

- `canManageScim` is `(isAdmin || permissions.manageScim) && useScim`, and it
  gates a side-nav item whose route is `settings/scim`.
- That route is **not registered**: zero occurrences of `{path:"scim"}` in the
  bundle. Upstream hardcodes the flag false, so the settings page is dead code
  the build strips - but the nav entry lives in shared library code and survives,
  gated only on the flag.
- Even with the page present it could not work. The vault builds its SCIM URL
  from `urls.scim`, which is set to **null** for the SelfHosted region, and the
  only SCIM hosts in the bundle are scim.bitwarden.com and its EU/gov siblings.
  It has no way to reach this fork's `/api/organizations/<id>/scim/api-key`.

**Action taken:** both lines reverted to `"useScim": false`, with the evidence
recorded in the code comment so the next person does not have to redo this.
Provisioning stays on the documented flow in docs/scim/setup.md Part B. Revisit
only if the web vault ships a self-hosted SCIM page.

**Effort:** S **(done)**
**Priority:** ~~P1~~ closed

### Superseded: the original blocked item

**What:** `Organization::to_json` and `Membership::to_json` now report
`"useScim": CONFIG.scim_enabled()` where upstream hardcoded `false`. Load the
web vault as an org Owner with `SCIM_ENABLED=true` and check whether a SCIM
section appears, and if it does, whether it works.

**Why:** This is the only change on the branch that is directly visible in the
web vault UI, and it is unverified. If the vault renders a SCIM configuration
page it will call Bitwarden's endpoint shapes, not this fork's
`/api/organizations/<id>/scim/*`, and will fail. Users would find controls that
look broken.

**Blocked on:** the `web-vault` directory is a separate gitignored download and
is not present in this checkout, so it cannot be inspected from source.

**If it does surface dead controls:** revert both lines to `false` and keep
driving everything through the documented curl flow in docs/scim/setup.md
Part B. There is precedent one line above - `"useDirectory": false, // Is
supported, but this value isn't checked anywhere (yet)`.

**Effort:** S
**Priority:** P1
**Depends on:** A built web vault

### Residual items from the 2026-08-08 review + CSO pass

**Update, same day (follow-up pass).** Items 1, 2 and 3 below are now CLOSED;
the text is kept because the reasoning still explains the shape of each fix.
Item 1 (delete_group ownership) shipped with a regression test verified to fail
without the guard. Item 2 (last-owner race) is only PARTLY closed - the
duplicated guard is now one helper, but the check-then-act race is NOT fixed;
see the revised note under that item. Item 3 (externalId UNIQUE index) shipped
as six migrations validated on all three backends, including a dedup step proven
against a database seeded with duplicates. Items 4 and 5 remain open and both
turned out to be larger than "small" - see the revised notes.

Three defects from this pass are **fixed and pinned** (see commit
"close the group-adoption escalation and two write-path defects"): the group
externalId adoption escalation, the non-atomic Group PATCH that granted access
without logging it, and the uncapped displayName. What follows is what the same
pass surfaced and deliberately did **not** change.

**1. `delete_group` has no ownership guard. CLOSED 2026-08-08.** Resolved the
strict way: SCIM now refuses to delete a group that grants collection access and
carries no externalId (or carries access_all), the same set additions are
refused for. The Entra cost noted below is real but bounded - a failing delete
retries, but only for groups SCIM never managed, which Entra has no reason to
delete. Original note follows.

 A token holder can enumerate every
group in the org (`GET /Groups` returns all of them) and DELETE any of them,
including admin-curated groups that grant collection access, wiping their
`collections_groups` mappings. Unlike memberships this carries no E2EE state and
is recoverable by re-creating the group and re-granting, so it is destructive but
not unrecoverable - which is why the feature's revoke-never-delete posture does
not already cover it. The open question is a policy one: should DELETE refuse an
unmanaged access-granting group the way additions now do, or is delete-is-
recoverable acceptable? Refusing it has an Entra cost (a failing delete retries
every cycle and can quarantine the app). **Effort:** S. **Priority:** P2.

**2. Last-owner guard is check-then-act. PARTLY CLOSED 2026-08-08 - the race
is STILL OPEN.** The duplicated guard is now a single helper called from both
paths, which removes the drift risk and one redundant count query per
owner-revoke. The race itself is not fixed, and the investigation changed what
the fix has to be: a single conditional UPDATE does NOT close it, because the
two concurrent requests target DIFFERENT rows, so their row locks never conflict
and both snapshots still read the pre-revoke count. Closing it needs
SERIALIZABLE isolation, a lock on a row both requests contend on, or a
maintained counter column on organizations - and this codebase uses no
transactions and no row locking anywhere, so it is an architectural decision
rather than a local fix. A counter column would also have to be maintained by
every non-SCIM path that changes owner status, or it drifts and starts refusing
legitimate revokes. Original note follows.

 `precheck_active_change` and
`revoke_member` both count active Owners and refuse at `<= 1`, outside any
transaction. Two concurrent revokes targeting two different Owners can each
observe a count of 2 and both proceed, leaving the org with zero active Owners -
a state SCIM itself cannot repair, because `reject_privileged_grant` refuses to
restore a privileged membership and a revoked Owner has no session. Entra
normally serialises writes, so this needs parallel sync workers to trigger. Fix
is a conditional UPDATE that revokes only when a subquery still counts more than
one active Owner, checking affected rows. The duplicated guard should collapse
into one helper at the same time (it is currently copy-pasted, and the count runs
twice per owner-revoke request). **Effort:** M. **Priority:** P2.

**3. externalId uniqueness. Closed 2026-08-08, REOPENED and properly closed
2026-08-09 - the first closure was wrong in a way that made things worse.**

The six migrations landed and the invariant looked backed. It was not. Both
`Membership::save` and `Group::save` use `diesel::replace_into` on sqlite and
mysql, and `REPLACE` resolves a conflict on ANY unique index by DELETING the
conflicting row and returning success. So adding the UNIQUE index did not make a
duplicate *fail* - it made a duplicate destroy a different member, taking the
`akey` that wraps their copy of the organization key, which under E2EE nobody
can reconstruct. Verified by experiment against the shipped index, not by
reading. The "the write paths now answer a lost race with the same 409" claim in
the original closure was therefore false on two of the three backends: the
recovery code never ran, because `save()` returned `Ok`.

Reachable two ways, and the second needs no concurrency at all: two concurrent
writes on any backend, and on mysql a pair of externalIds sharing a 150-character
prefix, because the index covers a prefix and the application compares the whole
300-character value.

**Closed properly by `Membership::save_strict` / `Group::save_strict`** (an
explicit UPDATE-then-INSERT, so the database raises the violation) plus
`is_unique_violation`, which asks the error rather than re-reading the row - a
re-read cannot see the mysql prefix case and answered a genuine duplicate with a
500. Pinned by `the_unique_index_refuses_a_duplicate_external_id_without_destroying_the_holder`
and `the_scim_write_helpers_answer_a_conflict_with_409_and_destroy_nothing`, the
second of which fails if either handler goes back to `save`.

**The lesson worth keeping: never add a UNIQUE index to a table whose write path
is `replace_into`.** The index does not become a constraint there, it becomes a
delete trigger.

Two smaller corrections to the original note. The dedup keeps an ARBITRARY row,
not the oldest - `MIN(uuid)` over random v4 uuids has no relation to age, and
`users_organizations` has no timestamp to order by. And the postgresql migration
now also clears values over 2000 bytes, because that column is unbounded TEXT
there, upstream's `ldap_import` applies no length check, and a single over-long
pre-existing row would make `CREATE UNIQUE INDEX` fail - which, before Rocket
listens, is a server that never starts. Original note follows.

 Now confirmed by two
independent passes: all six new composite indexes are plain `CREATE INDEX`, so
every uniqueness check remains application-level check-then-set. Concurrent
writes can commit duplicate correlation keys, after which
`find_by_external_id_and_org` resolves via `.first()` and a later sync binds to
an arbitrary one - the IdP can then update or deprovision the wrong member.
postgresql and sqlite can take a straight `CREATE UNIQUE INDEX` (NULLs stay
duplicable on both). MySQL is the awkward one: its index is a 150-char prefix, so
a UNIQUE prefix index would falsely reject distinct values sharing a prefix.
GUID-shaped externalIds are unaffected, but the divergence needs a decision
rather than a silent shrug. **Effort:** M. **Priority:** P2.

**4. `scim_status` has no step-up re-auth. CLOSED 2026-08-08, differently than
proposed.** Resolved by tightening the ROLE gate (AdminHeaders -> OwnerHeaders)
rather than adding the step-up. A step-up needs a request body, so it would have
forced this GET to become a POST - a breaking change to the endpoint's shape,
for a read - while closing the same gap. The endpoint reports credential state,
lastUsedAt and the directory-linked Owner count, and an Admin is exactly the
role that cannot mint, revoke or disable the credential that data describes.
Pinned by the existing Owner/Admin matrix test, extended to cover status;
verified load-bearing (an Admin read it with a 200 before the change). Original
note follows.

 `scim_status` is a GET with no body, so requiring
`PasswordOrOtpData::validate` means changing it to a POST: a breaking change to
the endpoint's HTTP shape, plus its docs and tests. Worth doing, but it is an API
decision rather than the one-line guard tightening this item originally
described. Original note follows.

 It returns SCIM key metadata
(configured, enabled, createdAt, revisionDate, lastUsedAt) behind an
`AdminHeaders` session alone, while its siblings `generate_scim_key` and
`delete_scim_key` both require `PasswordOrOtpData::validate`. No token material
is exposed, so this is an inconsistent guard rather than a leak - but it is the
kind of asymmetry a later change turns into one. Either require the step-up or
document why read-only metadata is exempt. **Effort:** S. **Priority:** P3.

**5. Credential audit events are indistinguishable. STILL OPEN - blocked on a
protocol decision.** The only mechanism for distinguishing these is the
EventType enum, whose values are Bitwarden wire-protocol constants that real
Bitwarden clients switch on. The Event model carries no free-text detail field.
So closing this means either minting new EventType values inside Bitwarden's
numbering space (risking collision with a future upstream definition) or outside
it (clients render an unknown type). Neither is obviously right, and picking one
unilaterally in a review pass would put non-standard values on a wire protocol
this fork otherwise implements faithfully. Needs an explicit call. Original note
follows.

 Mint, rotate, delete and
the enable/disable kill switch all log `EventType::OrganizationUpdated`, so the
org event log cannot tell a credential mint from any other org configuration
change. Actor identity, device type and IP are recorded correctly, so this is a
granularity gap, not a missing-audit gap - but at a SOC2 bar an auditor
reconstructing "who could provision, and when" has to correlate timestamps
against the `scim_api_key` row instead of reading the event stream. Distinct
event types would close it. **Effort:** S. **Priority:** P2.

**6. Group PATCH remains non-atomic for its own attributes.** The member-op half
is now pre-resolved, but displayName and externalId still commit via
`group.save` before the member loop runs. A body mixing a rename with a member op
that fails inside `apply_member_op` (rather than in the precheck) leaves the
rename persisted. The precheck makes this much harder to reach; closing it fully
needs either a transaction or per-op event logging. **Effort:** M.
**Priority:** P3.

### Residual items from the 2026-08-09 review pass

The pass that found the `replace_into` data-loss path (item 3 above) also closed
a long list of smaller things. What it deliberately did NOT close:

1. **`externalId` uniqueness is case-dependent on the dialect.** MySQL's default
   `utf8mb4` collation is case- and accent-insensitive, so `ABC` and `abc` are
   one key there and two on sqlite and postgresql - at migration time MySQL
   silently clears one of the pair, and at runtime
   `find_by_external_id_and_org` can resolve a differently-cased externalId to,
   and deprovision, a different member than the other backends would. Entra
   sends lowercase GUIDs so it is unreachable there; some LDAP DN sources mint
   case-varying values. Closing it means either normalising case in the
   application before every lookup and write, or adding `COLLATE utf8mb4_bin` to
   the MySQL index and the lookups. Both are a semantic decision, not a fix.
   Documented in `docs/scim/upgrading.md`. **Effort:** M. **Priority:** P3.

2. **The MySQL 150-character prefix still means uniqueness is enforced over less
   than the full value.** A pair of externalIds differing only after character
   150 now returns a correct 409 rather than a 500, so the failure mode is
   sound - but it is a *false* 409 on that backend and a successful write on the
   other two. Lowering `SCIM_MAX_EXTERNAL_ID_LEN` to 150 would make all three
   agree at the cost of refusing values the RFC permits. **Effort:** S.
   **Priority:** P3.

3. **The `scim-race-control` build feature is a test-only escape hatch that
   ships in `Cargo.toml`.** It compiles out the last-owner mutex so
   `tools/scim-owner-race.sh` can measure the race, and CI requires the harness
   to fail against it. Nothing prevents someone enabling it in a release build
   except the comment saying not to. A `compile_error!` guarded on
   `debug_assertions` would, at the cost of making the CI control binary a debug
   build. **Effort:** S. **Priority:** P3.

4. **`tools/scim-authentik-e2e.sh` pins `AUTHENTIK_TAG=2025.8`.** Chosen without
   being able to verify the tag resolves; if the weekly job fails at pull time
   that is the line to change. The failure is loud, which is the point - the
   previous arrangement fetched an unpinned compose file at run time and could
   not fail, it just tested a different Authentik each week. **Effort:** S.
   **Priority:** P3.

5. **Group PATCH is still non-atomic for its own attributes.** Unchanged by this
   pass and recorded above; the guard-ordering fix removed the wrong-answer case
   but not the partial-write case.

**Effort:** S each. **Priority:** P3.

## Enterprise feature upgrades

Tracked in full in `docs/enterprise-roadmap.md` **on the
`docs/enterprise-planning` branch**, not here and not on this branch. That
document is the single source of truth for the post-SCIM feature programme:
twenty items, each scoped to its own branch off `main`, each independently
reviewable and independently upstreamable. It lives off `main` because its
source citations are pinned to `main`, and because a SCIM reviewer should not
have to read it.

Items 1 to 12 came from the "can this run a 100-person company" gap analysis:
event log retention and export; the MaximumVaultTimeout and
DisablePersonalVaultExport policies; the AutoConfirm policy plus the
confirm-worker; RequireSso; per-org SSO binding; real custom roles; claimed
domains; admin panel identity; backup tooling beyond SQLite; HA readiness; object
storage by default.

Items 13 to 20 came from the feature survey in
`docs/enterprise-feature-parity.md` (same branch) - a
feature-by-feature comparison against Bitwarden across all editions plus ideas
from 1Password, Keeper, CyberArk and Delinea: IP allow-listing, device approval,
SIEM webhooks, time-limited grants, per-org retention, passkey login,
request-and-approve access, and one item held back (see below). Both documents
record what was deliberately **not** planned, with reasons, so the same ideas do
not get re-proposed.

**Item 13 is withheld from this file pending coordinated disclosure.** It is an
authentication-hardening item rather than a feature, and it is the one entry on
the roadmap whose details should reach the upstream maintainer before they reach
a public branch. The description lives only on the local
`docs/enterprise-planning` branch, which is deliberately unpushed, and in the
local session handoff.

> **Do not restore the detail here, and do not push
> `docs/enterprise-planning`, until upstream has been notified through their
> `SECURITY.md` process and has had a reasonable chance to respond.** Note that
> upstream's own exclusions put "missing security best practices that do not
> directly lead to a vulnerability" on the normal issue tracker instead, so they
> may redirect it - that is their call to make, not ours to pre-empt. Once
> notified, or once redirected, this paragraph can be replaced with the full
> text and the branch published.

The roadmap also records the distinction that decides sequencing: upstream's
`// Not supported (Not AGPLv3 Licensed)` markers are a deliberate refusal and
need a provenance discussion **before** code, whereas a plain `// Not supported`
or `// not implemented yet` is an ordinary contribution. `AutoConfirm` is in the
second category, which is why it is the most valuable and most upstreamable of
the hard items.

Anything SCIM-specific stays in this file. Anything on that list gets its own
branch and does not depend on `feature/scim-v2`.

**Deployment-side companion:** `docs/enterprise-network-hardening.md` (same
branch) is the operational half - what to do about these gaps before code
closes them.
It carries a verified route-by-route exposure map for the eight mount points at
`main.rs:586-593`, three deployment postures with the trade-offs of each, egress
and SSRF control, and blast-radius containment for a compromised user, admin,
SCIM credential or host. It is documentation only and needs no branch of its own.

Two findings from it that are code-relevant, recorded here so they are not lost:

- **`X-Real-IP` must be overwritten by the proxy, and the proxy must be
  trusted.** All four limiters in `ratelimit.rs` (login, admin, SCIM, and
  upstream's unauthenticated one) key on the client IP and all four run before
  authentication. Upstream #7472 changed the risk profile: `IP_HEADER` is now
  read only from a peer covered by `IP_HEADER_TRUSTED_PROXIES`, so a forwarded
  header no longer lets a caller pick their own bucket - that bypass is closed
  unless an operator sets the list to `all`. What remains, and is now easier to
  hit by accident, is starvation: an untrusted proxy means every request falls
  back to the peer address and shares one bucket, and setting `IP_HEADER`
  correctly does not fix it. Fails silently at default log levels.
- **`deauth_user` is a stronger containment primitive than it looks**
  (`admin.rs:463`): resetting the security stamp invalidates every outstanding
  access token immediately via the guard check at `auth.rs:668`, rather than
  waiting for expiry. Worth keeping in mind if session revocation ever gets an
  org-scoped equivalent.

## Upstream hygiene

### gitleaks: upstream historical findings (RESOLVED - allowlisted)

**Status: closed via `.gitleaks.toml`.** `gitleaks detect` now reports **no
leaks** across all 2277 commits, so a genuinely new leak will stand out instead
of being lost among ten known-benign ones.

**What the 10 findings were.** All upstream commits dated 2018-2021; none in
this branch's work.

| Count | Pattern | Assessment |
|---|---|---|
| 4 | `apk-key-hash:` | False positive - a public FIDO/U2F fingerprint, published by design |
| 1 | `stripeKey:` | False positive - a Stripe *publishable* key. File gone from HEAD |
| 2 | `password":` | False positive - example request bodies in comments |
| 3 | `ADMIN_TOKEN=` | `.env` is gone from HEAD and now gitignored, so the live exposure was already remediated upstream. `.env.template` still ships two commented-out real-looking examples |

**Validated, not assumed.** The allowlist was checked against a planted-secret
probe: detection is **identical with and without** the config (both catch a
planted `sk_live_` key), so it suppresses only the ten known findings and does
not weaken scanning of new content.

**History was deliberately NOT rewritten** - it would break the fork
relationship and every merge from upstream, for values that are public by design
or already removed. See branch discipline in CLAUDE.md.

**Left open upstream:** shipping a real-looking `ADMIN_TOKEN` as a
copy-pasteable example in `.env.template` is a mild footgun. Worth raising as a
docs issue upstream; not ours to change here.

**Effort:** done
**Priority:** -

### ip_constant clippy lints in http_client.rs tests

**What:** 9 pre-existing `clippy::ip_constant` errors in upstream
`src/http_client.rs` test code under `--all-targets` with the 1.96 toolchain.

**Why:** Blocks running `cargo clippy --all-targets` clean locally; will bite
if CI ever lints test targets.

**Context:** Upstream code, untouched per branch discipline. Fix as a separate
commit or PR upstream (`Ipv4Addr::LOCALHOST` instead of hand-coded addresses).

**Effort:** S
**Priority:** P3
**Depends on:** None

## Completed
