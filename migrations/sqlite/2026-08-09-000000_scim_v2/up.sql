-- The whole SCIM v2 schema, as one migration.
--
-- This collapses what were six migrations (2026-07-26-000000 through -000005)
-- plus the 2026-07-19 reissue they in turn superseded. None of them ever ran
-- against a deployed server, and collapsing an unreleased range is the one time
-- it is safe: diesel records only (version, run_on) in
-- `__diesel_schema_migrations`, with no checksum, so once a version has been
-- applied anywhere an edit to its file is a silent no-op on that database and a
-- different schema on a fresh one. After this branch reaches `main` that door
-- closes and every change arrives as a NEW migration - including comment-only
-- ones, because the file is the record of what a version did.
--
-- Issued under a NEW version rather than reusing 2026-07-26-000000, so that it
-- runs on every development database regardless of which subset of the old six
-- that database happened to record. Reusing the first version of a collapsed
-- range would have been skipped outright by a database that already had it, and
-- a half-migrated one would then have been missing `last_used_at` with nothing
-- at migration time to say so. Everything below is written to be re-runnable
-- for the same reason.
--
-- The one destructive step is the `scim_api_key` drop. The table holds only
-- bearer-token digests, which are regenerable - an operator who minted a token
-- on a pre-release build re-mints it - and nothing references it.

-- ---------------------------------------------------------------------------
-- 1. The SCIM credential.
-- ---------------------------------------------------------------------------
--
-- `last_used_at` is usage visibility, folded in from what was a separate
-- migration. The token has no expiry and is not invalidated when the Owner who
-- minted it leaves, so the only way an operator can tell a stale key from a
-- live one is whether it is still being used. NULL means "never used since this
-- column existed", deliberately distinguishable from "used long ago".
DROP TABLE IF EXISTS scim_api_key;

-- ON DELETE CASCADE is declared for parity with the mysql and postgresql
-- migrations, but it does NOT fire on sqlite: nothing in this tree ever issues
-- `PRAGMA foreign_keys = ON` on a pooled runtime connection (the pool's
-- on_acquire hook runs DATABASE_CONN_INIT, which sets only busy_timeout and
-- synchronous), and sqlite defaults the pragma off per connection. Deleting an
-- organization therefore relies on `Organization::delete` calling
-- `ScimApiKey::delete_all_by_organization` explicitly, which is what actually
-- keeps all three backends consistent. Do not drop that call on the strength of
-- this clause.
CREATE TABLE scim_api_key (
	uuid            TEXT NOT NULL PRIMARY KEY,
	org_uuid        TEXT NOT NULL UNIQUE REFERENCES organizations(uuid) ON DELETE CASCADE,
	key_hash        TEXT NOT NULL,
	enabled         BOOLEAN NOT NULL DEFAULT 1,
	created_at      DATETIME NOT NULL,
	revision_date   DATETIME NOT NULL,
	last_used_at    DATETIME NULL
);

-- ---------------------------------------------------------------------------
-- 2. The correlation key is unique per organization.
-- ---------------------------------------------------------------------------
--
-- `external_id` is what a provisioning engine uses to say "this Vaultwarden
-- membership is that directory object". Two rows claiming one directory object
-- is already broken state: `find_by_external_id_and_org` resolves via `.first()`,
-- so a later sync binds to an arbitrary one and can update or deprovision the
-- wrong member. This makes it an invariant the database keeps rather than one
-- application code re-checks on every write.
--
-- NOTE FOR THE WRITE PATH: adding a UNIQUE index to a table whose save uses
-- `diesel::replace_into` (sqlite and mysql) does NOT make a duplicate fail - SQL
-- REPLACE resolves a conflict on any unique index by DELETING the conflicting
-- row, taking a membership's `akey` or a group's `collections_groups` grants
-- with it. SCIM writes therefore go through `save_strict`, never `save`. See
-- `Membership::save_strict` and `Group::save_strict`.
--
-- sqlite needs no prefix and treats NULLs as distinct in a UNIQUE index, so most
-- memberships - which were never correlated to a directory object - stay
-- duplicable.
--
-- Any pre-existing duplicate must be resolved BEFORE the unique index is
-- created, or the CREATE fails - and because migrations run at pool
-- construction, before Rocket listens, a failing migration is a server that
-- permanently refuses to start. This is not hypothetical on an upgrade:
-- upstream's Directory Connector import writes `external_id` with no uniqueness
-- handling at all, so an existing deployment can already hold duplicates.
--
-- Keeping ONE row's correlation and clearing the rest destroys no membership,
-- no `akey`, no group and no access - only a correlation hint the next sync
-- re-establishes. WHICH row survives is arbitrary: `MIN(uuid)` picks the
-- lexicographically smallest uuid, and uuids come from `Uuid::new_v4()`, which
-- is random with no time component. It is NOT "keep the oldest", and there is no
-- better option - `users_organizations` carries no creation timestamp. `groups`
-- does carry a `creation_date`, but its repair is kept identical so the two read
-- the same way and neither implies a guarantee the other cannot make.
--
-- Each dedup is idempotent and each CREATE commits nothing until it succeeds, so
-- a failure part-way through leaves a state the re-run can start from. That is
-- what makes several DDL statements in one file safe here; see the mysql
-- sibling, where it took explicit work to be true.
UPDATE users_organizations
SET external_id = NULL
WHERE external_id IS NOT NULL
	AND uuid NOT IN (
		SELECT MIN(uuid)
		FROM users_organizations
		WHERE external_id IS NOT NULL
		GROUP BY org_uuid, external_id
	);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_organizations_org_external_id_unique
	ON users_organizations (org_uuid, external_id);

UPDATE groups
SET external_id = NULL
WHERE external_id IS NOT NULL
	AND uuid NOT IN (
		SELECT MIN(uuid)
		FROM groups
		WHERE external_id IS NOT NULL
		GROUP BY organizations_uuid, external_id
	);

CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_org_external_id_unique
	ON "groups" (organizations_uuid, external_id);

-- ---------------------------------------------------------------------------
-- 3. Paging indexes for the SCIM list endpoints.
-- ---------------------------------------------------------------------------
--
-- The list endpoints filter on the organization and order by uuid
-- (Membership::find_by_org_paged / Group::find_by_organization_paged). The org
-- filter alone was already served by the external_id indexes above, but the
-- ORDER BY was not: without a matching index the database sorts the whole
-- organization once per page, and a full Entra sync of a 20k-member org issues
-- 200 pages per cycle. Leading column matches the filter, second column matches
-- the sort, so the page becomes an index-ordered range scan with no sort step.
--
-- The ORDER BY is not a tuning detail: paging happens across separate requests,
-- so without a total order a member can appear on two pages or on none. See the
-- doc comment on Membership::find_by_org_paged.
CREATE INDEX IF NOT EXISTS idx_users_organizations_org_uuid_paged
	ON users_organizations (org_uuid, uuid);

CREATE INDEX IF NOT EXISTS idx_groups_org_uuid_paged
	ON "groups" (organizations_uuid, uuid);
