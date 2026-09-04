-- The whole SCIM v2 schema, as one migration.
--
-- This collapses what were six migrations (2026-07-26-000000 through -000005)
-- plus the 2026-07-19 reissue they in turn superseded. None of them ever ran
-- against a deployed server, and collapsing an unreleased range is the one time
-- it is safe: diesel records only (version, run_on) in
-- `__diesel_schema_migrations`, with no checksum, so once a version has been
-- applied anywhere an edit to its file is a silent no-op on that database and a
-- different schema on a fresh one. After this branch reaches `main` that door
-- closes and every change arrives as a NEW migration.
--
-- Issued under a NEW version rather than reusing 2026-07-26-000000, so that it
-- runs on every development database regardless of which subset of the old six
-- that database happened to record. Everything below is re-runnable for the
-- same reason.
--
-- The one destructive step is the `scim_api_key` drop. The table holds only
-- bearer-token digests, which are regenerable, and nothing references it.

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

-- org_uuid is VARCHAR(40) to match organizations.uuid exactly (VARCHAR(40) here
-- and on mysql). It was CHAR(36) once, which was wrong twice over: an org uuid
-- of 37-40 characters is legal in the parent table and inserts fine on mysql and
-- sqlite but fails here with "value too long for type character(36)", making the
-- SCIM key un-mintable for that organization on one backend only; and bpchar
-- blank-pads shorter values on storage and returns the padding, so a comparison
-- in Rust against an unpadded value would silently stop matching.
CREATE TABLE scim_api_key (
	uuid            CHAR(36) NOT NULL PRIMARY KEY,
	org_uuid        VARCHAR(40) NOT NULL UNIQUE REFERENCES organizations(uuid) ON DELETE CASCADE,
	key_hash        TEXT NOT NULL,
	enabled         BOOLEAN NOT NULL DEFAULT true,
	created_at      TIMESTAMP NOT NULL,
	revision_date   TIMESTAMP NOT NULL,
	last_used_at    TIMESTAMP NULL
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
-- NOTE FOR THE WRITE PATH: on sqlite and mysql, adding a UNIQUE index to a table
-- whose save uses `diesel::replace_into` does NOT make a duplicate fail - REPLACE
-- resolves the conflict by DELETING the conflicting row. postgresql is the one
-- backend that always behaved correctly here, because its save uses
-- `on_conflict(uuid)`, whose target is the primary key alone. SCIM writes go
-- through `save_strict` on every backend regardless. See `Membership::save_strict`.
--
-- NULLs stay duplicable, which is what we want: most memberships have never been
-- correlated to a directory object, and standard UNIQUE semantics treat NULLs as
-- distinct on postgresql.
--
-- Any pre-existing duplicate must be resolved BEFORE the unique index is
-- created, or the CREATE fails - and because migrations run at pool
-- construction, before Rocket listens, a failing migration is a server that
-- permanently refuses to start. Not hypothetical on an upgrade: upstream's
-- Directory Connector import writes `external_id` with no uniqueness handling,
-- so an existing deployment can already hold duplicates.
--
-- Keeping ONE row's correlation and clearing the rest destroys no membership, no
-- `akey`, no group and no access - only a correlation hint the next sync
-- re-establishes. WHICH row survives is arbitrary: `MIN(uuid)` picks the
-- lexicographically smallest uuid, and uuids come from `Uuid::new_v4()`, which is
-- random with no time component. It is NOT "keep the oldest", and there is no
-- better option - `users_organizations` carries no creation timestamp. `groups`
-- does carry a `creation_date`, but its repair is kept identical so the two read
-- the same way and neither implies a guarantee the other cannot make.
--
-- The length clause is the postgresql-only hazard. `users_organizations.external_id`
-- is TEXT here with no cap, and the one writer that predates SCIM - the Directory
-- Connector import - applies no length check at all, so a deployment using LDAP
-- DNs as externalIds can hold arbitrarily long values. A plain btree index entry
-- caps at about 2704 bytes, so a single over-long pre-existing row would make the
-- CREATE below fail outright and leave a server that will not start. SCIM caps
-- externalId at 300 characters (SCIM_MAX_EXTERNAL_ID_LEN), so anything longer was
-- never SCIM's to begin with. `groups.external_id` is VARCHAR(300) here, matching
-- that cap, so it needs no such guard.
--
-- Each dedup is idempotent and each CREATE commits nothing until it succeeds, so
-- a failure part-way through leaves a state the re-run can start from. That is
-- what makes several DDL statements in one file safe here; see the mysql
-- sibling, where it took explicit work to be true.
UPDATE users_organizations
SET external_id = NULL
WHERE external_id IS NOT NULL
	AND (
		octet_length(external_id) > 2000
		OR uuid NOT IN (
			SELECT MIN(uuid)
			FROM users_organizations
			WHERE external_id IS NOT NULL
			GROUP BY org_uuid, external_id
		)
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
	ON groups (organizations_uuid, uuid);
