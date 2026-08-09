-- Make the SCIM correlation key unique per organization, for groups.
--
-- See the users_organizations migration of the same date for the full reasoning.
-- In short: two rows claiming one directory object is already broken state, and
-- this makes it an invariant the database keeps rather than one application code
-- re-checks on every write.
--
-- ONE migration per index, deliberately. An earlier arrangement created a
-- non-unique index here, added a UNIQUE one on the identical key in a later
-- migration, and dropped the first in a third. Collapsed while this branch is
-- still unreleased, which is the only time collapsing a migration is safe: once
-- it has run anywhere, a change has to arrive as a NEW migration, because diesel
-- records the version and will never re-run an edited one.
--
-- NOTE FOR THE WRITE PATH: adding a UNIQUE index to a table whose save uses
-- `diesel::replace_into` (sqlite and mysql) does NOT make a duplicate fail - SQL
-- REPLACE resolves a conflict on any unique index by DELETING the conflicting
-- row, taking its `collections_groups` access grants with it. SCIM writes
-- therefore go through `save_strict`, never `save`. See `Group::save_strict`.
--
-- sqlite needs no prefix and treats NULLs as distinct in a UNIQUE index, so the
-- many groups created in the web vault and never correlated to a directory
-- object stay duplicable.

-- Any pre-existing duplicate must be resolved BEFORE the unique index is
-- created, or the CREATE fails - and because migrations run at pool
-- construction, before Rocket listens, a failing migration is a server that
-- permanently refuses to start. Not hypothetical on an upgrade: upstream's
-- Directory Connector import writes `external_id` with no uniqueness handling,
-- so an existing deployment can already hold duplicates.
--
-- Keeping ONE row's correlation and clearing the rest destroys no group and no
-- collection access - only a correlation hint the next sync re-establishes.
-- WHICH row survives is arbitrary: `MIN(uuid)` picks the lexicographically
-- smallest uuid, and uuids come from `Uuid::new_v4()`, which is random with no
-- time component. It is NOT "keep the oldest". `groups` does carry a
-- `creation_date` that could order this, but the repair is kept identical to the
-- users_organizations one, which has no such column, so the two read the same
-- way and neither implies a guarantee the other cannot make.
--
-- Two statements rather than the usual one. Safe because the first is idempotent
-- and the second commits nothing until it succeeds, so a retry starts from a
-- state it can handle - unlike two CREATE INDEX statements, where a failure on
-- the second leaves the first committed and unrecorded.
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
