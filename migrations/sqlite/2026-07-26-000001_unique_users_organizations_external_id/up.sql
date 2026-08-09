-- Make the SCIM correlation key unique per organization.
--
-- `external_id` is what a provisioning engine uses to say "this Vaultwarden
-- membership is that directory object". Two rows claiming one directory object
-- is already broken state: `find_by_external_id_and_org` resolves via `.first()`,
-- so a later sync binds to an arbitrary one and can update or deprovision the
-- wrong member. This makes it an invariant the database keeps rather than one
-- application code re-checks on every write.
--
-- ONE migration per index, deliberately. An earlier arrangement created a
-- non-unique index here, added a UNIQUE one on the identical key in a later
-- migration, and dropped the first in a third - three statements and two round
-- trips of index building for one index. Collapsed while this branch is still
-- unreleased, which is the only time collapsing a migration is safe: once it has
-- run anywhere, a change has to arrive as a NEW migration, because diesel records
-- the version and will never re-run an edited one.
--
-- If you ran an earlier build of this branch, recreate your development database.
-- Your recorded migration version is already applied, so this file will not run
-- and you would silently end up without the constraint. The SCIM test
-- `the_unique_index_refuses_a_duplicate_external_id_without_destroying_the_holder`
-- fails loudly in that case rather than letting it pass.
--
-- NOTE FOR THE WRITE PATH: adding a UNIQUE index to a table whose save uses
-- `diesel::replace_into` (sqlite and mysql) does NOT make a duplicate fail - SQL
-- REPLACE resolves a conflict on any unique index by DELETING the conflicting
-- row. SCIM writes therefore go through `save_strict`, never `save`. See
-- `Membership::save_strict`.
--
-- sqlite needs no prefix and treats NULLs as distinct in a UNIQUE index, so most
-- memberships - which were never correlated to a directory object - stay
-- duplicable.

-- Any pre-existing duplicate must be resolved BEFORE the unique index is
-- created, or the CREATE fails - and because migrations run at pool
-- construction, before Rocket listens, a failing migration is a server that
-- permanently refuses to start. This is not hypothetical on an upgrade:
-- upstream's Directory Connector import writes `external_id` with no
-- uniqueness handling at all, so an existing deployment can already hold
-- duplicates.
--
-- Keeping ONE row's correlation and clearing the rest destroys no membership,
-- no `akey` and no access - only a correlation hint the next sync
-- re-establishes. WHICH row survives is arbitrary: `MIN(uuid)` picks the
-- lexicographically smallest uuid, and uuids come from `Uuid::new_v4()`, which
-- is random with no time component. It is NOT "keep the oldest", and there is no
-- better option here - `users_organizations` carries no creation timestamp.
--
-- Two statements rather than the usual one. Safe because the first is idempotent
-- and the second commits nothing until it succeeds, so a retry starts from a
-- state it can handle - unlike two CREATE INDEX statements, where a failure on
-- the second leaves the first committed and unrecorded.
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
