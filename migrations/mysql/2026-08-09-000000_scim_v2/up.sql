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
-- that database happened to record.
--
-- ===========================================================================
-- WHY EVERY `CREATE INDEX` BELOW IS WRAPPED
-- ===========================================================================
--
-- MySQL DDL is not transactional: each statement commits on its own, and
-- diesel records the migration version only after the whole file succeeds. Put
-- four bare `CREATE INDEX` statements in one file and a failure on the third -
-- a lock wait timeout while building an index over a large organization is the
-- realistic one, not a logic error - leaves the first two committed and the
-- version unrecorded. Every retry then dies on "Duplicate key name" for an
-- index it already built, and because migrations run at pool construction,
-- before Rocket listens, that is a database that cannot be migrated and a
-- server that will not start. Manual DBA intervention is the only way out.
--
-- That hazard is exactly why this used to be one index per migration. Merging
-- them into one file is only defensible if each statement is re-runnable, and
-- MySQL 8 supports neither `CREATE INDEX ... IF NOT EXISTS` nor `DROP INDEX ...
-- IF EXISTS`. So each index is created through an information_schema check and
-- a prepared statement, which is the standard workaround and makes the whole
-- file idempotent: a retry skips what already exists and finishes the rest.
--
-- `DO 0` is the no-op branch - a valid statement that does nothing, so the
-- prepared-statement machinery has something to run when the index is present.
--
-- The two dedup `UPDATE`s need no such wrapping; they are already idempotent.
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

-- The FOREIGN KEY must be a table-level clause: MySQL silently ignores inline
-- column-level REFERENCES, so an inline one would create no real constraint.
--
-- org_uuid is VARCHAR(40) to match organizations.uuid exactly, which is
-- VARCHAR(40) on BOTH mysql and postgresql. An InnoDB foreign key additionally
-- requires the child column to match the parent's type, so a narrower one would
-- be rejected outright here rather than failing later on a long value.
CREATE TABLE scim_api_key (
	uuid            CHAR(36) NOT NULL PRIMARY KEY,
	org_uuid        VARCHAR(40) NOT NULL UNIQUE,
	key_hash        TEXT NOT NULL,
	enabled         BOOLEAN NOT NULL DEFAULT TRUE,
	created_at      DATETIME NOT NULL,
	revision_date   DATETIME NOT NULL,
	last_used_at    DATETIME NULL,
	FOREIGN KEY(org_uuid) REFERENCES organizations(uuid) ON DELETE CASCADE
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
-- Three things differ from the sqlite and postgresql siblings, and all three
-- are load-bearing.
--
-- 1. PREFIX, not the whole column. `users_organizations.external_id` is TEXT
--    (2023-09-02-212336_move_user_external_id) and mysql cannot index a TEXT
--    column without a prefix length. 150 because `org_uuid` CHAR(36) is 144
--    bytes and 150 utf8mb4 characters are 600, so 744 fits under the 767-byte
--    limit that COMPACT and REDUNDANT row formats still enforce. DYNAMIC allows
--    3072 and would take more, but a migration that only works on the newer
--    default is a server that permanently refuses to start on the older one.
--    `groups.external_id` is VARCHAR(300) rather than TEXT, but keeps the same
--    prefix for the same arithmetic: `organizations_uuid` CHAR(36) is 144 bytes
--    and 300 utf8mb4 characters would be 1200, well over the limit.
--
--    The consequence is worth stating rather than hiding: uniqueness is enforced
--    over the first 150 characters, so two externalIds differing only after
--    character 150 collide here and not on the other two backends.
--    SCIM_MAX_EXTERNAL_ID_LEN is 300, so that is reachable in principle; Entra
--    sends GUIDs of about 36 characters, so it is not reachable in practice. The
--    write path answers such a collision with a 409, not a 500 - see
--    `is_unique_violation`, which asks the error rather than re-reading the row,
--    because an exact-match re-read cannot see a prefix collision at all.
--
-- 2. The dedup MUST group by the same prefix the index enforces. Grouping by the
--    full value would leave two rows whose first 150 characters match but whose
--    tails differ, and the CREATE UNIQUE INDEX would then fail - which, because
--    migrations run before Rocket listens, is a server that will not start.
--
-- 3. mysql refuses to read the table being updated in a plain subquery ("You
--    can't specify target table ... for update in FROM clause"), so the keeper
--    set is wrapped in a derived table.
--
-- Also note mysql's default utf8mb4 collation is case- and accent-INSENSITIVE,
-- so 'ABC' and 'abc' are one key here and two on sqlite and postgresql. One of a
-- case-differing pair therefore has its correlation cleared on this backend
-- only. Recorded in TODOS.md and docs/scim/upgrading.md rather than silently
-- normalised, because picking a semantic for all three backends is a decision,
-- not a fix.
--
-- Any pre-existing duplicate must be resolved BEFORE the unique index is
-- created, or the CREATE fails. Not hypothetical on an upgrade: upstream's
-- Directory Connector import writes `external_id` with no uniqueness handling,
-- so an existing deployment can already hold duplicates.
--
-- Keeping ONE row's correlation and clearing the rest destroys no membership, no
-- `akey`, no group and no access - only a correlation hint the next sync
-- re-establishes. WHICH row survives is arbitrary: `MIN(uuid)` picks the
-- lexicographically smallest uuid, and uuids come from `Uuid::new_v4()`, which is
-- random with no time component. It is NOT "keep the oldest".
--
-- NOTE FOR THE WRITE PATH: adding a UNIQUE index to a table whose save uses
-- `diesel::replace_into` does NOT make a duplicate fail - REPLACE resolves the
-- conflict by DELETING the conflicting row, taking a membership's `akey` or a
-- group's `collections_groups` access grants with it. SCIM writes go through
-- `save_strict`, never `save`. See `Membership::save_strict` and
-- `Group::save_strict`.
UPDATE users_organizations
SET external_id = NULL
WHERE external_id IS NOT NULL
	AND uuid NOT IN (
		SELECT keeper FROM (
			SELECT MIN(uuid) AS keeper
			FROM users_organizations
			WHERE external_id IS NOT NULL
			GROUP BY org_uuid, LEFT(external_id, 150)
		) AS keepers
	);

SET @ddl := IF(
	(SELECT COUNT(*) FROM information_schema.statistics
	 WHERE table_schema = DATABASE()
	   AND table_name = 'users_organizations'
	   AND index_name = 'idx_users_organizations_org_external_id_unique') = 0,
	'CREATE UNIQUE INDEX idx_users_organizations_org_external_id_unique ON users_organizations (org_uuid, external_id(150))',
	'DO 0');
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- `groups` is a reserved word in mysql 8 and must be backticked.
UPDATE `groups`
SET external_id = NULL
WHERE external_id IS NOT NULL
	AND uuid NOT IN (
		SELECT keeper FROM (
			SELECT MIN(uuid) AS keeper
			FROM `groups`
			WHERE external_id IS NOT NULL
			GROUP BY organizations_uuid, LEFT(external_id, 150)
		) AS keepers
	);

SET @ddl := IF(
	(SELECT COUNT(*) FROM information_schema.statistics
	 WHERE table_schema = DATABASE()
	   AND table_name = 'groups'
	   AND index_name = 'idx_groups_org_external_id_unique') = 0,
	'CREATE UNIQUE INDEX idx_groups_org_external_id_unique ON `groups` (organizations_uuid, external_id(150))',
	'DO 0');
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

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
--
-- uuid is CHAR(36) on mysql, so these need no prefix length.
SET @ddl := IF(
	(SELECT COUNT(*) FROM information_schema.statistics
	 WHERE table_schema = DATABASE()
	   AND table_name = 'users_organizations'
	   AND index_name = 'idx_users_organizations_org_uuid_paged') = 0,
	'CREATE INDEX idx_users_organizations_org_uuid_paged ON users_organizations (org_uuid, uuid)',
	'DO 0');
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @ddl := IF(
	(SELECT COUNT(*) FROM information_schema.statistics
	 WHERE table_schema = DATABASE()
	   AND table_name = 'groups'
	   AND index_name = 'idx_groups_org_uuid_paged') = 0,
	'CREATE INDEX idx_groups_org_uuid_paged ON `groups` (organizations_uuid, uuid)',
	'DO 0');
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
