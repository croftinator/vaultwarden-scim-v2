-- Make the SCIM correlation key unique per organization.
--
-- See the postgresql migration of the same name for why. Three things differ on
-- mysql, and all three are load-bearing.
--
-- 1. PREFIX, not the whole column. `users_organizations.external_id` is TEXT
--    (2023-09-02-212336_move_user_external_id) and mysql cannot index a TEXT
--    column without a prefix length. 150 because `org_uuid` CHAR(36) is 144
--    bytes and 150 utf8mb4 characters are 600, so 744 fits under the 767-byte
--    limit that COMPACT and REDUNDANT row formats still enforce. DYNAMIC allows
--    3072 and would take more, but a migration that only works on the newer
--    default is a server that permanently refuses to start on the older one.
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
-- ONE migration per index, deliberately. An earlier arrangement created a
-- non-unique index here, added a UNIQUE one on the identical key in a later
-- migration, and dropped the first in a third. Collapsed while this branch is
-- still unreleased, which is the only time collapsing a migration is safe: once
-- it has run anywhere, a change has to arrive as a NEW migration, because diesel
-- records the version and will never re-run an edited one.
--
-- NOTE FOR THE WRITE PATH: adding a UNIQUE index to a table whose save uses
-- `diesel::replace_into` does NOT make a duplicate fail - REPLACE resolves the
-- conflict by DELETING the conflicting row, taking the member's `akey` with it.
-- SCIM writes go through `save_strict`, never `save`. See
-- `Membership::save_strict`.
--
-- Two statements rather than the usual one. Safe because the first is idempotent
-- and the second commits nothing until it succeeds, so a retry starts from a
-- state it can handle - unlike two CREATE INDEX statements, where a failure on
-- the second left the first committed and unrecorded and every retry died on
-- "Duplicate key name".
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

CREATE UNIQUE INDEX idx_users_organizations_org_external_id_unique
	ON users_organizations (org_uuid, external_id(150));
