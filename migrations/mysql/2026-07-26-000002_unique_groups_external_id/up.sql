-- Make the SCIM correlation key unique per organization, for groups.
--
-- See the users_organizations migration of the same date for the prefix
-- arithmetic, the derived-table workaround, the collation caveat, and why this
-- is one migration rather than the three it used to be.
--
-- `groups` is a reserved word in mysql 8 and must be backticked.
--
-- `groups.external_id` is VARCHAR(300) here rather than TEXT, but the 150-char
-- prefix is kept for the same reason as on users_organizations:
-- `organizations_uuid` CHAR(36) is 144 bytes, and 300 utf8mb4 characters would
-- be 1200, so the pair would exceed the 767-byte limit that COMPACT and
-- REDUNDANT row formats still enforce.
--
-- NOTE FOR THE WRITE PATH: adding a UNIQUE index to a table whose save uses
-- `diesel::replace_into` does NOT make a duplicate fail - REPLACE resolves the
-- conflict by DELETING the conflicting row, taking its `collections_groups`
-- access grants with it. SCIM writes go through `save_strict`, never `save`.
-- See `Group::save_strict`.
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

CREATE UNIQUE INDEX idx_groups_org_external_id_unique
	ON `groups` (organizations_uuid, external_id(150));
