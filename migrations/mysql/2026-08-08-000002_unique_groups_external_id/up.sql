-- The Groups half; see 2026-08-08-000001_unique_users_organizations_external_id
-- for the full reasoning, all three mysql-specific points included.
--
-- `groups` is a reserved word in mysql 8 and must be backticked, as the
-- upstream migration that creates the table does.
--
-- groups.external_id is VARCHAR(300) rather than TEXT, but the prefix is still
-- required: organizations_uuid VARCHAR(40) is 160 bytes and 300 utf8mb4
-- characters are 1200, so the full pair is 1360 and blows the 767-byte COMPACT
-- limit. 160 + 150*4 = 760 fits.
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
