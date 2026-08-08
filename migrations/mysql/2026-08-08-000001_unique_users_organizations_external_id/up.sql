-- Make the SCIM correlation key actually unique per organization.
--
-- See the postgresql migration of the same name for why: uniqueness was
-- enforced only by a check-then-write in application code, so concurrent
-- requests could commit duplicate correlation keys and a later sync would bind
-- to an arbitrary one. Three things differ on mysql.
--
-- 1. PREFIX, not the whole column. users_organizations.external_id is TEXT
--    (2023-09-02-212336_move_user_external_id) and mysql cannot index a TEXT
--    column without a prefix length. 150 for the same reason as the non-unique
--    index this replaces in purpose: org_uuid CHAR(36) is 144 bytes and
--    150 utf8mb4 characters are 600, so 744 fits under the 767-byte limit that
--    COMPACT and REDUNDANT row formats still enforce. DYNAMIC allows 3072 and
--    would take more, but a migration that only works on the newer default is a
--    server that permanently refuses to start on the older one.
--
--    The consequence is honest and worth stating: uniqueness is enforced over
--    the first 150 characters, so two externalIds differing only after
--    character 150 would collide here and not on the other two backends.
--    SCIM_MAX_EXTERNAL_ID_LEN is 300, so that is reachable in principle; Entra
--    sends GUIDs of about 36 characters, so it is not reachable in practice.
--    A false 409 is also the safe direction to fail - it refuses a write rather
--    than silently accepting a duplicate.
--
-- 2. The dedup MUST group by the same prefix the index enforces. Grouping by
--    the full value would leave two rows whose first 150 characters match but
--    whose tails differ, and the CREATE UNIQUE INDEX would then fail - which,
--    because migrations run before Rocket listens, is a server that will not
--    start.
--
-- 3. mysql refuses to read the table being updated in a plain subquery
--    ("You can't specify target table ... for update in FROM clause"), so the
--    keeper set is wrapped in a derived table.
--
-- Two statements, unlike the plain index migrations. Safe here because the
-- first is idempotent and the second commits nothing until it succeeds, so a
-- retry starts from a state it can handle - unlike two CREATE INDEX statements,
-- where the first stayed committed and unrecorded.
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
