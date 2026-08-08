-- The Groups half of the same invariant; see
-- 2026-08-08-000001_unique_users_organizations_external_id for the full
-- reasoning. Groups are correlated by externalId exactly as memberships are,
-- and check_external_id_available has the same check-then-write shape.
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
	ON groups (organizations_uuid, external_id);
