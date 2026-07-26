-- externalId is the SCIM correlation key, read on every write path, and
-- users_organizations is global across all organizations rather than scoped to
-- one - so an unindexed lookup scans every membership on the whole server once
-- per provisioned user. Composite, and in this order, because every SCIM query
-- filters on both columns.

-- Exactly ONE index statement per migration, deliberately.
--
-- MySQL DDL is not transactional and MySQL supports neither
-- CREATE INDEX ... IF NOT EXISTS nor DROP INDEX ... IF EXISTS. When two
-- CREATE INDEX statements shared a migration, a failure on the second left the
-- first committed while diesel never recorded the migration, so every retry
-- died on ERROR 1061 "Duplicate key name" and the database could not be
-- migrated at all. Because migrations run at pool construction, before Rocket
-- listens, that is a server that permanently refuses to start.
--
-- sqlite and postgresql are transactional and do not need this, but they keep
-- the same split so all three dialects stay reviewable side by side.
CREATE INDEX IF NOT EXISTS idx_groups_org_external_id
	ON groups (organizations_uuid, external_id);
