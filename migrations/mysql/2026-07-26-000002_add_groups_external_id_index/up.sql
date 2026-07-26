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
-- One statement per migration is the only shape that is safely retryable here:
-- a failure leaves nothing committed, so the retry starts clean.
--
-- `groups` is a reserved word in MySQL 8 and must be backticked - the upstream
-- migration that creates the table quotes it for the same reason.

-- The prefix length is required, not a tuning choice: users_organizations
-- .external_id is TEXT on mysql (2023-09-02-212336_move_user_external_id), and
-- MySQL cannot index a BLOB/TEXT column without one.
--
-- 150, not the usual 191. The 191 figure is the utf8mb4 ceiling for a
-- SINGLE-column 767-byte prefix, and this key is composite: prepending
-- org_uuid CHAR(36) (144 bytes) to external_id(191) (764 bytes) gives 908,
-- which blows the 767-byte limit that older InnoDB row formats (COMPACT,
-- REDUNDANT) still enforce. DYNAMIC - the default since MySQL 5.7.9 and
-- MariaDB 10.2.2 - allows 3072 and would accept it, but a migration that only
-- works on the newer default is a server that permanently refuses to start on
-- the older one, because migrations run before Rocket listens. 144 + 150*4 =
-- 744 fits under 767 and is far more than enough to keep a GUID selective.
CREATE INDEX idx_groups_org_external_id
	ON `groups` (organizations_uuid, external_id(150));
