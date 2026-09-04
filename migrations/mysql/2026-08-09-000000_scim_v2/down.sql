-- Reverses everything the collapsed migration created, in the reverse order.
--
-- The dedup in up.sql is NOT reversible: the cleared external_ids are gone and
-- the next IdP sync re-establishes them. Dropping the indexes restores the old
-- unenforced behaviour, which is all a rollback can honestly do.
--
-- Guarded the same way up.sql is, and for the same reason: mysql supports no
-- `DROP INDEX ... IF EXISTS`, DDL commits statement by statement, and diesel
-- records the revert only once the whole file succeeds. Bare drops would make a
-- part-way failure unrepeatable - every retry dying on the first index it had
-- already dropped.
SET @ddl := IF(
	(SELECT COUNT(*) FROM information_schema.statistics
	 WHERE table_schema = DATABASE()
	   AND table_name = 'groups'
	   AND index_name = 'idx_groups_org_uuid_paged') > 0,
	'DROP INDEX idx_groups_org_uuid_paged ON `groups`',
	'DO 0');
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @ddl := IF(
	(SELECT COUNT(*) FROM information_schema.statistics
	 WHERE table_schema = DATABASE()
	   AND table_name = 'users_organizations'
	   AND index_name = 'idx_users_organizations_org_uuid_paged') > 0,
	'DROP INDEX idx_users_organizations_org_uuid_paged ON users_organizations',
	'DO 0');
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @ddl := IF(
	(SELECT COUNT(*) FROM information_schema.statistics
	 WHERE table_schema = DATABASE()
	   AND table_name = 'groups'
	   AND index_name = 'idx_groups_org_external_id_unique') > 0,
	'DROP INDEX idx_groups_org_external_id_unique ON `groups`',
	'DO 0');
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @ddl := IF(
	(SELECT COUNT(*) FROM information_schema.statistics
	 WHERE table_schema = DATABASE()
	   AND table_name = 'users_organizations'
	   AND index_name = 'idx_users_organizations_org_external_id_unique') > 0,
	'DROP INDEX idx_users_organizations_org_external_id_unique ON users_organizations',
	'DO 0');
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

DROP TABLE IF EXISTS scim_api_key;
