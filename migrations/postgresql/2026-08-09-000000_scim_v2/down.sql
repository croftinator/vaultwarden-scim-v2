-- Reverses everything the collapsed migration created, in the reverse order.
--
-- The dedup in up.sql is NOT reversible: the cleared external_ids are gone and
-- the next IdP sync re-establishes them. Dropping the indexes restores the old
-- unenforced behaviour, which is all a rollback can honestly do.
DROP INDEX IF EXISTS idx_groups_org_uuid_paged;
DROP INDEX IF EXISTS idx_users_organizations_org_uuid_paged;
DROP INDEX IF EXISTS idx_groups_org_external_id_unique;
DROP INDEX IF EXISTS idx_users_organizations_org_external_id_unique;
DROP TABLE IF EXISTS scim_api_key;
