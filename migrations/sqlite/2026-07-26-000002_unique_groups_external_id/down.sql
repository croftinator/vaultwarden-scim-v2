-- The dedup is not reversible: the cleared external_ids are gone and the next
-- IdP sync re-establishes them. Dropping the index restores the old unenforced
-- behaviour, which is all a rollback can honestly do.
DROP INDEX IF EXISTS idx_groups_org_external_id_unique;
