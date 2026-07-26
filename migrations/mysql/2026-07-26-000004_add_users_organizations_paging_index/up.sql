-- Supports the SCIM list endpoints, which filter on the organization and order
-- by uuid (Membership::find_by_org_paged / Group::find_by_organization_paged).
-- The org filter alone was already served by the external_id index, but the
-- ORDER BY was not: without a matching index the database sorts the whole
-- organization once per page, and a full Entra sync of a 20k-member org issues
-- 200 pages per cycle. Leading column matches the filter, second column matches
-- the sort, so the page becomes an index-ordered range scan with no sort step.
--
-- uuid is CHAR(36) on mysql, so this one needs no prefix length.

CREATE INDEX idx_users_organizations_org_uuid_paged
	ON users_organizations (org_uuid, uuid);
