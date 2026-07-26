-- Supports the SCIM list endpoints, which filter on the organization and order
-- by uuid (Membership::find_by_org_paged / Group::find_by_organization_paged).
-- The org filter alone was already served by the external_id index, but the
-- ORDER BY was not: without a matching index the database sorts the whole
-- organization once per page, and a full Entra sync of a 20k-member org issues
-- 200 pages per cycle. Leading column matches the filter, second column matches
-- the sort, so the page becomes an index-ordered range scan with no sort step.
--
-- The ORDER BY is not a tuning detail: paging happens across separate requests,
-- so without a total order a member can appear on two pages or on none. See the
-- doc comment on Membership::find_by_org_paged.

CREATE INDEX IF NOT EXISTS idx_groups_org_uuid_paged
	ON groups (organizations_uuid, uuid);
