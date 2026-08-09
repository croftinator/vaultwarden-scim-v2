//
// SCIM /Groups endpoints. The SCIM Group id is Vaultwarden's GroupId, and
// member values are MembershipIds (the same ids the /Users endpoints expose),
// which is why User provisioning must precede Group assignment.
//
// SCIM owns group existence and membership only. Collection access stays an
// in-app admin decision: the IdP decides who is in a group, the vault admin
// decides what the group can see.
//
// Requires ORG_GROUPS_ENABLED. Unlike ldap_import, which silently skips
// groups when disabled, these endpoints fail loudly so a misconfigured
// deployment is visible in the IdP instead of quietly not syncing.
//
use std::collections::{HashMap, HashSet};

use rocket::Route;
use serde::Deserialize;
use serde_json::Value;

use crate::{
    api::{
        core::log_event,
        scim::{
            SCIM_ACTOR, SCIM_DEVICE_TYPE, SCIM_MAX_GROUP_MEMBER_OPS, SCIM_MAX_GROUP_MEMBERS, ScimJson, ScimResponse,
            error::ScimError,
            filter::parse_eq_filter,
            guard::ScimToken,
            patch::{MemberOp, PatchOp, parse_group_patch},
        },
    },
    db::{
        DbConn,
        models::{CollectionGroup, EventType, Group, GroupId, GroupUser, Membership, MembershipId},
    },
};

pub fn routes() -> Vec<Route> {
    routes![list_groups, get_group, post_group, put_group, patch_group, delete_group]
}

fn check_groups_enabled() -> Result<(), ScimError> {
    if !crate::api::scim::org_groups_enabled() {
        return Err(ScimError::not_implemented("Group support is disabled on this server (ORG_GROUPS_ENABLED=false)"));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScimGroupMember {
    value: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScimGroupRequest {
    display_name: Option<String>,
    external_id: Option<String>,
    // None (attribute omitted) and Some(vec![]) are different on PUT: an
    // omitted member list leaves membership unchanged, an empty one clears it.
    #[serde(default)]
    members: Option<Vec<ScimGroupMember>>,
}

async fn to_scim_group(group: &Group, token: &ScimToken, include_members: bool, conn: &DbConn) -> Value {
    let members: Option<Vec<MembershipId>> = if include_members {
        Some(
            GroupUser::find_by_group(&group.uuid, &token.org_uuid, conn)
                .await
                .into_iter()
                .map(|gu| gu.users_organizations_uuid)
                .collect(),
        )
    } else {
        None
    };
    scim_group_body(group, token, members.as_deref())
}

// Serializes a group from member ids already in hand, so a list response can
// load every page's members in one query instead of one per group.
fn scim_group_body(group: &Group, token: &ScimToken, members: Option<&[MembershipId]>) -> Value {
    let location = crate::api::scim::resource_location(&token.org_uuid, "Groups", &group.uuid);
    // meta.lastModified is populated for Groups because the row carries a
    // revision date. Users deliberately omit it: Membership has no equivalent
    // column, and inventing one would let a client build a delta sync on a
    // timestamp that does not track the data. See docs/scim/reference.md.
    let mut body = json!({
        "schemas": [crate::api::scim::discovery::GROUP_SCHEMA_URN],
        "id": group.uuid,
        "displayName": group.name,
        "meta": {
            "resourceType": "Group",
            "location": location,
            "created": crate::util::format_date(&group.creation_date),
            "lastModified": crate::util::format_date(&group.revision_date),
        },
    });
    // Omitted rather than null when unset; see to_scim_user for the reasoning.
    // A group created in the web vault has no externalId, so this is the common
    // case here rather than an edge one.
    if let Some(external_id) = &group.external_id {
        body["externalId"] = json!(external_id);
    }
    if let Some(members) = members {
        body["members"] = json!(members.iter().map(|id| json!({"value": id})).collect::<Vec<Value>>());
    }
    body
}

async fn log_group_event(event_type: EventType, group_uuid: &GroupId, token: &ScimToken, conn: &DbConn) {
    log_event(event_type as i32, group_uuid, &token.org_uuid, &SCIM_ACTOR.into(), SCIM_DEVICE_TYPE, &token.ip.ip, conn)
        .await;
}

// The 400 every unresolvable member value produces. Deliberately identical for
// "no such membership anywhere" and "belongs to another organization", so the
// endpoint cannot be used to probe for ids outside this org.
fn unresolvable_member() -> ScimError {
    ScimError::bad_request(
        "invalidValue",
        "members must reference existing members of this organization (provision the user first)",
    )
}

// Resolves SCIM member values to memberships of THIS org, or a 400: group
// assignment requires the user to be provisioned into the org first.
//
// Batched, not one lookup per value. Every write path resolves the whole list
// up front so a bad value cannot leave a half-applied change behind, which at
// the 1000-member cap meant 1000 sequential queries for one request.
async fn resolve_members(values: &[String], token: &ScimToken, conn: &DbConn) -> Result<Vec<MembershipId>, ScimError> {
    if values.is_empty() {
        return Ok(Vec::new());
    }
    let requested: Vec<MembershipId> = values.iter().map(|value| value.clone().into()).collect();
    let known: HashSet<MembershipId> = Membership::find_by_uuids_and_org(&requested, &token.org_uuid, conn)
        .await
        .into_iter()
        .map(|member| member.uuid)
        .collect();
    if requested.iter().any(|member_id| !known.contains(member_id)) {
        return Err(unresolvable_member());
    }
    Ok(requested)
}

// The operation count is bounded separately from the value count, because an
// operation carrying an empty value list contributes nothing to the latter. See
// SCIM_MAX_GROUP_MEMBER_OPS.
fn check_member_op_count(ops: usize) -> Result<(), ScimError> {
    if ops > SCIM_MAX_GROUP_MEMBER_OPS {
        return Err(ScimError::bad_request(
            "invalidValue",
            "Too many member operations in one request; split the membership update across several requests",
        ));
    }
    Ok(())
}

// Every member value costs a database round trip, so an uncapped list turns one
// legal request into tens of thousands of sequential queries holding a pooled
// connection. Reject oversized sets before any of that work happens.
fn check_member_count(count: usize) -> Result<(), ScimError> {
    if count > SCIM_MAX_GROUP_MEMBERS {
        // invalidValue, not tooMany. RFC 7644 section 3.12 defines tooMany
        // narrowly as "the specified FILTER yields many more results than the
        // server is willing to calculate" - a client branching on it would
        // retry with a narrower filter, which never fixes an oversized body.
        return Err(ScimError::bad_request(
            "invalidValue",
            "Too many members in one request; split the membership update across several requests",
        ));
    }
    Ok(())
}

// Saves a group whose externalId this request may have set, turning a lost
// uniqueness race into the same 409 the sequential case returns.
//
// The check-then-write in `check_external_id_available` is no longer the only
// enforcement: a UNIQUE index now backs it (2026-08-09-000000), which is the
// point - the check alone was one two concurrent requests could both pass. The
// loser now fails at the write instead, and a bare internal() would make that a
// 500, the one status Entra retries until it quarantines the application.
//
// `save_strict`, not `save`: the latter is a REPLACE on sqlite and mysql, so a
// conflict on that index DELETES the other group - and its `collections_groups`
// access grants with it - then reports success, which would leave this recovery
// unreachable. See `Group::save_strict`.
pub(super) async fn save_group_with_external_id(group: &mut Group, conn: &DbConn) -> Result<(), ScimError> {
    match group.save_strict(conn).await {
        Ok(()) => Ok(()),
        Err(e) if crate::api::scim::is_unique_violation(&e) => {
            Err(ScimError::conflict("uniqueness", "A group with this externalId already exists"))
        }
        Err(_) => Err(ScimError::internal()),
    }
}

// The externalId is the correlation key: enforce uniqueness within the org on
// every write path, mirroring the Users endpoints. Re-asserting the group's
// own current externalId is allowed (Entra repeats it on PUT).
async fn check_external_id_available(
    group: &Group,
    external_id: &str,
    token: &ScimToken,
    conn: &DbConn,
) -> Result<(), ScimError> {
    crate::api::scim::check_attribute_len("externalId", external_id, crate::api::scim::SCIM_MAX_EXTERNAL_ID_LEN)?;
    match Group::find_by_external_id_and_org(external_id, &token.org_uuid, conn).await {
        Some(existing) if existing.uuid != group.uuid => {
            Err(ScimError::conflict("uniqueness", "A group with this externalId already exists"))
        }
        _ => Ok(()),
    }
}

// Whether SCIM may ADD members to this group.
//
// SCIM resolves a group by its GroupId, so without this every group in the
// organization is reachable - including one an administrator created in the web
// vault and granted access to a sensitive collection. Vaultwarden grants
// collection access through `groups_users -> collections_groups` with no
// per-collection key, so adding a member to such a group hands that member real
// plaintext access to collections nobody granted them. The token holder gains
// nothing directly (they hold no org key), but they can hand access to someone
// they control, which is a privilege escalation by any useful definition.
//
// The rule targets groups that actually CONFER access, not every group SCIM did
// not create. Two are off limits for additions:
//
//   - `access_all`: blanket access to every collection in the organization.
//     SCIM never sets it (`post_group` hardcodes false and `put_group` leaves it
//     alone), so a group carrying it was escalated by a human. Refused
//     unconditionally - there is no externalId that makes this safe.
//   - carries collection grants AND has no `external_id`: an administrator
//     curated it in the web vault and SCIM never correlated it to a directory
//     object. This is the scoping `ldap_import` gets for free, because it
//     resolves groups strictly by external_id (`src/api/core/public.rs`) and so
//     cannot see a web-vault group at all. SCIM resolving by uuid is a genuine
//     widening of the precedent it was modelled on.
//
// A group with an externalId and collection grants is the INTENDED workflow -
// an admin grants the group its collections once, the IdP owns its membership -
// so it stays writable. A SCIM-created group with no grants confers nothing, so
// adding members to it escalates nothing and is also allowed; that keeps a
// non-Entra client that omits externalId working, and RFC 7643 makes externalId
// optional, so refusing it outright would be a spec deviation for no gain.
async fn scim_may_add_members(group: &Group, token: &ScimToken, conn: &DbConn) -> bool {
    if group.access_all {
        return false;
    }
    if group.external_id.is_some() {
        return true;
    }
    !group_confers_access(group, token, conn).await
}

// Whether this group hands its members real collection access, independent of
// whether SCIM has correlated it.
//
// This is the property every ownership guard here actually protects.
// `scim_may_add_members` layers the externalId ownership signal on top of it,
// which is right for "may SCIM add members" and WRONG for any question about
// the externalId itself: a guard that asks `scim_may_add_members` about a group
// that still carries its externalId gets `true` before it has looked at
// anything, because carrying an externalId is the very thing being changed.
async fn group_confers_access(group: &Group, token: &ScimToken, conn: &DbConn) -> bool {
    group.access_all || !CollectionGroup::find_by_group(&group.uuid, &token.org_uuid, conn).await.is_empty()
}

// Refuses an addition to a group SCIM does not own.
//
// Deliberately asymmetric: this gates ADDITIONS only, and removals always
// proceed. It is the same asymmetry as revoke-yes/restore-no on Users, for the
// same reason. A removal reduces access and is the deprovisioning path, which is
// the highest-value thing this feature does; refusing it would also leave the
// IdP re-sending a write it can never satisfy, and Entra retries a failing write
// every cycle until it quarantines the whole application - taking deprovisioning
// down with it. Failing closed on the safe direction costs more than it protects.
async fn reject_unmanaged_group_add(group: &Group, token: &ScimToken, conn: &DbConn) -> Result<(), ScimError> {
    if scim_may_add_members(group, token, conn).await {
        return Ok(());
    }
    Err(ScimError::bad_request(
        "mutability",
        "This group grants collection access and is not managed by SCIM (no externalId, or it \
         grants access to all collections); members can be removed from it but not added. Add \
         them in the web vault",
    ))
}

// Refuses SETTING an externalId onto an admin-owned, access-granting group.
//
// This is the mirror of `reject_privileged_grant` on the user side, and it
// closes a privilege escalation that `reject_unmanaged_group_add` alone does
// not. `scim_may_add_members` treats `external_id.is_some()` as proof that SCIM
// owns a group, so the FIRST assignment of an externalId is an ownership
// transfer: a token holder could stamp an externalId on a web-vault group that
// grants a sensitive collection and then add a member they control, reaching
// plaintext collection access nobody granted. Because the externalId write is
// itself the primitive, guarding only the member-add (or reordering writes
// within one handler) leaves a two-request sequence open - the write must be
// guarded directly, on every path that performs it.
//
// Evaluated against the group as loaded from the database, BEFORE any externalId
// mutation. Only a first assignment adopts: a group that already carries an
// externalId is already SCIM-correlated, and clearing one (empty value) is the
// opposite of a grant and never reaches here. The protected set is exactly the
// one `scim_may_add_members` refuses - `access_all` or collection-granting.
async fn reject_privileged_group_adoption(
    group: &Group,
    new_external_id: &str,
    token: &ScimToken,
    conn: &DbConn,
) -> Result<(), ScimError> {
    if new_external_id.trim().is_empty() || group.external_id.is_some() {
        return Ok(());
    }
    if group_confers_access(group, token, conn).await {
        return Err(ScimError::bad_request(
            "mutability",
            "This group grants collection access and is not managed by SCIM; its externalId \
             cannot be set through SCIM. Correlate it in the web vault instead",
        ));
    }
    Ok(())
}

// Refuses CLEARING the externalId of a group that confers collection access.
//
// The exact mirror of `reject_privileged_group_adoption`, and it exists because
// that function is one-way. Adoption refuses to ever SET an externalId on a
// collection-granting group, so clearing one is irreversible through the API: a
// single write strands an administrator's group outside SCIM's reach forever,
// with no path back short of the web vault.
//
// Asked of `group_confers_access`, NOT `scim_may_add_members`. The latter
// returns `true` the moment `external_id.is_some()`, which is true of every
// group that has an externalId to clear - so a guard built on it fires only for
// `access_all` groups and silently waves through the collection-granting case
// it was written for.
async fn reject_privileged_group_abandonment(group: &Group, token: &ScimToken, conn: &DbConn) -> Result<(), ScimError> {
    if group.external_id.is_none() {
        return Ok(());
    }
    if group_confers_access(group, token, conn).await {
        return Err(ScimError::bad_request(
            "mutability",
            "This group grants collection access and is not managed by SCIM; clearing its externalId \
             would put it permanently out of SCIM's reach. Change it in the web vault",
        ));
    }
    Ok(())
}

// Replaces the group's member set with exactly member_ids, as a diff rather
// than delete-all-then-reinsert. There is no transaction available here, so a
// wipe-and-rebuild leaves the group empty (and its collection access dead) if
// any single insert fails partway through. Diffing touches only the rows that
// actually change, so a failure can never remove a member it was not asked to.
// Whether `set_members` applies the unmanaged-group guard.
#[derive(PartialEq, Eq)]
enum AddPolicy {
    /// Refuse additions to a group SCIM does not own.
    Enforce,
    /// The group was created by this same request, so it is empty and carries no
    /// collection grants at all: there is nothing to escalate into, and its
    /// externalId (if the client sent none) is not a signal about ownership.
    NewGroup,
}

async fn set_members(
    group: &Group,
    member_ids: Vec<MembershipId>,
    add_policy: &AddPolicy,
    token: &ScimToken,
    conn: &DbConn,
) -> Result<(), ScimError> {
    let wanted: HashSet<MembershipId> = member_ids.into_iter().collect();
    let current: HashSet<MembershipId> = GroupUser::find_by_group(&group.uuid, &token.org_uuid, conn)
        .await
        .into_iter()
        .map(|group_user| group_user.users_organizations_uuid)
        .collect();

    // Checked before the first write, not per row, so a refused replace leaves
    // the group exactly as it was rather than half-applied. A replace that only
    // REMOVES members is still allowed on an unmanaged group.
    let mut additions = wanted.difference(&current).peekable();
    if *add_policy == AddPolicy::Enforce && additions.peek().is_some() {
        reject_unmanaged_group_add(group, token, conn).await?;
    }
    for member_id in wanted.difference(&current) {
        let mut group_user = GroupUser::new(group.uuid.clone(), member_id.clone());
        group_user.save(conn).await.map_err(|_| ScimError::internal())?;
    }
    for member_id in current.difference(&wanted) {
        GroupUser::delete_by_group_and_member(&group.uuid, member_id, conn).await.map_err(|_| ScimError::internal())?;
    }
    Ok(())
}

// Applies one PATCH member operation. Removes resolve through the org scope
// like adds do: GroupUser::delete_by_group_and_member looks the membership up
// globally to bump its sync revision, so an unscoped id would let this org
// touch a member of another one. A value that is not a member of this org was
// already a no-op, and stays one - Entra retries removals.
// Runs the SIDE-EFFECT-FREE failures every member op in a PATCH would hit,
// before the first one writes anything.
//
// PATCH applies its ops in sequence and each `GroupUser::save` commits on its
// own, with no transaction around the loop. Without this, an early add could
// commit - granting real collection access - and a later op could then fail,
// returning 4xx while that access stayed. Worse, the handler returns through
// `?` before `log_group_event`, so the committed grant was never written to the
// organization event log: access granted, audit trail silent.
//
// Resolving every op's values here means an unresolvable member id or an
// unmanaged-group addition is refused while the group is still untouched. This
// is the same "resolve before writing" discipline `put_group` and
// `precheck_active_change` already apply.
async fn precheck_member_ops(
    group: &Group,
    member_ops: &[MemberOp],
    token: &ScimToken,
    conn: &DbConn,
) -> Result<(), ScimError> {
    if member_ops.is_empty() {
        return Ok(());
    }

    // The ownership guard is decided by REPLAYING the ops against the group's
    // current member set, not by asking "is any op an add".
    //
    // A `Replace` is an add whenever it names someone the group does not
    // already have - `set_members` guards exactly that case, and lets a replace
    // that only removes through on an unmanaged group. Checking the op's kind
    // instead missed it entirely, so a PATCH of [remove x, replace [a]] on an
    // unmanaged group committed the removal and then 400'd on the replace,
    // returning through `?` before `log_group_event`: access changed, audit
    // trail silent. That is the failure this whole function exists to prevent.
    //
    // Removes are projected too even though they can never fail here. Skipping
    // them would leave a later `Replace` comparing against a member this PATCH
    // has already taken out, so a re-add would not read as an addition and the
    // guard would be laxer than the apply loop - the same hole, one op further
    // along.
    let mut projected: HashSet<MembershipId> = GroupUser::find_by_group(&group.uuid, &token.org_uuid, conn)
        .await
        .into_iter()
        .map(|group_user| group_user.users_organizations_uuid)
        .collect();
    let mut needs_add_permission = false;

    for member_op in member_ops {
        match member_op {
            // Both resolve strictly: an unknown value is a 400 either way.
            MemberOp::Replace(values) => {
                let wanted: HashSet<MembershipId> = resolve_members(values, token, conn).await?.into_iter().collect();
                needs_add_permission |= wanted.difference(&projected).next().is_some();
                projected = wanted;
            }
            MemberOp::Add(values) => {
                // `apply_member_op` guards ANY non-empty add, including a
                // redundant one, so mirror that rather than the narrower
                // "introduces someone" test used for a replace. A precheck that
                // is laxer than the apply loop is worse than no precheck.
                needs_add_permission |= !values.is_empty();
                projected.extend(resolve_members(values, token, conn).await?);
            }
            // Removes are deliberately tolerant of unknown values (Entra retries
            // removals, and "already gone" is the steady state), so there is no
            // failure here to hoist - only the projection above to maintain.
            MemberOp::Remove(values) => {
                for value in values {
                    projected.remove(&MembershipId::from(value.clone()));
                }
            }
        }
    }

    if needs_add_permission {
        reject_unmanaged_group_add(group, token, conn).await?;
    }
    Ok(())
}

async fn apply_member_op(
    group: &Group,
    member_op: &MemberOp,
    token: &ScimToken,
    conn: &DbConn,
) -> Result<(), ScimError> {
    match member_op {
        MemberOp::Replace(values) => {
            let member_ids = resolve_members(values, token, conn).await?;
            set_members(group, member_ids, &AddPolicy::Enforce, token, conn).await?;
        }
        MemberOp::Add(values) => {
            if !values.is_empty() {
                reject_unmanaged_group_add(group, token, conn).await?;
            }
            for member_id in resolve_members(values, token, conn).await? {
                let mut group_user = GroupUser::new(group.uuid.clone(), member_id);
                group_user.save(conn).await.map_err(|_| ScimError::internal())?;
            }
        }
        MemberOp::Remove(values) => {
            // One batched lookup for the whole list, same as the add path. A
            // value that is not a member of this org stays a silent no-op
            // rather than a 400: Entra retries removals, and "already gone" is
            // the expected steady state for one.
            let requested: Vec<MembershipId> = values.iter().map(|value| value.clone().into()).collect();
            let known: HashSet<MembershipId> = Membership::find_by_uuids_and_org(&requested, &token.org_uuid, conn)
                .await
                .into_iter()
                .map(|member| member.uuid)
                .collect();
            for member_id in requested.iter().filter(|member_id| known.contains(member_id)) {
                GroupUser::delete_by_group_and_member(&group.uuid, member_id, conn)
                    .await
                    .map_err(|_| ScimError::internal())?;
            }
        }
    }
    Ok(())
}

#[derive(FromForm)]
pub struct GroupListParams {
    filter: Option<String>,
    #[field(name = "startIndex")]
    start_index: Option<i64>,
    count: Option<i64>,
    #[field(name = "excludedAttributes")]
    excluded_attributes: Option<String>,
}

#[get("/v2/<_>/Groups?<params..>")]
async fn list_groups(params: GroupListParams, token: ScimToken, conn: DbConn) -> Result<ScimResponse, ScimError> {
    check_groups_enabled()?;

    // Entra requests excludedAttributes=members on list syncs; honoring it
    // avoids loading every group's member set.
    let include_members = !params.excluded_attributes.as_deref().is_some_and(|excluded| excluded.contains("members"));

    let (start_index, count) = crate::api::scim::page_bounds(params.start_index, params.count);

    // As in list_users: a filtered lookup is small and pages in memory, while
    // the unfiltered enumeration pages in the database on a stable order so a
    // group cannot be skipped or repeated across a client's separate requests.
    let (total, page): (usize, Vec<Group>) = if let Some(raw_filter) = params.filter.as_deref() {
        let eq = parse_eq_filter(raw_filter)?;
        let matched: Vec<Group> = match eq.attribute.as_str() {
            // displayName is caseExact=false in RFC 7643 section 4.2, so `eq`
            // must match case-insensitively - the same way the Users userName
            // filter does via User::find_by_mail's lowercasing. Done in Rust
            // because the three backends disagree about collation defaults;
            // groups per organization are bounded in a way memberships are not.
            "displayname" => Group::find_by_organization(&token.org_uuid, &conn)
                .await
                .into_iter()
                .filter(|g| g.name.eq_ignore_ascii_case(&eq.value))
                .collect(),
            "externalid" => {
                Group::find_by_external_id_and_org(&eq.value, &token.org_uuid, &conn).await.into_iter().collect()
            }
            _ => {
                return Err(ScimError::bad_request(
                    "invalidFilter",
                    "Filterable attributes are displayName and externalId",
                ));
            }
        };
        let total = matched.len();
        (total, matched.into_iter().skip(start_index - 1).take(count).collect())
    } else {
        let total = usize::try_from(Group::count_by_org(&token.org_uuid, &conn).await).unwrap_or(0);
        let offset = i64::try_from(start_index - 1).unwrap_or(i64::MAX);
        let limit = i64::try_from(count).unwrap_or(0);
        (total, Group::find_by_organization_paged(&token.org_uuid, limit, offset, &conn).await)
    };

    // One query for the whole page's membership, not one per group.
    let mut members_by_group: HashMap<GroupId, Vec<MembershipId>> = HashMap::new();
    if include_members {
        let group_ids: Vec<GroupId> = page.iter().map(|group| group.uuid.clone()).collect();
        for group_user in GroupUser::find_by_groups(&group_ids, &token.org_uuid, &conn).await {
            members_by_group.entry(group_user.groups_uuid).or_default().push(group_user.users_organizations_uuid);
        }
    }

    let resources: Vec<Value> = page
        .iter()
        .map(|group| {
            // A group with no members must still serialize "members": [], so
            // absent from the map is not the same as excluded by the client.
            let members = include_members.then(|| members_by_group.get(&group.uuid).map_or(&[][..], Vec::as_slice));
            scim_group_body(group, &token, members)
        })
        .collect();

    Ok(crate::api::scim::list_response(total, start_index, &resources))
}

#[get("/v2/<_>/Groups/<group_id>")]
async fn get_group(group_id: GroupId, token: ScimToken, conn: DbConn) -> Result<ScimResponse, ScimError> {
    check_groups_enabled()?;
    let Some(group) = Group::find_by_uuid_and_org(&group_id, &token.org_uuid, &conn).await else {
        return Err(ScimError::not_found());
    };
    Ok(ScimResponse::ok(to_scim_group(&group, &token, true, &conn).await))
}

#[post("/v2/<_>/Groups", data = "<data>")]
async fn post_group(
    data: Result<ScimJson<ScimGroupRequest>, ScimError>,
    token: ScimToken,
    conn: DbConn,
) -> Result<ScimResponse, ScimError> {
    check_groups_enabled()?;
    let request = data?.0;

    let Some(display_name) = request.display_name.as_deref().filter(|n| !n.trim().is_empty()) else {
        return Err(ScimError::bad_request("invalidValue", "displayName is required"));
    };
    crate::api::scim::check_attribute_len("displayName", display_name, crate::api::scim::SCIM_MAX_GROUP_NAME_LEN)?;

    if let Some(external_id) = request.external_id.as_deref() {
        crate::api::scim::check_attribute_len("externalId", external_id, crate::api::scim::SCIM_MAX_EXTERNAL_ID_LEN)?;
        if Group::find_by_external_id_and_org(external_id, &token.org_uuid, &conn).await.is_some() {
            return Err(ScimError::conflict("uniqueness", "A group with this externalId already exists"));
        }
    }

    // Resolve members before creating anything, so a bad member list cannot
    // leave a half-created group behind. On create, omitted members and an
    // empty list mean the same thing: a group with no members.
    let request_members = request.members.as_deref().unwrap_or_default();
    check_member_count(request_members.len())?;
    let values: Vec<String> = request_members.iter().map(|member| member.value.clone()).collect();
    let member_ids = resolve_members(&values, &token, &conn).await?;

    let mut group = Group::new(token.org_uuid.clone(), display_name.to_owned(), false, request.external_id.clone());
    save_group_with_external_id(&mut group, &conn).await?;
    set_members(&group, member_ids, &AddPolicy::NewGroup, &token, &conn).await?;

    log_group_event(EventType::GroupCreated, &group.uuid, &token, &conn).await;

    let location = crate::api::scim::resource_location(&token.org_uuid, "Groups", &group.uuid);
    let body = to_scim_group(&group, &token, true, &conn).await;
    Ok(ScimResponse::created(location, body))
}

// PUT replaces the attributes it carries: displayName, externalId, and the
// member set. members omitted (as opposed to explicitly empty) leaves the
// member set unchanged, so a sparse non-Entra client cannot wipe a group by
// accident; Entra always sends the full member list.
#[put("/v2/<_>/Groups/<group_id>", data = "<data>")]
async fn put_group(
    group_id: GroupId,
    data: Result<ScimJson<ScimGroupRequest>, ScimError>,
    token: ScimToken,
    conn: DbConn,
) -> Result<ScimResponse, ScimError> {
    check_groups_enabled()?;
    let Some(mut group) = Group::find_by_uuid_and_org(&group_id, &token.org_uuid, &conn).await else {
        return Err(ScimError::not_found());
    };
    let request = data?.0;

    // Resolve everything before writing anything, so a bad member list or a
    // conflicting externalId cannot leave a half-applied replacement behind.
    let member_ids = match request.members.as_deref() {
        Some(members) => {
            check_member_count(members.len())?;
            let values: Vec<String> = members.iter().map(|member| member.value.clone()).collect();
            Some(resolve_members(&values, &token, &conn).await?)
        }
        None => None,
    };
    // Guard the externalId WRITE, not just the member-add: setting an externalId
    // is the group-adoption primitive and clearing one is irreversible through
    // this API. Both are evaluated on the DB-loaded group, before any mutation
    // below, and both run BEFORE the `set_members` call at the end of the
    // handler - a PUT carrying `externalId: ""` and a member list must not
    // commit the clear and then fail the members.
    //
    // `set_external_id` treats a whitespace-only value as NULL, so the clear
    // branch has to test the same way or a PUT of `"   "` would slip past the
    // adoption guard, past this one, and clear the correlation anyway.
    if let Some(external_id) = request.external_id.as_deref() {
        if external_id.trim().is_empty() {
            reject_privileged_group_abandonment(&group, &token, &conn).await?;
        } else {
            check_external_id_available(&group, external_id, &token, &conn).await?;
            reject_privileged_group_adoption(&group, external_id, &token, &conn).await?;
        }
    }

    // Present-but-blank is an error, not a silent no-op, for the same reason as
    // the PATCH path: displayName is required (RFC 7643 section 4.2), and a 200
    // that did not apply the write makes the client record it as applied and
    // never retry, leaving the directory and the vault permanently disagreeing.
    // Absent (None) still means "leave the name alone" - that is what makes a
    // sparse PUT safe.
    if let Some(display_name) = request.display_name.as_deref() {
        if display_name.trim().is_empty() {
            return Err(ScimError::bad_request("invalidValue", "displayName is required and cannot be cleared"));
        }
        crate::api::scim::check_attribute_len("displayName", display_name, crate::api::scim::SCIM_MAX_GROUP_NAME_LEN)?;
        group.name = display_name.to_owned();
    }
    if request.external_id.is_some() {
        group.set_external_id(request.external_id.clone());
    }
    save_group_with_external_id(&mut group, &conn).await?;
    if let Some(member_ids) = member_ids {
        set_members(&group, member_ids, &AddPolicy::Enforce, &token, &conn).await?;
    }

    log_group_event(EventType::GroupUpdated, &group.uuid, &token, &conn).await;

    Ok(ScimResponse::ok(to_scim_group(&group, &token, true, &conn).await))
}

#[patch("/v2/<_>/Groups/<group_id>", data = "<data>")]
async fn patch_group(
    group_id: GroupId,
    data: Result<ScimJson<PatchOp>, ScimError>,
    token: ScimToken,
    conn: DbConn,
) -> Result<ScimResponse, ScimError> {
    check_groups_enabled()?;
    let Some(mut group) = Group::find_by_uuid_and_org(&group_id, &token.org_uuid, &conn).await else {
        return Err(ScimError::not_found());
    };

    let patch = parse_group_patch(&data?.0)?;
    check_member_op_count(patch.member_ops.len())?;
    check_member_count(patch.member_count())?;

    // Filtered on `trim()`, matching `set_external_id`, which stores a
    // whitespace-only value as NULL. Testing `is_empty()` alone routed `"   "`
    // down the SET path while the write below cleared the row.
    let new_external_id = patch.external_id.as_deref().filter(|id| !id.trim().is_empty());
    if let Some(external_id) = new_external_id {
        check_external_id_available(&group, external_id, &token, &conn).await?;
        // See put_group: the externalId write is the adoption primitive, so it
        // is guarded here on the DB-loaded group, before any mutation.
        reject_privileged_group_adoption(&group, external_id, &token, &conn).await?;
    } else if patch.external_id.is_some() {
        // The clear direction, guarded before `precheck_member_ops` so a PATCH
        // of [replace externalId "", add members] cannot commit the clear and
        // then 400 on the members.
        reject_privileged_group_abandonment(&group, &token, &conn).await?;
    }

    // displayName is required on a Group (RFC 7643 section 4.2), so a PATCH
    // trying to clear it is an error rather than a silently ignored no-op that
    // still returns 200 - the client would record the change as applied and
    // never retry, leaving the directory and the vault permanently disagreeing.
    let new_name = patch.display_name.as_deref();
    if let Some(display_name) = new_name {
        if display_name.trim().is_empty() {
            return Err(ScimError::bad_request("invalidValue", "displayName is required and cannot be cleared"));
        }
        crate::api::scim::check_attribute_len("displayName", display_name, crate::api::scim::SCIM_MAX_GROUP_NAME_LEN)?;
        group.name = display_name.to_owned();
    }
    // Every member op's resolvable-and-permitted check runs before the first
    // write of this request, so a later op cannot fail after an earlier one has
    // already committed an access grant that the audit log never records.
    //
    // Deliberately BEFORE the in-memory externalId change below, and that order
    // is load-bearing. `scim_may_add_members` branches on
    // `group.external_id.is_some()`, so mutating the struct first meant a single
    // PATCH of [remove externalId, add members] evaluated the ownership guard
    // against a group this request had just made look unmanaged - and rejected
    // its own member-add with a 400 the client could never satisfy. A
    // provisioning engine retries a failing write every cycle until it
    // quarantines the application, which is the failure this module is built to
    // avoid. The guards belong on the group as the database has it.
    precheck_member_ops(&group, &patch.member_ops, &token, &conn).await?;

    // An empty externalId is a PATCH remove; set_external_id stores it as NULL.
    // Both directions were permitted above, on the group as the database has
    // it, before `precheck_member_ops` and before any write.
    if let Some(external_id) = patch.external_id.clone() {
        group.set_external_id(Some(external_id));
    }

    // One save covers both owned attributes; skip the write for member-only patches.
    if new_name.is_some() || patch.external_id.is_some() {
        save_group_with_external_id(&mut group, &conn).await?;
    }

    // In the order the client sent them, per RFC 7644 section 3.5.2. Applying
    // them out of order (or dropping adds because a replace was also present)
    // silently changes who has access.
    for member_op in &patch.member_ops {
        apply_member_op(&group, member_op, &token, &conn).await?;
    }

    log_group_event(EventType::GroupUpdated, &group.uuid, &token, &conn).await;

    Ok(ScimResponse::ok(to_scim_group(&group, &token, true, &conn).await))
}

// Deleting a group only removes an access mapping: it carries no E2EE state
// (unlike memberships, where delete would destroy the wrapped org key), so a
// real delete is safe and matches RFC semantics.
//
// It is still gated by the same ownership rule as additions. SCIM resolves a
// group by uuid, so without this a token holder could enumerate every group in
// the organization (GET /Groups returns them all) and delete the
// administrator-curated ones, dropping their collections_groups rows and every
// access grant with them. That is recoverable - no E2EE state is destroyed, the
// admin re-creates the group and re-grants - which is why this is a lower bar
// than the membership paths, not why it should be unguarded.
//
// The asymmetry with removals is deliberate and matches
// reject_unmanaged_group_add: removing a MEMBER from an unmanaged group is
// still allowed, because that reduces access and is the deprovisioning path.
// Deleting the group itself is not deprovisioning - it destroys an
// administrator's configuration - so it is refused for exactly the groups
// additions are refused for.
#[delete("/v2/<_>/Groups/<group_id>")]
async fn delete_group(group_id: GroupId, token: ScimToken, conn: DbConn) -> Result<ScimResponse, ScimError> {
    check_groups_enabled()?;
    let Some(group) = Group::find_by_uuid_and_org(&group_id, &token.org_uuid, &conn).await else {
        return Err(ScimError::not_found());
    };
    if !scim_may_add_members(&group, &token, &conn).await {
        return Err(ScimError::bad_request(
            "mutability",
            "This group grants collection access and is not managed by SCIM (no externalId, or it \
             grants access to all collections); it cannot be deleted through SCIM. Delete it in the \
             web vault",
        ));
    }
    let group_uuid = group.uuid.clone();
    group.delete(&token.org_uuid, &conn).await.map_err(|_| ScimError::internal())?;
    // Log only after the delete succeeds, so the audit log never claims a
    // deletion that failed.
    log_group_event(EventType::GroupDeleted, &group_uuid, &token, &conn).await;
    Ok(ScimResponse::no_content())
}
