//
// SCIM /Users endpoints. The SCIM User id is the org-membership uuid
// (MembershipId), not the global user uuid: SCIM is org-scoped and one person
// can belong to several organizations.
//
// Deprovisioning maps to REVOKE, never delete: the membership row and its
// akey survive, so restore is lossless and needs no re-confirmation. This is
// a deliberate deviation from RFC 7644 DELETE semantics, matching the
// existing Directory Connector import endpoint, and it means a compromised
// SCIM token cannot destroy memberships.
//
// Provisioning creates at most Invited (or Accepted when mail is disabled
// and the user already has credentials). Confirmed requires an admin client
// to wrap the org key for the member; no server-side path can do that.
//
use std::{collections::HashMap, sync::LazyLock};

use rocket::Route;
use serde_json::Value;

use crate::{
    api::{
        EmptyResult,
        core::log_event,
        scim::{
            SCIM_ACTOR, SCIM_DEVICE_TYPE, ScimJson, ScimResponse,
            error::ScimError,
            filter::parse_eq_filter,
            guard::ScimToken,
            models::ScimUserRequest,
            patch::{PatchOp, parse_user_patch},
        },
    },
    db::{
        DbConn,
        models::{
            EventType, Invitation, Membership, MembershipId, MembershipStatus, MembershipType, OrgPolicy, Organization,
            User, UserId,
        },
    },
    mail,
    util::is_valid_email,
};

pub fn routes() -> Vec<Route> {
    routes![list_users, get_user, post_user, put_user, patch_user, delete_user]
}

// The single place the revocation encoding is interpreted: revoked statuses
// are stored as status - 128 (ACTIVATE_REVOKE_DIFF), so every stored revoked
// value is <= Revoked (-1). Never compare equality against Revoked.
fn membership_active(member: &Membership) -> bool {
    member.status > MembershipStatus::Revoked as i32
}

// SCIM never grants administrative privilege, in any direction.
//
// It cannot create one (post_user forces atype = User) and cannot promote to
// one (neither PUT nor PATCH writes atype), so a privileged membership was
// always made by a human in the web vault. This guard closes the remaining
// grant-shaped path: reinstating a revoked administrator, and linking one to a
// directory object. Restore is lossless - the akey survives revocation - so
// `active: true` on a revoked Owner returns full vault access with no admin
// action and no re-confirmation. The credential is a static, non-expiring token
// held by the IdP, so a departing administrator who kept their master password
// and retained that token could otherwise reinstate themselves.
//
// Revocation is deliberately NOT blocked. Deprovisioning an administrator from
// the IdP is a legitimate offboard, and refusing it would make the highest-value
// path of this whole feature a silent no-op for the accounts that matter most.
// The two failure modes are not symmetric: a malicious mass-revoke is
// recoverable (the last-confirmed-owner guard leaves one Owner standing, who can
// restore losslessly from the web vault), whereas an admin who is never
// deprovisioned keeps access until somebody audits.
fn is_privileged(member: &Membership) -> bool {
    member.atype != MembershipType::User as i32
}

fn reject_privileged_grant(member: &Membership) -> Result<(), ScimError> {
    if is_privileged(member) {
        return Err(ScimError::bad_request(
            "mutability",
            "This member holds an administrative role; SCIM can deprovision it but cannot reinstate \
             or link it. Restore this member in the web vault",
        ));
    }
    Ok(())
}

fn to_scim_user(member: &Membership, user: &User, token: &ScimToken) -> Value {
    let location = crate::api::scim::resource_location(&token.org_uuid, "Users", &member.uuid);
    json!({
        "schemas": [crate::api::scim::discovery::USER_SCHEMA_URN],
        "id": member.uuid,
        "externalId": member.external_id,
        "userName": user.email,
        "displayName": user.name,
        "active": membership_active(member),
        "emails": [{"value": user.email, "primary": true, "type": "work"}],
        "meta": {
            "resourceType": "User",
            "location": location,
        },
    })
}

async fn log_scim_event(event_type: EventType, member: &Membership, token: &ScimToken, conn: &DbConn) {
    log_event(
        event_type as i32,
        &member.uuid,
        &token.org_uuid,
        &SCIM_ACTOR.into(),
        SCIM_DEVICE_TYPE,
        &token.ip.ip,
        conn,
    )
    .await;
}

#[derive(FromForm)]
pub struct ListParams {
    filter: Option<String>,
    #[field(name = "startIndex")]
    start_index: Option<i64>,
    count: Option<i64>,
}

#[get("/v2/<_>/Users?<params..>")]
async fn list_users(params: ListParams, token: ScimToken, conn: DbConn) -> Result<ScimResponse, ScimError> {
    let (start_index, count) = crate::api::scim::page_bounds(params.start_index, params.count);

    // A filter resolves through a unique key, so it matches at most one
    // membership and is cheap to page in memory. The unfiltered enumeration is
    // the one Entra runs across the whole organization, so it pages in the
    // database instead: see Membership::find_by_org_paged for why the stable
    // ORDER BY matters as much as the LIMIT - without it a member can land on
    // two pages of one sync, or on none at all.
    let (total, page): (usize, Vec<Membership>) = if let Some(raw_filter) = params.filter.as_deref() {
        let eq = parse_eq_filter(raw_filter)?;
        let matched: Vec<Membership> = match eq.attribute.as_str() {
            // find_by_mail lowercases internally, so a mixed-case userName
            // from Entra still matches the lowercased stored email.
            "username" | "emails.value" => match User::find_by_mail(&eq.value, &conn).await {
                Some(user) => {
                    Membership::find_by_user_and_org(&user.uuid, &token.org_uuid, &conn).await.into_iter().collect()
                }
                None => Vec::new(),
            },
            "externalid" => {
                Membership::find_by_external_id_and_org(&eq.value, &token.org_uuid, &conn).await.into_iter().collect()
            }
            _ => {
                return Err(ScimError::bad_request(
                    "invalidFilter",
                    "Filterable attributes are userName, emails.value and externalId",
                ));
            }
        };
        let total = matched.len();
        (total, matched.into_iter().skip(start_index - 1).take(count).collect())
    } else {
        let total = usize::try_from(Membership::count_by_org(&token.org_uuid, &conn).await).unwrap_or(0);
        let offset = i64::try_from(start_index - 1).unwrap_or(i64::MAX);
        let limit = i64::try_from(count).unwrap_or(0);
        (total, Membership::find_by_org_paged(&token.org_uuid, limit, offset, &conn).await)
    };
    let user_ids: Vec<UserId> = page.iter().map(|member| member.user_uuid.clone()).collect();
    let users: HashMap<UserId, User> =
        User::find_by_uuids(&user_ids, &conn).await.into_iter().map(|user| (user.uuid.clone(), user)).collect();

    let mut resources = Vec::with_capacity(page.len());
    for member in &page {
        // A membership always references a user; a missing row would be a
        // dangling foreign key, so surface it as a 500 rather than skip.
        let Some(user) = users.get(&member.user_uuid) else {
            return Err(ScimError::internal());
        };
        resources.push(to_scim_user(member, user, &token));
    }

    Ok(crate::api::scim::list_response(total, start_index, &resources))
}

#[get("/v2/<_>/Users/<member_id>")]
async fn get_user(member_id: MembershipId, token: ScimToken, conn: DbConn) -> Result<ScimResponse, ScimError> {
    let Some(member) = Membership::find_by_uuid_and_org(&member_id, &token.org_uuid, &conn).await else {
        return Err(ScimError::not_found());
    };
    let Some(user) = User::find_by_uuid(&member.user_uuid, &conn).await else {
        return Err(ScimError::internal());
    };
    Ok(ScimResponse::ok(to_scim_user(&member, &user, &token)))
}

#[post("/v2/<_>/Users", data = "<data>")]
async fn post_user(
    data: Result<ScimJson<ScimUserRequest>, ScimError>,
    token: ScimToken,
    conn: DbConn,
) -> Result<ScimResponse, ScimError> {
    let request = data?.0;

    let Some(email) = request.email() else {
        return Err(ScimError::bad_request("invalidValue", "userName (or a primary email) must be an email address"));
    };
    if !is_valid_email(email) {
        return Err(ScimError::bad_request("invalidValue", "userName is not a valid email address"));
    }
    // Length as well as shape. `is_valid_email` enforces RFC 5321's per-part
    // limits but permits a ~320-character total, while `users.email` is
    // VARCHAR(255): a 300-character address passes validation, fails the insert
    // on postgresql, and returns a 500 that Entra retries forever.
    crate::api::scim::check_attribute_len("userName", email, crate::api::scim::SCIM_MAX_EMAIL_LEN)?;

    // Same VARCHAR/TEXT-limit reasoning as userName above: the composed
    // displayName lands in `users.name`, which mysql strict mode rejects when it
    // overflows, so cap it here rather than let it surface as an Entra-retried
    // 500. Resolved once and reused when the shell account is created below.
    let display_name = request.display_name();
    if let Some(name) = display_name.as_deref() {
        crate::api::scim::check_attribute_len("displayName", name, crate::api::scim::SCIM_MAX_DISPLAY_NAME_LEN)?;
    }

    // Uniqueness: by externalId and by email, both scoped to the org.
    if let Some(external_id) = request.external_id.as_deref() {
        crate::api::scim::check_attribute_len("externalId", external_id, crate::api::scim::SCIM_MAX_EXTERNAL_ID_LEN)?;
        if Membership::find_by_external_id_and_org(external_id, &token.org_uuid, &conn).await.is_some() {
            return Err(ScimError::conflict("uniqueness", "A member with this externalId already exists"));
        }
    }
    // Looked up once and reused below: Membership::find_by_email_and_org runs
    // User::find_by_mail internally, so resolving the account here as well
    // costs a second identical query on the hottest write path (Entra re-POSTs
    // known users on every sync cycle).
    let existing_user = User::find_by_mail(email, &conn).await;
    if let Some(user) = existing_user.as_ref()
        && Membership::find_by_user_and_org(&user.uuid, &token.org_uuid, &conn).await.is_some()
    {
        return Err(ScimError::conflict("uniqueness", "A member with this userName already exists"));
    }

    let Some(org) = Organization::find_by_uuid(&token.org_uuid, &conn).await else {
        return Err(ScimError::internal());
    };

    // Mirrors the Directory Connector import: link an existing account by
    // email, or create a shell account (no keypair yet) that the invite email
    // lets the person register.
    //
    // The signup gates are the same two `invite_user` applies (organizations.rs)
    // and must not be weaker here: an Invitation row overrides
    // `is_signup_allowed` when the account later registers, so skipping them
    // would let an org-scoped SCIM token punch a hole in a server-wide policy.
    let mut user_created = false;
    // Whether THIS request wrote an Invitation row for a PRE-EXISTING account.
    // An Invitation overrides `is_signup_allowed` at registration time, so one
    // left behind by a failed provision is a standing signup hole for that
    // address - the same registration bypass the rollback below exists to
    // prevent. It only needs tracking on this branch: on the created-user branch
    // `User::delete` takes the invitation with it.
    let mut invitation_created_for_existing_user = false;
    let user = if let Some(user) = existing_user {
        // An account that exists but has never registered still needs an
        // Invitation row when no invite mail will be sent, or it can never
        // complete registration. Same branch as invite_user's Some(user) arm.
        if !crate::api::scim::mail_enabled() && user.password_hash.is_empty() {
            Invitation::new(&user.email).save(&conn).await.map_err(|_| ScimError::internal())?;
            invitation_created_for_existing_user = true;
        }
        user
    } else {
        if !crate::api::scim::invitations_allowed() {
            return Err(ScimError::bad_request("invalidValue", "Creating new accounts is disabled on this server"));
        }
        if !crate::api::scim::is_email_domain_allowed(email) {
            return Err(ScimError::bad_request("invalidValue", "Email domain is not eligible for invitations"));
        }

        let mut new_user = User::new(email, display_name);
        // `users.email` is NOT NULL UNIQUE and `User::save` upserts on the uuid,
        // not the email, so two concurrent POSTs for the same new address both
        // pass the find_by_mail check above and the loser's insert fails here.
        // Entra retries hard enough to reach this. Returning 500 would be the
        // worst answer: it is retried forever and eventually quarantines the
        // tenant. Adopt the winner's account instead - that is exactly the
        // existing-account branch, reached a few microseconds late - and let the
        // membership UNIQUE below decide whether this request creates or 409s.
        if new_user.save(&conn).await.is_err() {
            let Some(raced) = User::find_by_mail(email, &conn).await else {
                return Err(ScimError::internal());
            };
            raced
        } else {
            // The user row is written but nothing references it yet, so a
            // failure here is the one other case that can leak a shell account.
            // Roll it back rather than leave one behind on every retry.
            let invitation_failed = if crate::api::scim::mail_enabled() {
                false
            } else {
                Invitation::new(&new_user.email).save(&conn).await.is_err()
            };
            if invitation_failed {
                // The SAME cross-org check `rollback_provisioning` performs, and
                // for the same reason: `User::delete` cascades EVERY membership,
                // including other organizations'. A concurrent SCIM POST from
                // another org can attach one to this account between the save
                // above and this failure, and a membership's akey is
                // unrecoverable under E2EE. No membership exists for THIS request
                // yet, so any membership at all means the account is no longer
                // ours to destroy - leave the orphan rather than take someone
                // else's data with it.
                if Membership::find_any_state_by_user(&new_user.uuid, &conn).await.is_empty() {
                    if let Err(e) = new_user.delete(&conn).await {
                        error!("SCIM provisioning could not roll back a shell account: {e:#?}");
                    }
                } else {
                    error!(
                        "SCIM provisioning failed after another organization claimed the account; \
                         leaving the user row in place rather than cascading their membership away"
                    );
                }
                return Err(ScimError::internal());
            }
            user_created = true;
            new_user
        }
    };

    // Reaching Accepted directly is only possible when no invite mail will be
    // sent and the account already has credentials to log in with.
    let member_status = if crate::api::scim::mail_enabled() || user.password_hash.is_empty() {
        MembershipStatus::Invited as i32
    } else {
        MembershipStatus::Accepted as i32
    };

    // RFC 7644 allows creating a resource already deactivated; store the
    // membership pre-revoked and send no invite mail in that case.
    let create_active = request.active.is_none_or(|b| b.0);

    let mut member = Membership::new(user.uuid.clone(), token.org_uuid.clone(), Some(org.billing_email.clone()));
    member.set_external_id(request.external_id.clone());
    member.access_all = false;
    member.atype = MembershipType::User as i32;
    member.status = member_status;
    if !create_active {
        member.revoke();
    }
    // The membership is the last row written, so this is the only failure that
    // can leave a user (and possibly an Invitation) behind with nothing to
    // reference it. Roll that back rather than leaking a shell account, and a
    // registration bypass with it, on every retry.
    if member.save(&conn).await.is_err() {
        // users_organizations carries UNIQUE (user_uuid, org_uuid), so a
        // concurrent POST for the same person - Entra retries hard enough to
        // produce this - loses the insert here. The winner's row is valid and
        // must survive, so report the conflict instead of rolling anything back.
        if Membership::find_by_user_and_org(&user.uuid, &token.org_uuid, &conn).await.is_some() {
            return Err(ScimError::conflict("uniqueness", "A member with this userName already exists"));
        }
        rollback_provisioning(user, member, user_created, invitation_created_for_existing_user, &conn).await;
        return Err(ScimError::internal());
    }

    if create_active
        && crate::api::scim::mail_enabled()
        && let Err(e) = mail::send_invite(
            &user,
            token.org_uuid.clone(),
            member.uuid.clone(),
            &org.name,
            Some(org.billing_email.clone()),
        )
        .await
    {
        // The membership is valid and the admin can re-send the invite from the
        // web vault, so a mail outage must not fail the request: returning 500
        // here would make Entra retry create-then-delete on every cycle and
        // eventually quarantine the whole tenant. Same call restore_member makes.
        error!("SCIM provisioning succeeded but the invite mail failed: {e:#?}");
    }

    log_scim_event(EventType::OrganizationUserInvited, &member, &token, &conn).await;
    if !create_active {
        log_scim_event(EventType::OrganizationUserRevoked, &member, &token, &conn).await;
    }

    let location = crate::api::scim::resource_location(&token.org_uuid, "Users", &member.uuid);
    Ok(ScimResponse::created(location, to_scim_user(&member, &user, &token)))
}

// Rollback for a provisioning that failed after its rows were written. The
// destructive decision lives here so it can be tested directly: a user this
// request created is removed entirely (User::delete cascades the membership),
// while a pre-existing account must survive and only the new membership goes.
//
// User::delete cascades EVERY membership, including other organizations'. A
// concurrent SCIM POST from another org can attach one to the same email
// between User::save and the failure here, so re-check before deleting: an
// account that has picked up a membership is no longer ours to destroy, and a
// membership's akey is unrecoverable under E2EE.
pub(super) async fn rollback_provisioning(
    user: User,
    member: Membership,
    user_created: bool,
    invitation_created: bool,
    conn: &DbConn,
) {
    // Any membership OTHER than the one being rolled back means another
    // organization has already attached to this account, so it is no longer
    // ours to delete. The row under rollback is excluded because it may or may
    // not have been written, depending on which step failed.
    // Captured before `user` is moved into `User::delete` below.
    let email = user.email.clone();
    let has_other_memberships =
        Membership::find_any_state_by_user(&user.uuid, conn).await.iter().any(|existing| existing.uuid != member.uuid);
    let user_is_ours = user_created && !has_other_memberships;
    let rollback: EmptyResult = if user_is_ours {
        user.delete(conn).await
    } else {
        member.delete(conn).await
    };
    // An Invitation this request wrote for a PRE-EXISTING account outlives the
    // membership, because only `User::delete` clears one and that path is not
    // taken here. Left behind, it overrides `is_signup_allowed` for that address
    // - a registration bypass that a repeatedly failing provision would leave
    // standing. Taken only when this request created it, so an invitation an
    // administrator issued by hand is never silently revoked.
    if invitation_created && !user_is_ours {
        Invitation::take(&email, conn).await;
    }
    if let Err(rollback_err) = rollback {
        let orphan = if user_is_ours {
            "user"
        } else {
            "membership"
        };
        error!("SCIM provisioning rollback failed, orphaned {orphan} row remains: {rollback_err:#?}");
    }
}

#[patch("/v2/<_>/Users/<member_id>", data = "<data>")]
async fn patch_user(
    member_id: MembershipId,
    data: Result<ScimJson<PatchOp>, ScimError>,
    token: ScimToken,
    conn: DbConn,
) -> Result<ScimResponse, ScimError> {
    let Some(mut member) = Membership::find_by_uuid_and_org(&member_id, &token.org_uuid, &conn).await else {
        return Err(ScimError::not_found());
    };

    let patch = parse_user_patch(&data?.0)?;

    // Before the first write: see precheck_active_change.
    precheck_active_change(&member, patch.active, &token, &conn).await?;

    if let Some(external_id) = patch.external_id.as_deref() {
        update_external_id(&mut member, external_id, &token, &conn).await?;
    }

    match patch.active {
        Some(true) => restore_member(&mut member, &token, &conn).await?,
        Some(false) => revoke_member(&mut member, &token, &conn).await?,
        // Every operation was an accepted-but-ignored attribute (for example
        // a displayName rename): succeed and return the current state.
        None => {}
    }

    let Some(user) = User::find_by_uuid(&member.user_uuid, &conn).await else {
        return Err(ScimError::internal());
    };
    Ok(ScimResponse::ok(to_scim_user(&member, &user, &token)))
}

// PUT replaces the attributes SCIM owns: externalId and active. userName,
// name, and role deliberately do not sync: email is the login identity and
// user.name is global to the person, while roles cannot round-trip through
// Vaultwarden's membership types. The response reflects the actual state.
#[put("/v2/<_>/Users/<member_id>", data = "<data>")]
async fn put_user(
    member_id: MembershipId,
    data: Result<ScimJson<ScimUserRequest>, ScimError>,
    token: ScimToken,
    conn: DbConn,
) -> Result<ScimResponse, ScimError> {
    let Some(mut member) = Membership::find_by_uuid_and_org(&member_id, &token.org_uuid, &conn).await else {
        return Err(ScimError::not_found());
    };
    let request = data?.0;

    // Before the first write: see precheck_active_change.
    precheck_active_change(&member, request.active.map(|b| b.0), &token, &conn).await?;

    if let Some(external_id) = request.external_id.as_deref() {
        update_external_id(&mut member, external_id, &token, &conn).await?;
    }

    match request.active.map(|b| b.0) {
        Some(true) => restore_member(&mut member, &token, &conn).await?,
        Some(false) => revoke_member(&mut member, &token, &conn).await?,
        None => {}
    }

    let Some(user) = User::find_by_uuid(&member.user_uuid, &conn).await else {
        return Err(ScimError::internal());
    };
    Ok(ScimResponse::ok(to_scim_user(&member, &user, &token)))
}

async fn update_external_id(
    member: &mut Membership,
    external_id: &str,
    token: &ScimToken,
    conn: &DbConn,
) -> Result<(), ScimError> {
    if member.external_id.as_deref() == Some(external_id) {
        return Ok(());
    }
    // An empty value means "clear" (a PATCH remove); set_external_id stores it
    // as NULL. Clearing an already-absent externalId is a no-op, not a write.
    let is_clear = external_id.is_empty();
    if is_clear && member.external_id.is_none() {
        return Ok(());
    }
    if !is_clear {
        crate::api::scim::check_attribute_len("externalId", external_id, crate::api::scim::SCIM_MAX_EXTERNAL_ID_LEN)?;
        // The correlation key binds a membership to a directory object. Letting
        // SCIM SET it on an administrator is the first half of linking that
        // account to the IdP, which is the grant-shaped direction this excludes.
        //
        // Clearing is deliberately NOT blocked. Unlinking an account from the
        // directory is the opposite of a grant, and refusing it would leave the
        // IdP re-sending a write it can never satisfy: Entra retries a failing
        // attribute write every cycle and eventually quarantines the whole
        // application, taking deprovisioning down with it. Failing closed on the
        // safe direction costs more than it protects.
        reject_privileged_grant(member)?;
        // The externalId is the correlation key: enforce uniqueness within the
        // org. A clear has nothing to collide with, so it skips this.
        if Membership::find_by_external_id_and_org(external_id, &token.org_uuid, conn).await.is_some() {
            return Err(ScimError::conflict("uniqueness", "A member with this externalId already exists"));
        }
    }
    member.set_external_id(Some(external_id.to_owned()));
    // The check above is no longer the only enforcement: a UNIQUE index now
    // backs it (2026-08-08-000001), which is the point - the check alone was a
    // check-then-write that two concurrent requests could both pass. That makes
    // the losing request fail HERE instead, and a bare internal() would turn it
    // into a 500 - the one status Entra retries forever until it quarantines the
    // application. Re-read to tell the two causes apart and answer the race with
    // the same 409 the sequential case gets.
    if member.save(conn).await.is_err() {
        if Membership::find_by_external_id_and_org(external_id, &token.org_uuid, conn)
            .await
            .is_some_and(|existing| existing.uuid != member.uuid)
        {
            return Err(ScimError::conflict("uniqueness", "A member with this externalId already exists"));
        }
        return Err(ScimError::internal());
    }
    log_scim_event(EventType::OrganizationUserUpdated, member, token, conn).await;
    Ok(())
}

// DELETE deprovisions by revoking, identically to PATCH active:false. The
// membership row is kept: see the module comment.
#[delete("/v2/<_>/Users/<member_id>")]
async fn delete_user(member_id: MembershipId, token: ScimToken, conn: DbConn) -> Result<ScimResponse, ScimError> {
    let Some(mut member) = Membership::find_by_uuid_and_org(&member_id, &token.org_uuid, &conn).await else {
        return Err(ScimError::not_found());
    };
    revoke_member(&mut member, &token, &conn).await?;
    Ok(ScimResponse::no_content())
}

// Runs the SIDE-EFFECT-FREE guards the requested `active` transition would hit.
//
// PUT and PATCH can carry an externalId change and an active change in one
// body, and the externalId write commits first. Without this, a body whose
// active change is going to be refused returned 400 having already persisted
// the correlation key, so the client saw a failed request while half of it had
// landed and would retry a write that was already applied. Resolve what can be
// resolved before writing anything, the way the Group handlers do.
//
// `OrgPolicy::check_user_allowed` is deliberately NOT called here, and this is
// the whole reason this function is scoped the way it is. It reads like a
// predicate but it is not one: with `EMAIL_2FA_AUTO_FALLBACK` set, an org
// enforcing the TwoFactorAuthentication policy, and a member holding no 2FA, it
// calls `two_factor::email::find_and_activate_email_2fa`, which SAVES a
// TwoFactor row (`org_policy.rs`). Hoisting it here would move a persistent
// account mutation ahead of the externalId write and make this function cause
// exactly the half-applied failure it exists to prevent - a request that enables
// email 2FA on someone's account and then returns an error. It stays in
// `restore_member`, where the write it performs happens in the same step as the
// restore it is authorising.
//
// The residual gap that leaves - a policy-blocked restore still commits an
// externalId change made in the same body - is recorded in TODOS.md. It needs a
// read-only policy predicate split out of `check_user_allowed`, which is
// upstream surface.
async fn precheck_active_change(
    member: &Membership,
    active: Option<bool>,
    token: &ScimToken,
    conn: &DbConn,
) -> Result<(), ScimError> {
    match active {
        // Restore of an already-active member is a no-op, so nothing to check.
        Some(true) if !membership_active(member) => {
            reject_privileged_grant(member)?;
        }
        Some(false) if membership_active(member) => {
            reject_last_owner_revoke(member, token, conn).await?;
        }
        _ => {}
    }
    Ok(())
}

// Never leave an organization without an owner.
//
// Reported as 400 rather than 409: RFC 7644 section 3.12 defines the scimType
// keywords for 400, and the only status/keyword pairing it sanctions outside
// that is 409 + uniqueness.
//
// Counted over ACTIVE owners in any status, not confirmed owners only.
// Confirmed-only was wrong in both directions. It let SCIM revoke an
// organization's sole Owner whenever that Owner was still Invited or Accepted
// (count_confirmed returns 0, so the guard never fired), and since
// `reject_privileged_grant` refuses to let SCIM restore a privileged membership,
// the organization was left with no owner and no SCIM path back. Counting active
// owners also keeps the case the confirmed-only test got right: with one
// confirmed Owner and one invited Owner the invited one can still be
// deprovisioned, because two are active.
//
// Upstream `revoke_member_impl` tests only `atype` plus the confirmed count,
// which refuses that legitimate revoke; the difference is deliberate, and the
// reason SCIM does not simply reuse the upstream condition.
//
// This is a check-then-act: the count and the write are separate statements, so
// on its own it is not safe against concurrency. Callers that WRITE must hold
// `OWNER_REVOKE_LOCK` across both - see `revoke_member`. Used bare only by
// `precheck_active_change`, which performs no write and is advisory.
async fn reject_last_owner_revoke(member: &Membership, token: &ScimToken, conn: &DbConn) -> Result<(), ScimError> {
    if member.atype == MembershipType::Owner
        && Membership::count_active_by_org_and_type(&token.org_uuid, MembershipType::Owner, conn).await <= 1
    {
        return Err(ScimError::bad_request("mutability", "Cannot revoke the last owner of the organization"));
    }
    Ok(())
}

// Serialises owner-revocations so the last-owner guard cannot be raced.
//
// The guard counts active Owners and then writes, as two separate statements.
// Two concurrent requests revoking two DIFFERENT Owners each observed a count of
// 2, each concluded it was not the last, and both committed - leaving the
// organization with no Owner at all. SCIM cannot repair that itself, because
// `reject_privileged_grant` refuses to restore a privileged membership.
//
// A conditional UPDATE does not fix this, which is why the lock exists: the two
// requests target different rows, so their row locks never conflict and both
// snapshots still read the pre-revoke count. Fixing it in the database needs
// SERIALIZABLE isolation, a lock on a row both requests contend on, or a
// maintained counter column - and this codebase uses no transactions or row
// locking anywhere, so any of those is an architectural change rather than a
// local one.
//
// What this DOES close: two requests in one process, which is how Vaultwarden is
// overwhelmingly deployed. What it does NOT close: two replicas sharing one
// database, where each holds its own lock. That residual is recorded in
// TODOS.md; it needs the database-level fix above.
//
// One global lock rather than one per organization, deliberately. Owner
// revocation is rare, the lock is taken only when `atype` is Owner - so ordinary
// deprovisioning never touches it - and a per-organization map would grow
// without bound and need eviction logic to solve a problem this does not have.
static OWNER_REVOKE_LOCK: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(|| tokio::sync::Mutex::new(()));

async fn revoke_member(member: &mut Membership, token: &ScimToken, conn: &DbConn) -> Result<(), ScimError> {
    if !membership_active(member) {
        // Already revoked: deprovisioning is idempotent.
        return Ok(());
    }

    // Held across BOTH the count and the write, which is the whole point: the
    // guard below is a check-then-act and is only sound while this is held.
    // Non-owners skip it entirely, so the common path is uncontended.
    let _owner_guard = if member.atype == MembershipType::Owner {
        Some(OWNER_REVOKE_LOCK.lock().await)
    } else {
        None
    };

    // The same guard the PUT/PATCH precheck runs, kept here because delete_user
    // reaches this function without going through that precheck. One helper
    // rather than two copies: the condition and its 400 body were duplicated
    // verbatim, so a change to either could silently apply to one path only.
    //
    // This call is the authoritative one. The precheck runs the same test
    // without the lock and is advisory - it exists to refuse before an
    // externalId write commits, not to decide the outcome.
    reject_last_owner_revoke(member, token, conn).await?;

    member.revoke();
    member.save(conn).await.map_err(|_| ScimError::internal())?;
    log_scim_event(EventType::OrganizationUserRevoked, member, token, conn).await;
    Ok(())
}

async fn restore_member(member: &mut Membership, token: &ScimToken, conn: &DbConn) -> Result<(), ScimError> {
    if membership_active(member) {
        return Ok(());
    }

    reject_privileged_grant(member)?;

    member.restore();
    // Policy check runs on the restored status, mirroring restore_member_impl.
    if let Err(e) = OrgPolicy::check_user_allowed(member, "restore", conn).await {
        // This condition never clears on its own, so the IdP will re-send
        // active:true every cycle and can eventually quarantine the app. Name
        // the member and the policy so an operator can actually find it.
        warn!(
            target: "scim",
            "SCIM restore of member {} in org {} is blocked by an organization policy: {e:#?}",
            member.uuid, token.org_uuid
        );
        return Err(ScimError::bad_request("invalidValue", "Restore is blocked by an organization policy"));
    }
    member.save(conn).await.map_err(|_| ScimError::internal())?;

    // A member restored to Invited has never joined the org. The original
    // invite may never have been sent (created active:false) or have expired,
    // so re-send it; otherwise the person has a membership and shell account
    // they were never told about and cannot register into.
    if member.status == MembershipStatus::Invited as i32
        && crate::api::scim::mail_enabled()
        && let (Some(user), Some(org)) =
            (User::find_by_uuid(&member.user_uuid, conn).await, Organization::find_by_uuid(&token.org_uuid, conn).await)
        && let Err(e) = mail::send_invite(
            &user,
            token.org_uuid.clone(),
            member.uuid.clone(),
            &org.name,
            Some(org.billing_email.clone()),
        )
        .await
    {
        // The membership is already restored and valid; a mail hiccup must not
        // fail the deprovision-reprovision cycle. Surface it in the log.
        error!("SCIM restore succeeded but re-sending the invite failed: {e:#?}");
    }

    log_scim_event(EventType::OrganizationUserRestored, member, token, conn).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member_with_status(status: i32) -> Membership {
        let mut member = Membership::new("test-user".to_owned().into(), "test-org".to_owned().into(), None);
        member.status = status;
        member
    }

    #[test]
    fn active_mapping_handles_revocation_offsets() {
        // Stored revoked values are status - 128; Revoked (-1) itself is a
        // sentinel that never hits the database.
        for (status, expected_active) in [(2, true), (1, true), (0, true), (-126, false), (-127, false), (-128, false)]
        {
            assert_eq!(membership_active(&member_with_status(status)), expected_active, "status {status}");
        }
    }

    #[test]
    fn revoke_restore_arithmetic_round_trips() {
        for initial in [0, 1, 2] {
            let mut member = member_with_status(initial);
            assert!(member.revoke());
            assert_eq!(member.status, initial - 128);
            assert!(!member.revoke(), "revoke must be idempotent");
            assert!(member.restore());
            assert_eq!(member.status, initial);
            assert!(!member.restore(), "restore must be idempotent");
        }
    }

    #[test]
    fn from_i32_still_rejects_revoked_values() {
        // Regression canary: OrgHeaders relies on revoked statuses mapping to
        // None. If upstream ever changes this, revisit membership_active().
        assert!(MembershipStatus::from_i32(-126).is_none());
        assert!(MembershipStatus::from_i32(-128).is_none());
        assert!(MembershipStatus::from_i32(-1).is_none());
    }
}
