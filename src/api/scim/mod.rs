//
// SCIM v2 provisioning endpoints (RFC 7643 / RFC 7644), Entra ID first.
//
// Mounted at /scim (see main.rs). Authentication is the per-organization
// static bearer token checked by guard::ScimToken. Management of that token
// is an admin-session concern and lives under /api via manage::routes().
//
pub mod guard;

mod discovery;
mod error;
mod filter;
mod groups;
mod manage;
mod models;
mod patch;
mod users;

use std::io::Cursor;

use rocket::{
    Catcher, Route,
    data::{Data, FromData, Outcome as DataOutcome},
    http::Status,
    request::Request,
    response::{self, Responder, Response},
};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::db::models::{DeviceType, OrganizationId};

pub use error::ScimError;
pub use manage::routes as manage_routes;

// Synthetic acting user recorded in the org event log for SCIM-driven
// changes, following the ACTING_ADMIN_USER precedent in the admin panel.
//
// It MUST be exactly 36 characters, the length of a UUID. `event.act_user_uuid`
// is CHAR(36) on PostgreSQL, which blank-pads anything shorter: a 35-character
// actor is written fine and then reads back with a trailing space, so it no
// longer equals this constant and anything filtering the event log by actor
// silently stops matching. sqlite and MySQL do not pad, so the bug is invisible
// on two of the three backends. Upstream's ACTING_ADMIN_USER is 36 for the same
// reason - "admin" simply happens to be one character longer than "scim".
pub(crate) const SCIM_ACTOR: &str = "vaultwarden-scim-000000-000000000000";
const _: () = assert!(SCIM_ACTOR.len() == 36, "SCIM_ACTOR must be exactly 36 chars or PostgreSQL will pad it");
// Device type recorded for SCIM events, same as the admin panel actor.
pub(crate) const SCIM_DEVICE_TYPE: i32 = DeviceType::UnknownBrowser as i32;

// Page-size cap advertised in ServiceProviderConfig (filter.maxResults) and
// enforced by every list endpoint; keep the two in sync through this constant.
pub(crate) const SCIM_MAX_RESULTS: usize = 200;
pub(crate) const SCIM_DEFAULT_PAGE_SIZE: i64 = 100;

// A page's worth of ids is passed to `User::find_by_uuids` and
// `GroupUser::find_by_groups` as one `eq_any`, i.e. one bound parameter per id,
// and older SQLite builds cap `SQLITE_MAX_VARIABLE_NUMBER` at 999. Those two
// helpers are unchunked (unlike `Membership::find_by_uuids_and_org`, whose
// input is capped at SCIM_MAX_GROUP_MEMBERS = 1000 and so has to chunk), which
// is safe only while a page stays well under the cap. That coupling lived
// nowhere but in this pair of numbers, and `find_by_groups` swallows a query
// error into `unwrap_or_default()` - so raising the page size past the cap
// would not fail loudly, it would silently report every group as empty. Fail at
// compile time instead.
const _: () = assert!(
    SCIM_MAX_RESULTS < 900,
    "SCIM_MAX_RESULTS bounds an unchunked eq_any; keep it clear of SQLite's 999 bound-parameter cap"
);

// Upper bound on member values accepted in one Group write. Each one costs a
// database round trip to resolve and another to write, so without a cap a
// single body inside SCIM_BODY_LIMIT can drive tens of thousands of sequential
// queries while holding a pooled connection.
pub(crate) const SCIM_MAX_GROUP_MEMBERS: usize = 1000;

// Upper bound on the two free-text attributes SCIM writes to the database.
//
// 300 because that is the narrowest column any of them lands in:
// `groups.external_id` is VARCHAR(300) on mysql and postgresql (and TEXT on
// sqlite). Without this check the backend decides, and the three disagree - a
// 400-character externalId is stored silently on sqlite, truncated or rejected
// on mysql depending on strict mode, and on postgresql fails the insert, which
// surfaces as a 500. A 500 is the worst possible answer here: Entra retries a
// failing write every cycle and eventually quarantines the whole application,
// taking deprovisioning down with it. A 400 tells it to stop.
//
// It also bounds what reaches an index. `users_organizations.external_id` is
// TEXT on every backend, and the postgresql composite index over it is a plain
// btree whose entries cap at about 2704 bytes, so an unvalidated externalId
// could turn a legal request into a hard write failure on one backend only.
pub(crate) const SCIM_MAX_EXTERNAL_ID_LEN: usize = 300;

// `groups.name` is VARCHAR(100) on BOTH mysql and postgresql
// (2022-07-27-110000_add_group_support), so displayName gets its own, much
// tighter cap. Sharing the externalId limit was wrong by 200 characters and
// left exactly the 500 this check exists to prevent: Entra permits group
// display names up to 256 characters, so a perfectly ordinary directory group
// reached it.
pub(crate) const SCIM_MAX_GROUP_NAME_LEN: usize = 100;

// `users.email` is VARCHAR(255) on mysql and postgresql. `is_valid_email`
// enforces RFC 5321's per-part limits (64 local, 255 domain) but permits a
// ~320-character total, so it is not a substitute for this.
pub(crate) const SCIM_MAX_EMAIL_LEN: usize = 255;

// `users.name` is TEXT on mysql (a 65,535-byte cap) and the SCIM body limit is
// 512KiB, so a displayName of a few hundred KB - composed here from
// name.formatted or givenName+familyName - passes JSON validation, fails the
// insert in mysql strict mode, and returns the same Entra-quarantining 500 the
// userName and externalId caps above exist to prevent. 255 matches the web
// vault's own name field and is ample for any real directory display name.
pub(crate) const SCIM_MAX_DISPLAY_NAME_LEN: usize = 255;

// Rejects an over-long attribute before it reaches a column that will decide
// the outcome differently on each backend: stored intact on sqlite, truncated
// or rejected on mysql depending on strict mode, and a failed insert on
// postgresql - which surfaces as a 500, the one status that makes Entra retry
// forever and eventually quarantine the whole application.
//
// Counted in characters, not bytes: the column limits are character limits, and
// a byte count would refuse legal non-ASCII values that fit.
pub(crate) fn check_attribute_len(name: &str, value: &str, max: usize) -> Result<(), ScimError> {
    if value.chars().count() > max {
        return Err(ScimError::bad_request("invalidValue", &format!("{name} must be at most {max} characters")));
    }
    Ok(())
}

// The "scim" data limit: registered in main.rs and used as the fallback when
// the figment carries no limit by that name (e.g. a test rocket built from
// Config::default()).
pub const SCIM_BODY_LIMIT: rocket::data::ByteUnit = rocket::data::ByteUnit::Kibibyte(512);

pub fn routes() -> Vec<Route> {
    let mut routes = discovery::routes();
    routes.append(&mut users::routes());
    routes.append(&mut groups::routes());
    routes
}

// The two config master switches, read through one indirection each.
//
// CONFIG is a process-global LazyLock that reads the environment on first
// deref, so a test binary cannot exercise both the enabled and the disabled
// state: whichever the ctor pinned is the only one reachable. These wrappers
// let a test override the answer for the duration of one test, which is the
// only way to cover the denied side of the two primary kill switches.
#[cfg(test)]
pub(crate) mod test_config {
    use std::sync::atomic::{AtomicU8, Ordering};

    // 0 = defer to CONFIG, 1 = force true, 2 = force false.
    pub(super) static SCIM_ENABLED: AtomicU8 = AtomicU8::new(0);
    pub(super) static ORG_GROUPS_ENABLED: AtomicU8 = AtomicU8::new(0);
    pub(super) static MAIL_ENABLED: AtomicU8 = AtomicU8::new(0);
    pub(super) static INVITATIONS_ALLOWED: AtomicU8 = AtomicU8::new(0);
    pub(super) static EMAIL_DOMAIN_ALLOWED: AtomicU8 = AtomicU8::new(0);

    // Restores the overridden switch when dropped, so a panicking test cannot
    // leak its override into whichever test runs next.
    pub(crate) struct Override(&'static AtomicU8);

    impl Drop for Override {
        fn drop(&mut self) {
            self.0.store(0, Ordering::SeqCst);
        }
    }

    fn set(flag: &'static AtomicU8, value: bool) -> Override {
        flag.store(u8::from(!value) + 1, Ordering::SeqCst);
        Override(flag)
    }

    #[must_use]
    pub(crate) fn scim_enabled(value: bool) -> Override {
        set(&SCIM_ENABLED, value)
    }

    #[must_use]
    pub(crate) fn org_groups_enabled(value: bool) -> Override {
        set(&ORG_GROUPS_ENABLED, value)
    }

    /// Mail is enabled in the hermetic test environment (the realistic
    /// production shape, and what the mail sink needs); use this to exercise
    /// the mail-disabled provisioning branches.
    #[must_use]
    pub(crate) fn mail_enabled(value: bool) -> Override {
        set(&MAIL_ENABLED, value)
    }

    /// The two server-wide signup gates `post_user` applies. Both default to
    /// permissive in the hermetic test environment, so the DENIED side - the
    /// side that actually enforces policy - is only reachable through these.
    #[must_use]
    pub(crate) fn invitations_allowed(value: bool) -> Override {
        set(&INVITATIONS_ALLOWED, value)
    }

    #[must_use]
    pub(crate) fn email_domain_allowed(value: bool) -> Override {
        set(&EMAIL_DOMAIN_ALLOWED, value)
    }

    pub(super) fn resolve(flag: &AtomicU8, configured: bool) -> bool {
        match flag.load(Ordering::SeqCst) {
            1 => true,
            2 => false,
            _ => configured,
        }
    }
}

pub(crate) fn scim_enabled() -> bool {
    let configured = crate::CONFIG.scim_enabled();
    #[cfg(test)]
    return test_config::resolve(&test_config::SCIM_ENABLED, configured);
    #[cfg(not(test))]
    configured
}

pub(crate) fn org_groups_enabled() -> bool {
    let configured = crate::CONFIG.org_groups_enabled();
    #[cfg(test)]
    return test_config::resolve(&test_config::ORG_GROUPS_ENABLED, configured);
    #[cfg(not(test))]
    configured
}

pub(crate) fn mail_enabled() -> bool {
    let configured = crate::CONFIG.mail_enabled();
    #[cfg(test)]
    return test_config::resolve(&test_config::MAIL_ENABLED, configured);
    #[cfg(not(test))]
    configured
}

pub(crate) fn invitations_allowed() -> bool {
    let configured = crate::CONFIG.invitations_allowed();
    #[cfg(test)]
    return test_config::resolve(&test_config::INVITATIONS_ALLOWED, configured);
    #[cfg(not(test))]
    configured
}

pub(crate) fn is_email_domain_allowed(email: &str) -> bool {
    let configured = crate::CONFIG.is_email_domain_allowed(email);
    #[cfg(test)]
    return test_config::resolve(&test_config::EMAIL_DOMAIN_ALLOWED, configured);
    #[cfg(not(test))]
    configured
}

// Clamps SCIM pagination parameters: startIndex is 1-based (RFC 7644
// section 3.4.2.4; zero, negative, and absent all become 1) and a negative
// count collapses to 0 while anything above the cap is truncated.
pub(crate) fn page_bounds(start_index: Option<i64>, count: Option<i64>) -> (usize, usize) {
    let start_index = usize::try_from(start_index.unwrap_or(1)).unwrap_or(1).max(1);
    let count = usize::try_from(count.unwrap_or(SCIM_DEFAULT_PAGE_SIZE)).unwrap_or(0).min(SCIM_MAX_RESULTS);
    (start_index, count)
}

pub(crate) fn list_response(total: usize, start_index: usize, resources: &[Value]) -> ScimResponse {
    ScimResponse::ok(json!({
        "schemas": [discovery::LIST_RESPONSE_URN],
        "totalResults": total,
        "itemsPerPage": resources.len(),
        "startIndex": start_index,
        "Resources": resources,
    }))
}

// Canonical location URL for a Users/Groups resource, used for both the
// Location header and meta.location.
pub(crate) fn resource_location(org_uuid: &OrganizationId, resource_type: &str, id: &dyn std::fmt::Display) -> String {
    format!("{}/scim/v2/{org_uuid}/{resource_type}/{id}", crate::CONFIG.domain())
}

// A JSON body limited by the "scim" size limit. Accepts both
// application/scim+json (what Entra sends) and application/json; rocket's
// own Json<T> would reject the former.
pub struct ScimJson<T>(pub T);

#[rocket::async_trait]
impl<'r, T: DeserializeOwned> FromData<'r> for ScimJson<T> {
    type Error = ScimError;

    async fn from_data(request: &'r Request<'_>, data: Data<'r>) -> DataOutcome<'r, Self> {
        let limit = request.limits().get("scim").unwrap_or(SCIM_BODY_LIMIT);
        let bytes = match data.open(limit).into_bytes().await {
            Ok(bytes) if bytes.is_complete() => bytes.into_inner(),
            Ok(_) => return DataOutcome::Error((Status::PayloadTooLarge, ScimError::payload_too_large())),
            Err(_) => {
                return DataOutcome::Error((
                    Status::BadRequest,
                    ScimError::bad_request("invalidSyntax", "Unreadable body"),
                ));
            }
        };
        match serde_json::from_slice::<T>(&bytes) {
            Ok(value) => DataOutcome::Success(ScimJson(value)),
            Err(e) => {
                warn!(target: "scim", "Rejecting unparseable SCIM body: {e}");
                DataOutcome::Error((Status::BadRequest, ScimError::bad_request("invalidSyntax", "Malformed SCIM body")))
            }
        }
    }
}

// A JSON body with Content-Type application/scim+json, RFC 7644 section 3.1.
pub struct ScimResponse {
    status: Status,
    location: Option<String>,
    body: Option<Value>,
}

impl ScimResponse {
    pub fn ok(body: Value) -> Self {
        Self {
            status: Status::Ok,
            location: None,
            body: Some(body),
        }
    }

    pub fn created(location: String, body: Value) -> Self {
        Self {
            status: Status::Created,
            location: Some(location),
            body: Some(body),
        }
    }

    pub fn no_content() -> Self {
        Self {
            status: Status::NoContent,
            location: None,
            body: None,
        }
    }
}

impl Responder<'_, 'static> for ScimResponse {
    fn respond_to(self, _: &Request<'_>) -> response::Result<'static> {
        let mut builder = Response::build();
        builder.status(self.status);
        if let Some(location) = self.location {
            builder.raw_header("Location", location);
        }
        if let Some(body) = self.body {
            let body = body.to_string();
            builder.header(error::scim_content_type()).sized_body(Some(body.len()), Cursor::new(body));
        }
        builder.ok()
    }
}

// Catchers keep every error under /scim inside the SCIM envelope, including
// guard rejections (which carry only a status). The 401 body is a constant:
// all auth failure causes look identical to the caller.
pub fn catchers() -> Vec<Catcher> {
    catchers![
        scim_bad_request,
        scim_unauthorized,
        scim_not_found,
        scim_unprocessable_entity,
        scim_payload_too_large,
        scim_too_many_requests,
        scim_internal,
        scim_default
    ]
}

#[catch(400)]
fn scim_bad_request() -> ScimError {
    ScimError::bad_request("invalidValue", "Bad request")
}

#[catch(401)]
fn scim_unauthorized() -> ScimError {
    ScimError::unauthorized()
}

#[catch(404)]
fn scim_not_found() -> ScimError {
    ScimError::not_found()
}

// Rocket answers 422 when a path or query parameter fails its guard - a
// malformed resource id, or a non-numeric startIndex. Without this catcher the
// caller receives Rocket's default HTML error page instead of a SCIM envelope,
// which a SCIM client parsing JSON cannot make sense of. Reported as 400
// invalidValue: 422 is not a status RFC 7644 uses.
#[catch(422)]
fn scim_unprocessable_entity() -> ScimError {
    ScimError::bad_request("invalidValue", "Malformed request parameter")
}

#[catch(413)]
fn scim_payload_too_large() -> ScimError {
    ScimError::payload_too_large()
}

#[catch(429)]
fn scim_too_many_requests() -> ScimError {
    ScimError::too_many_requests()
}

#[catch(500)]
fn scim_internal() -> ScimError {
    ScimError::internal()
}

// Backstop so no status can escape /scim as Rocket's HTML error page, which a
// SCIM client parsing JSON cannot make sense of. Two reachable cases the named
// catchers above miss: 503, returned by the DbConn guard when the connection
// pool is exhausted, and 405 on a method the route does not define.
#[catch(default)]
fn scim_default(status: Status, _: &Request<'_>) -> ScimError {
    ScimError::from_status(status)
}

// Compiled for every backend, not just sqlite: three dialects ship, and the
// upsert semantics, foreign-key behaviour and collation genuinely differ
// between them. Running against MySQL or PostgreSQL needs a live server at
// DATABASE_URL - see tools/scim-test-backends.sh.
#[cfg(test)]
mod tests;
