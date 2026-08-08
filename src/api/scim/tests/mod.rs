//
// Integration tests for the SCIM endpoints, driven through a Rocket local
// client against a temporary sqlite database.
//
// Environment: a #[ctor] constructor calls test_support::init_hermetic_env()
// BEFORE main and before any test thread starts. CONFIG is a process-global
// LazyLock that reads the environment on first deref, so this is the only
// point where its inputs can be controlled race-free. The main crate forbids
// unsafe code, which is why the env mutation lives in the test-support crate.
//
// Tests that build a rocket + database serialize on TEST_LOCK: the sqlite
// file and the CONFIG global are shared process state.
//
use std::sync::LazyLock;

use rocket::{
    http::{Header, Status},
    local::asynchronous::{Client, LocalResponse},
};

use serde_json::Value;

use crate::{
    api::scim::{self, error::SCIM_ERROR_URN},
    crypto,
    db::{
        DbConn, DbPool,
        models::{
            Collection, CollectionGroup, Event, EventType, Group, GroupId, GroupUser, Membership, MembershipId,
            MembershipStatus, MembershipType, OrgPolicy, OrgPolicyType, Organization, OrganizationId, ScimApiKey,
            User,
        },
    },
};

// Linking test-support activates its #[ctor] constructor, which points CONFIG
// at a hermetic temp environment before main. See test-support/src/lib.rs.
use test_support as _;

static TEST_LOCK: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(|| tokio::sync::Mutex::new(()));

const SCIM_CONTENT_TYPE: &str = "application/scim+json";

// One pool for the whole test process: it is never dropped, so no test can
// hit "database is locked" from a previous test's lazily-dropped connections,
// and the embedded migrations run exactly once.
fn test_pool() -> &'static DbPool {
    static POOL: std::sync::OnceLock<DbPool> = std::sync::OnceLock::new();
    POOL.get_or_init(|| {
        // sqlite derives its URL from the hermetic DATA_FOLDER. MySQL and
        // PostgreSQL need a live server, so fail with an actionable message
        // rather than a driver error nobody can act on.
        assert!(
            cfg!(sqlite) || std::env::var("DATABASE_URL").is_ok(),
            "DATABASE_URL must point at a live server for this backend. \
             Run tools/scim-test-backends.sh, which starts one in Docker."
        );
        DbPool::from_config().expect("test db pool (migrations embedded)")
    })
}

// Initializes the JWT signing keys exactly once per test process.
//
// `encode_jwt` resolves the key with `OnceLock::wait()`, which blocks FOREVER
// when the cell was never set - and `initialize_keys()` is only called from
// `main()`, which a test binary never runs. Without this, any test that sends
// an invite hangs instead of failing, which is far harder to diagnose than a
// panic. Generating the 2048-bit key costs about a second, once.
async fn ensure_jwt_keys() {
    static KEYS: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();
    KEYS.get_or_init(async || {
        crate::auth::initialize_keys().await.expect("initializing JWT keys for the test process");
    })
    .await;
}

async fn scim_client() -> (Client, DbPool) {
    ensure_jwt_keys().await;
    let pool = test_pool().clone();
    let rocket = rocket::custom(rocket::Config::default())
        .mount("/scim", scim::routes())
        .register("/scim", scim::catchers())
        .manage(pool.clone());
    let client = Client::untracked(rocket).await.expect("local rocket client");
    (client, pool)
}

/// Mounts the identity routes alongside SCIM, for the Suite C tests that drive
/// a real SSO login. Kept separate from `scim_client` so the SCIM tests carry
/// no dependency on the login surface.
async fn scim_and_identity_client() -> (Client, DbPool) {
    ensure_jwt_keys().await;
    let pool = test_pool().clone();
    let rocket = rocket::custom(rocket::Config::default())
        .mount("/scim", scim::routes())
        .register("/scim", scim::catchers())
        .mount("/identity", crate::api::identity_routes())
        .manage(pool.clone());
    let client = Client::untracked(rocket).await.expect("local rocket client");
    (client, pool)
}

async fn seed_org(conn: &DbConn, name: &str) -> OrganizationId {
    let org = Organization::new(String::from(name), "admin@example.com", None, None);
    org.save(conn).await.expect("saving test org");
    org.uuid
}

// Mints through the real management path (manage::mint_scim_token), so the
// token format and the guard's verification cannot drift apart between
// production and tests.
async fn seed_scim_key(conn: &DbConn, org_uuid: &OrganizationId) -> String {
    scim::manage::mint_scim_token(org_uuid, conn).await.expect("minting scim key").0
}

fn bearer(token: &str) -> Header<'static> {
    Header::new("Authorization", format!("Bearer {token}"))
}

async fn body_of(response: LocalResponse<'_>) -> String {
    response.into_string().await.expect("response body")
}

#[rocket::async_test]
async fn valid_token_reaches_discovery() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-authz-ok").await;
    let token = seed_scim_key(&conn, &org).await;

    let response = client.get(format!("/scim/v2/{org}/ServiceProviderConfig")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let content_type = response.headers().get_one("Content-Type").expect("content type");
    assert!(content_type.starts_with(SCIM_CONTENT_TYPE), "unexpected content type {content_type}");
    let body = body_of(response).await;
    assert!(body.contains("urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"));

    let response = client.get(format!("/scim/v2/{org}/ResourceTypes")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let body = body_of(response).await;
    assert!(body.contains("urn:ietf:params:scim:api:messages:2.0:ListResponse"));
    assert!(body.contains("\"endpoint\":\"/Users\""));

    let response = client.get(format!("/scim/v2/{org}/Schemas")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
}

#[rocket::async_test]
async fn auth_failures_are_uniform_401s() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");

    let org_a = seed_org(&conn, "scim-authz-a").await;
    let token_a = seed_scim_key(&conn, &org_a).await;
    let org_b = seed_org(&conn, "scim-authz-b").await;
    let _token_b = seed_scim_key(&conn, &org_b).await;
    // An org that exists but has no SCIM key configured.
    let org_c = seed_org(&conn, "scim-authz-c").await;

    let url_a = format!("/scim/v2/{org_a}/ServiceProviderConfig");

    let mut failures: Vec<(&str, LocalResponse<'_>)> = Vec::new();
    failures.push(("no auth header", client.get(&url_a).dispatch().await));
    failures
        .push(("not a bearer", client.get(&url_a).header(Header::new("Authorization", "Basic abc")).dispatch().await));
    failures.push(("malformed token", client.get(&url_a).header(bearer("garbage")).dispatch().await));
    failures.push((
        "wrong version prefix",
        client.get(&url_a).header(bearer(&format!("scim_v0.{org_a}.x"))).dispatch().await,
    ));
    failures.push((
        "wrong secret",
        client.get(&url_a).header(bearer(&format!("scim_v1.{org_a}.bm90LXRoZS1zZWNyZXQ"))).dispatch().await,
    ));
    failures.push((
        "token org != path org",
        client.get(format!("/scim/v2/{org_b}/ServiceProviderConfig")).header(bearer(&token_a)).dispatch().await,
    ));
    failures.push((
        "org without key",
        client
            .get(format!("/scim/v2/{org_c}/ServiceProviderConfig"))
            .header(bearer(&format!("scim_v1.{org_c}.c2VjcmV0")))
            .dispatch()
            .await,
    ));
    // A key row that exists but is disabled (the column is reserved for a
    // future disable-without-deleting endpoint) must be rejected identically,
    // even with the correct secret.
    let org_d = seed_org(&conn, "scim-authz-d").await;
    let secret_d = crypto::encode_random_bytes::<32>(&data_encoding::BASE64URL_NOPAD);
    let mut key_d = ScimApiKey::new(org_d.clone(), crypto::sha256_hex(secret_d.as_bytes()));
    key_d.enabled = false;
    key_d.save(&conn).await.expect("saving disabled scim key");
    failures.push((
        "disabled key with correct secret",
        client
            .get(format!("/scim/v2/{org_d}/ServiceProviderConfig"))
            .header(bearer(&format!("scim_v1.{org_d}.{secret_d}")))
            .dispatch()
            .await,
    ));

    let mut bodies = Vec::new();
    for (case, response) in failures {
        assert_eq!(response.status(), Status::Unauthorized, "expected 401 for case: {case}");
        bodies.push((case, body_of(response).await));
    }

    // Every failure cause must produce a byte-identical body: no signal about
    // which check rejected the request.
    let (_, first) = &bodies[0];
    for (case, body) in &bodies {
        assert_eq!(body, first, "401 body differs for case: {case}");
    }
    assert!(first.contains("urn:ietf:params:scim:api:messages:2.0:Error"));
    assert!(first.contains("\"status\":\"401\""));
}

#[rocket::async_test]
async fn minted_token_round_trips_and_rotation_kills_the_old_one() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-mint-org").await;

    // Mint through the real management path and authenticate with the result.
    let (token, _) = scim::manage::mint_scim_token(&org, &conn).await.expect("minting");
    let response = client.get(format!("/scim/v2/{org}/ServiceProviderConfig")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    // Rotation replaces the key row: the old token dies instantly, the new
    // one works.
    let (rotated, _) = scim::manage::mint_scim_token(&org, &conn).await.expect("rotating");
    let response = client.get(format!("/scim/v2/{org}/ServiceProviderConfig")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::Unauthorized, "rotation must invalidate the previous token");
    let response =
        client.get(format!("/scim/v2/{org}/ServiceProviderConfig")).header(bearer(&rotated)).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
}

#[rocket::async_test]
async fn malformed_resource_id_is_scim_enveloped_not_html() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-malformed-id-org").await;
    let token = seed_scim_key(&conn, &org).await;

    // A path id that is not a uuid fails Rocket's param guard with a 422 before
    // any handler runs. Without a 422 catcher that surfaces as Rocket's default
    // HTML page, which a SCIM client parsing JSON cannot handle.
    let response = client.get(format!("/scim/v2/{org}/Users/not-a-uuid")).header(bearer(&token)).dispatch().await;
    let content_type = response.headers().get_one("Content-Type").expect("content type").to_owned();
    assert!(content_type.starts_with(SCIM_CONTENT_TYPE), "malformed id returned {content_type}, expected SCIM json");

    let body = body_of(response).await;
    assert!(body.contains("urn:ietf:params:scim:api:messages:2.0:Error"), "not a SCIM error envelope: {body}");
    assert!(!body.contains("<!DOCTYPE"), "returned an HTML page: {body}");
}

#[rocket::async_test]
async fn unknown_scim_route_is_scim_enveloped_404() {
    let _guard = TEST_LOCK.lock().await;
    let (client, _pool) = scim_client().await;

    let response = client.get("/scim/v2/some-org/Nope").dispatch().await;
    assert_eq!(response.status(), Status::NotFound);
    let body = body_of(response).await;
    assert!(body.contains("urn:ietf:params:scim:api:messages:2.0:Error"));
    assert!(body.contains("\"status\":\"404\""));
}

#[test]
fn rate_limiter_returns_429_when_drained() {
    // Uses a synthetic IP so draining this bucket cannot affect the shared
    // bucket the HTTP tests consume from (the limiter is keyed by IP).
    let ip: std::net::IpAddr = "10.99.99.99".parse().expect("test ip");
    let burst = crate::CONFIG.scim_ratelimit_max_burst();
    let mut limited = false;
    for _ in 0..=burst {
        if crate::ratelimit::check_limit_scim(&ip).is_err() {
            limited = true;
            break;
        }
    }
    assert!(limited, "limiter never tripped after {burst} + 1 requests");
}

// ---------------------------------------------------------------------------
// Users lifecycle (Phase 1: provision, deprovision, restore)
// ---------------------------------------------------------------------------

fn scim_body(header_token: &str, body: &Value) -> (Header<'static>, Header<'static>, String) {
    (bearer(header_token), Header::new("Content-Type", "application/scim+json"), body.to_string())
}

async fn seed_user(conn: &DbConn, email: &str, with_password: bool) -> User {
    let mut user = User::new(email, None);
    if with_password {
        user.password_hash = vec![1, 2, 3];
    }
    user.save(conn).await.expect("saving test user");
    user
}

async fn seed_member(
    conn: &DbConn,
    org: &OrganizationId,
    email: &str,
    status: i32,
    atype: MembershipType,
) -> MembershipId {
    let user = seed_user(conn, email, true).await;
    let mut member = Membership::new(user.uuid, org.clone(), None);
    member.status = status;
    member.atype = atype as i32;
    member.save(conn).await.expect("saving test member");
    member.uuid
}

async fn member_status(conn: &DbConn, member_id: &MembershipId, org: &OrganizationId) -> i32 {
    Membership::find_by_uuid_and_org(member_id, org, conn).await.expect("membership row must exist").status
}

fn parse_json(body: &str) -> Value {
    serde_json::from_str(body).expect("valid json body")
}

#[rocket::async_test]
async fn post_creates_invited_user() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-post-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "Provision.Me@Example.com",
        "externalId": "entra-obj-001",
        "name": {"givenName": "Provision", "familyName": "Me"},
        "emails": [{"value": "Provision.Me@Example.com", "primary": true}],
        "active": true,
    });
    let (auth, content_type, body) = scim_body(&token, &payload);
    let response =
        client.post(format!("/scim/v2/{org}/Users")).header(auth).header(content_type).body(body).dispatch().await;

    assert_eq!(response.status(), Status::Created);
    let location = response.headers().get_one("Location").expect("Location header").to_owned();
    let parsed = parse_json(&body_of(response).await);

    // Mail is disabled and the user is new (no password): Invited (0).
    assert_eq!(parsed["active"], json!(true));
    assert_eq!(parsed["userName"], json!("provision.me@example.com"), "email must be stored lowercased");
    assert_eq!(parsed["externalId"], json!("entra-obj-001"));
    let member_id: MembershipId = parsed["id"].as_str().expect("id").to_owned().into();
    assert!(location.ends_with(&format!("/scim/v2/{org}/Users/{member_id}")));

    assert_eq!(member_status(&conn, &member_id, &org).await, 0, "new shell user must land at Invited");
    assert!(User::find_by_mail("provision.me@example.com", &conn).await.is_some());
}

#[rocket::async_test]
async fn post_existing_credentialed_user_becomes_accepted() {
    let _guard = TEST_LOCK.lock().await;
    // Accepted is only reachable when no invite mail will be sent AND the
    // account already has credentials to log in with. The hermetic environment
    // has mail enabled, so this branch has to opt out of it.
    let _mail_off = scim::test_config::mail_enabled(false);
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-post-accepted-org").await;
    let token = seed_scim_key(&conn, &org).await;
    seed_user(&conn, "has.password@example.com", true).await;

    let payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "has.password@example.com",
        "externalId": "entra-obj-002",
    });
    let (auth, content_type, body) = scim_body(&token, &payload);
    let response =
        client.post(format!("/scim/v2/{org}/Users")).header(auth).header(content_type).body(body).dispatch().await;

    assert_eq!(response.status(), Status::Created);
    let parsed = parse_json(&body_of(response).await);
    let member_id: MembershipId = parsed["id"].as_str().expect("id").to_owned().into();
    // Mail disabled + existing credentials: straight to Accepted (1).
    assert_eq!(member_status(&conn, &member_id, &org).await, 1);
}

#[rocket::async_test]
async fn post_duplicate_is_409_uniqueness() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-dup-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "dup@example.com",
        "externalId": "entra-dup-1",
    });
    let (auth, content_type, body) = scim_body(&token, &payload);
    let response =
        client.post(format!("/scim/v2/{org}/Users")).header(auth).header(content_type).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created);

    // Same externalId again.
    let (auth, content_type, body) = scim_body(&token, &payload);
    let response =
        client.post(format!("/scim/v2/{org}/Users")).header(auth).header(content_type).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Conflict);
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["scimType"], json!("uniqueness"));

    // Same email, different externalId.
    let payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "dup@example.com",
        "externalId": "entra-dup-2",
    });
    let (auth, content_type, body) = scim_body(&token, &payload);
    let response =
        client.post(format!("/scim/v2/{org}/Users")).header(auth).header(content_type).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Conflict);
}

#[rocket::async_test]
async fn patch_active_lifecycle_hits_correct_status_offsets() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-patch-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let invited = seed_member(&conn, &org, "patch.invited@example.com", 0, MembershipType::User).await;
    let confirmed = seed_member(&conn, &org, "patch.confirmed@example.com", 2, MembershipType::User).await;

    let deactivate = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "Replace", "path": "active", "value": "False"}],
    });
    let activate = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "value": {"active": true}}],
    });

    // Invited (0) revokes to -128, never -1.
    let (auth, ct, body) = scim_body(&token, &deactivate);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{invited}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(parse_json(&body_of(response).await)["active"], json!(false));
    assert_eq!(member_status(&conn, &invited, &org).await, -128);

    // Deprovisioning is idempotent.
    let (auth, ct, body) = scim_body(&token, &deactivate);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{invited}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(member_status(&conn, &invited, &org).await, -128);

    // Restore is lossless: straight back to Invited (0).
    let (auth, ct, body) = scim_body(&token, &activate);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{invited}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(member_status(&conn, &invited, &org).await, 0);

    // Confirmed (2) revokes to -126 and restores to 2 with akey intact.
    let (auth, ct, body) = scim_body(&token, &deactivate);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{confirmed}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(member_status(&conn, &confirmed, &org).await, -126);

    let response = client.get(format!("/scim/v2/{org}/Users/{confirmed}")).header(bearer(&token)).dispatch().await;
    assert_eq!(parse_json(&body_of(response).await)["active"], json!(false));

    let (auth, ct, body) = scim_body(&token, &activate);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{confirmed}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(member_status(&conn, &confirmed, &org).await, 2);
}

#[rocket::async_test]
async fn delete_revokes_and_keeps_the_row() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-delete-org").await;
    let token = seed_scim_key(&conn, &org).await;
    let member = seed_member(&conn, &org, "delete.me@example.com", 2, MembershipType::User).await;

    let response = client.delete(format!("/scim/v2/{org}/Users/{member}")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::NoContent);
    // The row survives (revoked), so restore stays lossless.
    assert_eq!(member_status(&conn, &member, &org).await, -126);

    // Idempotent.
    let response = client.delete(format!("/scim/v2/{org}/Users/{member}")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::NoContent);
    assert_eq!(member_status(&conn, &member, &org).await, -126);
}

#[rocket::async_test]
async fn last_active_owner_cannot_be_revoked() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-owner-org").await;
    let token = seed_scim_key(&conn, &org).await;
    let owner = seed_member(&conn, &org, "sole.owner@example.com", 2, MembershipType::Owner).await;

    let deactivate = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "active", "value": false}],
    });
    let (auth, ct, body) = scim_body(&token, &deactivate);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{owner}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::BadRequest);
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["scimType"], json!("mutability"));
    assert_eq!(member_status(&conn, &owner, &org).await, 2, "owner must remain untouched");

    // DELETE takes the same path.
    let response = client.delete(format!("/scim/v2/{org}/Users/{owner}")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::BadRequest);
    assert_eq!(member_status(&conn, &owner, &org).await, 2);
}

#[rocket::async_test]
async fn filter_round_trip_and_enumeration_shape() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-filter-org").await;
    let token = seed_scim_key(&conn, &org).await;
    seed_member(&conn, &org, "filter.target@example.com", 1, MembershipType::User).await;

    // Mixed-case filter value must match the lowercased stored email.
    let filter = "userName eq \"Filter.Target@Example.COM\"";
    let response = client
        .get(format!("/scim/v2/{org}/Users?filter={}", url_escape(filter)))
        .header(bearer(&token))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["totalResults"], json!(1));
    assert_eq!(parsed["Resources"][0]["userName"], json!("filter.target@example.com"));

    // A miss is an empty 200 list, not a 404: Entra's Test Connection probes
    // exactly this, and a distinguishable miss would enable enumeration.
    let filter = "userName eq \"nobody-here@example.com\"";
    let response = client
        .get(format!("/scim/v2/{org}/Users?filter={}", url_escape(filter)))
        .header(bearer(&token))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["totalResults"], json!(0));

    // Unsupported grammar is a 400 invalidFilter.
    let filter = "userName co \"partial\"";
    let response = client
        .get(format!("/scim/v2/{org}/Users?filter={}", url_escape(filter)))
        .header(bearer(&token))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::BadRequest);
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["scimType"], json!("invalidFilter"));
}

#[rocket::async_test]
async fn unknown_member_and_foreign_member_are_identical_404s() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org_a = seed_org(&conn, "scim-404-a").await;
    let token_a = seed_scim_key(&conn, &org_a).await;
    let org_b = seed_org(&conn, "scim-404-b").await;
    let _token_b = seed_scim_key(&conn, &org_b).await;
    let foreign = seed_member(&conn, &org_b, "foreign.member@example.com", 2, MembershipType::User).await;

    let response = client
        .get(format!("/scim/v2/{org_a}/Users/00000000-dead-beef-0000-000000000000"))
        .header(bearer(&token_a))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::NotFound);
    let unknown_body = body_of(response).await;

    // Another org's member id must be indistinguishable from a nonexistent one.
    let response = client.get(format!("/scim/v2/{org_a}/Users/{foreign}")).header(bearer(&token_a)).dispatch().await;
    assert_eq!(response.status(), Status::NotFound);
    let foreign_body = body_of(response).await;
    assert_eq!(unknown_body, foreign_body);
}

#[rocket::async_test]
async fn post_inactive_creates_revoked_membership() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-inactive-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "born.disabled@example.com",
        "externalId": "entra-inactive-1",
        "active": "False",
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created);
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["active"], json!(false));
    let member_id: MembershipId = parsed["id"].as_str().expect("id").to_owned().into();
    assert_eq!(member_status(&conn, &member_id, &org).await, -128, "invited-then-revoked offset");
}

#[rocket::async_test]
async fn patch_unsupported_path_is_invalid_path() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-badpatch-org").await;
    let token = seed_scim_key(&conn, &org).await;
    let member = seed_member(&conn, &org, "bad.patch@example.com", 1, MembershipType::User).await;

    let payload = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "wibble", "value": "New Name"}],
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{member}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::BadRequest);
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["scimType"], json!("invalidPath"));
}

fn url_escape(raw: &str) -> String {
    // Percent-encode just enough for filter values in test URLs.
    raw.replace('%', "%25").replace(' ', "%20").replace('"', "%22")
}

// ---------------------------------------------------------------------------
// Full Users surface (Phase 2: PUT, attribute PATCH, pagination)
// ---------------------------------------------------------------------------

#[rocket::async_test]
async fn patch_displayname_rename_is_accepted_noop() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-rename-org").await;
    let token = seed_scim_key(&conn, &org).await;
    let member = seed_member(&conn, &org, "renamed.user@example.com", 2, MembershipType::User).await;

    // Entra sends this on every directory rename; it must not error and must
    // not change membership state.
    let payload = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "displayName", "value": "New Display Name"}],
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{member}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["active"], json!(true));
    assert_eq!(member_status(&conn, &member, &org).await, 2);
}

#[rocket::async_test]
async fn patch_and_put_update_external_id_with_uniqueness() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-extid-org").await;
    let token = seed_scim_key(&conn, &org).await;
    let member_a = seed_member(&conn, &org, "extid.a@example.com", 1, MembershipType::User).await;
    let member_b = seed_member(&conn, &org, "extid.b@example.com", 1, MembershipType::User).await;

    // PATCH assigns an externalId.
    let payload = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "externalId", "value": "ext-a-1"}],
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{member_a}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(parse_json(&body_of(response).await)["externalId"], json!("ext-a-1"));

    // PUT replaces it and can toggle active in the same request.
    let payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "extid.a@example.com",
        "externalId": "ext-a-2",
        "active": false,
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response =
        client.put(format!("/scim/v2/{org}/Users/{member_a}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["externalId"], json!("ext-a-2"));
    assert_eq!(parsed["active"], json!(false));
    assert_eq!(member_status(&conn, &member_a, &org).await, -127, "accepted (1) revoked to -127");

    // Duplicate externalId on another member is a 409.
    let payload = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "externalId", "value": "ext-a-2"}],
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{member_b}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Conflict);
}

#[rocket::async_test]
async fn put_does_not_change_email_or_role() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-put-immutable-org").await;
    let token = seed_scim_key(&conn, &org).await;
    let member = seed_member(&conn, &org, "immutable@example.com", 2, MembershipType::User).await;

    let payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "changed@example.com",
        "displayName": "Different Person",
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response =
        client.put(format!("/scim/v2/{org}/Users/{member}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let parsed = parse_json(&body_of(response).await);
    // The response reflects the real state: the email did not change.
    assert_eq!(parsed["userName"], json!("immutable@example.com"));
    assert_eq!(member_status(&conn, &member, &org).await, 2);
}

#[rocket::async_test]
async fn provisioning_rollback_spares_preexisting_users() {
    let _guard = TEST_LOCK.lock().await;
    let (_client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-rollback-org").await;

    // A pre-existing account: rollback removes only the new membership. This
    // is the branch that must never delete someone's account on a transient
    // invite-mail failure.
    let user = seed_user(&conn, "rollback.existing@example.com", true).await;
    let user_uuid = user.uuid.clone();
    let mut member = Membership::new(user.uuid.clone(), org.clone(), None);
    member.status = 0;
    member.save(&conn).await.expect("saving membership");
    let member_uuid = member.uuid.clone();

    scim::users::rollback_provisioning(user, member, false, false, &conn).await;
    assert!(User::find_by_uuid(&user_uuid, &conn).await.is_some(), "pre-existing user must survive rollback");
    assert!(Membership::find_by_uuid_and_org(&member_uuid, &org, &conn).await.is_none(), "membership must be gone");

    // A shell account created by this request: rollback removes the user,
    // which cascades to the membership.
    let user = seed_user(&conn, "rollback.shell@example.com", false).await;
    let user_uuid = user.uuid.clone();
    let mut member = Membership::new(user.uuid.clone(), org.clone(), None);
    member.status = 0;
    member.save(&conn).await.expect("saving membership");
    let member_uuid = member.uuid.clone();

    scim::users::rollback_provisioning(user, member, true, false, &conn).await;
    assert!(User::find_by_uuid(&user_uuid, &conn).await.is_none(), "shell user must be removed");
    assert!(Membership::find_by_uuid_and_org(&member_uuid, &org, &conn).await.is_none(), "membership must cascade");
}

#[rocket::async_test]
async fn pagination_edges() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-page-org").await;
    let token = seed_scim_key(&conn, &org).await;
    for i in 1..=3 {
        seed_member(&conn, &org, &format!("page{i}@example.com"), 1, MembershipType::User).await;
    }

    // Middle page.
    let response =
        client.get(format!("/scim/v2/{org}/Users?startIndex=2&count=1")).header(bearer(&token)).dispatch().await;
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["totalResults"], json!(3));
    assert_eq!(parsed["itemsPerPage"], json!(1));
    assert_eq!(parsed["startIndex"], json!(2));

    // count=0 returns the total with no resources (RFC 7644 s3.4.2.4).
    let response = client.get(format!("/scim/v2/{org}/Users?count=0")).header(bearer(&token)).dispatch().await;
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["totalResults"], json!(3));
    assert_eq!(parsed["itemsPerPage"], json!(0));

    // startIndex beyond the end is an empty page, not an error.
    let response = client.get(format!("/scim/v2/{org}/Users?startIndex=10")).header(bearer(&token)).dispatch().await;
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["totalResults"], json!(3));
    assert_eq!(parsed["itemsPerPage"], json!(0));
}

// ---------------------------------------------------------------------------
// Groups (Phase 3)
// ---------------------------------------------------------------------------

#[rocket::async_test]
async fn group_crud_and_member_diff_lifecycle() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-group-org").await;
    let token = seed_scim_key(&conn, &org).await;
    let member_a = seed_member(&conn, &org, "group.a@example.com", 1, MembershipType::User).await;
    let member_b = seed_member(&conn, &org, "group.b@example.com", 2, MembershipType::User).await;

    // POST with one initial member.
    let payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Engineering",
        "externalId": "entra-group-1",
        "members": [{"value": member_a}],
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Groups")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created);
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["displayName"], json!("Engineering"));
    assert_eq!(parsed["members"].as_array().expect("members").len(), 1);
    let group_id = parsed["id"].as_str().expect("group id").to_owned();

    // PATCH add member_b via value list.
    let payload = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "Add", "path": "members", "value": [{"value": member_b}]}],
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response =
        client.patch(format!("/scim/v2/{org}/Groups/{group_id}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["members"].as_array().expect("members").len(), 2);

    // Adding the same member twice is idempotent.
    let payload = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "add", "path": "members", "value": [{"value": member_b}]}],
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response =
        client.patch(format!("/scim/v2/{org}/Groups/{group_id}")).header(auth).header(ct).body(body).dispatch().await;
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["members"].as_array().expect("members").len(), 2, "duplicate add must not duplicate the link");

    // Entra's filter-path removal form removes member_a only.
    let payload = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "Remove", "path": format!("members[value eq \"{member_a}\"]")}],
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response =
        client.patch(format!("/scim/v2/{org}/Groups/{group_id}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let parsed = parse_json(&body_of(response).await);
    let members = parsed["members"].as_array().expect("members");
    assert_eq!(members.len(), 1);
    assert_eq!(members[0]["value"], json!(member_b.to_string()));

    // excludedAttributes=members on list omits the member arrays.
    let response =
        client.get(format!("/scim/v2/{org}/Groups?excludedAttributes=members")).header(bearer(&token)).dispatch().await;
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["totalResults"], json!(1));
    assert!(parsed["Resources"][0].get("members").is_none(), "members must be excluded");

    // Filter by displayName.
    let response = client
        .get(format!("/scim/v2/{org}/Groups?filter={}", url_escape("displayName eq \"Engineering\"")))
        .header(bearer(&token))
        .dispatch()
        .await;
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["totalResults"], json!(1));

    // DELETE is a real delete for groups (no E2EE state involved).
    let response = client.delete(format!("/scim/v2/{org}/Groups/{group_id}")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::NoContent);
    let response = client.get(format!("/scim/v2/{org}/Groups/{group_id}")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::NotFound);
}

#[rocket::async_test]
async fn group_member_must_be_provisioned_first() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-group-order-org").await;
    let token = seed_scim_key(&conn, &org).await;
    let org_other = seed_org(&conn, "scim-group-other-org").await;
    let foreign_member = seed_member(&conn, &org_other, "other.org@example.com", 1, MembershipType::User).await;

    // A member id from another org must be rejected, same as an unknown id:
    // GroupUser keys on MembershipId, so cross-org references would otherwise
    // link silently.
    let payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Bad Members",
        "members": [{"value": foreign_member}],
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Groups")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::BadRequest);
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["scimType"], json!("invalidValue"));

    // And the failed create must not leave a group behind.
    let response = client.get(format!("/scim/v2/{org}/Groups")).header(bearer(&token)).dispatch().await;
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["totalResults"], json!(0));
}

#[rocket::async_test]
async fn group_put_replaces_member_set() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-group-put-org").await;
    let token = seed_scim_key(&conn, &org).await;
    let member_a = seed_member(&conn, &org, "put.a@example.com", 1, MembershipType::User).await;
    let member_b = seed_member(&conn, &org, "put.b@example.com", 1, MembershipType::User).await;

    let payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Replace Me",
        "members": [{"value": member_a}],
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Groups")).header(auth).header(ct).body(body).dispatch().await;
    let group_id = parse_json(&body_of(response).await)["id"].as_str().expect("id").to_owned();

    // PUT swaps the whole member set and renames.
    let payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Replaced",
        "members": [{"value": member_b}],
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response =
        client.put(format!("/scim/v2/{org}/Groups/{group_id}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["displayName"], json!("Replaced"));
    let members = parsed["members"].as_array().expect("members");
    assert_eq!(members.len(), 1);
    assert_eq!(members[0]["value"], json!(member_b.to_string()));
}

#[rocket::async_test]
async fn group_put_omitted_members_kept_but_empty_list_clears() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-group-sparse-put-org").await;
    let token = seed_scim_key(&conn, &org).await;
    let member_a = seed_member(&conn, &org, "sparse.a@example.com", 1, MembershipType::User).await;

    let payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Sparse",
        "members": [{"value": member_a}],
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Groups")).header(auth).header(ct).body(body).dispatch().await;
    let group_id = parse_json(&body_of(response).await)["id"].as_str().expect("id").to_owned();

    // A PUT that omits the members attribute renames without touching the
    // member set: a sparse client must not be able to wipe a group by accident.
    let payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Sparse Renamed",
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response =
        client.put(format!("/scim/v2/{org}/Groups/{group_id}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["displayName"], json!("Sparse Renamed"));
    assert_eq!(parsed["members"].as_array().expect("members").len(), 1, "omitted members must keep membership");

    // An explicit empty list is a real replacement and clears the group.
    let payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Sparse Renamed",
        "members": [],
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response =
        client.put(format!("/scim/v2/{org}/Groups/{group_id}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["members"].as_array().expect("members").len(), 0, "empty members must clear membership");
}

#[rocket::async_test]
async fn group_external_id_uniqueness_enforced_on_put_and_patch() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-group-extid-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let mut group_ids = Vec::new();
    for (name, ext) in [("Ext One", "ext-1"), ("Ext Two", "ext-2")] {
        let payload = json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": name,
            "externalId": ext,
        });
        let (auth, ct, body) = scim_body(&token, &payload);
        let response =
            client.post(format!("/scim/v2/{org}/Groups")).header(auth).header(ct).body(body).dispatch().await;
        assert_eq!(response.status(), Status::Created);
        group_ids.push(parse_json(&body_of(response).await)["id"].as_str().expect("id").to_owned());
    }
    let group_two = &group_ids[1];

    // PATCH onto a taken externalId is a 409, and must not change the group.
    let payload = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "externalId", "value": "ext-1"}],
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response =
        client.patch(format!("/scim/v2/{org}/Groups/{group_two}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Conflict);
    assert_eq!(parse_json(&body_of(response).await)["scimType"], json!("uniqueness"));

    // PUT onto a taken externalId is the same 409.
    let payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Ext Two",
        "externalId": "ext-1",
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response =
        client.put(format!("/scim/v2/{org}/Groups/{group_two}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Conflict);

    let response = client.get(format!("/scim/v2/{org}/Groups/{group_two}")).header(bearer(&token)).dispatch().await;
    assert_eq!(parse_json(&body_of(response).await)["externalId"], json!("ext-2"), "conflict must not partially apply");

    // Re-asserting a group's own externalId stays a no-op success: Entra
    // repeats it on every PUT.
    let payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Ext Two",
        "externalId": "ext-2",
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response =
        client.put(format!("/scim/v2/{org}/Groups/{group_two}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
}

// ---------------------------------------------------------------------------
// Invariants the design rests on. These guard properties whose failure is
// silent, unrecoverable, or both.
// ---------------------------------------------------------------------------

// Deprovisioning maps to REVOKE rather than DELETE for exactly one reason: the
// membership's akey (the org key wrapped under the member's public key) has no
// server-side reconstruction path under E2EE. If a change ever cleared it on
// revoke or restore, every confirmed member would need manual re-confirmation
// and nothing else in the suite would notice.
#[rocket::async_test]
async fn revoke_and_restore_preserve_the_wrapped_org_key() {
    const AKEY: &str = "2.ENCRYPTED-WRAPPED-ORG-KEY-BLOB|mac";

    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-akey-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let user = seed_user(&conn, "akey.member@example.com", true).await;
    let mut member = Membership::new(user.uuid, org.clone(), None);
    member.status = MembershipStatus::Confirmed as i32;
    member.akey = String::from(AKEY);
    member.save(&conn).await.expect("saving confirmed member");
    let member_id = member.uuid.clone();

    // PATCH active:false
    let payload = json!({
        "schemas": [scim::patch::PATCH_OP_URN],
        "Operations": [{"op": "replace", "path": "active", "value": false}],
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{member_id}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let row = Membership::find_by_uuid_and_org(&member_id, &org, &conn).await.expect("row");
    assert_eq!(row.status, -126, "confirmed revokes to -126, not to the Revoked sentinel");
    assert_eq!(row.akey, AKEY, "revoke must not clear the wrapped org key");

    // PATCH active:true - restore must be lossless, so no re-confirm is needed.
    let payload = json!({
        "schemas": [scim::patch::PATCH_OP_URN],
        "Operations": [{"op": "replace", "path": "active", "value": true}],
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{member_id}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let row = Membership::find_by_uuid_and_org(&member_id, &org, &conn).await.expect("row");
    assert_eq!(row.status, MembershipStatus::Confirmed as i32);
    assert_eq!(row.akey, AKEY, "restore must be lossless");

    // DELETE deprovisions by revoking, so it must preserve the key too.
    let response = client.delete(format!("/scim/v2/{org}/Users/{member_id}")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::NoContent);
    let row = Membership::find_by_uuid_and_org(&member_id, &org, &conn).await.expect("row");
    assert_eq!(row.status, -126);
    assert_eq!(row.akey, AKEY, "DELETE revokes rather than deletes, so the key survives");
}

// Cross-org isolation on the filter path. GET-by-id parity is covered by
// unknown_member_and_foreign_member_are_identical_404s; this covers the lookup
// Entra actually uses on every sync, which resolves through a global
// User::find_by_mail before narrowing to the org.
#[rocket::async_test]
async fn filters_cannot_see_members_of_another_org() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org_a = seed_org(&conn, "scim-filter-iso-a").await;
    let token_a = seed_scim_key(&conn, &org_a).await;
    let org_b = seed_org(&conn, "scim-filter-iso-b").await;

    let member_b = seed_member(&conn, &org_b, "only.in.b@example.com", 2, MembershipType::User).await;
    let mut row = Membership::find_by_uuid_and_org(&member_b, &org_b, &conn).await.expect("row");
    row.set_external_id(Some(String::from("ext-only-in-b")));
    row.save(&conn).await.expect("saving external id");

    for filter in ["userName eq \"only.in.b@example.com\"", "externalId eq \"ext-only-in-b\""] {
        let response = client
            .get(format!("/scim/v2/{org_a}/Users?filter={}", url_escape(filter)))
            .header(bearer(&token_a))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok, "filter {filter}");
        let parsed = parse_json(&body_of(response).await);
        assert_eq!(parsed["totalResults"], json!(0), "filter {filter} must not reach another org");
    }
}

// Every Groups handler independently repeats find_by_uuid_and_org. Dropping the
// org argument in any one of them would expose another tenant's groups.
#[rocket::async_test]
async fn foreign_group_is_invisible_on_every_verb() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org_a = seed_org(&conn, "scim-group-iso-a").await;
    let token_a = seed_scim_key(&conn, &org_a).await;
    let org_b = seed_org(&conn, "scim-group-iso-b").await;
    let token_b = seed_scim_key(&conn, &org_b).await;

    let create = json!({"schemas": [scim::discovery::GROUP_SCHEMA_URN], "displayName": "B Only"});
    let (auth, ct, body) = scim_body(&token_b, &create);
    let response = client.post(format!("/scim/v2/{org_b}/Groups")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created);
    let foreign = parse_json(&body_of(response).await)["id"].as_str().expect("id").to_owned();

    let response = client.get(format!("/scim/v2/{org_a}/Groups/{foreign}")).header(bearer(&token_a)).dispatch().await;
    assert_eq!(response.status(), Status::NotFound, "GET");

    let (auth, ct, body) = scim_body(&token_a, &create);
    let response =
        client.put(format!("/scim/v2/{org_a}/Groups/{foreign}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::NotFound, "PUT");

    let rename = json!({
        "schemas": [scim::patch::PATCH_OP_URN],
        "Operations": [{"op": "replace", "path": "displayName", "value": "Stolen"}],
    });
    let (auth, ct, body) = scim_body(&token_a, &rename);
    let response =
        client.patch(format!("/scim/v2/{org_a}/Groups/{foreign}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::NotFound, "PATCH");

    let response =
        client.delete(format!("/scim/v2/{org_a}/Groups/{foreign}")).header(bearer(&token_a)).dispatch().await;
    assert_eq!(response.status(), Status::NotFound, "DELETE");

    let response = client.get(format!("/scim/v2/{org_a}/Groups")).header(bearer(&token_a)).dispatch().await;
    assert_eq!(parse_json(&body_of(response).await)["totalResults"], json!(0), "list must not leak");

    // Still there for its real owner: the 404s were scoping, not a failed create.
    let response = client.get(format!("/scim/v2/{org_b}/Groups/{foreign}")).header(bearer(&token_b)).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
}

// The org event log is the only record of what an automated machine credential
// did to an organization. It was entirely dead under test until the hermetic
// env enabled ORG_EVENTS_ENABLED, so nothing had ever asserted a SCIM event row.
#[rocket::async_test]
async fn provisioning_actions_are_written_to_the_org_event_log() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-audit-org").await;
    let token = seed_scim_key(&conn, &org).await;
    let member = seed_member(&conn, &org, "audited@example.com", 2, MembershipType::User).await;

    let response = client.delete(format!("/scim/v2/{org}/Users/{member}")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::NoContent);

    let payload = json!({
        "schemas": [scim::patch::PATCH_OP_URN],
        "Operations": [{"op": "replace", "path": "active", "value": true}],
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{member}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let events = Event::find_by_organization_uuid(
        &org,
        &chrono::Utc::now().naive_utc().checked_sub_signed(chrono::Duration::hours(1)).expect("start"),
        &chrono::Utc::now().naive_utc().checked_add_signed(chrono::Duration::hours(1)).expect("end"),
        &conn,
    )
    .await;

    for expected in [EventType::OrganizationUserRevoked, EventType::OrganizationUserRestored] {
        let found = events
            .iter()
            .find(|e| e.event_type == expected as i32 && e.org_user_uuid.as_ref() == Some(&member))
            .unwrap_or_else(|| panic!("{expected:?} must be recorded for the member"));
        assert_eq!(
            found.act_user_uuid.as_ref().map(ToString::to_string),
            Some(scim::SCIM_ACTOR.to_owned()),
            "SCIM changes must be attributed to the synthetic SCIM actor"
        );
    }
}

// Entra repeats a member's existing externalId on every steady-state PUT/PATCH.
// Without the self-reassert early return, the uniqueness check finds the
// member's own row and turns every routine sync into a 409.
#[rocket::async_test]
async fn reasserting_a_members_own_external_id_stays_a_success() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-extid-selfassert-org").await;
    let token = seed_scim_key(&conn, &org).await;
    let member = seed_member(&conn, &org, "selfassert@example.com", 1, MembershipType::User).await;

    let payload = json!({
        "schemas": [scim::patch::PATCH_OP_URN],
        "Operations": [{"op": "replace", "path": "externalId", "value": "ext-self-1"}],
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{member}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    for round in 0..2 {
        let payload = json!({
            "schemas": [scim::discovery::USER_SCHEMA_URN],
            "userName": "selfassert@example.com",
            "externalId": "ext-self-1",
        });
        let (auth, ct, body) = scim_body(&token, &payload);
        let response =
            client.put(format!("/scim/v2/{org}/Users/{member}")).header(auth).header(ct).body(body).dispatch().await;
        assert_eq!(response.status(), Status::Ok, "re-asserting the current externalId must not 409 (round {round})");
        assert_eq!(parse_json(&body_of(response).await)["externalId"], json!("ext-self-1"));
    }
}

// The displayName filter must discriminate. With a single group in the org,
// totalResults == 1 is also what an unfiltered list returns, so deleting the
// filter entirely would keep such a test green.
#[rocket::async_test]
async fn group_display_name_filter_discriminates_and_ignores_case() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-group-filter-org").await;
    let token = seed_scim_key(&conn, &org).await;

    for name in ["Engineering", "Marketing"] {
        let payload = json!({"schemas": [scim::discovery::GROUP_SCHEMA_URN], "displayName": name});
        let (auth, ct, body) = scim_body(&token, &payload);
        let response =
            client.post(format!("/scim/v2/{org}/Groups")).header(auth).header(ct).body(body).dispatch().await;
        assert_eq!(response.status(), Status::Created);
    }

    let query = |filter: &str| format!("/scim/v2/{org}/Groups?filter={}", url_escape(filter));

    let response = client.get(query("displayName eq \"Engineering\"")).header(bearer(&token)).dispatch().await;
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["totalResults"], json!(1), "the decoy group must not match");
    assert_eq!(parsed["Resources"][0]["displayName"], json!("Engineering"));

    // RFC 7643 section 4.2 makes displayName caseExact=false.
    let response = client.get(query("displayName eq \"ENGINEERING\"")).header(bearer(&token)).dispatch().await;
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["totalResults"], json!(1), "eq on displayName must ignore case");

    let response = client.get(query("displayName eq \"Nonexistent\"")).header(bearer(&token)).dispatch().await;
    assert_eq!(parse_json(&body_of(response).await)["totalResults"], json!(0));
}

// Operations must apply in the order supplied (RFC 7644 section 3.5.2), and a
// replace must not swallow the other member operations in the same PatchOp.
#[rocket::async_test]
async fn group_patch_applies_member_operations_in_order() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-group-op-order-org").await;
    let token = seed_scim_key(&conn, &org).await;
    let member_a = seed_member(&conn, &org, "order.a@example.com", 1, MembershipType::User).await;
    let member_b = seed_member(&conn, &org, "order.b@example.com", 1, MembershipType::User).await;

    let payload = json!({
        "schemas": [scim::discovery::GROUP_SCHEMA_URN],
        "displayName": "Order Test",
        "members": [{"value": member_a}],
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Groups")).header(auth).header(ct).body(body).dispatch().await;
    let group_id = parse_json(&body_of(response).await)["id"].as_str().expect("id").to_owned();

    let members_of = |body: &str| -> Vec<String> {
        let mut ids: Vec<String> = parse_json(body)["members"]
            .as_array()
            .expect("members")
            .iter()
            .map(|m| m["value"].as_str().expect("value").to_owned())
            .collect();
        ids.sort();
        ids
    };

    // remove A then add A: the member must end up PRESENT.
    let payload = json!({
        "schemas": [scim::patch::PATCH_OP_URN],
        "Operations": [
            {"op": "remove", "path": "members", "value": [{"value": member_a}]},
            {"op": "add", "path": "members", "value": [{"value": member_a}]},
        ],
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response =
        client.patch(format!("/scim/v2/{org}/Groups/{group_id}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(
        members_of(&body_of(response).await),
        vec![member_a.to_string()],
        "remove-then-add must leave A present"
    );

    // add A then remove A: the member must end up ABSENT. Bucketing by op would
    // make this indistinguishable from the case above.
    let payload = json!({
        "schemas": [scim::patch::PATCH_OP_URN],
        "Operations": [
            {"op": "add", "path": "members", "value": [{"value": member_a}]},
            {"op": "remove", "path": "members", "value": [{"value": member_a}]},
        ],
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response =
        client.patch(format!("/scim/v2/{org}/Groups/{group_id}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    assert!(members_of(&body_of(response).await).is_empty(), "add-then-remove must leave A absent");

    // A replace must not discard a later add in the same PatchOp.
    let payload = json!({
        "schemas": [scim::patch::PATCH_OP_URN],
        "Operations": [
            {"op": "replace", "path": "members", "value": [{"value": member_a}]},
            {"op": "add", "path": "members", "value": [{"value": member_b}]},
        ],
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response =
        client.patch(format!("/scim/v2/{org}/Groups/{group_id}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let mut expected = vec![member_a.to_string(), member_b.to_string()];
    expected.sort();
    assert_eq!(members_of(&body_of(response).await), expected, "a replace must not swallow a later add");
}

// ---------------------------------------------------------------------------
// The two config master switches, from the DENIED side.
//
// CONFIG is a process-global LazyLock pinned by the test-support ctor, so these
// use scim::test_config to override the answer for the duration of one test.
// The override resets on drop, and TEST_LOCK keeps it from leaking sideways.
// ---------------------------------------------------------------------------

// SCIM_ENABLED is the master gate: with it off, a perfectly valid token must be
// refused, and refused identically to every other auth failure so the response
// carries no signal about which check rejected it.
#[rocket::async_test]
async fn scim_disabled_refuses_a_valid_token_with_the_uniform_401() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-disabled-org").await;
    let token = seed_scim_key(&conn, &org).await;
    let url = format!("/scim/v2/{org}/ServiceProviderConfig");

    // Enabled: the same token reaches the endpoint.
    let response = client.get(&url).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::Ok, "precondition: the token is valid");

    let disabled = scim::test_config::scim_enabled(false);
    let response = client.get(&url).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::Unauthorized, "SCIM_ENABLED=false must refuse a valid token");
    let denied_body = body_of(response).await;

    // Byte-identical to an unauthenticated request: the disabled state must not
    // be distinguishable from a bad credential.
    let response = client.get(&url).dispatch().await;
    assert_eq!(response.status(), Status::Unauthorized);
    assert_eq!(body_of(response).await, denied_body, "the disabled state must look like every other 401");

    drop(disabled);
    let response = client.get(&url).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::Ok, "the override must not leak past the test");
}

// ORG_GROUPS_ENABLED=false makes every Groups route answer 501, deliberately
// and loudly, inside a SCIM envelope rather than as an HTML error page.
#[rocket::async_test]
async fn groups_disabled_returns_a_scim_enveloped_501_on_every_verb() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-groups-disabled-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let payload = json!({"schemas": [scim::discovery::GROUP_SCHEMA_URN], "displayName": "Blocked"});
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Groups")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created, "precondition: groups work while enabled");
    let group_id = parse_json(&body_of(response).await)["id"].as_str().expect("id").to_owned();

    let disabled = scim::test_config::org_groups_enabled(false);

    let mut refused = Vec::new();
    refused.push(("list", client.get(format!("/scim/v2/{org}/Groups")).header(bearer(&token)).dispatch().await));
    refused
        .push(("get", client.get(format!("/scim/v2/{org}/Groups/{group_id}")).header(bearer(&token)).dispatch().await));
    let (auth, ct, body) = scim_body(&token, &payload);
    refused.push((
        "post",
        client.post(format!("/scim/v2/{org}/Groups")).header(auth).header(ct).body(body).dispatch().await,
    ));
    let (auth, ct, body) = scim_body(&token, &payload);
    refused.push((
        "put",
        client.put(format!("/scim/v2/{org}/Groups/{group_id}")).header(auth).header(ct).body(body).dispatch().await,
    ));
    let rename = json!({
        "schemas": [scim::patch::PATCH_OP_URN],
        "Operations": [{"op": "replace", "path": "displayName", "value": "Nope"}],
    });
    let (auth, ct, body) = scim_body(&token, &rename);
    refused.push((
        "patch",
        client.patch(format!("/scim/v2/{org}/Groups/{group_id}")).header(auth).header(ct).body(body).dispatch().await,
    ));
    refused.push((
        "delete",
        client.delete(format!("/scim/v2/{org}/Groups/{group_id}")).header(bearer(&token)).dispatch().await,
    ));

    for (verb, response) in refused {
        assert_eq!(response.status(), Status::NotImplemented, "{verb} must be 501 when groups are disabled");
        let body = body_of(response).await;
        assert!(body.contains("urn:ietf:params:scim:api:messages:2.0:Error"), "{verb} must stay in a SCIM envelope");
        assert!(body.contains("ORG_GROUPS_ENABLED"), "{verb} must name the switch an operator has to flip");
    }

    // Discovery must agree with the handlers rather than advertising an
    // endpoint that refuses.
    let response = client.get(format!("/scim/v2/{org}/ResourceTypes")).header(bearer(&token)).dispatch().await;
    let body = body_of(response).await;
    assert!(!body.contains("\"endpoint\":\"/Groups\""), "ResourceTypes must not advertise a disabled Groups endpoint");
    let response = client.get(format!("/scim/v2/{org}/Schemas")).header(bearer(&token)).dispatch().await;
    assert!(!body_of(response).await.contains(scim::discovery::GROUP_SCHEMA_URN), "Schemas must drop the Group schema");

    drop(disabled);
    let response = client.get(format!("/scim/v2/{org}/Groups")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::Ok, "the override must not leak past the test");
}

// Asserts one refused write against a privileged membership.
async fn assert_privileged_refusal(response: LocalResponse<'_>, what: &str, label: i32) {
    assert_eq!(response.status(), Status::BadRequest, "{what} on membership type {label} must be refused");
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["scimType"], json!("mutability"), "{what} on membership type {label}");
    assert!(
        parsed["detail"].as_str().expect("detail").contains("administrative role"),
        "{what} must say why it was refused"
    );
}

// SCIM never GRANTS administrative privilege, but may still deprovision it.
//
// Restore is lossless (the akey survives revocation), so reinstating a revoked
// Owner would return full vault access with no admin action - the path a
// departing administrator with a retained token and their master password could
// otherwise use on themselves. Revocation stays open: refusing it would make
// offboarding an administrator through the IdP a silent no-op, which is a worse
// failure than a recoverable mass-revoke.
#[rocket::async_test]
async fn scim_can_deprovision_an_administrator_but_never_reinstate_one() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-privileged-org").await;
    let token = seed_scim_key(&conn, &org).await;
    // A spare confirmed Owner, so the last-confirmed-owner guard is provably
    // not what allows or refuses anything below.
    seed_member(&conn, &org, "second.owner@example.com", 2, MembershipType::Owner).await;

    let activate = json!({
        "schemas": [scim::patch::PATCH_OP_URN],
        "Operations": [{"op": "replace", "path": "active", "value": true}],
    });

    for atype in [MembershipType::Owner, MembershipType::Admin, MembershipType::Manager] {
        let label = atype as i32;
        let member = seed_member(&conn, &org, &format!("privileged.{label}@example.com"), 2, atype).await;

        // Linking to a directory object is the first half of a grant: refused.
        let link = json!({
            "schemas": [scim::patch::PATCH_OP_URN],
            "Operations": [{"op": "replace", "path": "externalId", "value": format!("entra-admin-{label}")}],
        });
        let (auth, ct, body) = scim_body(&token, &link);
        let response =
            client.patch(format!("/scim/v2/{org}/Users/{member}")).header(auth).header(ct).body(body).dispatch().await;
        assert_privileged_refusal(response, "patch externalId", label).await;
        let stored = Membership::find_by_uuid_and_org(&member, &org, &conn).await.expect("row");
        assert_eq!(stored.external_id, None, "membership type {label} must not be linked to a directory object");

        // Deprovisioning is allowed: offboarding an admin from the IdP is
        // legitimate, and this is the highest-value path of the feature.
        let response = client.delete(format!("/scim/v2/{org}/Users/{member}")).header(bearer(&token)).dispatch().await;
        assert_eq!(response.status(), Status::NoContent, "membership type {label} must still be deprovisionable");
        assert_eq!(member_status(&conn, &member, &org).await, -126);

        // Reinstating is refused, and the membership stays revoked.
        let (auth, ct, body) = scim_body(&token, &activate);
        let response =
            client.patch(format!("/scim/v2/{org}/Users/{member}")).header(auth).header(ct).body(body).dispatch().await;
        assert_privileged_refusal(response, "patch active:true", label).await;
        assert_eq!(member_status(&conn, &member, &org).await, -126, "membership type {label} must remain revoked");

        // Still readable, so a mis-assignment surfaces as a clear per-user
        // error rather than a create loop on an address that already exists.
        let response = client.get(format!("/scim/v2/{org}/Users/{member}")).header(bearer(&token)).dispatch().await;
        assert_eq!(response.status(), Status::Ok, "membership type {label} must stay readable");
        assert_eq!(parse_json(&body_of(response).await)["active"], json!(false));
    }

    // An ordinary member round-trips in both directions, as always.
    let member = seed_member(&conn, &org, "ordinary@example.com", 2, MembershipType::User).await;
    let response = client.delete(format!("/scim/v2/{org}/Users/{member}")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::NoContent);
    assert_eq!(member_status(&conn, &member, &org).await, -126);
    let (auth, ct, body) = scim_body(&token, &activate);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{member}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok, "an ordinary member must still restore");
    assert_eq!(member_status(&conn, &member, &org).await, 2);
}

// ---------------------------------------------------------------------------
// Suite F - concurrency and idempotency.
//
// Entra retries aggressively and runs overlapping sync cycles, so every write
// path has to be safe against a duplicate arriving while the first is still in
// flight. These dispatch concurrently through one Rocket client; TEST_LOCK is
// still held, so the concurrency is inside the test, not across tests.
// ---------------------------------------------------------------------------

// F1: the membership uniqueness check is check-then-insert, backed by
// UNIQUE (user_uuid, org_uuid) on users_organizations. Concurrent creates must
// therefore collapse to exactly one membership - a duplicate would mean a
// deprovision revokes one row and leaves the other live.
#[rocket::async_test]
async fn concurrent_create_yields_exactly_one_membership() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-race-create-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let payload = json!({
        "schemas": [scim::discovery::USER_SCHEMA_URN],
        "userName": "race.create@example.com",
    });

    let mut inflight = Vec::new();
    for _ in 0..6 {
        let (auth, ct, body) = scim_body(&token, &payload);
        inflight.push(client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body(body).dispatch());
    }
    let responses = futures::future::join_all(inflight).await;

    let created = responses.iter().filter(|r| r.status() == Status::Created).count();
    let conflicts = responses.iter().filter(|r| r.status() == Status::Conflict).count();
    assert_eq!(created, 1, "exactly one create may win");
    assert_eq!(conflicts + created, 6, "every other request must be a 409, not a 500: {responses:?}");

    let user = User::find_by_mail("race.create@example.com", &conn).await.expect("user row");
    let memberships =
        Membership::find_by_org(&org, &conn).await.into_iter().filter(|m| m.user_uuid == user.uuid).count();
    assert_eq!(memberships, 1, "a duplicate membership would survive deprovisioning");
}

// F3: revoke and restore racing on one member. Either order is acceptable; a
// third state, or a lost akey, is not.
#[rocket::async_test]
async fn concurrent_revoke_and_restore_converge_without_losing_the_key() {
    const AKEY: &str = "2.RACE-WRAPPED-ORG-KEY|mac";

    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;

    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-race-active-org").await;
    let token = seed_scim_key(&conn, &org).await;
    let user = seed_user(&conn, "race.active@example.com", true).await;
    let mut member = Membership::new(user.uuid, org.clone(), None);
    member.status = MembershipStatus::Confirmed as i32;
    member.akey = String::from(AKEY);
    member.save(&conn).await.expect("saving member");
    let member_id = member.uuid.clone();

    let op = |value: bool| {
        json!({
            "schemas": [scim::patch::PATCH_OP_URN],
            "Operations": [{"op": "replace", "path": "active", "value": value}],
        })
    };

    let mut inflight = Vec::new();
    for i in 0..8 {
        let (auth, ct, body) = scim_body(&token, &op(i % 2 == 0));
        inflight.push(
            client.patch(format!("/scim/v2/{org}/Users/{member_id}")).header(auth).header(ct).body(body).dispatch(),
        );
    }
    let responses = futures::future::join_all(inflight).await;
    for response in &responses {
        assert_eq!(response.status(), Status::Ok, "every active flip must succeed or the sync stalls");
    }

    let stored = Membership::find_by_uuid_and_org(&member_id, &org, &conn).await.expect("row");
    assert!(
        stored.status == MembershipStatus::Confirmed as i32 || stored.status == -126,
        "must settle on Confirmed or revoked-Confirmed, got {}",
        stored.status
    );
    assert_eq!(stored.akey, AKEY, "no interleaving may destroy the wrapped org key");
}

// F4/F7: concurrent group membership writes. The diff-based set_members must
// converge without dropping a member that no request asked to remove.
#[rocket::async_test]
async fn concurrent_group_member_writes_converge() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-race-group-org").await;
    let token = seed_scim_key(&conn, &org).await;
    let keep = seed_member(&conn, &org, "race.keep@example.com", 1, MembershipType::User).await;
    let churn = seed_member(&conn, &org, "race.churn@example.com", 1, MembershipType::User).await;

    let create = json!({
        "schemas": [scim::discovery::GROUP_SCHEMA_URN],
        "displayName": "Race Group",
        "members": [{"value": keep}],
    });
    let (auth, ct, body) = scim_body(&token, &create);
    let response = client.post(format!("/scim/v2/{org}/Groups")).header(auth).header(ct).body(body).dispatch().await;
    let group_id = parse_json(&body_of(response).await)["id"].as_str().expect("id").to_owned();

    let member_op = |op: &str, id: &MembershipId| {
        json!({
            "schemas": [scim::patch::PATCH_OP_URN],
            "Operations": [{"op": op, "path": "members", "value": [{"value": id}]}],
        })
    };

    let mut inflight = Vec::new();
    for i in 0..8 {
        let payload = if i % 2 == 0 {
            member_op("add", &churn)
        } else {
            member_op("remove", &churn)
        };
        let (auth, ct, body) = scim_body(&token, &payload);
        inflight.push(
            client.patch(format!("/scim/v2/{org}/Groups/{group_id}")).header(auth).header(ct).body(body).dispatch(),
        );
    }
    for response in futures::future::join_all(inflight).await {
        assert_eq!(response.status(), Status::Ok);
    }

    // `keep` was never named by any concurrent operation, so no interleaving
    // may have removed it. This is the property wipe-and-rebuild used to break.
    let group_id_typed: GroupId = group_id.clone().into();
    let still_present = GroupUser::find_by_group(&group_id_typed, &org, &conn)
        .await
        .into_iter()
        .any(|gu| gu.users_organizations_uuid == keep);
    assert!(still_present, "a member nobody touched must never be collaterally removed");
}

// F5: two groups cannot end up sharing an externalId, which is the IdP's
// correlation key - a duplicate makes later syncs target an arbitrary group.
#[rocket::async_test]
async fn concurrent_group_create_cannot_duplicate_an_external_id() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-race-grp-ext-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let payload = json!({
        "schemas": [scim::discovery::GROUP_SCHEMA_URN],
        "displayName": "Race Ext Group",
        "externalId": "entra-race-grp-1",
    });

    let mut inflight = Vec::new();
    for _ in 0..5 {
        let (auth, ct, body) = scim_body(&token, &payload);
        inflight.push(client.post(format!("/scim/v2/{org}/Groups")).header(auth).header(ct).body(body).dispatch());
    }
    let responses = futures::future::join_all(inflight).await;
    let created = responses.iter().filter(|r| r.status() == Status::Created).count();

    let with_ext = Group::find_by_organization(&org, &conn)
        .await
        .into_iter()
        .filter(|g| g.external_id.as_deref() == Some("entra-race-grp-1"))
        .count();
    // What the code actually guarantees, and no more. Group externalId
    // uniqueness is check-then-set (post_group reads, then writes) with NO
    // backing constraint - the (org_uuid, external_id) index added on
    // 2026-07-26 is deliberately non-UNIQUE - so under real concurrency two
    // creates CAN both win. Asserting created == 1 pinned an invariant TODOS.md
    // records as open, which meant the test would flake, and while it stayed
    // green it read as proof the gap was closed.
    //
    // Strengthen this to created == 1 in the same change that adds UNIQUE to
    // that index and maps the violation to 409, not before. See TODOS.md,
    // "Harden SCIM write edges surfaced by adversarial review", gap (1).
    assert!(created >= 1, "at least one create must win, got {created}");
    assert!(
        responses.iter().all(|r| r.status() == Status::Created || r.status() == Status::Conflict),
        "every response must be 201 or 409, never a 5xx: {responses:?}"
    );
    assert_eq!(with_ext, created, "every winning create must be the one that stored the correlation key");
}

// F9: Entra re-sends steady state constantly. A replayed request must be a
// no-op at the row level, not just return the same status.
#[rocket::async_test]
async fn replaying_a_sync_cycle_changes_nothing() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-replay-org").await;
    let token = seed_scim_key(&conn, &org).await;
    let member = seed_member(&conn, &org, "replay@example.com", 2, MembershipType::User).await;

    let put = json!({
        "schemas": [scim::discovery::USER_SCHEMA_URN],
        "userName": "replay@example.com",
        "externalId": "entra-replay-1",
        "active": true,
    });

    let snapshot = |rows: Vec<Membership>| -> Vec<(String, i32, Option<String>, String)> {
        let mut v: Vec<_> = rows.into_iter().map(|m| (m.uuid.to_string(), m.status, m.external_id, m.akey)).collect();
        v.sort();
        v
    };

    // First application establishes the steady state.
    let (auth, ct, body) = scim_body(&token, &put);
    let response =
        client.put(format!("/scim/v2/{org}/Users/{member}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let before = snapshot(Membership::find_by_org(&org, &conn).await);

    // Ten identical replays must not move anything.
    for round in 0..10 {
        let (auth, ct, body) = scim_body(&token, &put);
        let response =
            client.put(format!("/scim/v2/{org}/Users/{member}")).header(auth).header(ct).body(body).dispatch().await;
        assert_eq!(response.status(), Status::Ok, "replay {round} must stay 200, not 409");
    }
    assert_eq!(snapshot(Membership::find_by_org(&org, &conn).await), before, "a replayed sync must be a no-op");
}

// ---------------------------------------------------------------------------
// Mail-dependent cases.
//
// The hermetic environment has mail ENABLED, pointed at an unroutable host;
// mail::test_sink intercepts every message before any transport is built. These
// assert the things that were previously invisible: that an invite was sent,
// that a second one was NOT, and what happens when the transport fails.
// ---------------------------------------------------------------------------

// A2: provisioning sends exactly one invite, to the right person.
#[rocket::async_test]
async fn provisioning_sends_exactly_one_invite() {
    let _guard = TEST_LOCK.lock().await;
    crate::mail::test_sink::reset();
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-mail-invite-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let payload = json!({
        "schemas": [scim::discovery::USER_SCHEMA_URN],
        "userName": "invitee@example.com",
        "externalId": "entra-invitee-1",
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created);

    let sent = crate::mail::test_sink::to("invitee@example.com");
    assert_eq!(sent.len(), 1, "exactly one invite, got {sent:?}");
}

// A5: restore of a CONFIRMED member must not re-invite - they already joined.
// Only a member restored to Invited gets the invite re-sent, because that one
// may never have received the original.
#[rocket::async_test]
async fn restore_reinvites_only_when_the_member_never_joined() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-mail-restore-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let activate = json!({
        "schemas": [scim::patch::PATCH_OP_URN],
        "Operations": [{"op": "replace", "path": "active", "value": true}],
    });

    // Confirmed -> revoked -> restored: no mail, the person already has access.
    let confirmed = seed_member(&conn, &org, "already.joined@example.com", 2, MembershipType::User).await;
    let response = client.delete(format!("/scim/v2/{org}/Users/{confirmed}")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::NoContent);
    crate::mail::test_sink::reset();
    let (auth, ct, body) = scim_body(&token, &activate);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{confirmed}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    assert!(
        crate::mail::test_sink::to("already.joined@example.com").is_empty(),
        "a confirmed member must not be re-invited on restore"
    );

    // Invited -> revoked -> restored: re-invited, because the original invite
    // may never have been sent or may have expired.
    let invited = seed_member(&conn, &org, "never.joined@example.com", 0, MembershipType::User).await;
    let response = client.delete(format!("/scim/v2/{org}/Users/{invited}")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::NoContent);
    crate::mail::test_sink::reset();
    let (auth, ct, body) = scim_body(&token, &activate);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{invited}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(
        crate::mail::test_sink::to("never.joined@example.com").len(),
        1,
        "a member restored to Invited must be re-invited or they can never register"
    );
}

// E7: an SMTP outage must NOT fail provisioning. Returning 5xx on every retry
// made Entra churn create-then-delete and risked quarantining the tenant.
#[rocket::async_test]
async fn smtp_outage_keeps_the_membership_and_does_not_fail_the_request() {
    let _guard = TEST_LOCK.lock().await;
    crate::mail::test_sink::reset();
    // RAII, not a bare toggle. Five assertions follow before the matching
    // fail_sends(false), and a panic in any of them would leave the global
    // flag set for every later test in the process - turning one failure into
    // a cascade that hides which test really broke.
    let smtp_outage = crate::mail::test_sink::fail_sends_guard();
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-smtp-outage-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let payload = json!({
        "schemas": [scim::discovery::USER_SCHEMA_URN],
        "userName": "outage@example.com",
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created, "an SMTP outage must not fail provisioning");
    let member_id = parse_json(&body_of(response).await)["id"].as_str().expect("id").to_owned();

    // The membership survives, so an admin can re-send from the web vault.
    let member_id: MembershipId = member_id.into();
    let stored = Membership::find_by_uuid_and_org(&member_id, &org, &conn).await.expect("membership must survive");
    assert_eq!(stored.status, MembershipStatus::Invited as i32);
    assert!(User::find_by_mail("outage@example.com", &conn).await.is_some(), "the account must survive too");

    // E8: once SMTP recovers, the next provision mails normally - no backlog,
    // no duplicate, no stuck state.
    drop(smtp_outage);
    let payload = json!({
        "schemas": [scim::discovery::USER_SCHEMA_URN],
        "userName": "after.outage@example.com",
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created);
    assert_eq!(crate::mail::test_sink::to("after.outage@example.com").len(), 1, "delivery must resume cleanly");
    assert!(
        crate::mail::test_sink::to("outage@example.com").is_empty(),
        "the failed invite must not be silently replayed later"
    );
}

// Provisioning a deactivated user (RFC 7644 allows creating one) must not mail:
// the person is not being invited to anything yet.
#[rocket::async_test]
async fn creating_an_inactive_member_sends_no_invite() {
    let _guard = TEST_LOCK.lock().await;
    crate::mail::test_sink::reset();
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-mail-inactive-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let payload = json!({
        "schemas": [scim::discovery::USER_SCHEMA_URN],
        "userName": "inactive@example.com",
        "active": false,
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created);
    assert!(crate::mail::test_sink::to("inactive@example.com").is_empty(), "a pre-revoked member must not be invited");
}

// The mail-disabled branch: no invite is possible, so an account that has never
// registered needs an Invitation row or it can never complete registration.
// This is the half of upstream's invite_user conditional that SCIM originally
// dropped.
#[rocket::async_test]
async fn mail_disabled_writes_an_invitation_row_for_unregistered_accounts() {
    let _guard = TEST_LOCK.lock().await;
    crate::mail::test_sink::reset();
    let _mail_off = scim::test_config::mail_enabled(false);
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-mail-off-org").await;
    let token = seed_scim_key(&conn, &org).await;

    // A brand-new account.
    let payload = json!({
        "schemas": [scim::discovery::USER_SCHEMA_URN],
        "userName": "fresh.shell@example.com",
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created);
    assert!(
        crate::db::models::Invitation::find_by_mail("fresh.shell@example.com", &conn).await.is_some(),
        "without an Invitation row the account can never register"
    );

    // A pre-existing account that has never registered (empty password hash),
    // e.g. created by an earlier SCIM run in another organization.
    let org_b = seed_org(&conn, "scim-mail-off-org-b").await;
    let token_b = seed_scim_key(&conn, &org_b).await;
    // seed_user creates only the account, never an Invitation row, so this
    // account starts in exactly the unregistered-and-uninvitable state.
    seed_user(&conn, "existing.shell@example.com", false).await;
    assert!(
        crate::db::models::Invitation::find_by_mail("existing.shell@example.com", &conn).await.is_none(),
        "precondition: no invitation row yet"
    );

    let payload = json!({
        "schemas": [scim::discovery::USER_SCHEMA_URN],
        "userName": "existing.shell@example.com",
    });
    let (auth, ct, body) = scim_body(&token_b, &payload);
    let response = client.post(format!("/scim/v2/{org_b}/Users")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created);
    assert!(
        crate::db::models::Invitation::find_by_mail("existing.shell@example.com", &conn).await.is_some(),
        "an existing but unregistered account also needs an Invitation row"
    );

    assert!(crate::mail::test_sink::captured().is_empty(), "no mail may be sent when mail is disabled");
}

// ---------------------------------------------------------------------------
// H2 - admin session fixture, and the token-management surface.
//
// /api/organizations/<org>/scim/* is the credential lifecycle: minting,
// rotating and revoking the machine token that guards everything else. It had
// no HTTP-level coverage at all, because it needs a real authenticated admin
// session. These build one: a user with a known master password, a device, and
// a genuine login JWT signed with the process key.
// ---------------------------------------------------------------------------

const ADMIN_PASSWORD: &str = "test-master-password-hash";

// Mounts the management routes where they live in production, at /api, so that
// OrgHeaders resolves the org from path parameter index 1 exactly as it does
// for real requests.
async fn manage_client() -> (Client, DbPool) {
    ensure_jwt_keys().await;
    let pool = test_pool().clone();
    let rocket = rocket::custom(rocket::Config::default())
        .mount("/api", scim::manage_routes())
        .register("/api", crate::api::core_catchers())
        .manage(pool.clone());
    let client = Client::untracked(rocket).await.expect("local rocket client");
    (client, pool)
}

/// Seeds a confirmed org admin and returns a bearer header for a real session.
async fn seed_admin_session(
    conn: &DbConn,
    org: &OrganizationId,
    email: &str,
    atype: MembershipType,
) -> Header<'static> {
    let mut user = User::new(email, None);
    user.password_hash =
        crypto::hash_password(ADMIN_PASSWORD.as_bytes(), &user.salt, user.password_iterations.cast_unsigned());
    user.verified_at = Some(chrono::Utc::now().naive_utc());
    user.save(conn).await.expect("saving admin user");

    let mut member = Membership::new(user.uuid.clone(), org.clone(), None);
    member.status = MembershipStatus::Confirmed as i32;
    member.atype = atype as i32;
    member.save(conn).await.expect("saving admin membership");

    let mut device = crate::db::models::Device::new(
        crate::db::models::DeviceId::from(crate::util::get_uuid()),
        user.uuid.clone(),
        String::from("test-device"),
        crate::db::models::DeviceType::ChromeBrowser as i32,
    );
    device.save(true, conn).await.expect("saving device");

    let now = chrono::Utc::now();
    let claims = crate::auth::LoginJwtClaims::new(
        &device,
        &user,
        now.timestamp(),
        (now + chrono::Duration::hours(2)).timestamp(),
        vec![String::from("api"), String::from("offline_access")],
        Some(String::from("web")),
        now,
    );
    Header::new("Authorization", format!("Bearer {}", crate::auth::encode_jwt(&claims)))
}

fn password_body(payload: &Value) -> (Header<'static>, String) {
    (Header::new("Content-Type", "application/json"), payload.to_string())
}

// The whole mint / use / rotate / revoke cycle, driven over HTTP.
#[rocket::async_test]
async fn scim_token_lifecycle_over_http() {
    let _guard = TEST_LOCK.lock().await;
    let (manage, pool) = manage_client().await;
    let (scim_api, _) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-manage-lifecycle-org").await;
    let admin = seed_admin_session(&conn, &org, "manage.admin@example.com", MembershipType::Owner).await;

    let auth = json!({"masterPasswordHash": ADMIN_PASSWORD});

    // Status before anything is minted.
    let response = manage.get(format!("/api/organizations/{org}/scim/status")).header(admin.clone()).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["keyConfigured"], json!(false));
    assert_eq!(parsed["scimEnabled"], json!(true));

    // Mint.
    let (ct, body) = password_body(&auth);
    let response = manage
        .post(format!("/api/organizations/{org}/scim/api-key"))
        .header(admin.clone())
        .header(ct)
        .body(body)
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let parsed = parse_json(&body_of(response).await);
    let first_token = parsed["token"].as_str().expect("token").to_owned();
    assert!(first_token.starts_with(&format!("scim_v1.{org}.")), "token must embed its org");
    assert_eq!(parsed["scimBaseUrl"], json!(format!("http://localhost:8000/scim/v2/{org}")));

    // The minted token actually works against the SCIM surface.
    let response =
        scim_api.get(format!("/scim/v2/{org}/ServiceProviderConfig")).header(bearer(&first_token)).dispatch().await;
    assert_eq!(response.status(), Status::Ok, "a freshly minted token must authenticate");

    // Rotate: the previous token dies immediately.
    let (ct, body) = password_body(&auth);
    let response = manage
        .post(format!("/api/organizations/{org}/scim/api-key"))
        .header(admin.clone())
        .header(ct)
        .body(body)
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let second_token = parse_json(&body_of(response).await)["token"].as_str().expect("token").to_owned();
    assert_ne!(first_token, second_token);

    let response =
        scim_api.get(format!("/scim/v2/{org}/ServiceProviderConfig")).header(bearer(&first_token)).dispatch().await;
    assert_eq!(response.status(), Status::Unauthorized, "rotation must kill the previous token at once");
    let response =
        scim_api.get(format!("/scim/v2/{org}/ServiceProviderConfig")).header(bearer(&second_token)).dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    // Exactly one key row survives rotation.
    assert!(ScimApiKey::find_by_org(&org, &conn).await.is_some());

    // Revoke.
    let (ct, body) = password_body(&auth);
    let response = manage
        .delete(format!("/api/organizations/{org}/scim/api-key"))
        .header(admin.clone())
        .header(ct)
        .body(body)
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let response =
        scim_api.get(format!("/scim/v2/{org}/ServiceProviderConfig")).header(bearer(&second_token)).dispatch().await;
    assert_eq!(response.status(), Status::Unauthorized, "a revoked token must stop working");

    let response = manage.get(format!("/api/organizations/{org}/scim/status")).header(admin).dispatch().await;
    assert_eq!(parse_json(&body_of(response).await)["keyConfigured"], json!(false));
}

// Minting is a protected action: an admin session alone is not enough.
#[rocket::async_test]
async fn minting_requires_reauthentication_and_the_right_org() {
    let _guard = TEST_LOCK.lock().await;
    let (manage, pool) = manage_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-manage-authz-org").await;
    let other_org = seed_org(&conn, "scim-manage-other-org").await;
    let admin = seed_admin_session(&conn, &org, "authz.admin@example.com", MembershipType::Owner).await;

    // No password and no OTP.
    let (ct, body) = password_body(&json!({}));
    let response = manage
        .post(format!("/api/organizations/{org}/scim/api-key"))
        .header(admin.clone())
        .header(ct)
        .body(body)
        .dispatch()
        .await;
    assert_ne!(response.status(), Status::Ok, "re-authentication must be required to mint a token");

    // Wrong password.
    let (ct, body) = password_body(&json!({"masterPasswordHash": "not-the-password"}));
    let response = manage
        .post(format!("/api/organizations/{org}/scim/api-key"))
        .header(admin.clone())
        .header(ct)
        .body(body)
        .dispatch()
        .await;
    assert_ne!(response.status(), Status::Ok, "a wrong master password must not mint a token");
    assert!(ScimApiKey::find_by_org(&org, &conn).await.is_none(), "no key may exist after a failed mint");

    // An admin of org A cannot mint for org B.
    let (ct, body) = password_body(&json!({"masterPasswordHash": ADMIN_PASSWORD}));
    let response = manage
        .post(format!("/api/organizations/{other_org}/scim/api-key"))
        .header(admin)
        .header(ct)
        .body(body)
        .dispatch()
        .await;
    assert_ne!(response.status(), Status::Ok, "cross-org minting must be refused");
    assert!(ScimApiKey::find_by_org(&other_org, &conn).await.is_none());

    // No session at all.
    let (ct, body) = password_body(&json!({"masterPasswordHash": ADMIN_PASSWORD}));
    let response = manage.post(format!("/api/organizations/{org}/scim/api-key")).header(ct).body(body).dispatch().await;
    assert_ne!(response.status(), Status::Ok, "an unauthenticated caller must not mint a token");
}

// A plain member must not be able to mint, rotate or inspect the org's SCIM
// credential - that is an administrative action.
#[rocket::async_test]
async fn a_plain_member_cannot_manage_the_scim_token() {
    let _guard = TEST_LOCK.lock().await;
    let (manage, pool) = manage_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-manage-member-org").await;
    let member = seed_admin_session(&conn, &org, "plain.member@example.com", MembershipType::User).await;

    let (ct, body) = password_body(&json!({"masterPasswordHash": ADMIN_PASSWORD}));
    let response = manage
        .post(format!("/api/organizations/{org}/scim/api-key"))
        .header(member.clone())
        .header(ct)
        .body(body)
        .dispatch()
        .await;
    assert_ne!(response.status(), Status::Ok, "a plain member must not mint a SCIM token");

    let (ct, body) = password_body(&json!({"masterPasswordHash": ADMIN_PASSWORD}));
    let response = manage
        .delete(format!("/api/organizations/{org}/scim/api-key"))
        .header(member.clone())
        .header(ct)
        .body(body)
        .dispatch()
        .await;
    assert_ne!(response.status(), Status::Ok, "a plain member must not revoke a SCIM token");

    let response = manage.get(format!("/api/organizations/{org}/scim/status")).header(member).dispatch().await;
    assert_ne!(response.status(), Status::Ok, "a plain member must not read SCIM key metadata");
}

// The break-glass signal: every confirmed Owner carrying a SCIM externalId
// means no Owner survives a compromise of the identity provider.
#[rocket::async_test]
async fn status_reports_when_every_owner_is_directory_linked() {
    let _guard = TEST_LOCK.lock().await;
    let (manage, pool) = manage_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-breakglass-org").await;
    let admin = seed_admin_session(&conn, &org, "breakglass.admin@example.com", MembershipType::Owner).await;

    // One Owner, not directory-linked: healthy, no warning.
    let response = manage.get(format!("/api/organizations/{org}/scim/status")).header(admin.clone()).dispatch().await;
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["confirmedOwners"], json!(1));
    assert_eq!(parsed["directoryLinkedOwners"], json!(0));
    assert_eq!(parsed["breakGlassWarning"], Value::Null, "an unlinked Owner means no warning");

    // Link that Owner to a directory object, as a promotion after provisioning
    // would. Now every Owner came from the IdP.
    let mut owner =
        Membership::find_by_email_and_org("breakglass.admin@example.com", &org, &conn).await.expect("owner membership");
    owner.set_external_id(Some(String::from("entra-owner-1")));
    owner.save(&conn).await.expect("linking owner");

    let response = manage.get(format!("/api/organizations/{org}/scim/status")).header(admin).dispatch().await;
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["confirmedOwners"], json!(1));
    assert_eq!(parsed["directoryLinkedOwners"], json!(1));
    assert!(
        parsed["breakGlassWarning"].as_str().is_some_and(|w| w.contains("no recovery path")),
        "an org whose every Owner is directory-linked must be warned"
    );
}

// ---------------------------------------------------------------------------
// Suite B1 - authentication edge cases.
//
// Every rejection must be a byte-identical 401, so the surface leaks nothing
// about which check failed or which organizations exist.
// ---------------------------------------------------------------------------

#[rocket::async_test]
async fn malformed_credentials_are_all_the_same_401() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-auth-edges-org").await;
    let token = seed_scim_key(&conn, &org).await;
    let url = format!("/scim/v2/{org}/ServiceProviderConfig");

    // Baseline: the real token works, so a 401 below is the credential and not
    // a broken route.
    let response = client.get(&url).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let secret = token.rsplit('.').next().expect("secret").to_owned();
    let cases: Vec<(&str, String)> = vec![
        ("trailing newline", format!("{token}\n")),
        ("trailing space", format!("{token} ")),
        ("leading space", format!(" {token}")),
        ("uppercased org segment", format!("scim_v1.{}.{secret}", org.to_string().to_uppercase())),
        ("right length wrong alphabet", format!("scim_v1.{org}.{}", "!".repeat(secret.len()))),
        ("empty secret", format!("scim_v1.{org}.")),
        ("no version prefix", format!("{org}.{secret}")),
        ("very long secret", format!("scim_v1.{org}.{}", "A".repeat(100_000))),
        ("null byte in secret", format!("scim_v1.{org}.{secret}\0")),
    ];

    let mut bodies = Vec::new();
    for (name, value) in cases {
        let response =
            client.get(&url).header(Header::new("Authorization", format!("Bearer {value}"))).dispatch().await;
        assert_eq!(response.status(), Status::Unauthorized, "case: {name}");
        bodies.push((name, body_of(response).await));
    }

    let (_, first) = &bodies[0];
    for (name, body) in &bodies {
        assert_eq!(body, first, "401 body differs for case: {name}");
    }
}

// A token for an organization that has since been deleted must fail closed,
// and must look no different from any other bad credential.
#[rocket::async_test]
async fn a_token_for_a_deleted_org_is_an_ordinary_401() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-deleted-org").await;
    let token = seed_scim_key(&conn, &org).await;
    let url = format!("/scim/v2/{org}/ServiceProviderConfig");

    let response = client.get(&url).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::Ok, "precondition");
    let unauth_body = body_of(client.get(&url).dispatch().await).await;

    Organization::find_by_uuid(&org, &conn).await.expect("org").delete(&conn).await.expect("deleting org");

    let response = client.get(&url).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::Unauthorized, "a deleted org's token must stop working");
    assert_eq!(body_of(response).await, unauth_body, "and must be indistinguishable from any other 401");

    // The cascade must have taken the key row with it.
    assert!(ScimApiKey::find_by_org(&org, &conn).await.is_none(), "org deletion must remove its SCIM key");
}

// ---------------------------------------------------------------------------
// Suite B4 - input validation. Hostile and merely awkward input must produce a
// SCIM-enveloped 4xx, never a 500 and never a panic.
// ---------------------------------------------------------------------------

#[rocket::async_test]
async fn hostile_string_input_is_rejected_or_stored_verbatim_never_5xx() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-hostile-input-org").await;
    let token = seed_scim_key(&conn, &org).await;

    // SQL metacharacters, unicode direction overrides, control characters and
    // template-looking values. The Diesel DSL boundary must hold for all of it.
    let nasty = [
        "'; DROP TABLE users_organizations; --",
        "\" OR \"1\"=\"1",
        "\u{202e}gnp.exe",
        "{{7*7}}",
        "<script>alert(1)</script>",
        "../../etc/passwd",
        "%00",
        "\u{1f600}\u{1f4a3}",
    ];

    for (i, value) in nasty.iter().enumerate() {
        let payload = json!({
            "schemas": [scim::discovery::USER_SCHEMA_URN],
            "userName": format!("hostile{i}@example.com"),
            "displayName": value,
            "externalId": value,
        });
        let (auth, ct, body) = scim_body(&token, &payload);
        let response = client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body(body).dispatch().await;
        assert!(
            response.status() == Status::Created || response.status() == Status::BadRequest,
            "value {value:?} produced {} - must be 201 or 400, never 5xx",
            response.status()
        );
    }

    // The table is still there and still queryable, which a successful
    // injection would have changed.
    let response = client.get(format!("/scim/v2/{org}/Users")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::Ok, "the members table must have survived");
}

#[rocket::async_test]
async fn malformed_and_oversized_bodies_stay_in_the_scim_envelope() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-bad-body-org").await;
    let token = seed_scim_key(&conn, &org).await;
    let url = format!("/scim/v2/{org}/Users");

    let post = |body: String| {
        client
            .post(&url)
            .header(bearer(&token))
            .header(Header::new("Content-Type", SCIM_CONTENT_TYPE))
            .body(body)
            .dispatch()
    };

    // Not JSON at all.
    let response = post(String::from("this is not json")).await;
    assert_eq!(response.status(), Status::BadRequest);
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["scimType"], json!("invalidSyntax"));
    assert!(parsed["schemas"][0].as_str().is_some_and(|s| s.ends_with(":Error")));

    // Valid JSON, wrong shape.
    let response = post(json!(["not", "an", "object"]).to_string()).await;
    assert_eq!(response.status(), Status::BadRequest);
    assert_eq!(parse_json(&body_of(response).await)["scimType"], json!("invalidSyntax"));

    // Over the 512 KiB body limit.
    let huge = json!({
        "schemas": [scim::discovery::USER_SCHEMA_URN],
        "userName": "huge@example.com",
        "displayName": "x".repeat(600 * 1024),
    });
    let response = post(huge.to_string()).await;
    assert_eq!(response.status(), Status::PayloadTooLarge, "the body cap must be enforced");
    let parsed = parse_json(&body_of(response).await);
    assert!(parsed["schemas"][0].as_str().is_some_and(|s| s.ends_with(":Error")), "413 must be a SCIM envelope");

    // Missing and invalid userName.
    for payload in [
        json!({"schemas": [scim::discovery::USER_SCHEMA_URN]}),
        json!({"schemas": [scim::discovery::USER_SCHEMA_URN], "userName": "not-an-email"}),
        json!({"schemas": [scim::discovery::USER_SCHEMA_URN], "userName": ""}),
    ] {
        let response = post(payload.to_string()).await;
        assert_eq!(response.status(), Status::BadRequest, "payload {payload} must be rejected");
        assert_eq!(parse_json(&body_of(response).await)["scimType"], json!("invalidValue"));
    }
}

#[rocket::async_test]
async fn pagination_parameters_never_panic() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-page-edges-org").await;
    let token = seed_scim_key(&conn, &org).await;
    seed_member(&conn, &org, "page.one@example.com", 2, MembershipType::User).await;

    // startIndex 0 is the dangerous one: list_users does skip(start_index - 1)
    // on a usize, so a missing clamp is an underflow panic.
    for query in [
        "startIndex=0",
        "startIndex=-1",
        "startIndex=9223372036854775807",
        "count=-1",
        "count=0",
        "count=99999",
        "startIndex=0&count=0",
        "startIndex=-5&count=-5",
    ] {
        let response = client.get(format!("/scim/v2/{org}/Users?{query}")).header(bearer(&token)).dispatch().await;
        assert_eq!(response.status(), Status::Ok, "query {query} must not fail");
        let parsed = parse_json(&body_of(response).await);
        let per_page = parsed["itemsPerPage"].as_u64().expect("itemsPerPage");
        assert!(per_page <= 200, "query {query} returned {per_page}, above the advertised cap");
        assert!(parsed["startIndex"].as_i64().expect("startIndex") >= 1, "startIndex must be clamped to 1-based");
    }

    // A non-numeric pagination parameter is IGNORED, not rejected: Rocket's
    // FromForm for Option<i64> is lenient, so it arrives as None and the
    // default applies. That is the safer behaviour for a provisioning client -
    // failing an entire list request over a junk query parameter would stall a
    // sync - and it stays correct because totalResults remains truthful, so a
    // client that pages properly still sees everything.
    for query in ["count=abc", "startIndex=abc", "count=1.5", "startIndex=%20"] {
        let response = client.get(format!("/scim/v2/{org}/Users?{query}")).header(bearer(&token)).dispatch().await;
        assert_eq!(response.status(), Status::Ok, "query {query} must fall back to defaults, not fail");
        let parsed = parse_json(&body_of(response).await);
        assert_eq!(parsed["totalResults"], json!(1), "query {query}: the total must stay truthful");
        assert_eq!(parsed["startIndex"], json!(1), "query {query}: default startIndex");
    }
}

// An unsupported filter must be an explicit 400, never a silent full or empty
// result - a provisioning client reads either as authoritative.
#[rocket::async_test]
async fn unsupported_filters_fail_loudly() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-filter-grammar-org").await;
    let token = seed_scim_key(&conn, &org).await;
    seed_member(&conn, &org, "grammar@example.com", 2, MembershipType::User).await;

    for filter in [
        "userName co \"grammar\"",
        "userName sw \"gram\"",
        "userName pr",
        "userName eq \"a\" and active eq true",
        "userName eq \"a\" or userName eq \"b\"",
        "(userName eq \"a\")",
        "emails[type eq \"work\"].value eq \"x\"",
        "active eq true",
        "userName EQ unquoted",
        "userName",
        "",
    ] {
        let response = client
            .get(format!("/scim/v2/{org}/Users?filter={}", url_escape(filter)))
            .header(bearer(&token))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest, "filter {filter:?} must be refused, not guessed at");
        assert_eq!(parse_json(&body_of(response).await)["scimType"], json!("invalidFilter"), "filter {filter:?}");
    }
}

// ---------------------------------------------------------------------------
// Suite D - out-of-order and human chaos.
//
// Administrators act on the vault while the IdP acts on the directory, and the
// two do not coordinate. Each case is a sequence; the assertion is always the
// same shape: no privilege is gained, no access silently persists, and the
// state is recoverable without touching the database by hand.
// ---------------------------------------------------------------------------

// D2/D3: an admin deletes the member outright in the web vault while the IdP
// still thinks they exist. Subsequent syncs must 404, never resurrect the row.
#[rocket::async_test]
async fn a_member_deleted_in_the_vault_is_not_resurrected_by_a_sync() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-vault-delete-org").await;
    let token = seed_scim_key(&conn, &org).await;
    let member = seed_member(&conn, &org, "vanished@example.com", 2, MembershipType::User).await;

    // The admin removes them from the organization entirely.
    Membership::find_by_uuid_and_org(&member, &org, &conn)
        .await
        .expect("membership")
        .delete(&conn)
        .await
        .expect("deleting membership");

    let deactivate = json!({
        "schemas": [scim::patch::PATCH_OP_URN],
        "Operations": [{"op": "replace", "path": "active", "value": false}],
    });
    let activate = json!({
        "schemas": [scim::patch::PATCH_OP_URN],
        "Operations": [{"op": "replace", "path": "active", "value": true}],
    });

    for (label, payload) in [("deprovision", &deactivate), ("reprovision", &activate)] {
        let (auth, ct, body) = scim_body(&token, payload);
        let response =
            client.patch(format!("/scim/v2/{org}/Users/{member}")).header(auth).header(ct).body(body).dispatch().await;
        assert_eq!(response.status(), Status::NotFound, "{label} of a deleted member must 404");
    }

    let response = client.delete(format!("/scim/v2/{org}/Users/{member}")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::NotFound, "DELETE of a deleted member must 404");

    assert!(
        Membership::find_by_uuid_and_org(&member, &org, &conn).await.is_none(),
        "no sync operation may recreate a membership the admin removed"
    );
}

// D4/D5: an admin promotes a SCIM-provisioned member to Owner. From that moment
// the membership is read-only to SCIM in the granting direction, but the IdP
// can still offboard them.
#[rocket::async_test]
async fn promoting_a_member_makes_it_grant_immune_but_still_deprovisionable() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-promote-org").await;
    let token = seed_scim_key(&conn, &org).await;
    seed_member(&conn, &org, "spare.owner@example.com", 2, MembershipType::Owner).await;

    // Provisioned normally, as a plain member.
    let payload = json!({
        "schemas": [scim::discovery::USER_SCHEMA_URN],
        "userName": "promoted@example.com",
        "externalId": "entra-promoted-1",
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created);
    let member: MembershipId = parse_json(&body_of(response).await)["id"].as_str().expect("id").to_owned().into();

    // The admin promotes them in the web vault.
    let mut row = Membership::find_by_uuid_and_org(&member, &org, &conn).await.expect("membership");
    row.atype = MembershipType::Owner as i32;
    row.status = MembershipStatus::Confirmed as i32;
    row.save(&conn).await.expect("promoting");

    // The IdP can still deprovision them - offboarding must not silently fail.
    let response = client.delete(format!("/scim/v2/{org}/Users/{member}")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::NoContent, "a promoted member must still be offboardable");
    assert_eq!(member_status(&conn, &member, &org).await, -126);

    // But it can no longer put them back.
    let activate = json!({
        "schemas": [scim::patch::PATCH_OP_URN],
        "Operations": [{"op": "replace", "path": "active", "value": true}],
    });
    let (auth, ct, body) = scim_body(&token, &activate);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{member}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::BadRequest, "reinstating a promoted member must be refused");
    assert_eq!(member_status(&conn, &member, &org).await, -126, "and must leave them revoked");
}

// D8/D9/D10: the credential changes underneath an in-flight sync. Every case
// must fail closed and leave nothing half-applied.
#[rocket::async_test]
async fn credential_changes_mid_sync_fail_closed() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-credential-churn-org").await;
    let token = seed_scim_key(&conn, &org).await;
    let member = seed_member(&conn, &org, "churn@example.com", 2, MembershipType::User).await;

    // Rotation: the old token dies at once.
    let rotated = seed_scim_key(&conn, &org).await;
    assert_ne!(token, rotated);
    let response = client.delete(format!("/scim/v2/{org}/Users/{member}")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::Unauthorized, "a rotated-away token must not still deprovision");
    assert_eq!(member_status(&conn, &member, &org).await, 2, "and must not have applied anything");

    // The new token works.
    let response = client.delete(format!("/scim/v2/{org}/Users/{member}")).header(bearer(&rotated)).dispatch().await;
    assert_eq!(response.status(), Status::NoContent);

    // Key deleted entirely: everything stops.
    ScimApiKey::delete_all_by_organization(&org, &conn).await.expect("deleting key");
    let response = client.get(format!("/scim/v2/{org}/Users")).header(bearer(&rotated)).dispatch().await;
    assert_eq!(response.status(), Status::Unauthorized, "a deleted key must stop the surface");

    // SCIM disabled globally: same, and indistinguishable.
    let fresh = seed_scim_key(&conn, &org).await;
    let disabled = scim::test_config::scim_enabled(false);
    let response = client.get(format!("/scim/v2/{org}/Users")).header(bearer(&fresh)).dispatch().await;
    assert_eq!(response.status(), Status::Unauthorized);
    drop(disabled);
    let response = client.get(format!("/scim/v2/{org}/Users")).header(bearer(&fresh)).dispatch().await;
    assert_eq!(response.status(), Status::Ok, "and must recover the moment it is re-enabled");
}

// D11: a group deleted in the vault must not be recreated by a membership
// PATCH still in flight from the IdP.
#[rocket::async_test]
async fn a_group_deleted_in_the_vault_is_not_resurrected() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-group-vanish-org").await;
    let token = seed_scim_key(&conn, &org).await;
    let member = seed_member(&conn, &org, "grp.member@example.com", 1, MembershipType::User).await;

    let create = json!({
        "schemas": [scim::discovery::GROUP_SCHEMA_URN],
        "displayName": "Doomed Group",
        "members": [{"value": member}],
    });
    let (auth, ct, body) = scim_body(&token, &create);
    let response = client.post(format!("/scim/v2/{org}/Groups")).header(auth).header(ct).body(body).dispatch().await;
    let group_id = parse_json(&body_of(response).await)["id"].as_str().expect("id").to_owned();

    // The admin deletes the group in the vault.
    let typed: GroupId = group_id.clone().into();
    Group::find_by_uuid_and_org(&typed, &org, &conn)
        .await
        .expect("group")
        .delete(&org, &conn)
        .await
        .expect("deleting group");

    let patch = json!({
        "schemas": [scim::patch::PATCH_OP_URN],
        "Operations": [{"op": "add", "path": "members", "value": [{"value": member}]}],
    });
    let (auth, ct, body) = scim_body(&token, &patch);
    let response =
        client.patch(format!("/scim/v2/{org}/Groups/{group_id}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::NotFound, "a membership PATCH must not recreate a deleted group");
    assert!(Group::find_by_uuid_and_org(&typed, &org, &conn).await.is_none());
}

// D13: the same person in two organizations. Deprovisioning from one must not
// touch the other's membership or its wrapped org key.
#[rocket::async_test]
async fn deprovisioning_in_one_org_leaves_the_other_untouched() {
    const AKEY_B: &str = "2.ORG-B-WRAPPED-KEY|mac";

    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");

    let org_a = seed_org(&conn, "scim-dual-a").await;
    let token_a = seed_scim_key(&conn, &org_a).await;
    let org_b = seed_org(&conn, "scim-dual-b").await;
    let user = seed_user(&conn, "in.both@example.com", true).await;

    let mut member_a = Membership::new(user.uuid.clone(), org_a.clone(), None);
    member_a.status = MembershipStatus::Confirmed as i32;
    member_a.save(&conn).await.expect("membership a");
    let mut member_b = Membership::new(user.uuid.clone(), org_b.clone(), None);
    member_b.status = MembershipStatus::Confirmed as i32;
    member_b.akey = String::from(AKEY_B);
    member_b.save(&conn).await.expect("membership b");
    let (id_a, id_b) = (member_a.uuid.clone(), member_b.uuid.clone());

    let response = client.delete(format!("/scim/v2/{org_a}/Users/{id_a}")).header(bearer(&token_a)).dispatch().await;
    assert_eq!(response.status(), Status::NoContent);

    assert_eq!(member_status(&conn, &id_a, &org_a).await, -126, "org A is revoked");
    let b = Membership::find_by_uuid_and_org(&id_b, &org_b, &conn).await.expect("org B membership must survive");
    assert_eq!(b.status, MembershipStatus::Confirmed as i32, "org B must be untouched");
    assert_eq!(b.akey, AKEY_B, "org B's wrapped key must be untouched");
    assert!(User::find_by_uuid(&user.uuid, &conn).await.is_some(), "the shared account must survive");
}

// D15: one person reachable through two assigned groups must still be one
// membership, not two.
#[rocket::async_test]
async fn a_person_in_two_assigned_groups_has_one_membership() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-two-groups-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let payload = json!({
        "schemas": [scim::discovery::USER_SCHEMA_URN],
        "userName": "in.two.groups@example.com",
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created);
    let member = parse_json(&body_of(response).await)["id"].as_str().expect("id").to_owned();

    // The second group's sync re-POSTs the same person; that must conflict,
    // not duplicate.
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Conflict);

    for name in ["Group One", "Group Two"] {
        let create = json!({
            "schemas": [scim::discovery::GROUP_SCHEMA_URN],
            "displayName": name,
            "members": [{"value": member}],
        });
        let (auth, ct, body) = scim_body(&token, &create);
        let response =
            client.post(format!("/scim/v2/{org}/Groups")).header(auth).header(ct).body(body).dispatch().await;
        assert_eq!(response.status(), Status::Created, "group {name}");
    }

    let user = User::find_by_mail("in.two.groups@example.com", &conn).await.expect("user");
    let count = Membership::find_by_org(&org, &conn).await.into_iter().filter(|m| m.user_uuid == user.uuid).count();
    assert_eq!(count, 1, "belonging to two assigned groups must not create two memberships");
}

// D17: Entra retries a delete after the member was already restored. The
// operation is idempotent and ends in the state the last request asked for.
#[rocket::async_test]
async fn retried_deprovision_after_restore_is_idempotent() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-retry-order-org").await;
    let token = seed_scim_key(&conn, &org).await;
    let member = seed_member(&conn, &org, "retry.order@example.com", 2, MembershipType::User).await;

    let activate = json!({
        "schemas": [scim::patch::PATCH_OP_URN],
        "Operations": [{"op": "replace", "path": "active", "value": true}],
    });

    // deprovision, restore, then a retried deprovision arrives late.
    for round in 0..3 {
        let response = client.delete(format!("/scim/v2/{org}/Users/{member}")).header(bearer(&token)).dispatch().await;
        assert_eq!(response.status(), Status::NoContent, "delete round {round}");
        assert_eq!(member_status(&conn, &member, &org).await, -126, "delete round {round} must not double-offset");

        let (auth, ct, body) = scim_body(&token, &activate);
        let response =
            client.patch(format!("/scim/v2/{org}/Users/{member}")).header(auth).header(ct).body(body).dispatch().await;
        assert_eq!(response.status(), Status::Ok, "restore round {round}");
        assert_eq!(member_status(&conn, &member, &org).await, 2, "restore round {round} must return exactly to 2");
    }

    // A duplicate delete must not shift the offset a second time.
    for _ in 0..3 {
        let response = client.delete(format!("/scim/v2/{org}/Users/{member}")).header(bearer(&token)).dispatch().await;
        assert_eq!(response.status(), Status::NoContent);
    }
    assert_eq!(member_status(&conn, &member, &org).await, -126, "repeated deletes must be idempotent");
}

// ---------------------------------------------------------------------------
// Suite C (partial) - SCIM x SSO invariants.
//
// Vaultwarden's SSO login resolves an account in this order (identity.rs:221):
//   SsoUser::find_by_identifier(sub)  ->  SsoUser::find_by_mail(email)  ->  create
//
// These pin the properties of a SCIM-provisioned account that decide which
// branch it lands in. They deliberately do NOT drive the OIDC protocol - that
// needs a stub issuer (harness item H3) and is tracked separately. What they do
// cover is every SCIM-side precondition the SSO path reads, so a change on this
// side that would silently break SSO login fails here instead.
// ---------------------------------------------------------------------------

// The association gate at identity.rs:236 refuses to link an existing account
// when SSO_SIGNUPS_MATCH_EMAIL is off - but only if `private_key.is_some()`.
// A SCIM-provisioned account has never registered, so it has no keypair and is
// therefore ALWAYS linkable. That asymmetry is almost certainly intended, and
// nothing else records it; if SCIM ever started populating a keypair, SSO login
// would begin refusing provisioned users with no other test noticing.
#[rocket::async_test]
async fn a_scim_provisioned_account_stays_linkable_by_sso() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-sso-linkable-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let payload = json!({
        "schemas": [scim::discovery::USER_SCHEMA_URN],
        "userName": "sso.linkable@example.com",
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created);

    let user = User::find_by_mail("sso.linkable@example.com", &conn).await.expect("provisioned account");
    assert!(
        user.private_key.is_none(),
        "a provisioned account must have no keypair, or SSO refuses to associate it when \
         SSO_SIGNUPS_MATCH_EMAIL is disabled"
    );
    assert!(user.password_hash.is_empty(), "and no password until the person registers");

    // This is the exact lookup sso_login performs before deciding to create.
    let found = crate::db::models::SsoUser::find_by_mail("sso.linkable@example.com", &conn).await;
    let (matched, sso_user) = found.expect("SSO must find the provisioned account by email");
    assert_eq!(matched.uuid, user.uuid);
    assert!(sso_user.is_none(), "not yet bound to an SSO identity, so association is still open");
}

// Order inversion: people log in before IT assigns them. SSO creates the
// account first, then SCIM provisions the same address - which must attach a
// membership to the existing account rather than colliding or duplicating.
#[rocket::async_test]
async fn scim_attaches_to_an_account_sso_created_first() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-sso-order-org").await;
    let token = seed_scim_key(&conn, &org).await;

    // What sso_login does for an unknown user: create the account, mark the
    // address verified, no membership anywhere.
    let mut sso_created = User::new("sso.first@example.com", Some(String::from("SSO First")));
    sso_created.verified_at = Some(chrono::Utc::now().naive_utc());
    sso_created.save(&conn).await.expect("saving sso-created user");
    let original_uuid = sso_created.uuid.clone();

    let payload = json!({
        "schemas": [scim::discovery::USER_SCHEMA_URN],
        "userName": "sso.first@example.com",
        "externalId": "entra-sso-first",
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created, "provisioning must attach to the existing account");

    let user = User::find_by_mail("sso.first@example.com", &conn).await.expect("account");
    assert_eq!(user.uuid, original_uuid, "SCIM must not create a second account for the same address");
    assert_eq!(
        Membership::find_by_org(&org, &conn).await.into_iter().filter(|m| m.user_uuid == original_uuid).count(),
        1,
        "exactly one membership"
    );
}

// Both sides lowercase email, so a directory that reports mixed case still
// resolves to one account. If either side stopped normalising, SSO would create
// a duplicate account for an already-provisioned person.
#[rocket::async_test]
async fn mixed_case_directory_addresses_resolve_to_one_account() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-sso-case-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let payload = json!({
        "schemas": [scim::discovery::USER_SCHEMA_URN],
        "userName": "Mixed.Case@Example.COM",
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created);

    // Stored lowercased, and reachable by every casing the IdP might send.
    for probe in ["mixed.case@example.com", "Mixed.Case@Example.COM", "MIXED.CASE@EXAMPLE.COM"] {
        assert!(
            crate::db::models::SsoUser::find_by_mail(probe, &conn).await.is_some(),
            "SSO lookup with casing {probe:?} must find the provisioned account"
        );
    }
    let user = User::find_by_mail("mixed.case@example.com", &conn).await.expect("account");
    assert_eq!(user.email, "mixed.case@example.com", "the address is normalised on the way in");
}

// Deprovisioning is organization-scoped, not account-scoped. The person can
// still authenticate to the server afterwards; they simply have no org access.
// If SCIM ever deleted the account instead, every other org they belong to
// would lose them too - and their SSO identity binding with it.
#[rocket::async_test]
async fn deprovisioning_leaves_the_account_able_to_authenticate() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-sso-deprov-org").await;
    let token = seed_scim_key(&conn, &org).await;
    let member = seed_member(&conn, &org, "deprov.sso@example.com", 2, MembershipType::User).await;
    let user_uuid = Membership::find_by_uuid_and_org(&member, &org, &conn).await.expect("row").user_uuid;

    let response = client.delete(format!("/scim/v2/{org}/Users/{member}")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::NoContent);

    let user = User::find_by_uuid(&user_uuid, &conn).await.expect("the account must survive deprovisioning");
    assert!(user.enabled, "and must remain able to log in");
    assert!(
        crate::db::models::SsoUser::find_by_mail("deprov.sso@example.com", &conn).await.is_some(),
        "so SSO can still resolve them"
    );
    assert_eq!(member_status(&conn, &member, &org).await, -126, "only the org membership is revoked");
}

// A person in two organizations has one account and one SSO identity. SCIM
// deprovisioning from one org must not disturb the account the other org and
// the SSO binding both depend on.
#[rocket::async_test]
async fn the_shared_account_survives_one_org_deprovisioning() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org_a = seed_org(&conn, "scim-sso-shared-a").await;
    let token_a = seed_scim_key(&conn, &org_a).await;
    let org_b = seed_org(&conn, "scim-sso-shared-b").await;
    let token_b = seed_scim_key(&conn, &org_b).await;

    let payload = json!({
        "schemas": [scim::discovery::USER_SCHEMA_URN],
        "userName": "shared.sso@example.com",
    });
    for (org, token) in [(&org_a, &token_a), (&org_b, &token_b)] {
        let (auth, ct, body) = scim_body(token, &payload);
        let response = client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body(body).dispatch().await;
        assert_eq!(response.status(), Status::Created, "each org provisions its own membership");
    }

    let user = User::find_by_mail("shared.sso@example.com", &conn).await.expect("account");
    let member_a = Membership::find_by_user_and_org(&user.uuid, &org_a, &conn).await.expect("membership a");

    let response =
        client.delete(format!("/scim/v2/{org_a}/Users/{}", member_a.uuid)).header(bearer(&token_a)).dispatch().await;
    assert_eq!(response.status(), Status::NoContent);

    assert!(User::find_by_uuid(&user.uuid, &conn).await.is_some(), "the shared account must survive");
    let member_b = Membership::find_by_user_and_org(&user.uuid, &org_b, &conn).await.expect("org B must be untouched");
    assert!(member_b.status >= 0, "org B access must be unaffected by org A deprovisioning");
}

// ---------------------------------------------------------------------------
// Suite C (protocol level) - driving the real SSO login endpoint.
//
// sso::exchange_code returns early when SsoAuth.auth_response is already
// populated (sso.rs:258) - the path that exists so the 2FA round trip does not
// redeem the same code twice. Seeding that column lets these tests drive the
// genuine /identity/connect/token handler, and with it the real account
// resolution in identity.rs:221, without standing up an OIDC issuer or making
// a single network call.
//
// The environment pins SSO_SIGNUPS_MATCH_EMAIL=false (test-support ctor), the
// strict setting, because that is where SCIM and SSO actually interact.
// ---------------------------------------------------------------------------

/// Seeds the state an IdP round trip would have left behind, and returns the
/// authorization code the client would present.
async fn seed_sso_session(conn: &DbConn, email: &str, subject: &str) -> String {
    let code = format!("code-{subject}");
    let mut auth = crate::db::models::SsoAuth::new(
        crate::sso::OIDCState::from(format!("state-{subject}")),
        crate::sso::OIDCCodeChallenge::from(String::from("challenge")),
        String::from("nonce"),
        String::from("https://vault.example.com/sso-connector.html"),
        None,
    );
    auth.code_response = Some(crate::sso::OIDCCode::from(code.clone()));
    auth.auth_response = Some(crate::db::models::OIDCAuthenticatedUser {
        refresh_token: None,
        access_token: String::from("stub-access-token"),
        // The token is opaque rather than a JWT, so vaultwarden cannot derive
        // an expiry from it and requires expires_in to be present.
        expires_in: Some(std::time::Duration::from_hours(1)),
        // What the IdP asserts: a stable subject, scoped by issuer.
        identifier: crate::sso::OIDCIdentifier::from(format!("http://sso.invalid/realms/test/{subject}")),
        email: email.to_owned(),
        email_verified: Some(true),
        user_name: Some(email.to_owned()),
    });
    auth.save(conn).await.expect("seeding sso auth");
    code
}

/// Drives the real token endpoint exactly as the web vault would.
async fn attempt_sso_login(client: &Client, code: &str) -> (Status, String) {
    let form = format!(
        "grant_type=authorization_code&code={code}&code_verifier=verifier\
         &scope=api%20offline_access&client_id=web\
         &device_identifier=00000000-0000-0000-0000-0000000000{:02x}&device_name=test&device_type=10",
        code.len()
    );
    let response = client
        .post("/identity/connect/token")
        .header(rocket::http::ContentType::Form)
        .header(Header::new("Bitwarden-Client-Name", "web"))
        .body(form)
        .dispatch()
        .await;
    let status = response.status();
    (status, response.into_string().await.unwrap_or_default())
}

// The headline interaction. SCIM provisions a shell account and invites it;
// the person then signs in through the IdP for the first time. SSO must adopt
// that account rather than refuse it or create a second one - even with
// SSO_SIGNUPS_MATCH_EMAIL disabled, because the shell has no keypair.
#[rocket::async_test]
async fn sso_login_adopts_a_scim_provisioned_shell_account() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_and_identity_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-sso-adopt-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let payload = json!({
        "schemas": [scim::discovery::USER_SCHEMA_URN],
        "userName": "adopt.me@example.com",
        "externalId": "entra-adopt",
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created);
    let provisioned = User::find_by_mail("adopt.me@example.com", &conn).await.expect("shell account");

    let code = seed_sso_session(&conn, "adopt.me@example.com", "adopt-subject").await;
    let (status, body) = attempt_sso_login(&client, &code).await;

    assert_eq!(status, Status::Ok, "SSO must adopt the provisioned shell account, got: {body}");
    let after = User::find_by_mail("adopt.me@example.com", &conn).await.expect("account still present");
    assert_eq!(after.uuid, provisioned.uuid, "it must be the same account, not a second one");

    // The org membership SCIM created has to survive the adoption, or the
    // person signs in successfully and finds no organization.
    let membership = Membership::find_by_user_and_org(&after.uuid, &org, &conn).await.expect("membership survives");
    assert_eq!(membership.status, 0, "still Invited - SSO login does not confirm anyone");

    // And the account is now bound to the IdP subject.
    let (_, sso_user) = crate::db::models::SsoUser::find_by_mail("adopt.me@example.com", &conn).await.expect("found");
    assert!(sso_user.is_some(), "the SSO identity binding must have been recorded");
}

// The operational trap worth documenting. Once an account is bound to an IdP
// subject, a DIFFERENT subject with the same email is refused - and Entra
// issues a new subject when a directory entry is deleted and recreated. The
// person is then locked out with no self-service recovery: the binding has to
// be cleared server-side.
#[rocket::async_test]
async fn a_recreated_directory_entry_is_locked_out_by_the_old_identity_binding() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_and_identity_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-sso-recreate-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let payload = json!({
        "schemas": [scim::discovery::USER_SCHEMA_URN],
        "userName": "recreated@example.com",
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created);

    // First sign-in binds the original subject.
    let code = seed_sso_session(&conn, "recreated@example.com", "original-subject").await;
    let (status, body) = attempt_sso_login(&client, &code).await;
    assert_eq!(status, Status::Ok, "first login should bind the identity: {body}");

    // The directory entry is deleted and recreated: same address, new subject.
    let code = seed_sso_session(&conn, "recreated@example.com", "recreated-subject").await;
    let (status, body) = attempt_sso_login(&client, &code).await;

    assert_eq!(
        status,
        Status::BadRequest,
        "a new IdP subject for an already-bound address must be refused, not silently adopted"
    );
    assert!(
        !body.contains("access_token"),
        "and must not issue a session; recovery requires clearing the binding server-side"
    );
}

// SSO on its own is authentication, not authorization. Someone who can sign in
// through the IdP but was never provisioned gets an account and no org access -
// which is what makes SCIM the thing that grants access.
#[rocket::async_test]
async fn sso_login_alone_grants_no_organization_access() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_and_identity_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-sso-noaccess-org").await;

    let code = seed_sso_session(&conn, "never.provisioned@example.com", "stranger-subject").await;
    let (status, body) = attempt_sso_login(&client, &code).await;
    assert_eq!(status, Status::Ok, "the IdP vouched for them, so they get an account: {body}");

    let user = User::find_by_mail("never.provisioned@example.com", &conn).await.expect("account created");
    assert!(
        Membership::find_by_user_and_org(&user.uuid, &org, &conn).await.is_none(),
        "but no organization access, because SCIM never provisioned them"
    );
}

// Deprovisioning revokes org access without touching the account or its IdP
// binding, so a deprovisioned person can still authenticate - and still reaches
// nothing. This is the state an offboarded employee is left in.
#[rocket::async_test]
async fn a_deprovisioned_person_can_still_sign_in_but_reaches_nothing() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_and_identity_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-sso-offboard-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let payload = json!({
        "schemas": [scim::discovery::USER_SCHEMA_URN],
        "userName": "offboarded@example.com",
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created);
    let user = User::find_by_mail("offboarded@example.com", &conn).await.expect("account");
    let membership = Membership::find_by_user_and_org(&user.uuid, &org, &conn).await.expect("membership");

    let response =
        client.delete(format!("/scim/v2/{org}/Users/{}", membership.uuid)).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::NoContent);

    let code = seed_sso_session(&conn, "offboarded@example.com", "offboard-subject").await;
    let (status, _) = attempt_sso_login(&client, &code).await;
    assert_eq!(status, Status::Ok, "the IdP still vouches for them until the directory entry goes");

    let after = Membership::find_by_user_and_org(&user.uuid, &org, &conn).await.expect("revoked membership persists");
    assert!(after.status <= -1, "and the revocation must hold across an SSO login");
}

// The negative control for `sso_login_adopts_a_scim_provisioned_shell_account`.
// That test proves the association guard does NOT fire for a shell account;
// this proves the guard fires at all. Without both, "shell accounts link" is
// equally explained by the guard being broken.
//
// Here the account has registered and owns a keypair, so with
// SSO_SIGNUPS_MATCH_EMAIL=false the server must refuse to adopt it.
#[rocket::async_test]
async fn sso_refuses_an_account_that_has_already_registered() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_and_identity_client().await;
    let conn = pool.get().await.expect("conn");

    let mut registered = User::new("registered@example.com", Some(String::from("Registered")));
    // What registration leaves behind: the keypair that makes this a real
    // account rather than a provisioned shell.
    registered.private_key = Some(String::from("2.fake-encrypted-private-key"));
    registered.public_key = Some(String::from("fake-public-key"));
    registered.save(&conn).await.expect("saving registered user");

    let code = seed_sso_session(&conn, "registered@example.com", "registered-subject").await;
    let (status, body) = attempt_sso_login(&client, &code).await;

    assert_eq!(
        status,
        Status::BadRequest,
        "with SSO_SIGNUPS_MATCH_EMAIL=false an already-registered account must not be adopted"
    );
    assert!(!body.contains("access_token"), "and no session may be issued");
    assert!(
        crate::db::models::SsoUser::find_by_mail("registered@example.com", &conn)
            .await
            .is_some_and(|(_, sso)| sso.is_none()),
        "the refusal must not leave a half-written identity binding behind"
    );
}

// An IdP that explicitly says the address is unverified must not be trusted to
// hand over an existing account - that is an account-takeover primitive.
#[rocket::async_test]
async fn sso_refuses_an_explicitly_unverified_email() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_and_identity_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-sso-unverified-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let payload = json!({
        "schemas": [scim::discovery::USER_SCHEMA_URN],
        "userName": "unverified@example.com",
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created);

    let code = seed_sso_session(&conn, "unverified@example.com", "unverified-subject").await;
    // Downgrade the claim to an explicit false.
    let mut auth_row = crate::db::models::SsoAuth::find_by_code(&crate::sso::OIDCCode::from(code.clone()), &conn)
        .await
        .expect("seeded row");
    if let Some(response) = auth_row.auth_response.as_mut() {
        response.email_verified = Some(false);
    }
    auth_row.save(&conn).await.expect("saving downgraded claim");

    let (status, body) = attempt_sso_login(&client, &code).await;
    assert_eq!(status, Status::BadRequest, "an unverified address must not adopt an existing account");
    assert!(!body.contains("access_token"), "and no session may be issued");
}

// An IdP that omits the claim entirely is treated as unverified unless the
// operator has opted in with SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION. Fail closed.
#[rocket::async_test]
async fn sso_refuses_an_unknown_email_verification_status() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_and_identity_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-sso-unknown-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let payload = json!({
        "schemas": [scim::discovery::USER_SCHEMA_URN],
        "userName": "unknown.verification@example.com",
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created);

    let code = seed_sso_session(&conn, "unknown.verification@example.com", "unknown-subject").await;
    let mut auth_row = crate::db::models::SsoAuth::find_by_code(&crate::sso::OIDCCode::from(code.clone()), &conn)
        .await
        .expect("seeded row");
    if let Some(response) = auth_row.auth_response.as_mut() {
        response.email_verified = None;
    }
    auth_row.save(&conn).await.expect("saving absent claim");

    let (status, _) = attempt_sso_login(&client, &code).await;
    assert_eq!(
        status,
        Status::BadRequest,
        "an absent email_verified claim must fail closed unless the operator opts in"
    );
}

// C8. The invite mail is the only thing a provisioned person actually receives,
// and under SSO_ONLY it has to carry `orgSsoIdentifier` - that parameter is what
// makes the web vault route them to the IdP instead of asking for a master
// password they will never be allowed to use.
//
// CONFIG is a LazyLock, so one binary observes one value. This asserts whichever
// branch is active, which makes it meaningful in the default pass AND in the
// SSO_ONLY pass driven by tools/scim-test-config-matrix.sh.
#[rocket::async_test]
async fn the_invite_routes_through_sso_exactly_when_sso_only_is_set() {
    let _guard = TEST_LOCK.lock().await;
    crate::mail::test_sink::reset();
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-sso-only-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let payload = json!({
        "schemas": [scim::discovery::USER_SCHEMA_URN],
        "userName": "sso.only.invite@example.com",
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created);

    let sent = crate::mail::test_sink::to("sso.only.invite@example.com");
    assert_eq!(sent.len(), 1, "provisioning must send exactly one invite");
    let body = &sent[0].2;

    // Present regardless of config: without a token the invite cannot be redeemed.
    assert!(body.contains("accept-organization"), "the invite must link to the accept-organization flow");
    assert!(body.contains("token="), "and must carry an invite token");
    assert!(body.contains(&format!("organizationId={org}")), "scoped to the provisioning org");

    let sso_only = crate::CONFIG.sso_enabled() && crate::CONFIG.sso_only();

    // Guard against the matrix becoming theatre. Both branches below pass by
    // construction, so if the environment override never reached CONFIG this
    // test would quietly take the else-branch and still go green. Cross-check
    // the two sources directly: if the caller asked for SSO_ONLY and CONFIG
    // disagrees, the ctor's CALLER_MAY_OVERRIDE list is broken.
    if let Ok(requested) = std::env::var("SSO_ONLY") {
        let requested = requested == "true";
        assert_eq!(
            requested,
            crate::CONFIG.sso_only(),
            "SSO_ONLY was requested as {requested} but CONFIG reports {}; the test-support ctor \
             is no longer deferring to the caller and this matrix pass proves nothing",
            crate::CONFIG.sso_only()
        );
    }

    if sso_only {
        assert!(
            body.contains(&format!("orgSsoIdentifier={org}")),
            "under SSO_ONLY the invite must carry orgSsoIdentifier, or the person lands on a \
             master-password registration form they are forbidden to complete"
        );
    } else {
        assert!(!body.contains("orgSsoIdentifier"), "without SSO_ONLY the invite must not push the person at the IdP");
    }
}

// C10. Two IdP identities claiming the same verified address: the second is
// refused, and - the half that matters - the first is left entirely intact.
// A failed login attempt must not be able to damage an established binding.
#[rocket::async_test]
async fn a_second_identity_claiming_the_same_address_cannot_disturb_the_first() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_and_identity_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-sso-collision-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let payload = json!({
        "schemas": [scim::discovery::USER_SCHEMA_URN],
        "userName": "contested@example.com",
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created);

    let first = seed_sso_session(&conn, "contested@example.com", "first-claimant").await;
    let (status, _) = attempt_sso_login(&client, &first).await;
    assert_eq!(status, Status::Ok, "the first identity binds");
    let bound = User::find_by_mail("contested@example.com", &conn).await.expect("account");

    // A different subject asserts the same address.
    let second = seed_sso_session(&conn, "contested@example.com", "second-claimant").await;
    let (status, body) = attempt_sso_login(&client, &second).await;
    assert_eq!(status, Status::BadRequest, "the second identity must be refused");
    assert!(!body.contains("access_token"), "and issued no session");

    // The original binding survives untouched, and still works.
    let after = User::find_by_mail("contested@example.com", &conn).await.expect("account survives");
    assert_eq!(after.uuid, bound.uuid, "the refused attempt must not have replaced the account");
    let replay = seed_sso_session(&conn, "contested@example.com", "first-claimant-again").await;
    let mut row = crate::db::models::SsoAuth::find_by_code(&crate::sso::OIDCCode::from(replay.clone()), &conn)
        .await
        .expect("seeded row");
    if let Some(response) = row.auth_response.as_mut() {
        // Same subject as the original binding.
        response.identifier =
            crate::sso::OIDCIdentifier::from(String::from("http://sso.invalid/realms/test/first-claimant"));
    }
    row.save(&conn).await.expect("saving replay");
    let (status, _) = attempt_sso_login(&client, &replay).await;
    assert_eq!(status, Status::Ok, "the original identity must still be able to sign in afterwards");
}

// C13. Someone the IdP authenticated but SCIM never provisioned must not show up
// in the SCIM Users collection. If they did, Entra would see a member it has no
// source record for and could try to manage or deprovision an account outside
// its scope.
#[rocket::async_test]
async fn sso_created_accounts_are_invisible_to_the_scim_collection() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_and_identity_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-sso-invisible-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let code = seed_sso_session(&conn, "outsider@example.com", "outsider-subject").await;
    let (status, _) = attempt_sso_login(&client, &code).await;
    assert_eq!(status, Status::Ok, "the IdP vouched for them, so an account exists");
    assert!(User::find_by_mail("outsider@example.com", &conn).await.is_some(), "account really was created");

    // The collection is org-scoped, so an account with no membership is absent.
    let response = client.get(format!("/scim/v2/{org}/Users")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let listed: Value = serde_json::from_str(&response.into_string().await.expect("body")).expect("json");
    assert_eq!(listed["totalResults"], 0, "an account with no membership is not a SCIM resource");

    // And it is not addressable by filter either.
    let response = client
        .get(format!("/scim/v2/{org}/Users?filter=userName%20eq%20%22outsider@example.com%22"))
        .header(bearer(&token))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let filtered: Value = serde_json::from_str(&response.into_string().await.expect("body")).expect("json");
    assert_eq!(filtered["totalResults"], 0, "filtering by their address must not reveal them either");
}

// ---------------------------------------------------------------------------
// Suite H - protocol conformance.
//
// These assert the wire contract rather than behaviour: the shapes Microsoft's
// SCIM Validator and Entra's own client read. H1 (the hosted validator) needs a
// publicly reachable URL and stays manual; everything else is checkable here.
// ---------------------------------------------------------------------------

// H3. A client that follows `Location` and a client that follows
// `meta.location` must land on the same resource. They are produced by
// different code paths, so nothing but a test keeps them in agreement.
#[rocket::async_test]
async fn location_header_and_meta_location_agree_on_every_create() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-conformance-loc-org").await;
    let token = seed_scim_key(&conn, &org).await;

    // Users
    let payload = json!({
        "schemas": [scim::discovery::USER_SCHEMA_URN],
        "userName": "location.check@example.com",
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created);
    let header = response.headers().get_one("Location").map(str::to_owned);
    let created: Value = serde_json::from_str(&response.into_string().await.expect("body")).expect("json");

    let header = header.expect("RFC 7644 3.1 requires a Location header on 201");
    let meta = created["meta"]["location"].as_str().expect("meta.location must be present");
    assert_eq!(header, meta, "Location header and meta.location must be the same URI");
    assert!(
        header.ends_with(&format!("/Users/{}", created["id"].as_str().expect("id"))),
        "and must address the resource by id: {header}"
    );

    // Groups - the same contract, a different code path.
    let payload = json!({
        "schemas": [scim::discovery::GROUP_SCHEMA_URN],
        "displayName": "Location Check",
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Groups")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created);
    let header = response.headers().get_one("Location").map(str::to_owned);
    let created: Value = serde_json::from_str(&response.into_string().await.expect("body")).expect("json");

    let header = header.expect("Groups create must also carry Location");
    let meta = created["meta"]["location"].as_str().expect("meta.location must be present");
    assert_eq!(header, meta, "Location header and meta.location must agree for Groups too");
    assert!(
        header.ends_with(&format!("/Groups/{}", created["id"].as_str().expect("id"))),
        "and address it by id: {header}"
    );
}

// H4. RFC 7644 section 3.1 requires application/scim+json, and Entra reads the
// content type before it reads the body. Errors are the easy thing to get wrong
// because they take a different responder.
#[rocket::async_test]
async fn every_response_carries_the_scim_content_type_including_errors() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-conformance-ct-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let expected = rocket::http::ContentType::new("application", "scim+json");

    // 200 on a collection.
    let response = client.get(format!("/scim/v2/{org}/Users")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.content_type(), Some(expected.clone()), "list response");

    // 201 on a create.
    let payload = json!({"schemas": [scim::discovery::USER_SCHEMA_URN], "userName": "ct.check@example.com"});
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created);
    assert_eq!(response.content_type(), Some(expected.clone()), "create response");

    // 404 - a routed error.
    let response = client
        .get(format!("/scim/v2/{org}/Users/00000000-0000-0000-0000-000000000000"))
        .header(bearer(&token))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::NotFound);
    assert_eq!(response.content_type(), Some(expected.clone()), "404 error response");

    // 401 - produced before any handler runs.
    let response = client.get(format!("/scim/v2/{org}/Users")).header(bearer("not-a-real-token")).dispatch().await;
    assert_eq!(response.status(), Status::Unauthorized);
    assert_eq!(response.content_type(), Some(expected.clone()), "401 from the guard");

    // 400 - a malformed body, which goes through the FromData error path.
    let (auth, ct, _) = scim_body(&token, &json!({}));
    let response =
        client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body("{not json").dispatch().await;
    assert_eq!(response.status(), Status::BadRequest);
    assert_eq!(response.content_type(), Some(expected), "400 from malformed JSON");
}

// H5. `totalResults` counts the whole result set; `itemsPerPage` counts what was
// actually returned. Conflating them makes a client either stop paging early or
// page forever, and both look fine on a single small page.
#[rocket::async_test]
async fn list_response_counts_are_pre_and_post_pagination_respectively() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-conformance-page-org").await;
    let token = seed_scim_key(&conn, &org).await;

    for i in 0..5 {
        seed_member(&conn, &org, &format!("listpage{i}@example.com"), 2, MembershipType::User).await;
    }

    // A page smaller than the result set is where the two counts diverge.
    let response =
        client.get(format!("/scim/v2/{org}/Users?startIndex=1&count=2")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let page: Value = serde_json::from_str(&response.into_string().await.expect("body")).expect("json");

    assert_eq!(page["schemas"][0], "urn:ietf:params:scim:api:messages:2.0:ListResponse", "the envelope schema URN");
    assert_eq!(page["totalResults"], 5, "totalResults counts the whole set, before paging");
    assert_eq!(page["itemsPerPage"], 2, "itemsPerPage counts what this page actually returned");
    assert_eq!(page["startIndex"], 1, "startIndex echoes the 1-based request");
    assert_eq!(page["Resources"].as_array().expect("Resources").len(), 2, "and Resources agrees with itemsPerPage");

    // The last partial page: itemsPerPage shrinks, totalResults does not.
    let response =
        client.get(format!("/scim/v2/{org}/Users?startIndex=5&count=2")).header(bearer(&token)).dispatch().await;
    let tail: Value = serde_json::from_str(&response.into_string().await.expect("body")).expect("json");
    assert_eq!(tail["totalResults"], 5, "totalResults is unaffected by which page was asked for");
    assert_eq!(tail["itemsPerPage"], 1, "the final page returns the remainder");
    assert_eq!(tail["startIndex"], 5);

    // Past the end: still a valid envelope, not an error.
    let response =
        client.get(format!("/scim/v2/{org}/Users?startIndex=99&count=2")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::Ok, "paging past the end is not an error");
    let past: Value = serde_json::from_str(&response.into_string().await.expect("body")).expect("json");
    assert_eq!(past["totalResults"], 5);
    assert_eq!(past["itemsPerPage"], 0);
    assert_eq!(past["Resources"].as_array().expect("Resources").len(), 0, "an empty page, not a missing key");
}

// H7. Discovery is a promise. A client reads ServiceProviderConfig to decide
// what to attempt, so anything advertised there must actually work, and
// anything unsupported must not be advertised.
#[rocket::async_test]
async fn discovery_promises_match_what_the_implementation_does() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-conformance-disco-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let response = client.get(format!("/scim/v2/{org}/ServiceProviderConfig")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let config: Value = serde_json::from_str(&response.into_string().await.expect("body")).expect("json");

    // PATCH is advertised, so PATCH must work.
    assert_eq!(config["patch"]["supported"], true, "PATCH is the primary Entra deprovision path");
    let member = seed_member(&conn, &org, "disco@example.com", 2, MembershipType::User).await;
    let patch = json!({
        "schemas": [scim::patch::PATCH_OP_URN],
        "Operations": [{"op": "replace", "path": "active", "value": false}],
    });
    let (auth, ct, body) = scim_body(&token, &patch);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{member}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok, "advertised PATCH support must be real");

    // Filtering is advertised with a maxResults; both halves must hold.
    assert_eq!(config["filter"]["supported"], true);
    let max = config["filter"]["maxResults"].as_u64().expect("maxResults must be advertised");
    assert!(max > 0, "an advertised maxResults of 0 would tell a client not to bother");

    // Anything advertised as unsupported must not be silently implemented,
    // because a client that trusts discovery will never exercise it.
    for capability in ["bulk", "sort", "etag"] {
        let supported = config[capability]["supported"].as_bool();
        assert!(supported.is_some(), "{capability}.supported must be stated explicitly, not omitted");
    }
    assert_eq!(config["bulk"]["supported"], false, "bulk is not implemented");
    let response = client.post(format!("/scim/v2/{org}/Bulk")).header(bearer(&token)).dispatch().await;
    assert_ne!(response.status(), Status::Ok, "an unadvertised Bulk endpoint must not answer");
}

/// Reads (status, scimType) off an error response, asserting the RFC 7644
/// section 3.12 envelope is intact: Error schema URN present, and status
/// carried as a *string* rather than a number.
async fn error_envelope(response: LocalResponse<'_>) -> (u16, String) {
    let status = response.status().code;
    let body: Value = serde_json::from_str(&response.into_string().await.expect("body")).expect("json");
    assert_eq!(
        body["schemas"][0], "urn:ietf:params:scim:api:messages:2.0:Error",
        "every error must carry the Error schema URN"
    );
    assert_eq!(body["status"], json!(status.to_string()), "RFC 3.12 requires status as a string");
    (status, body["scimType"].as_str().unwrap_or_default().to_owned())
}

// H2. Every `scimType` the implementation emits, triggered over HTTP and
// checked against the status RFC 7644 section 3.12 assigns it. The existing
// unit test proves the envelope is built correctly; this proves the keywords
// actually reach the wire from a real request, with the right status, and that
// Entra can therefore distinguish "retry differently" from "give up".
#[rocket::async_test]
async fn every_emitted_scim_type_reaches_the_wire_with_its_rfc_status() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-conformance-types-org").await;
    let token = seed_scim_key(&conn, &org).await;

    // invalidSyntax - a body that is not valid JSON at all.
    let (auth, ct, _) = scim_body(&token, &json!({}));
    let response =
        client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body("{not json").dispatch().await;
    assert_eq!(error_envelope(response).await, (400, String::from("invalidSyntax")), "malformed JSON");

    // invalidValue - well-formed JSON missing a required attribute.
    let payload = json!({"schemas": [scim::discovery::USER_SCHEMA_URN]});
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(error_envelope(response).await, (400, String::from("invalidValue")), "missing userName");

    // uniqueness - provisioning the same person twice.
    let payload = json!({"schemas": [scim::discovery::USER_SCHEMA_URN], "userName": "dupe.types@example.com"});
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created);
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(
        error_envelope(response).await,
        (409, String::from("uniqueness")),
        "a duplicate is 409, the one status RFC 3.12 sanctions for scimType outside 400"
    );

    // invalidPath - a PATCH naming an attribute that cannot be addressed.
    let member = seed_member(&conn, &org, "types.patch@example.com", 2, MembershipType::User).await;
    let patch = json!({
        "schemas": [scim::patch::PATCH_OP_URN],
        "Operations": [{"op": "replace", "path": "!!not-a-path!!", "value": "x"}],
    });
    let (auth, ct, body) = scim_body(&token, &patch);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{member}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(error_envelope(response).await, (400, String::from("invalidPath")), "unparseable PATCH path");

    // noTarget - a remove whose filter selects nothing addressable.
    let patch = json!({
        "schemas": [scim::patch::PATCH_OP_URN],
        "Operations": [{"op": "remove"}],
    });
    let (auth, ct, body) = scim_body(&token, &patch);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{member}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(error_envelope(response).await, (400, String::from("noTarget")), "a remove with no path");

    // invalidFilter - a filter the parser rejects.
    let response = client
        .get(format!("/scim/v2/{org}/Users?filter=userName%20zz%20%22x%22"))
        .header(bearer(&token))
        .dispatch()
        .await;
    assert_eq!(error_envelope(response).await, (400, String::from("invalidFilter")), "unknown filter operator");

    // mutability - SCIM must never reinstate an administrator.
    let admin = seed_member(&conn, &org, "types.admin@example.com", -126, MembershipType::Admin).await;
    let patch = json!({
        "schemas": [scim::patch::PATCH_OP_URN],
        "Operations": [{"op": "replace", "path": "active", "value": true}],
    });
    let (auth, ct, body) = scim_body(&token, &patch);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{admin}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(
        error_envelope(response).await,
        (400, String::from("mutability")),
        "restoring a privileged membership is refused as immutable"
    );
}

// ---------------------------------------------------------------------------
// T5 - property / fuzz over the two hand-written parsers.
//
// Both take attacker-influenced strings straight off the wire: the filter
// parser from a query parameter, the PATCH path parser from a request body.
// Neither may panic, and neither may accept something it cannot faithfully
// represent - a parser that silently mis-parses a filter returns the wrong
// members, which is a data-disclosure bug rather than a parsing bug.
//
// The generator is a fixed-seed LCG rather than a fuzzing crate: no new
// dependency, and a failure reproduces exactly from the printed seed.
// ---------------------------------------------------------------------------

/// Deterministic PRNG. Numerical Recipes LCG constants; quality is irrelevant
/// here, reproducibility is the point.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        self.0 >> 16
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            usize::try_from(self.next() % n as u64).unwrap_or(0)
        }
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

/// Fragments chosen to sit near the parser's decision boundaries: the
/// whitespace splits, the quote handling, and the case-insensitive operator.
const FRAGMENTS: &[&str] = &[
    "userName",
    "USERNAME",
    "externalId",
    "displayName",
    "",
    " ",
    "  ",
    "\t",
    "\n",
    "eq",
    "EQ",
    "Eq",
    "ne",
    "co",
    "sw",
    "\"",
    "\"\"",
    "\"x\"",
    "\"a b\"",
    "\"\\\"\"",
    "and",
    "or",
    "(",
    ")",
    "[",
    "]",
    "value",
    "members",
    "0",
    "-1",
    "null",
    "true",
    "\0",
    "é",
    "🙂",
    "%22",
    "\\",
    "'",
    "`",
    ";",
    "--",
];

// The filter parser must return Ok or Err for every input, never panic, and
// every Ok must round-trip: the attribute it reports must be the lowercased
// attribute actually present, and the value must be what was between the
// quotes. A parser that accepts `a eq "x" or 1=1` and reports attribute `a`
// would be silently dropping the injected tail.
#[test]
fn filter_parser_never_panics_and_never_mis_parses() {
    let mut rng = Lcg(0x5EED_1234);
    let mut accepted = 0_u32;

    for iteration in 0..20_000 {
        let parts = 1 + rng.below(6);
        let mut input = String::new();
        for _ in 0..parts {
            input.push_str(rng.pick(FRAGMENTS));
            if rng.below(3) == 0 {
                input.push(' ');
            }
        }

        // The contract: a Result, for any input, without unwinding.
        match scim::filter::parse_eq_filter(&input) {
            Err(error) => {
                assert_eq!(error.status, Status::BadRequest, "iteration {iteration}: input {input:?}");
                assert_eq!(error.scim_type, Some("invalidFilter"), "iteration {iteration}: input {input:?}");
            }
            Ok(filter) => {
                accepted += 1;
                assert_eq!(
                    filter.attribute,
                    filter.attribute.to_lowercase(),
                    "iteration {iteration}: attribute must be normalised, input {input:?}"
                );
                assert!(
                    !filter.attribute.is_empty(),
                    "iteration {iteration}: an empty attribute would match nothing meaningful, input {input:?}"
                );
                // Whatever was accepted must actually appear in the input, in
                // the order claimed - the guard against a parser inventing or
                // dropping content.
                let lowered = input.to_lowercase();
                let at = lowered.find(&filter.attribute).expect("attribute must come from the input");
                assert!(
                    lowered[at..].contains(" eq") || lowered[at..].contains("\teq") || lowered[at..].contains("\neq"),
                    "iteration {iteration}: accepted without an eq operator, input {input:?}"
                );
                assert!(
                    input.contains(&filter.value) || filter.value.is_empty(),
                    "iteration {iteration}: value {:?} not present in input {input:?}",
                    filter.value
                );
            }
        }
    }

    // If the generator stopped producing anything parseable the test would be
    // vacuously green, so require that it still exercises the accept path.
    assert!(accepted > 0, "the corpus no longer reaches the accepting branch; the test proves nothing");
}

/// Fragments aimed at the PATCH path parser's boundaries: bracket matching,
/// quoting, and the `members[value eq "..."]` form Entra actually sends.
const PATH_FRAGMENTS: &[&str] = &[
    "members",
    "MEMBERS",
    "[",
    "]",
    "value",
    "eq",
    "\"",
    "\"abc\"",
    "displayName",
    "active",
    ".",
    "..",
    "",
    " ",
    "externalId",
    "emails[type",
    "value]",
    "\0",
    "🙂",
    "%5B",
    "\\",
];

// The PATCH path parser feeds group membership changes. Its failure mode is
// worse than the filter's: `parse_members_filter_path` returning the wrong
// member id removes the wrong person from a group.
#[test]
fn patch_path_parser_never_panics_on_arbitrary_paths() {
    let mut rng = Lcg(0xC0FF_EE01);

    for iteration in 0..20_000 {
        let parts = 1 + rng.below(6);
        let mut path = String::new();
        for _ in 0..parts {
            path.push_str(rng.pick(PATH_FRAGMENTS));
        }

        let op = json!({
            "schemas": [scim::patch::PATCH_OP_URN],
            "Operations": [{
                "op": rng.pick(&["add", "remove", "replace", "ADD", "Remove", "bogus"]),
                "path": path,
                "value": rng.pick(&[json!("x"), json!(null), json!([]), json!({"value": "y"}), json!(true)]),
            }],
        });

        // Deserialising is part of the surface: a body that fails to
        // deserialise is fine, but it must not panic either.
        let Ok(parsed) = serde_json::from_value::<scim::patch::PatchOp>(op) else {
            continue;
        };

        // Both parsers must answer, not unwind. Any Ok must be self-consistent.
        if let Ok(group_patch) = scim::patch::parse_group_patch(&parsed) {
            assert!(
                group_patch.member_count() < 10_000,
                "iteration {iteration}: implausible member count from path {path:?}"
            );
        }
        // Must answer rather than unwind; the value itself is not the point.
        drop(scim::patch::parse_user_patch(&parsed));
    }
}

// H5 (partial) - rate limiter RECOVERY.
//
// `rate_limiter_returns_429_when_drained` proves the limiter trips. The more
// dangerous failure is the opposite one: a limiter that trips and never resets
// locks a tenant out of provisioning permanently, and a sync that stays 429
// forever looks identical to a limiter working as intended.
//
// The full H5 injectable clock was NOT built. `governor` keeps its clock in the
// LazyLock statics in ratelimit.rs, so injecting a fake one means making the
// production types generic and swapping a static at runtime - a real change to
// shipping code for test-only benefit. The test environment already pins
// SCIM_RATELIMIT_SECONDS=1, so the window can simply be waited out instead.
// The cost is one second of wall clock, paid once.
#[rocket::async_test]
async fn the_rate_limiter_recovers_once_its_window_passes() {
    // A dedicated synthetic IP: draining a bucket must not disturb the shared
    // one every other HTTP test draws from.
    let ip: std::net::IpAddr = "10.99.99.98".parse().expect("test ip");
    let burst = crate::CONFIG.scim_ratelimit_max_burst();

    let mut drained = false;
    for _ in 0..=burst {
        if crate::ratelimit::check_limit_scim(&ip).is_err() {
            drained = true;
            break;
        }
    }
    assert!(drained, "limiter never tripped after {burst} + 1 requests; cannot test recovery");

    // Still refused immediately afterwards - otherwise the wait below would
    // prove nothing about the window.
    assert!(crate::ratelimit::check_limit_scim(&ip).is_err(), "must still be limited immediately after draining");

    // Polled rather than asserted once after a fixed sleep. governor replenishes
    // against real elapsed time, so a single sleep-then-assert is a race with
    // whatever else the machine is doing - and the failure mode is a flake in
    // the one test whose whole point is that a throttled tenant recovers.
    // The loop exits as soon as the window has actually passed, so the common
    // case stays as fast as the old fixed sleep.
    let period = crate::CONFIG.scim_ratelimit_seconds().max(1);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(period * 5 + 2);
    let mut recovered = false;
    while std::time::Instant::now() < deadline {
        if crate::ratelimit::check_limit_scim(&ip).is_ok() {
            recovered = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    assert!(
        recovered,
        "the limiter must admit traffic again after its {period}s window, or a throttled tenant \
         never recovers without a restart"
    );
}

// ---------------------------------------------------------------------------
// Suite H - regressions pinned from the security, data-migration, performance
// and API-contract review passes.
//
// Every test here corresponds to a defect that shipped on this branch and was
// fixed. They exist so the same mistake is loud next time rather than silent.
// ---------------------------------------------------------------------------

// Minting the SCIM credential is an Owner action, not an admin one.
//
// A SCIM token can revoke any member that is not the last active Owner,
// while the web vault refuses an Admin revoking an Owner outright ("Only owners
// can revoke other owners"). AdminHeaders resolves for Admin and Owner alike, so
// gating the mint on admin let an Admin issue itself a credential that did what
// its own session was denied - and reject_privileged_grant then stopped SCIM
// putting the Owner back afterwards.
#[rocket::async_test]
async fn only_an_owner_can_mint_or_revoke_the_scim_credential() {
    let _guard = TEST_LOCK.lock().await;
    let (manage, pool) = manage_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-owner-gate-org").await;

    let owner = seed_admin_session(&conn, &org, "gate.owner@example.com", MembershipType::Owner).await;

    for atype in [MembershipType::Admin, MembershipType::Manager] {
        let label = atype as i32;
        let session = seed_admin_session(&conn, &org, &format!("gate.{label}@example.com"), atype).await;

        let (ct, body) = password_body(&json!({"masterPasswordHash": ADMIN_PASSWORD}));
        let response = manage
            .post(format!("/api/organizations/{org}/scim/api-key"))
            .header(session.clone())
            .header(ct)
            .body(body)
            .dispatch()
            .await;
        assert_ne!(
            response.status(),
            Status::Ok,
            "membership type {label} must not mint a credential that can revoke an Owner"
        );

        let (ct, body) = password_body(&json!({"masterPasswordHash": ADMIN_PASSWORD}));
        let response = manage
            .delete(format!("/api/organizations/{org}/scim/api-key"))
            .header(session)
            .header(ct)
            .body(body)
            .dispatch()
            .await;
        assert_ne!(response.status(), Status::Ok, "membership type {label} must not revoke the credential");
    }

    assert!(ScimApiKey::find_by_org(&org, &conn).await.is_none(), "a refused mint must not leave a key behind");

    let (ct, body) = password_body(&json!({"masterPasswordHash": ADMIN_PASSWORD}));
    let response = manage
        .post(format!("/api/organizations/{org}/scim/api-key"))
        .header(owner)
        .header(ct)
        .body(body)
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok, "an Owner must still be able to mint");
    assert!(ScimApiKey::find_by_org(&org, &conn).await.is_some());
}

// Rotation must overwrite the stored digest, never leave the previous one live.
//
// mint_scim_token builds a row with a FRESH uuid every time, so the upsert's
// update fallback keyed on uuid matched nothing: it affected no rows, reported
// success, and left the old key_hash in place. The admin was handed a token that
// could not authenticate while the token they meant to revoke still could - a
// rotation that silently does not revoke. sqlite reaches the row through
// replace_into; the update fallback is a MySQL path, which is why this test is
// part of the all-backends run (tools/scim-test-backends.sh).
#[rocket::async_test]
async fn every_rotation_overwrites_the_stored_digest() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-rotation-digest-org").await;

    let mut issued: Vec<String> = Vec::new();
    for round in 0..3 {
        let token = seed_scim_key(&conn, &org).await;

        let stored = ScimApiKey::find_by_org(&org, &conn).await.expect("a key row must exist after minting");
        let secret = token.rsplit('.').next().expect("token secret");
        assert!(
            stored.check_valid_secret(secret),
            "round {round}: the stored digest must match the secret just issued, not a previous one"
        );

        let response =
            client.get(format!("/scim/v2/{org}/ServiceProviderConfig")).header(bearer(&token)).dispatch().await;
        assert_eq!(response.status(), Status::Ok, "round {round}: the current token must authenticate");

        for (earlier, old) in issued.iter().enumerate() {
            let response =
                client.get(format!("/scim/v2/{org}/ServiceProviderConfig")).header(bearer(old)).dispatch().await;
            assert_eq!(
                response.status(),
                Status::Unauthorized,
                "round {round}: the token from round {earlier} must not survive rotation"
            );
        }
        issued.push(token);
    }
}

// Unlinking a privileged membership from the directory is the OPPOSITE of a
// grant, so it must be allowed even though linking one is refused.
//
// Blocking it left Entra re-sending a write it could never satisfy, and a
// permanently failing attribute write eventually quarantines the whole
// application - taking deprovisioning, the highest-value path here, down with it.
#[rocket::async_test]
async fn a_privileged_member_can_be_unlinked_but_not_linked() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-unlink-org").await;
    let token = seed_scim_key(&conn, &org).await;
    seed_member(&conn, &org, "unlink.spare.owner@example.com", 2, MembershipType::Owner).await;

    // Distinct from the "promoted@example.com" used by
    // promoting_a_member_makes_it_grant_immune_but_still_deprovisionable:
    // users.email is globally UNIQUE and User::save upserts on uuid, not
    // email, so a shared address makes whichever test runs second panic in
    // seed_user. That it passed at all depended on libtest's alphabetical
    // ordering, which a rename or a shuffled run would have broken.
    let member = seed_member(&conn, &org, "unlink.promoted@example.com", 2, MembershipType::Owner).await;
    // The realistic shape: SCIM provisioned and linked this person while they
    // were an ordinary member, then a human promoted them in the web vault, so
    // the link predates the privilege and is already on the row.
    let mut row = Membership::find_by_uuid_and_org(&member, &org, &conn).await.expect("row");
    row.set_external_id(Some(String::from("entra-promoted-1")));
    row.save(&conn).await.expect("linking");

    let relink = json!({
        "schemas": [scim::patch::PATCH_OP_URN],
        "Operations": [{"op": "replace", "path": "externalId", "value": "entra-promoted-2"}],
    });
    let unlink = json!({
        "schemas": [scim::patch::PATCH_OP_URN],
        "Operations": [{"op": "remove", "path": "externalId"}],
    });

    // Re-linking to a different directory object is still a grant: refused.
    let (auth, ct, body) = scim_body(&token, &relink);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{member}")).header(auth).header(ct).body(body).dispatch().await;
    assert_privileged_refusal(response, "patch externalId", MembershipType::Owner as i32).await;
    let stored = Membership::find_by_uuid_and_org(&member, &org, &conn).await.expect("row");
    assert_eq!(stored.external_id.as_deref(), Some("entra-promoted-1"), "a refused re-link must not partly apply");

    // Removing it succeeds and actually clears the column.
    let (auth, ct, body) = scim_body(&token, &unlink);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{member}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok, "unlinking a privileged member must be allowed");
    let stored = Membership::find_by_uuid_and_org(&member, &org, &conn).await.expect("row");
    assert_eq!(stored.external_id, None, "remove externalId must clear the column");

    // Repeating it is a no-op, not an error: Entra retries.
    let (auth, ct, body) = scim_body(&token, &unlink);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{member}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok, "a repeated unlink must stay idempotent");

    // The grant direction is still closed after the unlink.
    let (auth, ct, body) = scim_body(&token, &relink);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{member}")).header(auth).header(ct).body(body).dispatch().await;
    assert_privileged_refusal(response, "patch externalId after unlink", MembershipType::Owner as i32).await;
}

// Paging must cover the organization exactly once.
//
// The list endpoints used to load every row and slice in memory with no ORDER
// BY. A client pages by issuing separate requests, so each page was its own
// unordered query: on PostgreSQL an UPDATE relocates a row and changes scan
// order, and a concurrent revoke IS an UPDATE, so a member could appear on two
// pages or on none and a full sync would silently skip them.
#[rocket::async_test]
async fn user_paging_covers_every_member_exactly_once() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-paging-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let mut expected: std::collections::HashSet<String> = std::collections::HashSet::new();
    for n in 0..25 {
        let member = seed_member(&conn, &org, &format!("page.{n}@example.com"), 2, MembershipType::User).await;
        expected.insert(member.to_string());
    }

    let mut seen: Vec<String> = Vec::new();
    let mut start = 1;
    loop {
        let response = client
            .get(format!("/scim/v2/{org}/Users?startIndex={start}&count=10"))
            .header(bearer(&token))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let parsed = parse_json(&body_of(response).await);
        assert_eq!(
            parsed["totalResults"],
            json!(expected.len()),
            "totalResults must count the whole organization, not the page"
        );
        let page = parsed["Resources"].as_array().expect("Resources").clone();
        if page.is_empty() {
            break;
        }
        for resource in &page {
            seen.push(resource["id"].as_str().expect("id").to_owned());
        }
        start += 10;
    }

    let unique: std::collections::HashSet<String> = seen.iter().cloned().collect();
    assert_eq!(seen.len(), expected.len(), "paging must not skip or repeat a member");
    assert_eq!(unique, expected, "every member must appear exactly once across the pages");
}

// The served schema must describe what the handlers actually accept.
//
// Declaring an attribute readOnly tells a schema-driven client (Okta, OneLogin,
// Microsoft's SCIM Validator, Entra's discovery step) never to send it. That was
// fatal for userName, which post_user REQUIRES, and for emails[], which is the
// only address a tenant mapping into emails rather than userName ever sends.
#[rocket::async_test]
async fn served_schemas_describe_what_the_handlers_accept() {
    const MUTABILITY: [&str; 4] = ["readOnly", "readWrite", "immutable", "writeOnly"];
    const RETURNED: [&str; 4] = ["always", "never", "default", "request"];
    const UNIQUENESS: [&str; 3] = ["none", "server", "global"];
    // Attributes the POST/PUT handlers read out of the request body.
    const CLIENT_SUPPLIED: [&str; 5] = ["userName", "displayName", "name", "emails", "active"];

    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-schema-contract-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let response = client.get(format!("/scim/v2/{org}/Schemas")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let parsed = parse_json(&body_of(response).await);
    let resources = parsed["Resources"].as_array().expect("Resources").clone();
    assert!(!resources.is_empty(), "at least the User schema must be served");

    let mut client_supplied_seen = 0;
    for schema in &resources {
        let attributes = schema["attributes"].as_array().expect("attributes");
        assert!(!attributes.is_empty(), "schema {} must describe its attributes", schema["id"]);
        for attribute in attributes {
            let name = attribute["name"].as_str().expect("name");
            // externalId is a COMMON attribute (RFC 7643 section 3.1), present
            // on every resource and not part of any schema definition.
            assert_ne!(name, "externalId", "externalId is a common attribute, not a schema-defined one");
            for key in [
                "name",
                "type",
                "multiValued",
                "description",
                "required",
                "caseExact",
                "mutability",
                "returned",
                "uniqueness",
            ] {
                assert!(attribute.get(key).is_some(), "{name} is missing the RFC 7643 section 7 key {key}");
            }
            let mutability = attribute["mutability"].as_str().expect("mutability");
            assert!(MUTABILITY.contains(&mutability), "{name} has a non-canonical mutability {mutability}");
            assert!(RETURNED.contains(&attribute["returned"].as_str().expect("returned")), "{name} returned");
            assert!(UNIQUENESS.contains(&attribute["uniqueness"].as_str().expect("uniqueness")), "{name} uniqueness");
            if CLIENT_SUPPLIED.contains(&name) {
                assert_ne!(
                    mutability, "readOnly",
                    "{name} is read from the request body, so a conforming client must be allowed to send it"
                );
                client_supplied_seen += 1;
            }
        }
    }
    assert!(
        client_supplied_seen >= CLIENT_SUPPLIED.len(),
        "every client-supplied attribute must appear in the served schema"
    );
}

// Everything discovery advertises as a meta.location must actually resolve.
// RFC 7644 section 4 defines /ResourceTypes/{id} and /Schemas/{id} as
// retrievable; without handlers, every location the collections advertise 404s.
#[rocket::async_test]
async fn advertised_discovery_locations_resolve() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-discovery-location-org").await;
    let token = seed_scim_key(&conn, &org).await;

    for collection in ["ResourceTypes", "Schemas"] {
        let response = client.get(format!("/scim/v2/{org}/{collection}")).header(bearer(&token)).dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        let parsed = parse_json(&body_of(response).await);
        for resource in parsed["Resources"].as_array().expect("Resources") {
            let location = resource["meta"]["location"].as_str().expect("meta.location");
            let path = location.split("/scim").nth(1).expect("location must be under /scim");
            let response = client.get(format!("/scim{path}")).header(bearer(&token)).dispatch().await;
            assert_eq!(response.status(), Status::Ok, "advertised location {location} must resolve");
            let fetched = parse_json(&body_of(response).await);
            assert_eq!(fetched["id"], resource["id"], "{location} must return the resource it was advertised for");
        }
    }

    // An unknown id inside a real collection is a SCIM 404, not an HTML one.
    let response =
        client.get(format!("/scim/v2/{org}/ResourceTypes/NotAResource")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::NotFound);
    assert_eq!(parse_json(&body_of(response).await)["schemas"][0], json!(SCIM_ERROR_URN));
}

// Asserts one refused oversized member list.
//
// The scimType is invalidValue, NOT tooMany: RFC 7644 section 3.12 defines
// tooMany as a FILTER keyword, so a client branching on it would retry with a
// narrower filter, which never fixes an oversized request body.
async fn assert_member_cap_refusal(response: LocalResponse<'_>, what: &str) {
    assert_eq!(response.status(), Status::BadRequest, "{what} must refuse an oversized member list");
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["scimType"], json!("invalidValue"), "{what} scimType");
}

// The oversized-member-list guard, on all three write paths.
//
// PATCH sums across operations, so a body split into several ops still trips the
// cap - that distinction is the whole point of GroupPatch::member_count.
#[rocket::async_test]
async fn oversized_member_lists_are_refused_on_every_write_path() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-member-cap-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let over: Vec<Value> = (0..=scim::SCIM_MAX_GROUP_MEMBERS).map(|n| json!({"value": format!("m-{n}")})).collect();

    let payload = json!({
        "schemas": [scim::discovery::GROUP_SCHEMA_URN],
        "displayName": "Too Big",
        "members": over,
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Groups")).header(auth).header(ct).body(body).dispatch().await;
    assert_member_cap_refusal(response, "POST").await;

    // A real group to aim PUT and PATCH at.
    let payload = json!({"schemas": [scim::discovery::GROUP_SCHEMA_URN], "displayName": "Cap Target"});
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Groups")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created);
    let group = parse_json(&body_of(response).await)["id"].as_str().expect("id").to_owned();

    let payload = json!({
        "schemas": [scim::discovery::GROUP_SCHEMA_URN],
        "displayName": "Cap Target",
        "members": over,
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response =
        client.put(format!("/scim/v2/{org}/Groups/{group}")).header(auth).header(ct).body(body).dispatch().await;
    assert_member_cap_refusal(response, "PUT").await;

    // Split across two operations, each individually under the cap, summing over.
    let half = scim::SCIM_MAX_GROUP_MEMBERS / 2 + 1;
    let chunk: Vec<Value> = (0..half).map(|n| json!({"value": format!("m-{n}")})).collect();
    let payload = json!({
        "schemas": [scim::patch::PATCH_OP_URN],
        "Operations": [
            {"op": "add", "path": "members", "value": chunk},
            {"op": "add", "path": "members", "value": chunk},
        ],
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response =
        client.patch(format!("/scim/v2/{org}/Groups/{group}")).header(auth).header(ct).body(body).dispatch().await;
    assert_member_cap_refusal(response, "PATCH summed across operations").await;

    // Exactly at the cap gets past the guard and fails later, on resolution -
    // proving the boundary is inclusive rather than off by one.
    let at_cap: Vec<Value> = (0..scim::SCIM_MAX_GROUP_MEMBERS).map(|n| json!({"value": format!("m-{n}")})).collect();
    let payload = json!({
        "schemas": [scim::discovery::GROUP_SCHEMA_URN],
        "displayName": "At Cap",
        "members": at_cap,
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Groups")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::BadRequest);
    let parsed = parse_json(&body_of(response).await);
    assert!(
        parsed["detail"].as_str().expect("detail").contains("existing members"),
        "a list exactly at the cap must reach member resolution, not be refused by the cap"
    );
}

// displayName is required on a Group, so a PATCH clearing it is an error rather
// than a silently ignored no-op that still returns 200 - the client would record
// the change as applied and never retry.
#[rocket::async_test]
async fn a_group_display_name_cannot_be_cleared() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-group-name-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let payload = json!({"schemas": [scim::discovery::GROUP_SCHEMA_URN], "displayName": "Keeps Its Name"});
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Groups")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created);
    let group = parse_json(&body_of(response).await)["id"].as_str().expect("id").to_owned();

    for operation in [
        json!({"op": "replace", "path": "displayName", "value": ""}),
        json!({"op": "replace", "path": "displayName", "value": "   "}),
        json!({"op": "remove", "path": "displayName"}),
    ] {
        let payload = json!({"schemas": [scim::patch::PATCH_OP_URN], "Operations": [operation.clone()]});
        let (auth, ct, body) = scim_body(&token, &payload);
        let response =
            client.patch(format!("/scim/v2/{org}/Groups/{group}")).header(auth).header(ct).body(body).dispatch().await;
        assert_eq!(response.status(), Status::BadRequest, "clearing displayName via {operation} must be refused");
        assert_eq!(parse_json(&body_of(response).await)["scimType"], json!("invalidValue"));
    }

    let stored = Group::find_by_uuid_and_org(&group.clone().into(), &org, &conn).await.expect("group");
    assert_eq!(stored.name, "Keeps Its Name", "a refused rename must not partly apply");
}

// A throttled request must surface as a SCIM 429 with a usable Retry-After.
//
// The limiter is drained in-process for a dedicated synthetic IP so the shared
// limiter every other test runs through is untouched; ClientIp reads X-Real-IP
// (the CONFIG.ip_header default), so the dispatched request is attributed to it.
#[rocket::async_test]
async fn a_throttled_request_gets_a_scim_429_with_retry_after() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-429-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let ip: std::net::IpAddr = "10.99.99.77".parse().expect("test ip");
    for _ in 0..=crate::CONFIG.scim_ratelimit_max_burst() {
        if crate::ratelimit::check_limit_scim(&ip).is_err() {
            break;
        }
    }

    let response = client
        .get(format!("/scim/v2/{org}/ServiceProviderConfig"))
        .header(bearer(&token))
        .header(Header::new("X-Real-IP", "10.99.99.77"))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::TooManyRequests, "a drained limiter must surface as 429, not 401");

    let retry_after = response.headers().get_one("Retry-After").map(str::to_owned);
    let content_type = response.headers().get_one("Content-Type").map(str::to_owned);
    let parsed = parse_json(&body_of(response).await);

    let expected = crate::CONFIG.scim_ratelimit_seconds().max(1).to_string();
    assert_eq!(
        retry_after.as_deref(),
        Some(expected.as_str()),
        "a throttled client needs somewhere to start backing off from"
    );
    assert!(
        content_type.is_some_and(|ct| ct.starts_with(SCIM_CONTENT_TYPE)),
        "a 429 must still be application/scim+json"
    );
    assert_eq!(parsed["schemas"][0], json!(SCIM_ERROR_URN));
    assert_eq!(parsed["status"], json!("429"), "status must be a string per RFC 7644 section 3.12");
}

// The server-wide signup gates, on their DENIED side.
//
// post_user applies INVITATIONS_ALLOWED and the domain allowlist because an
// Invitation row is a hard override of is_signup_allowed at registration - so
// skipping them would turn an org-scoped SCIM token into a server-wide signup
// bypass. The hermetic environment pins both permissive and CONFIG is a
// LazyLock, so the enforcing side was unreachable until scim::test_config grew
// an override for each. That made this a security guard with no proof it held.
#[rocket::async_test]
async fn the_signup_gates_refuse_new_accounts_and_write_nothing() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-signup-gate-org").await;
    let token = seed_scim_key(&conn, &org).await;

    // The guard is built INSIDE the loop, one gate at a time. Constructing both
    // in the array literal - which this test used to do - evaluates both
    // elements before the iterator yields the first, so iteration 1 ran with
    // INVITATIONS_ALLOWED=false AND EMAIL_DOMAIN_ALLOWED=false simultaneously.
    // Since either gate produces the identical 400/invalidValue, deleting the
    // invitations check outright would have left this test green: it proved
    // "at least one of two gates fires", not "each gate fires".
    for (label, gate_invitations, email) in [
        ("invitations disabled", true, "gate.invites@example.com"),
        ("domain not allowed", false, "gate.domain@example.com"),
    ] {
        let _override_guard = if gate_invitations {
            scim::test_config::invitations_allowed(false)
        } else {
            scim::test_config::email_domain_allowed(false)
        };
        let payload = json!({
            "schemas": [scim::discovery::USER_SCHEMA_URN],
            "userName": email,
            "active": true,
        });
        let (auth, ct, body) = scim_body(&token, &payload);
        let response = client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body(body).dispatch().await;

        assert_eq!(response.status(), Status::BadRequest, "{label} must refuse a brand-new account");
        assert_eq!(parse_json(&body_of(response).await)["scimType"], json!("invalidValue"), "{label}");

        // Nothing may be left behind. An orphan User plus an Invitation row is
        // exactly the registration bypass these gates exist to prevent.
        assert!(User::find_by_mail(email, &conn).await.is_none(), "{label} must not create a user");
        assert!(
            Membership::find_by_email_and_org(email, &org, &conn).await.is_none(),
            "{label} must not create a membership"
        );
    }

    // With both gates permissive again, the same request succeeds - proving the
    // refusals above came from the gates and not from something else.
    let payload = json!({
        "schemas": [scim::discovery::USER_SCHEMA_URN],
        "userName": "gate.allowed@example.com",
        "active": true,
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created, "the gates must not refuse when both are permissive");
}

// Usage visibility for the credential: an operator needs to tell a live key
// from a stale one, and the only available signal is whether it is still
// authenticating requests.
#[rocket::async_test]
async fn key_usage_is_recorded_and_reset_on_rotation() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-lastused-org").await;
    let token = seed_scim_key(&conn, &org).await;

    // A freshly minted key has never been used.
    let stored = ScimApiKey::find_by_org(&org, &conn).await.expect("key");
    assert_eq!(stored.last_used_at, None, "a key that has never authenticated must report no usage");

    let response = client.get(format!("/scim/v2/{org}/ServiceProviderConfig")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    let used = ScimApiKey::find_by_org(&org, &conn).await.expect("key").last_used_at;
    assert!(used.is_some(), "a successful SCIM request must record usage");

    // Rotation must clear it: carrying the previous key's timestamp forward
    // would make a brand-new, never-used credential look actively in use.
    let rotated = seed_scim_key(&conn, &org).await;
    assert_ne!(rotated, token);
    assert_eq!(
        ScimApiKey::find_by_org(&org, &conn).await.expect("key").last_used_at,
        None,
        "rotation must reset usage, or a dead token's activity is attributed to the new one"
    );
}

// A failed authentication must not record usage - otherwise the field an
// operator reads to spot a stale key can be kept warm by an attacker guessing
// against it.
#[rocket::async_test]
async fn a_rejected_request_does_not_record_usage() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-lastused-reject-org").await;
    let _token = seed_scim_key(&conn, &org).await;

    let wrong = format!("scim_v1.{org}.not-the-right-secret");
    let response = client.get(format!("/scim/v2/{org}/ServiceProviderConfig")).header(bearer(&wrong)).dispatch().await;
    assert_eq!(response.status(), Status::Unauthorized);

    assert_eq!(
        ScimApiKey::find_by_org(&org, &conn).await.expect("key").last_used_at,
        None,
        "a rejected credential must not leave a usage trace"
    );
}

// The reversible kill switch. Deleting the key also stops provisioning, but it
// destroys the digest and forces a new token into the IdP; disabling stops it
// now and resumes without touching Entra.
#[rocket::async_test]
async fn the_key_can_be_disabled_and_re_enabled_without_rotating() {
    let _guard = TEST_LOCK.lock().await;
    let (manage, pool) = manage_client().await;
    let (scim_api, _) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-killswitch-org").await;
    let owner = seed_admin_session(&conn, &org, "killswitch.owner@example.com", MembershipType::Owner).await;
    let token = seed_scim_key(&conn, &org).await;

    let response =
        scim_api.get(format!("/scim/v2/{org}/ServiceProviderConfig")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::Ok, "the token must work before it is disabled");

    // Disable.
    let (ct, body) = password_body(&json!({"masterPasswordHash": ADMIN_PASSWORD, "enabled": false}));
    let response = manage
        .put(format!("/api/organizations/{org}/scim/api-key/enabled"))
        .header(owner.clone())
        .header(ct)
        .body(body)
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok, "an Owner must be able to disable the key");
    assert_eq!(parse_json(&body_of(response).await)["keyEnabled"], json!(false));

    let response =
        scim_api.get(format!("/scim/v2/{org}/ServiceProviderConfig")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::Unauthorized, "a disabled key must stop authenticating at once");
    // The digest survives, which is the whole point of disable-over-delete.
    assert!(ScimApiKey::find_by_org(&org, &conn).await.is_some(), "disabling must not destroy the key row");

    // Re-enable.
    let (ct, body) = password_body(&json!({"masterPasswordHash": ADMIN_PASSWORD, "enabled": true}));
    let response = manage
        .put(format!("/api/organizations/{org}/scim/api-key/enabled"))
        .header(owner)
        .header(ct)
        .body(body)
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);

    let response =
        scim_api.get(format!("/scim/v2/{org}/ServiceProviderConfig")).header(bearer(&token)).dispatch().await;
    assert_eq!(
        response.status(),
        Status::Ok,
        "re-enabling must restore the SAME token, so the IdP never needs re-configuring"
    );
}

// The kill switch is an Owner action, like minting and deleting.
#[rocket::async_test]
async fn a_non_owner_cannot_disable_the_key() {
    let _guard = TEST_LOCK.lock().await;
    let (manage, pool) = manage_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-killswitch-authz-org").await;
    seed_admin_session(&conn, &org, "ks.owner@example.com", MembershipType::Owner).await;
    seed_scim_key(&conn, &org).await;

    for atype in [MembershipType::Admin, MembershipType::User] {
        let label = atype as i32;
        let session = seed_admin_session(&conn, &org, &format!("ks.{label}@example.com"), atype).await;
        let (ct, body) = password_body(&json!({"masterPasswordHash": ADMIN_PASSWORD, "enabled": false}));
        let response = manage
            .put(format!("/api/organizations/{org}/scim/api-key/enabled"))
            .header(session)
            .header(ct)
            .body(body)
            .dispatch()
            .await;
        assert_ne!(response.status(), Status::Ok, "membership type {label} must not toggle the credential");
    }

    assert!(
        ScimApiKey::find_by_org(&org, &conn).await.expect("key").enabled,
        "a refused toggle must leave the key enabled"
    );
}

// ---------------------------------------------------------------------------
// Coverage added by the 2026-07-26 /review + /cso pass.
// ---------------------------------------------------------------------------

/// PUT must refuse a blank displayName exactly like PATCH does.
///
/// PUT used to filter a blank name out and return 200 with the old name still
/// in place. That is the precise failure the PATCH guard's comment argues
/// against: the client records the rename as applied and never retries, so the
/// directory and the vault disagree permanently. PUT is also the only endpoint
/// Entra uses for full replacement, so it was the half that mattered.
#[rocket::async_test]
async fn group_put_refuses_a_blank_display_name() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-put-blankname-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let create = json!({
        "schemas": [scim::discovery::GROUP_SCHEMA_URN],
        "displayName": "Keep This Name",
        "externalId": "put-blankname-1",
    });
    let (auth, ct, body) = scim_body(&token, &create);
    let response = client.post(format!("/scim/v2/{org}/Groups")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created);
    let group_id = parse_json(&body_of(response).await)["id"].as_str().expect("group id").to_owned();

    for blank in ["", "   ", "\t"] {
        let put = json!({
            "schemas": [scim::discovery::GROUP_SCHEMA_URN],
            "displayName": blank,
        });
        let (auth, ct, body) = scim_body(&token, &put);
        let response =
            client.put(format!("/scim/v2/{org}/Groups/{group_id}")).header(auth).header(ct).body(body).dispatch().await;
        assert_eq!(response.status(), Status::BadRequest, "PUT displayName {blank:?} must be refused");
        assert_eq!(parse_json(&body_of(response).await)["scimType"], json!("invalidValue"), "{blank:?}");
    }

    // Omitting the attribute entirely is a different thing and still means
    // "leave the name alone" - that is what makes a sparse PUT safe.
    let put = json!({"schemas": [scim::discovery::GROUP_SCHEMA_URN], "externalId": "put-blankname-1"});
    let (auth, ct, body) = scim_body(&token, &put);
    let response =
        client.put(format!("/scim/v2/{org}/Groups/{group_id}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok, "an omitted displayName must stay a no-op");
    assert_eq!(parse_json(&body_of(response).await)["displayName"], json!("Keep This Name"));
}

/// externalId and displayName are refused past SCIM_MAX_ATTRIBUTE_LEN.
///
/// Without the cap the backend decides, and the three disagree: sqlite stores
/// an over-long value, mysql truncates or rejects depending on strict mode, and
/// postgresql fails the insert - surfacing as a 500, the one status that makes
/// Entra retry forever and eventually quarantine the application.
#[rocket::async_test]
async fn over_long_attributes_are_refused_with_400_not_500() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-attrlen-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let too_long = "x".repeat(scim::SCIM_MAX_EXTERNAL_ID_LEN + 1);
    let at_cap = "y".repeat(scim::SCIM_MAX_EXTERNAL_ID_LEN);

    // POST /Users
    let payload = json!({
        "schemas": [scim::discovery::USER_SCHEMA_URN],
        "userName": "attrlen.user@example.com",
        "externalId": too_long,
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::BadRequest, "an over-long externalId must be a 400, never a 500");
    assert_eq!(parse_json(&body_of(response).await)["scimType"], json!("invalidValue"));
    assert!(User::find_by_mail("attrlen.user@example.com", &conn).await.is_none(), "nothing may be written");

    // POST /Groups, both attributes.
    for (attr, value) in [("externalId", &too_long), ("displayName", &too_long)] {
        let payload = json!({
            "schemas": [scim::discovery::GROUP_SCHEMA_URN],
            "displayName": if attr == "displayName" { value.clone() } else { "Attr Len Group".to_owned() },
            "externalId": if attr == "externalId" { value.clone() } else { "attrlen-grp".to_owned() },
        });
        let (auth, ct, body) = scim_body(&token, &payload);
        let response =
            client.post(format!("/scim/v2/{org}/Groups")).header(auth).header(ct).body(body).dispatch().await;
        assert_eq!(response.status(), Status::BadRequest, "an over-long {attr} must be a 400");
        assert_eq!(parse_json(&body_of(response).await)["scimType"], json!("invalidValue"), "{attr}");
    }

    // PUT and PATCH /Groups were entirely unguarded: post_group had the check
    // and the two update paths did not, so an over-long displayName reached
    // group.save() with only the SCIM body limit bounding it.
    let create = json!({
        "schemas": [scim::discovery::GROUP_SCHEMA_URN],
        "displayName": "Attr Len Updatable",
        "externalId": "attrlen-updatable",
    });
    let (auth, ct, body) = scim_body(&token, &create);
    let response = client.post(format!("/scim/v2/{org}/Groups")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created);
    let group_id = parse_json(&body_of(response).await)["id"].as_str().expect("group id").to_owned();

    // groups.name is VARCHAR(100) on mysql AND postgresql, so displayName has a
    // much tighter cap than externalId. Entra permits display names up to 256
    // characters, so 101-300 is an ordinary directory value, not a hostile one.
    let long_name = "n".repeat(scim::SCIM_MAX_GROUP_NAME_LEN + 1);
    assert!(
        long_name.chars().count() < scim::SCIM_MAX_EXTERNAL_ID_LEN,
        "the two caps must differ, or this proves nothing"
    );

    let put = json!({"schemas": [scim::discovery::GROUP_SCHEMA_URN], "displayName": long_name});
    let (auth, ct, body) = scim_body(&token, &put);
    let response =
        client.put(format!("/scim/v2/{org}/Groups/{group_id}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::BadRequest, "PUT must cap displayName at the groups.name column width");
    assert_eq!(parse_json(&body_of(response).await)["scimType"], json!("invalidValue"));

    let patch = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "displayName", "value": long_name}],
    });
    let (auth, ct, body) = scim_body(&token, &patch);
    let response =
        client.patch(format!("/scim/v2/{org}/Groups/{group_id}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::BadRequest, "PATCH must cap displayName too");

    // POST /Groups with the same value: a name that fits the externalId cap but
    // not the column would have passed the shared 300-char check.
    let payload = json!({
        "schemas": [scim::discovery::GROUP_SCHEMA_URN],
        "displayName": long_name,
        "externalId": "attrlen-longname",
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Groups")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::BadRequest, "POST must use the group-name cap, not the externalId cap");

    // userName: is_valid_email permits a ~320-char address, users.email is
    // VARCHAR(255), so shape validation alone let a 300-char address through.
    // Built to be WELL-FORMED and over-long at the same time, which is the
    // whole point: local part 64 (the RFC 5321 maximum), domain 194 (under its
    // 255 maximum, every label under 63), total 259. is_valid_email accepts it,
    // so a 400 here can only come from the length check and not from the shape
    // check - otherwise this test would pass without the fix.
    let long_email = format!("{}@{}.{}.{}.example.com", "e".repeat(64), "b".repeat(60), "c".repeat(60), "d".repeat(60));
    assert!(crate::util::is_valid_email(&long_email), "the probe must be a VALID address, or it proves nothing");
    assert!(long_email.chars().count() > scim::SCIM_MAX_EMAIL_LEN, "the probe must exceed the cap");
    let payload = json!({"schemas": [scim::discovery::USER_SCHEMA_URN], "userName": long_email});
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::BadRequest, "an over-long but well-formed address must be a 400, not a 500");
    let parsed = parse_json(&body_of(response).await);
    assert_eq!(parsed["scimType"], json!("invalidValue"));
    assert!(
        parsed["detail"].as_str().is_some_and(|d| d.contains("at most")),
        "the refusal must come from the LENGTH check, not the shape check: {parsed}"
    );

    // Exactly at the cap is legal - the boundary is inclusive.
    let payload = json!({
        "schemas": [scim::discovery::USER_SCHEMA_URN],
        "userName": "attrlen.ok@example.com",
        "externalId": at_cap,
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response = client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created, "a value exactly at the cap must be accepted");
}

/// A refused `active` change must not leave the externalId write behind.
///
/// PUT and PATCH can carry both mutations in one body and the externalId write
/// commits first, so a body whose restore is blocked by `reject_privileged_grant`
/// used to return 400 having already persisted the correlation key - a failed
/// request that half-applied, which the client then retries.
#[rocket::async_test]
async fn a_refused_active_change_rolls_back_nothing_because_it_writes_nothing() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-precheck-org").await;
    let token = seed_scim_key(&conn, &org).await;
    // A spare Owner so the last-owner guard is not what refuses this.
    seed_member(&conn, &org, "precheck.spare.owner@example.com", 2, MembershipType::Owner).await;

    // A REVOKED admin: restoring it is the grant-shaped path SCIM refuses.
    let member = seed_member(&conn, &org, "precheck.admin@example.com", 2, MembershipType::Admin).await;
    let mut row = Membership::find_by_uuid_and_org(&member, &org, &conn).await.expect("row");
    assert!(row.revoke());
    row.save(&conn).await.expect("revoking");
    let status_before = member_status(&conn, &member, &org).await;

    for (label, method_is_put) in [("PUT", true), ("PATCH", false)] {
        let payload = if method_is_put {
            json!({
                "schemas": [scim::discovery::USER_SCHEMA_URN],
                "userName": "precheck.admin@example.com",
                "externalId": "precheck-should-not-land",
                "active": true,
            })
        } else {
            json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [
                    {"op": "replace", "path": "externalId", "value": "precheck-should-not-land"},
                    {"op": "replace", "path": "active", "value": true},
                ],
            })
        };
        let (auth, ct, body) = scim_body(&token, &payload);
        let url = format!("/scim/v2/{org}/Users/{member}");
        let response = if method_is_put {
            client.put(url).header(auth).header(ct).body(body).dispatch().await
        } else {
            client.patch(url).header(auth).header(ct).body(body).dispatch().await
        };

        assert_eq!(response.status(), Status::BadRequest, "{label}: restoring an admin must be refused");
        assert_eq!(parse_json(&body_of(response).await)["scimType"], json!("mutability"), "{label}");

        let row = Membership::find_by_uuid_and_org(&member, &org, &conn).await.expect("row");
        assert_eq!(row.status, status_before, "{label}: the member must stay revoked");
        assert_eq!(
            row.external_id, None,
            "{label}: the externalId write must not have landed - the whole request failed"
        );
    }
}

/// The last-owner guard counts ACTIVE owners, not confirmed ones.
///
/// Counting only confirmed owners let SCIM revoke an organization's sole Owner
/// whenever that Owner was still Invited or Accepted, because the confirmed
/// count was 0 and the guard never fired. `reject_privileged_grant` then refuses
/// to let SCIM put it back, so the org was left with no owner at all.
#[rocket::async_test]
async fn the_last_owner_guard_covers_an_unconfirmed_sole_owner() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");

    // Status 0 = Invited, 1 = Accepted: neither is Confirmed.
    for (label, status, org_name, email) in [
        ("invited", 0, "scim-lastowner-invited", "lastowner.invited@example.com"),
        ("accepted", 1, "scim-lastowner-accepted", "lastowner.accepted@example.com"),
    ] {
        let org = seed_org(&conn, org_name).await;
        let token = seed_scim_key(&conn, &org).await;
        let owner = seed_member(&conn, &org, email, status, MembershipType::Owner).await;

        let response = client.delete(format!("/scim/v2/{org}/Users/{owner}")).header(bearer(&token)).dispatch().await;
        assert_eq!(response.status(), Status::BadRequest, "{label}: the sole owner must not be revocable");
        assert_eq!(parse_json(&body_of(response).await)["scimType"], json!("mutability"), "{label}");
        assert_eq!(member_status(&conn, &owner, &org).await, status, "{label}: owner must be untouched");
    }

    // The case the confirmed-only test got right, which must not regress: with
    // one confirmed Owner standing, a second, unconfirmed Owner IS deprovisionable.
    let org = seed_org(&conn, "scim-lastowner-pair").await;
    let token = seed_scim_key(&conn, &org).await;
    seed_member(&conn, &org, "lastowner.confirmed@example.com", 2, MembershipType::Owner).await;
    let spare = seed_member(&conn, &org, "lastowner.spare@example.com", 0, MembershipType::Owner).await;

    let response = client.delete(format!("/scim/v2/{org}/Users/{spare}")).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::NoContent, "a non-last owner must still be deprovisionable");
    assert!(member_status(&conn, &spare, &org).await <= -1, "the spare owner must be revoked");
}

/// Rollback must not delete an account another organization has attached to.
///
/// `User::delete` cascades EVERY membership, including other orgs'. A concurrent
/// SCIM POST from another org can attach one between `User::save` and the
/// failure, and a membership's akey is unrecoverable under E2EE - so this is the
/// branch whose failure mode is destroying another organization's data. It was
/// the one `rollback_provisioning` outcome with no test.
#[rocket::async_test]
async fn rollback_spares_an_account_another_org_has_claimed() {
    let _guard = TEST_LOCK.lock().await;
    let (_client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org_a = seed_org(&conn, "scim-rollback-race-a").await;
    let org_b = seed_org(&conn, "scim-rollback-race-b").await;

    // This request created the account...
    let user = seed_user(&conn, "rollback.raced@example.com", false).await;
    let user_uuid = user.uuid.clone();

    // ...but org B attached a membership to it before the failure.
    let mut other = Membership::new(user.uuid.clone(), org_b.clone(), None);
    other.status = 0;
    other.save(&conn).await.expect("saving org B membership");
    let other_uuid = other.uuid.clone();

    let mut member = Membership::new(user.uuid.clone(), org_a.clone(), None);
    member.status = 0;
    member.save(&conn).await.expect("saving org A membership");
    let member_uuid = member.uuid.clone();

    // user_created = true, which on its own would mean "delete the account".
    scim::users::rollback_provisioning(user, member, true, false, &conn).await;

    assert!(
        User::find_by_uuid(&user_uuid, &conn).await.is_some(),
        "an account another org has claimed is no longer ours to destroy"
    );
    assert!(
        Membership::find_by_uuid_and_org(&other_uuid, &org_b, &conn).await.is_some(),
        "org B's membership must survive - its akey is unrecoverable"
    );
    assert!(
        Membership::find_by_uuid_and_org(&member_uuid, &org_a, &conn).await.is_none(),
        "only this request's own membership may be rolled back"
    );
}

/// A PATCH remove naming another org's membership id is a scoped no-op.
///
/// `delete_by_group_and_member` looks the membership up globally to bump its
/// sync revision, so an unscoped id would let one org reach into another. The
/// refusal has to be silent rather than a 400, because Entra retries removals
/// and "already gone" is the steady state for one.
#[rocket::async_test]
async fn a_group_member_removal_cannot_reach_into_another_org() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org_a = seed_org(&conn, "scim-xorg-remove-a").await;
    let token = seed_scim_key(&conn, &org_a).await;
    let org_b = seed_org(&conn, "scim-xorg-remove-b").await;

    let mine = seed_member(&conn, &org_a, "xorg.remove.mine@example.com", 2, MembershipType::User).await;
    let theirs = seed_member(&conn, &org_b, "xorg.remove.theirs@example.com", 2, MembershipType::User).await;

    let create = json!({
        "schemas": [scim::discovery::GROUP_SCHEMA_URN],
        "displayName": "Cross Org Remove",
        "externalId": "xorg-remove-1",
        "members": [{"value": mine.to_string()}],
    });
    let (auth, ct, body) = scim_body(&token, &create);
    let response = client.post(format!("/scim/v2/{org_a}/Groups")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created);
    let group_id = parse_json(&body_of(response).await)["id"].as_str().expect("group id").to_owned();

    for (label, victim) in [("another org's member", theirs.to_string()), ("nonexistent", "no-such-member".to_owned())]
    {
        let patch = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "remove", "path": "members", "value": [{"value": victim}]}],
        });
        let (auth, ct, body) = scim_body(&token, &patch);
        let response = client
            .patch(format!("/scim/v2/{org_a}/Groups/{group_id}"))
            .header(auth)
            .header(ct)
            .body(body)
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok, "{label}: an unresolvable removal is a no-op, not an error");

        let parsed = parse_json(&body_of(response).await);
        let members = parsed["members"].as_array().expect("members array");
        assert_eq!(members.len(), 1, "{label}: our own member must still be there");
        assert_eq!(members[0]["value"], json!(mine.to_string()), "{label}");
    }

    // And org B is untouched.
    assert!(
        Membership::find_by_uuid_and_org(&theirs, &org_b, &conn).await.is_some(),
        "the other org's membership must survive"
    );
}

/// A member list larger than the 500-id chunk must resolve completely.
///
/// `Membership::find_by_uuids_and_org` chunks at SQLITE_SAFE_BIND_CHUNK = 500
/// to stay under SQLite's 999 bound-parameter cap, and the group cap is 1000, so
/// any large write crosses exactly two chunks. Every other test that reaches the
/// chunking sends bogus ids and asserts the FAILURE path, so a bug that dropped
/// the second chunk (append vs assign, an early return, a wrong slice) would
/// surface as a legitimate write refused with "provision the user first" and
/// nothing would catch it.
#[rocket::async_test]
async fn a_member_list_crossing_the_chunk_boundary_resolves_completely() {
    // 600 > 500, so this spans two chunks.
    const MEMBERS: usize = 600;

    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-chunk-org").await;
    let token = seed_scim_key(&conn, &org).await;
    let mut values = Vec::with_capacity(MEMBERS);
    for n in 0..MEMBERS {
        let member = seed_member(&conn, &org, &format!("chunk.{n}@example.com"), 2, MembershipType::User).await;
        values.push(json!({"value": member.to_string()}));
    }

    let create = json!({
        "schemas": [scim::discovery::GROUP_SCHEMA_URN],
        "displayName": "Chunk Crossing",
        "externalId": "chunk-crossing-1",
        "members": values,
    });
    let (auth, ct, body) = scim_body(&token, &create);
    let response = client.post(format!("/scim/v2/{org}/Groups")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created, "a 600-member group is well inside the cap and must be accepted");

    let parsed = parse_json(&body_of(response).await);
    assert_eq!(
        parsed["members"].as_array().expect("members array").len(),
        MEMBERS,
        "every member across both chunks must have resolved and been written"
    );
}

/// The last-used throttle must actually skip the write.
///
/// The early return is the entire reason this column is safe on the hot auth
/// path: a full Entra sync is thousands of authenticated requests, and without
/// the throttle every one becomes an UPDATE. Only the write path and the
/// rotation reset were covered, so a regression that inverted or dropped the
/// condition would not fail anything.
#[rocket::async_test]
async fn the_last_used_write_is_throttled_not_repeated() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-lastused-throttle-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let url = format!("/scim/v2/{org}/ServiceProviderConfig");
    let response = client.get(&url).header(bearer(&token)).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let first = ScimApiKey::find_by_org(&org, &conn).await.expect("key").last_used_at.expect("first use recorded");

    // Several more authenticated requests, all well inside the resolution
    // window. The stored timestamp must be byte-identical, not merely Some.
    for _ in 0..3 {
        let response = client.get(&url).header(bearer(&token)).dispatch().await;
        assert_eq!(response.status(), Status::Ok);
    }
    let after = ScimApiKey::find_by_org(&org, &conn).await.expect("key").last_used_at.expect("still recorded");
    assert_eq!(after, first, "a request inside the resolution window must not write last_used_at again");
}

/// SCIM may remove members from a group it does not own, but not add them.
///
/// Group writes resolve by GroupId, so without this guard a leaked token reaches
/// every group in the organization - including one an administrator created in
/// the web vault and granted access to a sensitive collection. Adding a member
/// to such a group hands that member real plaintext access, because collection
/// access runs through `groups_users -> collections_groups` with no
/// per-collection key.
///
/// The asymmetry is the point, and mirrors revoke-yes/restore-no on Users:
/// removals reduce access and are the deprovisioning path, and refusing them
/// would leave Entra re-sending a write it can never satisfy until it
/// quarantines the whole application.
#[rocket::async_test]
async fn an_unmanaged_group_accepts_removals_but_refuses_additions() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-unmanaged-grp-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let sitting = seed_member(&conn, &org, "unmanaged.sitting@example.com", 2, MembershipType::User).await;
    let intruder = seed_member(&conn, &org, "unmanaged.intruder@example.com", 2, MembershipType::User).await;

    // A group as an admin would create it in the web vault: no externalId, one
    // member already in it, and - critically - a grant to a collection. The
    // grant is what makes it worth protecting: the rule targets groups that
    // CONFER access, not every group SCIM happens not to have created. A
    // SCIM-created group with no grants escalates nothing, so it stays writable
    // (proven by the control at the end of this test).
    let mut admin_group = Group::new(org.clone(), "Admin Curated".to_owned(), false, None);
    admin_group.save(&conn).await.expect("saving admin group");
    let group_id = admin_group.uuid.clone();
    GroupUser::new(group_id.clone(), sitting.clone()).save(&conn).await.expect("seeding member");

    let secret = Collection::new(org.clone(), "Payroll".to_owned(), None);
    secret.save(&conn).await.expect("saving collection");
    CollectionGroup::new(secret.uuid.clone(), group_id.clone(), false, false, false)
        .save(&org, &conn)
        .await
        .expect("granting the group access to the collection");

    let members_of = |gid: GroupId, org: OrganizationId| {
        let conn = &conn;
        async move {
            GroupUser::find_by_group(&gid, &org, conn)
                .await
                .into_iter()
                .map(|gu| gu.users_organizations_uuid)
                .collect::<Vec<_>>()
        }
    };

    // PATCH add is refused.
    let patch = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "add", "path": "members", "value": [{"value": intruder.to_string()}]}],
    });
    let (auth, ct, body) = scim_body(&token, &patch);
    let response =
        client.patch(format!("/scim/v2/{org}/Groups/{group_id}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::BadRequest, "adding to an unowned group must be refused");
    assert_eq!(parse_json(&body_of(response).await)["scimType"], json!("mutability"));
    assert_eq!(members_of(group_id.clone(), org.clone()).await.len(), 1, "nothing may have been added");

    // PUT replace that would add is refused, and adds nothing.
    let put = json!({
        "schemas": [scim::discovery::GROUP_SCHEMA_URN],
        "displayName": "Admin Curated",
        "members": [{"value": sitting.to_string()}, {"value": intruder.to_string()}],
    });
    let (auth, ct, body) = scim_body(&token, &put);
    let response =
        client.put(format!("/scim/v2/{org}/Groups/{group_id}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::BadRequest, "a PUT that adds must be refused too");
    let after = members_of(group_id.clone(), org.clone()).await;
    assert_eq!(after.len(), 1, "a refused replace must leave the group exactly as it was");
    assert_eq!(after[0], sitting, "and must not have removed the sitting member either");

    // Removal is allowed: deprovisioning must never be blocked.
    let patch = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "remove", "path": "members", "value": [{"value": sitting.to_string()}]}],
    });
    let (auth, ct, body) = scim_body(&token, &patch);
    let response =
        client.patch(format!("/scim/v2/{org}/Groups/{group_id}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok, "removing from an unowned group must still work");
    assert!(members_of(group_id.clone(), org.clone()).await.is_empty(), "the removal must have applied");

    // An access_all group is off limits for additions even WITH an externalId:
    // SCIM never sets access_all, so a group carrying it was escalated by a human.
    let mut broad = Group::new(org.clone(), "Everything".to_owned(), true, Some("entra-broad-1".to_owned()));
    broad.save(&conn).await.expect("saving access_all group");
    let broad_id = broad.uuid.clone();

    let patch = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "add", "path": "members", "value": [{"value": intruder.to_string()}]}],
    });
    let (auth, ct, body) = scim_body(&token, &patch);
    let response =
        client.patch(format!("/scim/v2/{org}/Groups/{broad_id}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::BadRequest, "an access_all group must refuse additions");
    assert!(members_of(broad_id, org.clone()).await.is_empty(), "nothing may have been added");

    // The control: a group SCIM created, carrying an externalId, still syncs
    // normally. Without this the test above is equally explained by group
    // membership being broken outright.
    let create = json!({
        "schemas": [scim::discovery::GROUP_SCHEMA_URN],
        "displayName": "Entra Managed",
        "externalId": "entra-managed-1",
        "members": [{"value": sitting.to_string()}],
    });
    let (auth, ct, body) = scim_body(&token, &create);
    let response = client.post(format!("/scim/v2/{org}/Groups")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created, "a SCIM-created group must still accept its members");
    let managed_id = parse_json(&body_of(response).await)["id"].as_str().expect("id").to_owned();

    let patch = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "add", "path": "members", "value": [{"value": intruder.to_string()}]}],
    });
    let (auth, ct, body) = scim_body(&token, &patch);
    let response =
        client.patch(format!("/scim/v2/{org}/Groups/{managed_id}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok, "a group SCIM owns must still accept additions");
    assert_eq!(
        parse_json(&body_of(response).await)["members"].as_array().expect("members").len(),
        2,
        "the addition must have applied to the owned group"
    );
}

// ---------------------------------------------------------------------------
// Coverage added by the 2026-08-08 /review + /cso pass.
// ---------------------------------------------------------------------------

/// Setting an externalId must not be usable to ADOPT an admin-owned group.
///
/// `scim_may_add_members` treats `external_id.is_some()` as proof that SCIM owns
/// a group, so the first assignment of an externalId is an ownership transfer.
/// Guarding only the member-add left a two-request escalation: stamp an
/// externalId on a web-vault group that grants a sensitive collection, then add
/// a member you control and reach plaintext collection access nobody granted.
///
/// Both halves are pinned here. The single-request form proves a reordering fix
/// is not enough on its own; the two-request form is the one a naive fix misses.
#[rocket::async_test]
async fn a_scim_token_cannot_adopt_an_admin_owned_group_by_setting_its_external_id() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-adoption-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let intruder = seed_member(&conn, &org, "adopt.intruder@example.com", 2, MembershipType::User).await;

    // Exactly the shape the guard protects: created in the web vault (no
    // externalId) and granting a collection.
    let mut admin_group = Group::new(org.clone(), "Payroll Access".to_owned(), false, None);
    admin_group.save(&conn).await.expect("saving admin group");
    let group_id = admin_group.uuid.clone();

    let secret = Collection::new(org.clone(), "Payroll".to_owned(), None);
    secret.save(&conn).await.expect("saving collection");
    CollectionGroup::new(secret.uuid.clone(), group_id.clone(), false, false, false)
        .save(&org, &conn)
        .await
        .expect("granting the group access to the collection");

    let members_now = |gid: GroupId, org: OrganizationId| {
        let conn = &conn;
        async move { GroupUser::find_by_group(&gid, &org, conn).await.len() }
    };
    let external_id_now = |gid: GroupId, org: OrganizationId| {
        let conn = &conn;
        async move { Group::find_by_uuid_and_org(&gid, &org, conn).await.expect("group").external_id }
    };

    // Request 1 of the two-request chain: adopt the group on its own. This is
    // the primitive, and it must be refused by itself.
    let adopt = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "externalId", "value": "entra-adopted"}],
    });
    let (auth, ct, body) = scim_body(&token, &adopt);
    let response =
        client.patch(format!("/scim/v2/{org}/Groups/{group_id}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::BadRequest, "adopting an access-granting group must be refused");
    assert_eq!(parse_json(&body_of(response).await)["scimType"], json!("mutability"));
    assert!(external_id_now(group_id.clone(), org.clone()).await.is_none(), "the externalId must not have been set");

    // The PUT form of the same adoption.
    let put = json!({
        "schemas": [scim::discovery::GROUP_SCHEMA_URN],
        "displayName": "Payroll Access",
        "externalId": "entra-adopted",
    });
    let (auth, ct, body) = scim_body(&token, &put);
    let response =
        client.put(format!("/scim/v2/{org}/Groups/{group_id}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::BadRequest, "PUT must refuse the adoption too");
    assert!(external_id_now(group_id.clone(), org.clone()).await.is_none(), "PUT must not have set the externalId");

    // The single-request form: adopt and add in one body. Refused, and nothing
    // may have been committed by the earlier half of the same request.
    let combined = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {"op": "replace", "path": "externalId", "value": "entra-adopted"},
            {"op": "add", "path": "members", "value": [{"value": intruder.to_string()}]},
        ],
    });
    let (auth, ct, body) = scim_body(&token, &combined);
    let response =
        client.patch(format!("/scim/v2/{org}/Groups/{group_id}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::BadRequest, "adopt-and-add in one request must be refused");
    assert!(external_id_now(group_id.clone(), org.clone()).await.is_none(), "no externalId may have been committed");
    assert_eq!(members_now(group_id.clone(), org.clone()).await, 0, "no member may have been added");

    // The control: correlating a group that grants NOTHING is still allowed. A
    // group with no collection grants confers nothing, so adopting it escalates
    // nothing - and refusing it would break non-Entra clients for no gain.
    let mut harmless = Group::new(org.clone(), "No Grants".to_owned(), false, None);
    harmless.save(&conn).await.expect("saving harmless group");
    let harmless_id = harmless.uuid.clone();

    let adopt = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "externalId", "value": "entra-harmless"}],
    });
    let (auth, ct, body) = scim_body(&token, &adopt);
    let response = client
        .patch(format!("/scim/v2/{org}/Groups/{harmless_id}"))
        .header(auth)
        .header(ct)
        .body(body)
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok, "a group that grants nothing must still be correlatable");
    assert_eq!(
        external_id_now(harmless_id, org.clone()).await,
        Some("entra-harmless".to_owned()),
        "the harmless correlation must have applied"
    );
}

/// A PATCH whose later operation fails must not leave an earlier one committed.
///
/// PATCH applies member ops in sequence with no transaction, and the single
/// `GroupUpdated` event is logged only after the whole loop succeeds. An early
/// add that committed a real collection-access grant, followed by a failing op,
/// therefore returned 4xx with the access granted AND no audit record at all -
/// access up, audit trail silent. Every op is now resolved before the first
/// write, so the request fails while the group is still untouched.
#[rocket::async_test]
async fn a_failing_patch_operation_leaves_no_committed_member_change() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-patch-atomic-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let intruder = seed_member(&conn, &org, "atomic.intruder@example.com", 2, MembershipType::User).await;

    // A group SCIM legitimately owns, so the add itself would be permitted -
    // isolating atomicity from the ownership guard.
    let mut group = Group::new(org.clone(), "Entra Owned".to_owned(), false, Some("entra-atomic-1".to_owned()));
    group.save(&conn).await.expect("saving group");
    let group_id = group.uuid.clone();

    let before = chrono::Utc::now().naive_utc().checked_sub_signed(chrono::Duration::hours(1)).expect("start");

    // Op 1 would add a real member; op 2 names a member id that does not exist.
    // Op 1 must not survive op 2's failure.
    let patch = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {"op": "add", "path": "members", "value": [{"value": intruder.to_string()}]},
            {"op": "replace", "path": "members", "value": [{"value": "00000000-dead-beef-0000-000000000000"}]},
        ],
    });
    let (auth, ct, body) = scim_body(&token, &patch);
    let response =
        client.patch(format!("/scim/v2/{org}/Groups/{group_id}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::BadRequest, "an unresolvable member must fail the request");

    assert!(
        GroupUser::find_by_group(&group_id, &org, &conn).await.is_empty(),
        "the earlier operation must not have committed a member (it would be an unlogged access grant)"
    );

    // And the audit log must not claim an update that did not happen.
    let events = Event::find_by_organization_uuid(
        &org,
        &before,
        &chrono::Utc::now().naive_utc().checked_add_signed(chrono::Duration::hours(1)).expect("end"),
        &conn,
    )
    .await;
    assert!(
        !events.iter().any(|e| e.event_type == EventType::GroupUpdated as i32),
        "a fully refused PATCH must not record a GroupUpdated event"
    );

    // The control: the same add on its own applies and IS logged, so the
    // assertions above cannot be explained by group writes being broken.
    let patch = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "add", "path": "members", "value": [{"value": intruder.to_string()}]}],
    });
    let (auth, ct, body) = scim_body(&token, &patch);
    let response =
        client.patch(format!("/scim/v2/{org}/Groups/{group_id}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok, "the same add alone must succeed");
    assert_eq!(GroupUser::find_by_group(&group_id, &org, &conn).await.len(), 1, "the control add must have applied");

    let events = Event::find_by_organization_uuid(
        &org,
        &before,
        &chrono::Utc::now().naive_utc().checked_add_signed(chrono::Duration::hours(1)).expect("end"),
        &conn,
    )
    .await;
    assert!(
        events.iter().any(|e| e.event_type == EventType::GroupUpdated as i32),
        "the successful PATCH must record a GroupUpdated event"
    );
}

/// An over-long displayName is a 400, not the 500 that quarantines the tenant.
///
/// `users.name` is TEXT on mysql and the SCIM body limit is 512KiB, so a
/// several-hundred-KB display name passed validation, failed the insert in
/// strict mode, and surfaced as a 500 - the one status Entra retries forever
/// until it quarantines the application, taking deprovisioning down with it.
/// userName and externalId were already capped; displayName was not.
#[rocket::async_test]
async fn an_over_long_display_name_is_refused_with_400_not_500() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-longname-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let too_long = "n".repeat(scim::SCIM_MAX_DISPLAY_NAME_LEN + 1);
    let create = json!({
        "schemas": [scim::discovery::USER_SCHEMA_URN],
        "userName": "longname@example.com",
        "displayName": too_long,
        "active": true,
    });
    let (auth, ct, body) = scim_body(&token, &create);
    let response = client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::BadRequest, "an over-long displayName must be a clean 400");
    assert_eq!(parse_json(&body_of(response).await)["scimType"], json!("invalidValue"));
    assert!(
        User::find_by_mail("longname@example.com", &conn).await.is_none(),
        "no shell account may be left behind by the refused request"
    );

    // The boundary is inclusive: exactly at the cap is accepted. Without this
    // the assertion above is equally explained by an off-by-one refusing
    // everything.
    let at_cap = "n".repeat(scim::SCIM_MAX_DISPLAY_NAME_LEN);
    let create = json!({
        "schemas": [scim::discovery::USER_SCHEMA_URN],
        "userName": "atcap@example.com",
        "displayName": at_cap,
        "active": true,
    });
    let (auth, ct, body) = scim_body(&token, &create);
    let response = client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created, "a displayName exactly at the cap must be accepted");

    // The composed form (givenName + familyName) reaches the same column and is
    // capped by the same check.
    let composed = json!({
        "schemas": [scim::discovery::USER_SCHEMA_URN],
        "userName": "composed@example.com",
        "name": {"givenName": "g".repeat(scim::SCIM_MAX_DISPLAY_NAME_LEN), "familyName": "f".repeat(20)},
        "active": true,
    });
    let (auth, ct, body) = scim_body(&token, &composed);
    let response = client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::BadRequest, "a composed name over the cap must also be refused");
}

// ---------------------------------------------------------------------------
// Coverage added by the 2026-08-08 follow-up pass: the Entra-facing branches
// TODOS.md recorded as untested, plus the new unmanaged-group delete guard.
// ---------------------------------------------------------------------------

/// A restore refused by an organization policy is a 400, and changes nothing.
///
/// `restore_member` runs `OrgPolicy::check_user_allowed` on the RESTORED status
/// and returns before `member.save()`, so the row must stay revoked. This branch
/// had no coverage at all: a regression that let a policy-blocked member through
/// would silently readmit someone the organization's own policy excludes, and a
/// regression in the other direction would send Entra a status it retries
/// forever.
#[rocket::async_test]
async fn a_policy_blocked_restore_is_refused_and_leaves_the_member_revoked() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-policy-restore-org").await;
    let token = seed_scim_key(&conn, &org).await;

    // Confirmed so that the restored status is > Invited, which is what
    // check_user_allowed gates on; a plain User so atype < Admin.
    let member_id = seed_member(&conn, &org, "policy.blocked@example.com", 2, MembershipType::User).await;

    // Revoke first, so the PATCH below is a real restore.
    let mut member = Membership::find_by_uuid_and_org(&member_id, &org, &conn).await.expect("member");
    member.revoke();
    member.save(&conn).await.expect("revoking");

    // The organization requires 2FA and this member has none, so a restore is
    // exactly what the policy forbids.
    OrgPolicy::new(org.clone(), OrgPolicyType::TwoFactorAuthentication, true, "null".to_owned())
        .save(&conn)
        .await
        .expect("saving policy");

    let payload = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "active", "value": true}],
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{member_id}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::BadRequest, "a policy-blocked restore must be a 400");
    assert_eq!(parse_json(&body_of(response).await)["scimType"], json!("invalidValue"));

    let after = Membership::find_by_uuid_and_org(&member_id, &org, &conn).await.expect("member");
    assert!(after.status <= MembershipStatus::Revoked as i32, "the member must still be revoked");

    // The control: with the policy disabled the same request succeeds, so the
    // refusal above cannot be explained by restore being broken outright.
    let mut policy =
        OrgPolicy::find_by_org_and_type(&org, OrgPolicyType::TwoFactorAuthentication, &conn).await.expect("policy");
    policy.enabled = false;
    policy.save(&conn).await.expect("disabling policy");

    let payload = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "active", "value": true}],
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{member_id}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok, "the same restore must succeed once the policy is off");
    let after = Membership::find_by_uuid_and_org(&member_id, &org, &conn).await.expect("member");
    assert!(after.status > MembershipStatus::Revoked as i32, "the control restore must have applied");
}

/// externalId filters must FIND the resource they name, on both endpoints.
///
/// Only the cross-org negative was pinned (which passes just as happily if the
/// filter matches nothing at all). Entra correlates on externalId, so a
/// regression that stopped matching would make every sync cycle believe the
/// member does not exist yet and re-POST it - duplicate provisioning, seen from
/// the tenant as a loop of 409s.
#[rocket::async_test]
async fn external_id_filters_find_the_resource_they_name() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-extid-filter-org").await;
    let token = seed_scim_key(&conn, &org).await;

    // A member carrying an externalId, created the way Entra creates one.
    let create = json!({
        "schemas": [scim::discovery::USER_SCHEMA_URN],
        "userName": "extid.match@example.com",
        "externalId": "entra-extid-match",
        "active": true,
    });
    let (auth, ct, body) = scim_body(&token, &create);
    let response = client.post(format!("/scim/v2/{org}/Users")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created);
    let member_id = parse_json(&body_of(response).await)["id"].as_str().expect("id").to_owned();

    let filter = url_escape("externalId eq \"entra-extid-match\"");
    let (auth, ct, _) = scim_body(&token, &json!({}));
    let response =
        client.get(format!("/scim/v2/{org}/Users?filter={filter}")).header(auth).header(ct).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let listed = parse_json(&body_of(response).await);
    assert_eq!(listed["totalResults"], json!(1), "the externalId filter must match the member");
    assert_eq!(listed["Resources"][0]["id"], json!(member_id), "and must return the right one");

    // A value that exists nowhere still returns an empty 200, not a 404 - this
    // is the shape Entra's own probe depends on.
    let filter = url_escape("externalId eq \"entra-extid-absent\"");
    let (auth, ct, _) = scim_body(&token, &json!({}));
    let response =
        client.get(format!("/scim/v2/{org}/Users?filter={filter}")).header(auth).header(ct).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(parse_json(&body_of(response).await)["totalResults"], json!(0));

    // The Groups arm had no positive coverage at all.
    let create = json!({
        "schemas": [scim::discovery::GROUP_SCHEMA_URN],
        "displayName": "ExtId Filter Group",
        "externalId": "entra-grp-extid-match",
    });
    let (auth, ct, body) = scim_body(&token, &create);
    let response = client.post(format!("/scim/v2/{org}/Groups")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created);
    let group_id = parse_json(&body_of(response).await)["id"].as_str().expect("id").to_owned();

    let filter = url_escape("externalId eq \"entra-grp-extid-match\"");
    let (auth, ct, _) = scim_body(&token, &json!({}));
    let response =
        client.get(format!("/scim/v2/{org}/Groups?filter={filter}")).header(auth).header(ct).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let listed = parse_json(&body_of(response).await);
    assert_eq!(listed["totalResults"], json!(1), "the Groups externalId filter must match");
    assert_eq!(listed["Resources"][0]["id"], json!(group_id), "and must return the right group");
}

/// A second POST /Groups carrying an externalId already in use is a 409.
///
/// The concurrent test asserts only `created >= 1` with 201-or-409, which is
/// correct for a race but means deleting post_group's uniqueness check entirely
/// would keep every existing test green. This pins the sequential case, where
/// there is no race and 409 is the only acceptable answer.
#[rocket::async_test]
async fn a_sequential_duplicate_group_external_id_is_a_409() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-dup-grp-extid-org").await;
    let token = seed_scim_key(&conn, &org).await;

    let create = json!({
        "schemas": [scim::discovery::GROUP_SCHEMA_URN],
        "displayName": "First Group",
        "externalId": "entra-dup-grp",
    });
    let (auth, ct, body) = scim_body(&token, &create);
    let response = client.post(format!("/scim/v2/{org}/Groups")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created);

    // Different displayName, same externalId: the correlation key is what must
    // collide, not the name.
    let duplicate = json!({
        "schemas": [scim::discovery::GROUP_SCHEMA_URN],
        "displayName": "Second Group",
        "externalId": "entra-dup-grp",
    });
    let (auth, ct, body) = scim_body(&token, &duplicate);
    let response = client.post(format!("/scim/v2/{org}/Groups")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Conflict, "a duplicate group externalId must be a 409");
    assert_eq!(parse_json(&body_of(response).await)["scimType"], json!("uniqueness"));

    let carrying =
        Group::find_by_organization(&org, &conn).await.into_iter().filter(|g| g.external_id.is_some()).count();
    assert_eq!(carrying, 1, "exactly one group may carry the externalId");
}

/// An SMTP outage during RESTORE must not fail the restore.
///
/// `restore_member` has its own mail branch, independent of the POST path that
/// `smtp_outage_keeps_the_membership_and_does_not_fail_the_request` covers. A
/// regression propagating the mail error here would fail every
/// restore-after-outage cycle, which is the reprovision half of the highest
/// value thing this feature does.
#[rocket::async_test]
async fn an_smtp_outage_during_restore_still_restores_the_member() {
    let _guard = TEST_LOCK.lock().await;
    crate::mail::test_sink::reset();
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-smtp-restore-org").await;
    let token = seed_scim_key(&conn, &org).await;

    // Invited, so the restore lands back on Invited and takes the re-invite mail
    // branch - the one under test.
    let member_id = seed_member(&conn, &org, "restore.outage@example.com", 0, MembershipType::User).await;
    let mut member = Membership::find_by_uuid_and_org(&member_id, &org, &conn).await.expect("member");
    member.revoke();
    member.save(&conn).await.expect("revoking");

    // RAII guard, matching the POST-path test: a panic in the assertions below
    // must not leave the global fail flag set for every later test.
    let smtp_outage = crate::mail::test_sink::fail_sends_guard();

    let payload = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "active", "value": true}],
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{member_id}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok, "an SMTP outage must not fail the restore");
    assert_eq!(parse_json(&body_of(response).await)["active"], json!(true));

    let after = Membership::find_by_uuid_and_org(&member_id, &org, &conn).await.expect("member");
    assert_eq!(after.status, MembershipStatus::Invited as i32, "the restore must have been committed");

    // Once SMTP recovers the next restore mails normally, and the failed one is
    // not silently replayed.
    drop(smtp_outage);
    let mut member = Membership::find_by_uuid_and_org(&member_id, &org, &conn).await.expect("member");
    member.revoke();
    member.save(&conn).await.expect("re-revoking");

    let payload = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "active", "value": true}],
    });
    let (auth, ct, body) = scim_body(&token, &payload);
    let response =
        client.patch(format!("/scim/v2/{org}/Users/{member_id}")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(
        crate::mail::test_sink::to("restore.outage@example.com").len(),
        1,
        "delivery must resume, and the outage-era invite must not be replayed"
    );
}

/// SCIM must not delete an admin-owned group that grants collection access.
///
/// delete_group resolves by uuid like every other Group path, so without a guard
/// a token holder could enumerate every group in the organization and delete the
/// administrator-curated ones, dropping their collection grants. Recoverable, so
/// a lower bar than the membership paths - but the same ownership rule as
/// additions.
#[rocket::async_test]
async fn an_unmanaged_group_cannot_be_deleted_through_scim() {
    let _guard = TEST_LOCK.lock().await;
    let (client, pool) = scim_client().await;
    let conn = pool.get().await.expect("conn");
    let org = seed_org(&conn, "scim-grp-delete-org").await;
    let token = seed_scim_key(&conn, &org).await;

    // Web-vault shaped: no externalId, and it grants a collection.
    let mut admin_group = Group::new(org.clone(), "Admin Curated".to_owned(), false, None);
    admin_group.save(&conn).await.expect("saving admin group");
    let group_id = admin_group.uuid.clone();

    let secret = Collection::new(org.clone(), "Payroll".to_owned(), None);
    secret.save(&conn).await.expect("saving collection");
    CollectionGroup::new(secret.uuid.clone(), group_id.clone(), false, false, false)
        .save(&org, &conn)
        .await
        .expect("granting collection access");

    let (auth, ct, _) = scim_body(&token, &json!({}));
    let response =
        client.delete(format!("/scim/v2/{org}/Groups/{group_id}")).header(auth).header(ct).dispatch().await;
    assert_eq!(response.status(), Status::BadRequest, "deleting an unmanaged access-granting group must be refused");
    assert_eq!(parse_json(&body_of(response).await)["scimType"], json!("mutability"));
    assert!(
        Group::find_by_uuid_and_org(&group_id, &org, &conn).await.is_some(),
        "the group must still exist"
    );

    // The control: a group SCIM owns is still deletable, so the refusal above is
    // not just group deletion being broken.
    let create = json!({
        "schemas": [scim::discovery::GROUP_SCHEMA_URN],
        "displayName": "Entra Owned",
        "externalId": "entra-deletable-1",
    });
    let (auth, ct, body) = scim_body(&token, &create);
    let response = client.post(format!("/scim/v2/{org}/Groups")).header(auth).header(ct).body(body).dispatch().await;
    assert_eq!(response.status(), Status::Created);
    let owned_id = parse_json(&body_of(response).await)["id"].as_str().expect("id").to_owned();

    let (auth, ct, _) = scim_body(&token, &json!({}));
    let response =
        client.delete(format!("/scim/v2/{org}/Groups/{owned_id}")).header(auth).header(ct).dispatch().await;
    assert_eq!(response.status(), Status::NoContent, "a SCIM-managed group must still be deletable");
}
