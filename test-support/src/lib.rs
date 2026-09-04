//! Test-only environment bootstrap.
//!
//! The main crate forbids `unsafe`, and `std::env::set_var` is `unsafe` on
//! edition 2024, so the mutation lives here. The `#[ctor]` constructor runs
//! before `main` and before any test thread exists, which is the only point
//! where the process environment can be changed race-free and the only point
//! early enough to beat the first deref of Vaultwarden's process-global
//! `CONFIG` (a `LazyLock` that reads the environment).
//!
//! Linkage is intentional: this crate only takes effect in test binaries that
//! reference it (`use test_support as _;`). Feature combos that do not compile
//! those test modules never link it and keep upstream behaviour.

/// Points every config-relevant environment variable at a per-process
/// temporary directory and enables the flags the SCIM test suite needs.
///
/// `DATABASE_URL` is deliberately left unset: Vaultwarden derives it as
/// `sqlite://{DATA_FOLDER}/db.sqlite3`, which lands inside the hermetic
/// directory, and hardcoding a sqlite URL here would poison config validation
/// for mysql/postgresql-only feature combos.
///
/// # Panics
///
/// Panics if the hermetic temporary directory or its empty env file cannot be
/// created. There is no useful way to continue: every test in the process
/// depends on `CONFIG` being pointed somewhere writable before `main`.
pub fn init_hermetic_env() {
    // Listed here rather than mid-function so it does not shadow the reader's
    // sense of where the scope's items begin.
    //
    // CONFIG is a LazyLock, so one test binary can only ever observe one value
    // for each pinned key. Keys named here defer to a value already present in
    // the environment, which lets a second pass over the same binary exercise
    // the opposite branch (see tools/scim-test-config-matrix.sh). Everything
    // else is pinned unconditionally so a developer's shell cannot change what
    // the suite means.
    const CALLER_MAY_OVERRIDE: &[&str] = &["SSO_ONLY"];

    let base = std::env::temp_dir().join(format!("vaultwarden-test-{}", std::process::id()));
    let data = base.join("data");
    std::fs::create_dir_all(&data).expect("creating hermetic test data dir");

    // An empty env file: a configured-but-missing ENV_FILE makes Vaultwarden
    // exit at config load, and an unset one falls back to the repo's dev .env.
    let env_file = base.join("test.env");
    std::fs::write(&env_file, "").expect("creating hermetic test env file");

    let vars: &[(&str, String)] = &[
        ("ENV_FILE", env_file.to_string_lossy().into_owned()),
        ("DATA_FOLDER", data.to_string_lossy().into_owned()),
        ("DOMAIN", String::from("http://localhost:8000")),
        ("WEB_VAULT_ENABLED", String::from("false")),
        ("SIGNUPS_ALLOWED", String::from("true")),
        ("INVITATIONS_ALLOWED", String::from("true")),
        ("ORG_GROUPS_ENABLED", String::from("true")),
        // Without this, log_event returns on its first line and every SCIM
        // audit-log call is dead code under test.
        ("ORG_EVENTS_ENABLED", String::from("true")),
        ("SCIM_ENABLED", String::from("true")),
        // Upstream #7472 made ClientIp honour IP_HEADER only when the peer is a
        // trusted proxy. The default, "local", needs a known non-global peer,
        // but Rocket's local client presents no remote address at all, so the
        // header would be dropped and every request attributed to the 0.0.0.0
        // fallback. That collapses the per-IP tests onto one bucket. "all" is
        // safe here precisely because there is no real peer to spoof from.
        ("IP_HEADER_TRUSTED_PROXIES", String::from("all")),
        ("SCIM_RATELIMIT_SECONDS", String::from("1")),
        // High burst so the shared per-IP limiter never trips ordinary tests;
        // the 429 path is exercised against a distinct synthetic IP.
        ("SCIM_RATELIMIT_MAX_BURST", String::from("10000")),
        // The Suite C tests each drive a real login, and they share one client
        // IP. Upstream's default burst is 10, so the suite exhausts it and
        // later tests see 429 instead of the status they assert. Raise it for
        // the same reason SCIM_RATELIMIT_MAX_BURST is raised; the 429 path is
        // exercised deliberately against dedicated synthetic IPs.
        ("LOGIN_RATELIMIT_MAX_BURST", String::from("10000")),
        ("LOGIN_RATELIMIT_SECONDS", String::from("1")),
        // SSO is enabled so the login path is reachable, but the authority is
        // never contacted: the SCIM x SSO tests pre-populate SsoAuth.auth_response,
        // which makes sso::exchange_code return before it builds an OIDC client.
        // The URL only has to satisfy config validation at startup.
        ("SSO_ENABLED", String::from("true")),
        ("SSO_AUTHORITY", String::from("http://sso.invalid/realms/test")),
        ("SSO_CLIENT_ID", String::from("vaultwarden-test")),
        ("SSO_CLIENT_SECRET", String::from("not-a-real-secret")),
        // The strict setting, and the one worth pinning: with it off, SSO
        // refuses to adopt an existing account that has a keypair. A
        // SCIM-provisioned shell account has none, so it must still link -
        // that asymmetry is what the Suite C tests exist to protect.
        ("SSO_SIGNUPS_MATCH_EMAIL", String::from("false")),
        // Default pass runs with SSO_ONLY off; the config-matrix pass sets it
        // to true in the environment and the loop above defers to that.
        ("SSO_ONLY", String::from("false")),
    ];

    for (key, value) in vars {
        if CALLER_MAY_OVERRIDE.contains(key) && std::env::var(key).is_ok() {
            continue;
        }
        // SAFETY: runs pre-main via #[ctor]; the process is single-threaded,
        // so mutating the environment cannot race with any reader.
        unsafe {
            std::env::set_var(key, value);
        }
    }

    // Mail is ENABLED, pointed at an unroutable host, because that is the
    // realistic production shape and because the invite paths are otherwise
    // untestable. Nothing can actually be delivered: `mail::test_sink`
    // intercepts every message inside `send_with_selected_transport`, before
    // any transport is constructed, in all `cfg(test)` builds. The host below
    // is never contacted; it exists only so `CONFIG.mail_enabled()` is true.
    let mail_vars: &[(&str, &str)] = &[
        ("SMTP_HOST", "smtp.invalid"),
        ("SMTP_FROM", "vaultwarden-test@example.com"),
        ("SMTP_FROM_NAME", "Vaultwarden Test"),
        ("SMTP_PORT", "25"),
        ("SMTP_SECURITY", "off"),
    ];
    for (key, value) in mail_vars {
        // SAFETY: as above.
        unsafe {
            std::env::set_var(key, value);
        }
    }

    // A developer shell exporting a real sendmail command must not win.
    // SAFETY: as above.
    unsafe {
        std::env::remove_var("USE_SENDMAIL");
        std::env::remove_var("SENDMAIL_COMMAND");
    }
}

/// Installs the rustls crypto provider.
///
/// `main()` does this at startup and a test binary never runs `main()`. Any
/// deref of `CONFIG` builds an HTTP client, which panics without a provider -
/// so this must happen before the first test touches config, whichever test
/// that turns out to be. Doing it from a helper only worked by accident of
/// parallel scheduling: under `--test-threads=1` the first unit test to touch
/// `CONFIG` ran before any helper had been called, and the process aborted.
pub fn init_crypto_provider() {
    // Err means it is already installed, which is the desired end state.
    if rustls::crypto::ring::default_provider().install_default().is_err() {
        eprintln!("[test-support] rustls crypto provider was already installed");
    }
}

#[ctor::ctor(unsafe)]
fn hermetic_env() {
    init_hermetic_env();
    init_crypto_provider();
}
