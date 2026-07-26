use std::{net::IpAddr, num::NonZeroU32, sync::LazyLock, time::Duration};

use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DashMapStateStore};

use crate::{CONFIG, Error};

type Limiter<T = IpAddr> = RateLimiter<T, DashMapStateStore<T>, DefaultClock>;

static LIMITER_LOGIN: LazyLock<Limiter> = LazyLock::new(|| {
    let seconds = Duration::from_secs(CONFIG.login_ratelimit_seconds());
    let burst = NonZeroU32::new(CONFIG.login_ratelimit_max_burst()).expect("Non-zero login ratelimit burst");
    RateLimiter::keyed(Quota::with_period(seconds).expect("Non-zero login ratelimit seconds").allow_burst(burst))
});

static LIMITER_ADMIN: LazyLock<Limiter> = LazyLock::new(|| {
    let seconds = Duration::from_secs(CONFIG.admin_ratelimit_seconds());
    let burst = NonZeroU32::new(CONFIG.admin_ratelimit_max_burst()).expect("Non-zero admin ratelimit burst");
    RateLimiter::keyed(Quota::with_period(seconds).expect("Non-zero admin ratelimit seconds").allow_burst(burst))
});

static LIMITER_SCIM: LazyLock<Limiter> = LazyLock::new(|| {
    let seconds = Duration::from_secs(CONFIG.scim_ratelimit_seconds());
    let burst = NonZeroU32::new(CONFIG.scim_ratelimit_max_burst()).expect("Non-zero scim ratelimit burst");
    RateLimiter::keyed(Quota::with_period(seconds).expect("Non-zero scim ratelimit seconds").allow_burst(burst))
});

static LIMITER_UNAUTHENTICATED: LazyLock<Limiter> = LazyLock::new(|| {
    let seconds = Duration::from_secs(CONFIG.unauthenticated_ratelimit_seconds());
    let burst = NonZeroU32::new(CONFIG.unauthenticated_ratelimit_max_burst())
        .expect("Non-zero unauthenticated ratelimit burst");
    RateLimiter::keyed(
        Quota::with_period(seconds).expect("Non-zero unauthenticated ratelimit seconds").allow_burst(burst),
    )
});

pub fn check_limit_unauthenticated(ip: &IpAddr) -> Result<(), Error> {
    match LIMITER_UNAUTHENTICATED.check_key(ip) {
        Ok(()) => Ok(()),
        Err(_e) => {
            err_code!("Too many requests", 429);
        }
    }
}

pub fn check_limit_login(ip: &IpAddr) -> Result<(), Error> {
    match LIMITER_LOGIN.check_key(ip) {
        Ok(()) => Ok(()),
        Err(_e) => {
            err_code!("Too many login requests", 429);
        }
    }
}

pub fn check_limit_admin(ip: &IpAddr) -> Result<(), Error> {
    match LIMITER_ADMIN.check_key(ip) {
        Ok(()) => Ok(()),
        Err(_e) => {
            err_code!("Too many admin requests", 429);
        }
    }
}

pub fn check_limit_scim(ip: &IpAddr) -> Result<(), Error> {
    match LIMITER_SCIM.check_key(ip) {
        Ok(()) => Ok(()),
        Err(_e) => {
            err_code!("Too many SCIM requests", 429);
        }
    }
}

/// Drops rate-limiter buckets that have fully replenished.
///
/// The keyed state store never evicts on its own, so every distinct key ever
/// seen keeps an entry for the process lifetime. The key is the client IP, and
/// the set of distinct client IPs is unbounded: a proxy that forwards real
/// client addresses supplies one entry per internet peer. Upstream #7472 closed
/// the sharper version of this, where `IP_HEADER` was honoured from any caller
/// and so the key could be chosen freely, but it only narrowed the source, it
/// did not bound the count. All four limiters are checked before
/// authentication, so the growth is reachable by unauthenticated traffic; SCIM
/// widens that surface, which is why this now runs on a schedule.
/// `retain_recent` alone only half-solves this. governor's keyed DashMap store
/// implements it as a `retain`, which removes entries but does not release the
/// map's bucket capacity, so a single burst of spoofed IPs would leave the
/// allocation inflated for the process lifetime even after every entry expired.
/// `shrink_to_fit` is the separate call that actually returns the memory.
pub fn prune_limiters() {
    LIMITER_LOGIN.retain_recent();
    LIMITER_LOGIN.shrink_to_fit();
    LIMITER_ADMIN.retain_recent();
    LIMITER_ADMIN.shrink_to_fit();
    LIMITER_SCIM.retain_recent();
    LIMITER_SCIM.shrink_to_fit();
    LIMITER_UNAUTHENTICATED.retain_recent();
    LIMITER_UNAUTHENTICATED.shrink_to_fit();
}
