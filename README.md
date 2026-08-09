# Vaultwarden + SCIM v2

A fork of [Vaultwarden](https://github.com/dani-garcia/vaultwarden) that adds a
**SCIM v2 provisioning server** (RFC 7643 / RFC 7644), so organization
membership can be driven from an identity provider.

Standard SCIM 2.0, so any compliant provisioning engine works - nothing in the
request path branches on which client is calling. **Microsoft Entra ID**,
**Okta** and **Google Workspace** each have their
documented request cycle covered by the test suite, and **Authentik** has been
verified end to end against a running server. See
[providers.md](docs/scim/providers.md), including what "supported" is verified
to mean for each.

The fork automates member **invite**, **update**, and **deprovision** from your
IdP, plus **group sync**. End-to-end encryption means the final *confirm* step
stays a manual admin action - the docs explain why.

> [!WARNING]
> **No identity provider has been validated against a live tenant yet. Do not
> roll this out to production without testing it yourself first.**
>
> Entra ID, Okta and Google Workspace are covered by
> tests written from each vendor's *published documentation*, not from observed
> traffic against a real tenant. That catches protocol mistakes; it cannot catch
> a vendor behaving differently from its own documentation, and they sometimes
> do. Authentik is the one exception - a real engine has driven a full lifecycle
> end to end - but it is not one of the major cloud providers.
>
> Before any rollout: run the full lifecycle against a **throwaway** tenant and
> a test organisation - never production. Step-by-step setup and a six-step
> verification procedure for each provider are in
> [provider-setup.md](docs/scim/provider-setup.md). Create, update, add to a group,
> deprovision, and re-provision, and confirm each one landed. The rungs in
> [testing.md](docs/scim/testing.md) get you most of the way for free - the
> hosted Microsoft SCIM Validator needs no tenant at all.

## Documentation (this fork)

Start at **[docs/scim/](docs/scim/README.md)** - it indexes the rest.

| Guide | Covers |
|---|---|
| [deployment.md](docs/scim/deployment.md) | Cloud-agnostic containers, PostgreSQL, secrets, SSO, break-glass Owner |
| [setup.md](docs/scim/setup.md) | Server config, org token, and the Entra ID walkthrough |
| [provider-setup.md](docs/scim/provider-setup.md) | Setting up **and verifying** each IdP: Entra ID, Okta, Google Workspace, Authentik |
| [providers.md](docs/scim/providers.md) | What each provider sends, and what is actually verified |
| [client-rollout.md](docs/scim/client-rollout.md) | Pointing staff Bitwarden apps at your server, zero-touch and manual |
| [operations.md](docs/scim/operations.md) | Member lifecycle and troubleshooting |
| [reference.md](docs/scim/reference.md) | Deliberate behaviours and named RFC divergences |
| [upgrading.md](docs/scim/upgrading.md) | Whether an upgrade needs downtime, and the exact sequence |
| [testing.md](docs/scim/testing.md) | Validating a change, from the unit suite to a live tenant |
| [design.md](docs/scim/design.md) | Architecture, E2EE security model, threat model, decision log |

What changed and why, including the security fixes: **[CHANGELOG.md](CHANGELOG.md)**.

## The base project

Everything that is not the SCIM feature - what Vaultwarden is, and how to
install, run, and configure it, its full feature set, and the wiki - lives in
the upstream project:
**[dani-garcia/vaultwarden](https://github.com/dani-garcia/vaultwarden)**.

## Get in touch

Questions, bugs, or change requests about the **SCIM feature or this fork**:

- [Open an issue](https://github.com/croftinator/vaultwarden-scim-v2/issues) on this repository.
- [Open a pull request](https://github.com/croftinator/vaultwarden-scim-v2/pulls) with a fix or improvement.

Please **do not** raise fork-specific matters with the upstream Vaultwarden
project or with Bitwarden - they do not maintain this code.

## License

This fork is a modification of Vaultwarden, an AGPLv3 work, and is itself
licensed under **AGPL-3.0**. See [LICENSE.txt](LICENSE.txt). All upstream
copyright and attribution notices are retained.

## Disclaimer

This project is **not associated with [Bitwarden](https://bitwarden.com/) or
Bitwarden, Inc.** It is also an independent fork and is **not endorsed by the
upstream Vaultwarden maintainers**.
