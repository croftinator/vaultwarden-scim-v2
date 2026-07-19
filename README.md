# Vaultwarden + SCIM v2

A fork of [Vaultwarden](https://github.com/dani-garcia/vaultwarden) that adds a
**SCIM v2 provisioning server** (RFC 7643 / RFC 7644), so organization
membership can be driven from an identity provider. Microsoft Entra ID is the
tested provider.

The fork automates member **invite**, **update**, and **deprovision** from your
IdP, plus **group sync**. End-to-end encryption means the final *confirm* step
stays a manual admin action - the docs explain why.

## Documentation (this fork)

- **[docs/scim/README.md](docs/scim/README.md)** - operator setup, the Microsoft
  Entra ID walkthrough, rolling the server out to the Bitwarden client apps, and
  troubleshooting.
- **[docs/scim/design.md](docs/scim/design.md)** - architecture, the end-to-end
  encryption security model, and diagrams.

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
