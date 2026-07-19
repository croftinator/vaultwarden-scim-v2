> [!NOTE]
> **This fork adds a SCIM v2 provisioning server** (RFC 7643 / RFC 7644) for
> identity-provider-driven organization membership, tested against Microsoft
> Entra ID. Setup and rollout: **[docs/scim/](docs/scim/)**.
> Everything below is the upstream Vaultwarden README.

![Vaultwarden Logo](./resources/vaultwarden-logo-auto.svg)

An alternative server implementation of the Bitwarden Client API, written in Rust and compatible with [official Bitwarden clients](https://bitwarden.com/download/) [[disclaimer](#disclaimer)], perfect for self-hosted deployment where running the official resource-heavy service might not be ideal.

---

<!-- Fork note: the upstream README's GitHub-API-backed shields badges (release,
     contributors, forks, stars, issues, discussions, workflow status, deps.rs,
     discourse) are removed here. They render unreliably through GitHub's image
     proxy AND point at dani-garcia/vaultwarden, so they show upstream's numbers,
     not this fork's. The badges kept below do not depend on the GitHub API. -->
[![ghcr.io Pulls](https://img.shields.io/badge/dynamic/json?style=for-the-badge&logo=github&logoColor=fff&color=005AA4&url=https%3A%2F%2Fipitio.github.io%2Fbackage%2Fdani-garcia%2Fvaultwarden%2Fvaultwarden.json&query=%24.downloads&label=ghcr.io%20pulls&cacheSeconds=14400)](https://github.com/dani-garcia/vaultwarden/pkgs/container/vaultwarden)
[![Docker Pulls](https://img.shields.io/docker/pulls/vaultwarden/server.svg?style=for-the-badge&logo=docker&logoColor=fff&color=005AA4&label=docker.io%20pulls)](https://hub.docker.com/r/vaultwarden/server)
[![Quay.io](https://img.shields.io/badge/quay.io-download-005AA4?style=for-the-badge&logo=redhat&cacheSeconds=14400)](https://quay.io/repository/vaultwarden/server) <br>
[![AGPL-3.0 Licensed](https://img.shields.io/github/license/dani-garcia/vaultwarden.svg?style=flat-square&logo=vaultwarden&color=944000&cacheSeconds=14400)](https://github.com/dani-garcia/vaultwarden/blob/main/LICENSE.txt)
[![Matrix Chat](https://img.shields.io/matrix/vaultwarden:matrix.org.svg?style=flat-square&logo=matrix&logoColor=fff&color=953B00&cacheSeconds=14400)](https://matrix.to/#/#vaultwarden:matrix.org)

> [!IMPORTANT]
> **When using this server, please report any bugs or suggestions directly to us (see [Get in touch](#get-in-touch)), regardless of whatever clients you are using (mobile, desktop, browser...). DO NOT use the official Bitwarden support channels.**

<br>

## Features

A nearly complete implementation of the Bitwarden Client API is provided, including:

 * [Personal Vault](https://bitwarden.com/help/managing-items/)
 * [Send](https://bitwarden.com/help/about-send/)
 * [Attachments](https://bitwarden.com/help/attachments/)
 * [Website icons](https://bitwarden.com/help/website-icons/)
 * [Personal API Key](https://bitwarden.com/help/personal-api-key/)
 * [Organizations](https://bitwarden.com/help/getting-started-organizations/)
   - [Collections](https://bitwarden.com/help/about-collections/),
     [Password Sharing](https://bitwarden.com/help/sharing/),
     [Member Roles](https://bitwarden.com/help/user-types-access-control/),
     [Groups](https://bitwarden.com/help/about-groups/),
     [Event Logs](https://bitwarden.com/help/event-logs/),
     [Admin Password Reset](https://bitwarden.com/help/admin-reset/),
     [Directory Connector](https://bitwarden.com/help/directory-sync/),
     [Policies](https://bitwarden.com/help/policies/)
 * [Multi/Two Factor Authentication](https://bitwarden.com/help/bitwarden-field-guide-two-step-login/)
   - [Authenticator](https://bitwarden.com/help/setup-two-step-login-authenticator/),
     [Email](https://bitwarden.com/help/setup-two-step-login-email/),
     [FIDO2 WebAuthn](https://bitwarden.com/help/setup-two-step-login-fido/),
     [YubiKey](https://bitwarden.com/help/setup-two-step-login-yubikey/),
     [Duo](https://bitwarden.com/help/setup-two-step-login-duo/)
 * [Emergency Access](https://bitwarden.com/help/emergency-access/)
 * [Vaultwarden Admin Backend](https://github.com/dani-garcia/vaultwarden/wiki/Enabling-admin-page)
 * [Modified Web Vault client](https://github.com/dani-garcia/bw_web_builds) (Bundled within our containers)

<br>

## Usage

> [!IMPORTANT]
> The web-vault requires the use of HTTPS and a secure context for the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API). <br>
> That means it will only work if you [enable HTTPS](https://github.com/dani-garcia/vaultwarden/wiki/Enabling-HTTPS). <br>
> We also suggest to use a [reverse proxy](https://github.com/dani-garcia/vaultwarden/wiki/Proxy-examples).

The recommended way to install and use Vaultwarden is via our container images which are published to [ghcr.io](https://github.com/dani-garcia/vaultwarden/pkgs/container/vaultwarden), [docker.io](https://hub.docker.com/r/vaultwarden/server) and [quay.io](https://quay.io/repository/vaultwarden/server).
See [which container image to use](https://github.com/dani-garcia/vaultwarden/wiki/Which-container-image-to-use) for an explanation of the provided tags.

There are also [community driven packages](https://github.com/dani-garcia/vaultwarden/wiki/Third-party-packages) which can be used, but those might be lagging behind the latest version or might deviate in the way Vaultwarden is configured, as described in our [Wiki](https://github.com/dani-garcia/vaultwarden/wiki).

Alternatively, you can also [build Vaultwarden](https://github.com/dani-garcia/vaultwarden/wiki/Building-binary) yourself.

While Vaultwarden is based upon the [Rocket web framework](https://rocket.rs) which has built-in support for TLS our recommendation would be that you setup a reverse proxy (see [proxy examples](https://github.com/dani-garcia/vaultwarden/wiki/Proxy-examples)).

> [!TIP]
>**For more detailed examples on how to install, use and configure Vaultwarden you can check our [Wiki](https://github.com/dani-garcia/vaultwarden/wiki).**

### Docker/Podman CLI

Pull the container image and mount a volume from the host for persistent storage.<br>
You can replace `docker` with `podman` if you prefer to use podman.

```shell
docker pull vaultwarden/server:latest
docker run --detach --name vaultwarden \
  --env DOMAIN="https://vw.domain.tld" \
  --volume /vw-data/:/data/ \
  --restart unless-stopped \
  --publish 127.0.0.1:8000:80 \
  vaultwarden/server:latest
```

This will preserve any persistent data under `/vw-data/`, you can adapt the path to whatever suits you.

### Docker Compose

To use Docker compose you need to create a `compose.yaml` which will hold the configuration to run the Vaultwarden container.

```yaml
services:
  vaultwarden:
    image: vaultwarden/server:latest
    container_name: vaultwarden
    restart: unless-stopped
    environment:
      DOMAIN: "https://vw.domain.tld"
    volumes:
      - ./vw-data/:/data/
    ports:
      - 127.0.0.1:8000:80
```

<br>

## Get in touch

Have a question, suggestion or need help? Join our community on [Matrix](https://matrix.to/#/#vaultwarden:matrix.org), [GitHub Discussions](https://github.com/dani-garcia/vaultwarden/discussions) or [Discourse Forums](https://vaultwarden.discourse.group/).

Encountered a bug or crash? Please search our issue tracker and discussions to see if it's already been reported. If not, please [start a new discussion](https://github.com/dani-garcia/vaultwarden/discussions) or [create a new issue](https://github.com/dani-garcia/vaultwarden/issues/). Ensure you're using the latest version of Vaultwarden and there aren't any similar issues open or closed!

<br>

## Contributors

Thanks for your contribution to the project!

<!-- Fork note: the GitHub-API-backed "Contributors Count" shields badge is
     removed here for the same reason as the header badges. -->
[![Contributors Avatars](https://contributors-img.web.app/image?repo=dani-garcia/vaultwarden)](https://github.com/dani-garcia/vaultwarden/graphs/contributors)

<br>

## Disclaimer

**This project is not associated with [Bitwarden](https://bitwarden.com/) or Bitwarden, Inc.**

However, one of the active maintainers for Vaultwarden is employed by Bitwarden and is allowed to contribute to the project on their own time. These contributions are independent of Bitwarden and are reviewed by other maintainers.

The maintainers work together to set the direction for the project, focusing on serving the self-hosting community, including individuals, families, and small organizations, while ensuring the project's sustainability.

**Please note:** We cannot be held liable for any data loss that may occur while using Vaultwarden. This includes passwords, attachments, and other information handled by the application. We highly recommend performing regular backups of your files and database. However, should you experience data loss, we encourage you to contact us immediately.

<br>

## Bitwarden_RS

This project was known as Bitwarden_RS and has been renamed to separate itself from the official Bitwarden server in the hopes of avoiding confusion and trademark/branding issues.<br>
Please see [#1642 - v1.21.0 release and project rename to Vaultwarden](https://github.com/dani-garcia/vaultwarden/discussions/1642) for more explanation.
