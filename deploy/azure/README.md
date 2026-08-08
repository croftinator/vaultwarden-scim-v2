# Deploying Vaultwarden with SCIM on Azure

Bicep templates for Vaultwarden on Azure Container Apps, with the SCIM v2
provisioning endpoints this fork adds. Every value is a parameter, and the
companion workflow supplies them from GitHub repository variables and secrets -
so nothing about your deployment lives in this repository.

What gets created:

| Resource | Why |
|---|---|
| Container App + environment | Runs Vaultwarden, terminates TLS, provides the public HTTPS endpoint Entra requires |
| PostgreSQL Flexible Server | `users_organizations` is global across all organizations and is on the SCIM hot path; also survives container restarts |
| Key Vault | Holds the admin token, SMTP credential and database URL; the app reads them via managed identity |
| Log Analytics workspace | Required by Container Apps, and the sink for request logs |
| User-assigned managed identity | Lets the app read Key Vault without any stored credential |

> [!IMPORTANT]
> These templates deploy the infrastructure. They deliberately do **not** create
> your organization, mint the SCIM token, or configure Entra - those need a
> running server and are covered in [`docs/scim/setup.md`](../../docs/scim/setup.md).

## Prerequisites

1. An Azure subscription, and permission to create resource groups.
2. An Entra app registration with a **federated credential** for this repository,
   granted **Contributor** on the target resource group. This is what makes OIDC
   login work without storing a cloud secret in GitHub.
3. A generated admin token. Generate the **hash**, never store the plaintext:

   ```bash
   docker run --rm vaultwarden/server:latest /vaultwarden hash --preset owasp
   ```

   Put the resulting `$argon2id$...` string in the `VW_ADMIN_TOKEN` secret.

## Configuration

Set these under **Settings → Secrets and variables → Actions**.

### Secrets (never variables)

| Secret | Required | Notes |
|---|---|---|
| `AZURE_CLIENT_ID` | yes | App registration client ID |
| `AZURE_TENANT_ID` | yes | Directory tenant ID |
| `AZURE_SUBSCRIPTION_ID` | yes | Target subscription |
| `VW_POSTGRES_ADMIN_PASSWORD` | when Postgres is on | Strong, unique |
| `VW_ADMIN_TOKEN` | recommended | The argon2 **hash**, not plaintext. Empty disables `/admin` |
| `VW_SMTP_PASSWORD` | when mail is on | SCIM invites need working mail to reach users |

### Variables

| Variable | Default | Notes |
|---|---|---|
| `AZURE_RESOURCE_GROUP` | *(required)* | Created if absent |
| `VW_LOCATION` | `australiaeast` | Any region supporting Container Apps |
| `VW_NAME_PREFIX` | `vaultwarden` | 3-11 lowercase alphanumeric chars |
| `VW_CONTAINER_IMAGE` | `vaultwarden/server:latest` | **Pin by digest in production** |
| `VW_DOMAIN` | *(empty)* | Custom domain, e.g. `https://vault.example.com`. Empty uses the generated FQDN |
| `VW_DEPLOY_POSTGRES` | `true` | `false` runs SQLite - trials only, see below |
| `VW_POSTGRES_SKU` / `VW_POSTGRES_TIER` | `Standard_B1ms` / `Burstable` | Raise for production load |
| `VW_POSTGRES_STORAGE_GB` | `32` | Minimum is 32 |
| `VW_POSTGRES_BACKUP_DAYS` | `7` | 7-35 |
| `VW_SCIM_ENABLED` | `true` | Master switch for `/scim/v2` |
| `VW_ORG_EVENTS_ENABLED` | `true` | **Keep true.** This is the provisioning audit trail |
| `VW_ORG_GROUPS_ENABLED` | `true` | Required for SCIM Group sync |
| `VW_SCIM_RATELIMIT_SECONDS` | `1` | Average seconds between requests per IP |
| `VW_SCIM_RATELIMIT_MAX_BURST` | `60` | Entra bursts during sync cycles |
| `VW_SIGNUPS_ALLOWED` | `false` | Keep false when provisioning through an IdP |
| `VW_CPU` / `VW_MEMORY` | `0.5` / `1Gi` | Must pair (0.5 CPU → 1Gi) |
| `VW_MIN_REPLICAS` | `1` | **Keep ≥ 1 with SCIM**, see below |
| `VW_MAX_REPLICAS` | `1` | Raise only after reading the scaling note |
| `VW_SMTP_HOST` / `_PORT` / `_SECURITY` / `_USERNAME` / `_FROM` | *(empty)* / `587` / `starttls` | Empty host disables mail |
| `VW_LOG_RETENTION_DAYS` | `30` | 30-730 |

## Deploying

Run the **Deploy to Azure** workflow. It defaults to **what-if preview**;
uncheck `whatIf` to apply. The run summary prints the app URL, the SCIM base URL
and the remaining manual steps.

Locally, the same templates work with the same variable names exported:

```bash
export VW_LOCATION=australiaeast VW_POSTGRES_ADMIN_PASSWORD='...'
az group create -n my-rg -l "$VW_LOCATION"
az deployment group create -g my-rg \
  -f deploy/azure/main.bicep -p deploy/azure/main.bicepparam
```

## Four settings that matter more than they look

**`IP_HEADER` is set to `X-Forwarded-For`, not the Vaultwarden default.** The
SCIM rate limiter keys on this header. Container Apps ingress sets
`X-Forwarded-For` and does not set `X-Real-IP`, so leaving the default would
collapse every client into one bucket and let a single noisy caller throttle
everyone. The template handles this; do not override it.

**`DOMAIN` must match the URL clients actually use.** SCIM `Location` headers,
`meta.location` and invite links are all built from it. Wrong value means Entra
receives resource URLs it cannot follow, and invite emails point somewhere dead.
Set `VW_DOMAIN` whenever you bind a custom domain.

**Keep `VW_MIN_REPLICAS` at 1 or more.** Scale-to-zero means Entra's first
request of a sync cycle pays a cold start. A timeout there counts against the
tenant's failure budget, and sustained failures quarantine the enterprise
application - which takes **deprovisioning** down with it, the highest-value
thing SCIM does here.

**Multiple replicas share no rate-limiter state.** The limiter is per-process,
so raising `VW_MAX_REPLICAS` to N multiplies the effective SCIM rate limit by N.
It still works, but the configured numbers stop meaning what they say.

## SQLite mode

Setting `VW_DEPLOY_POSTGRES=false` runs the SQLite default. **The Container Apps
filesystem is ephemeral, so the database is lost on every revision restart**
unless you attach a storage volume, which these templates do not do. Treat it as
trial-only. Anything real should use PostgreSQL.

## Hardening beyond the defaults

The templates are deliberately reachable-by-default so a first deployment works.
For a production or regulated deployment, layer on:

- **Private networking.** Put the Container Apps environment on a VNet, switch
  PostgreSQL to private access, and set the Key Vault `networkAcls` default
  action to `Deny` with a service endpoint. This needs a delegated subnet, which
  a generic template cannot assume.
- **Pin the image by digest.** `:latest` means a redeploy can silently change the
  running version.
- **Custom domain with a managed certificate**, so the URL is stable and matches
  `DOMAIN`.
- **Diagnostic settings** exporting Container App and PostgreSQL logs to the
  workspace for the retention your compliance regime requires.
- **A break-glass Owner that does not exist in Entra.** If your only Owners are
  Entra-managed, a directory compromise or a bad sync can lock you out of the
  organization entirely. See the deployment guide's break-glass section.

## After the infrastructure is up

Bicep stops here. To get provisioning working:

1. Register the first account and create the organization.
2. Create the **break-glass Owner** and seal its credentials away.
3. Mint the SCIM token - `POST /api/organizations/<org_id>/scim/api-key`. It is
   shown exactly once.
4. Paste the SCIM base URL (`https://<host>/scim/v2/<org_id>`) and the token into
   the Entra enterprise application, then run **Test Connection**.
5. Validate before trusting it, using the rungs in
   [`docs/scim/testing.md`](../../docs/scim/testing.md) -
   `tools/scim-entra-replay.sh` against the live endpoint is the cheapest real
   check.

Full walkthrough: [`docs/scim/setup.md`](../../docs/scim/setup.md).
Operational detail: [`docs/scim/deployment.md`](../../docs/scim/deployment.md).
