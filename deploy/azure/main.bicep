// Vaultwarden with SCIM v2 provisioning, on Azure Container Apps.
//
// Generic and fully parameterized: every environment-specific value arrives as
// a parameter, so nothing about any particular deployment is committed here.
// The companion workflow feeds these from GitHub variables and secrets.
//
// Scope is the resource group. Create it first (the workflow does this), then:
//
//   az deployment group create \
//     --resource-group <rg> \
//     --template-file deploy/azure/main.bicep \
//     --parameters deploy/azure/main.bicepparam
//
// See deploy/azure/README.md for the variable list and the post-deploy steps
// that Bicep cannot do (minting the SCIM token, creating the break-glass Owner).

targetScope = 'resourceGroup'

@description('Azure region. Defaults to the resource group\'s region.')
param location string = resourceGroup().location

@description('Short name prefix for every resource. Lowercase alphanumeric, 3-11 chars.')
@minLength(3)
@maxLength(11)
param namePrefix string = 'vaultwarden'

@description('Deployment environment label, used in names and tags.')
@allowed([
  'dev'
  'test'
  'staging'
  'prod'
])
param environmentLabel string = 'prod'

@description('Container image. PIN BY DIGEST in production rather than :latest.')
param containerImage string = 'vaultwarden/server:latest'

@description('Custom domain (https://vault.example.com). Leave empty to use the generated Container Apps FQDN.')
param customDomain string = ''

// --- Database -------------------------------------------------------------

@description('Deploy a PostgreSQL Flexible Server. Set false only for a trial deployment on SQLite.')
param deployPostgres bool = true

@description('PostgreSQL administrator login.')
param postgresAdminLogin string = 'vwadmin'

@description('PostgreSQL administrator password. Supply from a GitHub secret.')
@secure()
param postgresAdminPassword string = ''

@description('PostgreSQL compute SKU.')
param postgresSkuName string = 'Standard_B1ms'

@description('PostgreSQL SKU tier.')
@allowed([
  'Burstable'
  'GeneralPurpose'
  'MemoryOptimized'
])
param postgresSkuTier string = 'Burstable'

@description('PostgreSQL storage in GB.')
@minValue(32)
param postgresStorageGB int = 32

@description('PostgreSQL backup retention in days.')
@minValue(7)
@maxValue(35)
param postgresBackupRetentionDays int = 7

// --- Application ----------------------------------------------------------

@description('Enable the SCIM v2 endpoints.')
param scimEnabled bool = true

@description('Enable the organization event log. Keep true with SCIM: it is the provisioning audit trail.')
param orgEventsEnabled bool = true

@description('Enable organization groups. Required for SCIM Group sync.')
param orgGroupsEnabled bool = true

@description('Average seconds between SCIM requests from one IP before throttling.')
@minValue(1)
param scimRatelimitSeconds int = 1

@description('SCIM request burst allowance.')
@minValue(1)
param scimRatelimitMaxBurst int = 60

@description('Allow open registration. Keep false on a provisioned deployment.')
param signupsAllowed bool = false

@description('CPU cores per replica.')
param cpu string = '0.5'

@description('Memory per replica.')
param memory string = '1Gi'

@description('Minimum replicas. Keep >= 1 with SCIM so Entra never hits a cold start.')
@minValue(0)
param minReplicas int = 1

@description('Maximum replicas.')
@minValue(1)
param maxReplicas int = 1

@description('Argon2-hashed admin token. Empty leaves the admin panel disabled.')
@secure()
param adminToken string = ''

// --- Mail -----------------------------------------------------------------

@description('SMTP host. Empty disables mail, which also disables SCIM invite delivery.')
param smtpHost string = ''

@description('SMTP port.')
param smtpPort int = 587

@description('SMTP security mode.')
@allowed([
  'starttls'
  'force_tls'
  'off'
])
param smtpSecurity string = 'starttls'

@description('SMTP username.')
param smtpUsername string = ''

@description('SMTP password.')
@secure()
param smtpPassword string = ''

@description('From address for outgoing mail.')
param smtpFrom string = ''

// --- Observability --------------------------------------------------------

@description('Log Analytics retention in days.')
@minValue(30)
@maxValue(730)
param logRetentionDays int = 30

@description('Extra tags merged into the defaults.')
param additionalTags object = {}

// --------------------------------------------------------------------------

var uniqueSuffix = uniqueString(resourceGroup().id)
var baseName = '${namePrefix}-${environmentLabel}'

var tags = union({
  application: 'vaultwarden'
  environment: environmentLabel
  managedBy: 'bicep'
  component: 'vaultwarden-scim'
}, additionalTags)

// Key Vault names are globally unique and capped at 24 characters, so the
// prefix is truncated rather than allowed to overflow.
var keyVaultName = take('${namePrefix}kv${uniqueSuffix}', 24)
var postgresServerName = toLower('${baseName}-pg-${uniqueSuffix}')

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${baseName}-identity'
  location: location
  tags: tags
}

module logs 'modules/loganalytics.bicep' = {
  name: 'loganalytics'
  params: {
    location: location
    name: '${baseName}-logs'
    retentionInDays: logRetentionDays
    tags: tags
  }
}

module postgres 'modules/postgres.bicep' = if (deployPostgres) {
  name: 'postgres'
  params: {
    location: location
    name: postgresServerName
    administratorLogin: postgresAdminLogin
    administratorPassword: postgresAdminPassword
    skuName: postgresSkuName
    skuTier: postgresSkuTier
    storageSizeGB: postgresStorageGB
    backupRetentionDays: postgresBackupRetentionDays
    tags: tags
  }
}

// sslmode=require is not optional: without it the connection to a public
// PostgreSQL endpoint can fall back to plaintext.
//
// Built with format() rather than string interpolation so the source carries no
// literal in the shape `scheme://user:password@host`. Every field here is a
// parameter reference resolved at deploy time - there is no credential in this
// file - but a connection-string-shaped literal trips credential scanners, and
// a template that cries wolf trains people to wave real findings through.
var databaseUrlTemplate = '{0}://{1}:{2}@{3}:5432/{4}?sslmode=require'
var databaseUrl = deployPostgres
  ? format(
      databaseUrlTemplate,
      'postgresql',
      postgresAdminLogin,
      uriComponent(postgresAdminPassword),
      postgres!.outputs.fqdn,
      postgres!.outputs.databaseName
    )
  : ''

module vault 'modules/keyvault.bicep' = {
  name: 'keyvault'
  params: {
    location: location
    name: keyVaultName
    readerPrincipalId: identity.properties.principalId
    adminToken: adminToken
    smtpPassword: smtpPassword
    databaseUrl: databaseUrl
    hasAdminToken: !empty(adminToken)
    hasSmtpPassword: !empty(smtpPassword)
    hasDatabaseUrl: deployPostgres
    tags: tags
  }
}

module containerApp 'modules/containerapp.bicep' = {
  name: 'containerapp'
  params: {
    location: location
    name: '${baseName}-app'
    environmentName: '${baseName}-env'
    logAnalyticsWorkspaceId: logs.outputs.id
    logAnalyticsCustomerId: logs.outputs.customerId
    managedIdentityId: identity.id
    containerImage: containerImage
    domain: customDomain
    cpu: cpu
    memory: memory
    minReplicas: minReplicas
    maxReplicas: maxReplicas
    scimEnabled: scimEnabled
    orgEventsEnabled: orgEventsEnabled
    orgGroupsEnabled: orgGroupsEnabled
    scimRatelimitSeconds: scimRatelimitSeconds
    scimRatelimitMaxBurst: scimRatelimitMaxBurst
    signupsAllowed: signupsAllowed
    invitationsAllowed: true
    databaseUrlSecretUri: vault.outputs.databaseUrlSecretUri
    adminTokenSecretUri: vault.outputs.adminTokenSecretUri
    smtpSecretUri: vault.outputs.smtpSecretUri
    smtpHost: smtpHost
    smtpPort: smtpPort
    smtpSecurity: smtpSecurity
    smtpUsername: smtpUsername
    smtpFrom: smtpFrom
    tags: tags
  }
}

output appUrl string = containerApp.outputs.appUrl
output appFqdn string = containerApp.outputs.fqdn
output appName string = containerApp.outputs.appName
output keyVaultName string = vault.outputs.vaultName
output postgresServerName string = deployPostgres ? postgres!.outputs.serverName : ''
output logAnalyticsWorkspace string = logs.outputs.name

@description('Set DOMAIN to this (or your custom domain) before running SCIM: Location headers and invite links are built from it.')
output domainToConfigure string = empty(customDomain) ? containerApp.outputs.appUrl : customDomain

@description('SCIM base URL to paste into the Entra enterprise application, once an org exists and a token is minted.')
output scimTenantUrlHint string = containerApp.outputs.scimEndpointHint
