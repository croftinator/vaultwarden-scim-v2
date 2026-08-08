// Parameter file driven entirely by environment variables.
//
// The deploy workflow maps GitHub repository variables and secrets onto these,
// so no value specific to any deployment is committed. Running this locally
// works too - export the same names first.
//
//   az deployment group create -g <rg> -f deploy/azure/main.bicep \
//     -p deploy/azure/main.bicepparam
//
// readEnvironmentVariable's second argument is the default used when the
// variable is unset, which is what keeps a minimal deployment to a handful of
// settings.

using 'main.bicep'

param namePrefix = readEnvironmentVariable('VW_NAME_PREFIX', 'vaultwarden')
param environmentLabel = readEnvironmentVariable('VW_ENVIRONMENT', 'prod')
param location = readEnvironmentVariable('VW_LOCATION', 'australiaeast')
param containerImage = readEnvironmentVariable('VW_CONTAINER_IMAGE', 'vaultwarden/server:latest')
param customDomain = readEnvironmentVariable('VW_DOMAIN', '')

// Database
param deployPostgres = bool(readEnvironmentVariable('VW_DEPLOY_POSTGRES', 'true'))
param postgresAdminLogin = readEnvironmentVariable('VW_POSTGRES_ADMIN_LOGIN', 'vwadmin')
param postgresAdminPassword = readEnvironmentVariable('VW_POSTGRES_ADMIN_PASSWORD', '')
param postgresSkuName = readEnvironmentVariable('VW_POSTGRES_SKU', 'Standard_B1ms')
param postgresSkuTier = readEnvironmentVariable('VW_POSTGRES_TIER', 'Burstable')
param postgresStorageGB = int(readEnvironmentVariable('VW_POSTGRES_STORAGE_GB', '32'))
param postgresBackupRetentionDays = int(readEnvironmentVariable('VW_POSTGRES_BACKUP_DAYS', '7'))

// Application
param scimEnabled = bool(readEnvironmentVariable('VW_SCIM_ENABLED', 'true'))
param orgEventsEnabled = bool(readEnvironmentVariable('VW_ORG_EVENTS_ENABLED', 'true'))
param orgGroupsEnabled = bool(readEnvironmentVariable('VW_ORG_GROUPS_ENABLED', 'true'))
param scimRatelimitSeconds = int(readEnvironmentVariable('VW_SCIM_RATELIMIT_SECONDS', '1'))
param scimRatelimitMaxBurst = int(readEnvironmentVariable('VW_SCIM_RATELIMIT_MAX_BURST', '60'))
param signupsAllowed = bool(readEnvironmentVariable('VW_SIGNUPS_ALLOWED', 'false'))
param cpu = readEnvironmentVariable('VW_CPU', '0.5')
param memory = readEnvironmentVariable('VW_MEMORY', '1Gi')
param minReplicas = int(readEnvironmentVariable('VW_MIN_REPLICAS', '1'))
param maxReplicas = int(readEnvironmentVariable('VW_MAX_REPLICAS', '1'))
param adminToken = readEnvironmentVariable('VW_ADMIN_TOKEN', '')

// Mail
param smtpHost = readEnvironmentVariable('VW_SMTP_HOST', '')
param smtpPort = int(readEnvironmentVariable('VW_SMTP_PORT', '587'))
param smtpSecurity = readEnvironmentVariable('VW_SMTP_SECURITY', 'starttls')
param smtpUsername = readEnvironmentVariable('VW_SMTP_USERNAME', '')
param smtpPassword = readEnvironmentVariable('VW_SMTP_PASSWORD', '')
param smtpFrom = readEnvironmentVariable('VW_SMTP_FROM', '')

// Observability
param logRetentionDays = int(readEnvironmentVariable('VW_LOG_RETENTION_DAYS', '30'))
