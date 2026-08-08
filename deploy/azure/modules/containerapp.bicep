// Container Apps environment + the Vaultwarden app itself.
//
// Three things here are SCIM-specific and are the ones a generic Vaultwarden
// template gets wrong:
//
//   1. IP_HEADER must be X-Forwarded-For on Container Apps. Vaultwarden's
//      default is X-Real-IP, which the Container Apps ingress does not set, so
//      the SCIM rate limiter would see every request as coming from the same
//      (empty) client and one noisy tenant could throttle everyone.
//   2. DOMAIN must be the public HTTPS URL. SCIM Location headers,
//      meta.location and invite links are all built from it; a wrong value
//      produces resources Entra cannot follow.
//   3. minReplicas must be >= 1 when SCIM is enabled. Scale-to-zero means a
//      cold start on Entra's first request of a sync cycle, and a timeout there
//      counts as a failure against the tenant's quarantine budget.

@description('Azure region.')
param location string

@description('Container App name.')
param name string

@description('Container Apps managed environment name.')
param environmentName string

@description('Log Analytics workspace resource ID.')
param logAnalyticsWorkspaceId string

@description('Log Analytics customer (workspace) ID.')
param logAnalyticsCustomerId string

@description('Resource ID of the user-assigned managed identity used for Key Vault access.')
param managedIdentityId string

@description('Container image. Pin by digest in production, not :latest.')
param containerImage string = 'vaultwarden/server:latest'

@description('Public HTTPS URL clients and Entra will use. Leave empty to use the generated Container Apps FQDN.')
param domain string = ''

@description('CPU cores per replica.')
param cpu string = '0.5'

@description('Memory per replica. Must pair with cpu: 0.5 CPU -> 1Gi.')
param memory string = '1Gi'

@description('Minimum replicas. Keep >= 1 when SCIM is enabled so Entra never hits a cold start.')
@minValue(0)
param minReplicas int = 1

@description('Maximum replicas.')
@minValue(1)
param maxReplicas int = 1

@description('Enable the SCIM v2 endpoints.')
param scimEnabled bool = true

@description('Enable the organization event log. Strongly recommended with SCIM: it is the provisioning audit trail.')
param orgEventsEnabled bool = true

@description('Enable organization groups. Required for SCIM Group sync.')
param orgGroupsEnabled bool = true

@description('Average seconds between SCIM requests from one IP before throttling.')
@minValue(1)
param scimRatelimitSeconds int = 1

@description('SCIM request burst allowance. Entra sends bursts during sync cycles.')
@minValue(1)
param scimRatelimitMaxBurst int = 60

@description('Allow open registration. Should be false for a provisioned deployment.')
param signupsAllowed bool = false

@description('Allow invitations (SCIM provisioning creates invites, so this must stay true).')
param invitationsAllowed bool = true

@description('Key Vault secret URI for DATABASE_URL. Empty falls back to the SQLite default.')
param databaseUrlSecretUri string = ''

@description('Key Vault secret URI for ADMIN_TOKEN. Empty leaves the admin panel disabled.')
param adminTokenSecretUri string = ''

@description('Key Vault secret URI for the SMTP credential. Empty disables mail.')
param smtpSecretUri string = ''

@description('SMTP host. Empty disables mail. SCIM invites need mail to reach users.')
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

@description('From address for outgoing mail.')
param smtpFrom string = ''

@description('Tags applied to resources.')
param tags object = {}

var mailConfigured = !empty(smtpHost)

resource environment 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: environmentName
  location: location
  tags: tags
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logAnalyticsCustomerId
        // Bicep resolves this at deploy time; the key never appears in source.
        sharedKey: listKeys(logAnalyticsWorkspaceId, '2023-09-01').primarySharedKey
      }
    }
  }
}

// Key Vault references, resolved by the platform using the managed identity.
// The secret VALUES never enter this template or the deployment history.
var databaseUrlSecret = empty(databaseUrlSecretUri) ? [] : [
  {
    name: 'database-url'
    keyVaultUrl: databaseUrlSecretUri
    identity: managedIdentityId
  }
]
var adminTokenSecret = empty(adminTokenSecretUri) ? [] : [
  {
    name: 'admin-token'
    keyVaultUrl: adminTokenSecretUri
    identity: managedIdentityId
  }
]
var smtpPasswordSecret = empty(smtpSecretUri) ? [] : [
  {
    name: 'smtp-password'
    keyVaultUrl: smtpSecretUri
    identity: managedIdentityId
  }
]

var baseEnv = [
  {
    // See the header: X-Real-IP (the Vaultwarden default) is not set by the
    // Container Apps ingress, so the SCIM rate limiter needs this.
    name: 'IP_HEADER'
    value: 'X-Forwarded-For'
  }
  {
    name: 'ROCKET_ADDRESS'
    value: '0.0.0.0'
  }
  {
    name: 'ROCKET_PORT'
    value: '80'
  }
  {
    name: 'SCIM_ENABLED'
    value: string(scimEnabled)
  }
  {
    name: 'ORG_EVENTS_ENABLED'
    value: string(orgEventsEnabled)
  }
  {
    name: 'ORG_GROUPS_ENABLED'
    value: string(orgGroupsEnabled)
  }
  {
    name: 'SCIM_RATELIMIT_SECONDS'
    value: string(scimRatelimitSeconds)
  }
  {
    name: 'SCIM_RATELIMIT_MAX_BURST'
    value: string(scimRatelimitMaxBurst)
  }
  {
    name: 'SIGNUPS_ALLOWED'
    value: string(signupsAllowed)
  }
  {
    name: 'INVITATIONS_ALLOWED'
    value: string(invitationsAllowed)
  }
]

var databaseEnv = empty(databaseUrlSecretUri) ? [] : [
  {
    name: 'DATABASE_URL'
    secretRef: 'database-url'
  }
]

var adminEnv = empty(adminTokenSecretUri) ? [] : [
  {
    name: 'ADMIN_TOKEN'
    secretRef: 'admin-token'
  }
]

var mailEnv = !mailConfigured ? [] : concat([
  {
    name: 'SMTP_HOST'
    value: smtpHost
  }
  {
    name: 'SMTP_PORT'
    value: string(smtpPort)
  }
  {
    name: 'SMTP_SECURITY'
    value: smtpSecurity
  }
  {
    name: 'SMTP_FROM'
    value: smtpFrom
  }
], empty(smtpUsername) ? [] : [
  {
    name: 'SMTP_USERNAME'
    value: smtpUsername
  }
], empty(smtpSecretUri) ? [] : [
  {
    name: 'SMTP_PASSWORD'
    secretRef: 'smtp-password'
  }
])

resource app 'Microsoft.App/containerApps@2024-03-01' = {
  name: name
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${managedIdentityId}': {}
    }
  }
  properties: {
    environmentId: environment.id
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: true
        targetPort: 80
        transport: 'auto'
        // TLS terminates here. Entra requires a publicly trusted HTTPS endpoint
        // and will not talk to plain HTTP, so redirect rather than serve both.
        allowInsecure: false
        traffic: [
          {
            latestRevision: true
            weight: 100
          }
        ]
      }
      secrets: concat(databaseUrlSecret, adminTokenSecret, smtpPasswordSecret)
    }
    template: {
      containers: [
        {
          name: 'vaultwarden'
          image: containerImage
          resources: {
            cpu: json(cpu)
            memory: memory
          }
          env: concat(baseEnv, databaseEnv, adminEnv, mailEnv, empty(domain) ? [] : [
            {
              name: 'DOMAIN'
              value: domain
            }
          ])
          probes: [
            {
              type: 'Liveness'
              httpGet: {
                path: '/alive'
                port: 80
              }
              initialDelaySeconds: 10
              periodSeconds: 30
            }
            {
              type: 'Readiness'
              httpGet: {
                path: '/alive'
                port: 80
              }
              initialDelaySeconds: 5
              periodSeconds: 10
            }
          ]
        }
      ]
      scale: {
        minReplicas: minReplicas
        maxReplicas: maxReplicas
      }
    }
  }
}

output fqdn string = app.properties.configuration.ingress.fqdn
output appUrl string = 'https://${app.properties.configuration.ingress.fqdn}'
output appName string = app.name
output scimEndpointHint string = 'https://${app.properties.configuration.ingress.fqdn}/scim/v2/<org_uuid>'
