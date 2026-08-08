// Key Vault holding the deployment's secrets.
//
// The Container App reads these through its user-assigned managed identity, so
// no secret value is ever stored in the Container App resource, in a workflow
// file, or in this repository. GitHub secrets feed the values in at deploy time
// and the vault holds them afterwards.

@description('Azure region.')
param location string

@description('Vault name. Must be globally unique, 3-24 chars, alphanumeric and hyphens.')
@minLength(3)
@maxLength(24)
param name string

@description('Principal ID of the identity that should be able to read secrets.')
param readerPrincipalId string

@description('Admin token (already argon2-hashed - see the README). Empty disables the admin panel.')
@secure()
param adminToken string = ''

@description('SMTP password. Empty when mail is not configured.')
@secure()
param smtpPassword string = ''

@description('Full DATABASE_URL connection string.')
@secure()
param databaseUrl string = ''

// Whether each secret is being created, passed in as plain booleans by the
// caller. The outputs below are secret URIs (safe to emit - they are addresses,
// not values), but deriving their condition from the @secure() parameters
// directly makes the Bicep linter treat the outputs as secret-bearing. Taking
// the condition as a non-secure input keeps the outputs provably clean.
@description('True when an admin token is being stored.')
param hasAdminToken bool = false

@description('True when an SMTP password is being stored.')
param hasSmtpPassword bool = false

@description('True when a database URL is being stored.')
param hasDatabaseUrl bool = false

@description('Tags applied to the vault.')
param tags object = {}

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
    // RBAC rather than access policies: access policies are legacy, and RBAC is
    // what lets the managed identity below be granted read-only cleanly.
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    // Deliberately ON. A vault holding the admin token and database credentials
    // should not be destroyable by an accidental `az group delete`.
    enablePurgeProtection: true
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      defaultAction: 'Allow'
      bypass: 'AzureServices'
    }
  }
}

// Secrets are only written when a value was supplied, so a deployment without
// mail does not create an empty smtp secret that looks configured.
resource adminTokenSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = if (hasAdminToken) {
  parent: vault
  name: 'admin-token'
  properties: {
    value: adminToken
  }
}

resource smtpPasswordSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = if (hasSmtpPassword) {
  parent: vault
  name: 'smtp-password'
  properties: {
    value: smtpPassword
  }
}

resource databaseUrlSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = if (hasDatabaseUrl) {
  parent: vault
  name: 'database-url'
  properties: {
    value: databaseUrl
  }
}

// Key Vault Secrets User: read secret VALUES, nothing else. Not Contributor.
//
// This GUID is Azure's published, built-in role definition id. It is the same
// in every tenant on earth and is documented public reference data, not a
// credential - but it is a high-entropy string next to the word "secret", so
// the scanner flags it. Allowed inline rather than by widening .gitleaks.toml,
// which would exempt the pattern repository-wide.
var secretsUserRoleId = '4633458b-17de-408a-b874-0445c86b69e6' // gitleaks:allow

resource secretsUserAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: vault
  name: guid(vault.id, readerPrincipalId, secretsUserRoleId)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', secretsUserRoleId)
    principalId: readerPrincipalId
    principalType: 'ServicePrincipal'
  }
}

output vaultUri string = vault.properties.vaultUri
output vaultName string = vault.name
output adminTokenSecretUri string = hasAdminToken ? '${vault.properties.vaultUri}secrets/admin-token' : ''
output smtpSecretUri string = hasSmtpPassword ? '${vault.properties.vaultUri}secrets/smtp-password' : ''
output databaseUrlSecretUri string = hasDatabaseUrl ? '${vault.properties.vaultUri}secrets/database-url' : ''
