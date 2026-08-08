// PostgreSQL Flexible Server for Vaultwarden.
//
// Why PostgreSQL rather than the default SQLite for anything beyond a trial:
// `users_organizations` is global across every organization on the server, not
// per-org, and the SCIM hot path queries it on every provisioned user. SQLite on
// a Container Apps ephemeral filesystem also loses the database on every
// revision restart unless a volume is attached.
//
// Deployments that genuinely want SQLite should set deployPostgres=false in
// main.bicep and attach a storage volume instead; see the README.

@description('Azure region.')
param location string

@description('Server name. Must be globally unique within the postgres.database.azure.com namespace.')
param name string

@description('Administrator login. Not a secret, but not guessable is still better.')
param administratorLogin string

@description('Administrator password. Supply from a GitHub secret; never commit it.')
@secure()
param administratorPassword string

@description('Compute SKU. Burstable B1ms is the cheapest that runs this workload sensibly.')
param skuName string = 'Standard_B1ms'

@description('SKU tier matching skuName.')
@allowed([
  'Burstable'
  'GeneralPurpose'
  'MemoryOptimized'
])
param skuTier string = 'Burstable'

@description('Storage in GB. 32 is the Flexible Server minimum.')
@minValue(32)
param storageSizeGB int = 32

@description('PostgreSQL major version.')
@allowed([
  '14'
  '15'
  '16'
])
param version string = '16'

@description('Backup retention in days.')
@minValue(7)
@maxValue(35)
param backupRetentionDays int = 7

@description('Enable geo-redundant backup. Not available on Burstable tiers.')
param geoRedundantBackup bool = false

@description('Name of the application database created on the server.')
param databaseName string = 'vaultwarden'

@description('Tags applied to the server.')
param tags object = {}

resource server 'Microsoft.DBforPostgreSQL/flexibleServers@2024-08-01' = {
  name: name
  location: location
  tags: tags
  sku: {
    name: skuName
    tier: skuTier
  }
  properties: {
    version: version
    administratorLogin: administratorLogin
    administratorLoginPassword: administratorPassword
    storage: {
      storageSizeGB: storageSizeGB
    }
    backup: {
      backupRetentionDays: backupRetentionDays
      geoRedundantBackup: geoRedundantBackup ? 'Enabled' : 'Disabled'
    }
    highAvailability: {
      mode: 'Disabled'
    }
    // Public networking with a firewall rule for Azure services. Locking this
    // down to a VNet is the right move for a production financial-services
    // deployment; see the README's hardening section, which needs a delegated
    // subnet and is therefore not something a generic template can assume.
    network: {
      publicNetworkAccess: 'Enabled'
    }
  }
}

resource database 'Microsoft.DBforPostgreSQL/flexibleServers/databases@2024-08-01' = {
  parent: server
  name: databaseName
  properties: {
    charset: 'UTF8'
    collation: 'en_US.utf8'
  }
}

// Container Apps egresses from shared Azure address space, so this rule is what
// makes the app reachable at all without a VNet. The 0.0.0.0 start/end pair is
// Azure's documented sentinel for "Azure services", NOT the whole internet.
resource allowAzureServices 'Microsoft.DBforPostgreSQL/flexibleServers/firewallRules@2024-08-01' = {
  parent: server
  name: 'AllowAllAzureServicesAndResourcesWithinAzureIps'
  properties: {
    startIpAddress: '0.0.0.0'
    endIpAddress: '0.0.0.0'
  }
}

output fqdn string = server.properties.fullyQualifiedDomainName
output databaseName string = database.name
output serverName string = server.name
