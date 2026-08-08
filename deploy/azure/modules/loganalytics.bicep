// Log Analytics workspace: the Container Apps environment requires one, and it
// is also where SCIM request logs land. Worth keeping even on a minimal
// deployment - the SCIM audit story assumes you can retrieve request logs.

@description('Azure region for the workspace.')
param location string

@description('Workspace name.')
param name string

@description('Retention in days. 30 is the Azure minimum on the PerGB2018 SKU.')
@minValue(30)
@maxValue(730)
param retentionInDays int = 30

@description('Tags applied to the workspace.')
param tags object = {}

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: retentionInDays
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
}

output id string = workspace.id
output customerId string = workspace.properties.customerId
output name string = workspace.name
