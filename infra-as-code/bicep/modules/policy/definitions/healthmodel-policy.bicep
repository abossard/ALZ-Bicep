targetScope = 'subscription'

// healthmodel-policy: DeployIfNotExists policy that provisions a Microsoft.CloudHealth
// platform health model with one per-domain discovery rule (Security, Connectivity,
// Management, Identity). See healthmodel-policy.README.md for concepts, parameters,
// and deploy/verify steps.

// Parameters (single source of defaults; the policy definition below carries no defaultValue)

@description('Location for the discovery identity, policy assignment identity and remediation deployments. Must support Microsoft.CloudHealth (for example uksouth, centralus, swedencentral, northeurope).')
param location string = 'uksouth'

@description('Resource group the platform health model is deployed into. Must already exist.')
param targetResourceGroupName string = 'rg-alz-healthmodels'

@description('Platform health model name to deploy. One model carries all four domain discovery rules.')
param healthModelName string = 'alz-platform-healthmodel'

@description('Name of the user-assigned managed identity the discovery rules run as.')
param identityName string = 'alz-healthmodel-mi'

@description('Policy definition name.')
param policyName string = 'Deploy-ALZ-CloudHealth-PlatformModel'

@description('Policy assignment name.')
@maxLength(24)
param assignmentName string = 'Deploy-ALZ-CloudHealth'

@description('Policy effect.')
@allowed([
  'DeployIfNotExists'
  'Disabled'
])
param effect string = 'DeployIfNotExists'

@description('Enforcement mode for the assignment.')
@allowed([
  'Default'
  'DoNotEnforce'
])
param enforcementMode string = 'Default'

@description('Resource types added to EVERY domain\'s discovery query (unioned with the per-domain list). Empty by default: an operator hook to inject a type across all domains. Pick monitorable types - resources such as resource groups have no health signals.')
param includedResourceTypesGlobal array = []

@description('Resource types discovered for the Security platform domain (unioned with the global list). Override to add/replace Security types.')
param securityResourceTypes array = [
  'Microsoft.KeyVault/vaults'
  'Microsoft.Network/azureFirewalls'
  'Microsoft.Network/firewallPolicies'
  'Microsoft.Network/ddosProtectionPlans'
]

@description('Resource types discovered for the Connectivity platform domain (unioned with the global list). Override to add/replace Connectivity types.')
param connectivityResourceTypes array = [
  'Microsoft.Network/virtualNetworks'
  'Microsoft.Network/virtualNetworkGateways'
  'Microsoft.Network/expressRouteCircuits'
  'Microsoft.Network/publicIPAddresses'
  'Microsoft.Network/loadBalancers'
  'Microsoft.Network/applicationGateways'
  'Microsoft.Network/privateDnsZones'
  'Microsoft.Network/bastionHosts'
  'Microsoft.Network/natGateways'
  'Microsoft.Network/connections'
]

@description('Resource types discovered for the Management platform domain (unioned with the global list). Override to add/replace Management types.')
param managementResourceTypes array = [
  'Microsoft.OperationalInsights/workspaces'
  'Microsoft.Automation/automationAccounts'
  'Microsoft.RecoveryServices/vaults'
  'Microsoft.Storage/storageAccounts'
  'Microsoft.Insights/components'
  'Microsoft.Insights/actionGroups'
]

@description('Resource types discovered for the Identity platform domain (unioned with the global list). Override to add/replace Identity types.')
param identityResourceTypes array = [
  'Microsoft.ManagedIdentity/userAssignedIdentities'
  'Microsoft.Compute/virtualMachines'
  'Microsoft.KeyVault/vaults'
  'Microsoft.Network/privateDnsZones'
]

@description('Optional subscription id to scope the Security domain discovery to. Empty = discover across every subscription the discovery identity can read.')
param securitySubscriptionId string = ''

@description('Optional subscription id to scope the Connectivity domain discovery to. Empty = discover across every subscription the discovery identity can read.')
param connectivitySubscriptionId string = ''

@description('Optional subscription id to scope the Management domain discovery to. Empty = discover across every subscription the discovery identity can read.')
param managementSubscriptionId string = ''

@description('Optional subscription id to scope the Identity domain discovery to. Empty = discover across every subscription the discovery identity can read.')
param identitySubscriptionId string = ''

@description('Optional full Resource Graph query override for the Security domain. Leave empty to auto-build from securityResourceTypes + includedResourceTypesGlobal (and securitySubscriptionId if set). If set, it is used verbatim.')
param securityQueryOverride string = ''

@description('Optional full Resource Graph query override for the Connectivity domain. Leave empty to auto-build from connectivityResourceTypes + includedResourceTypesGlobal (and connectivitySubscriptionId if set). If set, it is used verbatim.')
param connectivityQueryOverride string = ''

@description('Optional full Resource Graph query override for the Management domain. Leave empty to auto-build from managementResourceTypes + includedResourceTypesGlobal (and managementSubscriptionId if set). If set, it is used verbatim.')
param managementQueryOverride string = ''

@description('Optional full Resource Graph query override for the Identity domain. Leave empty to auto-build from identityResourceTypes + includedResourceTypesGlobal (and identitySubscriptionId if set). If set, it is used verbatim.')
param identityQueryOverride string = ''

// Variables

var builtInRoleIds = {
  Contributor: 'b24988ac-6180-42a0-ab88-20f7382dd24c'
  ManagedIdentityOperator: 'f1a07417-d97a-45cb-824c-7a7467783830'
  Reader: 'acdd72a7-3385-48ef-bd42-f606fba81ae7'
}

// Roles the policy assignment (remediation) identity needs: write CloudHealth
// resources and attach the discovery identity. Reader is granted only to the
// discovery identity below, not here.
var remediationRoleIds = {
  Contributor: builtInRoleIds.Contributor
  ManagedIdentityOperator: builtInRoleIds.ManagedIdentityOperator
}

var authenticationSettingName = 'managed-identity'

resource targetResourceGroup 'Microsoft.Resources/resourceGroups@2025-04-01' existing = {
  name: targetResourceGroupName
}

// Discovery identity (resource-group-scoped module)

module discoveryIdentity 'healthmodel-discovery-identity.bicep' = {
  scope: targetResourceGroup
  name: 'alz-healthmodel-identity'
  params: {
    identityName: identityName
    location: location
  }
}

resource discoverySubscriptionReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, identityName, builtInRoleIds.Reader)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', builtInRoleIds.Reader)
    principalId: discoveryIdentity.outputs.principalId
    principalType: 'ServicePrincipal'
  }
}

// Policy definition (DeployIfNotExists)

resource policyDefinition 'Microsoft.Authorization/policyDefinitions@2025-01-01' = {
  name: policyName
  properties: {
    displayName: 'Deploy a Microsoft CloudHealth platform health model with per-domain discovery rules'
    description: 'Deploys a Microsoft.CloudHealth platform health model with one discovery rule per platform domain (Security, Connectivity, Management, Identity), each discovering resources by type, when missing.'
    policyType: 'Custom'
    mode: 'All'
    metadata: {
      category: 'Monitoring'
      version: '4.0.0'
      preview: true
    }
    parameters: {
      effect: {
        type: 'String'
        allowedValues: [
          'DeployIfNotExists'
          'Disabled'
        ]
        metadata: {
          displayName: 'Effect'
          description: 'Enable (DeployIfNotExists) or turn off (Disabled) automatic deployment of the platform health model when it is missing.'
        }
      }
      targetResourceGroupName: {
        type: 'String'
        metadata: {
          displayName: 'Target resource group'
          description: 'Name of the existing resource group the platform health model is deployed into. The rule triggers on this resource group and its compliance is driven by whether the model exists here.'
        }
      }
      healthModelName: {
        type: 'String'
        metadata: {
          displayName: 'Health model name'
          description: 'Name of the Microsoft.CloudHealth health model to deploy. One model holds all four domain discovery rules.'
        }
      }
      location: {
        type: 'String'
        metadata: {
          displayName: 'Location'
          description: 'Azure region for the health model and remediation deployment. Must support Microsoft.CloudHealth (for example uksouth, centralus, swedencentral, northeurope).'
        }
      }
      userAssignedIdentityId: {
        type: 'String'
        metadata: {
          displayName: 'Discovery identity id'
          description: 'Resource id of the user-assigned managed identity the discovery rules run as. Set automatically from the identity module; its read scope determines which subscriptions discovery can see.'
        }
      }
      authenticationSettingName: {
        type: 'String'
        metadata: {
          displayName: 'Authentication setting name'
          description: 'Name of the health model authentication setting that binds the discovery identity to the model.'
        }
      }
      includedResourceTypesGlobal: {
        type: 'Array'
        metadata: {
          displayName: 'Global included resource types'
          description: 'Resource types added to every domain discovery query, unioned with each per-domain list. Empty by default; use it to add one type across all domains.'
        }
      }
      securityResourceTypes: {
        type: 'Array'
        metadata: {
          displayName: 'Security resource types'
          description: 'Resource types discovered for the Security platform domain, unioned with the global list to form that domain query.'
        }
      }
      connectivityResourceTypes: {
        type: 'Array'
        metadata: {
          displayName: 'Connectivity resource types'
          description: 'Resource types discovered for the Connectivity platform domain, unioned with the global list to form that domain query.'
        }
      }
      managementResourceTypes: {
        type: 'Array'
        metadata: {
          displayName: 'Management resource types'
          description: 'Resource types discovered for the Management platform domain, unioned with the global list to form that domain query.'
        }
      }
      identityResourceTypes: {
        type: 'Array'
        metadata: {
          displayName: 'Identity resource types'
          description: 'Resource types discovered for the Identity platform domain, unioned with the global list to form that domain query.'
        }
      }
      securitySubscriptionId: {
        type: 'String'
        metadata: {
          displayName: 'Security subscription id'
          description: 'Optional. Scope Security discovery to a single subscription id (adds a where subscriptionId clause). Empty discovers across every subscription the identity can read - set this when Security lives in its own platform subscription.'
        }
      }
      connectivitySubscriptionId: {
        type: 'String'
        metadata: {
          displayName: 'Connectivity subscription id'
          description: 'Optional. Scope Connectivity discovery to a single subscription id (adds a where subscriptionId clause). Empty discovers across every subscription the identity can read - set this when Connectivity lives in its own platform subscription.'
        }
      }
      managementSubscriptionId: {
        type: 'String'
        metadata: {
          displayName: 'Management subscription id'
          description: 'Optional. Scope Management discovery to a single subscription id (adds a where subscriptionId clause). Empty discovers across every subscription the identity can read - set this when Management lives in its own platform subscription.'
        }
      }
      identitySubscriptionId: {
        type: 'String'
        metadata: {
          displayName: 'Identity subscription id'
          description: 'Optional. Scope Identity discovery to a single subscription id (adds a where subscriptionId clause). Empty discovers across every subscription the identity can read - set this when Identity lives in its own platform subscription.'
        }
      }
      securityQueryOverride: {
        type: 'String'
        metadata: {
          displayName: 'Security query override'
          description: 'Optional. Full Resource Graph query used verbatim for the Security domain. Empty auto-builds the query from Security and global resource types (and the Security subscription id when set).'
        }
      }
      connectivityQueryOverride: {
        type: 'String'
        metadata: {
          displayName: 'Connectivity query override'
          description: 'Optional. Full Resource Graph query used verbatim for the Connectivity domain. Empty auto-builds the query from Connectivity and global resource types (and the Connectivity subscription id when set).'
        }
      }
      managementQueryOverride: {
        type: 'String'
        metadata: {
          displayName: 'Management query override'
          description: 'Optional. Full Resource Graph query used verbatim for the Management domain. Empty auto-builds the query from Management and global resource types (and the Management subscription id when set).'
        }
      }
      identityQueryOverride: {
        type: 'String'
        metadata: {
          displayName: 'Identity query override'
          description: 'Optional. Full Resource Graph query used verbatim for the Identity domain. Empty auto-builds the query from Identity and global resource types (and the Identity subscription id when set).'
        }
      }
    }
    policyRule: {
      if: {
        allOf: [
          {
            field: 'type'
            equals: 'Microsoft.Resources/subscriptions/resourceGroups'
          }
          {
            field: 'name'
            equals: '[parameters(\'targetResourceGroupName\')]'
          }
        ]
      }
      then: {
        effect: '[parameters(\'effect\')]'
        details: {
          type: 'Microsoft.CloudHealth/healthmodels'
          existenceScope: 'resourceGroup'
          existenceCondition: {
            field: 'name'
            equals: '[parameters(\'healthModelName\')]'
          }
          deploymentScope: 'resourceGroup'
          roleDefinitionIds: [
            '/providers/Microsoft.Authorization/roleDefinitions/${builtInRoleIds.Contributor}'
            '/providers/Microsoft.Authorization/roleDefinitions/${builtInRoleIds.ManagedIdentityOperator}'
          ]
          deployment: {
            properties: {
              mode: 'Incremental'
              parameters: {
                healthModelName: {
                  value: '[parameters(\'healthModelName\')]'
                }
                location: {
                  value: '[parameters(\'location\')]'
                }
                userAssignedIdentityId: {
                  value: '[parameters(\'userAssignedIdentityId\')]'
                }
                authenticationSettingName: {
                  value: '[parameters(\'authenticationSettingName\')]'
                }
                includedResourceTypesGlobal: {
                  value: '[parameters(\'includedResourceTypesGlobal\')]'
                }
                securityResourceTypes: {
                  value: '[parameters(\'securityResourceTypes\')]'
                }
                connectivityResourceTypes: {
                  value: '[parameters(\'connectivityResourceTypes\')]'
                }
                managementResourceTypes: {
                  value: '[parameters(\'managementResourceTypes\')]'
                }
                identityResourceTypes: {
                  value: '[parameters(\'identityResourceTypes\')]'
                }
                securitySubscriptionId: {
                  value: '[parameters(\'securitySubscriptionId\')]'
                }
                connectivitySubscriptionId: {
                  value: '[parameters(\'connectivitySubscriptionId\')]'
                }
                managementSubscriptionId: {
                  value: '[parameters(\'managementSubscriptionId\')]'
                }
                identitySubscriptionId: {
                  value: '[parameters(\'identitySubscriptionId\')]'
                }
                securityQueryOverride: {
                  value: '[parameters(\'securityQueryOverride\')]'
                }
                connectivityQueryOverride: {
                  value: '[parameters(\'connectivityQueryOverride\')]'
                }
                managementQueryOverride: {
                  value: '[parameters(\'managementQueryOverride\')]'
                }
                identityQueryOverride: {
                  value: '[parameters(\'identityQueryOverride\')]'
                }
              }
              template: {
                '$schema': 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
                contentVersion: '1.0.0.0'
                parameters: {
                  healthModelName: {
                    type: 'string'
                  }
                  location: {
                    type: 'string'
                  }
                  userAssignedIdentityId: {
                    type: 'string'
                  }
                  authenticationSettingName: {
                    type: 'string'
                  }
                  includedResourceTypesGlobal: {
                    type: 'array'
                  }
                  securityResourceTypes: {
                    type: 'array'
                  }
                  connectivityResourceTypes: {
                    type: 'array'
                  }
                  managementResourceTypes: {
                    type: 'array'
                  }
                  identityResourceTypes: {
                    type: 'array'
                  }
                  securitySubscriptionId: {
                    type: 'string'
                  }
                  connectivitySubscriptionId: {
                    type: 'string'
                  }
                  managementSubscriptionId: {
                    type: 'string'
                  }
                  identitySubscriptionId: {
                    type: 'string'
                  }
                  securityQueryOverride: {
                    type: 'string'
                  }
                  connectivityQueryOverride: {
                    type: 'string'
                  }
                  managementQueryOverride: {
                    type: 'string'
                  }
                  identityQueryOverride: {
                    type: 'string'
                  }
                }
                variables: {
                  securityTypes: '[union(parameters(\'includedResourceTypesGlobal\'), parameters(\'securityResourceTypes\'))]'
                  securitySubFilter: '[if(empty(parameters(\'securitySubscriptionId\')), \'\', concat(\'where subscriptionId =~ \'\'\', parameters(\'securitySubscriptionId\'), \'\'\' | \'))]'
                  securityAutoQuery: '[concat(\'resources | \', variables(\'securitySubFilter\'), \'where type in~ (\', concat(\'\'\'\', join(variables(\'securityTypes\'), \'\'\',\'\'\'), \'\'\'\'), \') | project id\')]'
                  securityQuery: '[if(empty(parameters(\'securityQueryOverride\')), variables(\'securityAutoQuery\'), parameters(\'securityQueryOverride\'))]'
                  connectivityTypes: '[union(parameters(\'includedResourceTypesGlobal\'), parameters(\'connectivityResourceTypes\'))]'
                  connectivitySubFilter: '[if(empty(parameters(\'connectivitySubscriptionId\')), \'\', concat(\'where subscriptionId =~ \'\'\', parameters(\'connectivitySubscriptionId\'), \'\'\' | \'))]'
                  connectivityAutoQuery: '[concat(\'resources | \', variables(\'connectivitySubFilter\'), \'where type in~ (\', concat(\'\'\'\', join(variables(\'connectivityTypes\'), \'\'\',\'\'\'), \'\'\'\'), \') | project id\')]'
                  connectivityQuery: '[if(empty(parameters(\'connectivityQueryOverride\')), variables(\'connectivityAutoQuery\'), parameters(\'connectivityQueryOverride\'))]'
                  managementTypes: '[union(parameters(\'includedResourceTypesGlobal\'), parameters(\'managementResourceTypes\'))]'
                  managementSubFilter: '[if(empty(parameters(\'managementSubscriptionId\')), \'\', concat(\'where subscriptionId =~ \'\'\', parameters(\'managementSubscriptionId\'), \'\'\' | \'))]'
                  managementAutoQuery: '[concat(\'resources | \', variables(\'managementSubFilter\'), \'where type in~ (\', concat(\'\'\'\', join(variables(\'managementTypes\'), \'\'\',\'\'\'), \'\'\'\'), \') | project id\')]'
                  managementQuery: '[if(empty(parameters(\'managementQueryOverride\')), variables(\'managementAutoQuery\'), parameters(\'managementQueryOverride\'))]'
                  identityTypes: '[union(parameters(\'includedResourceTypesGlobal\'), parameters(\'identityResourceTypes\'))]'
                  identitySubFilter: '[if(empty(parameters(\'identitySubscriptionId\')), \'\', concat(\'where subscriptionId =~ \'\'\', parameters(\'identitySubscriptionId\'), \'\'\' | \'))]'
                  identityAutoQuery: '[concat(\'resources | \', variables(\'identitySubFilter\'), \'where type in~ (\', concat(\'\'\'\', join(variables(\'identityTypes\'), \'\'\',\'\'\'), \'\'\'\'), \') | project id\')]'
                  identityQuery: '[if(empty(parameters(\'identityQueryOverride\')), variables(\'identityAutoQuery\'), parameters(\'identityQueryOverride\'))]'
                }
                resources: [
                  {
                    type: 'Microsoft.CloudHealth/healthmodels'
                    apiVersion: '2026-05-01-preview'
                    name: '[parameters(\'healthModelName\')]'
                    location: '[parameters(\'location\')]'
                    identity: {
                      type: 'UserAssigned'
                      userAssignedIdentities: {
                        '[parameters(\'userAssignedIdentityId\')]': {}
                      }
                    }
                    properties: {}
                  }
                  {
                    type: 'Microsoft.CloudHealth/healthmodels/authenticationsettings'
                    apiVersion: '2026-05-01-preview'
                    name: '[format(\'{0}/{1}\', parameters(\'healthModelName\'), parameters(\'authenticationSettingName\'))]'
                    properties: {
                      authenticationKind: 'ManagedIdentity'
                      managedIdentityName: '[parameters(\'userAssignedIdentityId\')]'
                    }
                    dependsOn: [
                      '[resourceId(\'Microsoft.CloudHealth/healthmodels\', parameters(\'healthModelName\'))]'
                    ]
                  }
                  {
                    type: 'Microsoft.CloudHealth/healthmodels/discoveryrules'
                    apiVersion: '2026-05-01-preview'
                    name: '[format(\'{0}/discover-security\', parameters(\'healthModelName\'))]'
                    properties: {
                      displayName: 'Security platform resources'
                      authenticationSetting: '[parameters(\'authenticationSettingName\')]'
                      addRecommendedSignals: 'Enabled'
                      addResourceHealthSignal: 'Enabled'
                      discoverRelationships: 'Disabled'
                      specification: {
                        kind: 'ResourceGraphQuery'
                        resourceGraphQuery: '[variables(\'securityQuery\')]'
                      }
                    }
                    dependsOn: [
                      '[resourceId(\'Microsoft.CloudHealth/healthmodels/authenticationsettings\', parameters(\'healthModelName\'), parameters(\'authenticationSettingName\'))]'
                    ]
                  }
                  {
                    type: 'Microsoft.CloudHealth/healthmodels/discoveryrules'
                    apiVersion: '2026-05-01-preview'
                    name: '[format(\'{0}/discover-connectivity\', parameters(\'healthModelName\'))]'
                    properties: {
                      displayName: 'Connectivity platform resources'
                      authenticationSetting: '[parameters(\'authenticationSettingName\')]'
                      addRecommendedSignals: 'Enabled'
                      addResourceHealthSignal: 'Enabled'
                      discoverRelationships: 'Disabled'
                      specification: {
                        kind: 'ResourceGraphQuery'
                        resourceGraphQuery: '[variables(\'connectivityQuery\')]'
                      }
                    }
                    dependsOn: [
                      '[resourceId(\'Microsoft.CloudHealth/healthmodels/authenticationsettings\', parameters(\'healthModelName\'), parameters(\'authenticationSettingName\'))]'
                    ]
                  }
                  {
                    type: 'Microsoft.CloudHealth/healthmodels/discoveryrules'
                    apiVersion: '2026-05-01-preview'
                    name: '[format(\'{0}/discover-management\', parameters(\'healthModelName\'))]'
                    properties: {
                      displayName: 'Management platform resources'
                      authenticationSetting: '[parameters(\'authenticationSettingName\')]'
                      addRecommendedSignals: 'Enabled'
                      addResourceHealthSignal: 'Enabled'
                      discoverRelationships: 'Disabled'
                      specification: {
                        kind: 'ResourceGraphQuery'
                        resourceGraphQuery: '[variables(\'managementQuery\')]'
                      }
                    }
                    dependsOn: [
                      '[resourceId(\'Microsoft.CloudHealth/healthmodels/authenticationsettings\', parameters(\'healthModelName\'), parameters(\'authenticationSettingName\'))]'
                    ]
                  }
                  {
                    type: 'Microsoft.CloudHealth/healthmodels/discoveryrules'
                    apiVersion: '2026-05-01-preview'
                    name: '[format(\'{0}/discover-identity\', parameters(\'healthModelName\'))]'
                    properties: {
                      displayName: 'Identity platform resources'
                      authenticationSetting: '[parameters(\'authenticationSettingName\')]'
                      addRecommendedSignals: 'Enabled'
                      addResourceHealthSignal: 'Enabled'
                      discoverRelationships: 'Disabled'
                      specification: {
                        kind: 'ResourceGraphQuery'
                        resourceGraphQuery: '[variables(\'identityQuery\')]'
                      }
                    }
                    dependsOn: [
                      '[resourceId(\'Microsoft.CloudHealth/healthmodels/authenticationsettings\', parameters(\'healthModelName\'), parameters(\'authenticationSettingName\'))]'
                    ]
                  }
                  {
                    type: 'Microsoft.CloudHealth/healthmodels/relationships'
                    apiVersion: '2026-05-01-preview'
                    name: '[format(\'{0}/root-to-discover-security\', parameters(\'healthModelName\'))]'
                    properties: {
                      parentEntityName: '[parameters(\'healthModelName\')]'
                      childEntityName: 'discover-security'
                    }
                    dependsOn: [
                      '[resourceId(\'Microsoft.CloudHealth/healthmodels/discoveryrules\', parameters(\'healthModelName\'), \'discover-security\')]'
                    ]
                  }
                  {
                    type: 'Microsoft.CloudHealth/healthmodels/relationships'
                    apiVersion: '2026-05-01-preview'
                    name: '[format(\'{0}/root-to-discover-connectivity\', parameters(\'healthModelName\'))]'
                    properties: {
                      parentEntityName: '[parameters(\'healthModelName\')]'
                      childEntityName: 'discover-connectivity'
                    }
                    dependsOn: [
                      '[resourceId(\'Microsoft.CloudHealth/healthmodels/discoveryrules\', parameters(\'healthModelName\'), \'discover-connectivity\')]'
                    ]
                  }
                  {
                    type: 'Microsoft.CloudHealth/healthmodels/relationships'
                    apiVersion: '2026-05-01-preview'
                    name: '[format(\'{0}/root-to-discover-management\', parameters(\'healthModelName\'))]'
                    properties: {
                      parentEntityName: '[parameters(\'healthModelName\')]'
                      childEntityName: 'discover-management'
                    }
                    dependsOn: [
                      '[resourceId(\'Microsoft.CloudHealth/healthmodels/discoveryrules\', parameters(\'healthModelName\'), \'discover-management\')]'
                    ]
                  }
                  {
                    type: 'Microsoft.CloudHealth/healthmodels/relationships'
                    apiVersion: '2026-05-01-preview'
                    name: '[format(\'{0}/root-to-discover-identity\', parameters(\'healthModelName\'))]'
                    properties: {
                      parentEntityName: '[parameters(\'healthModelName\')]'
                      childEntityName: 'discover-identity'
                    }
                    dependsOn: [
                      '[resourceId(\'Microsoft.CloudHealth/healthmodels/discoveryrules\', parameters(\'healthModelName\'), \'discover-identity\')]'
                    ]
                  }
                ]
              }
            }
          }
        }
      }
    }
  }
}

// Policy assignment

resource policyAssignment 'Microsoft.Authorization/policyAssignments@2025-01-01' = {
  name: assignmentName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    displayName: 'Deploy CloudHealth platform health model with per-domain discovery'
    policyDefinitionId: policyDefinition.id
    enforcementMode: enforcementMode
    parameters: {
      effect: {
        value: effect
      }
      targetResourceGroupName: {
        value: targetResourceGroupName
      }
      healthModelName: {
        value: healthModelName
      }
      location: {
        value: location
      }
      userAssignedIdentityId: {
        value: discoveryIdentity.outputs.identityId
      }
      authenticationSettingName: {
        value: authenticationSettingName
      }
      includedResourceTypesGlobal: {
        value: includedResourceTypesGlobal
      }
      securityResourceTypes: {
        value: securityResourceTypes
      }
      connectivityResourceTypes: {
        value: connectivityResourceTypes
      }
      managementResourceTypes: {
        value: managementResourceTypes
      }
      identityResourceTypes: {
        value: identityResourceTypes
      }
      securitySubscriptionId: {
        value: securitySubscriptionId
      }
      connectivitySubscriptionId: {
        value: connectivitySubscriptionId
      }
      managementSubscriptionId: {
        value: managementSubscriptionId
      }
      identitySubscriptionId: {
        value: identitySubscriptionId
      }
      securityQueryOverride: {
        value: securityQueryOverride
      }
      connectivityQueryOverride: {
        value: connectivityQueryOverride
      }
      managementQueryOverride: {
        value: managementQueryOverride
      }
      identityQueryOverride: {
        value: identityQueryOverride
      }
    }
  }
}

resource roleAssignments 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for role in items(remediationRoleIds): {
    name: guid(subscription().id, assignmentName, role.value)
    properties: {
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', role.value)
      principalId: policyAssignment.identity.principalId
      principalType: 'ServicePrincipal'
    }
  }
]

// Outputs

output policyDefinitionId string = policyDefinition.id
output policyAssignmentId string = policyAssignment.id
output discoveryIdentityId string = discoveryIdentity.outputs.identityId
