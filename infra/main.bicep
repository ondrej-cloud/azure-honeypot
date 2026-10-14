// Azure honeypot: one small Ubuntu VM running Cowrie, a locked-down storage
// account for its logs, and a secretless identity that lets GitHub Actions
// read those logs. Nothing in here hands out a password, key or SAS token.

@description('Azure region. Defaults to the resource group location.')
param location string = resourceGroup().location

@description('Lowercase letters/digits used as a prefix for resource names.')
@minLength(3)
@maxLength(8)
param prefix string = 'hpot'

@description('VM size. B1s (1 vCPU, 1 GiB RAM) is in the Azure free tier and is plenty for Cowrie.')
param vmSize string = 'Standard_B1s'

@description('Your public IP as CIDR, e.g. 203.0.113.7/32. Only this address can reach the real SSH port.')
param adminSourceCidr string

@description('SSH public key for the admin user.')
param sshPublicKey string

@description('Admin user on the VM.')
param adminUsername string = 'azureuser'

@description('Port of the real OpenSSH daemon. Port 22 is taken by the honeypot.')
param adminSshPort int = 22222

@description('GitHub repository (owner/name) whose main-branch workflow may read the logs.')
param githubRepo string

@description('Start of the OIDC subject GitHub signs for that repository. Newer repositories use immutable IDs (repo:owner@123/name@456); deploy.sh reads the right one from the GitHub API.')
param githubSubjectPrefix string = 'repo:${githubRepo}'

@description('Object ID of your Entra ID user, granted read access to the raw logs. Empty to skip.')
param adminPrincipalId string = ''

var suffix = uniqueString(resourceGroup().id)
var sensorName = 'azure-${location}'

var roles = {
  blobDataContributor: 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
  blobDataReader: '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1'
}

// ---------------------------------------------------------------- storage

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: '${prefix}${suffix}'
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    accessTier: 'Hot'
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false // Entra ID only: account keys and SAS tokens are disabled
    defaultToOAuthAuthentication: true
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storage
  name: 'default'
  properties: {
    // A compromised VM could overwrite or delete logs; soft delete keeps a way back.
    deleteRetentionPolicy: { enabled: true, days: 7 }
  }
}

resource logsContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: 'logs'
  properties: { publicAccess: 'None' }
}

// ---------------------------------------------------------------- network

resource nsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: '${prefix}-nsg'
  location: location
  properties: {
    securityRules: [
      {
        name: 'Allow-Honeypot-SSH'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '22'
        }
      }
      {
        name: 'Allow-Honeypot-Telnet'
        properties: {
          priority: 110
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '23'
        }
      }
      {
        name: 'Allow-Admin-SSH'
        properties: {
          priority: 120
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: adminSourceCidr
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: string(adminSshPort)
        }
      }
    ]
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: '${prefix}-vnet'
  location: location
  properties: {
    addressSpace: { addressPrefixes: ['10.42.0.0/24'] }
    subnets: [
      {
        name: 'sensor'
        properties: {
          addressPrefix: '10.42.0.0/27'
          networkSecurityGroup: { id: nsg.id }
        }
      }
    ]
  }
}

resource publicIp 'Microsoft.Network/publicIPAddresses@2024-05-01' = {
  name: '${prefix}-pip'
  location: location
  sku: { name: 'Standard' }
  properties: {
    publicIPAllocationMethod: 'Static'
    publicIPAddressVersion: 'IPv4'
  }
}

resource nic 'Microsoft.Network/networkInterfaces@2024-05-01' = {
  name: '${prefix}-nic'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: { id: vnet.properties.subnets[0].id }
          privateIPAllocationMethod: 'Dynamic'
          publicIPAddress: { id: publicIp.id }
        }
      }
    ]
  }
}

// ---------------------------------------------------------------- sensor VM

var cloudInit = reduce(
  [
    { key: '__STORAGE_ACCOUNT__', value: storage.name }
    { key: '__SENSOR_NAME__', value: sensorName }
    { key: '__ADMIN_SSH_PORT__', value: string(adminSshPort) }
    { key: '__COMPOSE_B64__', value: loadFileAsBase64('../sensor/docker-compose.yml') }
    { key: '__SHIPPER_B64__', value: loadFileAsBase64('../sensor/shipper.py') }
  ],
  loadTextContent('cloud-init.yaml'),
  (text, item) => replace(text, item.key, item.value)
)

resource vm 'Microsoft.Compute/virtualMachines@2024-07-01' = {
  name: '${prefix}-vm'
  location: location
  identity: { type: 'SystemAssigned' }
  properties: {
    hardwareProfile: { vmSize: vmSize }
    osProfile: {
      computerName: 'srv-db01'
      adminUsername: adminUsername
      customData: base64(cloudInit)
      linuxConfiguration: {
        disablePasswordAuthentication: true
        ssh: {
          publicKeys: [
            {
              path: '/home/${adminUsername}/.ssh/authorized_keys'
              keyData: sshPublicKey
            }
          ]
        }
      }
    }
    storageProfile: {
      imageReference: {
        publisher: 'Canonical'
        offer: 'ubuntu-24_04-lts'
        sku: 'server'
        version: 'latest'
      }
      osDisk: {
        createOption: 'FromImage'
        diskSizeGB: 64
        managedDisk: { storageAccountType: 'Premium_LRS' } // P6, part of the 12-month free tier
        deleteOption: 'Delete'
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nic.id
          properties: { deleteOption: 'Delete' }
        }
      ]
    }
    diagnosticsProfile: {
      bootDiagnostics: { enabled: true } // enables the serial console if SSH ever breaks
    }
  }
}

// ---------------------------------------------------------------- identities & access

// The VM writes logs with its own managed identity, scoped to one container.
resource vmWritesLogs 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(logsContainer.id, vm.id, roles.blobDataContributor)
  scope: logsContainer
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.blobDataContributor)
    principalId: vm.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// GitHub Actions trades its OIDC token for this identity: no secret in the repo.
resource githubIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${prefix}-github-reader'
  location: location
}

resource githubFederation 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials@2023-01-31' = {
  parent: githubIdentity
  name: 'github-main'
  properties: {
    issuer: 'https://token.actions.githubusercontent.com'
    subject: '${githubSubjectPrefix}:ref:refs/heads/main'
    audiences: ['api://AzureADTokenExchange']
  }
}

resource githubReadsLogs 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(logsContainer.id, githubIdentity.id, roles.blobDataReader)
  scope: logsContainer
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.blobDataReader)
    principalId: githubIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource adminReadsLogs 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(adminPrincipalId)) {
  name: guid(logsContainer.id, adminPrincipalId, roles.blobDataReader)
  scope: logsContainer
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.blobDataReader)
    principalId: adminPrincipalId
    principalType: 'User'
  }
}

// ---------------------------------------------------------------- outputs

output publicIp string = publicIp.properties.ipAddress
output sshCommand string = 'ssh -p ${adminSshPort} ${adminUsername}@${publicIp.properties.ipAddress}'
output storageAccount string = storage.name
output githubClientId string = githubIdentity.properties.clientId
output tenantId string = tenant().tenantId
