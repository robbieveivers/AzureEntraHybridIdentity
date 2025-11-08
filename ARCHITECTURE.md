# Architecture Documentation

## Overview

This project deploys a complete Azure Entra Hybrid Identity testing environment using Infrastructure as Code (IaC).

## Components

### Infrastructure Layer (Terraform)

#### Network Components
- **Virtual Network (VNet)**: 10.10.0.0/16 address space
- **Subnet**: 10.10.1.0/24 for VM placement
- **Network Security Group (NSG)**: Restricts access to your IP only
  - RDP (3389)
  - SSH (22)
  - WinRM HTTP (5985)
- **Public IP**: Static allocation for VM access
- **Azure Bastion**: Developer SKU for secure remote access

#### Compute Resources
- **Windows Server 2025 VM**
  - SKU: Standard_B2as_v2
  - OS Disk: 64GB Premium SSD
  - Active Directory Domain Services role
  - Entra Cloud Sync agent

#### Resource Organization
- **Resource Group**: Contains all deployed resources
- **Tags**: Applied to all resources for tracking and management

### Application Layer (Ansible)

The Ansible playbook (`ad_enroll_agent.yml`) performs the following tasks:

1. **Domain Controller Promotion**
   - Creates new Active Directory forest
   - Configures DNS
   - Sets domain and forest functional levels to Windows Server 2025

2. **Cloud Sync Agent Installation**
   - Downloads the provisioning agent installer
   - Installs the agent silently
   - Configures agent service

3. **Cloud Sync Configuration**
   - Authenticates to Azure Entra ID
   - Creates Group Managed Service Account (gMSA)
   - Registers the AD domain with Entra ID
   - Establishes sync connection

### Identity Synchronization Layer

The Terraform module (`entra-cloud-sync-config`) configures:
- Sync scope (which users/groups to sync)
- Sync schedule
- Attribute mappings
- Sync rules and filters

## Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│                      Azure Entra ID                          │
│                    (Cloud Identity)                          │
└──────────────────────▲──────────────────────────────────────┘
                       │
                       │ HTTPS (Outbound only)
                       │ Cloud Sync Protocol
                       │
┌──────────────────────┴──────────────────────────────────────┐
│              Entra Cloud Sync Agent                          │
│           (Running on Windows Server VM)                     │
└──────────────────────▲──────────────────────────────────────┘
                       │
                       │ LDAP/Kerberos
                       │
┌──────────────────────┴──────────────────────────────────────┐
│              Active Directory Domain Services                │
│           (Windows Server 2025 Domain Controller)            │
└──────────────────────────────────────────────────────────────┘
```

## Deployment Flow

1. **Terraform Init Phase**
   - Authenticates to Azure using Azure CLI
   - Retrieves access token via `get-token.sh`
   - Initializes providers (azurerm, azapi, msgraph)

2. **Infrastructure Provisioning**
   - Creates resource group
   - Deploys network infrastructure
   - Creates and configures Windows VM
   - Waits for VM to be ready

3. **Ansible Configuration** (via Terraform local-exec)
   - Connects to VM via WinRM
   - Promotes server to Domain Controller
   - Installs Cloud Sync agent
   - Registers agent with Entra ID
   - Configures gMSA and domain sync

4. **Cloud Sync Configuration**
   - Terraform module configures sync settings
   - Activates synchronization

5. **Post-Deployment**
   - Azure Bastion deployed for secure access
   - Outputs display connection information

## Security Architecture

### Network Security
- NSG restricts access to deployer's IP only
- Azure Bastion provides secure tunnel (no public RDP)
- Private subnet with service endpoints

### Identity Security
- Least-privilege service accounts
- gMSA for agent authentication (automatically rotated passwords)
- Token-based authentication to Entra ID
- No passwords stored in sync agent configuration

### Data Protection
- Terraform state contains sensitive data (use remote state with encryption)
- Credentials passed as sensitive parameters
- Tokens marked as sensitive in Terraform

## Scalability Considerations

This architecture is designed for testing/development. For production:

1. **High Availability**
   - Deploy multiple VMs in availability set/zones
   - Multiple Cloud Sync agents for redundancy
   - Geo-redundant storage for backups

2. **Performance**
   - Larger VM SKU for production workloads
   - Premium storage for all disks
   - Dedicated domain controllers (separate sync agents)

3. **Networking**
   - Hub-and-spoke network topology
   - ExpressRoute for hybrid connectivity
   - Private endpoints for Azure services

4. **Monitoring**
   - Azure Monitor for VM metrics
   - Log Analytics for centralized logging
   - Entra ID Connect Health for sync monitoring

## Prerequisites

### Azure Resources
- Azure subscription with permissions to create resources
- Resource providers registered:
  - Microsoft.Compute
  - Microsoft.Network
  - Microsoft.Storage

### Entra ID Permissions
- Hybrid Identity Administrator role
- Application Administrator (for service principal creation)

### Tools Required
- Terraform >= 1.0
- Ansible >= 2.9
- Azure CLI >= 2.0
- PowerShell modules (installed automatically by Ansible)

## Maintenance

### Regular Tasks
- Monitor sync status in Entra ID portal
- Review sync errors and warnings
- Update VM patches and security updates
- Rotate credentials periodically

### Backup Strategy
- Azure Backup for VM
- System State backups for AD
- Export Terraform state regularly
- Document custom configurations

## Troubleshooting

### Common Issues

1. **Token Acquisition Failure**
   - Ensure `az login` is successful
   - Verify account has Hybrid Identity Administrator role

2. **Ansible Connection Timeout**
   - Verify NSG rules allow WinRM from your IP
   - Check VM is fully booted (wait 5-10 minutes)

3. **Cloud Sync Agent Registration**
   - Verify token is not expired
   - Check firewall allows outbound HTTPS to Microsoft endpoints
   - Review agent logs in Event Viewer

4. **Sync Not Starting**
   - Verify domain is accessible from VM
   - Check gMSA creation was successful
   - Review module configuration in Entra portal

## References

- [Entra Cloud Sync Documentation](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/)
- [Azure Bastion Documentation](https://learn.microsoft.com/en-us/azure/bastion/)
- [Terraform Azure Provider](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs)
- [Ansible Windows Modules](https://docs.ansible.com/ansible/latest/collections/ansible/windows/)
