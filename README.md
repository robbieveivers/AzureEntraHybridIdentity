# AzureEntraHybridIdentity
Repo for Standing up Infra for Entra Hybrid Identity Testing

## Terraform Deploys VM on azure, Ansible Configures and Enrolls the Entra Cloud Sync agent, Terraform configures the Cloud Sync Config

## Permissions Required.

Warning, do not use global admin user for this activity as it involes passing around dangours tokens which use AAD graph endpoints and user_impersonation

Currently cloud sync enrollment does support SPN, it looks like user accounts required.

The token is grabbed from Az cli rest.

Set up Terraform to use AZ CLI auth with the following permissions:

### User Account with Hybrid Identity Role
configuing and enrolling cloud sync agent

### Permissions to Deploy various Azure components to a subscription
vnet, bastion, virtual machine, disk


https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/how-to-prerequisites?tabs=public-cloud

