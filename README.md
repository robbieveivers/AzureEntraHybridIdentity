# Azure Entra Hybrid Identity

Infrastructure as Code (IaC) repository for deploying and testing Azure Entra Hybrid Identity environments.

## Overview

This project automates the deployment of a complete hybrid identity testing environment:
- **Terraform** deploys a Windows Server 2025 VM on Azure
- **Ansible** configures Active Directory and enrolls the Entra Cloud Sync agent
- **Terraform** configures the Cloud Sync configuration

## ⚠️ Security Warning

**Do not use a Global Admin account for this deployment!** This activity involves passing authentication tokens that use AAD Graph endpoints and user_impersonation scopes. Use a dedicated account with minimal required permissions instead.

## Prerequisites

Currently, cloud sync enrollment does not support Service Principal Names (SPN) - user accounts are required.

### Authentication

The authentication token is obtained from the Azure CLI using `az account get-access-token`.

### Required Permissions

1. **User Account with Hybrid Identity Administrator Role**
   - Required for configuring and enrolling the Cloud Sync agent
   
2. **Azure Subscription Permissions**
   - Ability to deploy the following resources:
     - Virtual Network (VNet)
     - Azure Bastion
     - Virtual Machine
     - Managed Disks
     - Network Security Groups
     - Public IP addresses

📚 **Reference**: [Cloud Sync Prerequisites](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/how-to-prerequisites?tabs=public-cloud)

## 🚀 Quick Start

### Option 1: Using the Deploy Script (Recommended)

The easiest way to deploy is using the provided deployment script:

```bash
# Make sure you're authenticated to Azure
az login

# Run the deployment script
./deploy.sh
```

The script will:
- ✅ Check all prerequisites (Terraform, Ansible, Azure CLI)
- ✅ Verify Azure authentication
- ✅ Create and validate terraform.tfvars
- ✅ Run Terraform plan and apply
- ✅ Display deployment outputs

### Option 2: Manual Deployment

1. Copy the example configuration file:
   ```bash
   cp terraform.tfvars.example terraform.tfvars
   ```

2. Update `terraform.tfvars` with your specific values:
   - Azure location
   - AD domain name and NetBIOS name
   - VM credentials (use a strong password!)
   - Azure subscription ID

3. Authenticate with Azure CLI:
   ```bash
   az login
   ```
   Use an account with the Hybrid Identity Administrator role and appropriate Azure subscription permissions.

4. Initialize and apply Terraform:
   ```bash
   terraform init
   terraform plan
   terraform apply
   ```

## 📋 Configuration

See `terraform.tfvars.example` for all available configuration options.

## 🏗️ Architecture

This deployment creates:
- Windows Server 2025 VM with Active Directory Domain Services
- Azure Entra Cloud Sync agent installed and configured
- Network infrastructure (VNet, NSG, Bastion)
- Cloud Sync configuration linked to your Azure Entra tenant

## 🧹 Cleanup

To remove all deployed resources:
```bash
terraform destroy
```

## 🛠️ Development

### Pre-commit Hooks (Optional)

This project includes pre-commit hooks for code quality. To use them:

```bash
# Install pre-commit
pip install pre-commit

# Install the git hooks
pre-commit install

# Run manually on all files
pre-commit run --all-files
```

## 📚 Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) - Detailed system architecture and design
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Common issues and solutions
- [SECURITY.md](SECURITY.md) - Security best practices and policies
- [CONTRIBUTING.md](CONTRIBUTING.md) - Guidelines for contributing
- [CHANGELOG.md](CHANGELOG.md) - Version history and changes

## 📝 License

See [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to contribute to this project.
