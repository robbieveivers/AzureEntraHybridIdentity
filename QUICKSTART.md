# Quick Start Guide

Get up and running with Azure Entra Hybrid Identity in minutes!

## Prerequisites Checklist

Before you begin, ensure you have:

- [ ] Azure subscription
- [ ] Azure account with:
  - [ ] Hybrid Identity Administrator role in Entra ID
  - [ ] Contributor (or higher) role on Azure subscription
- [ ] Tools installed:
  - [ ] Azure CLI (`az --version`)
  - [ ] Terraform (`terraform --version`)
  - [ ] Ansible (`ansible --version`)

## 5-Minute Setup

### Step 1: Clone and Navigate

```bash
git clone https://github.com/robbieveivers/AzureEntraHybridIdentity.git
cd AzureEntraHybridIdentity
```

### Step 2: Configure

```bash
# Copy the example configuration
cp terraform.tfvars.example terraform.tfvars

# Edit with your values (use your favorite editor)
nano terraform.tfvars  # or vim, code, etc.
```

**Required fields in `terraform.tfvars`:**
- `subscription_id` - Your Azure subscription ID
- `ad_password` - Strong password (12+ characters)
- `location` - Azure region (e.g., "eastus")

### Step 3: Authenticate

```bash
# Login to Azure
az login

# Verify your account
az account show
```

### Step 4: Deploy

```bash
# Option A: Automated (recommended)
./deploy.sh

# Option B: Manual
terraform init
terraform plan
terraform apply
```

### Step 5: Access Your VM

After deployment (20-30 minutes), connect via:

**Azure Bastion (Recommended):**
1. Open Azure Portal
2. Navigate to your VM: `domain-win25`
3. Click "Connect" → "Bastion"
4. Enter credentials from your `terraform.tfvars`

**Or check outputs:**
```bash
terraform output
```

## What Gets Deployed?

| Resource | Description |
|----------|-------------|
| 🖥️ Windows Server 2025 | Domain Controller VM |
| 🌐 Virtual Network | Isolated network (10.10.0.0/16) |
| 🔒 Network Security Group | Firewall rules (your IP only) |
| 🏰 Azure Bastion | Secure remote access |
| 📊 Active Directory | Fully configured domain |
| 🔄 Cloud Sync Agent | Connected to Entra ID |

## Quick Commands

```bash
# Check deployment status
terraform show

# See all outputs
terraform output

# Update configuration
terraform plan
terraform apply

# Destroy everything
terraform destroy
```

## Common Issues

### Issue: "Not logged in to Azure CLI"
**Fix:** Run `az login`

### Issue: "subscription_id is empty"
**Fix:** Edit `terraform.tfvars` and add your subscription ID

### Issue: "Cannot connect to VM"
**Fix:** Wait 5-10 minutes for Windows to fully boot

### Issue: "Token acquisition failed"
**Fix:** Ensure your account has Hybrid Identity Administrator role

## Next Steps

✅ **After deployment:**
1. Verify Cloud Sync in [Entra Admin Center](https://entra.microsoft.com)
2. Review sync configuration
3. Test user synchronization

📚 **Learn more:**
- [ARCHITECTURE.md](ARCHITECTURE.md) - How it works
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Detailed troubleshooting
- [SECURITY.md](SECURITY.md) - Security best practices

## Getting Help

- 📖 Read [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
- 🐛 Open an [issue](../../issues)
- 💬 Start a [discussion](../../discussions)

## Clean Up

When you're done testing:

```bash
# Remove all resources
terraform destroy

# Confirm with: yes
```

**Note:** This will delete all deployed resources and cannot be undone!

---

**Happy testing!** 🎉

For detailed information, see the full [README.md](README.md)
